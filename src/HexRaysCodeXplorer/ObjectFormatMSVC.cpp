/*	Copyright (c) 2013-2015
REhints <info@rehints.com>
All rights reserved.

==============================================================================

This file is part of HexRaysCodeXplorer

HexRaysCodeXplorer is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see
<http://www.gnu.org/licenses/>.

==============================================================================
*/

#include "ObjectFormatMSVC.h"
#include "ObjectExplorer.h"
#include "Utility.h"


#if !defined (__LINUX__) && !defined (__MAC__)
#include <tchar.h>
#else
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif


//---------------------------------------------------------------------------
// MSVC VTBL parsing
//
// Based on some impressions and code from ClassInformer plugin
// http://sourceforge.net/projects/classinformer/
//---------------------------------------------------------------------------

// Attempt to get information of and fix vftable at address
// Return TRUE along with info if valid vftable parsed at address
bool vftable::getTableInfo(ea_t ea, vtinfo &info)
{
	ZeroMemory(&info, sizeof(vtinfo));

	// Start of a vft should have an xref and a name (auto, or user, etc).
	// Ideal flags 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
	//dumpFlags(ea);
	flags_t flags = get_flags_novalue(ea);
	if (hasRef(flags) && has_any_name(flags) && (isEa(flags) || isUnknown(flags)))
	{
		// Get raw (auto-generated mangled, or user named) vft name
		//if (!get_name(BADADDR, ea, info.name, SIZESTR(info.name)))
		//    logmsg(DEBUG, EAFORMAT" ** vftable::getTableInfo(): failed to get raw name!\n", ea);

		// Determine the vft's method count
		ea_t start = info.start = ea;
		while (TRUE)
		{
			// Should be an ea_t offset to a function here (could be unknown if dirty IDB)
			// Ideal flags for 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
			//dumpFlags(ea);
			flags_t indexFlags = get_flags_novalue(ea);
			if (!(isEa(indexFlags) || isUnknown(indexFlags)))
			{
				break;
			}

			// Look at what this (assumed vftable index) points too
			ea_t memberPtr = getEa(ea);
			if (!(memberPtr && (memberPtr != BADADDR)))
			{
				// vft's often have a zero ea_t (NULL pointer?) following, fix it
				if (memberPtr == 0)
					fixEa(ea);

				break;
			}

			// Should see code for a good vft method here, but it could be dirty
			flags_t flags = get_flags_novalue(memberPtr);
			if (!(isCode(flags) || isUnknown(flags)))
			{
				break;
			}

			if (ea != start)
			{
				// If we see a ref after first index it's probably the beginning of the next vft or something else
				if (hasRef(indexFlags))
				{
					break;
				}

				// If we see a COL here it must be the start of another vftable
				if (RTTI::_RTTICompleteObjectLocator::isValid(memberPtr))
				{
					break;
				}
			}

			// As needed fix ea_t pointer, and, or, missing code and function def here
			fixEa(ea);
			fixFunction(memberPtr);

			ea += sizeof(ea_t);
		};

		// Reached the presumed end of it
		if ((info.methodCount = ((ea - start) / sizeof(ea_t))) > 0)
		{
			info.end = ea;
			return true;
		}
	}

	return false;
}


//---------------------------------------------------------------------------
// MSVC RTTI parsing
//
// Based on some impressions and code from ClassInformer plugin
// http://sourceforge.net/projects/classinformer/
//---------------------------------------------------------------------------

// Skip type_info tag for class/struct mangled name strings
#define SKIP_TD_TAG(_str) (_str + SIZESTR(".?Ax"))

// Class name list container
struct bcdInfo
{
	char m_name[496];
	UINT m_attribute;
	RTTI::PMD m_pmd;
};
typedef qvector<bcdInfo> bcdList;

namespace RTTI
{
	static void getBCDInfo(ea_t col, OUT bcdList &nameList, OUT UINT &numBaseClasses);
};


typedef std::map<ea_t, qstring> stringMap;
static stringMap stringCache;
static eaSet tdSet;
static eaSet chdSet;
static eaSet bcdSet;

void RTTI::freeWorkingData()
{
	stringCache.clear();
	tdSet.clear();
	chdSet.clear();
	bcdSet.clear();
}


// Return a short label indicating the CHD inheritance type by attributes
// TODO: Consider CHD_AMBIGUOUS?
static LPCSTR attributeLabel(UINT attributes)
{
	if ((attributes & 3) == RTTI::CHD_MULTINH)
		return((char *) "[MI]");
	else
		if ((attributes & 3) == RTTI::CHD_VIRTINH)
			return((char *) "[VI]");
		else
			if ((attributes & 3) == (RTTI::CHD_MULTINH | RTTI::CHD_VIRTINH))
				return((char *) "[MI VI]");
			else
				return((char *) "");
}

// Read a string from IDB at address
static int readIdaString(ea_t ea, OUT LPSTR buffer, int bufferSize)
{
	// Return cached name if it exists
	stringMap::iterator it = stringCache.find(ea);
	if (it != stringCache.end())
	{
		const LPCSTR str = it->second.c_str();
		int len = strlen(str);
		if (len > bufferSize) len = bufferSize;
		qstrncpy(buffer, str, len); buffer[len] = 0;
		return(len);
	}
	else
	{
		// Read string at ea if it exists
		int len = get_max_ascii_length(ea, ASCSTR_C, ALOPT_IGNHEADS);
		if (len > 0)
		{
			if (len > bufferSize) len = bufferSize;
			if (get_ascii_contents2(ea, len, ASCSTR_C, buffer, bufferSize))
			{
				// Cache it
				buffer[len - 1] = 0;
				stringCache[ea] = buffer;
			}
			else
				len = 0;
		}
		return(len);
	}
}


// --------------------------- Type descriptor ---------------------------

// Get type name into a buffer
// type_info assumed to be valid
int RTTI::type_info::getName(ea_t typeInfo, OUT LPSTR buffer, int bufferSize)
{
	return(readIdaString(typeInfo + offsetof(type_info, _M_d_name), buffer, bufferSize));
}

// A valid type_info/TypeDescriptor at pointer?
bool RTTI::type_info::isValid(ea_t typeInfo)
{
	// TRUE if we've already seen it
	if (tdSet.find(typeInfo) != tdSet.end())
		return true;

	if (isLoaded(typeInfo))
	{
		// Verify what should be a vftable
		ea_t ea = getEa(typeInfo + offsetof(type_info, vfptr));
		if (isLoaded(ea))
		{
			// _M_data should be NULL statically
			ea_t _M_data = BADADDR;
			if (getVerifyEa((typeInfo + offsetof(type_info, _M_data)), _M_data))
			{
				if (_M_data == 0)
					return(isTypeName(typeInfo + offsetof(type_info, _M_d_name)));
			}
		}
	}

	return false;
}

// Returns TRUE if known typename at address
bool RTTI::type_info::isTypeName(ea_t name)
{
	//	char demangledStr[MAXSTR];
	// Should start with a period
	if (get_byte(name) == '.')
	{
		// Read the rest of the possible name string
		char buffer[MAXSTR]; buffer[0] = buffer[SIZESTR(buffer)] = 0;

		if (readIdaString(name, buffer, SIZESTR(buffer)))
		{

			// Should be valid if it properly demangles
			//			if (demangle_name(demangledStr, (MAXSTR), buffer, (MT_MSCOMP | MNG_NODEFINIT)) >= 0)
			//if (LPSTR s = __unDName(NULL, buffer + 1 /*skip the '.'*/, 0, malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY)))
			if ((buffer[0] == '.') && (buffer[1] == '?') && (buffer[2] == 'A') && (buffer[3] == 'V'))
			{
				//                free(s);
				return true;
			}
		}
	}
	return false;
}

// --------------------------- Complete Object Locator ---------------------------

// Return TRUE if address is a valid RTTI structure
BOOL RTTI::_RTTICompleteObjectLocator::isValid(ea_t col)
{
	if (isLoaded(col))
	{
		// Check signature
		UINT signature = -1;
		if (getVerify32_t((col + offsetof(_RTTICompleteObjectLocator, signature)), signature))
		{
			if (signature == 0)
			{
				// Check valid type_info
				ea_t typeInfo = getEa(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
				if (RTTI::type_info::isValid(typeInfo))
				{
					ea_t classDescriptor = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));

					if (RTTI::_RTTIClassHierarchyDescriptor::isValid(classDescriptor, 0))
					{
						return(TRUE);
					}
				}
			}
		}
	}

	return(FALSE);
}

// Same as above but from an already validated type_info perspective

BOOL RTTI::_RTTICompleteObjectLocator::isValid2(ea_t col)
{
	// 'signature' should be zero
	UINT signature = -1;
	if (getVerify32_t((col + offsetof(_RTTICompleteObjectLocator, signature)), signature))
	{
		if (signature == 0)
		{
			// Verify CHD
			ea_t classDescriptor = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
			if (classDescriptor && (classDescriptor != BADADDR))
				return(RTTI::_RTTIClassHierarchyDescriptor::isValid(classDescriptor, 0));
		}
	}

	return(FALSE);
}


// --------------------------- Base Class Descriptor ---------------------------

// Return TRUE if address is a valid BCD
bool RTTI::_RTTIBaseClassDescriptor::isValid(ea_t bcd, ea_t colBase64)
{
	// TRUE if we've already seen it
	if (bcdSet.find(bcd) != bcdSet.end())
		return true;

	if (isLoaded(bcd))
	{
		// Check attributes flags first
		UINT attributes = -1;
		if (getVerify32_t((bcd + offsetof(_RTTIBaseClassDescriptor, attributes)), attributes))
		{
			// Valid flags are the lower byte only
			if ((attributes & 0xFFFFFF00) == 0)
			{
				// Check for valid type_info
#ifndef __EA64__
				return(RTTI::type_info::isValid(getEa(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor))));
#else
				UINT tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
				ea_t typeInfo = (colBase64 + (UINT64)tdOffset);
				return(RTTI::type_info::isValid(typeInfo));
#endif
			}
		}
	}

	return false;
}

// --------------------------- Class Hierarchy Descriptor ---------------------------

// Return true if address is a valid CHD structure
bool RTTI::_RTTIClassHierarchyDescriptor::isValid(ea_t chd, ea_t colBase64)
{
	// TRUE if we've already seen it
	if (chdSet.find(chd) != chdSet.end())
		return true;

	if (isLoaded(chd))
	{
		// signature should be zero statically
		UINT signature = -1;
		if (getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, signature)), signature))
		{
			if (signature == 0)
			{
				// Check attributes flags
				UINT attributes = -1;
				if (getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, attributes)), attributes))
				{
					// Valid flags are the lower nibble only
					if ((attributes & 0xFFFFFFF0) == 0)
					{
						// Should have at least one base class
						UINT numBaseClasses = 0;
						if (getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)), numBaseClasses))
						{
							if (numBaseClasses >= 1)
							{
								// Check the first BCD entry
#ifndef __EA64__
								ea_t baseClassArray = getEa(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
#else
								UINT baseClassArrayOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
								ea_t baseClassArray = (colBase64 + (UINT64)baseClassArrayOffset);
#endif

								if (isLoaded(baseClassArray))
								{
#ifndef __EA64__
									ea_t baseClassDescriptor = getEa(baseClassArray);
									return(RTTI::_RTTIBaseClassDescriptor::isValid(baseClassDescriptor, 0));
#else
									ea_t baseClassDescriptor = (colBase64 + (UINT64)get_32bit(baseClassArray));
									return(RTTI::_RTTIBaseClassDescriptor::isValid(baseClassDescriptor, colBase64));
#endif
								}
							}
						}
					}
				}
			}
		}
	}

	return false;
}


// Get list of base class descriptor info
static void RTTI::getBCDInfo(ea_t col, OUT bcdList &list, OUT UINT &numBaseClasses)
{
	numBaseClasses = 0;

#ifndef __EA64__
	ea_t chd = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
#else
	UINT cdOffset = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
	UINT objectLocator = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, objectBase));
	ea_t colBase = (col - (UINT64)objectLocator);
	ea_t chd = (colBase + (UINT64)cdOffset);
#endif

	if (chd)
	{
		if (numBaseClasses = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)))
		{
			list.resize(numBaseClasses);

			// Get pointer
#ifndef __EA64__
			ea_t baseClassArray = getEa(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
#else
			UINT bcaOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
			ea_t baseClassArray = (colBase + (UINT64)bcaOffset);
#endif

			if (baseClassArray && (baseClassArray != BADADDR))
			{
				for (UINT i = 0; i < numBaseClasses; i++, baseClassArray += sizeof(UINT)) // sizeof(ea_t)
				{
#ifndef __EA64__
					// Get next BCD
					ea_t bcd = getEa(baseClassArray);

					// Get type name
					ea_t typeInfo = getEa(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
#else
					UINT bcdOffset = get_32bit(baseClassArray);
					ea_t bcd = (colBase + (UINT64)bcdOffset);

					UINT tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
					ea_t typeInfo = (colBase + (UINT64)tdOffset);
#endif
					bcdInfo *bi = &list[i];
					type_info::getName(typeInfo, bi->m_name, SIZESTR(bi->m_name));

					// Add info to list
					UINT mdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, mdisp)));
					UINT pdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, pdisp)));
					UINT vdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, vdisp)));
					// As signed int
					bi->m_pmd.mdisp = *((PINT)&mdisp);
					bi->m_pmd.pdisp = *((PINT)&pdisp);
					bi->m_pmd.vdisp = *((PINT)&vdisp);
					bi->m_attribute = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, attributes));

				}
			}
		}
	}
}


// Process RTTI vftable info
BOOL RTTI::processVftable(ea_t vft, ea_t col, vftable::vtinfo &vi)
{
	BOOL sucess = FALSE;
	// Get vftable info
	if (vftable::getTableInfo(vft, vi))
	{
		ea_t typeInfo = getEa(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
		ea_t chd = get_32bit(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));

		char colName[MAXSTR]; colName[0] = colName[SIZESTR(colName)] = 0;
		type_info::getName(typeInfo, colName, SIZESTR(colName));
		char demangledColName[MAXSTR];
		getPlainTypeName(colName, demangledColName);
		UINT chdAttributes = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes));
		UINT offset = get_32bit(col + offsetof(_RTTICompleteObjectLocator, offset));

		// Parse BCD info
		bcdList list;
		UINT numBaseClasses;
		getBCDInfo(col, list, numBaseClasses);

		BOOL isTopLevel = FALSE;
		qstring cmt;

		// ======= Simple or no inheritance
		if ((offset == 0) && ((chdAttributes & (CHD_MULTINH | CHD_VIRTINH)) == 0)) {
			// Build object hierarchy string
			int placed = 0;
			if (numBaseClasses > 1) {
				// Parent
				char plainName[MAXSTR];
				getPlainTypeName(list[0].m_name, plainName);
				cmt.sprnt("%s%s: ", ((list[0].m_name[3] == 'V') ? "" : "struct "), plainName);
				placed++;
				isTopLevel = ((strcmp(list[0].m_name, colName) == 0) ? TRUE : FALSE);

				// Child object hierarchy
				for (UINT i = 1; i < numBaseClasses; i++)
				{
					// Append name
					getPlainTypeName(list[i].m_name, plainName);
					cmt.cat_sprnt("%s%s, ", ((list[i].m_name[3] == 'V') ? "" : "struct "), plainName);
					placed++;
				}

				// Nix the ending ',' for the last one
				if (placed > 1)
					cmt.remove((cmt.length() - 2), 2);
			}
			else {
				// Plain, no inheritance object(s)
				cmt.sprnt("%s%s", ((colName[3] == 'V') ? "" : "struct "), demangledColName);
				isTopLevel = TRUE;
			}

			sucess = TRUE;
		}
		
		// ======= Multiple inheritance, and, or, virtual inheritance hierarchies
		else
		{
			bcdInfo *bi = NULL;
			int index = 0;

			// Must be the top level object for the type
			if (offset == 0)
			{
				//_ASSERT(strcmp(colName, list[0].m_name) == 0);
				bi = &list[0];
				isTopLevel = TRUE;
			}
			else
			{
				// Get our object BCD level by matching COL offset to displacement
				for (UINT i = 0; i < numBaseClasses; i++)
				{
					if (list[i].m_pmd.mdisp == offset)
					{
						bi = &list[i];
						index = i;
						break;
					}
				}

				// If not found in list, use the first base object instead
				if (!bi)
				{
					//logmsg(DEBUG, "** "EAFORMAT" MI COL class offset: %X(%d) not in BCD.\n", vft, offset, offset);
					for (UINT i = 0; i < numBaseClasses; i++)
					{
						if (list[i].m_pmd.pdisp != -1)
						{
							bi = &list[i];
							index = i;
							break;
						}
					}
				}
			}

			if (bi)
			{
				// Top object level layout
				int placed = 0;
				if (isTopLevel)
				{


					// Build hierarchy string starting with parent
					char plainName[MAXSTR];
					getPlainTypeName(list[0].m_name, plainName);
					cmt.sprnt("%s%s: ", ((list[0].m_name[3] == 'V') ? "" : "struct "), plainName);
					placed++;

					// Concatenate forward child hierarchy
					for (UINT i = 1; i < numBaseClasses; i++)
					{
						getPlainTypeName(list[i].m_name, plainName);
						cmt.cat_sprnt("%s%s, ", ((list[i].m_name[3] == 'V') ? "" : "struct "), plainName);
						placed++;
					}
					if (placed > 1)
						cmt.remove((cmt.length() - 2), 2);
				}
				else
				{
					// Combine COL and CHD name
					char combinedName[MAXSTR]; combinedName[SIZESTR(combinedName)] = 0;
					_snprintf(combinedName, SIZESTR(combinedName), "%s6B%s@", SKIP_TD_TAG(colName), SKIP_TD_TAG(bi->m_name));


					// Build hierarchy string starting with parent
					char plainName[MAXSTR];
					getPlainTypeName(bi->m_name, plainName);
					cmt.sprnt("%s%s: ", ((bi->m_name[3] == 'V') ? "" : "struct "), plainName);
					placed++;

					// Concatenate forward child hierarchy
					if (++index < (int)numBaseClasses)
					{
						for (; index < (int)numBaseClasses; index++)
						{
							getPlainTypeName(list[index].m_name, plainName);
							cmt.cat_sprnt("%s%s, ", ((list[index].m_name[3] == 'V') ? "" : "struct "), plainName);
							placed++;
						}
						if (placed > 1)
							cmt.remove((cmt.length() - 2), 2);
					}
				}
				//                if (placed > 1)
				//                    cmt += ';';
				sucess = TRUE;
			}
		}

		if (sucess)
		{
			//             cmt.cat_sprnt(" %s", attributeLabel(chdAttributes));

			vi.type_info = cmt;
		}
	}

	return sucess;
}


//---------------------------------------------------------------------------
// MSVC parsing core
//---------------------------------------------------------------------------

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static eaList colList;
std::map<ea_t, vftable::vtinfo> rtti_vftables;

static void freeWorkingData() {
	RTTI::freeWorkingData();
	colList.clear();
	rtti_vftables.clear();
}


// Return TRUE if address as a anterior comment
inline BOOL hasAnteriorComment(ea_t ea)
{
	return(get_first_free_extra_cmtidx(ea, E_PREV) != E_PREV);
}

// Delete any anterior comment(s) at address if there is some
inline void killAnteriorComments(ea_t ea)
{
	delete_extra_cmts(ea, E_PREV);
}

// Force a memory location to be DWORD size
void fixDword(ea_t ea)
{
	if (!isDwrd(get_flags_novalue(ea)))
	{
		setUnknown(ea, sizeof(DWORD));
		doDwrd(ea, sizeof(DWORD));
	}
}

// Force memory location to be ea_t size
void fixEa(ea_t ea)
{
#ifndef __EA64__
	if (!isDwrd(get_flags_novalue(ea)))
#else
	if (!isQwrd(get_flags_novalue(ea)))
#endif
	{
		setUnknown(ea, sizeof(ea_t));
#ifndef __EA64__
		doDwrd(ea, sizeof(ea_t));
#else
		doQwrd(ea, sizeof(ea_t));
#endif
	}
}

// Make address a function
void fixFunction(ea_t ea)
{
	flags_t flags = get_flags_novalue(ea);
	if (!isCode(flags))
	{
		create_insn(ea);
		add_func(ea, BADADDR);
	}
	else
		if (!isFunc(flags))
			add_func(ea, BADADDR);
}

// Get IDA EA bit value with verification
bool getVerifyEa(ea_t ea, ea_t &rValue)
{
	// Location valid?
	if (isLoaded(ea))
	{
		// Get ea_t value
		rValue = getEa(ea);
		return true;
	}

	return false;
}


// Undecorate to minimal class name
// typeid(T).name()
// http://en.wikipedia.org/wiki/Name_mangling
// http://en.wikipedia.org/wiki/Visual_C%2B%2B_name_mangling
// http://www.agner.org/optimize/calling_conventions.pdf

BOOL getPlainTypeName(LPCSTR mangled, LPSTR outStr)
{
	outStr[0] = outStr[MAXSTR - 1] = 0;

	// Use CRT function for type names
	if (mangled[0] == '.')
	{
		/*
		__unDName(outStr, mangled + 1, MAXSTR, malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU));
		if ((outStr[0] == 0) || (strcmp((mangled + 1), outStr) == 0))
		{
		logmsg(ERROR, "** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n", mangled);
		return(FALSE);
		}
		*/
		qstrncpy(outStr, mangled, MAXSTR);
	}
	else
		// IDA demangler for everything else
	{
		int result = demangle_name(outStr, (MAXSTR - 1), mangled, (MT_MSCOMP | MNG_NODEFINIT));
		if (result < 0)
		{
			return(FALSE);
		}

		// No inhibit flags will drop this
		if (LPSTR ending = strstr(outStr, "::`vftable'"))
			*ending = 0;
	}

	return(TRUE);
}

void idaapi setUnknown(ea_t ea, int size)
{
	// TODO: Does the overrun problem still exist?
	//do_unknown_range(ea, (size_t)size, DOUNK_SIMPLE);
	while (size > 0)
	{
		int isize = get_item_size(ea);
		if (isize > size)
			break;
		else
		{
			do_unknown(ea, DOUNK_SIMPLE);
			ea += (ea_t)isize, size -= isize;
		}
	};
}


// Scan segment for COLs
void idaapi scanSeg4Cols(segment_t *seg)
{
	unsigned int found = 0;
	if (seg->size() >= sizeof(RTTI::_RTTICompleteObjectLocator))
	{
		ea_t startEA = ((seg->startEA + sizeof(UINT)) & ~((ea_t)(sizeof(UINT) - 1)));
		ea_t endEA = (seg->endEA - sizeof(RTTI::_RTTICompleteObjectLocator));

		for (ea_t ptr = startEA; ptr < endEA;)
		{
			// TypeDescriptor address here?
			ea_t ea = getEa(ptr);
			if (ea >= 0x10000)
			{
				if (RTTI::type_info::isValid(ea))
				{
					// yes, a COL here?
					ea_t col = (ptr - offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
					if (RTTI::_RTTICompleteObjectLocator::isValid2(col))
					{
						// yes
						colList.push_front(col);
						ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
						continue;
					}

				}
			}


			ptr += sizeof(unsigned int);
		}
	}

	return;
}
//
// Locate COL by descriptor list
void idaapi findCols()
{
	// Usually in ".rdata" seg, try it first
	std::set<segment_t *> segSet;
	if (segment_t *seg = get_segm_by_name(".rdata"))
	{
		segSet.insert(seg);
		scanSeg4Cols(seg);
	}

	// And ones named ".data"
	int segCount = get_segm_qty();
	for (int i = 0; i < segCount; i++)
	{
		if (segment_t *seg = getnseg(i))
		{
			if (seg->type == SEG_DATA)
			{
				if (segSet.find(seg) == segSet.end())
				{
					char name[8];
					if (get_true_segm_name(seg, name, SIZESTR(name)) == SIZESTR(".data"))
					{
						if (strcmp(name, ".data") == 0)
						{
							segSet.insert(seg);
							scanSeg4Cols(seg);
						}
					}
				}
			}
		}
	}
	

	// If still none found, try any remaining data type segments
	if (colList.empty())
	{
		for (int i = 0; i < segCount; i++)
		{
			if (segment_t *seg = getnseg(i))
			{
				if (seg->type == SEG_DATA)
				{
					if (segSet.find(seg) == segSet.end())
					{
						segSet.insert(seg);
						scanSeg4Cols(seg);
					}
				}
			}
		}
	}



	return;
}

// Locate vftables
void idaapi scanSeg4Vftables(segment_t *seg, eaRefMap &colMap)
{
	UINT found = 0;
	if (seg->size() >= sizeof(ea_t))
	{
		ea_t startEA = ((seg->startEA + sizeof(ea_t)) & ~((ea_t)(sizeof(ea_t) - 1)));
		ea_t endEA = (seg->endEA - sizeof(ea_t));
		eaRefMap::iterator colEnd = colMap.end();

		for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(UINT))
		{
			// COL here?
			ea_t ea = getEa(ptr);
			eaRefMap::iterator it = colMap.find(ea);
			if (it != colEnd)
			{
				// yes, look for vftable one ea_t below
				ea_t vfptr = (ptr + sizeof(ea_t));
				ea_t method = getEa(vfptr);
				// Points to code?
				if (segment_t *s = getseg(method))
				{
					// yes,
					if (s->type == SEG_CODE)
					{
						vftable::vtinfo vi;
						if (RTTI::processVftable(vfptr, it->first, vi)) {
							rtti_vftables[vfptr] = vi;
						}

						it->second++, found++;
					}
				}
			}
		}
	}


	return;
}
//
void idaapi findVftables()
{
	// COLs in a hash map for speed, plus match counts
	eaRefMap colMap;
	for (eaList::const_iterator it = colList.begin(), end = colList.end(); it != end; ++ it)
		colMap[*it] = 0;

	// Usually in ".rdata", try first.
	std::set<segment_t *> segSet;
	if (segment_t *seg = get_segm_by_name(".rdata"))
	{
		segSet.insert(seg);
		scanSeg4Vftables(seg, colMap);
	}

	// And ones named ".data"
	int segCount = get_segm_qty();
	for (int i = 0; i < segCount; i++)
	{
		if (segment_t *seg = getnseg(i))
		{
			if (seg->type == SEG_DATA)
			{
				if (segSet.find(seg) == segSet.end())
				{
					char name[8];
					if (get_true_segm_name(seg, name, SIZESTR(name)) == SIZESTR(".data"))
					{
						if (strcmp(name, ".data") == 0)
						{
							segSet.insert(seg);
							scanSeg4Vftables(seg, colMap);
						}
					}
				}
			}
		}
	}

	// If still none found, try any remaining data type segments
	if (colList.empty())
	{
		for (int i = 0; i < segCount; i++)
		{
			if (segment_t *seg = getnseg(i))
			{
				if (seg->type == SEG_DATA)
				{
					if (segSet.find(seg) == segSet.end())
					{
						segSet.insert(seg);
						scanSeg4Vftables(seg, colMap);
					}
				}
			}
		}
	}

	// Rebuild 'colList' with any that were not located
	if (!colList.empty())
	{
		colList.clear();
		for (eaRefMap::const_iterator it = colMap.begin(), end = colMap.end(); it != end; ++it)
		{
			if (it->second == 0)
				colList.push_front(it->first);
		}
	}

	return;
}

// Gather RTTI data
void idaapi getRttiData()
{
	freeWorkingData();

	findCols();

	findVftables();
}