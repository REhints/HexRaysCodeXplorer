/*	Copyright (c) 2013-2020
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

#include "MSVCObjectFormatParser.h"
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
	flags_t flags = get_flags(ea);
	if (has_xref(flags) && has_any_name(flags) && (isEa(flags) || is_unknown(flags)))
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
			flags_t indexFlags = get_flags(ea);
			if (!(isEa(indexFlags) || is_unknown(indexFlags)))
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
			flags_t flags = get_flags(memberPtr);
			if (!(is_code(flags) || is_unknown(flags)))
			{
				break;
			}

			if (ea != start)
			{
				// If we see a ref after first index it's probably the beginning of the next vft or something else
				if (has_xref(indexFlags))
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

			ea += EA_SIZE;
		};

		// Reached the presumed end of it
		if ((info.methodCount = ((ea - start) / EA_SIZE)) > 0)
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
#define SKIP_TD_TAG(_str) ((_str) + _countof(".?Ax") - 1)

// Class name list container
struct bcdInfo
{
	qstring m_name;
	UINT m_attribute;
	RTTI::PMD m_pmd;
};
typedef qvector<bcdInfo> bcdList;

namespace RTTI
{
	static bool getBCDInfo(ea_t col, bcdList &nameList, OUT UINT &numBaseClasses);
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
static size_t readIdaString(ea_t ea, qstring& rv)
{
	// Return cached name if it exists
	auto it = stringCache.find(ea);
	if (it != stringCache.end())
	{
		rv = it->second;
		return rv.length();
	}

	// Read string at ea if it exists
	auto len = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);
	if (!len)
		return 0;

	rv.reserve(len + 4);
	if (get_strlit_contents(&rv, ea, len, STRTYPE_C) <= 0)
		return 0;

	// Cache it
	stringCache[ea] = rv;
	return rv.length();
}


// --------------------------- Type descriptor ---------------------------

// Get type name into a buffer
// type_info assumed to be valid
bool RTTI::type_info::getName(ea_t typeInfo, qstring& outName)
{
	return readIdaString(typeInfo + offsetof(type_info, _M_d_name), outName) > 0;
}

// A valid type_info/TypeDescriptor at pointer?
bool RTTI::type_info::isValid(ea_t typeInfo)
{
	// TRUE if we've already seen it
	if (tdSet.find(typeInfo) != tdSet.end())
		return true;

	if (is_loaded(typeInfo))
	{
		// Verify what should be a vftable
		ea_t ea = getEa(typeInfo + offsetof(type_info, vfptr));
		if (is_loaded(ea))
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
		qstring buffer;

		if (readIdaString(name, buffer) && buffer.length() > 3)
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
bool RTTI::_RTTICompleteObjectLocator::isValid(ea_t col)
{
	if (!is_loaded(col))
		return false;

	// Check signature
	UINT signature = -1;
	if (!getVerify32_t(col + ea_t(offsetof(_RTTICompleteObjectLocator, signature)), signature) || signature != 0)
		return false;

	// Check valid type_info
	ea_t typeInfo = getEa(col + ea_t(offsetof(_RTTICompleteObjectLocator, typeDescriptor)));
	if (!RTTI::type_info::isValid(typeInfo))
		return false;

	ea_t classDescriptor = getEa(col + ea_t(offsetof(_RTTICompleteObjectLocator, classDescriptor)));

	return RTTI::_RTTIClassHierarchyDescriptor::isValid(classDescriptor, 0);
}

// Same as above but from an already validated type_info perspective

bool RTTI::_RTTICompleteObjectLocator::isValid2(ea_t col)
{
	// 'signature' should be zero
	UINT signature = -1;
	if (!getVerify32_t((col + ea_t(offsetof(_RTTICompleteObjectLocator, signature))), signature) || signature != 0)
		return false;

	// Verify CHD
	ea_t classDescriptor = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
	if (classDescriptor && (classDescriptor != BADADDR))
		return RTTI::_RTTIClassHierarchyDescriptor::isValid(classDescriptor, 0);

	return false;
}


// --------------------------- Base Class Descriptor ---------------------------

// Return TRUE if address is a valid BCD
bool RTTI::_RTTIBaseClassDescriptor::isValid(ea_t bcd, ea_t colBase64)
{
	// TRUE if we've already seen it
	if (bcdSet.find(bcd) != bcdSet.end())
		return true;

	if (!is_loaded(bcd))
		return false;

	// Check attributes flags first
	UINT attributes = -1;
	if (getVerify32_t(bcd + ea_t(offsetof(_RTTIBaseClassDescriptor, attributes)), attributes))
	{
		// Valid flags are the lower byte only
		if ((attributes & 0xFFFFFF00) == 0)
		{
			// Check for valid type_info
			ea_t typeInfo;
			if (inf_is_64bit())
			{
				UINT tdOffset = get_32bit(bcd + ea_t(offsetof(_RTTIBaseClassDescriptor, typeDescriptor)));
				typeInfo = colBase64 + (UINT64)tdOffset;
			}
			else
			{
				typeInfo = getEa(bcd + ea_t(offsetof(_RTTIBaseClassDescriptor, typeDescriptor)));
			}

			return RTTI::type_info::isValid(typeInfo);
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

	if (!is_loaded(chd))
		return false;

	// signature should be zero statically
	UINT signature = -1;
	if (!getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, signature)), signature) || signature != 0)
		return false;

	// Check attributes flags
	UINT attributes = -1;
	if (!getVerify32_t(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes), attributes))
		return false;

	// Valid flags are the lower nibble only
	if (attributes & 0xFFFFFFF0)
		return false;

	// Should have at least one base class
	UINT numBaseClasses = 0;
	if (!getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)), numBaseClasses))
		return false;

	if (!numBaseClasses)
		return false;

	// Check the first BCD entry
	ea_t baseClassArray;
	if (inf_is_64bit())
	{
		UINT baseClassArrayOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
		baseClassArray = colBase64 + (UINT64)baseClassArrayOffset;
	}
	else
	{
		baseClassArray = getEa(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
	}

	if (!is_loaded(baseClassArray))
		return false;

	if (inf_is_64bit())
	{
		ea_t baseClassDescriptor = colBase64 + (UINT64)get_32bit(baseClassArray);
		return RTTI::_RTTIBaseClassDescriptor::isValid(baseClassDescriptor, colBase64);
	}
	else
	{
		ea_t baseClassDescriptor = getEa(baseClassArray);
		return RTTI::_RTTIBaseClassDescriptor::isValid(baseClassDescriptor, 0);
	}
}


// Get list of base class descriptor info
static bool RTTI::getBCDInfo(ea_t col, bcdList &list, OUT UINT &numBaseClasses)
{
	numBaseClasses = 0;

	ea_t chd, colBase;
	if (inf_is_64bit())
	{
		UINT cdOffset = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
		UINT objectLocator = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, objectBase));
		colBase = (col - (UINT64)objectLocator);
		chd = (colBase + (UINT64)cdOffset);
	}
	else
	{
		chd = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
	}

	if (!chd)
		return false;

	if (!(numBaseClasses = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses))))
		return true;

	list.resize(numBaseClasses);

	// Get pointer
	ea_t baseClassArray;
	if (inf_is_64bit())
	{
		UINT bcaOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
		baseClassArray = (colBase + (UINT64)bcaOffset);
	}
	else
	{
		baseClassArray = getEa(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
	}

	if (!::is_mapped(baseClassArray))
		return false;

	for (UINT i = 0; i < numBaseClasses; ++i, baseClassArray += sizeof(UINT)) // sizeof(ea_t)
	{
		ea_t bcd, typeInfo;
		if (inf_is_64bit())
		{
			UINT bcdOffset = get_32bit(baseClassArray);
			bcd = (colBase + (UINT64)bcdOffset);

			UINT tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
			typeInfo = (colBase + (UINT64)tdOffset);
		}
		else
		{
			// Get next BCD
			bcd = getEa(baseClassArray);
			if (!is_mapped(bcd))
				continue;

			// Get type name
			typeInfo = getEa(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
		}

		if (!is_mapped(typeInfo))
			continue;

		bcdInfo& bi = list[i];
		type_info::getName(typeInfo, bi.m_name);

		// Add info to list
		UINT mdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, mdisp)));
		UINT pdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, pdisp)));
		UINT vdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, vdisp)));
		// As signed int
		bi.m_pmd.mdisp = *((PINT)&mdisp);
		bi.m_pmd.pdisp = *((PINT)&pdisp);
		bi.m_pmd.vdisp = *((PINT)&vdisp);
		bi.m_attribute = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, attributes));
	}
	return true;
}


// Process RTTI vftable info
bool RTTI::processVftable(ea_t vft, ea_t col, vftable::vtinfo &vi)
{
	// Get vftable info
	if (!vftable::getTableInfo(vft, vi))
		return false;

	bool sucess = false;
	qstring plainName;

	ea_t typeInfo = getEa(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
	ea_t chd = get_32bit(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));

	qstring colName;
	type_info::getName(typeInfo, colName);

	qstring demangledColName;
	getPlainTypeName(colName, demangledColName);
	UINT chdAttributes = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes));
	UINT offset = get_32bit(col + offsetof(_RTTICompleteObjectLocator, offset));

	// Parse BCD info
	bcdList list;
	UINT numBaseClasses = 0;
	if (!getBCDInfo(col, list, numBaseClasses))
		return false;

	bool isTopLevel = false;
	qstring cmt;

	// ======= Simple or no inheritance
	if (offset == 0 && (chdAttributes & (CHD_MULTINH | CHD_VIRTINH)) == 0) {
		// Build object hierarchy string
		int placed = 0;
		if (numBaseClasses > 1) {
			// Parent
			getPlainTypeName(list[0].m_name, plainName);
			cmt.sprnt("%s%s: ", list[0].m_name.length() < 4 || list[0].m_name[3] == 'V' ? "" : "struct ", plainName.c_str());
			placed++;
			isTopLevel = list[0].m_name == colName;

			// Child object hierarchy
			for (UINT i = 1; i < numBaseClasses; i++)
			{
				// Append name
				getPlainTypeName(list[i].m_name, plainName);
				cmt.cat_sprnt("%s%s, ", list[i].m_name.length() < 4 || list[i].m_name[3] == 'V' ? "" : "struct ", plainName.c_str());
				placed++;
			}

			// Nix the ending ',' for the last one
			if (placed > 1)
				cmt.remove(cmt.length() - 2, 2);
		}
		else {
			// Plain, no inheritance object(s)
			cmt.sprnt("%s%s", colName.length() < 4 || colName[3] == 'V' ? "" : "struct ", demangledColName.c_str());
			isTopLevel = true;
		}

		vi.type_info = cmt;
		return true;
	}

	// ======= Multiple inheritance, and, or, virtual inheritance hierarchies
	bcdInfo *bi = nullptr;
	int index = 0;

	// Must be the top level object for the type
	if (offset == 0)
	{
		//_ASSERT(strcmp(colName, list[0].m_name) == 0);
		bi = &list[0];
		isTopLevel = true;
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
			getPlainTypeName(list[0].m_name, plainName);
			cmt.sprnt("%s%s: ", list[0].m_name.length() < 4 || list[0].m_name[3] == 'V' ? "" : "struct ", plainName.c_str());
			placed++;

			// Concatenate forward child hierarchy
			for (UINT i = 1; i < numBaseClasses; i++)
			{
				getPlainTypeName(list[i].m_name, plainName);
				cmt.cat_sprnt("%s%s, ", list[i].m_name.length() < 4 || list[i].m_name[3] == 'V' ? "" : "struct ", plainName.c_str());
				placed++;
			}
			if (placed > 1)
				cmt.remove(cmt.length() - 2, 2);
		}
		else
		{
			// Combine COL and CHD name
//			char combinedName[MAXSTR] = {};
//			_snprintf(combinedName, _countof(combinedName) - 1, "%s6B%s@", SKIP_TD_TAG(colName), SKIP_TD_TAG(bi->m_name));

			// Build hierarchy string starting with parent
			getPlainTypeName(bi->m_name, plainName);
			cmt.sprnt("%s%s: ", bi->m_name.length() < 4 || bi->m_name[3] == 'V' ? "" : "struct ", plainName.c_str());
			placed++;

			// Concatenate forward child hierarchy
			if (++index < (int)numBaseClasses)
			{
				for (; index < (int)numBaseClasses; index++)
				{
					getPlainTypeName(list[index].m_name, plainName);
					cmt.cat_sprnt("%s%s, ", list[index].m_name.length() < 4 || list[index].m_name[3] == 'V' ? "" : "struct ", plainName.c_str());
					placed++;
				}
				if (placed > 1)
					cmt.remove(cmt.length() - 2, 2);
			}
		}
		// if (placed > 1)
		//     cmt += ';';
		// cmt.cat_sprnt(" %s", attributeLabel(chdAttributes));		vi.type_info = cmt;
		return true;
	}

	return false;
}


//---------------------------------------------------------------------------
// MSVC parsing core
//---------------------------------------------------------------------------

#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace {

static eaList colList;
static std::map<ea_t, vftable::vtinfo> rtti_vftables;

} // anonymous

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
	if (!is_dword(get_flags(ea)))
	{
		setUnknown(ea, sizeof(DWORD));
		create_dword(ea, sizeof(DWORD));
	}
}

// Force memory location to be ea_t size
void fixEa(ea_t ea)
{
	if (!isEa(get_flags(ea)))
	{
		setUnknown(ea, EA_SIZE);
		createEa(ea, EA_SIZE);
	}
}

// Make address a function
void fixFunction(ea_t ea)
{
	flags_t flags = get_flags(ea);
	if (!is_code(flags))
	{
		create_insn(ea);
		add_func(ea, BADADDR);
	}
	else
		if (!is_func(flags))
			add_func(ea, BADADDR);
}

// Get IDA EA bit value with verification
bool getVerifyEa(ea_t ea, ea_t &rValue)
{
	// Location valid?
	if (is_loaded(ea))
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

bool getPlainTypeName(const qstring& mangled, qstring& outStr)
{
	outStr.clear();

	// Use CRT function for type names
	if (!mangled.empty() && mangled[0] == '.')
	{
		/*
		__unDName(outStr, mangled + 1, MAXSTR, malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU));
		if ((outStr[0] == 0) || (strcmp((mangled + 1), outStr) == 0))
		{
		logmsg(ERROR, "** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n", mangled);
		return(FALSE);
		}
		*/
		outStr = mangled;
	}
	else
		// IDA demangler for everything else
	{
		int result = demangle_name(&outStr, mangled.c_str(), (MT_MSCOMP | MNG_NODEFINIT));
		if (result < 0)
			return false;

		// No inhibit flags will drop this

		if (auto p = outStr.find("::`vftable'"))
			outStr.resize(p);
	}

	return true;
}

// Scan segment for COLs
void idaapi scanSeg4Cols(segment_t *seg)
{
	unsigned int found = 0;
	if (seg->size() < sizeof(RTTI::_RTTICompleteObjectLocator))
		return;

	ea_t startEA = ((seg->start_ea + sizeof(UINT)) & ~((ea_t)(sizeof(UINT) - 1)));
	ea_t endEA = (seg->end_ea - sizeof(RTTI::_RTTICompleteObjectLocator));

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
	for (int i = 0; i < segCount; ++i)
	{
		segment_t *seg = getnseg(i);
		if (!seg)
			continue;

		if (seg->type != SEG_DATA)
			continue;

		if (segSet.find(seg) == segSet.end())
		{
			qstring name;
			if (get_segm_name(&name, seg) <= 0)
				continue;

			if (name == ".data" || name == "_data")
			{
				segSet.insert(seg);
				scanSeg4Cols(seg);
			}
		}
	}

	// If still none found, try any remaining data type segments
	if (colList.empty())
	{
		for (int i = 0; i < segCount; i++)
		{
			segment_t *seg = getnseg(i);
			if (!seg || seg->type != SEG_DATA)
				continue;
			if (segSet.find(seg) == segSet.end())
			{
				segSet.insert(seg);
				scanSeg4Cols(seg);
			}
		}
	}

	return;
}

// Locate vftables
void idaapi scanSeg4Vftables(segment_t *seg, eaRefMap &colMap)
{
	//UINT found = 0;
	if (seg->size() <= EA_SIZE)
		return;

	ea_t startEA = ((seg->start_ea + EA_SIZE) & ~((ea_t)(EA_SIZE - 1)));
	ea_t endEA = (seg->end_ea - EA_SIZE);

	if (startEA >= endEA)
		return;

	eaRefMap::iterator colEnd = colMap.end();

	for (ea_t ptr = startEA; ptr < endEA; ptr += EA_SIZE)
	{
		// COL here?
		ea_t ea = getEa(ptr);
		eaRefMap::iterator it = colMap.find(ea);
		if (it == colEnd)
			continue;

		// yes, look for vftable one ea_t below
		ea_t vfptr = ptr + EA_SIZE;
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

				it->second++;
				//found++;
			}
		}
	}
}
//
void idaapi findVftables()
{
	// COLs in a hash map for speed, plus match counts
	eaRefMap colMap;
	for (ea_t ea : colList)
		colMap[ea] = 0;

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
		segment_t *seg = getnseg(i);
		if (!seg || seg->type != SEG_DATA)
			continue;

		if (segSet.find(seg) == segSet.end())
		{
			qstring name;
			if (get_segm_name(&name, seg) > 0 && name == ".data")
			{
				segSet.insert(seg);
				scanSeg4Vftables(seg, colMap);
			}
		}
	}

	// If still none found, try any remaining data type segments
	if (colList.empty())
	{
		for (int i = 0; i < segCount; i++)
		{
			segment_t *seg = getnseg(i);
			if (!seg || seg->type == SEG_DATA)
				continue;

			if (segSet.find(seg) == segSet.end())
			{
				segSet.insert(seg);
				scanSeg4Vftables(seg, colMap);
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
}

static void buildReconstructableTypes() {

}


MSVCObjectFormatParser::~MSVCObjectFormatParser()
{
}

void MSVCObjectFormatParser::get_rtti_info()
{
	freeWorkingData();

	findCols();

	findVftables();

	buildReconstructableTypes();
}

void MSVCObjectFormatParser::clear_info()
{
	freeWorkingData();
}
