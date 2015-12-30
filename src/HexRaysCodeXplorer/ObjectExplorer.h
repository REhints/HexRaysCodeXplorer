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
 	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	==============================================================================
*/

#ifndef __H_OBJECTEXPLORER__
#define __H_OBJECTEXPLORER__


// Object Explorer Form Init
struct object_explorer_info_t
{
	TForm *form;
	TCustomControl *cv;
	TCustomControl *codeview;
	strvec_t sv;
	object_explorer_info_t(TForm *f) : form(f), cv(NULL) {}
};

void object_explorer_form_init();


// VTBL 
struct VTBL_info_t
{
	qstring vtbl_name;
	ea_t ea_begin;
	ea_t ea_end;
	UINT methods;
	
};


extern qvector <qstring> vtbl_list;
extern qvector <qstring>::iterator vtbl_iter;



inline BOOL is_valid_name(LPCSTR name){ return(*((PDWORD) name) == 0x375F3F3F /*"??_7"*/); }
void parse_vft_members(LPCTSTR name, ea_t ea_start, ea_t ea_end);

void search_objects(bool bForce = true);


template <class T> BOOL verify_32_t(ea_t ea_ptr, T &rvalue)
{
	if(getFlags(ea_ptr))
	{
		rvalue = (T) get_32bit(ea_ptr);
		return(TRUE);
	}

	return(FALSE);
}


// RTTI
struct RTTI_info_t
{
	PVOID vftable;
	PVOID m_data;
	char  m_d_name[MAXSTR]; // mangled name (prefix: .?AV=classes, .?AU=structs)
};

static BOOL is_valid_rtti(RTTI_info_t *pIDA);
static LPSTR get_name(IN RTTI_info_t *pIDA, OUT LPSTR pszBufer, int iSize);

// returns TRUE if mangled name is a unknown type name		
static inline BOOL is_type_name(LPCSTR pszName){ return((*((PUINT)pszName) & 0xFFFFFF) == 0x413F2E /*".?A"*/); }


struct PMD
{
	int mdisp;	// member
	int pdisp;  // vftable
	int vdisp;  // place inside vftable		
};


struct RTTIBaseClassDescriptor
{
	RTTI_info_t *pTypeDescriptor;	// type descriptor of the class
	UINT numContainedBases;			// number of nested classes
	PMD  pmd;						// pointer-to-member displacement info
	UINT attributes;				// flags (usually 0)
};


struct RTTIClassHierarchyDescriptor
{
	UINT signature;			// always zero?
	UINT attributes;		// bit 0 set = multiple inheritance, bit 1 set = virtual inheritance
	UINT numBaseClasses;	// number of classes in pBaseClassArray
	RTTIBaseClassDescriptor **pBaseClassArray;
};

const UINT CHDF_MULTIPLE = (1 << 0);
const UINT CHDF_VIRTUAL = (1 << 1);


struct RTTICompleteObjectLocator
{
	UINT signature;					// always zero ?
	UINT offset;					// offset of this vftable in the complete class
	UINT cdOffset;					// constructor displacement offset
	RTTI_info_t *pTypeDescriptor;	// TypeDescriptor of the complete class
	RTTIClassHierarchyDescriptor *pClassDescriptor; // 10 Describes inheritance hierarchy
};

ea_t find_RTTI(ea_t start_ea, ea_t end_ea);
char* get_demangle_name(ea_t class_addr);
void process_rtti();

const char * get_text_disasm(ea_t ea);

bool get_vbtbl_by_ea(ea_t vtbl_addr, VTBL_info_t &vtbl);

tid_t create_vtbl_struct(ea_t vtbl_addr, ea_t vtbl_addr_end, char* vtbl_name, uval_t idx, unsigned int* vtbl_len = NULL);

#endif