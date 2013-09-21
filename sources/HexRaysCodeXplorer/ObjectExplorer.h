/*	Copyright (c) 2013
	REhints <info@rehints.com>
	All rights reserved.
	
	============================================================================
	
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
*/

#pragma once

#include "ida.hpp"
#include "netnode.hpp"
#include <kernwin.hpp>

#include <windows.h>



struct object_explorer_info_t
{
	TForm *form;
	TCustomControl *cv;
	TCustomControl *codeview;
	strvec_t sv;
	object_explorer_info_t(TForm *f) : form(f), cv(NULL) {}
};

void custom_form_init();


struct tVTBL_info
{
	ea_t ea_begin;
	ea_t ea_end;
	UINT methods;
	char name_size[MAXSTR];
};


extern qvector <qstring> vtbl_list;
extern qvector <qstring>::iterator vtbl_iter;


BOOL get_vtbl_info(ea_t eaAddress, tVTBL_info &rtInfo);
inline BOOL is_valid_name(LPCSTR pszName){ return(*((PDWORD) pszName) == 0x375F3F3F /*"??_7"*/); }
void parse_vft_members(LPCTSTR lpszName, ea_t eaStart, ea_t eaEnd);

void search_vtbl();


template <class T> BOOL verify_32_t(ea_t ea_ptr, T &rvalue)
{
	if(getFlags(ea_ptr))
	{
		rvalue = (T) get_32bit(ea_ptr);
		return(TRUE);
	}

	return(FALSE);
}