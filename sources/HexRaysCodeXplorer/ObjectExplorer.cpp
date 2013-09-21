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


#include "Common.h"
#include "ObjectExplorer.h"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <struct.hpp>
#include <loader.hpp>

#include <string.h>
#include <stdarg.h>
#include <tchar.h>



LPCTSTR get_text_disasm(ea_t ea)
{
	static char disasm_buff[MAXSTR];
	disasm_buff[0] = disasm_buff[MAXSTR - 1] = 0;

	if(generate_disasm_line(ea, disasm_buff, (sizeof(disasm_buff) - 1)))
		tag_remove(disasm_buff, disasm_buff, (sizeof(disasm_buff) - 1));

	return(disasm_buff);
}


BOOL get_vtbl_info(ea_t ea_address, tVTBL_info &vtbl_info)
{
	flags_t flags = getFlags(ea_address);  
	if(!(hasRef(flags) || has_any_name(flags) && (isDwrd(flags) || isUnknown(flags))))
		return(FALSE);
	else
	{
		BOOL is_move_xref = FALSE;
		ea_t ea_code_ref = get_first_dref_to(ea_address);
		if(ea_code_ref && (ea_code_ref != BADADDR))
		{
			do 
			{	
				if(isCode(getFlags(ea_code_ref)))
				{
					LPCTSTR disasm_line = get_text_disasm(ea_code_ref);
					if((*((PUINT) disasm_line) == 0x20766F6D /*"mov "*/) && (strstr(disasm_line+4, " offset ") != NULL))
					{
						is_move_xref = TRUE;
						break;
					}
				}			
				
				ea_code_ref = get_next_dref_to(ea_address, ea_code_ref);

			} while(ea_code_ref && (ea_code_ref != BADADDR));		
		}
		if(!is_move_xref)
			return(FALSE);

		ZeroMemory(&vtbl_info, sizeof(tVTBL_info));

		get_name(BADADDR, ea_address, vtbl_info.name_size, (MAXSTR - 1));

		ea_t ea_start = vtbl_info.ea_begin = ea_address;
		while(TRUE)
		{
			flags_t index_flags = getFlags(ea_address);
			if(!(hasValue(index_flags) && (isDwrd(index_flags) || isUnknown(index_flags))))
				break;

			ea_t ea_index_value = get_32bit(ea_address);
			if(!(ea_index_value && (ea_index_value != BADADDR)))
				break;

			if(ea_address != ea_start)
				if(hasRef(index_flags))
					break;

			flags_t value_flags = getFlags(ea_index_value);
			if(!isCode(value_flags))
			{
				break;
			}
			else
				if(isUnknown(index_flags))
				{						
					doDwrd(ea_address, sizeof(DWORD));			
				}

				ea_address += sizeof(UINT);
		};

		if((vtbl_info.methods = ((ea_address - ea_start) / sizeof(UINT))) > 0)
		{
			vtbl_info.ea_end = ea_address;	
			return(TRUE);
		}
		else
		{
			return(FALSE);
		}
	}
}


qvector <qstring> vtbl_list;
static BOOL process_vtbl(ea_t &ea_rdata)
{
	tVTBL_info vftable_info_t;
	if(get_vtbl_info(ea_rdata, vftable_info_t))
	{
		ea_rdata = vftable_info_t.ea_end;
		ea_t eaAssumedCOL;
		verify_32_t((vftable_info_t.ea_begin - 4), eaAssumedCOL);
		
		if(vftable_info_t.methods > 1)
		{
			if(has_user_name(getFlags(vftable_info_t.ea_begin)))
			{					
				char szName[MAXSTR] = {0};			
				get_short_name(BADADDR, vftable_info_t.ea_begin, szName, (MAXSTR - 1));	

				qstring vtbl_info;
				vtbl_info.cat_sprnt("0x%x - 0x%x: \t %s \t method count: %u", vftable_info_t.ea_begin, vftable_info_t.ea_end, vftable_info_t.name_size, vftable_info_t.methods);
				vtbl_list.push_back(vtbl_info);  

				return(TRUE);
			}
		}
			
		return(FALSE);
	}

	ea_rdata += sizeof(UINT);	
	return(FALSE);
}


void search_vtbl()
{
	segment_t *rdata_seg = get_segm_by_name(".rdata");
	ea_t ea_rdata = rdata_seg->startEA;	
	while(ea_rdata <= rdata_seg->endEA)
	{			
		process_vtbl(ea_rdata);								
	};
}



//---------------------------------------------------------------------------
// IDA Custom View Window Initialization 
//---------------------------------------------------------------------------
static bool idaapi ct_keyboard(TCustomControl * /*v*/, int key, int shift, void *ud)
{
	if ( shift == 0 )
	{
		object_explorer_info_t *si = (object_explorer_info_t *)ud;
		switch ( key )
		{
			case IK_ESCAPE:
				close_tform(si->form, FORM_SAVE | FORM_CLOSE_LATER);
				return true;
		}
	}
	return false;
}


static bool idaapi lines_linenum(
	TCustomControl * /*cv*/,
	const place_t *p,
	uval_t *num,
	void * /*ud*/)
{
	*num = p->touval(NULL) + 1;
	return true;
}


int idaapi ui_callback(void *ud, int code, va_list va)
{
	object_explorer_info_t *si = (object_explorer_info_t *)ud;
	switch ( code )
	{
	case ui_tform_invisible:
		{
			TForm *f = va_arg(va, TForm *);
			if ( f == si->form )
			{
				delete si;
				unhook_from_notification_point(HT_UI, ui_callback, NULL);
			}
		}
		break;
	}
	return 0;
}


void custom_form_init()
{
	HWND hwnd = NULL;  
	TForm *form = create_tform("Object Explorer", &hwnd);
	if ( hwnd == NULL )
	{
		warning("Object Explorer window already open. Switching to it.");
		form = find_tform("Object Explorer");
		if ( form != NULL )
			switchto_tform(form, true);
		return;
	}

	object_explorer_info_t *si = new object_explorer_info_t(form);
	
	qvector <qstring>::iterator vtbl_iter;
	for ( vtbl_iter = vtbl_list.begin(); vtbl_iter != vtbl_list.end(); vtbl_iter++ )
		si->sv.push_back(simpleline_t(*vtbl_iter));

	simpleline_place_t s1;
	simpleline_place_t s2(si->sv.size()-1);
	si->cv = create_custom_viewer("", NULL, &s1, &s2, &s1, 0, &si->sv);
	si->codeview = create_code_viewer(form, si->cv, CDVF_NOLINES);
	set_code_viewer_lines_icon_margin(si->codeview, 2);
	hook_to_notification_point(HT_UI, ui_callback, si);
	open_tform(form, FORM_TAB|FORM_MENU|FORM_RESTORE);
}