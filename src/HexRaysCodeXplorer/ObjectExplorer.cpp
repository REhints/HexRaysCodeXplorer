/*	Copyright (c) 2014
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
#include <search.hpp>

#include <string.h>
#include <stdarg.h>
#include <tchar.h>


//---------------------------------------------------------------------------
// VTBL code parsing
//---------------------------------------------------------------------------

LPCTSTR get_text_disasm(ea_t ea)
{
	static char disasm_buff[MAXSTR];
	disasm_buff[0] = disasm_buff[MAXSTR - 1] = 0;

	if(generate_disasm_line(ea, disasm_buff, (sizeof(disasm_buff) - 1)))
		tag_remove(disasm_buff, disasm_buff, (sizeof(disasm_buff) - 1));

	return(disasm_buff);
}


BOOL get_vtbl_info(ea_t ea_address, VTBL_info_t &vtbl_info)
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

		ZeroMemory(&vtbl_info, sizeof(VTBL_info_t));

		get_name(BADADDR, ea_address, vtbl_info.vtbl_name, (MAXSTR - 1));

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


qvector <VTBL_info_t> vtbl_t_list;
qvector <qstring> vtbl_list; // list of vtables for ObjectExplrer view
static BOOL process_vtbl(ea_t &ea_sect)
{
	VTBL_info_t vftable_info_t;
	if(get_vtbl_info(ea_sect, vftable_info_t))
	{
		ea_sect = vftable_info_t.ea_end;
		ea_t ea_assumed;
		verify_32_t((vftable_info_t.ea_begin - 4), ea_assumed);

		if(vftable_info_t.methods > 1)
		{
			if(has_user_name(getFlags(vftable_info_t.ea_begin)))
			{							
				get_short_name(BADADDR, vftable_info_t.ea_begin, vftable_info_t.vtbl_name, (MAXSTR - 1));

				qstring vtbl_info_str;
				vtbl_info_str.cat_sprnt("0x%x - 0x%x:  %s   method count: %u", vftable_info_t.ea_begin, vftable_info_t.ea_end, vftable_info_t.vtbl_name, vftable_info_t.methods);
				vtbl_list.push_back(vtbl_info_str);

				vtbl_t_list.push_back(vftable_info_t);

				return(TRUE);
			}
		}

		return(FALSE);
	}

	ea_sect += sizeof(UINT);	
	return(FALSE);
}


tid_t create_vtbl_struct(ea_t vtbl_addr, char* vtbl_name, uval_t idx, unsigned int* vtbl_len = NULL)
{
	qstring struc_name = vtbl_name;
	tid_t id = add_struc(BADADDR, struc_name.c_str());
	if (id == BADADDR)
	{
		struc_name.clear();
		struc_name = askstr(HIST_IDENT, NULL, "Default name %s not correct. Enter other structure name: ", struc_name.c_str());
		id = add_struc(BADADDR, struc_name.c_str());
		set_struc_cmt(id, vtbl_name, true);
	}

	struc_t* new_struc = get_struc(id);
	if (!new_struc)
		return BADNODE;

	ea_t ea = vtbl_addr;
	int offset = 0;
	while (TRUE)
	{
		offset = ea - vtbl_addr;
		char method_name[MAXSTR];
		memset(method_name, 0, sizeof(method_name));
		ea_t method_ea = get_long(ea);

		if (method_ea == 0) break;
		if (!isEnabled(method_ea)) break;

		flags_t method_flags = getFlags(method_ea);
		char* struc_member_name = NULL;
		if (isFunc(method_flags))
		{
			if (get_short_name(BADADDR, method_ea, method_name, sizeof(method_name)))
				struc_member_name = method_name;
		}

		add_struc_member(new_struc, NULL, offset, dwrdflag(), NULL, 4);
		if (struc_member_name)
		{
			if (!set_member_name(new_struc, offset, struc_member_name))
			{
				get_name(NULL, method_ea, method_name, sizeof(method_name));
				set_member_name(new_struc, offset, struc_member_name);
			}
		}

		ea = ea + 4;
		flags_t ea_flags = getFlags(ea);
		if (has_any_name(ea_flags)) break;
	}

	return id;
}


//---------------------------------------------------------------------------
// RTTI code parsing 
// (simple code init in v1.1 will be redevelop in the following versions)
//---------------------------------------------------------------------------

// Find RTTI objects by signature
ea_t find_RTTI(ea_t start_ea, ea_t end_ea)
{
	// "2E 3F 41 56" == .?AV
	return find_binary(start_ea, end_ea, "2E 3F 41 56", getDefaultRadix(), SEARCH_DOWN);
}


// Demangle C++ class name
char* get_demangle_name(ea_t class_addr)
{
	char buf_name[MAXSTR];
	int name_size = get_max_ascii_length(class_addr, ASCSTR_TERMCHR, true);
	get_ascii_contents(class_addr, name_size, ASCSTR_TERMCHR, buf_name, sizeof(buf_name));

	return qstrdup(buf_name);
}


qvector <qstring> rtti_list;
qvector <ea_t> rtti_addr;
void process_rtti()
{
	ea_t start = getnseg(0)->startEA;
	while (TRUE)
	{
		ea_t rt = find_RTTI(start, inf.maxEA);
		start = rt + 4;

		if (rt == BADADDR)
			break;

		char* name = get_demangle_name(rt);
		ea_t rtd = rt - 8;

		rtti_addr.push_back(rtd);

		qstring tmp;
		tmp.cat_sprnt("0x%x:  %s", rtd, name);
		rtti_list.push_back(tmp);
	}
}


//---------------------------------------------------------------------------
// Handle VTBL & RTTI 
//---------------------------------------------------------------------------
void search_objects()
{
	segment_t *text_seg = get_segm_by_name(".text");

	if (text_seg != NULL)
	{
		ea_t ea_text = text_seg->startEA;
		while (ea_text <= text_seg->endEA)
			process_vtbl(ea_text);
	}

	segment_t *rdata_seg = get_segm_by_name(".rdata");
	if (rdata_seg != NULL)
	{
		ea_t ea_rdata = rdata_seg->startEA;
		while (ea_rdata <= rdata_seg->endEA)
			process_vtbl(ea_rdata);
	}

	process_rtti();
}


//---------------------------------------------------------------------------
// IDA Custom View Window Initialization 
//---------------------------------------------------------------------------

static int current_line_pos = NULL;

static bool idaapi make_vtbl_struct_cb(void *ud)
{	
	VTBL_info_t vtbl_t = vtbl_t_list[current_line_pos];
	tid_t id = add_struc(BADADDR, vtbl_t.vtbl_name);

	create_vtbl_struct(vtbl_t.ea_begin, vtbl_t.vtbl_name, id);

	return true;
}


// Popup window with RTTI objects list
static bool idaapi ct_rtti_window_click(TCustomControl *v, int shift, void *ud)
{
	int x, y;
	place_t *place = get_custom_viewer_place(v, true, &x, &y);
	simpleline_place_t *spl = (simpleline_place_t *)place;
	int line_num = spl->n;

	ea_t cur_vt_ea = rtti_addr[line_num];
	jumpto(cur_vt_ea);

	return true;
}


static bool idaapi show_rtti_window_cb(void *ud)
{
	if (!rtti_list.empty() && !rtti_addr.empty())
	{
		HWND hwnd = NULL;
		TForm *form = create_tform("RTTI Objects List", &hwnd);

		object_explorer_info_t *si = new object_explorer_info_t(form);

		qvector <qstring>::iterator rtti_iter;
		for (rtti_iter = rtti_list.begin(); rtti_iter != rtti_list.end(); rtti_iter++)
			si->sv.push_back(simpleline_t(*rtti_iter));

		simpleline_place_t s1;
		simpleline_place_t s2(si->sv.size() - 1);
		si->cv = create_custom_viewer("", NULL, &s1, &s2, &s1, 0, &si->sv);
		si->codeview = create_code_viewer(form, si->cv, CDVF_STATUSBAR);
		set_custom_viewer_handlers(si->cv, NULL, NULL, ct_rtti_window_click, NULL, NULL, si);
		open_tform(form, FORM_ONTOP | FORM_RESTORE);

		return true;
	}

	warning("HexRaysCodeXplorer don't find any RTTI objects inside");

	return false;
}
//////////////////////////////////////////////////////////////////////////


static void idaapi ct_object_explorer_popup(TCustomControl *v, void *ud) 
{
	set_custom_viewer_popup_menu(v, NULL);
	add_custom_viewer_popup_item(v, "Make VTBL_Srtruct", "S", make_vtbl_struct_cb, ud);
	add_custom_viewer_popup_item(v, "Show RTTI objects list", "R", show_rtti_window_cb, ud);
}


static bool idaapi ct_object_explorer_keyboard(TCustomControl * /*v*/, int key, int shift, void *ud)
{
	if (shift == 0)
	{
		object_explorer_info_t *si = (object_explorer_info_t *)ud;
		switch (key)
		{
		case IK_ESCAPE:
			close_tform(si->form, FORM_SAVE | FORM_CLOSE_LATER);
			return true;
		}
	}
	return false;
}


static bool idaapi ct_object_explorer_click(TCustomControl *v, int shift, void *ud)
{
	int x, y;
	place_t *place = get_custom_viewer_place(v, true, &x, &y);
	simpleline_place_t *spl = (simpleline_place_t *)place;
	int line_num = spl->n;

	ea_t cur_vt_ea = vtbl_t_list[line_num].ea_begin;
	jumpto(cur_vt_ea);

	return true;
}


static char* get_vtbl_hint(int line_num)
{
	current_line_pos = line_num;
	char tag_lines [4096];
	ZeroMemory(tag_lines, sizeof(tag_lines));
	
	if (isEnabled(vtbl_t_list[line_num].ea_begin))
	{
		int flags = calc_default_idaplace_flags();
		linearray_t ln(&flags);
		idaplace_t pl;
		pl.ea = vtbl_t_list[line_num].ea_begin;
		pl.lnnum = 0;
		ln.set_place(&pl);

		int used = 0;
		int n = ln.get_linecnt();           
		for ( int i=0; i < n; i++ )        
		{
			char buf[MAXSTR];
			char *line = ln.down();           
			tag_remove(line, buf, sizeof(buf));
			used += sprintf_s(tag_lines + used, sizeof(tag_lines) - used, "%s\n", buf);
		}

	}

	return qstrdup(tag_lines);
}


int idaapi ui_object_explorer_callback(void *ud, int code, va_list va)
{
	object_explorer_info_t *si = (object_explorer_info_t *)ud;
	switch (code)
	{
		case ui_get_custom_viewer_hint:
		{
			TCustomControl *viewer	= va_arg(va, TCustomControl *);
			place_t *place			= va_arg(va, place_t *);
			int *important_lines	= va_arg(va, int *);
			qstring &hint			= *va_arg(va, qstring *);

			if ( si->cv == viewer )
			{
				if ( place == NULL )
					return 0;

				simpleline_place_t *spl = (simpleline_place_t *)place;
				hint = get_vtbl_hint (spl->n);
				*important_lines = 10;
				return 1;
			}
			break;
		}
		case ui_tform_invisible:
		{
			TForm *f = va_arg(va, TForm *);
			if ( f == si->form )
			{
				delete si;
				unhook_from_notification_point(HT_UI, ui_object_explorer_callback, NULL);
			}
		}
		break;
	}
	return 0;
}


void object_explorer_form_init()
{
	if (!vtbl_list.empty() && !vtbl_t_list.empty())
	{
		HWND hwnd = NULL;
		TForm *form = create_tform("Object Explorer", &hwnd);
		if (hwnd == NULL)
		{
			warning("Object Explorer window already open. Switching to it.");
			form = find_tform("Object Explorer");
			if (form != NULL)
				switchto_tform(form, true);
			return;
		}

		object_explorer_info_t *si = new object_explorer_info_t(form);

		qvector <qstring>::iterator vtbl_iter;
		for (vtbl_iter = vtbl_list.begin(); vtbl_iter != vtbl_list.end(); vtbl_iter++)
			si->sv.push_back(simpleline_t(*vtbl_iter));

		simpleline_place_t s1;
		simpleline_place_t s2(si->sv.size() - 1);
		si->cv = create_custom_viewer("", NULL, &s1, &s2, &s1, 0, &si->sv);
		si->codeview = create_code_viewer(form, si->cv, CDVF_STATUSBAR);
		set_custom_viewer_handlers(si->cv, ct_object_explorer_keyboard, ct_object_explorer_popup, ct_object_explorer_click, NULL, NULL, si);
		hook_to_notification_point(HT_UI, ui_object_explorer_callback, si);
		open_tform(form, FORM_TAB | FORM_MENU | FORM_RESTORE);
	}
	else
		warning("HexRaysCodeXplorer don't find any virtual tables inside");
}