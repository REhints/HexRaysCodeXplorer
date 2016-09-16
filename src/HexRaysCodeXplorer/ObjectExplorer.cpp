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


#include "Common.h"
#include "ObjectExplorer.h"
#include "ObjectFormatMSVC.h"
#include "Utility.h"

#include "Debug.h"

#if !defined (__LINUX__) && !defined (__MAC__)
#include <tchar.h>
#else
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

qvector <VTBL_info_t> vtbl_t_list;	// list of vtables found in the binary
qvector <qstring> vtbl_list;		// list of string for ObjectExplrer vtables view

extern std::map<ea_t, vftable::vtinfo> rtti_vftables;

void free_vtable_lists() {
	vtbl_t_list.clear();
	vtbl_list.clear();
}


//---------------------------------------------------------------------------
// VTBL code parsing
//---------------------------------------------------------------------------

const char* get_text_disasm(ea_t ea) {
	static char disasm_buff[MAXSTR];
	disasm_buff[0] = disasm_buff[MAXSTR - 1] = 0;

	if(generate_disasm_line(ea, disasm_buff, (sizeof(disasm_buff) - 1)))
		tag_remove(disasm_buff, disasm_buff, (sizeof(disasm_buff) - 1));

	return disasm_buff;
}

static bool check_vtable_load_instruction(ea_t ea_code) {
	bool is_move_xref = false;
	const char* disasm_line = get_text_disasm(ea_code);
	if((strncmp(disasm_line, "mov ", 4) == 0) && (qstrstr(disasm_line + 4, " offset ") != NULL)) {
		is_move_xref = true;
	} else if ((strncmp(disasm_line, "lea", 3) == 0)) {
		is_move_xref = true;
	}

	return is_move_xref;
}

//---------------------------------------------------------------------------
// Try to find vtable at the specified address
//---------------------------------------------------------------------------
static bool get_vtbl_info(ea_t ea_address, VTBL_info_t &vtbl_info)
{
	flags_t flags = get_flags_novalue(ea_address);
	if (hasRef(flags) && has_any_name(flags) && (isEa(flags) || isUnknown(flags))) {
		bool is_move_xref = false;
		
		ea_t ea_code_ref = get_first_dref_to(ea_address);
		if(ea_code_ref && (ea_code_ref != BADADDR)) {
			do {	
				if(isCode(get_flags_novalue(ea_code_ref)) && check_vtable_load_instruction(ea_code_ref)) {
					is_move_xref = true;
					break;
				}			
				
				ea_code_ref = get_next_dref_to(ea_address, ea_code_ref);

			} while(ea_code_ref && (ea_code_ref != BADADDR));		
		}
		
		if(is_move_xref) {
			ZeroMemory(&vtbl_info, sizeof(VTBL_info_t));
			
			get_ea_name(&vtbl_info.vtbl_name, ea_address);
			
			ea_t ea_start = vtbl_info.ea_begin = ea_address;
			
			while(true) {
				flags_t index_flags = get_flags_novalue(ea_address);
				if(!(isEa(index_flags) || isUnknown(index_flags)))
					break;

				ea_t ea_index_value = getEa(ea_address);
				if(!(ea_index_value && (ea_index_value != BADADDR)))
					break;

				if(ea_address != ea_start)
					if(hasRef(index_flags))
						break;

				flags_t value_flags = get_flags_novalue(ea_index_value);
				if(!isCode(value_flags)) {
					break;
				} else {
					if(isUnknown(index_flags)) {
#ifndef __EA64__
						doDwrd(ea_address, sizeof(ea_t));
#else
						doQwrd(ea_address, sizeof(ea_t));
#endif
					}
				}

				ea_address += sizeof(ea_t);
			};

			if((vtbl_info.methods = ((ea_address - ea_start) / sizeof(ea_t))) > 0) {
				vtbl_info.ea_end = ea_address;	
				return true;
			}
		}
	}

	return false;
}

//---------------------------------------------------------------------------
// Try to find and parse vtable at the specified address
//---------------------------------------------------------------------------
static void process_vtbl(ea_t &ea_sect)
{
	VTBL_info_t vftable_info_t;
	// try to parse vtable at this address
	if(get_vtbl_info(ea_sect, vftable_info_t))
	{
		ea_sect = vftable_info_t.ea_end;

		if(vftable_info_t.methods > 1) {
			// check if we have already processed this table
			if (rtti_vftables.count(vftable_info_t.ea_begin) == 0) {
				vftable_info_t.vtbl_name = get_short_name(vftable_info_t.ea_begin);

				qstring vtbl_info_str;
#ifndef  __EA64__
				vtbl_info_str.cat_sprnt(" 0x%0x - 0x%0x:  %s  methods count: %d", vftable_info_t.ea_begin, vftable_info_t.ea_end, vftable_info_t.vtbl_name.c_str(), vftable_info_t.methods);
#else
				vtbl_info_str.cat_sprnt(" 0x%016llx - 0x%016llx:  %s  methods count: %d", vftable_info_t.ea_begin, vftable_info_t.ea_end, vftable_info_t.vtbl_name.c_str(), vftable_info_t.methods);
#endif // !#ifndef __EA64__

				
			
				vtbl_list.push_back(vtbl_info_str);
				vtbl_t_list.push_back(vftable_info_t);
			}
			
			ea_sect = vftable_info_t.ea_end;
			return;
		}
	}

	// nothing found: increment ea_sect by size of the pointer to continue search at the next location
	ea_sect += sizeof(ea_t);
	return;
}

//---------------------------------------------------------------------------
// Get vtable structure from the list by address
//---------------------------------------------------------------------------
bool get_vbtbl_by_ea(ea_t vtbl_addr, VTBL_info_t &vtbl) {
	bool result = false;

	search_objects(false);

	qvector <VTBL_info_t>::iterator vtbl_iter;
	for (vtbl_iter = vtbl_t_list.begin(); vtbl_iter != vtbl_t_list.end(); vtbl_iter++) {
		if ((*vtbl_iter).ea_begin == vtbl_addr) {
			vtbl =  *vtbl_iter;
			result = true;
			break;
		}
	}

	return result;
}

//---------------------------------------------------------------------------
// Create a structurte in IDA local types which represents vtable
//---------------------------------------------------------------------------
tid_t create_vtbl_struct(ea_t vtbl_addr, ea_t vtbl_addr_end, char* vtbl_name, uval_t idx, unsigned int* vtbl_len)
{
	qstring struc_name = vtbl_name;
	tid_t id = add_struc(BADADDR, struc_name.c_str());
	
	if (id == BADADDR) {
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

	while (ea < vtbl_addr_end) {
		offset = ea - vtbl_addr;
		qstring method_name;
		ea_t method_ea = getEa(ea);

		if (method_ea == 0) break;
		if (!isEnabled(method_ea)) break;

		flags_t method_flags = getFlags(method_ea);
		char* struc_member_name = NULL;
		if (isFunc(method_flags)) {
			method_name = get_short_name(method_ea);
			if (method_name.length() != 0)
				struc_member_name = (char*)method_name.c_str();
		}
#ifndef __EA64__
		add_struc_member(new_struc, NULL, offset, dwrdflag(), NULL, sizeof(ea_t));
#else
		add_struc_member(new_struc, NULL, offset, qwrdflag(), NULL, sizeof(ea_t));
#endif
		if (struc_member_name) {
			if (!set_member_name(new_struc, offset, struc_member_name)) {
				get_ea_name(&method_name, method_ea);
				set_member_name(new_struc, offset, struc_member_name);
			}
		}

		ea = ea + sizeof(ea_t);
		flags_t ea_flags = getFlags(ea);

		if (has_any_name(ea_flags)) break;
	}

	return id;
}


void find_vtables_rtti()
{
	logmsg(DEBUG, "\nprocess_rtti()\n");

	// get rtti_vftables map using rtti data
	getRttiData();

	// store this inormation in the lists
	for (std::map<ea_t, vftable::vtinfo>::iterator it = rtti_vftables.begin(); it != rtti_vftables.end() ; it ++ ) {
		VTBL_info_t vftable_info_t;
		vftable_info_t.ea_begin = it->second.start;
		vftable_info_t.ea_end = it->second.end;
		vftable_info_t.methods = it->second.methodCount;
		vftable_info_t.vtbl_name = it->second.type_info;

		qstring vtbl_info_str;
		vtbl_info_str.cat_sprnt(" 0x%x - 0x%x:  %s  methods count: %d", vftable_info_t.ea_begin, vftable_info_t.ea_end, vftable_info_t.vtbl_name.c_str(), vftable_info_t.methods);
			
		vtbl_list.push_back(vtbl_info_str);
		vtbl_t_list.push_back(vftable_info_t);
	}
}


//---------------------------------------------------------------------------
// Find vtables in the binary
//---------------------------------------------------------------------------
void find_vtables()
{
	// set of the processed segments
	std::set<segment_t *> segSet;

	// start with .rdata section
	logmsg(DEBUG, "search_objects() - going for .rdata");
	if (segment_t *seg = get_segm_by_name(".rdata")) {
		logmsg(DEBUG, "search_objects() - .rdata exist");

		segSet.insert(seg);
		
		ea_t ea_text = seg->startEA;
		while (ea_text <= seg->endEA)
			process_vtbl(ea_text);

	} else {
		logmsg(DEBUG, "search_objects() - .rdata does not exist");
	}

	// look also at .data section
	logmsg(DEBUG, "search_objects() - going for .data");
	int segCount = get_segm_qty();
	{
		for (int i = 0; i < segCount; i++) {
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
								logmsg(DEBUG, "search_objects() - .data exist");
								segSet.insert(seg);
								ea_t ea_text = seg->startEA;
								while (ea_text <= seg->endEA)
									process_vtbl(ea_text);
							}
						}
					}
				}
			}
		}
		

        // If still none found, try any remaining data type segments
        if (vtbl_t_list.empty())
        {
			logmsg(DEBUG, "search_objects() - going for other data sections");
            for (int i = 0; i < segCount; i++)
            {
                if (segment_t *seg = getnseg(i))
                {
                    if (seg->type == SEG_DATA)
                    {
                        if (segSet.find(seg) == segSet.end())
                        {
							segSet.insert(seg);
                            ea_t ea_text = seg->startEA;
							while (ea_text <= seg->endEA)
								process_vtbl(ea_text);
                        }
                    }
                }
            }
        }
	}
}


//---------------------------------------------------------------------------
// Handle VTBL & RTTI 
//---------------------------------------------------------------------------

bool bScaned = false;

void search_objects(bool bForce)
{
	if (!bScaned || bForce) {
		logmsg(DEBUG, "search_objects()");

		// free previously found objects
		free_vtable_lists();

		// first search vtables using rtti information
		find_vtables_rtti();
		
		// find all the other vtables
		find_vtables();
	
		bScaned = true;
	}
}


//---------------------------------------------------------------------------
// IDA Custom View Window Initialization 
//---------------------------------------------------------------------------

static int current_line_pos = 0;

static bool idaapi make_vtbl_struct_cb(void *ud)
{	
	VTBL_info_t vtbl_t = vtbl_t_list[current_line_pos];
	tid_t id = add_struc(BADADDR, vtbl_t.vtbl_name.c_str());

	create_vtbl_struct(vtbl_t.ea_begin, vtbl_t.ea_end, (char*)vtbl_t.vtbl_name.c_str(), id);

	return true;
}



// Popup window with VTBL XREFS
qvector<qstring> xref_list;
qvector<ea_t> xref_addr;
static void get_xrefs_to_vtbl()
{
	ea_t cur_vt_ea = vtbl_t_list[current_line_pos].ea_begin;
	for (ea_t addr = get_first_dref_to(cur_vt_ea); addr != BADADDR; addr = get_next_dref_to(cur_vt_ea, addr))
	{
		qstring name;
		get_func_name2(&name, addr);

		xref_addr.push_back(addr);

		qstring tmp;
		tmp.cat_sprnt(" 0x%x:  %s", addr, name.c_str());
		xref_list.push_back(tmp);
	}
}


static bool idaapi ct_vtbl_xrefs_window_dblclick(TCustomControl *v, int shift, void *ud)
{
	int x, y;
	place_t *place = get_custom_viewer_place(v, true, &x, &y);
	simpleline_place_t *spl = (simpleline_place_t *)place;
	int line_num = spl->n;

	ea_t cur_xref_ea = xref_addr[line_num];
	jumpto(cur_xref_ea);

	return true;
}


static bool idaapi show_vtbl_xrefs_window_cb(void *ud)
{
	get_xrefs_to_vtbl();
	if (!xref_list.empty())
	{
		HWND hwnd = NULL;
		TForm *form = create_tform(vtbl_t_list[current_line_pos].vtbl_name.c_str(), &hwnd);

		object_explorer_info_t *si = new object_explorer_info_t(form);

		qvector <qstring>::iterator xref_iter;
		for (xref_iter = xref_list.begin(); xref_iter != xref_list.end(); xref_iter++)
			si->sv.push_back(simpleline_t(*xref_iter));

		simpleline_place_t s1;
		simpleline_place_t s2(si->sv.size() - 1);
		si->cv = create_custom_viewer("", NULL, &s1, &s2, &s1, 0, &si->sv);
		si->codeview = create_code_viewer(form, si->cv, CDVF_STATUSBAR);
		set_custom_viewer_handler(si->cv, CVH_DBLCLICK, (void *)ct_vtbl_xrefs_window_dblclick);

		open_tform(form, FORM_ONTOP | FORM_RESTORE);

		return true;
	}

	warning("ObjectExplorer not found any xrefs here ...");
	logmsg(DEBUG, "ObjectExplorer not found any xrefs here ...");

	return false;
}


//////////////////////////////////////////////////////////////////////////


static void idaapi ct_object_explorer_popup(TCustomControl *v, void *ud) 
{
	set_custom_viewer_popup_menu(v, NULL);
	add_custom_viewer_popup_item(v, "Make VTBL_Srtruct", "S", make_vtbl_struct_cb, ud);
	add_custom_viewer_popup_item(v, "Show all XREFS to VTBL", "X", show_vtbl_xrefs_window_cb, ud);

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

		case 83: // S
			make_vtbl_struct_cb(ud);
			return true;

		case 88: // X
			show_vtbl_xrefs_window_cb(ud);
			return true;
		}
	}
	return false;
}


static bool idaapi ct_object_explorer_dblclick(TCustomControl *v, int shift, void *ud)
{
	int x, y;
	place_t *place = get_custom_viewer_place(v, true, &x, &y);
	simpleline_place_t *spl = (simpleline_place_t *)place;
	int line_num = spl->n;

	ea_t cur_vt_ea = vtbl_t_list[line_num].ea_begin;
	jumpto(cur_vt_ea);

	return true;
}


static qstring get_vtbl_hint(int line_num)
{
	current_line_pos = line_num;
	qstring tag_lines;

	if (isEnabled(vtbl_t_list[line_num].ea_begin))
	{
		int flags = calc_default_idaplace_flags();
		linearray_t ln(&flags);
		
		idaplace_t here;
		here.ea = vtbl_t_list[line_num].ea_begin;
		here.lnnum = 0;
		ln.set_place(&here);

		int used = 0;
		int n = ln.get_linecnt();           
		for ( int i=0; i < n; i++ )        
		{
			char hint_str[MAXSTR];
			char* line = ln.down();
			tag_remove(line, hint_str, sizeof(hint_str));
			tag_lines.cat_sprnt((COLSTR(SCOLOR_INV"%s\n", SCOLOR_DREF)), hint_str);
			used++;
			int n = qmin(ln.get_linecnt(), 20);
			used += n;
			for (int j = 0; j < n; ++j)
				tag_lines.cat_sprnt("%s\n", ln.down());
		}

	}
	return qstrdup(tag_lines.c_str());
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
				*important_lines = 20;
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
			logmsg(DEBUG, "Object Explorer window already open. Switching to it.");
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

		//custom_viewer_handlers_t cvh = custom_viewer_handlers_t(ct_object_explorer_keyboard, ct_object_explorer_popup, NULL, ct_object_explorer_click);
		custom_viewer_handlers_t cvh = custom_viewer_handlers_t();
		cvh.keyboard = ct_object_explorer_keyboard;
		cvh.popup = ct_object_explorer_popup;
		cvh.dblclick = ct_object_explorer_dblclick;
		set_custom_viewer_handlers(si->cv, &cvh, si);

		hook_to_notification_point(HT_UI, ui_object_explorer_callback, si);
		open_tform(form, FORM_TAB | FORM_MENU | FORM_RESTORE);
	}
	else {
		warning("ObjectExplorer not found any virtual tables here ...");
		logmsg(DEBUG, "ObjectExplorer not found any virtual tables here ...");
	}
}
