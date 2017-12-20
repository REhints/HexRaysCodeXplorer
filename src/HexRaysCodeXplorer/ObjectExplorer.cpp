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
#include "GCCObjectFormatParser.h"
#include "Utility.h"

#include "Debug.h"

#include <functional>

#if !defined (__LINUX__) && !defined (__MAC__)
#include <tchar.h>
#else
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif


qvector <VTBL_info_t> vtbl_t_list;	// list of vtables found in the binary
qvector <qstring> vtbl_list;		// list of string for ObjectExplrer vtables view

std::map<ea_t, VTBL_info_t> rtti_vftables;

void free_vtable_lists() {
	vtbl_t_list.clear();
	vtbl_list.clear();
}


//---------------------------------------------------------------------------
// VTBL code parsing
//---------------------------------------------------------------------------

bool get_text_disasm(ea_t ea, qstring& rv) {
	rv.clear();

	if (!generate_disasm_line(&rv, ea))
		return false;

	tag_remove(&rv);

	return true;
}

static bool check_vtable_load_instruction(ea_t ea_code) {

	qstring dism;
	if (!get_text_disasm(ea_code, dism))
		return false;

	if (dism.find("mov ") == 0 && dism.find(" offset ") != dism.npos)
		return true;

	if (dism.find("lea") == 0)
		return true;

	return false;
}

//---------------------------------------------------------------------------
// Try to find vtable at the specified address
//---------------------------------------------------------------------------
static bool get_vtbl_info(ea_t ea_address, VTBL_info_t &vtbl_info)
{
	flags_t flags = get_flags(ea_address);
	if (has_xref(flags) && has_any_name(flags) && (isEa(flags) || is_unknown(flags))) {
		bool is_move_xref = false;

		ea_t ea_code_ref = get_first_dref_to(ea_address);
		if(ea_code_ref && ea_code_ref != BADADDR) {
			do {
				if(is_code(get_flags(ea_code_ref)) && check_vtable_load_instruction(ea_code_ref)) {
					is_move_xref = true;
					break;
				}

				ea_code_ref = get_next_dref_to(ea_address, ea_code_ref);

			} while(ea_code_ref && ea_code_ref != BADADDR);
		}

		if(is_move_xref) {
			ZeroMemory(&vtbl_info, sizeof(VTBL_info_t));

			get_ea_name(&vtbl_info.vtbl_name, ea_address);

			ea_t ea_start = vtbl_info.ea_begin = ea_address;

			while(true) {
				flags_t index_flags = get_flags(ea_address);
				if(!(isEa(index_flags) || is_unknown(index_flags)))
					break;

				ea_t ea_index_value = getEa(ea_address);
				if(!ea_index_value || ea_index_value == BADADDR)
					break;

				if (ea_address != ea_start && has_xref(index_flags))
					break;

				flags_t value_flags = get_flags(ea_index_value);
				if(!is_code(value_flags)) {
					break;
				} else {
					if(is_unknown(index_flags)) {
#ifndef __EA64__
						create_dword(ea_address, sizeof(ea_t));
#else
						create_qword(ea_address, sizeof(ea_t));
#endif
					}
				}

				ea_address += sizeof(ea_t);
			}

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
	struc_name += "::vtable";
	tid_t id = add_struc(BADADDR, struc_name.c_str());

	if (id == BADADDR) {
		struc_name.clear();
		if (!ask_str(&struc_name, HIST_IDENT, "Default name %s not correct. Enter other structure name: ", struc_name.c_str()))
			return BADNODE;
		id = add_struc(BADADDR, struc_name.c_str());
		set_struc_cmt(id, vtbl_name, true);
	}

	struc_t* new_struc = get_struc(id);
	if (!new_struc)
		return BADNODE;

	ea_t ea = vtbl_addr;
	ea_t offset = 0;

	while (ea < vtbl_addr_end) {
		offset = ea - vtbl_addr;
		qstring method_name;
		ea_t method_ea = getEa(ea);

		if (ph.id == PLFM_ARM)
		{
			method_ea &= (ea_t)-2;
		}

		if (method_ea == 0)
		{
			ea = ea + sizeof(ea_t);
			continue;
		}
		if (!is_mapped(method_ea))
			break;

		flags_t method_flags = get_flags(method_ea);
		const char* struc_member_name = nullptr;
		if (is_func(method_flags)) {
			method_name = get_short_name(method_ea);
			if (!method_name.empty())
				struc_member_name = method_name.c_str();
		}
#ifndef __EA64__
		add_struc_member(new_struc, NULL, offset, dword_flag(), NULL, sizeof(ea_t));
#else
		add_struc_member(new_struc, NULL, offset, qword_flag(), NULL, sizeof(ea_t));
#endif
		if (struc_member_name) {
			if (!set_member_name(new_struc, offset, struc_member_name)) {
				get_ea_name(&method_name, method_ea);
				set_member_name(new_struc, offset, struc_member_name);
			}
		}

		ea = ea + sizeof(ea_t);
		flags_t ea_flags = get_flags(ea);

		if (has_any_name(ea_flags))
			break;
	}

	return id;
}


void find_vtables_rtti()
{
	logmsg(DEBUG, "\nprocess_rtti()\n");

	if (!objectFormatParser && !initObjectFormatParser())
		return;

	// get rtti_vftables map using rtti data
	objectFormatParser->getRttiInfo();

	// store this inormation in the lists
	for (std::map<ea_t, VTBL_info_t>::iterator it = rtti_vftables.begin(); it != rtti_vftables.end(); it++) {
		VTBL_info_t vftable_info_t;
		vftable_info_t.ea_begin = it->second.ea_begin;
		vftable_info_t.ea_end = it->second.ea_end;
		vftable_info_t.methods = it->second.methods;
		vftable_info_t.vtbl_name = it->second.vtbl_name;

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
	logmsg(DEBUG, "search_objects() - going for .rdata\n");
	if (segment_t *seg = get_segm_by_name(".rdata")) {
		logmsg(DEBUG, "search_objects() - .rdata exist\n");

		segSet.insert(seg);

		ea_t ea_text = seg->start_ea;
		while (ea_text <= seg->end_ea)
			process_vtbl(ea_text);

	} else {
		logmsg(DEBUG, "search_objects() - .rdata does not exist\n");
	}

	// look also at .data section
	logmsg(DEBUG, "search_objects() - going for .data\n");
	int segCount = get_segm_qty();
	qstring segm_name;

	for (int i = 0; i < segCount; i++) {
		segment_t *seg = getnseg(i);
		if (!seg || seg->type != SEG_DATA)
			continue;

		if (segSet.find(seg) == segSet.end())
		{
			if (get_segm_name(&segm_name, seg) > 0 && segm_name == ".data")
			{
				logmsg(DEBUG, "search_objects() - .data exist\n");
				segSet.insert(seg);
				ea_t ea_text = seg->start_ea;
				while (ea_text <= seg->end_ea)
					process_vtbl(ea_text);
			}
		}
	}

	// If still none found, try any remaining data type segments
	if (vtbl_t_list.empty())
	{
		logmsg(DEBUG, "search_objects() - going for other data sections\n");
		for (int i = 0; i < segCount; i++)
		{
			segment_t *seg = getnseg(i);
			if (!seg || seg->type != SEG_DATA)
				continue;

			if (segSet.find(seg) == segSet.end())
			{
				segSet.insert(seg);
				ea_t ea_text = seg->start_ea;
				while (ea_text <= seg->end_ea)
					process_vtbl(ea_text);
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

bool idaapi make_vtbl_struct_cb()
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
		get_func_name(&name, addr);

		xref_addr.push_back(addr);

		qstring tmp;
		tmp.cat_sprnt(" 0x%x:  %s", addr, name.c_str());
		xref_list.push_back(tmp);
	}
}


static bool idaapi ct_vtbl_xrefs_window_dblclick(TWidget *v, int shift, void *ud)
{
	int x, y;
	place_t *place = get_custom_viewer_place(v, true, &x, &y);
	simpleline_place_t *spl = (simpleline_place_t *)place;
	int line_num = spl->n;

	if (line_num < 0 || line_num >= static_cast<int>(xref_addr.size()))
		return false;

	ea_t cur_xref_ea = xref_addr[line_num];

	return jumpto(cur_xref_ea);
}


bool idaapi show_vtbl_xrefs_window_cb()
{
	get_xrefs_to_vtbl();

	if (xref_list.empty())
	{
		warning("ObjectExplorer not found any xrefs here ...\n");
		logmsg(DEBUG, "ObjectExplorer not found any xrefs here ...\n");

		return false;
	}

	TWidget *widget = create_empty_widget(vtbl_t_list[current_line_pos].vtbl_name.c_str());

	object_explorer_info_t *si = new object_explorer_info_t(widget);

	for (const qstring& xref : xref_list)
		si->sv.push_back(simpleline_t(xref));

	simpleline_place_t s1;
	simpleline_place_t s2(static_cast<int>(si->sv.size()) - 1);
	si->cv = create_custom_viewer("", &s1, &s2, &s1, nullptr, &si->sv, nullptr, nullptr, widget);
	si->codeview = create_code_viewer(si->cv, CDVF_STATUSBAR, widget);
	set_custom_viewer_handler(si->cv, CVH_DBLCLICK, (void *)ct_vtbl_xrefs_window_dblclick);
	display_widget(widget, WOPN_ONTOP | WOPN_RESTORE);

	return true;
}


//////////////////////////////////////////////////////////////////////////


static bool idaapi ct_object_explorer_keyboard(TWidget * /*v*/, int key, int shift, void *ud)
{
	if (shift == 0)
	{
		object_explorer_info_t *si = (object_explorer_info_t *)ud;
		switch (key)
		{
		case IK_ESCAPE:
			close_widget(si->widget, WOPN_CLOSED_BY_ESC);
			return true;

		case 83: // S
			make_vtbl_struct_cb();
			return true;

		case 88: // X
			show_vtbl_xrefs_window_cb();
			return true;
		}
	}
	return false;
}


static bool idaapi ct_object_explorer_dblclick(TWidget *v, int shift, void *ud)
{
	int x, y;
	place_t *place = get_custom_viewer_place(v, true, &x, &y);
	simpleline_place_t *spl = (simpleline_place_t *)place;
	int line_num = spl->n;

	if (line_num < 0 || line_num >= static_cast<int>(vtbl_t_list.size()))
		return false;

	ea_t cur_vt_ea = vtbl_t_list[line_num].ea_begin;

	return jumpto(cur_vt_ea);
}


static qstring get_vtbl_hint(int line_num)
{
	current_line_pos = line_num;
	qstring tag_lines;

	if (is_mapped(vtbl_t_list[line_num].ea_begin))
	{
		int flags = calc_default_idaplace_flags();
		linearray_t ln(&flags);

		idaplace_t here;
		here.ea = vtbl_t_list[line_num].ea_begin;
		here.lnnum = 0;
		ln.set_place(&here);

		int used = 0;
		for (int i = 0; i < ln.get_linecnt(); i++)
		{
			qstring line = *ln.down();
			tag_remove(&line);

			tag_lines.cat_sprnt((COLSTR(SCOLOR_INV"%s\n", SCOLOR_DREF)), line.c_str());
			used++;
			int n = qmin(ln.get_linecnt(), 20);
			used += n;
			for (int j = 0; j < n; ++j)
				tag_lines.cat_sprnt("%s\n", ln.down()->c_str());
		}
	}
	return tag_lines;
}


ssize_t idaapi ui_object_explorer_callback(void *ud, int code, va_list va)
{
	object_explorer_info_t *si = (object_explorer_info_t *)ud;
	switch (code)
	{
		case ui_get_custom_viewer_hint:
		{
			TWidget *viewer	= va_arg(va, TWidget *);
			place_t *place = va_arg(va, place_t *);
			int *important_lines = va_arg(va, int *);
			qstring &hint = *va_arg(va, qstring *);

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
		case ui_widget_invisible:
		{
			TWidget *f = va_arg(va, TWidget *);
			if ( f == si->widget )
			{
				delete si;
				unhook_from_notification_point(HT_UI, ui_object_explorer_callback, NULL);
			}
		}
		break;

		case ui_populating_widget_popup:
		{
			TWidget* viewer = va_arg(va, TWidget *);
			TPopupMenu* popup = va_arg(va, TPopupMenu *);
			if (si->widget == viewer || si->cv == viewer)
			{
				attach_action_to_popup(viewer, popup, "codexplorer::make_vtbl_struct");
				attach_action_to_popup(viewer, popup, "codexplorer::show_vtbl_xrefs_window");
			}
		}
		break;
	}
	return 0;
}

struct HandlerCBAction_t : public action_handler_t
{
	typedef std::function<bool()> handler_t;

	handler_t handler_;

	HandlerCBAction_t(handler_t handler)
		: handler_(handler)
	{}

	virtual int idaapi activate(action_activation_ctx_t* ctx)
	{
		return handler_() ? 1 : 0;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*)
	{
		return AST_ENABLE_ALWAYS;
	}
};

static HandlerCBAction_t kMakeVTBLStructActionHandler{ make_vtbl_struct_cb };
static HandlerCBAction_t kShowVTBLXrefsWindowActionHandler{ show_vtbl_xrefs_window_cb };

static const action_desc_t kMakeVTBLStrucActionDesc = ACTION_DESC_LITERAL("codexplorer::make_vtbl_struct",
	"Make VTBL_Struct", &kMakeVTBLStructActionHandler, "S", NULL, -1);
static const action_desc_t kShowVTBLXrefsWindowActionDesc = ACTION_DESC_LITERAL("codexplorer::show_vtbl_xrefs_window",
	"Show all XREFS to VTBL", &kShowVTBLXrefsWindowActionHandler, "X", NULL, -1);

void object_explorer_form_init()
{
	if (vtbl_list.empty() || vtbl_t_list.empty())
	{
		warning("ObjectExplorer not found any virtual tables here ...\n");
		logmsg(DEBUG, "ObjectExplorer not found any virtual tables here ...\n");
		return;
	}

	TWidget *widget = find_widget("Object Explorer");
	if (widget)
	{
		warning("Object Explorer window already open. Switching to it.\n");
		logmsg(DEBUG, "Object Explorer window already open. Switching to it.\n");
		activate_widget(widget, true);
		return;
	}

	widget = create_empty_widget("Object Explorer");
	static bool actionsInitialized = false;
	if (!actionsInitialized)
	{
		actionsInitialized = true;
		register_action(kMakeVTBLStrucActionDesc);
		register_action(kShowVTBLXrefsWindowActionDesc);
	}
	object_explorer_info_t *si = new object_explorer_info_t(widget);

	qvector <qstring>::iterator vtbl_iter;
	for (vtbl_iter = vtbl_list.begin(); vtbl_iter != vtbl_list.end(); vtbl_iter++)
		si->sv.push_back(simpleline_t(*vtbl_iter));

	simpleline_place_t s1;
	simpleline_place_t s2(static_cast<int>(si->sv.size()) - 1);
	si->cv = create_custom_viewer("", &s1, &s2, &s1, nullptr, &si->sv, nullptr, nullptr, widget);
	si->codeview = create_code_viewer(si->cv, CDVF_STATUSBAR, widget);

	custom_viewer_handlers_t cvh = custom_viewer_handlers_t();
	cvh.keyboard = ct_object_explorer_keyboard;
	cvh.dblclick = ct_object_explorer_dblclick;
	set_custom_viewer_handlers(si->cv, &cvh, si);

	hook_to_notification_point(HT_UI, ui_object_explorer_callback, si);
	display_widget(widget, WOPN_TAB | WOPN_MENU | WOPN_RESTORE);
}
