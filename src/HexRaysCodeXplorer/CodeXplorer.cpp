/*	Copyright (c) 2013-2016
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

#include "Common.h"
#include "CtreeGraphBuilder.h"
#include "ObjectExplorer.h"
#include "TypeReconstructor.h"
#include "TypeExtractor.h"
#include "CtreeExtractor.h"
#include "Utility.h"

#include "Debug.h"

extern plugin_t PLUGIN;

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


// Hex-Rays API pointer
hexdsp_t *hexdsp = NULL;

static bool inited = false;

// Hotkey for the new command
static const char hotkey_dg[] = "T";
static int hotcode_dg;

static const char hotkey_ce[] = "O";
static int hotcode_ce;

static const char hotkey_rt[] = "R";
static int hotcode_rt;

static const char hotkey_gd[] = "J";
static int hotcode_gd;

static const char hotkey_et[] = "S";
static int hotcode_et;

static const char hotkey_ec[] = "C";
static int hotcode_ec;

static const char hotkey_vc[] = "V";
static int hotcode_vc;

static const char hotkey_so[] = "Q"; // After positioning cursor at source code user can press Q to copy to clipboard string of form modulename + 0xoffset. 
									 // It can be useful while working with WinDbg.
static int hotcode_dq;

static const char hotkey_rv[] = "E"; // Automatic renaming of duplicating variables by pressing E. 
									 // All duplicating successors obtain _2, _3 ... postfixes.
static int hotcode_de;

static const char * crypto_prefix_param = "CRYPTO";



//--------------------------------------------------------------------------
// Helper class to build graph from ctree.
struct graph_builder_t : public ctree_parentee_t
{
	callgraph_t &cg;
	std::map<citem_t *, int> reverse;  // Reverse mapping for tests and adding edges

	graph_builder_t(callgraph_t &_cg) : cg(_cg) {}

	// overriding functions
	int add_node(citem_t *i);
	int process(citem_t *i);

	// We treat expressions and statements the same way: add them to the graph
	int idaapi visit_insn(cinsn_t *i) { return process(i); }
	int idaapi visit_expr(cexpr_t *e) { return process(e); }
};

// Add a new node to the graph
int graph_builder_t::add_node(citem_t *i)
{
	// Check if the item has already been encountered during the traversal
	if (reverse.find(i) != reverse.end())
	{
		warning("bad ctree - duplicate nodes!");
		logmsg(DEBUG, "bad ctree - duplicate nodes!");
		return -1;
	}

	// Add a node to the graph
	int n = cg.add(i);

	// Also remember the reverse mapping (citem_t* -> n)
	reverse[i] = n;

	return n;
}

// Process a ctree item
int graph_builder_t::process(citem_t *item)
{
	// Add a node for citem
	int n = add_node(item);
	if (n == -1)
		return -1; // error

	if (parents.size() > 1)             // The current item has a parent?
	{
		int p = reverse[parents.back()];    // Parent node number
											// cg.add_edge(p, n);               // Add edge from the parent to the current item
		cg.create_edge(p, n);
	}

	return 0;
}

#define DECLARE_GI_VAR \
  graph_info_t *gi = (graph_info_t *) ud

#define DECLARE_GI_VARS \
  DECLARE_GI_VAR;       \
  callgraph_t *fg = &gi->fg

//--------------------------------------------------------------------------
static int idaapi gr_callback(void *ud, int code, va_list va)
{
	bool result = false;
	switch (code)
	{
		// refresh user-defined graph nodes and edges
	case grcode_user_refresh:
		// in:  mutable_graph_t *g
		// out: success
	{
		DECLARE_GI_VARS;
		func_t *f = get_func(gi->func_ea);
		if (f == NULL)
			break;

		graph_builder_t gb(*fg);       // Graph builder helper class
		gb.apply_to(&gi->vu->cfunc->body, NULL);

		mutable_graph_t *mg = va_arg(va, mutable_graph_t *);

		// we have to resize
		mg->resize(fg->count());

		callgraph_t::edge_iterator end = fg->end_edges();
		for (callgraph_t::edge_iterator it = fg->begin_edges();
		it != end;
			++it)
		{
			mg->add_edge(it->id1, it->id2, NULL);
		}

		fg->clear_edges();
		result = true;
	}
	break;

	// retrieve text for user-defined graph node
	case grcode_user_text:
		//mutable_graph_t *g
		//      int node
		//      const char **result
		//      bgcolor_t *bg_color (maybe NULL)
		// out: must return 0, result must be filled
		// NB: do not use anything calling GDI!
	{
		DECLARE_GI_VARS;
		va_arg(va, mutable_graph_t *);
		int node = va_arg(va, int);
		const char **text = va_arg(va, const char **);
		bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);

		callgraph_t::nodeinfo_t *ni = fg->get_info(node);
		result = ni != NULL;
		if (result)
		{
			*text = ni->name.c_str();
			if (bgcolor != NULL)
				*bgcolor = ni->color;
		}
	}
	break;

	case grcode_user_hint:
	{
		DECLARE_GI_VARS;
		va_arg(va, mutable_graph_t *);
		int mousenode = va_argi(va, int);
		int to = va_argi(va, int);
		int from = va_argi(va, int);
		char **hint = va_arg(va, char **);

		callgraph_t::nodeinfo_t *ni = fg->get_info(mousenode);
		result = ni != NULL;
		if (result && ni->ea != BADADDR)
		{
			qstring s = get_text_disasm(ni->ea);
			*hint = qstrdup(s.c_str());
		}
	}
	break;

	case grcode_dblclicked:
	{
		DECLARE_GI_VARS;
		graph_viewer_t *v = va_arg(va, graph_viewer_t *);
		selection_item_t *s = va_arg(va, selection_item_t *);

		callgraph_t::nodeinfo_t *ni = fg->get_info(s->node);
		result = ni != NULL;
		if (result && s->is_node && ni->ea != BADADDR)
			jumpto(ni->ea);
	}
	break;

	}
	return (int)result;
}


// Display ctree graph for current decompiled function
static bool idaapi display_ctree_graph(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;

	// Determine the ctree item to highlight
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;
	graph_info_t *gi = graph_info_t::create(vu.cfunc->entry_ea, highlight);

	netnode id;
	id.create();

	qstring title = gi->title;

	HWND hwnd = NULL;
	TForm *form = create_tform(title.c_str(), &hwnd);
	if (hwnd == NULL)
	{
		warning("Ctree Graph window already open. Switching to it.");
		logmsg(DEBUG, "Ctree Graph window already open. Switching to it.");
		form = find_tform(title.c_str());
		if (form != NULL)
			switchto_tform(form, true);
		return true;
	}

	if (hwnd != NULL)
	{
		gi->vu = (vdui_t *)ud;
		gi->form = form;
		gi->gv = create_graph_viewer(form, id, gr_callback, gi, 0);
		open_tform(form, FORM_TAB | FORM_MENU | FORM_QWIDGET);

		viewer_fit_window(gi->gv);
	}

	return true;
}


// Get pointer to func_t by routine name
func_t * get_func_by_name(const char *func_name)
{
	func_t * result_func = NULL;
	size_t func_total = get_func_qty();
	if (func_total > 0)
	{
		char tmp[1024];
		for (unsigned int i = 0; i < func_total - 1; i++)
		{
			func_t * func = getn_func(i);
			if (func != NULL)
			{
				memset(tmp, 0x00, sizeof(tmp));
				char *func_n = get_func_name(func->startEA, tmp, sizeof(tmp));
				if (func_n != NULL)
				{
					if (!strcmp(func_name, func_n))
					{
						result_func = func;
						break;
					}
				}
			}
		}
	}
	return result_func;
}


static char* get_expr_name(citem_t *citem)
{
	static char citem_name[MAXSTR];
	memset(citem_name, 0x00, sizeof(citem_name));
	if (citem->is_expr())
	{
		cexpr_t *e = (cexpr_t *)citem;

		// retrieve the name of the routine
		e->print1(citem_name, sizeof(citem_name), NULL);
		tag_remove(citem_name, citem_name, MAXSTR);

		return citem_name;
	}
	return citem_name;
}


static bool idaapi decompile_func(vdui_t &vu)
{
	// Determine the ctree item to highlight
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;

	if (highlight != NULL)
	{
		// if it is an expression
		if (highlight->is_expr())
		{
			cexpr_t *e = (cexpr_t *)highlight;

			char *citem_name = get_expr_name(highlight);
			char *proc_name = citem_name + strlen(citem_name);

			while ((proc_name > citem_name) && (*(proc_name - 1) != '>'))
				proc_name--;

			if (proc_name != citem_name) 
			{
				func_t * func = get_func_by_name(proc_name);
				if (func != NULL)
					vdui_t * decompiled_window = open_pseudocode(func->startEA, -1);
			}
		}
	}

	return true;
}

/*
* TODO: Make changes persistent
*/


lvars_t* lvars;
lvar_t lv;
map<lvar_t*, qstring> to_rename;

static bool idaapi rename_simple_expr(void *ud) 
{
	vdui_t &vu = *(vdui_t *)ud;
	cfuncptr_t pfunc = vu.cfunc;

	lvars = pfunc->get_lvars();

	struct ida_local renamer_t : public ctree_visitor_t
	{
#define ROOT "*&|"

		map<qstring, int> valid_rvars;
		map<qstring, int> postfixes;
		map<qstring, vector<qstring>> roots;

		renamer_t(void) : ctree_visitor_t(CV_FAST) {}

		qstring rvar_depends_on(cexpr_t* e) {
			qstring rvar_name = (*lvars)[e->y->v.idx].name;
			map<qstring, vector<qstring>>::iterator it;
			for (it = roots.begin(); it != roots.end(); it++) 
			{
				if (it->first == rvar_name)
					return ROOT;
				vector<qstring>::iterator yt;
				for (yt = it->second.begin(); yt != it->second.end(); yt++) 
				{
					if (*yt == rvar_name)
						return it->first;
				}
			}
			return ROOT;
		}

		int idaapi visit_expr(cexpr_t *e)
		{
			char pstx_buf[8];
			qstring new_name;
			qstring lvar_name, rvar_name, tvar_name;
			if (e->op == cot_asg && e->x->op == cot_var && e->y->op == cot_var)
			{
				lvar_name = (*lvars)[e->x->v.idx].name;
				rvar_name = (*lvars)[e->y->v.idx].name;
				tvar_name = rvar_depends_on(e);
				if (tvar_name == ROOT) 
				{
					//rvar is root variable
					if (rvar_name != lvar_name)
						roots[rvar_name].push_back(lvar_name);
				}
				else 
				{
					//rvar is dependant
					if (tvar_name != lvar_name) 
					{
						rvar_name = tvar_name;
						roots[tvar_name].push_back(lvar_name);
					}
				}

				for (int i = 0; i < roots[lvar_name].size(); i++) 
				{
					if (roots[lvar_name][i] == rvar_name) 
						return 0;
				}

				postfixes.insert(pair<qstring, int>(rvar_name, 2));
				sprintf(pstx_buf, "%d",postfixes[rvar_name]++);
				new_name = rvar_name + "_" + pstx_buf;
				to_rename[&(*lvars)[e->x->v.idx]] = new_name;
				roots[rvar_name].push_back(new_name);
			}
			return 0;
		}
	};
	renamer_t zc;
	zc.apply_to(&pfunc->body, NULL);
	for (map<lvar_t*, qstring>::iterator it = to_rename.begin(); it != to_rename.end(); it++)
		vu.rename_lvar(it->first, it->second.c_str(), 0);
	vu.refresh_ctext();
	return true;
}

static bool idaapi show_offset_in_windbg_format(void *ud) {
	char _offset[32] = { 0 };
	char module_name[256] = { 0 };
	qstring result;
	int offset;
	vdui_t &vu = *(vdui_t *)ud;
	vu.get_current_item(USE_KEYBOARD);
	offset = vu.item.i->ea - get_imagebase();

	if (offset < 0) 
	{
		info("Locate pointer after = sign or at operand of function\n");
		return false;
	}

	get_root_filename(module_name, 255);
	for (int i = 0; i < 255; i++)
		if (module_name[i] == '.') { module_name[i] = 0; break; }
	sprintf(_offset, "%x", offset);
	result.cat_sprnt("%s+0x%s", module_name, _offset);

	qstring title {0};
	title.cat_sprnt("0x%X", vu.item.i->ea);
	show_string_in_custom_view(&vu, title, result);

#if defined (__LINUX__) || defined (__MAC__)
	msg(result.c_str());
#else
	OpenClipboard(0); 
	EmptyClipboard();
	HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, result.size());

	if (!hg) 
	{
		CloseClipboard(); 
		msg("Can't alloc\n");
		return -2;
	}

	CopyMemory(GlobalLock(hg), result.c_str(), result.size());
	GlobalUnlock(hg);
	SetClipboardData(CF_TEXT, hg);
	CloseClipboard();
	GlobalFree(hg);
#endif
	return true;
}

// show disassembly line for ctree->item
static bool idaapi decompiled_line_to_disasm(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
	vu.ctree_to_disasm();

	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;

	return true;
}


// extract ctree to custom view
static bool idaapi show_current_citem_in_custom_view(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight_item = vu.item.is_citem() ? vu.item.e : NULL;
	ctree_dumper_t ctree_dump;

	if (highlight_item != NULL)
	{
		char ctree_item[MAXSTR];
		ctree_dump.parse_ctree_item(highlight_item, ctree_item, MAXSTR);

		if (highlight_item->is_expr())
		{
			cexpr_t *e = (cexpr_t *)highlight_item;
			qstring item_name = get_expr_name(highlight_item);
			show_citem_custom_view(&vu, ctree_item, item_name);
		}
	}
	return true;
}


// display Object Explorer
static bool idaapi display_vtbl_objects(void *ud)
{
	if (isMSVC())
	{
		vdui_t &vu = *(vdui_t *)ud;
		search_objects();
		object_explorer_form_init();
		return true;
	}

	info("CodeXplorer doesn't support parsing of not MSVC VTBL's");
	return false;
}


//--------------------------------------------------------------------------
// This callback handles various hexrays events.
static int idaapi callback(void *, hexrays_event_t event, va_list va)
{
	switch (event)
	{
	case hxe_right_click:
	{
		vdui_t &vu = *va_arg(va, vdui_t *);
		// add new command to the popup menu
		add_custom_viewer_popup_item(vu.ct, "Display Ctree Graph", hotkey_dg, display_ctree_graph, &vu);
		add_custom_viewer_popup_item(vu.ct, "Object Explorer", hotkey_ce, display_vtbl_objects, &vu);
		add_custom_viewer_popup_item(vu.ct, "REconstruct Type", hotkey_rt, reconstruct_type, &vu);
		add_custom_viewer_popup_item(vu.ct, "Extract Types to File", hotkey_et, extract_all_types, &vu);
		add_custom_viewer_popup_item(vu.ct, "Extract Ctrees to File", hotkey_ec, extract_all_ctrees, &vu);
		add_custom_viewer_popup_item(vu.ct, "Ctree Item View", hotkey_vc, show_current_citem_in_custom_view, &vu);
		add_custom_viewer_popup_item(vu.ct, "Jump to Disasm", hotkey_gd, decompiled_line_to_disasm, &vu);
		add_custom_viewer_popup_item(vu.ct, "Show/Copy item offset", hotkey_so, show_offset_in_windbg_format, &vu);
		add_custom_viewer_popup_item(vu.ct, "Rename vars", hotkey_rv, rename_simple_expr, &vu);
	}
	break;

	case hxe_keyboard:
	{
		vdui_t &vu = *va_arg(va, vdui_t *);
		int keycode = va_arg(va, int);
		// check for the hotkey
		if (keycode == hotcode_dg)
			return display_ctree_graph(&vu);
		if (keycode == hotcode_ce)
			return display_vtbl_objects(&vu);
		if (keycode == hotcode_rt)
			return reconstruct_type(&vu);
		if (keycode == hotcode_et)
			return extract_all_types(&vu);
		if (keycode == hotcode_ec)
			return extract_all_ctrees(&vu);
		if (keycode == hotcode_vc)
			return show_current_citem_in_custom_view(&vu);
		if (keycode == hotcode_gd)
			return decompiled_line_to_disasm(&vu);
		if (keycode == hotcode_dq)
			return show_offset_in_windbg_format(&vu);
		if (keycode == hotcode_de)
			return rename_simple_expr(&vu);
	}
	break;

	case hxe_double_click:
	{
		vdui_t &vu = *va_arg(va, vdui_t *);
		decompile_func(vu);
	}
	break;
	default:
		break;
	}
	return 0;
}

void parse_plugin_options(qstring &options, bool &dump_types, bool &dump_ctrees, qstring &crypto_prefix) {
	qvector<qstring> params;
	qstring splitter = ":";
	split_qstring(options, splitter, params);

	dump_types = false;
	dump_ctrees = false;
	crypto_prefix = "";

	for (qvector<qstring>::iterator param_iter = params.begin(); param_iter != params.end(); param_iter++) {
		if ((*param_iter) == "dump_types") {
			dump_types = true;
		}
		else if ((*param_iter) == "dump_ctrees") {
			dump_ctrees = true;
		}
		else if (((*param_iter).length() > strlen(crypto_prefix_param)) && ((*param_iter).find(crypto_prefix_param) == 0)) {
			crypto_prefix = (*param_iter).substr(strlen(crypto_prefix_param));
		}
		else {
			qstring message = "Invalid argument: ";
			message += (*param_iter) + "\n";
			logmsg(INFO, message.c_str());
		}
	}
}



//--------------------------------------------------------------------------
// Initialize the plugin.
int idaapi init(void)
{
	logmsg(INFO, "\nHexRaysCodeXplorer plugin by @REhints loaded.\n\n\n");

	if (!init_hexrays_plugin())
		return PLUGIN_SKIP; // no decompiler

	bool dump_types = false,
		dump_ctrees = false;
	qstring crypto_prefix;

	qstring options = get_plugin_options(PLUGIN.wanted_name);
	parse_plugin_options(options, dump_types, dump_ctrees, crypto_prefix);

	install_hexrays_callback(callback, NULL);
	const char *hxver = get_hexrays_version();
	logmsg(INFO, "Hex-rays version %s has been detected, %s ready to use\n", hxver, PLUGIN.wanted_name);
	inited = true;
	hotcode_dg = 84; // T
	hotcode_ce = 79; // O
	hotcode_rt = 82; // R
	hotcode_gd = 74; // J
	hotcode_et = 83; // S
	hotcode_ec = 67; // C
	hotcode_vc = 86; // V
	hotcode_dq = 81; // Q
	hotcode_de = 69; // E

	static const char hotkey_vc[] = "V";
	static int hotcode_vc;

	if (dump_ctrees || dump_types) {
		autoWait();

		if (dump_types) {
			qstring options_msg = "Dumping types\n";
			logmsg(DEBUG, options_msg.c_str());
			extract_all_types(NULL);

			int file_id = qcreate("codexplorer_types_done", 511);
			if (file_id != -1)
				qclose(file_id);
		}

		if (dump_ctrees) {
			logmsg(DEBUG, "Dumping ctrees\n");
			dump_funcs_ctree(NULL, crypto_prefix);

			int file_id = qcreate("codexplorer_ctrees_done", 511);
			if (file_id != -1)
				qclose(file_id);
		}

		logmsg(INFO, "\nHexRaysCodeXplorer plugin by @REhints exiting...\n\n\n");
		//qexit(0);
	}

	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
	if (inited)
	{
		logmsg(INFO, "\nHexRaysCodeXplorer plugin by @REhints terminated.\n\n\n");
		remove_hexrays_callback(callback, NULL);
		term_hexrays_plugin();
	}
}

//--------------------------------------------------------------------------
void idaapi run(int)
{
	// This function won't be called because our plugin is invisible (no menu
	// item in the Edit, Plugins menu) because of PLUGIN_HIDE
}

//--------------------------------------------------------------------------
static char comment[] = "HexRaysCodeXplorer plugin by @REhints";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_HIDE,          // plugin flags
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	comment,              // long comment about the plugin
						  // it could appear in the status line or as a hint
	"",                   // multiline help about the plugin
	"HexRaysCodeXplorer by @REhints", // the preferred short name of the plugin (PLUGIN.wanted_name)
	""                    // the preferred hotkey to run the plugin
};
