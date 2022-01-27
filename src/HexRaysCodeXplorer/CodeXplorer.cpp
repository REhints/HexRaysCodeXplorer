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

#include "Common.h"
#include "MicrocodeExtractor.h"
#include "CtreeGraphBuilder.h"
#include "ObjectExplorer.h"
#include "TypeReconstructor.h"
#include "TypeExtractor.h"
#include "CtreeExtractor.h"
#include "Utility.h"

#include "Debug.h"
#include "IObjectFormatParser.h"
#include "MSVCObjectFormatParser.h"
#include "GCCObjectFormatParser.h"
#include "ReconstructableType.h"
#include "reconstructed_place_t.h"
#include <functional>
#include <utility>

extern plugin_t PLUGIN;

reconstructed_place_t replace_template;
int g_replace_id;

IObjectFormatParser *object_format_parser = nullptr;
#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#if IDA_SDK_VERSION < 760
// Hex-Rays API pointer
hexdsp_t *hexdsp = nullptr;
#endif

namespace {

static bool inited = false;

// Hotkey for the new command
static char hotkey_dg[] = "Ctrl-Alt-T";
static char hotkey_ce[] = "O";
static char hotkey_rt[] = "R";
static char hotkey_gd[] = "J";
static char hotkey_et[] = "S";
static char hotkey_ec[] = "C";
static char hotkey_vc[] = "V";
static char hotkey_mc[] = "Ctrl-Shift-M";
static char hotkey_so[] = "Q"; // After positioning cursor at source code user can press Q to copy to clipboard string of form modulename + 0xoffset. 
									 // It can be useful while working with WinDbg.

static char hotkey_rv[] = "E"; // Automatic renaming of duplicating variables by pressing E. 
									 // All duplicating successors obtain _2, _3 ... postfixes.

static qstring k_crypto_prefix_param = "CRYPTO";



//--------------------------------------------------------------------------
// Helper class to build graph from ctree.
struct graph_builder_t final : public ctree_parentee_t
{
	callgraph_t &cg;
	std::map<citem_t *, int> reverse;  // Reverse mapping for tests and adding edges

	explicit graph_builder_t(callgraph_t &cg) : cg(cg) {}

	// overriding functions
	int add_node(citem_t *i);
	int process(citem_t *i);

	// We treat expressions and statements the same way: add them to the graph
	int idaapi visit_insn(cinsn_t *i) override { return process(i); }
	int idaapi visit_expr(cexpr_t *e) override { return process(e); }
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
	const auto n = cg.add(i);

	// Also remember the reverse mapping (citem_t* -> n)
	reverse[i] = n;

	return n;
}

// Process a ctree item
int graph_builder_t::process(citem_t *i)
{
	// Add a node for citem
	const auto n = add_node(i);
	if (n == -1)
		return -1; // error

	if (parents.size() > 1)             // The current item has a parent?
	{
		const auto p = reverse[parents.back()];    // Parent node number
		// cg.add_edge(p, n);               // Add edge from the parent to the current item
		cg.create_edge(p, n);
	}

	return 0;
}

typedef map<lvar_t*, qstring> to_raname_t;

const qstring k_root = "*&|";

struct ida_local renamer_t final : public ctree_visitor_t
{
	to_raname_t& to_rename_;
	lvars_t& lvars_;

	renamer_t(to_raname_t& to_rename, lvars_t& lvars)
		: ctree_visitor_t(CV_FAST)
		, to_rename_(to_rename)
		, lvars_(lvars)
	{
	}

	map<qstring, int> valid_rvars;
	map<qstring, int> postfixes;
	map<qstring, vector<qstring>> roots;

	qstring rvar_depends_on(cexpr_t* e) {
		const auto rvar_name = lvars_[e->y->v.idx].name;
		for (auto it = roots.begin(); it != roots.end(); ++it)
		{
			if (it->first == rvar_name)
				return k_root;
			vector<qstring>::iterator yt;
			for (yt = it->second.begin(); yt != it->second.end(); ++yt)
			{
				if (*yt == rvar_name)
					return it->first;
			}
		}
		return k_root;
	}

	int idaapi visit_expr(cexpr_t *e) override
	{
		char pstx_buf[8];
		if (e->op == cot_asg && e->x->op == cot_var && e->y->op == cot_var)
		{
			const auto lvar_name = lvars_[e->x->v.idx].name;
			auto rvar_name = lvars_[e->y->v.idx].name;
			const auto tvar_name = rvar_depends_on(e);
			if (tvar_name == k_root)
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

			for (auto& i : roots[lvar_name])
			{
				if (i == rvar_name)
					return 0;
			}

			postfixes.insert(pair<qstring, int>(rvar_name, 2));
			sprintf(pstx_buf, "%d", postfixes[rvar_name]++);
			const auto new_name = rvar_name + "_" + pstx_buf;
			to_rename_[&lvars_[e->x->v.idx]] = new_name;
			roots[rvar_name].push_back(new_name);
		}
		return 0;
	}
};

} // anonymous

#define DECLARE_GI_VAR \
  graph_info_t *gi = (graph_info_t *) ud

#define DECLARE_GI_VARS \
  DECLARE_GI_VAR;       \
  callgraph_t *fg = &gi->fg

//--------------------------------------------------------------------------
static ssize_t idaapi gr_callback(void *ud, const int code, va_list va)
{
	auto result = false;
	switch (code)
	{
		// refresh user-defined graph nodes and edges
	case grcode_user_refresh:
		// in:  mutable_graph_t *g
		// out: success
	{
		DECLARE_GI_VARS;
		const auto f = get_func(gi->func_ea);
		if (f == nullptr)
			break;

		graph_builder_t gb(*fg);       // Graph builder helper class
		gb.apply_to(&gi->vu->cfunc->body, nullptr);

		auto mg = va_arg(va, mutable_graph_t *);

		// we have to resize
		mg->resize(fg->count());

		const auto end = fg->end_edges();
		for (auto it = fg->begin_edges();
		     it != end;
		     ++it)
		{
			mg->add_edge(it->id1, it->id2, nullptr);
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
		const auto node = va_arg(va, int);
		const auto text = va_arg(va, const char **);
		const auto bgcolor = va_arg(va, bgcolor_t *);

		const auto ni = fg->get_info(node);
		result = ni != nullptr;
		if (result)
		{
			*text = ni->name.c_str();
			if (bgcolor != nullptr)
				*bgcolor = ni->color;
		}
	}
	break;

	case grcode_user_hint:
	{
		DECLARE_GI_VARS;
		va_arg(va, mutable_graph_t *);
		const auto mousenode = va_argi(va, int);
		const auto to = va_argi(va, int);
		const auto from = va_argi(va, int);
		const auto hint = va_arg(va, char **);

		const auto ni = fg->get_info(mousenode);
		result = ni != nullptr;
		if (result && ni->ea != BADADDR)
		{
			qstring s;
			get_text_disasm(ni->ea, s);
			*hint = qstrdup(s.c_str());
		}
	}
	break;

	case grcode_dblclicked:
	{
		DECLARE_GI_VARS;
		const auto v = va_arg(va, graph_viewer_t *);
		const auto s = va_arg(va, selection_item_t *);
		if (s != nullptr) {
			const auto ni = fg->get_info(s->node);
			result = ni != nullptr;
			if (result && s->is_node && ni->ea != BADADDR)
				jumpto(ni->ea);
		}
	}
	break;
	default: ;
	}
	return static_cast<int>(result);
}


// Display ctree graph for current decompiled function
static bool idaapi display_ctree_graph(void *ud)
{
	auto& vu = *static_cast<vdui_t*>(ud);

	// Determine the ctree item to highlight
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : nullptr;
	const auto gi = graph_info_t::create(vu.cfunc->entry_ea, highlight);

	netnode id;
	id.create();

	const auto title = gi->title;

	auto widget = find_widget(title.c_str());
	if (widget)
	{
		warning("Ctree Graph window already open. Switching to it.\n");
		logmsg(DEBUG, "Ctree Graph window already open. Switching to it.\n");
		activate_widget(widget, true);
		return true;
	}
	widget = create_empty_widget(title.c_str());

	gi->vu = static_cast<vdui_t*>(ud);
	gi->widget = widget;
	gi->gv = create_graph_viewer("ctree", id, gr_callback, gi, 0, widget);
	activate_widget(widget, true);
	display_widget(widget, WOPN_DP_TAB);

	viewer_fit_window(gi->gv);

	return true;
}

// Get pointer to func_t by routine name
func_t * get_func_by_name(const char *func_name)
{
#if 0
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
				qstring func_n;
				if (get_func_name(&func_n, func->start_ea) > 0)
				{
					if (!strcmp(func_name, func_n.c_str()))
					{
						result_func = func;
						break;
					}
				}
			}
		}
	}
	return result_func;
#endif // 0
	return get_func(get_name_ea(BADADDR, func_name));
}


static bool get_expr_name(citem_t *citem, qstring& rv)
{
	if (!citem->is_expr())
		return false;

	const auto e = static_cast<cexpr_t*>(citem);

	// retrieve the name of the routine
	print1wrapper(e, &rv, nullptr);
	tag_remove(&rv);

	return true;
}


static bool idaapi decompile_func(vdui_t &vu)
{
	// Determine the ctree item to highlight
	vu.get_current_item(USE_KEYBOARD);
	citem_t* highlight = vu.item.is_citem() ? vu.item.e : nullptr;
	if (!highlight)
		return false;

	// if it is an expression
	if (!highlight->is_expr())
		return false;

	auto*e = static_cast<cexpr_t*>(highlight);

	qstring qcitem_name;
	if (!get_expr_name(highlight, qcitem_name))
		return false;

	const auto citem_name = qcitem_name.c_str();
	auto proc_name = citem_name + strlen(citem_name);

	while ((proc_name > citem_name) && (*(proc_name - 1) != '>'))  // WTF is going here?
		proc_name--;

	if (proc_name != citem_name)
	{
		if (const auto func = get_func_by_name(proc_name))
			open_pseudocode(func->start_ea, -1);
	}

	return true;
}


//--------------------------------------------------------------------------
//
// TODO: Make changes persistent
//

static bool idaapi rename_simple_expr(void *ud) 
{
	auto& vu = *static_cast<vdui_t*>(ud);
	auto pfunc = vu.cfunc;

	auto& lvars = *pfunc->get_lvars();

	map<lvar_t*, qstring> to_rename;
	renamer_t zc{to_rename, lvars};
	zc.apply_to(&pfunc->body, nullptr);
	for (auto it = to_rename.begin(); it != to_rename.end(); ++it)
		vu.rename_lvar(it->first, it->second.c_str(), false);
	vu.refresh_ctext();
	return true;
}

//--------------------------------------------------------------------------
static bool idaapi show_offset_in_windbg_format(void *ud) {
	char _offset[32] = { 0 };
	char module_name[256] = { 0 };
	qstring result;
	auto& vu = *static_cast<vdui_t*>(ud);
	vu.get_current_item(USE_KEYBOARD);
	const adiff_t offset = vu.item.i->ea - get_imagebase();

	if (offset < 0)
	{
		info("Locate pointer after = sign or at operand of function\n");
		return false;
	}

	get_root_filename(module_name, 255);
	for (auto i = 0; i < 255; i++)
		if (module_name[i] == '.') { module_name[i] = 0; break; }
#ifdef __EA64__
	const auto fmt = "%llx";
#else
	const auto fmt = "%x";
#endif
	sprintf(_offset, fmt, offset);
	result.cat_sprnt("%s+0x%s", module_name, _offset);

	qstring title;
	title.cat_sprnt("0x%X", vu.item.i->ea);
	show_string_in_custom_view(&vu, title, result);

#if defined (__LINUX__) || defined (__MAC__)
	msg("%s", result.c_str());
#else
	OpenClipboard(0);
	EmptyClipboard();
	const auto hg = GlobalAlloc(GMEM_MOVEABLE, result.size());

	if (!hg)
	{
		CloseClipboard();
		msg("Can't alloc\n");
		return false;
	}

	CopyMemory(GlobalLock(hg), result.c_str(), result.size());
	GlobalUnlock(hg);
	SetClipboardData(CF_TEXT, hg);
	CloseClipboard();
	GlobalFree(hg);
#endif
	return true;
}

//--------------------------------------------------------------------------
// show disassembly line for ctree->item
bool idaapi decompiled_line_to_disasm_cb(void *ud)
{
	auto& vu = *static_cast<vdui_t*>(ud);
	vu.ctree_to_disasm();

	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : nullptr;

	return true;
}

//--------------------------------------------------------------------------
// extract ctree to custom view
static bool idaapi show_current_citem_in_custom_view(void *ud)
{
	auto &vu = *static_cast<vdui_t*>(ud);
	vu.get_current_item(USE_KEYBOARD);
	auto *highlight_item = vu.item.is_citem() ? vu.item.e : nullptr;
	if (!highlight_item)
		return false;

	const ctree_dumper_t ctree_dump;
	qstring ctree_item;
	ctree_dump.parse_ctree_item(highlight_item, ctree_item);

	if (highlight_item->is_expr())
	{
		auto *e = static_cast<cexpr_t*>(highlight_item);
		qstring item_name;
		get_expr_name(highlight_item, item_name);
		show_citem_custom_view(&vu, ctree_item, item_name);
	}
	return true;
}


//--------------------------------------------------------------------------
bool init_object_format_parser()
{
	if (!object_format_parser)
	{
		if (compilerIs(MSVC_COMPILER_ABBR))
			object_format_parser = new MSVCObjectFormatParser();
		if (compilerIs(GCC_COMPILER_ABBR))
			object_format_parser = new GCCObjectFormatParser();
		if (!object_format_parser)
		{
			info("CodeXplorer doesn't support yet parsing of neither MSVC nor GCC VTBL's");
			return false;
		}
	}
	return true;
}

//--------------------------------------------------------------------------
// display Object Explorer

static bool idaapi display_vtbl_objects(void *ud)
{
	if (!init_object_format_parser())
		return false;

	search_objects();
	object_explorer_form_init();
	re_types_form_init();
	return true;
}

//--------------------------------------------------------------------------
// display Microcode Explorer window

static bool idaapi display_micvrocode_explorer(void* ud)
{
	clear_cached_cfuncs();
	show_microcode_explorer();

	return true;
}


//--------------------------------------------------------------------------
// This callback handles various hexrays events.
static ssize_t idaapi callback(void* ud, const hexrays_event_t event, va_list va)
{
	switch (event)
	{
		case hxe_populating_popup:
		{
			auto widget = va_arg(va, TWidget *);
			const auto popup = va_arg(va, TPopupMenu *);
			auto &vu = *va_arg(va, vdui_t *);

			// add new command to the popup menu
			attach_action_to_popup(vu.ct, popup, "codexplorer::display_ctree_graph");
			attach_action_to_popup(vu.ct, popup, "codexplorer::object_explorer");
			attach_action_to_popup(vu.ct, popup, "codexplorer::reconstruct_type");

			attach_action_to_popup(vu.ct, popup, "codexplorer::extract_types_to_file");
			attach_action_to_popup(vu.ct, popup, "codexplorer::extract_ctrees_to_file");
			attach_action_to_popup(vu.ct, popup, "codexplorer::ctree_item_view");
			attach_action_to_popup(vu.ct, popup, "codexplorer::microcode_view");
			attach_action_to_popup(vu.ct, popup, "codexplorer::jump_to_disasm");
			attach_action_to_popup(vu.ct, popup, "codexplorer::show_copy_item_offset");
			attach_action_to_popup(vu.ct, popup, "codexplorer::rename_vars");
		}
		break;

		case hxe_double_click:
		{
			auto& vu = *va_arg(va, vdui_t *);
			decompile_func(vu);
		}
		break;
	}
	
	return 0;
}

void parse_plugin_options(qstring &options, bool &dump_types, bool &dump_ctrees, qstring &crypto_prefix) {
	qvector<qstring> params;
	const qstring splitter = ":";
	split_qstring(options, splitter, params);

	dump_types = false;
	dump_ctrees = false;
	crypto_prefix = "";

	for (const auto& param : params) {
		if (param == "dump_types") {
			dump_types = true;
		}
		else if (param == "dump_ctrees") {
			dump_ctrees = true;
		}
		else if (param.length() > k_crypto_prefix_param.length() && param.find(k_crypto_prefix_param) == 0) {
			crypto_prefix = param.substr(k_crypto_prefix_param.length());
		}
		else {
			qstring message = "Invalid argument: ";
			message += param + "\n";
			logmsg(INFO, message.c_str());
		}
	}
}

namespace {

	class menu_action_handler final : public action_handler_t
	{
	public:
		typedef std::function<bool(void*)> handler_t;
		bool is_enabled;

		explicit menu_action_handler(handler_t handler)
			: is_enabled(true), handler_(std::move(handler))
		{
		}

		menu_action_handler(handler_t handler, const bool enabled)
			: is_enabled(enabled), handler_(std::move(handler))
		{
		}

		int idaapi activate(action_activation_ctx_t* ctx) override
		{
			const auto vdui = get_widget_vdui(ctx->widget);
			return handler_(vdui) ? TRUE : FALSE;
		}

		action_state_t idaapi update(action_update_ctx_t* ctx) override
		{
			return ctx->widget_type == BWN_PSEUDOCODE ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
		}

	private:
		handler_t handler_;
	};

	static menu_action_handler k_display_ctree_graph_handler{ display_ctree_graph };
	static menu_action_handler k_object_explorer_handler{ display_vtbl_objects };
	static menu_action_handler k_reconstruct_type_handler{ reconstruct_type_cb };
	static menu_action_handler k_extract_all_types_handler{ extract_all_types };
	static menu_action_handler k_extract_all_ctrees_handler{ extract_all_ctrees };
	static menu_action_handler k_show_current_c_item_in_custom_view{ show_current_citem_in_custom_view };
	static menu_action_handler k_show_microcode_explorer_view{ display_micvrocode_explorer };
	static menu_action_handler k_jump_to_disasm_handler{ decompiled_line_to_disasm_cb };
	static menu_action_handler k_show_offset_in_windbg_format_handler{ show_offset_in_windbg_format };
	static menu_action_handler k_rename_vars_handler{ rename_simple_expr };

	static action_desc_t k_action_descs[] = {
		ACTION_DESC_LITERAL("codexplorer::display_ctree_graph", "Display Ctree Graph", &k_display_ctree_graph_handler, hotkey_dg, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::object_explorer", "Object Explorer", &k_object_explorer_handler, hotkey_ce, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::reconstruct_type", "REconstruct Type", &k_reconstruct_type_handler, hotkey_rt, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::extract_types_to_file", "Extract Types to File", &k_extract_all_types_handler, hotkey_et, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::extract_ctrees_to_file", "Extract Ctrees to File", &k_extract_all_ctrees_handler, hotkey_ec, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::ctree_item_view", "Ctree Item View", &k_show_current_c_item_in_custom_view, hotkey_vc, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::microcode_view", "Microcode View", &k_show_microcode_explorer_view, hotkey_mc, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::jump_to_disasm", "Jump to Disasm", &k_jump_to_disasm_handler, hotkey_gd, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::show_copy_item_offset", "Show/Copy item offset", &k_show_offset_in_windbg_format_handler, hotkey_so, nullptr, -1),
		ACTION_DESC_LITERAL("codexplorer::rename_vars", "Rename vars", &k_rename_vars_handler, hotkey_rv, nullptr, -1)
	};


	static const cfgopt_t g_opts[] =
	{
		cfgopt_t("HOTKEY_DISPLAY_GRAPH", hotkey_dg, (size_t)sizeof(hotkey_dg), false),
		cfgopt_t("HOTKEY_OBJECT_EXPLORER", hotkey_ce, (size_t)sizeof(hotkey_ce), false),
		cfgopt_t("HOTKEY_RECONSTRUCT_TYPE", hotkey_rt, (size_t)sizeof(hotkey_rt), false),
		cfgopt_t("HOTKEY_JUMP_TO_DISASM", hotkey_gd, (size_t)sizeof(hotkey_gd), false),
		cfgopt_t("HOTKEY_EXTRACT_TYPES", hotkey_et, (size_t)sizeof(hotkey_et), false),
		cfgopt_t("HOTKEY_EXTRACT_CTREE", hotkey_ec, (size_t)sizeof(hotkey_ec), false),
		cfgopt_t("HOTKEY_CTREE_EXPLORER", hotkey_vc, (size_t)sizeof(hotkey_vc), false),
		cfgopt_t("HOTKEY_MICROCODE_EXPLORER", hotkey_mc, (size_t)sizeof(hotkey_mc), false),
		cfgopt_t("HOTKEY_SHOW_COPY_ITEM_OFFSET", hotkey_so, (size_t)sizeof(hotkey_so), false),
		cfgopt_t("HOTKEY_RENAME_VARS", hotkey_rv, (size_t)sizeof(hotkey_rv), false)
	};

} 

// Plugin context, necessary for the correct work of the plugin with the flag PLUGIN_MULTI
struct codexplorer_ctx_t : public plugmod_t
{
	~codexplorer_ctx_t()
	{
		if (inited)
		{
			logmsg(INFO, "\nHexRaysCodeXplorer plugin by @REhints terminated.\n\n\n");
			remove_hexrays_callback(static_cast<hexrays_cb_t*>(callback), nullptr);
			re_types_form_fini();
			term_hexrays_plugin();
		}
	}
	virtual bool idaapi run(size_t arg) override;
};



bool idaapi codexplorer_ctx_t::run(size_t arg)
{
    auto reconstruct_type_params = *reinterpret_cast<reconstruct_type_params_t *>(arg);
    return reconstruct_type(reconstruct_type_params);
}

//--------------------------------------------------------------------------
// Initialize the plugin.
plugmod_t *idaapi init(void)
{
	logmsg(INFO, "\nHexRaysCodeXplorer plugin by @REhints loaded.\n\n\n");
	msg("\nHexRaysCodeXplorer plugin by @REhints loaded.\n\n\n");

	if (!init_hexrays_plugin())
	{
		warning("Hex-Rays Decompiler not found!");
		return nullptr; // no decompiler
	}

	auto dump_types = false;
	auto dump_ctrees = false;
	qstring crypto_prefix;

	qstring options = get_plugin_options(PLUGIN.wanted_name);
	parse_plugin_options(options, dump_types, dump_ctrees, crypto_prefix);

	auto config_read = read_config_file("codeexplorer.cfg", g_opts, _countof(g_opts), nullptr);

	for (auto& k_action_desc : k_action_descs)
	{
		if (k_action_desc.shortcut[0])
			register_action(k_action_desc);
	}

	install_hexrays_callback(static_cast<hexrays_cb_t*>(callback), nullptr);
	logmsg(INFO, "Hex-rays version %s has been detected\n", get_hexrays_version());
	inited = true;

	if (dump_ctrees || dump_types) {
		auto_wait();

		if (dump_types) {
			logmsg(DEBUG, "Dumping types\n");
			extract_all_types(nullptr);

			const auto file_id = qcreate("codexplorer_types_done", 511);
			if (file_id != -1)
				qclose(file_id);
		}

		if (dump_ctrees) {
			logmsg(DEBUG, "Dumping ctrees\n");
			dump_funcs_ctree(nullptr, crypto_prefix);

			const auto file_id = qcreate("codexplorer_ctrees_done", 511);
			if (file_id != -1)
				qclose(file_id);
		}

		logmsg(INFO, "\nHexRaysCodeXplorer plugin by @REhints exiting...\n\n\n");
	}

	// You should always pass at least PCF_MAKEPLACE_ALLOCATES
	g_replace_id = register_place_class(&replace_template, PCF_MAKEPLACE_ALLOCATES, &PLUGIN);

	return new codexplorer_ctx_t;
}

//--------------------------------------------------------------------------
static const char comment[] = "HexRaysCodeXplorer plugin by @REhints";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_HIDE | PLUGIN_MULTI,	// plugin flags
	init,						// initialize
	nullptr,					// terminate. this pointer may be NULL.
	nullptr,					// invoke plugin
	comment,					// long comment about the plugin
								// it could appear in the status line or as a hint
	"",							// multiline help about the plugin
	"HexRaysCodeXplorer by @REhints", // the preferred short name of the plugin (PLUGIN.wanted_name)
	""							// the preferred hotkey to run the plugin
};
