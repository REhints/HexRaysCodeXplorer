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


#include "Common.h"
#include "GraphBuilder.h"
#include "ObjectExplorer.h"
#include "ObjectType.h"


// Hex-Rays API pointer
hexdsp_t *hexdsp = NULL;

static bool inited = false;

// Hotkey for the new command
static const char hotkey_dg[] = "T";
static ushort hotcode_dg;

static const char hotkey_ce[] = "O";
static ushort hotcode_ce;

static const char hotkey_rt[] = "R";
static ushort hotcode_rt;

static const char hotkey_gd[] = "J";
static ushort hotcode_gd;



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
  if ( reverse.find(i) != reverse.end() )
  {
    warning("bad ctree - duplicate nodes!");
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
  if ( n == -1 )
    return -1; // error

  if ( parents.size() > 1 )             // The current item has a parent?
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
  switch ( code )
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
      for ( callgraph_t::edge_iterator it=fg->begin_edges();
        it != end;
        ++it )
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
      int node           = va_arg(va, int);
      const char **text  = va_arg(va, const char **);
      bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);

	  callgraph_t::nodeinfo_t *ni = fg->get_info(node);
	  result = ni != NULL;
	  if ( result )
	  {
		  *text = ni->name.c_str();
		  if ( bgcolor != NULL )
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


static bool idaapi display_graph(void *ud)
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
	if(func_total > 0)
	{
		char tmp[1024];
		for (unsigned int i = 0 ; i < func_total - 1 ; i ++)
		{
			func_t * func = getn_func(i);
			if(func != NULL)
			{
				memset(tmp, 0x00, sizeof(tmp));
				char *func_n = get_func_name(func->startEA, tmp, sizeof(tmp));
				if(func_n != NULL)
				{
					if(!strcmp(func_name, func_n))
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


static bool idaapi decompile_func(vdui_t &vu)
{
  // Determine the ctree item to highlight
  vu.get_current_item(USE_KEYBOARD);
  citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;
  
  if(highlight != NULL)
  {
	  // if it is an expression
	  if(highlight->is_expr())
	  {
		  cexpr_t *e = (cexpr_t *)highlight;
		  
		  // retrieve the name of the routine
		  char tmp[1024];
		  memset(tmp, 0x00, sizeof(tmp));
		  e->print1(tmp, sizeof(tmp), NULL);
		  tag_remove(tmp, tmp, sizeof(tmp));

		  char *proc_name = tmp + strlen(tmp);

		  while((proc_name > tmp) && (*(proc_name - 1) != '>'))
			  proc_name --;

		  if (proc_name != tmp) {
			  func_t * func = get_func_by_name(proc_name);
			  if(func != NULL)
			  {
				  vdui_t * decompiled_window = open_pseudocode(func->startEA, -1);
			  }
		  }
	  }
  }
  
  return true;                    
}


// extract ctree custom view
static bool idaapi ctree_into_custom_view(void *ud) // TODO
{
	vdui_t &vu = *(vdui_t *)ud;
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;

	if (highlight != NULL)
	{
		// if it is an expression
		if (highlight->is_expr())
		{
			cexpr_t *e = (cexpr_t *)highlight;

			// retrieve the name of the routine
			char tmp[1024];
			memset(tmp, 0x00, sizeof(tmp));
			e->print1(tmp, sizeof(tmp), NULL);
			tag_remove(tmp, tmp, sizeof(tmp));
		}
	}

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


// display Object Explorer
static bool idaapi display_objects(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
	search_objects();
	object_explorer_form_init();

	return true;
}

//--------------------------------------------------------------------------
// This callback handles various hexrays events.
static int idaapi callback(void *, hexrays_event_t event, va_list va)
{
  switch ( event )
  {
    case hxe_right_click:
      {
        vdui_t &vu = *va_arg(va, vdui_t *);
        // add new command to the popup menu
        add_custom_viewer_popup_item(vu.ct, "Display Graph", hotkey_dg, display_graph, &vu);
		add_custom_viewer_popup_item(vu.ct, "Object Explorer", hotkey_ce, display_objects, &vu);
		add_custom_viewer_popup_item(vu.ct, "REconstruct Type", hotkey_rt, reconstruct_type, &vu);
		add_custom_viewer_popup_item(vu.ct, "Jump to Disasm", hotkey_gd, decompiled_line_to_disasm, &vu);
      }
      break;

	case hxe_keyboard:
      {
        vdui_t &vu = *va_arg(va, vdui_t *);
        int keycode = va_arg(va, int);
        // check for the hotkey
		if (keycode == hotcode_dg)
          return display_graph(&vu);
		if (keycode == hotcode_ce)
			return display_objects(&vu);
		if (keycode == hotcode_rt)
          return reconstruct_type(&vu);
		if (keycode == hotcode_gd)
			return decompiled_line_to_disasm(&vu);
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

//--------------------------------------------------------------------------
// Initialize the plugin.
int idaapi init(void)
{
	if ( !init_hexrays_plugin() )
    return PLUGIN_SKIP; // no decompiler
	install_hexrays_callback(callback, NULL);
	const char *hxver = get_hexrays_version();
	msg("Hex-rays version %s has been detected, %s ready to use\n", hxver, PLUGIN.wanted_name);
	inited = true;
	hotcode_dg = 84; // T
	hotcode_ce = 79; // O
	hotcode_rt = 82; // R
	hotcode_gd = 74; // J
	msg(
		"\nHexRaysCodeXplorer plugin by @REhints loaded.\n\n\n");

	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  if ( inited )
  {
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
static char comment[] = "HexRaysCodeXplorer plugin";

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
  "HexRaysCodeXplorer", // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
