/*  Copyright (c) 2013
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
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/


#include "HexRaysCodeXplorer.h"

hexdsp_t *hexdsp = NULL;

  // Display a graph node. Feel free to modify this function to fine tune the node display.
  char * idaapi cfunc_graph_t::get_node_label(int n, char *buf, int bufsize)
  {
    char *ptr = buf;
    char *endp = buf + bufsize;
    // Get the corresponding ctree item
    const citem_t *item = items[n];
    // Each node will have the element type at the first line
    APPEND(ptr, endp, get_ctype_name(item->op));
    const cexpr_t *e = (const cexpr_t *)item;
    const cinsn_t *i = (const cinsn_t *)item;
    // For some item types, display additional information
    switch ( item->op )
    {
      case cot_ptr     : // *x
      case cot_memptr  : // x->m
        // Display access size for pointers
        ptr += qsnprintf(ptr, endp-ptr, ".%d", e->ptrsize);
        if ( item->op == cot_ptr )
          break;
      case cot_memref  : // x.m
        // Display member offset for structure fields
        ptr += qsnprintf(ptr, endp-ptr, " (m=%d)", e->m);
        break;
      case cot_obj     : // v
      case cot_var     : // l
        // Display object size for local variables and global data
        ptr += qsnprintf(ptr, endp-ptr, ".%d", e->refwidth);
      case cot_num     : // n
      case cot_helper  : // arbitrary name
      case cot_str     : // string constant
        // Display helper names and number values
        APPCHAR(ptr, endp, ' ');
        e->print1(ptr, endp-ptr, NULL);
        tag_remove(ptr, ptr, 0);
        ptr = tail(ptr);
        break;
     case cit_goto:
        // Display target label number for gotos
        ptr += qsnprintf(ptr, endp-ptr, " LABEL_%d", i->cgoto->label_num);
        break;
     case cit_asm:
        // Display instruction block address and size for asm-statements
        ptr += qsnprintf(ptr, endp-ptr, " %a.%"FMT_Z, *i->casm->begin(), i->casm->size());
        break;
      default:
        break;
    }
    // The second line of the node contains the item address
    ptr += qsnprintf(ptr, endp-ptr, "\nea: %a", item->ea);
    if ( item->is_expr() && !e->type.empty() )
    {
      // For typed expressions, the third line will have
      // the expression type in human readable form
      APPCHAR(ptr, endp, '\n');
      if ( print_type_to_one_line(ptr, endp-ptr, idati, e->type.u_str()) != T_NORMAL )
      { // could not print the type?
        APPCHAR(ptr, endp, '?');
        APPZERO(ptr, endp);
      }

	  if(e->type.is_ptr())
		{
			typestring ptr_rem = remove_pointer(e->type);
			if(ptr_rem.is_struct())
			{
				qstring typenm;

				print_type_to_qstring(&typenm, "prefix ", 0,0, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI, idati, ptr_rem.u_str());

//				print_type_to_one_line(ptr, endp-ptr, idati, ptr_rem.u_str());
			}
		}
    }
    return buf;
  }


  // Display a graph edge.
  bool idaapi cfunc_graph_t::print_edge(FILE *fp, int i, int j)
  {
    qfprintf(fp, "edge: { sourcename: \"%d\" targetname: \"%d\" ", i, j);
    const char *label = NULL;
    const citem_t *a = items[i];
    const citem_t *b = items[j];
    if ( a->is_expr() ) // For expressions, add labels to the edges
    {
      cexpr_t *e = (cexpr_t *)a;
      if ( e->x == b ) label = "x";
      if ( e->y == b ) label = "y";
      if ( e->z == b ) label = "z";
    }
    if ( label != NULL )
      qfprintf(fp, "label: \"%s\" ", label);
    qfprintf(fp, "}\n");
    return true;
  }
  // Determine the node color. Feel free to change it.
  bgcolor_t idaapi cfunc_graph_t::get_node_color(int n)
  {
    const citem_t *item = items[n];
    if ( item == highlight )
      return CL_GREEN;          // Highlighted item
    if ( item->is_expr() )
    {
      char buf[MAXSTR];
      const cexpr_t *e = (const cexpr_t *)item;
      if ( print_type_to_one_line(buf, sizeof(buf), idati, e->type.u_str()) != T_NORMAL )
        return CL_YELLOWGREEN; // Problematic type
    }

	if(item->op == cot_call)
		return CL_RED;

    return DEFCOLOR;
  }
  // Print the node color.
  void idaapi cfunc_graph_t::print_node_attributes(FILE *fp, int n)
  {
    bgcolor_t c = get_node_color(n);
    if ( c != DEFCOLOR )
      qfprintf(fp, " color: %s", get_color_name(c));
  }

//--------------------------------------------------------------------------
// Helper class to build graph from ctree.
struct graph_builder_t : public ctree_parentee_t
{
  cfunc_graph_t &cg;                 // Resulting graph
  std::map<citem_t *, int> reverse;  // Reverse mapping for tests and adding edges

  graph_builder_t(cfunc_graph_t &_cg) : cg(_cg) {}
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
  int n = cg.add_node();
  // Remember the pointer to the item, we will need it to generate GDL
  // (in print_node_label)
  if ( n <= cg.items.size() )
    cg.items.push_back(i);
  cg.items[n] = i;
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
    cg.add_edge(p, n);                  // Add edge from the parent to the current item
  }
  return 0;
}

//--------------------------------------------------------------------------
// Build and display graph for the ctree
static bool idaapi display_graph(void *ud)
{
  vdui_t &vu = *(vdui_t *)ud;
  // Determine the ctree item to highlight
  vu.get_current_item(USE_KEYBOARD);
  citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;

  cfunc_graph_t cg(highlight);  // Graph to display
  graph_builder_t gb(cg);       // Graph builder helper class
  // Build the graph by traversing the ctree
  gb.apply_to(&vu.cfunc->body, NULL);

  // Our graph object 'cg' is ready. Now display it by converting it to GDL
  // and calling wingraph32
  char fname[QMAXPATH];
  qtmpnam(fname, sizeof(fname));        // Generate temporary file name
  gen_gdl(&cg, fname);                  // Generate GDL file from 'cg' graph
  display_gdl(fname);                   // Display the GDL file
  return true;                          // Success!
}

func_t * get_func_by_name(const char *func_name)
{
	func_t * result_func = NULL;
	size_t func_total = get_func_qty();
	if(func_total > 0)
	{
		char tmp[1024];
		for (int i = 0 ; i < func_total - 1 ; i ++)
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
	  if(highlight->is_expr())
	  //if(highlight->op == cot_call)
	  {
		  cexpr_t *e = (cexpr_t *)highlight;
		  char tmp[512];
		  memset(tmp, 0x00, sizeof(tmp));
		  e->print1(tmp, sizeof(tmp), NULL);
		  tag_remove(tmp, tmp, sizeof(tmp));

		  char *proc_name = tmp + strlen(tmp);


		  while((proc_name > tmp) && (*(proc_name - 1) != '>'))
			  proc_name --;

		  msg("Function %s is choosen\n", proc_name);

		  func_t * func = get_func_by_name(proc_name);
		  if(func != NULL)
		  {
			  vdui_t * decompiled_window = open_pseudocode(func->startEA, -1);
			  /*
			  hexrays_failure_t error;
			  cfuncptr_t decompiled = decompile(func, &error);
			  if(decompiled != NULL)
				switch_to(decompiled);
				*/
		  }
	  }
  }
  
  return true;                          // Success!
}
