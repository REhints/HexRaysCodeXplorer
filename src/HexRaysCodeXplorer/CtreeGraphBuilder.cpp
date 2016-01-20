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
#include "CtreeGraphBuilder.h"
#include "ObjectExplorer.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


bool callgraph_t::visited(citem_t *i, int *nid)
{
  ea_int_map_t::const_iterator it = ea2node.find(i);
  if ( it != ea2node.end() )
  {
    if ( nid != NULL )
      *nid = it->second;
    return true;
  }
  return false;
}


void callgraph_t::create_edge(int id1, int id2)
{
	edges.push_back(edge_t(id1, id2));
}


char * callgraph_t::get_node_label(int n, char *buf, int bufsize) const
{
	int_ea_map_t::const_iterator it = node2ea.find(n);
	
	if ( it != node2ea.end() )
	{
		const citem_t *item = it->second;

		char *ptr = buf;
		char *endp = buf + bufsize;
		
		// Each node will have the element type at the first line
		APPEND(ptr, endp, get_ctype_name(item->op));
		const cexpr_t *e = (const cexpr_t *)item;
		const cinsn_t *i = (const cinsn_t *)item;

		// For some item types, display additional information
		switch (item->op)
		{
		case cot_call:
			char buf[MAXSTR];
			if (get_func_name(e->x->obj_ea, buf, sizeof(buf)) == NULL)
				ptr += qsnprintf(ptr, endp - ptr, " sub_%a", e->x->obj_ea);
			ptr += qsnprintf(ptr, endp - ptr, " %s", buf);
			break;
		case cot_ptr: // *x
		case cot_memptr: // x->m
			// Display access size for pointers
			ptr += qsnprintf(ptr, endp - ptr, ".%d", e->ptrsize);
			if (item->op == cot_ptr)
				break;
		case cot_memref: // x.m
			// Display member offset for structure fields
			ptr += qsnprintf(ptr, endp - ptr, " (m=%d)", e->m);
			break;
		case cot_obj: // v

		case cot_var: // l
			// Display object size for local variables and global data
			ptr += qsnprintf(ptr, endp - ptr, ".%d", e->refwidth);
		case cot_num: // n
		case cot_helper: // arbitrary name
		case cot_str: // string constant
			// Display helper names and number values
			APPCHAR(ptr, endp, ' ');
			e->print1(ptr, endp - ptr, NULL);
			tag_remove(ptr, ptr, sizeof(ptr));
			ptr = tail(ptr);
			break;
		case cit_goto:
			// Display target label number for gotos
			ptr += qsnprintf(ptr, endp - ptr, " LABEL_%d", i->cgoto->label_num);
			break;
		case cit_asm:
			// Display instruction block address and size for asm-statements
			ptr += qsnprintf(ptr, endp - ptr, " %a.%" FMT_Z, *i->casm->begin(), i->casm->size());
			break;
		default:
			break;
		}
    
		ptr += qsnprintf(ptr, endp-ptr, "\nea: %a", item->ea);

		if ( item->is_expr() && !e->type.empty() )
		{
		  // For typed expressions, the third line will have
		  // the expression type in human readable form
		  APPCHAR(ptr, endp, '\n');
		  qstring out;
		  if (e->type.print(&out))
		  {
			  APPEND(ptr, endp, out.c_str());
		  }
		  else 
		  { // could not print the type?
			APPCHAR(ptr, endp, '?');
			APPZERO(ptr, endp);
		  }

		  if(e->type.is_ptr())
			{
				tinfo_t ptr_rem = remove_pointer(e->type);
				if(ptr_rem.is_struct())
				{
					qstring typenm;
					ptr_rem.print(&typenm, "prefix ", 0, 0, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI);
				}
			}
		}
	}
	
	return buf;
}


callgraph_t::nodeinfo_t *callgraph_t::get_info(int nid)
{
  nodeinfo_t *ret = NULL;

  do
  {
    // returned cached name
    int_funcinfo_map_t::iterator it = cached_funcs.find(nid);
    if ( it != cached_funcs.end() )
    {
      ret = &it->second;
      break;
    }

    // node does not exist?
    int_ea_map_t::const_iterator it_ea = node2ea.find(nid);
    if ( it_ea == node2ea.end() )
      break;

    citem_t *pfn = it_ea->second;
    if ( pfn == NULL )
      break;

    nodeinfo_t fi;

    // get name
    char buf[MAXSTR];
	if(get_node_label(nid, buf, MAXSTR))
		fi.name = buf;
	else
		fi.name = "?unknown";

    // get color
	if(pfn == highlighted) // highlight element with current cursor position 
		fi.color = 2000;
	else
		fi.color = 1;

	#define CL_DARKBLUE      ((0  )+  (0  <<8)+  (128<<16)) 
	if (pfn->op == cit_expr)
		fi.color = CL_DARKBLUE;
	#define CL_BLUE          ((0  )+  (0  <<8)+  (255<<16))
	if (pfn->op == cit_block)
		fi.color = CL_BLUE;
	

	fi.ea = pfn->ea;

    it = cached_funcs.insert(cached_funcs.end(), std::make_pair(nid, fi));
    ret = &it->second;
  } while ( false );

  return ret;
}


//--------------------------------------------------------------------------
int callgraph_t::add(citem_t *i)
{
	// check if we are trying to add existing node
	ea_int_map_t::const_iterator it = ea2node.find(i);
	if ( it != ea2node.end() )
		return it->second;

	ea2node[i] = node_count;
	node2ea[node_count] = i;
	
	int ret_val = node_count;
	node_count ++;
	return ret_val;
}


//--------------------------------------------------------------------------
callgraph_t::callgraph_t() : node_count(0)
{
  cur_text[0] = '\0';
}


//--------------------------------------------------------------------------
void callgraph_t::clear_edges()
{
  edges.clear();
}

//--------------------------------------------------------------------------
graph_info_t::graphinfo_list_t graph_info_t::instances;

//--------------------------------------------------------------------------
graph_info_t::graph_info_t()
{
  form = NULL;
  gv = NULL;
}


//--------------------------------------------------------------------------
// Create graph for current decompiled function
graph_info_t * graph_info_t::create(ea_t func_ea, citem_t *highlighted)
{
  graph_info_t *r;
 
  func_t *pfn = get_func(func_ea);
  if ( pfn == NULL )
	return NULL;
  
  r = new graph_info_t();
  r->func_ea = pfn->startEA;
  r->fg.highlighted = highlighted;
  
  size_t num_inst = 0;
  for(graphinfo_list_t::iterator it = instances.begin() ; it != instances.end() ; it ++)
  {
	  if(((*(it))->func_ea == func_ea) && (num_inst < (*(it))->func_instance_no))
		  num_inst = (*(it))->func_instance_no;
  }
  
  r->func_instance_no = ++ num_inst;
  get_title(func_ea, num_inst, &r->title);

  instances.push_back(r);
  
  return r;
}


//--------------------------------------------------------------------------
bool graph_info_t::get_title(ea_t func_ea, size_t num_inst, qstring *out)
{
  // we should succeed in getting the name
  char func_name[MAXSTR];
  if ( get_func_name(func_ea, func_name, sizeof(func_name)) == NULL )
    return false;

  out->sprnt("Ctree Graph View: %s %d", func_name, num_inst);
  
  return true;
}


void graph_info_t::destroy(graph_info_t *gi)
{
	for(graphinfo_list_t::iterator it = instances.begin() ; it != instances.end() ; it ++)
	{
		if((*(it)) == gi)
		{
			instances.erase(it);
			break;
		}
	}
}
