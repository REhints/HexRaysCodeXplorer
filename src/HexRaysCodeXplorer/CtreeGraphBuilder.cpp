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
 	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	==============================================================================
*/


#include "Common.h"
#include "CtreeGraphBuilder.h"
#include "ObjectExplorer.h"
#include "Utility.h"

#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif


bool callgraph_t::visited(citem_t *i, int *nid)
{
	const ea_int_map_t::const_iterator it = ea2node_.find(i);
	if (it != ea2node_.end())
	{
		if (nid != nullptr)
			*nid = it->second;
		return true;
	}
	return false;
}


void callgraph_t::create_edge(const int id1, const int id2)
{
	edges.push_back(edge_t(id1, id2));
}


void callgraph_t::get_node_label(int n, qstring& rv) const
{
	const auto it = node2ea_.find(n);
	rv.clear();

	if ( it != node2ea_.end() )
	{
		const citem_t *item = it->second;

		// Each node will have the element type at the first line
		const auto ctype_name = get_ctype_name(item->op);
		if (ctype_name)
			rv = ctype_name;

		const auto e = static_cast<const cexpr_t*>(item);
		const auto i = static_cast<const cinsn_t*>(item);

		// For some item types, display additional information
		qstring func_name;
		qstring constant;
		switch (item->op)
		{
		case cot_call:
			if (get_func_name(&func_name, e->x->obj_ea) == 0)
				rv.cat_sprnt(" sub_%a", e->x->obj_ea);
			else
				rv.cat_sprnt(" %s", func_name.c_str());
			break;
		case cot_ptr: // *x
		case cot_memptr: // x->m
			// Display access size for pointers
			rv.cat_sprnt(".%d", e->ptrsize);
			if (item->op == cot_ptr)
				break;
		case cot_memref: // x.m
			// Display member offset for structure fields
			rv.cat_sprnt(" (m=%d)", e->m);
			break;
		case cot_obj: // v

		case cot_var: // l
			// Display object size for local variables and global data
			rv.cat_sprnt(".%d", e->refwidth);
		case cot_num: // n
		case cot_helper: // arbitrary name
		case cot_str: // string constant
			// Display helper names and number values
			rv.append(' ');
			{
				qstring qbuf;
				print1wrapper(e, &qbuf, nullptr);
				tag_remove(&qbuf);
				rv += qbuf;
			}
			break;
		case cit_goto:
			// Display target label number for gotos
			rv.cat_sprnt(" LABEL_%d", i->cgoto->label_num);
			break;
		case cit_asm:
			// Display instruction block address and size for asm-statements
			rv.cat_sprnt(" %a.%" FMT_Z, *i->casm->begin(), i->casm->size());
			break;
		default:
			break;
		}

		rv.cat_sprnt("\nea: %a", item->ea);

		if ( item->is_expr() && !e->type.empty() )
		{
			// For typed expressions, the third line will have
			// the expression type in human readable form
			rv.append('\n');
			qstring out;
			if (e->type.print(&out))
			{
				rv += out;
			}
			else
			{ // could not print the type?
				rv.append('?');
			}

			if(e->type.is_ptr())
			{
				const auto ptr_rem = remove_pointer(e->type);
				if(ptr_rem.is_struct())
				{
					qstring typenm;
					ptr_rem.print(&typenm, "prefix ", 0, 0, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI);
				}
			}
		}
	}
}


callgraph_t::nodeinfo_t *callgraph_t::get_info(int nid)
{
	nodeinfo_t *ret = nullptr;

	do
	{
		// returned cached name
		auto it = cached_funcs.find(nid);
		if (it != cached_funcs.end())
		{
			ret = &it->second;
			break;
		}

		// node does not exist?
		const int_ea_map_t::const_iterator it_ea = node2ea_.find(nid);
		if (it_ea == node2ea_.end())
			break;

		const auto pfn = it_ea->second;
		if (!pfn)
			break;

		nodeinfo_t fi;

		// get name
		qstring node_label;
		get_node_label(nid, node_label);
		if (!node_label.empty())
			fi.name = node_label;
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
	ea_int_map_t::const_iterator it = ea2node_.find(i);
	if ( it != ea2node_.end() )
		return it->second;

	ea2node_[i] = node_count_;
	node2ea_[node_count_] = i;

	const auto ret_val = node_count_;
	node_count_ ++;
	return ret_val;
}


//--------------------------------------------------------------------------
callgraph_t::callgraph_t()
	: node_count_(0)
	, highlighted(nullptr)
{
	//cur_text[0] = '\0';
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
	: gv(nullptr)
	, widget(nullptr)
	, vu(nullptr)
	, func_ea(BADADDR)
	, func_instance_no(0)
{
}


//--------------------------------------------------------------------------
// Create graph for current decompiled function
graph_info_t * graph_info_t::create(const ea_t func_ea, citem_t *highlighted)
{
	const auto pfn = get_func(func_ea);
	if (!pfn)
		return nullptr;

	auto r = new graph_info_t();
	r->func_ea = pfn->start_ea;
	r->fg.highlighted = highlighted;

	size_t num_inst = 0;
	for (const graph_info_t* gi : instances)
	{
		if (gi->func_ea == func_ea && num_inst < gi->func_instance_no)
			num_inst = gi->func_instance_no;
	}

	r->func_instance_no = ++num_inst;
	get_title(func_ea, num_inst, &r->title);

	instances.push_back(r);

	return r;
}


//--------------------------------------------------------------------------
bool graph_info_t::get_title(const ea_t func_ea, size_t num_inst, qstring *out)
{
	// we should succeed in getting the name
	qstring func_name;
	if ( get_func_name(&func_name, func_ea) == 0)
		return false;

	out->sprnt("Ctree Graph View: %s %d", func_name.c_str(), static_cast<int>(num_inst));

	return true;
}


void graph_info_t::destroy(graph_info_t *gi)
{
	// FIXME: never called
	for(auto it = instances.begin() ; it != instances.end() ; ++it)
	{
		if (*it == gi)
		{
			instances.erase(it);
			break;
		}
	}
}
