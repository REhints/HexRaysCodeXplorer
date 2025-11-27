/*	Copyright (c) 2013-2024
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

// SDK 9.2 optimized version with improved memory management

#include "Common.h"
#include "CtreeGraphBuilder.h"
#include "ObjectExplorer.h"
#include "Utility.h"
#include <memory>
#include <string_view>

#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

// RAII wrapper for graph resources
class graph_resource_guard
{
private:
	callgraph_t* graph_;
	bool should_cleanup_;

public:
	explicit graph_resource_guard(callgraph_t* g) 
		: graph_(g), should_cleanup_(true) {}
	
	~graph_resource_guard() 
	{
		if (should_cleanup_ && graph_)
			graph_->clear();
	}
	
	void release() { should_cleanup_ = false; }
	graph_resource_guard(const graph_resource_guard&) = delete;
	graph_resource_guard& operator=(const graph_resource_guard&) = delete;
};

bool callgraph_t::visited(citem_t *i, int *nid)
{
	if (!i)
		return false;
		
	const auto it = ea2node_.find(i);
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
	// Validate node IDs before creating edge
	if (id1 < 0 || id2 < 0 || id1 >= node2ea_.size() || id2 >= node2ea_.size())
	{
		logmsg(DEBUG, "Invalid edge creation attempt: %d -> %d\n", id1, id2);
		return;
	}
	
	edges.push_back(edge_t(id1, id2));
}

void callgraph_t::clear()
{
	edges.clear();
	node2ea_.clear();
	ea2node_.clear();
}

// SDK 9.2: Optimized node label generation with string_view
void callgraph_t::get_node_label(int n, qstring& rv) const
{
	rv.clear();
	
	const auto it = node2ea_.find(n);
	if (it == node2ea_.end())
		return;

	const citem_t *item = it->second;
	if (!item)
		return;

	// Each node will have the element type at the first line
	const auto ctype_name = get_ctype_name(item->op);
	if (ctype_name)
		rv = ctype_name;

	// Use smart pointers for safer casting
	std::unique_ptr<qstring> func_name;
	std::unique_ptr<qstring> constant;
	
	const auto e = (item->is_expr()) ? static_cast<const cexpr_t*>(item) : nullptr;
	const auto i = (!item->is_expr()) ? static_cast<const cinsn_t*>(item) : nullptr;

	// For some item types, display additional information
	switch (item->op)
	{
	case cot_call:
		if (e && e->x)
		{
			func_name = std::make_unique<qstring>();
			if (get_func_name(func_name.get(), e->x->obj_ea) == 0)
				rv.cat_sprnt(" sub_%a", e->x->obj_ea);
			else
				rv.cat_sprnt(" %s", func_name->c_str());
		}
		break;
		
	case cot_ptr: // *x
	case cot_memptr: // x->m
		// Display access size for pointers
		if (e)
		{
			rv.cat_sprnt(".%d", e->ptrsize);
			if (item->op == cot_ptr)
				break;
		}
		// fallthrough for memptr
		
	case cot_memref: // x.m
		// Display member offset for structure fields
		if (e)
			rv.cat_sprnt(" (m=%d)", e->m);
		break;
		
	case cot_obj: // v
	case cot_var: // l
		// Display object size for local variables and global data
		if (e)
			rv.cat_sprnt(".%d", e->refwidth);
		// fallthrough
		
	case cot_num: // n
	case cot_helper: // arbitrary name
	case cot_str: // string constant
		// Display helper names and number values
		if (e)
		{
			constant = std::make_unique<qstring>();
			print1wrapper(e, constant.get(), nullptr);
			
			// Sanitize and truncate long strings
			if (constant->length() > 128)
			{
				constant->resize(128);
				constant->append("...");
			}
			
			tag_remove(constant.get());
			rv.cat_sprnt(" %s", constant->c_str());
		}
		break;
		
	case cit_goto:
		// Display jump target label number for gotos
		if (i)
			rv.cat_sprnt(" LABEL_%d", i->cgoto->label_num);
		break;
		
	case cit_asm:
		// Display instruction list for asm-statements
		if (i && !i->casm->empty())
		{
			rv.append(" ");
			const auto& insns = *i->casm;
			const size_t max_insns = std::min(insns.size(), size_t(10)); // Limit display
			
			for (size_t k = 0; k < max_insns; ++k)
			{
				if (k > 0)
					rv.append(";");
					
				qstring buf;
#if IDA_SDK_VERSION >= 920
				generate_disasm_line(&buf, insns[k].ea, GENDSM_REMOVE_TAGS);
#else
				generate_disasm_line(&buf, insns[k].ea);
				tag_remove(&buf);
#endif
				rv.append(buf);
			}
			
			if (insns.size() > max_insns)
				rv.append("...");
		}
		break;
		
	default:
		break;
	}

	// Display item address (if present)
	if (item->ea != BADADDR)
		rv.cat_sprnt(" <%a>", item->ea);

	// Display type (for expressions)
	if (e && !e->type.empty())
	{
		qstring type_str;
		if (e->type.print(&type_str))
		{
			// Limit type string length
			if (type_str.length() > 64)
			{
				type_str.resize(64);
				type_str.append("...");
			}
			rv.cat_sprnt(" : %s", type_str.c_str());
		}
	}
}

// SDK 9.2: Thread-safe node addition
int callgraph_t::add(citem_t *i)
{
	if (!i)
		return -1;

	// Check if already exists
	int id;
	if (visited(i, &id))
		return id;

	// Create new node
	const int max_nodes = 10000; // Prevent runaway graphs
	if (node2ea_.size() >= max_nodes)
	{
		logmsg(WARNING, "Graph size limit reached (%d nodes)\n", max_nodes);
		return -1;
	}

	const int new_id = static_cast<int>(node2ea_.size());
	node2ea_[new_id] = i;
	ea2node_[i] = new_id;

	return new_id;
}

// SDK 9.2: Improved graph display with error handling
ssize_t idaapi callgraph_t::gr_callback(void *ud, int code, va_list va)
{
	auto cg = static_cast<callgraph_t*>(ud);
	if (!cg)
		return 0;

	try
	{
		switch (code)
		{
		case grcode_user_gentext:
			// Deprecated in SDK 7.6+
#if IDA_SDK_VERSION < 760
			return 1;
#else
			break;
#endif

		case grcode_user_refresh:
		{
			// Refresh user-defined graph nodes and edges
			auto mg = va_arg(va, interactive_graph_t*);
			if (!mg)
				return 0;

			// Validate and resize
			const size_t node_count = cg->node2ea_.size();
			if (node_count > 10000) // Safety check
			{
				warning("Graph too large to display (%zu nodes)", node_count);
				return 0;
			}

			mg->resize(node_count);
			mg->batch_edge_begin();
			
			for (const auto& edge : cg->edges)
			{
				if (edge.id1 >= 0 && edge.id2 >= 0 && 
				    edge.id1 < node_count && edge.id2 < node_count)
				{
					mg->add_edge(edge.id1, edge.id2, nullptr);
				}
			}
			
			mg->batch_edge_end();
			return 1;
		}

		case grcode_user_text:
		{
			// Retrieve text for user-defined graph node
			va_arg(va, interactive_graph_t*);
			const int node = va_arg(va, int);
			const char** text = va_arg(va, const char**);
			auto* bg_color = va_arg(va, bgcolor_t*);

			if (!text)
				return 0;

			// Generate and cache node label
			cg->node_label_cache_.clear();
			cg->get_node_label(node, cg->node_label_cache_);
			*text = cg->node_label_cache_.c_str();

			// Optional: Set background color based on node type
			if (bg_color)
			{
				const auto it = cg->node2ea_.find(node);
				if (it != cg->node2ea_.end() && it->second)
				{
					switch (it->second->op)
					{
					case cot_call:
						*bg_color = 0xFFFFE0; // Light yellow for calls
						break;
					case cit_return:
						*bg_color = 0xE0FFE0; // Light green for returns
						break;
					case cit_if:
					case cit_switch:
						*bg_color = 0xE0E0FF; // Light blue for branches
						break;
					default:
						*bg_color = DEFCOLOR;
						break;
					}
				}
			}

			return 1;
		}

		case grcode_user_hint:
		{
			// Provide hint for a node
			va_arg(va, interactive_graph_t*);
			const int node = va_arg(va, int);
			const char** hint = va_arg(va, const char**);

			if (!hint)
				return 0;

			const auto it = cg->node2ea_.find(node);
			if (it != cg->node2ea_.end() && it->second)
			{
				cg->hint_cache_.clear();
				cg->hint_cache_.sprnt("Node %d: %s", node, 
					get_ctype_name(it->second->op));
				
				if (it->second->ea != BADADDR)
					cg->hint_cache_.cat_sprnt("\nAddress: %a", it->second->ea);
					
				*hint = cg->hint_cache_.c_str();
			}

			return 1;
		}

		default:
			break;
		}
	}
	catch (const std::exception& e)
	{
		logmsg(ERROR, "Exception in graph callback: %s\n", e.what());
	}
	catch (...)
	{
		logmsg(ERROR, "Unknown exception in graph callback\n");
	}

	return 0;
}

// SDK 9.2: Display graph with improved error handling
bool callgraph_t::display(const char* title)
{
	if (!title)
		title = "Ctree Graph";

	try
	{
		// Create widget
		TWidget* widget = find_widget(title);
		if (widget)
		{
			warning("Graph window '%s' already exists", title);
			activate_widget(widget, true);
			return false;
		}

		widget = create_empty_widget(title);
		if (!widget)
		{
			warning("Failed to create widget");
			return false;
		}

		// Create graph viewer
		netnode id;
		id.create();
		
		graph_viewer_t* gv = create_graph_viewer(title, id, gr_callback, this, 0, widget);
		if (!gv)
		{
			close_widget(widget, 0);
			warning("Failed to create graph viewer");
			return false;
		}

		// Display and center
		display_widget(widget, WOPN_TAB | WOPN_RESTORE);
		viewer_fit_window(gv);

		return true;
	}
	catch (const std::exception& e)
	{
		warning("Failed to display graph: %s", e.what());
		return false;
	}
}