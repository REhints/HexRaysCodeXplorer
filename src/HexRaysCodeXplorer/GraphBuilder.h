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

#ifndef __H_GRAPHBUILDER__
#define __H_GRAPHBUILDER__

#pragma once

#include "Common.h"

// function call graph creator class
class callgraph_t
{
	// total number of the nodes in the graph
	int node_count;

	// node id to func addr and reverse lookup
	typedef std::map<citem_t *, int> ea_int_map_t;
	typedef std::map<int, citem_t *> int_ea_map_t;
	ea_int_map_t ea2node;
	int_ea_map_t node2ea;

	// current node search ptr
	int  cur_node;
	char cur_text[MAXSTR];

	bool visited(citem_t *i, int *nid);
  
public:

	citem_t *highlighted;
	
	int  add(citem_t *i);
	// edge structure
	struct edge_t
	{
		int id1;
		int id2;
		edge_t(int i1, int i2): id1(i1), id2(i2) { }
		edge_t(): id1(0), id2(0) { }
	};
	
	typedef qlist<edge_t> edges_t;

	// edge manipulation
	typedef edges_t::iterator edge_iterator;
	void create_edge(int id1, int id2);
  
	edge_iterator begin_edges() { return edges.begin(); }
	edge_iterator end_edges() { return edges.end(); }
  
	void clear_edges();
	
	callgraph_t();
	
	const int count() const { return node_count; }

  // node / func info
  struct nodeinfo_t
  {
    qstring name;
    bgcolor_t color;
    ea_t ea;
  };
  
  typedef std::map<int, nodeinfo_t> int_funcinfo_map_t;
  int_funcinfo_map_t cached_funcs;
  nodeinfo_t *get_info(int nid);


//  int walk_func(func_t *func);
private:
  edges_t edges;

  char * get_node_label(int n, char *buf, int bufsize) const;
};


// per function call graph context
class graph_info_t
{
// Actual context variables
public:
  callgraph_t fg;		// associated graph maker
  graph_viewer_t *gv;	// associated graph_view
  TForm *form;			// associated TForm
  vdui_t *vu;
  

  ea_t func_ea; // function ea in question
  qstring title; // the title

  size_t func_instance_no;
// Instance management
private:
  typedef qlist<graph_info_t *> graphinfo_list_t;
  typedef graphinfo_list_t::iterator iterator;
  
  // Remove instance upon deletion of the objects
  static graphinfo_list_t instances;


  graph_info_t();
public:
  static graph_info_t *create(ea_t func_ea, citem_t *it);
  static void destroy(graph_info_t *gi);
  static bool get_title(ea_t func_ea, size_t num_inst, qstring *out);
};

#endif