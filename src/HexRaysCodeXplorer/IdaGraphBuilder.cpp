/*	Copyright (c) 2013
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


#include "Common.h"
#include "IdaGraphBuilder.h"
#include "HexRaysCodeXplorer.h"

#include <string>

#ifndef __LINUX__
#include <windows.h>
#else
#define RGB(r,g,b) ((bgcolor_t)(((char)(r)|((uint16_t)((char)(g))<<8))|(((uint32_t)(char)(b))<<16)))
#endif

//typedef std::map<obj_name, obj_addr> graph_nodes;

typedef std::map<ea_t, asize_t> basic_blocks_t;

static std::vector<std::string> graph_text;
static basic_blocks_t bbs;


static bool gather_basic_blocks(ea_t ea1, ea_t ea2)
{
	show_wait_box("Finding basic blocks");
	ea_t start = BADADDR;
	bool ok = true;
	int cnt = 0;
	while ( ea1 != ea2 )
	{
		if ( wasBreak() )
		{
			ok = false;
			break;
		}
		if ( start == BADADDR )
		{
			start = ea1;
			ea1 = nextthat(ea1, ea2, f_isCode, NULL);
			if ( ea1 >= ea2 )
				break;
			//start = ea1;
		}
		while ( ea1 < ea2 )
		{
			if ( !ua_ana0(ea1) )
				break;
			ea1 = get_item_end(ea1);
			if ( is_basic_block_end(false) )
				break;
		}
		if ( ea1 != start )
			bbs[start] = ea1 - start; // remember the bb start and size
		if ( !isCode(get_flags_novalue(ea1)) )
			start = BADADDR;
		else
			start = ea1;
	}
	hide_wait_box();
	return ok;
}


//--------------------------------------------------------------------------
// wrapper for gather_basic_blocks()
static void update_basic_blocks(void)
{
	bbs.clear();
	func_t *f = NULL;

	f = get_func(get_screen_ea());
	if( f != NULL )
	{
		if( gather_basic_blocks( f->startEA, f->endEA ) )
		{	
			//msg("List of basic blocks:\n");
			for ( basic_blocks_t::iterator p=bbs.begin(); p != bbs.end(); ++p )
			{
				size_t i = p->first;// - base;
				//msg("%08X: (end: %08X)\n",i,i+p->second);
			}
		}

	}

}


//--------------------------------------------------------------------------
// return number of instructions within two addresses
static size_t get_num_insns(ea_t start, ea_t end)
{
	ea_t cur = start;
	size_t insns = 0;

	while( cur != BADADDR )
	{
		if(isCode(getFlags(cur)))
			insns++;
		start = cur;
		cur=next_head( start, end );
	}

	return insns; 
}

//--------------------------------------------------------------------------
static int BuildGraph(void *, int code, va_list va)
{
	int result = 0;
	switch ( code )
	{

	case grcode_user_refresh: // refresh user-defined graph nodes and edges
		// in:  mutable_graph_t *g
		// out: success
		{
			mutable_graph_t *g = va_arg(va, mutable_graph_t *);
			msg("%x: refresh\n", g);

			if ( g->empty() )
				g->resize( (int)(bbs.size())  );

			int j=0;
			for ( basic_blocks_t::iterator p=bbs.begin(); p != bbs.end(); ++p )
			{
				//size_t i = p->first;// - base;
				//msg("%08X: (end: %08X)\n",i,i+p->second);
				xrefblk_t xb;
				for ( bool ok=xb.first_from(prevthat(p->first+p->second, 0, f_isCode, NULL), XREF_ALL); ok; ok=xb.next_from() )
				{
					//xb.to - contains the referenced address
					int k=0;
					for ( basic_blocks_t::iterator p2=bbs.begin(); p2 != bbs.end(); ++p2 )
					{
						if( xb.to == p2->first )
						{
							g->add_edge(j, k, NULL);
							msg("%08x: -> %08X\n", prevthat(p->first+p->second, 0, f_isCode, NULL), xb.to);
						}
						k++;
					}
				}
				j++;
			}
			result = true;
		}
		break;

	case grcode_user_gentext: // generate text for user-defined graph nodes
		// in:  mutable_graph_t *g
		// out: must return 0
		{
			mutable_graph_t *g = va_arg(va, mutable_graph_t *);
			msg("%x: generate text for graph nodes\n", g);
			graph_text.resize(g->size());

			for ( node_iterator p=g->begin(); p != g->end(); ++p )
			{
				int n = *p;
				char buf[MAXSTR];

				qsnprintf(buf,sizeof(buf),"Node    %8d\n",n);
				graph_text[n] = buf;

				int j=0;
				for ( basic_blocks_t::iterator bbi=bbs.begin(); bbi != bbs.end(); ++bbi )
				{
					if(n==j)
					{
						qsnprintf(buf, sizeof(buf), "StartEA %08X\n"
							"EndEA   %08X\n",
							bbi->first,
							bbi->first+bbi->second);
						graph_text[n] += buf;
						qsnprintf(buf,sizeof(buf),"Instr   %8d\n",get_num_insns(bbi->first,bbi->first+bbi->second));
						graph_text[n] += buf;
						break;
					}
					j++;
				}

				qsnprintf(buf, sizeof(buf),"Indeg   %8d\n"
					"Outdeg  %8d\n",
					g->npred(n),
					g->nsucc(n)
					);


				graph_text[n] += buf;

			}
			result = true;
		}
		break;

	case grcode_user_text:    // retrieve text for user-defined graph node
		// in:  mutable_graph_t *g
		//      int node
		//      const char **result
		//      bgcolor_t *bg_color (maybe NULL)
		// out: must return 0, result must be filled
		// NB: do not use anything calling GDI!
		{
			mutable_graph_t *g = va_arg(va, mutable_graph_t *);
			int node           = va_argi(va, int);
			const char **text  = va_arg(va, const char **);
			bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);

			int succ = g->nsucc(node);
			int	pred = g->npred(node);

			*text = graph_text[node].c_str();

			if ( bgcolor != NULL )
			{
				// same indegree as outdegree and != 0 ?
				if(pred == succ && pred != 0)
					*bgcolor = RGB(220, 220, 220);

				// a few edges only
				else if(  succ <= 2 && pred <= 2 )
				{
					if( succ == 0 || pred == 0 )
					{
						// nodes with no edges at all
						if(pred == succ)
							*bgcolor = RGB(255, 50, 50);
						// nodes with either in- or outdegree edges only
						else
							*bgcolor = RGB(0, 130, 255);
					}
					// "normal" node, default color
					else
						*bgcolor = DEFCOLOR;
				}
				// in- or outdegree > 2
				else
					*bgcolor = RGB( 255, 255, 0 );
			}

			result = true;
			qnotused(g);
		}
		break;


	case grcode_dblclicked:   // a graph node has been double clicked
		// in:  graph_viewer_t *gv
		//      selection_item_t *current_item
		// out: 0-ok, 1-ignore click
		{
			graph_viewer_t *v   = va_arg(va, graph_viewer_t *);
			selection_item_t *s = va_arg(va, selection_item_t *);

			if ( s->is_node )
			{
				int j=0;

				for ( basic_blocks_t::iterator bbi=bbs.begin(); bbi != bbs.end(); ++bbi )
				{
					if(s->node==j)
					{
						//jump to dblclicked node in disassembly/IDA graph view
						jumpto(bbi->first,-1);
						break;
					}
					j++;
				}
			}

		}
		break;

	}
	return result;
}
