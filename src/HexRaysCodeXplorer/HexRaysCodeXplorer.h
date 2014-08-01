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


#include <hexrays.hpp>
#include <gdl.hpp>
#include <graph.hpp>

// Hex-Rays API pointer
extern hexdsp_t *hexdsp;

static bool inited = false;

// Hotkey for the new command
static const char hotkey[] = "G";
static ushort hotcode;

//-------------------------------------------------------------------------
//                        red      green       blue
#define CL_WHITE         ((255)+  (255<<8)+  (255<<16)) //   0
#define CL_BLUE          ((0  )+  (0  <<8)+  (255<<16)) //   1
#define CL_RED           ((255)+  (0  <<8)+  (0  <<16)) //   2
#define CL_GREEN         ((0  )+  (255<<8)+  (0  <<16)) //   3
#define CL_YELLOW        ((255)+  (255<<8)+  (0  <<16)) //   4
#define CL_MAGENTA       ((255)+  (0  <<8)+  (255<<16)) //   5
#define CL_CYAN          ((0  )+  (255<<8)+  (255<<16)) //   6
#define CL_DARKGREY      ((85 )+  (85 <<8)+  (85 <<16)) //   7
#define CL_DARKBLUE      ((0  )+  (0  <<8)+  (128<<16)) //   8
#define CL_DARKRED       ((128)+  (0  <<8)+  (0  <<16)) //   9
#define CL_DARKGREEN     ((0  )+  (128<<8)+  (0  <<16)) //  10
#define CL_DARKYELLOW    ((128)+  (128<<8)+  (0  <<16)) //  11
#define CL_DARKMAGENTA   ((128)+  (0  <<8)+  (128<<16)) //  12
#define CL_DARKCYAN      ((0  )+  (128<<8)+  (128<<16)) //  13
#define CL_GOLD          ((255)+  (215<<8)+  (0  <<16)) //  14
#define CL_LIGHTGREY     ((170)+  (170<<8)+  (170<<16)) //  15
#define CL_LIGHTBLUE     ((128)+  (128<<8)+  (255<<16)) //  16
#define CL_LIGHTRED      ((255)+  (128<<8)+  (128<<16)) //  17
#define CL_LIGHTGREEN    ((128)+  (255<<8)+  (128<<16)) //  18
#define CL_LIGHTYELLOW   ((255)+  (255<<8)+  (128<<16)) //  19
#define CL_LIGHTMAGENTA  ((255)+  (128<<8)+  (255<<16)) //  20
#define CL_LIGHTCYAN     ((128)+  (255<<8)+  (255<<16)) //  21
#define CL_LILAC         ((238)+  (130<<8)+  (238<<16)) //  22
#define CL_TURQUOISE     ((64 )+  (224<<8)+  (208<<16)) //  23
#define CL_AQUAMARINE    ((127)+  (255<<8)+  (212<<16)) //  24
#define CL_KHAKI         ((240)+  (230<<8)+  (140<<16)) //  25
#define CL_PURPLE        ((160)+  (32 <<8)+  (240<<16)) //  26
#define CL_YELLOWGREEN   ((154)+  (205<<8)+  (50 <<16)) //  27
#define CL_PINK          ((255)+  (192<<8)+  (203<<16)) //  28
#define CL_ORANGE        ((255)+  (165<<8)+  (0  <<16)) //  29
#define CL_ORCHID        ((218)+  (112<<8)+  (214<<16)) //  30
#define CL_BLACK         ((0  )+  (0  <<8)+  (0  <<16)) //  31

//-------------------------------------------------------------------------
// Convert internal background color code into textual form for GDL
static const char *get_color_name(bgcolor_t c)
{
	switch ( c )
	{
	case CL_WHITE       : return "white";
	case CL_BLUE        : return "blue";
	case CL_RED         : return "red";
	case CL_GREEN       : return "green";
	case CL_YELLOW      : return "yellow";
	case CL_MAGENTA     : return "magenta";
	case CL_CYAN        : return "cyan";
	case CL_DARKGREY    : return "darkgrey";
	case CL_DARKBLUE    : return "darkblue";
	case CL_DARKRED     : return "darkred";
	case CL_DARKGREEN   : return "darkgreen";
	case CL_DARKYELLOW  : return "darkyellow";
	case CL_DARKMAGENTA : return "darkmagenta";
	case CL_DARKCYAN    : return "darkcyan";
	case CL_GOLD        : return "gold";
	case CL_LIGHTGREY   : return "lightgrey";
	case CL_LIGHTBLUE   : return "lightblue";
	case CL_LIGHTRED    : return "lightred";
	case CL_LIGHTGREEN  : return "lightgreen";
	case CL_LIGHTYELLOW : return "lightyellow";
	case CL_LIGHTMAGENTA: return "lightmagenta";
	case CL_LIGHTCYAN   : return "lightcyan";
	case CL_LILAC       : return "lilac";
	case CL_TURQUOISE   : return "turquoise";
	case CL_AQUAMARINE  : return "aquamarine";
	case CL_KHAKI       : return "khaki";
	case CL_PURPLE      : return "purple";
	case CL_YELLOWGREEN : return "yellowgreen";
	case CL_PINK        : return "pink";
	case CL_ORANGE      : return "orange";
	case CL_ORCHID      : return "orchid";
	case CL_BLACK       : return "black";
	}
	return "?";
}

//--------------------------------------------------------------------------
// Since we can not directly display cfunc_t as a graph, we build a graph
// object which will be saved as a GDL file and displayed with wingraph32.
class cfunc_graph_t : public gdl_graph_t
{
	typedef qvector<const citem_t *> itemrefs_t;
	itemrefs_t items;
	const citem_t *highlight;     // item to highlight
	friend struct graph_builder_t;
	array_of_intseq_t succs;
	array_of_intseq_t preds;
	int  idaapi nsucc(int b) const  { return size() ? succs[b].size() : 0; }
	int  idaapi npred(int b) const  { return size() ? preds[b].size() : 0; }
	int  idaapi succ(int b, int i) const { return succs[b][i]; }
	int  idaapi pred(int b, int i) const { return preds[b][i]; }
public:
	cfunc_graph_t(const citem_t *_highlight) : highlight(_highlight) {}
	char *idaapi get_node_label(int n, char *buf, int bufsize);
	bool idaapi print_edge(FILE *fp, int i, int j);
	bgcolor_t idaapi get_node_color(int n);
	void idaapi print_node_attributes(FILE *fp, int n);
	int idaapi size(void) const { return preds.size(); }
	int add_node(void)
	{
		int n = size();
		preds.resize(n+1);
		succs.resize(n+1);
		return n;
	}
	void add_edge(int x, int y)
	{
		preds[y].push_back(x);
		succs[x].push_back(y);
	}
};


static bool idaapi display_graph(void *ud);
func_t* get_func_by_name(const char *func_name);
static bool idaapi decompile_func(vdui_t &vu);
