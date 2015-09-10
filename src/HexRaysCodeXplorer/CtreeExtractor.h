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

#ifndef __H_FUNCCTREEDUMPER__
#define __H_FUNCCTREEDUMPER__

#pragma once

// Helper class to get ctree
struct ctree_dumper_t : public ctree_parentee_t
{
	ctree_dumper_t() : ctree_parentee_t(true) {}
	qstring ctree_dump;
	qstring ctree_for_hash;

	int process(citem_t *i);
	int process_leave(citem_t *i);
	void process_for_hash(citem_t *i);
	// We treat expressions and statements the same way: add them to the graph
	int idaapi visit_insn(cinsn_t *i) { return process(i); }
	int idaapi visit_expr(cexpr_t *e) { return process(e); }
	// We treat expressions and statements the same way: add them to the graph
	int idaapi leave_insn(cinsn_t *i) { return process_leave(i); }
	int idaapi leave_expr(cexpr_t *e) { return process_leave(e); }
	bool idaapi filter_citem(citem_t *item);
	char * parse_ctree_item(citem_t *item, char *buf, int bufsize) const;
};


bool idaapi show_citem_custom_view(void *ud, qstring ctree_item, qstring item_name);
bool idaapi dump_funcs_ctree(void *ud, qstring &crypto_prefix);
bool idaapi extract_all_ctrees(void *ud);
int create_open_file(const char* file_name);
int get_hash_of_string(qstring &string_to_hash, qstring &hash);


#endif