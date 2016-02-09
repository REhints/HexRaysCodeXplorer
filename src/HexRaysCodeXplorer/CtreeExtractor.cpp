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
#include "TypeReconstructor.h"
#include "CtreeExtractor.h"
#include "Utility.h"
#include "Debug.h"

#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#define MIN_HEURISTIC_FUNC_SIZE_DUMP 0x160
#define MIN_FUNC_SIZE_DUMP 0x60

#define N_FUNCS_TO_DUMP 40
#define N_HEUR_FUNCS_TO_DUMP 60
#define N_CRYPTO_FUNCS_TO_DUMP 30

#define MAX_FUNC_DEPTH 100

bool idaapi ctree_dumper_t::filter_citem(citem_t *item) {
	if (item->is_expr()) {
		cexpr_t * expr = (cexpr_t *)item;
		
		if (item->op == cot_cast)
			return true;
		else if (item->op == cot_helper)
			return true;
		else if ((item->op >= cot_postinc) && (item->op <= cot_predec)) 
			return true;
		else if ((item->op >= cot_idx) && ((item->op <= cot_last)))
			return true;
	} else {
		if (item->op == cit_expr)
			return true;
	}

	return false;
}

void ctree_dumper_t::process_for_hash(citem_t *item)
{
	if (!filter_citem(item)) {
		const char* ctype_name = get_ctype_name(item->op);
		ctree_for_hash.cat_sprnt("%s:", ctype_name);
	}
}

// Process a ctree item
int ctree_dumper_t::process(citem_t *item)
{
	int parent_count = parents.size();
	if (parent_count > 1) {
		ctree_dump += "(";
	}

	char buf[MAXSTR];
	parse_ctree_item(item, buf, MAXSTR);
	ctree_dump.cat_sprnt("%s", buf);
	
	process_for_hash(item);
	return 0;
}

int ctree_dumper_t::process_leave(citem_t *item)
{
	int parent_count = parents.size();
	if (parent_count > 1) {
		ctree_dump += ")";
	}
	return 0;
}

char * ctree_dumper_t::parse_ctree_item(citem_t *item, char *buf, int bufsize) const
{
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
			if (e->x->op == cot_obj) {
				if (get_func_name(e->x->obj_ea, buf, sizeof(buf)) == NULL)
					ptr += qsnprintf(ptr, endp - ptr, " sub_%a", e->x->obj_ea);
				else 
					ptr += qsnprintf(ptr, endp - ptr, " %s", buf);
			}
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
    
		// The second line of the node contains the item address
		ptr += qsnprintf(ptr, endp - ptr, ";ea->%a", item->ea);

		if ( item->is_expr() && !e->type.empty() )
		{
			// For typed expressions, the third line will have
			// the expression type in human readable form
			APPCHAR(ptr, endp, ';');
			qstring out;
			if (e->type.print(&out))
			{
				APPEND(ptr, endp, out.c_str());
			}
			else 
			{	// could not print the type?
				APPCHAR(ptr, endp, '?');
				APPZERO(ptr, endp);
			}

			if(e->type.is_ptr())
			{
				tinfo_t ptr_rem = ::remove_pointer(e->type);
				if(ptr_rem.is_struct())
				{
					qstring typenm;
					ptr_rem.print(&typenm, "prefix ", 0, 0, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI);
				}
			}
		}
	
	return buf;
}

struct ctree_dump_line {
	qvector<ea_t> referres;
	qstring ctree_for_hash;
	qstring ctree_dump;
	qstring func_name;
	int func_depth;
	ea_t func_start;
	ea_t func_end;
	bool heuristic_flag;
};


int create_open_file(const char* file_name) {
	int file_id = qopen(file_name, O_BINARY | O_TRUNC | O_CREAT);
	if (file_id == BADADDR)
		file_id = qcreate(file_name, 511);

	return file_id;
}

int get_hash_of_string(qstring &string_to_hash, qstring &hash) {
	SHA1Context sha;
	uint8_t Message_Digest[SHA1HashSize];
	int err;

	err = SHA1Reset(&sha);
	if (err == shaSuccess) {
		err = SHA1Input(&sha, (uint8_t *)string_to_hash.c_str(), string_to_hash.length());
		if (err == shaSuccess) {
			err = err = SHA1Result(&sha, Message_Digest);
			if (err == shaSuccess) {
				char digest_hex[SHA1HashSize * 2 + 1];
				memset(digest_hex, 0x00, sizeof(digest_hex));
				SHA1MessageDigestToString(Message_Digest, digest_hex);

				hash = digest_hex;
			}
		}
	}

	return err;
}

void dump_ctrees_in_file(std::map<ea_t, ctree_dump_line> &data_to_dump, qstring &crypto_prefix) {
	int file_id = create_open_file("ctrees.txt");
	if (file_id != -1) {

		size_t crypt_prefix_len = crypto_prefix.length();

		for (std::map<ea_t, ctree_dump_line>::iterator ctrees_iter = data_to_dump.begin(); ctrees_iter != data_to_dump.end() ; ctrees_iter ++) {
			qstring sha_hash;
			int err = get_hash_of_string((*ctrees_iter).second.ctree_for_hash, sha_hash);
			if (err == shaSuccess) {
				qstring dump_line = sha_hash + ";";
				err = get_hash_of_string((*ctrees_iter).second.ctree_dump, sha_hash);
				if (err == shaSuccess) {
					dump_line += sha_hash + ";";
					dump_line += (*ctrees_iter).second.ctree_dump;
					dump_line.cat_sprnt(";%d", (*ctrees_iter).second.func_depth);
					dump_line.cat_sprnt(";%08X", (*ctrees_iter).second.func_start);
					dump_line.cat_sprnt(";%08X", (*ctrees_iter).second.func_end);
					if (((*ctrees_iter).second.func_name.length() > crypt_prefix_len) && (crypt_prefix_len > 0) && ((*ctrees_iter).second.func_name.find(crypto_prefix) == 0))
						dump_line.cat_sprnt(";E", (*ctrees_iter).second.func_end);
					else
						dump_line.cat_sprnt(";N", (*ctrees_iter).second.func_end);
					
					if (((*ctrees_iter).second.heuristic_flag))
						dump_line.cat_sprnt(";H", (*ctrees_iter).second.func_end);
					else
						dump_line.cat_sprnt(";N", (*ctrees_iter).second.func_end);
					
					dump_line += "\n";
				}
				
				qwrite(file_id, dump_line.c_str(), dump_line.length());
					
			} 
			if (err != shaSuccess) {
				logmsg(ERROR, "Error in computing SHA1 hash\r\n");
			}
		}

		qclose(file_id);
	} else {
		logmsg(ERROR, "Failed to open file for dumping ctress\r\n");
	}
}


inline bool func_name_has_prefix(qstring &prefix, ea_t startEA) {
	qstring func_name;
	
	if (prefix.length() <= 0)
		return false;
	
	if (get_func_name2(&func_name, startEA) == 0)
		return false;
	
	if (func_name.length() <= 0)
		return false;
	
	if (func_name.find(prefix.c_str(), 0) != 0)
		return false;
	
	return true;
}

bool idaapi dump_funcs_ctree(void *ud, qstring &crypto_prefix) 
{
	logmsg(DEBUG, "dump_funcs_ctree entered\n");

	std::map<ea_t, ctree_dump_line> data_to_dump;

	// enumerate through all the functions in the idb file
	bool heuristic_flag;
	size_t count = 0, heur_count = 0, crypto_count = 0;
	size_t total_func_qty = get_func_qty();
	for (size_t i = 0 ; i < total_func_qty ; i ++) {
		heuristic_flag = 0;
		
		func_t *function = getn_func(i);
		if (function != NULL) {
			bool crypto_flag = func_name_has_prefix(crypto_prefix, function->startEA);
			
			// skip libs that are not marked as crypto
			if ( ((function->flags & FUNC_LIB) != 0) && !crypto_flag )
				continue;
			
			// From this point on, we have a function outside of lib or a crypto one
			
			// Ignore functions less than MIN_FUNC_SIZE_DUMP bytes
			if ( ((function->endEA - function->startEA) < MIN_FUNC_SIZE_DUMP) && !crypto_flag )
				continue;
			
			// If function is bigger than MIN_HEURISTIC_FUNC_SIZE_DUMP, mark as being triggered by the heuristic
			if (function->endEA - function->startEA > MIN_HEURISTIC_FUNC_SIZE_DUMP)
				heuristic_flag = 1;
				
			// dump up to N_CRYPTO_FUNCS_TO_DUMP crypto functions
			// dump up to N_HEUR_FUNCS_TO_DUMP heuristic functions
			// at least N_FUNCS_TO_DUMP functions will be dumped
			if ((count < N_FUNCS_TO_DUMP) || (crypto_flag && (crypto_count < N_CRYPTO_FUNCS_TO_DUMP)) || (heuristic_flag && (heur_count < N_HEUR_FUNCS_TO_DUMP))) {
				hexrays_failure_t hf;
				cfuncptr_t cfunc = decompile(function, &hf);

				logmsg(DEBUG, "\nafter decompile()\n");
				if (cfunc != NULL) {
					ctree_dumper_t ctree_dumper;
					ctree_dumper.apply_to(&cfunc->body, NULL);
					
					ctree_dump_line func_dump;
					func_dump.ctree_dump = ctree_dumper.ctree_dump;
					func_dump.ctree_for_hash = ctree_dumper.ctree_for_hash;

					func_dump.func_depth = -1;

					func_dump.func_start = function->startEA;
					func_dump.func_end = function->endEA;

					qstring func_name;
					if (get_func_name2(&func_name, function->startEA) != 0) {
						if (func_name.length() > 0) {
							func_dump.func_name = func_name;
						}
					}
					
					func_parent_iterator_t fpi(function);
					for (ea_t addr = get_first_cref_to(function->startEA); addr != BADADDR; addr = get_next_cref_to(function->startEA, addr)) {
						func_t *referer = get_func(addr);
						if (referer != NULL) {
							func_dump.referres.push_back(referer->startEA);
						}
					}
					
					func_dump.heuristic_flag = heuristic_flag; // 0 or 1 depending on code above
					if (heuristic_flag)
						heur_count++;

					if (crypto_flag)
						crypto_count++;
					
					count++;
					
					data_to_dump[function->startEA] = func_dump;
				}
			}
		}
	}
	
	dump_ctrees_in_file(data_to_dump, crypto_prefix);

	return true;
}

bool idaapi extract_all_ctrees(void *ud)
{
	// default prefix to display in the dialog
	qstring default_prefix = "crypto_";
	
	va_list va;
	va_end(va);
	
	char * crypto_prefix = vaskstr(0, default_prefix.c_str(), "Enter prefix of crypto function names", va);
	if((crypto_prefix != NULL) && (strlen(crypto_prefix) > 0)) {
		qstring qcrypt_prefix = crypto_prefix;
		dump_funcs_ctree(NULL, qcrypt_prefix);
	} else {
		warning("Incorrect prefix!!");
	}

	return true;
}


// Ctree Item Form Init
struct func_ctree_info_t
{
	TForm *form;
	TCustomControl *cv;
	TCustomControl *codeview;
	strvec_t sv;
	func_ctree_info_t(TForm *f) : form(f), cv(NULL) {}
};


bool idaapi show_citem_custom_view(void *ud, qstring ctree_item, qstring item_name)
{
	HWND hwnd = NULL;
	qstring form_name = "Ctree Item View: ";
	form_name.append(item_name);
	TForm *form = create_tform(form_name.c_str(), &hwnd);
	func_ctree_info_t *si = new func_ctree_info_t(form);

	istringstream s_citem_str(ctree_item.c_str());
	string tmp_str;
	while (getline(s_citem_str, tmp_str, ';'))
	{
		qstring tmp_qstr = tmp_str.c_str();
		si->sv.push_back(simpleline_t(tmp_qstr));
	}

	simpleline_place_t s1;
	simpleline_place_t s2(ctree_item.size());
	si->cv = create_custom_viewer("Ctree Item View: ", NULL, &s1, &s2, &s1, 0, &si->sv);
	si->codeview = create_code_viewer(form, si->cv, CDVF_NOLINES);
	set_custom_viewer_handlers(si->cv, NULL, si);
	open_tform(form, FORM_ONTOP | FORM_RESTORE);

	return false;
}

