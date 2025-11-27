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
		auto expr = static_cast<cexpr_t*>(item);
		
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
	size_t parent_count = parents.size();
	if (parent_count > 1) {
		ctree_dump += "(";
	}

	qstring buf;
	parse_ctree_item(item, buf);
	ctree_dump += buf;

	process_for_hash(item);
	return 0;
}

int ctree_dumper_t::process_leave(citem_t *item)
{
	size_t parent_count = parents.size();
	if (parent_count > 1) {
		ctree_dump += ")";
	}
	return 0;
}

void ctree_dumper_t::parse_ctree_item(citem_t *item, qstring& rv) const
{
	rv.clear();
	// Each node will have the element type at the first line
	if (const auto v = get_ctype_name(item->op))
		rv = v;

	const auto e = static_cast<const cexpr_t*>(item);
	const auto i = static_cast<const cinsn_t*>(item);

	// For some item types, display additional information
	qstring func_name;
	qstring s;
	switch (item->op)
	{
	case cot_call:
		if (e->x->op == cot_obj) {
			if (get_func_name(&func_name, e->x->obj_ea) == 0)
				rv.cat_sprnt(" sub_%a", e->x->obj_ea);
			else 
				rv.cat_sprnt(" %s", func_name.c_str());
		}
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

	// The second line of the node contains the item address
	rv.cat_sprnt(";ea->%a", item->ea);

	if ( item->is_expr() && !e->type.empty() )
	{
		// For typed expressions, the third line will have
		// the expression type in human readable form
		rv.append(';');
		qstring out;
		if (e->type.print(&out))
		{
			rv += out;
		}
		else
		{	// could not print the type?
			rv.append('?');
		}

		if(e->type.is_ptr())
		{
			const auto ptr_rem = ::remove_pointer(e->type);
			if(ptr_rem.is_struct())
			{
				qstring typenm;
				ptr_rem.print(&typenm, "prefix ", 0, 0, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI);
			}
		}
	}

}

struct ctree_dump_line {
	qvector<ea_t> referres;
	qstring ctree_for_hash;
	qstring ctree_dump;
	qstring func_name;
	int func_depth{};
	ea_t func_start{};
	ea_t func_end{};
	bool heuristic_flag{};
};

struct ctree_dump_line_impl : ctree_dump_line
{
};


int create_open_file(const char* file_name) {
	auto file_id = qopen(file_name, O_BINARY | O_TRUNC | O_CREAT);
	if (file_id == BADADDR)
		file_id = qcreate(file_name, 511);

	return file_id;
}

int get_hash_of_string(const qstring &string_to_hash, qstring &hash) {
	SHA1Context sha;
	uint8_t message_digest[SHA1HashSize];

	auto err = SHA1Reset(&sha);
	if (err == shaSuccess) {
		err = SHA1Input(&sha, (uint8_t *)string_to_hash.c_str(), static_cast<unsigned>(string_to_hash.length()));
		if (err == shaSuccess) {
			err = SHA1Result(&sha, message_digest);
			if (err == shaSuccess) {
				char digest_hex[SHA1HashSize * 2 + 1];
				memset(digest_hex, 0x00, sizeof(digest_hex));
				SHA1MessageDigestToString(message_digest, digest_hex);

				hash = digest_hex;
			}
		}
	}

	return err;
}

void dump_ctrees_in_file(std::map<ea_t, ctree_dump_line> &data_to_dump, const qstring &crypto_prefix) {
	const auto file_id = create_open_file("ctrees.txt");
	if (file_id == -1)
	{
		logmsg(ERROR, "Failed to open file for dumping ctress\r\n");
		return;
	}

	size_t crypt_prefix_len = crypto_prefix.length();

	for (auto ctrees_iter = data_to_dump.begin(); ctrees_iter != data_to_dump.end(); ++ctrees_iter) {
		const auto& cdl = ctrees_iter->second;

		qstring sha_hash;
		auto err = get_hash_of_string(cdl.ctree_for_hash, sha_hash);
		if (err != shaSuccess) {
			logmsg(ERROR, "Error in computing SHA1 hash\r\n");
			continue;
		}

		auto dump_line = sha_hash + ";";
		err = get_hash_of_string(cdl.ctree_dump, sha_hash);
		if (err != shaSuccess) {
			logmsg(ERROR, "Error in computing SHA1 hash\r\n");
			continue;
		}
		dump_line += sha_hash + ";";
		dump_line += cdl.ctree_dump;
		dump_line.cat_sprnt(";%d", cdl.func_depth);
		dump_line.cat_sprnt(";%08X", cdl.func_start);
		dump_line.cat_sprnt(";%08X", cdl.func_end);
		if ((cdl.func_name.length() > crypt_prefix_len) && (crypt_prefix_len > 0) && (cdl.func_name.find(crypto_prefix) == 0))
			dump_line.cat_sprnt(";E");
		else
			dump_line.cat_sprnt(";N");

		if ((cdl.heuristic_flag))
			dump_line.cat_sprnt(";H");
		else
			dump_line.cat_sprnt(";N");

		dump_line += "\n";

		qwrite(file_id, dump_line.c_str(), dump_line.length());
	}

	qclose(file_id);
}


inline bool func_name_has_prefix(const qstring &prefix, const ea_t start_ea) {
	if (prefix.length() <= 0)
		return false;

	qstring func_name;
	if (get_func_name(&func_name, start_ea) <= 0)
		return false;

	if (func_name.empty())
		return false;

	return func_name.find(prefix.c_str(), 0) == 0;
}

bool idaapi dump_funcs_ctree(void *ud, const qstring &crypto_prefix)
{
	logmsg(DEBUG, "dump_funcs_ctree entered\n");

	std::map<ea_t, ctree_dump_line> data_to_dump;

	size_t count = 0, heur_count = 0, crypto_count = 0;
	size_t total_func_qty = get_func_qty();
	for (size_t i = 0 ; i < total_func_qty ; i ++) {
		auto heuristic_flag = false;

		func_t *function = getn_func(i);
		if (function != nullptr) {
			bool crypto_flag = func_name_has_prefix(crypto_prefix, function->start_ea);

			// skip libs that are not marked as crypto
			if ( ((function->flags & FUNC_LIB) != 0) && !crypto_flag )
				continue;

			// From this point on, we have a function outside of lib or a crypto one

			// Ignore functions less than MIN_FUNC_SIZE_DUMP bytes
			if ( ((function->end_ea - function->start_ea) < MIN_FUNC_SIZE_DUMP) && !crypto_flag )
				continue;

			// If function is bigger than MIN_HEURISTIC_FUNC_SIZE_DUMP, mark as being triggered by the heuristic
			if (function->end_ea - function->start_ea > MIN_HEURISTIC_FUNC_SIZE_DUMP)
				heuristic_flag = true;

			// dump up to N_CRYPTO_FUNCS_TO_DUMP crypto functions
			// dump up to N_HEUR_FUNCS_TO_DUMP heuristic functions
			// at least N_FUNCS_TO_DUMP functions will be dumped
			if ((count < N_FUNCS_TO_DUMP) || (crypto_flag && (crypto_count < N_CRYPTO_FUNCS_TO_DUMP)) || (heuristic_flag && (heur_count < N_HEUR_FUNCS_TO_DUMP))) {
				hexrays_failure_t hf;
				cfuncptr_t cfunc = decompile(function, &hf);

				logmsg(DEBUG, "\nafter decompile()\n");
				if (cfunc != nullptr) {
					ctree_dumper_t ctree_dumper;
					ctree_dumper.apply_to(&cfunc->body, nullptr);

					ctree_dump_line func_dump;
					func_dump.ctree_dump = ctree_dumper.ctree_dump;
					func_dump.ctree_for_hash = ctree_dumper.ctree_for_hash;

					func_dump.func_depth = -1;

					func_dump.func_start = function->start_ea;
					func_dump.func_end = function->end_ea;

					qstring func_name;
					if (get_func_name(&func_name, function->start_ea) != 0) {
						if (func_name.length() > 0) {
							func_dump.func_name = func_name;
						}
					}

					func_parent_iterator_t fpi(function);
					for (ea_t addr = get_first_cref_to(function->start_ea); addr != BADADDR; addr = get_next_cref_to(function->start_ea, addr)) {
						func_t *referer = get_func(addr);
						if (referer != nullptr) {
							func_dump.referres.push_back(referer->start_ea);
						}
					}

					func_dump.heuristic_flag = heuristic_flag; // 0 or 1 depending on code above
					if (heuristic_flag)
						heur_count++;

					if (crypto_flag)
						crypto_count++;

					count++;

					data_to_dump[function->start_ea] = func_dump;
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
	static const qstring kDefaultPrefix = "crypto_";

	va_list va;
	va_end(va);

	auto crypto_prefix = kDefaultPrefix;
	if (!ask_str(&crypto_prefix, 0, "Enter prefix of crypto function names", va))
		return false;

	if(!crypto_prefix.empty()) {
		dump_funcs_ctree(nullptr, crypto_prefix);
	} else {
		warning("Incorrect prefix!!");
	}

	return true;
}


// Ctree Item Form Init
struct func_ctree_info_t
{
	TWidget *widget;
	TWidget *cv;
	TWidget *codeview;
	strvec_t sv;
	explicit func_ctree_info_t(TWidget *f) : widget(f), cv(nullptr), codeview(nullptr){}
};


bool idaapi show_citem_custom_view(void *ud, const qstring& ctree_item, const qstring& item_name)
{
	qstring form_name = "Ctree Item View: ";
	form_name.append(item_name);
	const auto widget = create_empty_widget(form_name.c_str());
	auto si = new func_ctree_info_t(widget);

	istringstream s_citem_str(ctree_item.c_str());
	string tmp_str;
	while (getline(s_citem_str, tmp_str, ';'))
	{
		qstring tmp_qstr = tmp_str.c_str();
		si->sv.push_back(simpleline_t(tmp_qstr));
	}

	simpleline_place_t s1;
	simpleline_place_t s2(static_cast<int>(ctree_item.size()));
	si->cv = create_custom_viewer("", &s1, &s2, &s1, nullptr, &si->sv, nullptr, nullptr, widget);
	si->codeview = create_code_viewer(si->cv, CDVF_NOLINES, widget);
	set_custom_viewer_handlers(si->cv, nullptr, si);
	display_widget(widget, WOPN_RESTORE);

	return false;
}

