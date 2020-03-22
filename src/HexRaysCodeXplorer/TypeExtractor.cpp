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
#include "TypeExtractor.h"
#include "CtreeExtractor.h"

#include "Debug.h"
#include "Utility.h"

#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#define STRUCT_DUMP_MIN_MEMBER_COUNT  4

extern qvector <VTBL_info_t> vtbl_t_list;
extern std::unordered_map<ea_t, VTBL_info_t> rtti_vftables;

struct obj_fint_t : public ctree_parentee_t
{
	qstring vtbl_name;
	qstring var_name;
	bool bFound;

	int idaapi visit_expr(cexpr_t *e);

	obj_fint_t()
		: bFound(false)
	{}
};


int idaapi obj_fint_t::visit_expr(cexpr_t *e)
{
	// check if the expression being visited is variable
	if (e->op != cot_obj)
		return 0;

	// get the variable name
	qstring s;
	print1wrapper(e, &s, NULL);
	tag_remove(&s);

	// check for the target variable
	if (s != vtbl_name)
		return 0;

	size_t max_parents = 3;
	if (parents.size() < max_parents) {
		max_parents = parents.size();
	}

	for (size_t i = 1; i <= max_parents; i++) {
		citem_t *parent = parents.back();
		if (parent->is_expr() && parent->op == cot_asg) {
			cexpr_t * target_expr = (cexpr_t *)parent;

			while (target_expr->x != NULL && target_expr->op != cot_var && target_expr->op != cot_obj)
				target_expr = target_expr->x;

			if (target_expr->op == cot_var) {
				s.clear();
				print1wrapper(target_expr, &s, NULL);
				tag_remove(&s);

				var_name = s;
				bFound = true;
				break;
			}
		}
	}

	return 0;
}

void idaapi reset_pointer_type(cfuncptr_t cfunc, const qstring &var_name) {
	lvars_t * locals = cfunc->get_lvars();
	if (locals == NULL)
		return;

	qvector<lvar_t>::iterator locals_iter;

	for (locals_iter = locals->begin(); locals_iter != locals->end(); locals_iter++) {
		if (var_name != locals_iter->name)
			continue;

		tinfo_t int_type = tinfo_t(BT_INT32);
		locals_iter->set_final_lvar_type(int_type);
		locals_iter->set_user_type();
		cfunc->build_c_tree();
		break;
	}
}

bool idaapi find_var(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;

	// Determine the ctree item to highlight
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;

	// highlight == NULL might happen if one chooses variable at local variables declaration statement
	if (!highlight)
	{
		logmsg(DEBUG, "Invalid item is choosen");
		return false;
	}

	// the chosen item must be an expression and of 'variable' type
	if (highlight->is_expr() && (highlight->op == cot_obj))
	{
		cexpr_t *highl_expr = (cexpr_t *)highlight;

		qstring s;
		print1wrapper(highlight, &s, NULL);
		tag_remove(&s);

		// initialize type rebuilder
		obj_fint_t obj_find;
		obj_find.vtbl_name = s;

		// traverse the ctree structure
		obj_find.apply_to(&vu.cfunc->body, NULL);

		if (obj_find.bFound) {
			logmsg(DEBUG, (obj_find.var_name + "\n").c_str());
			reset_pointer_type(vu.cfunc, obj_find.var_name);

			vu.refresh_ctext();
		} else {
			warning("Failed to find variable...\n");
			logmsg(DEBUG, "Failed to find variable...\n");
		}
	}

	return true;
}

bool idaapi find_var(cfuncptr_t cfunc, const qstring& vtbl_name, qstring &var_name)
{
	var_name.clear();

	obj_fint_t obj_find;
	obj_find.vtbl_name = vtbl_name;

	if (obj_find.vtbl_name.find("const ") == 0)
		obj_find.vtbl_name.remove(0, 6);

	// traverse the ctree structure
	obj_find.apply_to(&cfunc->body, NULL);

	if (!obj_find.bFound) {
		logmsg(DEBUG, "Failed to find variable...\n");
		return false;
	}

	var_name = obj_find.var_name;
	reset_pointer_type(cfunc, var_name);
	return true;
}

tid_t idaapi merge_types(const qvector<qstring>& types_to_merge, const qstring& type_name) {
	tid_t struct_type_id = BADADDR;

	if (types_to_merge.empty())
		return struct_type_id;

	std::set<ea_t> offsets;

	struct_type_id = add_struc(BADADDR, type_name.c_str());
	if (struct_type_id == BADADDR)
		return struct_type_id;

	struc_t * struc = get_struc(struct_type_id);
	if (!struc)
		return struct_type_id;

	for (auto types_iter = types_to_merge.begin(), end = types_to_merge.end(); types_iter != end; ++types_iter) {
		struc_t * struc_type = get_struc(get_struc_id(types_iter->c_str()));
		if (!struc_type)
			continue;

		// enumerate members
		for ( ea_t offset = get_struc_first_offset(struc_type) ; offset != BADADDR ; offset = get_struc_next_offset(struc_type, offset)) {
			member_t * member_info = get_member(struc_type, offset);
			if (!member_info)
				continue;

			if (offsets.count(member_info->soff) == 0) {
				qstring member_name = get_member_name(member_info->id);
				asize_t member_size = get_member_size(member_info);

				if (member_name.find("vftbl_", 0) != -1) {
					tinfo_t tif;
					if (get_member_tinfo(&tif, member_info)) {
						add_struc_member(struc, member_name.c_str(), member_info->soff, dword_flag(), NULL, member_size);
						if (member_t * membr = get_member(struc, member_info->soff)) {
							set_member_tinfo(struc, membr, 0, tif, SET_MEMTI_COMPATIBLE);
						}
					}
				}
				else {
					add_struc_member(struc, member_name.c_str(), member_info->soff, member_info->flag, NULL, member_size);
				}

				offsets.insert(member_info->soff);
			}
		}
	}

	return struct_type_id;
}

void get_struct_key(struc_t * struc_type, const VTBL_info_t& vtbl_info, qstring &file_entry_key, bool &filtered, const std::unordered_map<ea_t, VTBL_info_t>& vtbl_map) {
	qstring sub_key;
	qstring vtables_sub_key;
	int vftbales_num = 0;
	int members_count = 0;
	for ( ea_t offset = get_struc_first_offset(struc_type) ; offset != BADADDR ; offset = get_struc_next_offset(struc_type, offset)) {
		member_t * member_info = get_member(struc_type, offset);
		if (member_info != NULL) {
			qstring member_name = get_member_name(member_info->id);
			asize_t member_size = get_member_size(member_info);

			if (member_name.find("vftbl_", 0) != -1) {

				ea_t vtable_addr = 0;
				int i;

				if (qsscanf(member_name.c_str(), "vftbl_%d_%" FMT_EA "x", &i, &vtable_addr) > 0) {
					if (vtbl_map.count(vtable_addr) != 0) {
						vtables_sub_key.cat_sprnt("_%d", vtbl_map.at(vtable_addr).methods);
					}
				}

				vftbales_num ++;
			}

			sub_key.cat_sprnt("_%d", member_size);

			members_count ++;
		}
	}
	file_entry_key.sprnt("t_%d_%d", vtbl_info.methods, vftbales_num);
	file_entry_key += vtables_sub_key;
	file_entry_key += sub_key;

	if (members_count < STRUCT_DUMP_MIN_MEMBER_COUNT)
		filtered = true;
}

void idaapi dump_type_info(int file_id, const VTBL_info_t& vtbl_info, const qstring& type_name, const std::unordered_map<ea_t, VTBL_info_t>& vtbl_map) {
	struc_t * struc_type = get_struc(get_struc_id(type_name.c_str()));
	if (!struc_type)
		return;

	qstring file_entry_key;
	qstring key_hash;
	bool filtered = false;

	get_struct_key(struc_type, vtbl_info, file_entry_key, filtered, vtbl_map);
	get_hash_of_string(file_entry_key, key_hash);

	if (filtered)
		return;

	qstring file_entry_val;
	tinfo_t new_type = create_typedef(type_name.c_str());

	if (new_type.is_correct() && new_type.print(&file_entry_val, NULL, PRTYPE_DEF | PRTYPE_1LINE)) {
		qstring line;

		line = key_hash + ";" + file_entry_key + ";";
		line.cat_sprnt("%a;", vtbl_info.ea_begin);
		line += file_entry_val + ";";

		if (rtti_vftables.count(vtbl_info.ea_begin) != 0) {
			VTBL_info_t vi = rtti_vftables[vtbl_info.ea_begin];
			line += vi.vtbl_name;
		}
		line.rtrim();
		line += "\r\n";
		qwrite(file_id, line.c_str(), line.length());
	}
}

bool idaapi check_subtype(VTBL_info_t vtbl_info, qstring subtype_name) {
	qstring search_str;
	search_str.sprnt("_%a", vtbl_info.ea_begin);

	struc_t * struc_type = get_struc(get_struc_id(subtype_name.c_str()));
	if (!struc_type)
		return false;

	// enumerate members
	for ( ea_t offset = get_struc_first_offset(struc_type) ; offset != BADADDR ; offset = get_struc_next_offset(struc_type, offset)) {
		member_t * member_info = get_member(struc_type, offset);
		if (!member_info)
			continue;

		qstring member_name = get_member_name(member_info->id);
		if (member_name.find(search_str, 0) != member_name.npos)
			return true;
	}

	return false;
}

bool idaapi extract_all_types(void *ud)
{
	logmsg(DEBUG, "extract_types()\n");

	// find vtables in the binary
	search_objects(false);

	qvector <VTBL_info_t>::iterator vtbl_iter;

	std::unordered_map<ea_t, VTBL_info_t> vtbl_map;
	for (vtbl_iter = vtbl_t_list.begin(); vtbl_iter != vtbl_t_list.end(); vtbl_iter++)
		vtbl_map[(*vtbl_iter).ea_begin] = (*vtbl_iter);

	int file_id = create_open_file("types.txt");
	if (file_id == -1)
	{
		logmsg(ERROR, "Failed to open file for dumping types.txt\r\n");
		return false;
	}

	int struct_no = 0;

	for (vtbl_iter = vtbl_t_list.begin(); vtbl_iter != vtbl_t_list.end(); vtbl_iter++) {
		qstring info_msg;
		info_msg.cat_sprnt("Processing vtable %s\n", (*vtbl_iter).vtbl_name.c_str());
		logmsg(DEBUG, info_msg.c_str());

		qstring type_name;
		type_name.sprnt("struc_2_%d", struct_no);

		ea_t cur_vt_ea = (*vtbl_iter).ea_begin;
		int struct_subno = 0;

		qvector <qstring> types_to_merge;
		for (ea_t addr = get_first_dref_to(cur_vt_ea); addr != BADADDR; addr = get_next_dref_to(cur_vt_ea, addr)) {
			qstring name;
			if (get_func_name(&name, addr) <= 0)
				continue;

			qstring info_msg1;
			info_msg1.cat_sprnt("\t%s\n", name.c_str());
			logmsg(DEBUG, info_msg1.c_str());

			func_t *pfn = get_func(addr);
			if (!pfn)
				continue;

			hexrays_failure_t hf;
			cfuncptr_t cfunc = decompile(pfn, &hf);
			if (cfunc != NULL) {
				qstring var_name;
				info_msg.clear();

				if (find_var(cfunc, (*vtbl_iter).vtbl_name, var_name)) {
					info_msg.cat_sprnt(" : %s\n", var_name.c_str());
					logmsg(DEBUG, info_msg.c_str());

					qstring sub_type_name = type_name;
					sub_type_name.cat_sprnt("_%d", struct_subno);
					struct_subno++;

					if (reconstruct_type(cfunc, var_name, sub_type_name)) {
						if (check_subtype((*vtbl_iter), sub_type_name)) {
							types_to_merge.push_back(sub_type_name);
						}
					}
				}
				else {
					info_msg.cat_sprnt(" : none\n");
					logmsg(DEBUG, info_msg.c_str());
				}
			}
		}

		struct_no++;

		merge_types(types_to_merge, type_name);
		dump_type_info(file_id, (*vtbl_iter), type_name, vtbl_map);
	}

	qclose(file_id);
	return true;
}
