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
#include "ObjectFormatMSVC.h"

#include "Debug.h"

#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#define STRUCT_DUMP_MIN_MEMBER_COUNT  4

extern qvector <VTBL_info_t> vtbl_t_list;
extern std::map<ea_t, vftable::vtinfo> rtti_vftables;

struct obj_fint_t : public ctree_parentee_t
{
 	std::string vtbl_name;

	std::string var_name;

	bool bFound;

	int idaapi visit_expr(cexpr_t *e);

	obj_fint_t() : bFound(false) {}
};


int idaapi obj_fint_t::visit_expr(cexpr_t *e)
{
	// check if the expression being visited is variable
	if(e->op == cot_obj) {
		// get the variable name
		char expr_name[MAXSTR];
		e->print1(expr_name, MAXSTR, NULL);
        tag_remove(expr_name, expr_name, sizeof(expr_name));

		// check for the target variable
		if(!strcmp(expr_name, vtbl_name.c_str())) {
			size_t max_parents = 3;
			if ( parents.size() < max_parents ) {
				max_parents = parents.size();
			}
				
			for (size_t i = 1 ; i <= max_parents ; i ++) {
				citem_t *parent = parents[parents.size() - i];
				if(parent->is_expr() && (parent->op == cot_asg)) {
					cexpr_t * target_expr = (cexpr_t *)parent;
					while ((target_expr->x != NULL) && (target_expr->op != cot_var) && (target_expr->op != cot_obj))
						target_expr = target_expr->x;

					if (target_expr->op == cot_var) {
						target_expr->print1(expr_name, MAXSTR, NULL);
						tag_remove(expr_name, expr_name, sizeof(expr_name));
						var_name = expr_name;

						bFound = true;

						break;
					}
				}
			}
		}
	}

	return 0;
}

void idaapi reset_pointer_type(cfuncptr_t cfunc, qstring &var_name) {
	lvars_t * locals = cfunc->get_lvars();
	if (locals != NULL) {
		qvector<lvar_t>::iterator locals_iter;

		for (locals_iter = locals->begin(); locals_iter != locals->end(); locals_iter++) {
			if (!strcmp(var_name.c_str(), (*locals_iter).name.c_str())) {
				tinfo_t int_type = tinfo_t(BT_INT32);
				(*locals_iter).set_final_lvar_type(int_type);
				(*locals_iter).set_user_type();
				cfunc->build_c_tree();
				break;
			}
		}
	}
}

bool idaapi find_var(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
  
	// Determine the ctree item to highlight
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;

	// highlight == NULL might happen if one chooses variable at local variables declaration statement
	if(highlight != NULL)
	{
		// the chosen item must be an expression and of 'variable' type
		if(highlight->is_expr() && (highlight->op == cot_obj))
		{
			cexpr_t *highl_expr = (cexpr_t *)highlight;

			char expr_name[MAXSTR];
			highlight->print1(expr_name, MAXSTR, NULL);
			tag_remove(expr_name, expr_name, sizeof(expr_name));

			// initialize type rebuilder
			obj_fint_t obj_find;
			obj_find.vtbl_name = expr_name;
			
		
			// traverse the ctree structure
			obj_find.apply_to(&vu.cfunc->body, NULL);

			if (obj_find.bFound) {
				logmsg(DEBUG, obj_find.var_name.c_str());
				// Using this horrible code to remove warnings on GCC 4.9.2. Fix this later.
				qstring temp_var2=qstring(obj_find.var_name.c_str());
				qstring &temp_var= temp_var2;
				reset_pointer_type(vu.cfunc, temp_var);

			
				vu.refresh_ctext();
			} else {
				warning("Failed to find variable...");
				logmsg(DEBUG, "Failed to find variable...");
			}
		}
	}
	else
	{
		logmsg(DEBUG, "Invalid item is choosen");
	}

	return true;
}

bool idaapi find_var(cfuncptr_t cfunc, qstring vtbl_name, qstring &var_name)
{
	obj_fint_t obj_find;
	int offs = 0;
	if (!strncmp(vtbl_name.c_str(), "const ", 6))
		offs = 6;
	obj_find.vtbl_name = vtbl_name.c_str() + offs;
	bool bResult = false;
			
		
	// traverse the ctree structure
	obj_find.apply_to(&cfunc->body, NULL);

	if (obj_find.bFound) {
		var_name = obj_find.var_name.c_str();
		reset_pointer_type(cfunc, var_name);
		bResult = true;
	} else {
		logmsg(DEBUG, "Failed to find variable...");
	}

	return bResult;
}

tid_t idaapi merge_types(qvector<qstring> types_to_merge, qstring type_name) {
	tid_t struct_type_id = BADADDR;

	std::set<ea_t> offsets;

	if (types_to_merge.size() != 0) {
		struct_type_id = add_struc(BADADDR, type_name.c_str());
		if (struct_type_id != 0 || struct_type_id != BADADDR)
		{
			struc_t * struc = get_struc(struct_type_id);
			if(struc != NULL) {
				qvector<qstring>::iterator types_iter;
				for (types_iter = types_to_merge.begin(); types_iter != types_to_merge.end(); types_iter ++) {
					
					tid_t type_id = get_struc_id((*types_iter).c_str());
					if (type_id != BADADDR) {
						struc_t * struc_type = get_struc(type_id);
						if(struc_type != NULL) {
							// enumerate members
							for ( ea_t offset = get_struc_first_offset(struc_type) ; offset != BADADDR ; offset = get_struc_next_offset(struc_type, offset)) {
								member_t * member_info = get_member(struc_type, offset);
								if (member_info != NULL) {
									if (offsets.count(member_info->soff) == 0) {
										qstring member_name = get_member_name2(member_info->id);
										asize_t member_size = get_member_size(member_info);

										if (member_name.find("vftbl_", 0) != -1) {
											tinfo_t tif;
											if (get_member_tinfo2(member_info, &tif)) {
												add_struc_member(struc, member_name.c_str(), member_info->soff, dwrdflag(), NULL, member_size);
												member_t * membr = get_member(struc, member_info->soff);
												if (membr != NULL) {
													set_member_tinfo2(struc, membr, 0, tif, SET_MEMTI_COMPATIBLE);
												}
											}
										} else {
											add_struc_member(struc, member_name.c_str(), member_info->soff, member_info->flag, NULL, member_size);
										}

										offsets.insert(member_info->soff);
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return struct_type_id;
}

void get_struct_key(struc_t * struc_type, VTBL_info_t vtbl_info, qstring &file_entry_key, bool &filtered, std::map<ea_t, VTBL_info_t> vtbl_map) {
	qstring sub_key;
	qstring vtables_sub_key;
	int vftbales_num = 0;
	int members_count = 0;
	for ( ea_t offset = get_struc_first_offset(struc_type) ; offset != BADADDR ; offset = get_struc_next_offset(struc_type, offset)) {
		member_t * member_info = get_member(struc_type, offset);
		if (member_info != NULL) {
			qstring member_name = get_member_name2(member_info->id);
			asize_t member_size = get_member_size(member_info);

			if (member_name.find("vftbl_", 0) != -1) {

				ea_t vtable_addr = 0;
				int i;

				if (qsscanf(member_name.c_str(), "vftbl_%d_%p", &i, &vtable_addr) > 0) {
					if (vtbl_map.count(vtable_addr) != 0) {
						vtables_sub_key.cat_sprnt("_%d", vtbl_map[vtable_addr].methods);
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

void idaapi dump_type_info(int file_id, VTBL_info_t vtbl_info, qstring type_name, std::map<ea_t, VTBL_info_t> vtbl_map) {
	tid_t type_id = get_struc_id(type_name.c_str());
	if (type_id != BADADDR) {
		struc_t * struc_type = get_struc(type_id);
		if(struc_type != NULL) {
			qstring file_entry_key;
			qstring key_hash;
			bool filtered = false;
			
			get_struct_key(struc_type, vtbl_info, file_entry_key, filtered, vtbl_map);
			get_hash_of_string(file_entry_key, key_hash);

			if (!filtered) {
				qstring file_entry_val;
				tinfo_t new_type = create_typedef(type_name.c_str());
				if(new_type.is_correct()) {
					if (new_type.print(&file_entry_val, NULL, PRTYPE_DEF | PRTYPE_1LINE)) {
						qstring line;

						line = key_hash + ";" + file_entry_key + ";";
						line.cat_sprnt("%p;", vtbl_info.ea_begin);
						line += file_entry_val + ";";
						
						if (rtti_vftables.count(vtbl_info.ea_begin) != 0) {
							vftable::vtinfo vi = rtti_vftables[vtbl_info.ea_begin];
							line += vi.type_info;
						}
						line.rtrim();
						line += "\r\n";
						qwrite(file_id, line.c_str(), line.length());
					}
				}
			}
		}
	}
}

bool idaapi check_subtype(VTBL_info_t vtbl_info, qstring subtype_name) {
	bool bResult = false;
	qstring search_str;
	search_str.sprnt("_%p", vtbl_info.ea_begin);
	
	tid_t type_id = get_struc_id(subtype_name.c_str());
	if (type_id != BADADDR) {
		struc_t * struc_type = get_struc(type_id);
		if(struc_type != NULL) {
			// enumerate members
			for ( ea_t offset = get_struc_first_offset(struc_type) ; offset != BADADDR ; offset = get_struc_next_offset(struc_type, offset)) {
				member_t * member_info = get_member(struc_type, offset);
				if (member_info != NULL) {
					qstring member_name = get_member_name2(member_info->id);
					if (member_name.find(search_str, 0) != -1) {
						bResult = true;
						break;
					}
				}
			}
		}
	}

	return bResult;
}

bool idaapi extract_all_types(void *ud)
{
	logmsg(DEBUG, "extract_types()");

	// find vtables in the binary
	search_objects(false);

	qvector <VTBL_info_t>::iterator vtbl_iter;

	std::map<ea_t, VTBL_info_t> vtbl_map;
	for (vtbl_iter = vtbl_t_list.begin(); vtbl_iter != vtbl_t_list.end(); vtbl_iter++)
		vtbl_map[(*vtbl_iter).ea_begin] = (*vtbl_iter);

	int file_id = create_open_file("types.txt");
	if (file_id != BADADDR) {
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
				get_func_name2(&name, addr);

				

				qstring info_msg1;
				info_msg1.cat_sprnt("\t%s", name.c_str());
				logmsg(DEBUG, info_msg1.c_str());

				func_t *pfn = get_func(addr);
				if ( pfn != NULL ) {
					hexrays_failure_t hf;
					cfuncptr_t cfunc = decompile(pfn, &hf);
					if ( cfunc != NULL ) {
						qstring var_name;
						info_msg.clear();

						if (find_var(cfunc, (*vtbl_iter).vtbl_name, var_name)) {	
							info_msg.cat_sprnt(" : %s\n", var_name.c_str());
							logmsg(DEBUG, info_msg.c_str());

							qstring sub_type_name = type_name;
							sub_type_name.cat_sprnt("_%d", struct_subno);
							struct_subno ++;
							
							if (reconstruct_type(cfunc, var_name, sub_type_name)) {
								if (check_subtype((*vtbl_iter), sub_type_name)) {
									types_to_merge.push_back(sub_type_name);
								}
							}
						} else {
							info_msg.cat_sprnt(" : none\n", var_name.c_str());
							logmsg(DEBUG, info_msg.c_str());
						}
					}
				}
			}

			struct_no ++;

			merge_types(types_to_merge, type_name);
			dump_type_info(file_id, (*vtbl_iter), type_name, vtbl_map);
		}

		qclose(file_id);
	}
	
	return true;
}
