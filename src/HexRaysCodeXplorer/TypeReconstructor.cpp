/*	Copyright (c) 2013-2016
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

#include "Debug.h"

#if !defined (__LINUX__) && !defined (__MAC__)
#include <tchar.h>
#else
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/*
	Representation of the reconstructed type
*/
struct type_reference {
	tinfo_t type;

	// offset of the referenced field by the helper, if any
	int hlpr_off;

	// size of the referenced field by the helper, if any
	int hlpr_size;

	// offset of the field after all checks
	int final_off;

	// size of the field after all checks
	int final_size;

	void idaapi init(cexpr_t *e);

	void idaapi update_hlpr(int off, int num);

	void idaapi update_type(cexpr_t *e);

	int idaapi update_offset(int offset);

	int idaapi update_size(int offset);

	int idaapi get_type_increment_val();

	int idaapi get_offset();

	int idaapi get_size();
};

void idaapi type_reference::init(cexpr_t *e) {
	type = e->type;
	hlpr_off = 0;
	final_off = 0;

	hlpr_size = 0;
	final_size = 0;
}

void idaapi type_reference::update_type(cexpr_t *e) {
	type = e->type;
}

int idaapi type_reference::get_type_increment_val() {
	if (type.is_ptr()) {
		ptr_type_data_t ptr_deets;
		if(type.get_ptr_details(&ptr_deets)) {
			return ptr_deets.obj_type.get_size();
		}
	} else if (type.is_array()) {
		return 1;
	} 
	
	return 1;
}

int idaapi type_reference::update_offset(int offset) {
	int update_factor = get_type_increment_val();
	final_off += update_factor * offset;

	return final_off;
}

int idaapi type_reference::update_size(int size) {
	final_size = size;
	return final_size;
}

int idaapi type_reference::get_offset()
{
	return final_off + hlpr_off;
}

int idaapi type_reference::get_size()
{
	if(hlpr_size != 0)
		return hlpr_size;
	else
		return final_size;
}

void idaapi type_reference::update_hlpr(int off, int num)
{
	hlpr_off = off;
	hlpr_size = num;
}

struct type_builder_t : public ctree_parentee_t
{
	std::vector<std::string> expression_to_match;

	struct struct_filed
	{
		int offset;
		int size;
		ea_t vftbl;
	};

	std::map<int, struct_filed> structure;
	
	int idaapi visit_expr(cexpr_t *e);

	tid_t get_structure(const qstring name);

	bool get_structure(std::map<int, struct_filed> &struc);

	int get_structure_size();

	bool match_expression(char *expr_name);

	bool idaapi check_memptr(struct_filed &str_fld);

	bool idaapi check_idx(struct_filed &str_fld);

	bool idaapi check_helper(citem_t *parent, int &offs, int &size);

	bool idaapi check_ptr(cexpr_t *e, struct_filed &str_fld);

	ea_t idaapi get_vftbl(cexpr_t *e);
};

int get_idx_type_size(cexpr_t *idx_expr)
{
	qstring buf;
	idx_expr->type.print(&buf);
	
	if(strstr(buf.c_str(), "char"))
		return 1;
	else if(strstr(buf.c_str(), "short"))
		return 2;
	else if(strstr(buf.c_str(), "int"))
		return 4;

	return 0;
}

bool idaapi type_builder_t::check_helper(citem_t *parent, int &off, int &num)
{
	if(parent->op == cot_call)
	{
		cexpr_t *expr_2 = (cexpr_t *)parent;
		if(!strcmp(get_ctype_name(expr_2->x->op), "helper"))
		{
			char buff[MAXSTR];
			expr_2->x->print1(buff, MAXSTR, NULL);
			tag_remove(buff, buff, MAXSTR);

			if(!strcmp(buff, "LOBYTE"))
			{
				num = 1;
				off = 0;
			}
			else if(!strcmp(buff, "HIBYTE") || !strcmp(buff, "BYTE3"))
			{
				num = 1;
				off = 3;
			}
			else if(!strcmp(buff, "BYTE1"))
			{
				num = 1;
				off = 1;
			}
			else if(!strcmp(buff, "BYTE2"))
			{
				num = 1;
				off = 2;
			}
			else if(!strcmp(buff, "LOWORD"))
			{
				num = 2;
				off = 0;
			}
			else if(!strcmp(buff, "HIWORD"))
			{
				num = 2;
				off = 2;
			}
			else
			{
				return false;
			}

			return true;
		}
	}

	return false;
}

bool idaapi type_builder_t::check_memptr(struct_filed &str_fld)
{
	// check if it has at least two parents
	if ( parents.size() > 2 )
	{
		citem_t *parent_1 = parents.back();

		// check if its parent is memptr
		if(parent_1->is_expr() && (parent_1->op == cot_memptr))
		{
			citem_t *parent_2 = parents[parents.size() - 2];
			citem_t *parent_3 = NULL;
			
			int num = 0;
			int off = 0;
			
			// check presence of the helper block
			bool bHelper = check_helper(parent_2, off, num);
			if(bHelper)
				parent_3 = parents[parents.size() - 3];
			else
				parent_3 = parent_2;

			if(parent_2->is_expr() && (parent_2->op == cot_asg))
			{
				cexpr_t *expr = (cexpr_t *)parent_1;

				if(bHelper)
				{
					str_fld.offset = expr->m + off;
					str_fld.size = num;
				}
				else
				{
					str_fld.offset = expr->m;
					str_fld.size = expr->ptrsize;
				}

				return true;
			}
		}
	}

	return false;
}

ea_t idaapi type_builder_t::get_vftbl(cexpr_t *e) {
	ea_t vftbl = BADADDR;

	if (e->is_expr()) {
		if ((e->op == cot_cast) && (e->x != NULL))
			e = e->x;

		if ((e->op == cot_ref) && (e->x != NULL))
			e = e->x;
			
		if (e->op == cot_obj) {
			vftbl = e->obj_ea;
		}
	}

	return vftbl;
}

bool idaapi type_builder_t::check_ptr(cexpr_t *e, struct_filed &str_fld)
{
	str_fld.offset = 0;
	str_fld.size = 0;
	str_fld.vftbl = BADADDR;

	type_reference referInfo;
	referInfo.init(e);

	qstring dbg_info;

	bool done = false;

	int par_size = parents.size();
	// check if it has at least three parents
	if ( par_size > 2 )
	{
		int offset = 0;
		int parent_idx = 1;

		int num = 0;
		int off = 0;

		for (size_t i = 0 ; i < parents.size() - 1 ; i ++) {
			citem_t *parent_i = parents[parents.size() - i - 1];

			// if its parent is addition 
			if(parent_i->is_expr() && (parent_i->op == cot_add))
			{
				cexpr_t *expr_2 = (cexpr_t *)parent_i;
				
				// get index_value
				char buff[MAXSTR];
				expr_2->y->print1(buff, MAXSTR, NULL);
				tag_remove(buff, buff, MAXSTR);
				
				int base = 10;
				if (strncmp(buff, "0x", 2) == 0)
					base = 16;
				
				offset = strtol(buff, NULL, base);

				referInfo.update_offset(offset);
			} else if(parent_i->is_expr() && (parent_i->op == cot_cast)) {
				referInfo.update_type((cexpr_t *)parent_i);
			} else if(parent_i->is_expr() && check_helper((cexpr_t *)parent_i, off, num)) {
				referInfo.update_hlpr(off, num);
			} else if(parent_i->is_expr() && (parent_i->op == cot_ptr)) {
				referInfo.update_size(((cexpr_t *)parent_i)->ptrsize);
				citem_t *parent_ii = parents[parents.size() - i - 2];
				if ((parent_ii->is_expr()) && (((cexpr_t *)parent_ii)->op == cot_asg) && (((cexpr_t *)parent_ii)->x == parent_i)) {
					ea_t vftbl = get_vftbl(((cexpr_t *)parent_ii)->y);
					if (vftbl != BADADDR)
						str_fld.vftbl = vftbl;
				}
				done = true;
				break;
			} else if(parent_i->is_expr() && (parent_i->op == cot_memptr)) {
				referInfo.update_offset(((cexpr_t *)parent_i)->m);
				referInfo.update_size(((cexpr_t *)parent_i)->ptrsize);
				done = true;
				break;
			} else if(parent_i->is_expr() && (parent_i->op == cot_asg)) {
				if (((cexpr_t *)parent_i)->y == e) { //parents[parents.size() - i]) {
					char expr_name[MAXSTR];
					((cexpr_t *)parent_i)->x->print1(expr_name, MAXSTR, NULL);
					tag_remove(expr_name, expr_name, MAXSTR);

					char comment[258];
					memset(comment, 0x00, sizeof(comment));
					sprintf_s(comment, sizeof(comment), "monitoring %s\r\n", expr_name);

					logmsg(DEBUG, comment);

					expression_to_match.push_back(expr_name);

					
				} else {
					get_vftbl(((cexpr_t *)parent_i)->y);
				}
				done = true;
				break;
			} else if(parent_i->is_expr() && (parent_i->op == cot_call)) {
				done = true;
				break;
			}
		}
	}

	if(done) {
		str_fld.offset = referInfo.get_offset();
		str_fld.size = referInfo.get_size();
		if (str_fld.size == 0) {
			str_fld.size = 4;
		}

		if (str_fld.vftbl != BADADDR) {
			char tmp[1024];
			memset(tmp, 0x00, sizeof(tmp));
			sprintf_s(tmp, sizeof(tmp), "vftbl reference detected at offset 0x%X, ea=0x%08X\r\n", str_fld.offset, str_fld.vftbl);

			logmsg(DEBUG, tmp);
		}
	}

	return done;
}

bool idaapi type_builder_t::check_idx(struct_filed &str_fld)
{
	// check if it has at least two parents
	if ( parents.size() > 1 )
	{
		citem_t *parent_1 = parents.back();

		// if its parrent is 
		if(parent_1->is_expr() && (parent_1->op == cot_memptr))
		{
			citem_t *parent_2 = parents[parents.size() - 2];
			if(parent_2->op == cot_idx)
			{
				cexpr_t *expr_2 = (cexpr_t *)parent_2;
				
				// get index_value
				char buff[MAXSTR];
				expr_2->y->print1(buff, MAXSTR, NULL);
				tag_remove(buff, buff, MAXSTR);
				int num = atoi(buff);
						
				citem_t *parent_3 = parents[parents.size() - 3];
				if(parent_3->is_expr() && (parent_3->op == cot_asg))
				{
					cexpr_t *expr_1 = (cexpr_t *)parent_1;	
				
					str_fld.offset = expr_1->m + num;
					str_fld.size = get_idx_type_size(expr_2);

					return true;
				}
			}
		}
	}

	return false;
}

bool type_builder_t::match_expression(char *expr_name) {
	for (std::vector<std::string>::iterator it = expression_to_match.begin(); it != expression_to_match.end(); ++it) {
		if ((*it).compare(expr_name) == 0)
			return true;
	}

	return false;
}

int idaapi type_builder_t::visit_expr(cexpr_t *e)
{
	// check if the expression being visited is variable
	if(e->op == cot_var)
	{
		// get the variable name
		char expr_name[MAXSTR];
		e->print1(expr_name, MAXSTR, NULL);
        tag_remove(expr_name, expr_name, MAXSTR);

		// check for the target variable
		if(match_expression(expr_name))
		{
			struct_filed str_fld;

			if(check_ptr(e, str_fld)) {
				std::pair<std::map<int,struct_filed>::iterator,bool> ret;
				ret = structure.insert(std::pair<int,struct_filed>(str_fld.offset, str_fld));
				if ((ret.second == false) && (str_fld.vftbl != BADADDR)) {
					structure[str_fld.offset] = str_fld;
				}
			}
		}
	}

	return 0;
}

int type_builder_t::get_structure_size()
{
	int highest_offset = 0;
	int reference_size = 0;

	
	for(std::map<int, struct_filed>::iterator i = structure.begin(); i != structure.end() ; i ++)
	{
		if(highest_offset < i->second.offset)
		{
			highest_offset = i ->second.offset;
			reference_size = i->second.size;
		}
	}

	return highest_offset + reference_size;
}

tid_t type_builder_t::get_structure(const qstring name)
{
	tid_t struct_type_id = add_struc(BADADDR, name.c_str());
	if (struct_type_id != 0 || struct_type_id != -1)
	{
		struc_t * struc = get_struc(struct_type_id);
		if(struc != NULL)
		{
			opinfo_t opinfo;
			opinfo.tid = struct_type_id;

			int j = 0;
			
			for(std::map<int, struct_filed>::iterator i = structure.begin(); i != structure.end() ; i ++)
			{
				VTBL_info_t vtbl;

				flags_t member_flgs = 0;
				if(i->second.size == 1)
					member_flgs = byteflag();
				else if (i->second.size == 2)
					member_flgs = wordflag();
				else if (i->second.size == 4)
					member_flgs = dwrdflag();
				else if (i->second.size == 8)
					member_flgs = qwrdflag();

				char field_name[258];
				memset(field_name, 0x00, sizeof(field_name));

				if((i->second.vftbl != BADADDR) && get_vbtbl_by_ea(i->second.vftbl, vtbl)) 
				{
					qstring vftbl_name = name;
					vftbl_name.cat_sprnt("_VTABLE_%X_%p", i->second.offset, i->second.vftbl);

					tid_t vtbl_str_id = create_vtbl_struct(vtbl.ea_begin, vtbl.ea_end, (char *)vftbl_name.c_str(), 0);
					if (vtbl_str_id != BADADDR) {
						sprintf_s(field_name, sizeof(field_name), "vftbl_%d_%p", j, i->second.vftbl);
						int iRet = add_struc_member(struc, field_name, i->second.offset, member_flgs, NULL, i->second.size);

						member_t * membr = get_member_by_name(struc, field_name);
						if (membr != NULL) {
							tinfo_t new_type = create_typedef((char *)vftbl_name.c_str());
							if(new_type.is_correct()) {
								smt_code_t dd = set_member_tinfo2(struc, membr, 0, make_pointer(new_type), SET_MEMTI_COMPATIBLE);
							}
						}
					}	
				} 
				else 
				{
					sprintf_s(field_name, sizeof(field_name), "field_%X", i->second.offset);
					int iRet = add_struc_member(struc, field_name, i->second.offset, member_flgs, NULL, i->second.size);
				}
				j ++;
			}
		}
	}
	return struct_type_id;
}

bool type_builder_t::get_structure(std::map<int, struct_filed> &struc)
{
	bool bResult = false;

	if (structure.size() != 0) {
		for(std::map<int, struct_filed>::iterator i = structure.begin(); i != structure.end() ; i ++) {
			struc[i->first] = i->second;
		}

		bResult = true;
	}

	return bResult;
}

bool idaapi reconstruct_type(void *ud)
{
	vdui_t &vu = *(vdui_t *)ud;
  
	// Determine the ctree item to highlight
	vu.get_current_item(USE_KEYBOARD);
	citem_t *highlight = vu.item.is_citem() ? vu.item.e : NULL;

	// highlight == NULL might happen if one chooses variable at local variables declaration statement
	if (highlight != NULL)
	{
		// the chosen item must be an expression and of 'variable' type
		if (highlight->is_expr() && (highlight->op == cot_var))
		{
			cexpr_t *highl_expr = (cexpr_t *)highlight;

			// initialize type rebuilder
			type_builder_t type_bldr;
			char highl_expr_name[MAXSTR];
			highl_expr->print1(highl_expr_name, sizeof(highl_expr_name), NULL);
			tag_remove(highl_expr_name, highl_expr_name, sizeof(highl_expr_name));
			type_bldr.expression_to_match.push_back(highl_expr_name);

			// traverse the ctree structure
			type_bldr.apply_to(&vu.cfunc->body, NULL);
			// get local var information
			lvar_t *lvar = vu.item.get_lvar();
			if (!type_bldr.structure.empty() && lvar != NULL)
			{
				qstring type_name{ "struct_name" };
				askqstr(&type_name, "Enter type name:");
				if (!type_name.empty())
				{
					tid_t struct_type_id = type_bldr.get_structure(type_name.c_str());
					if (struct_type_id != 0 || struct_type_id != -1)
					{
						tinfo_t new_type = create_typedef(type_name.c_str());
						if (new_type.is_correct())
						{
							qstring type_str;
							if (new_type.print(&type_str, NULL, PRTYPE_DEF | PRTYPE_MULTI))
							{
								msg("New type created:\r\n%s", type_str.c_str());
								logmsg(DEBUG, ("New type created:\r\n%s", type_str.c_str()));
								tinfo_t ptype = make_pointer(new_type);
								vu.set_lvar_type(lvar, ptype);
								vu.refresh_ctext();
								return true;
							}
						}
					}
				}
			}
			else
			{
				warning("Failed to reconstruct type, no field references have been found ...");
				logmsg(DEBUG, "Failed to reconstruct type, no field references have been found ...");
				return false;
			}
		}
	}
	else
	{
		warning("Selected item is invalid...");
		logmsg(DEBUG, "Selected item is invalid...");
		return false;
	}
}

bool idaapi reconstruct_type(cfuncptr_t cfunc, qstring var_name, qstring type_name)
{
	bool bResult = false;
	// initialize type rebuilder
	type_builder_t type_bldr;
	type_bldr.expression_to_match.push_back(var_name.c_str());
	
	// traverse the ctree structure
	type_bldr.apply_to(&cfunc->body, NULL);
	
	if (type_bldr.structure.size() != 0) {
		tid_t struct_type_id = type_bldr.get_structure(type_name.c_str());
		
		if(struct_type_id != 0 || struct_type_id != -1) {
			tinfo_t new_type = create_typedef(type_name.c_str());
			if(new_type.is_correct()) {
				qstring type_str = type_name.c_str();
				//if (new_type.print(&type_str, NULL, PRTYPE_DEF | PRTYPE_MULTI))
					logmsg(DEBUG, ("New type created: %s\n", type_str.c_str()));

				bResult = true;
			}
		}
	} else {
		warning("Failed to reconstruct type, no field references have been found...");
		logmsg(DEBUG, "Failed to reconstruct type, no field references have been found...");
	}

	return bResult;
}
