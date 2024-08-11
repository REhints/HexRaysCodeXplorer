#include "Compat.h"
#include <expr.hpp>
#include <typeinf.hpp>

namespace Compat
{
	tid_t add_struc(uval_t idx, const char* name, bool is_union)
	{
		udt_type_data_t udt { .is_union = is_union };
		tinfo_t tif;
		tif.create_udt(udt);
		tif.set_named_type(nullptr, name);
		return tif.get_tid();
	}

	struc_error_t add_struc_member(tid_t sid, const char* fieldname, ea_t offset, flags64_t flag,
								   const opinfo_t* mt, asize_t nbytes)
	{
		qstring name_user;
		if (fieldname)
			qstr2user(&name_user, fieldname);

		qstring snippet;
		snippet.sprnt("add_struc_member(%ld, \"%s\", %ld, %llu, %ld, %ld);",
					  (long)sid, name_user.c_str(), (long)offset, flag, mt ? (long)mt->tid : -1L, (long)nbytes);

		idc_value_t result;
		eval_idc_snippet(&result, snippet.c_str());
		return (struc_error_t)result.num;
	}

	int get_member_flag(tid_t sid, asize_t offset)
	{
		qstring snippet;
		snippet.sprnt("get_member_flag(%ld, %ld);", (long)sid, (long)offset);

		idc_value_t result;
		eval_idc_snippet(&result, snippet.c_str());
		return result.num;
	}

	tid_t get_member_id(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm { .offset = offset };
			if (auto idx = tif.find_udm(&udm, STRMEM_AUTO); idx != -1)
				return tif.get_udm_tid(idx);
		}

		return BADADDR;
	}

	qstring get_member_name(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm { .offset = offset };
			if (auto idx = tif.find_udm(&udm, STRMEM_AUTO); idx != -1)
				return udm.name;
		}

		return qstring();
	}

	asize_t get_member_size(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm { .offset = offset };
			if (auto idx = tif.find_udm(&udm, STRMEM_AUTO); idx != -1)
				return udm.size / 8;
		}

		return BADADDR;
	}

	bool get_member_tinfo(tinfo_t* tif, tid_t sid, asize_t offset)
	{
		tinfo_t tif_local;
		if (tif_local.get_type_by_tid(sid) && tif_local.is_udt())
		{
			udm_t udm { .offset = offset };
			if (auto idx = tif_local.find_udm(&udm, STRMEM_AUTO); idx != -1)
				*tif = udm.type;
		}

		return false;
	}

	ea_t get_struc_first_offset(tid_t id)
	{
		qstring snippet;
		snippet.sprnt("get_first_member(%ld);", (long)id);

		idc_value_t result;
		eval_idc_snippet(&result, snippet.c_str());
		return result.num != -1 ? result.num : BADADDR;
	}

	tid_t get_struc_id(const char* name)
	{
		tid_t tid = get_named_type_tid(name);
		tinfo_t tif;
		return tid != BADADDR && tif.get_type_by_tid(tid) && tif.is_udt() ? tid : BADADDR;
	}

	qstring get_struc_name(tid_t id)
	{
		qstring name;
		get_tid_name(&name, id);
		return name;
	}

	ea_t get_struc_next_offset(tid_t id, ea_t offset)
	{
		qstring snippet;
		snippet.sprnt("get_next_offset(%ld, %ld);", (long)id, (long)offset);

		idc_value_t result;
		eval_idc_snippet(&result, snippet.c_str());
		return result.num != -1 ? result.num : BADADDR;
	}

	bool set_member_name(tid_t sid, ea_t offset, const char* name)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm { .offset = offset };
			if (auto idx = tif.find_udm(&udm, STRMEM_AUTO); idx != -1)
				return tif.rename_udm(idx, name) == TERR_OK;
		}

		return false;
	}

	bool set_member_tinfo(tid_t sid, uval_t memoff, const tinfo_t& tif, int flags)
	{
		qstring snippet;
		snippet.sprnt("set_member_type(%ld, %ld, %d, %ld, %zu);",
					  (long)sid, (long)memoff, flags, (long)tif.get_tid(), tif.get_size());

		idc_value_t result;
		eval_idc_snippet(&result, snippet.c_str());
		return result.num != 0;
	}

	bool set_struc_cmt(tid_t id, const char* cmt, bool repeatable)
	{
		tinfo_t tif;
		return tif.get_type_by_tid(id) && tif.set_type_cmt(cmt, !repeatable) == TERR_OK;
	}
}
