#include "Compat.h"
#include <expr.hpp>
#include <typeinf.hpp>

namespace Compat
{
	tid_t add_struc(uval_t idx, const char* name, bool is_union)
	{
		udt_type_data_t udt;
		udt.is_union = is_union;

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

		idc_value_t result;
		idc_value_t args[6] = { sid, name_user, offset, flag, mt ? mt->tid : BADADDR, nbytes };
		call_idc_func(&result, "add_struc_member", args, 6);
		return static_cast<struc_error_t>(result.num);
	}

	int get_member_flag(tid_t sid, asize_t offset)
	{
		idc_value_t result;
		idc_value_t args[2] = { sid, offset };
		call_idc_func(&result, "get_member_flag", args, 2);
		return result.num;
	}

	tid_t get_member_id(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm;
			udm.offset = offset;

			int idx = tif.find_udm(&udm, STRMEM_AUTO);
			if (idx != -1)
				return tif.get_udm_tid(idx);
		}

		return BADADDR;
	}

	qstring get_member_name(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm;
			udm.offset = offset;

			int idx = tif.find_udm(&udm, STRMEM_AUTO);
			if (idx != -1)
				return udm.name;
		}

		return qstring();
	}

	asize_t get_member_size(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm;
			udm.offset = offset;

			int idx = tif.find_udm(&udm, STRMEM_AUTO);
			if (idx != -1)
				return udm.size / 8;
		}

		return BADADDR;
	}

	bool get_member_tinfo(tinfo_t* tif, tid_t sid, asize_t offset)
	{
		tinfo_t tif_local;
		if (tif_local.get_type_by_tid(sid) && tif_local.is_udt())
		{
			udm_t udm;
			udm.offset = offset;

			int idx = tif_local.find_udm(&udm, STRMEM_AUTO);
			if (idx != -1)
				*tif = udm.type;
		}

		return false;
	}

	ea_t get_struc_first_offset(tid_t id)
	{
		idc_value_t result;
		idc_value_t args[1] = { id };
		call_idc_func(&result, "get_first_member", args, 1);
		return result.num;
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
		idc_value_t result;
		idc_value_t args[2] = { id, offset };
		call_idc_func(&result, "get_next_offset", args, 2);
		return result.num;
	}

	bool set_member_name(tid_t sid, ea_t offset, const char* name)
	{
		tinfo_t tif;
		if (tif.get_type_by_tid(sid) && tif.is_udt())
		{
			udm_t udm;
			udm.offset = offset;

			int idx = tif.find_udm(&udm, STRMEM_AUTO);
			if (idx != -1)
				return tif.rename_udm(idx, name) == TERR_OK;
		}

		return false;
	}

	bool set_member_tinfo(tid_t sid, uval_t memoff, const tinfo_t& tif, int flags)
	{
		idc_value_t result;
		idc_value_t args[5] { sid, memoff, flags, tif.get_tid(), tif.get_size() };
		call_idc_func(&result, "set_member_type", args, 5);
		return result.num != 0;
	}

	bool set_struc_cmt(tid_t id, const char* cmt, bool repeatable)
	{
		tinfo_t tif;
		return tif.get_type_by_tid(id) && tif.set_type_cmt(cmt, !repeatable) == TERR_OK;
	}
}
