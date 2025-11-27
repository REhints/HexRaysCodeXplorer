// Compat.cpp - Compatibility layer for IDA SDK 9.2
// Updated to use native SDK APIs instead of IDC workarounds

#include "Compat.h"
#include <expr.hpp>
#include <typeinf.hpp>
#include <bytes.hpp>
#include <name.hpp>

namespace Compat
{
	// SDK 9.2 optimized: Direct tinfo_t API usage for structure creation
	tid_t add_struc(uval_t idx, const char* name, bool is_union)
	{
		udt_type_data_t udt;
		udt.is_union = is_union;

		tinfo_t tif;
		if (!tif.create_udt(udt))
			return BADADDR;
		
		// SDK 9.2: improved error handling
		if (tif.set_named_type(nullptr, name) != TERR_OK)
			return BADADDR;
		
		return tif.get_tid();
	}

	// SDK 9.2: Native API instead of IDC workaround
	struc_error_t add_struc_member(tid_t sid, const char* fieldname, ea_t offset, flags64_t flag,
								   const opinfo_t* mt, asize_t nbytes)
	{
		tinfo_t struct_tif;
		if (!struct_tif.get_type_by_tid(sid) || !struct_tif.is_udt())
			return STRUC_ERROR_MEMBER_STRUCT;

		udt_type_data_t udt;
		if (!struct_tif.get_udt_details(&udt))
			return STRUC_ERROR_MEMBER_STRUCT;

		// Create member type from flags
		tinfo_t member_tif;
		if (mt && mt->tid != BADADDR)
		{
			if (!member_tif.get_type_by_tid(mt->tid))
				return STRUC_ERROR_MEMBER_TINFO;
		}
		else
		{
			// Create type based on size
			member_tif = tinfo_t(get_scalar_bt(nbytes));
		}

		// Add member
		udm_t udm;
		udm.offset = offset * 8; // SDK 9.2 uses bit offsets
		udm.size = nbytes * 8;
		udm.type = member_tif;
		udm.name = fieldname ? fieldname : "";

		udt.push_back(udm);
		struct_tif.create_udt(udt);
		
		return struct_tif.save_type() ? STRUC_ERROR_MEMBER_OK : STRUC_ERROR_MEMBER_STRUCT;
	}

	// SDK 9.2: Direct tinfo_t API usage
	int get_member_flag(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(sid) || !tif.is_udt())
			return 0;

		udm_t udm;
		udm.offset = offset * 8; // SDK 9.2 uses bit offsets

		int idx = tif.find_udm(&udm, STRMEM_AUTO);
		if (idx == -1)
			return 0;

		// Get member at index
		udt_type_data_t udt;
		if (tif.get_udt_details(&udt) && idx < udt.size())
		{
			// SDK 9.2: Return member size as flags (simplified)
			const udm_t& member = udt[idx];
			return static_cast<int>(member.type.get_size());
		}
		return 0;
	}

	// SDK 9.2: Corrected offset handling (bit offsets)
	tid_t get_member_id(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(sid) || !tif.is_udt())
			return BADADDR;

		udm_t udm;
		udm.offset = offset * 8; // SDK 9.2 uses bit offsets

		int idx = tif.find_udm(&udm, STRMEM_AUTO);
		if (idx != -1)
		{
			udt_type_data_t udt;
			if (tif.get_udt_details(&udt) && idx < udt.size())
			{
				return udt[idx].type.get_tid();
			}
		}

		return BADADDR;
	}

	// SDK 9.2: Enhanced with proper error handling
	qstring get_member_name(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(sid) || !tif.is_udt())
			return qstring();

		udm_t udm;
		udm.offset = offset * 8; // SDK 9.2 uses bit offsets

		int idx = tif.find_udm(&udm, STRMEM_AUTO);
		if (idx != -1)
		{
			udt_type_data_t udt;
			if (tif.get_udt_details(&udt) && idx < udt.size())
			{
				return udt[idx].name;
			}
		}

		return qstring();
	}

	// SDK 9.2: Proper bit to byte conversion
	asize_t get_member_size(tid_t sid, asize_t offset)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(sid) || !tif.is_udt())
			return BADADDR;

		udm_t udm;
		udm.offset = offset * 8; // SDK 9.2 uses bit offsets

		int idx = tif.find_udm(&udm, STRMEM_AUTO);
		if (idx != -1)
		{
			udt_type_data_t udt;
			if (tif.get_udt_details(&udt) && idx < udt.size())
			{
				return udt[idx].type.get_size();
			}
		}

		return BADADDR;
	}

	// SDK 9.2: Improved get_member_tinfo with native API
	bool get_member_tinfo(tinfo_t* tif, tid_t sid, asize_t offset)
	{
		if (!tif)
			return false;

		tinfo_t struct_tif;
		if (!struct_tif.get_type_by_tid(sid) || !struct_tif.is_udt())
			return false;

		udm_t udm;
		udm.offset = offset * 8; // SDK 9.2 uses bit offsets

		int idx = struct_tif.find_udm(&udm, STRMEM_AUTO);
		if (idx != -1)
		{
			udt_type_data_t udt;
			if (struct_tif.get_udt_details(&udt) && idx < udt.size())
			{
				*tif = udt[idx].type;
				return true;
			}
		}

		return false;
	}

	// SDK 9.2: Native API for first offset
	ea_t get_struc_first_offset(tid_t id)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(id) || !tif.is_udt())
			return BADADDR;

		udt_type_data_t udt;
		if (!tif.get_udt_details(&udt) || udt.empty())
			return BADADDR;

		return udt[0].offset / 8; // Convert from bits to bytes
	}

	// SDK 9.2: Proper structure ID retrieval
	tid_t get_struc_id(const char* name)
	{
		tid_t tid = get_named_type_tid(name);
		if (tid == BADADDR)
			return BADADDR;

		tinfo_t tif;
		if (!tif.get_type_by_tid(tid) || !tif.is_udt())
			return BADADDR;

		return tid;
	}

	// SDK 9.2: Direct name retrieval
	qstring get_struc_name(tid_t id)
	{
		qstring name;
		if (get_tid_name(&name, id))
			return name;
		return qstring();
	}

	// SDK 9.2: Native API for next offset
	ea_t get_struc_next_offset(tid_t id, ea_t offset)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(id) || !tif.is_udt())
			return BADADDR;

		udt_type_data_t udt;
		if (!tif.get_udt_details(&udt))
			return BADADDR;

		ea_t bit_offset = offset * 8;
		for (const auto& member : udt)
		{
			if (member.offset > bit_offset)
				return member.offset / 8; // Convert from bits to bytes
		}

		return BADADDR;
	}

	// SDK 9.2: Native member renaming
	bool set_member_name(tid_t sid, ea_t offset, const char* name)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(sid) || !tif.is_udt())
			return false;

		udm_t udm;
		udm.offset = offset * 8; // SDK 9.2 uses bit offsets

		int idx = tif.find_udm(&udm, STRMEM_AUTO);
		if (idx != -1)
		{
			return tif.rename_udm(idx, name) == TERR_OK;
		}

		return false;
	}

	// SDK 9.2: Improved member type setting
	bool set_member_tinfo(tid_t sid, uval_t memoff, const tinfo_t& new_tif, int flags)
	{
		tinfo_t struct_tif;
		if (!struct_tif.get_type_by_tid(sid) || !struct_tif.is_udt())
			return false;

		udt_type_data_t udt;
		if (!struct_tif.get_udt_details(&udt))
			return false;

		// Find and update member
		udm_t search_udm;
		search_udm.offset = memoff * 8; // SDK 9.2 uses bit offsets
		
		int idx = struct_tif.find_udm(&search_udm, STRMEM_AUTO);
		if (idx != -1 && idx < udt.size())
		{
			udt[idx].type = new_tif;
			udt[idx].size = new_tif.get_size() * 8;
			
			// Recreate structure with updated member
			struct_tif.create_udt(udt);
			return struct_tif.save_type();
		}

		return false;
	}

	// SDK 9.2: Native comment setting
	bool set_struc_cmt(tid_t id, const char* cmt, bool repeatable)
	{
		tinfo_t tif;
		if (!tif.get_type_by_tid(id))
			return false;
		
		return tif.set_type_cmt(cmt, !repeatable) == TERR_OK;
	}
}