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
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	==============================================================================
*/



#pragma once
#include "Common.h"
#include "IObjectFormatParser.h"
#include "ObjectExplorer.h"


namespace GCC_RTTI {
#pragma pack(push, 1)

	struct __vtable_info {
		sval_t ptrdiff;
		ea_t type_info;
	};


	struct __class_type_info;

	struct type_info {
		ea_t __type_info_vtable;
		ea_t  __type_info_name;
	};

	struct __pbase_type_info : public type_info {
		int quals;
		ea_t *type;

		enum quals_masks {
			const_mask = 0x1,
			volatile_mask = 0x2,
			restrict_mask = 0x4,
			incomplete_mask = 0x8,
			incomplete_class_mask = 0x10
		};

	};

	struct __pointer_type_info
		: public __pbase_type_info {
		const __class_type_info *klass;
	};

	enum vmi_masks {
		virtual_mask = 0x1,
		public_mask = 0x2,
		hwm_bit = 2,
		offset_shift = 8          /* bits to shift offset by */
	};

	struct __base_class_info {
		ea_t base;
		uval_t vmi_offset_flags;

	};


	struct __class_type_info
		: public type_info
	{
		enum __sub_kind
		{
			__unknown = 0,              /* we have no idea */
			__not_contained,            /* not contained within us (in some */
										/* circumstances this might mean not contained */
										/* publicly) */
										__contained_ambig,          /* contained ambiguously */

										__contained_virtual_mask = virtual_mask, /* via a virtual path */
										__contained_public_mask = public_mask,   /* via a public path */
										__contained_mask = 1 << hwm_bit,         /* contained within us */

										__contained_private = __contained_mask,
										__contained_public = __contained_mask | __contained_public_mask
		};


	};

	struct __si_class_type_info
		: public __class_type_info
	{
		ea_t base;
	};

	struct __vmi_class_type_info : public __class_type_info
	{
		int vmi_flags;
		int vmi_base_count;
		struct __base_class_info vmi_bases[1];

		enum vmi_flags_masks {
			non_diamond_repeat_mask = 0x1,   /* distinct instance of repeated base */
			diamond_shaped_mask = 0x2,       /* diamond shaped multiple inheritance */
			non_public_base_mask = 0x4,      /* has non-public direct or indirect base */
			public_base_mask = 0x8,          /* has public base (direct) */

			__flags_unknown_mask = 0x10
		};

	};

	struct __user_type_info : public type_info
	{
		enum sub_kind
		{
			unknown = 0,              // we have no idea
			not_contained,            // not contained within us (in some
									  // circumstances this might mean not contained
									  // publicly)
									  contained_ambig,          // contained ambiguously
									  contained_mask = 4,       // contained within us
									  contained_virtual_mask = 1, // via a virtual path
									  contained_public_mask = 2,  // via a public path
									  contained_private = contained_mask,
									  contained_public = contained_mask | contained_public_mask
		};

	};



#pragma pack(pop)
};

class GCCObjectFormatParser :
	public IObjectFormatParser
{

public:
	GCCObjectFormatParser();

	virtual ~GCCObjectFormatParser();
	/* Collect rtti info from a binary.
	*/
	virtual void get_rtti_info();
	/* clear collected rtti info.
	*/
	virtual void clear_info();
	/* Collect class_type_info_name, si_class_type_info_name,
		and vmi_class_type_info_name vtbls info from a binary.
		@param force when set will try to redifine already existant
		addresses of vtabls.
		@return zero if success.
	*/
	int collect_info_vtbls(bool force=false);


	void scanSeg4Vftables(segment_t *seg);
};

class GCCVtableInfo;
class GCCTypeInfo;

extern std::unordered_map<ea_t, GCCVtableInfo *>g_KnownVtables;
extern std::unordered_map<ea_t, GCCTypeInfo *>g_KnownTypes;
extern std::unordered_map<std::string, GCCVtableInfo *>g_KnownVtableNames;
extern std::unordered_map<std::string, GCCTypeInfo *>g_KnownTypeNames;

extern DLLEXPORT ea_t class_type_info_vtbl;
extern DLLEXPORT ea_t si_class_type_info_vtbl;
extern DLLEXPORT ea_t vmi_class_type_info_vtbl;

extern std::unordered_map<ea_t, VTBL_info_t> rtti_vftables;


