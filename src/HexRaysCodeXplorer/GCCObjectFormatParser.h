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

	virtual void getRttiInfo();
	virtual void clearInfo();

	void scanSeg4Vftables(segment_t *seg);
};

class GCCVtableInfo;
class GCCTypeInfo;

extern std::map<ea_t, GCCVtableInfo *>g_KnownVtables;
extern std::map<ea_t, GCCTypeInfo *>g_KnownTypes;
extern std::map<std::string, GCCVtableInfo *>g_KnownVtableNames;
extern std::map<std::string, GCCTypeInfo *>g_KnownTypeNames;

extern ea_t class_type_info_vtbl;
extern ea_t si_class_type_info_vtbl;
extern ea_t vmi_class_type_info_vtbl;

extern std::map<ea_t, VTBL_info_t> rtti_vftables;


