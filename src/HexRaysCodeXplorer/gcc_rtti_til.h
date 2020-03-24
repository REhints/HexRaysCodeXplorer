#pragma once

struct GCC_RTTI::__vtable_info {
	size_t ptrdiff;
	void* type_info;
};
struct GCC_RTTI::__class_type_info;
struct GCC_RTTI::type_info {
	GCC_RTTI::__vtable_info* __type_info_vtable;
	char *  __type_info_name;
};
struct GCC_RTTI::__pbase_type_info : public GCC_RTTI::type_info {
	int quals;
	void *type;
	enum quals_masks {
		const_mask = 0x1,
		volatile_mask = 0x2,
		restrict_mask = 0x4,
		incomplete_mask = 0x8,
		incomplete_class_mask = 0x10
	};
};
struct GCC_RTTI::__pointer_type_info
	: public GCC_RTTI::__pbase_type_info {
	const GCC_RTTI::__class_type_info *klass;
};
struct GCC_RTTI::__base_class_info {
	void * base;
	size_t vmi_offset_flags;
	enum vmi_masks {
		virtual_mask = 0x1,
		public_mask = 0x2,
		hwm_bit = 2,
		offset_shift = 8
	};
};
struct GCC_RTTI::__class_type_info
	: public GCC_RTTI::type_info
{
	enum __sub_kind
	{
		__unknown = 0,
		__not_contained,
		__contained_ambig,
		__contained_virtual_mask = 0x1,
		__contained_public_mask = 0x2,
		__contained_mask = 1 << 2,
		__contained_private = __contained_mask,
		__contained_public = __contained_mask | __contained_public_mask
	};
};
struct GCC_RTTI::__si_class_type_info
	: public GCC_RTTI::__class_type_info
{
	void * base;
};
struct GCC_RTTI::__vmi_class_type_info : public GCC_RTTI::__class_type_info
{
	int vmi_flags;
	int vmi_base_count;
	struct GCC_RTTI::__base_class_info vmi_bases[1];

	enum vmi_flags_masks {
		non_diamond_repeat_mask = 0x1,
		diamond_shaped_mask = 0x2,
		non_public_base_mask = 0x4,
		public_base_mask = 0x8,
		__flags_unknown_mask = 0x10
	};
};
struct GCC_RTTI::__user_type_info : public GCC_RTTI::type_info
{
	enum sub_kind
	{
		unknown = 0,
		not_contained,
	  contained_ambig,
	  contained_mask = 4,
	  contained_virtual_mask = 1,
	  contained_public_mask = 2,
	  contained_private = contained_mask,
	  contained_public = contained_mask | contained_public_mask
	};

};

struct GCC_RTTI::virtual_destruct_vtable_info {
	struct GCC_RTTI::__vtable_info info;
	void (*scalar_destruct)(void *);
	void (*vector_destruct)(void *);
};