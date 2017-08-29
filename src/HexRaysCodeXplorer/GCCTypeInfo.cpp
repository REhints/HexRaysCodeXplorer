#include "GCCTypeInfo.h"
#include "GCCObjectFormatParser.h"
#include "offset.hpp"
#include "Utility.h"




GCCTypeInfo::GCCTypeInfo() : parentsCount(0), parentsTypes(0)
{
}


GCCTypeInfo::~GCCTypeInfo()
{
	if (parentsTypes)
		delete[] parentsTypes;

}


GCCTypeInfo *GCCTypeInfo::parseTypeInfo(ea_t ea)
{
	if (g_KnownTypes.count(ea))
		return g_KnownTypes[ea];

	ea_t name_ea;
	GCCTypeInfo * result;
	
	GCC_RTTI::type_info tmp;
	if (!get_many_bytes(ea, (uval_t *)&tmp, sizeof(GCC_RTTI::type_info)))
		return 0;
	name_ea = tmp.__type_info_name;

	size_t length = get_max_ascii_length(name_ea, ASCSTR_C, ALOPT_IGNHEADS);

	char *buffer = new char[length];
	memset(buffer, 0, length);

	if (!get_ascii_contents2(name_ea, length, ASCSTR_C, buffer, length)) {
		delete[] buffer;
		return 0;
	}
	qstring name(buffer);
	qstring demangled_name;
	name = qstring("_ZTS") + name;
	delete buffer;
	int32 res = demangle_name2(&demangled_name, name.c_str(), 0);
	if (res != (MT_GCC3 | M_AUTOCRT | MT_RTTI))
	{
		return 0;
	}

	demangled_name = demangled_name.substr(19);

	result = new GCCTypeInfo();
	result->ea = ea;
	result->typeName = demangled_name;
	result->vtbl = tmp.__type_info_vtable;
	
	setUnknown(ea + offsetof(GCC_RTTI::type_info, __type_info_vtable), sizeof(void*));
	set_offset(ea + offsetof(GCC_RTTI::type_info, __type_info_vtable), 0, 0);
	setUnknown(ea + offsetof(GCC_RTTI::type_info, __type_info_name), sizeof(void*));
	set_offset(ea + offsetof(GCC_RTTI::type_info, __type_info_name), 0, 0);
	MakeName(ea, demangled_name, "RTTI_", "");

	if (tmp.__type_info_vtable == class_type_info_vtbl)
	{
		g_KnownTypes[ea] = result;
		return result;
	}
		

	if (tmp.__type_info_vtable == si_class_type_info_vtbl)
	{
		GCC_RTTI::__si_class_type_info si_class;
		if (!get_many_bytes(ea, (uval_t *)&si_class, sizeof(GCC_RTTI::__si_class_type_info)))
		{
			delete result;
			return 0;
		}
		GCCTypeInfo *base = parseTypeInfo(si_class.base);
		if (base == 0)
		{
			delete result;
			return 0;
		}

		setUnknown(ea + offsetof(GCC_RTTI::__si_class_type_info, base), sizeof(void*));
		set_offset(ea + offsetof(GCC_RTTI::__si_class_type_info, base), 0, 0);

		result->parentsCount = 1;
		result->parentsTypes = new GCCParentType*[1];
		result->parentsTypes[0] = new GCCParentType();
		result->parentsTypes[0]->ea = base->ea;
		result->parentsTypes[0]->info = base;
		result->parentsTypes[0]->flags = 0;
		g_KnownTypes[ea] = result;
		return result;
	}

	if (tmp.__type_info_vtable != vmi_class_type_info_vtbl) {
		// Unknown type, ignore it
		delete result;
		return 0;
	}

	GCC_RTTI::__vmi_class_type_info vmi_class;
	if (!get_many_bytes(ea, (uval_t *)&vmi_class, sizeof(GCC_RTTI::__vmi_class_type_info)))
		return 0;

	vmi_class.vmi_flags;
	
	
	result->parentsCount = vmi_class.vmi_base_count;
	result->parentsTypes = new GCCParentType*[result->parentsCount];
	ea_t addr = ea + offsetof(GCC_RTTI::__vmi_class_type_info, vmi_bases);

	setUnknown(ea + offsetof(GCC_RTTI::__vmi_class_type_info, vmi_flags), sizeof(void*));
	doDwrd(ea + offsetof(GCC_RTTI::__vmi_class_type_info, vmi_flags), sizeof(void *));

	setUnknown(ea + offsetof(GCC_RTTI::__vmi_class_type_info, vmi_base_count), sizeof(int));
	doDwrd(ea + offsetof(GCC_RTTI::__vmi_class_type_info, vmi_base_count), sizeof(int));

	

	GCC_RTTI::__base_class_info baseInfo;
	for (int i = 0; i < vmi_class.vmi_base_count; ++i, addr += sizeof(baseInfo))
	{
		if (!get_many_bytes(addr, (uval_t *)&baseInfo, sizeof(baseInfo)))
		{
			delete result;
			return 0;
		}
			
		GCCTypeInfo *base = parseTypeInfo(baseInfo.base);
		if (base == 0)
		{
			delete result;
			return 0;
		}
		setUnknown(addr + offsetof(GCC_RTTI::__base_class_info, base), sizeof(void*));
		set_offset(addr + offsetof(GCC_RTTI::__base_class_info, base), 0, 0);

		setUnknown(addr + offsetof(GCC_RTTI::__base_class_info, vmi_offset_flags), sizeof(void*));
		doDwrd(addr + offsetof(GCC_RTTI::__base_class_info, vmi_offset_flags), sizeof(int));
		result->parentsTypes[i] = new GCCParentType();
		result->parentsTypes[i]->ea = base->ea;
		result->parentsTypes[i]->ea = base->ea;
		result->parentsTypes[i]->info = base;
		result->parentsTypes[i]->flags = baseInfo.vmi_offset_flags;

		qstring flags;
		if (baseInfo.vmi_offset_flags & baseInfo.virtual_mask)
			flags += " virtual_mask ";
		if (baseInfo.vmi_offset_flags & baseInfo.public_mask)
			flags += " public_mask ";
		if (baseInfo.vmi_offset_flags & baseInfo.offset_shift)
			flags += " offset_shift ";
		set_cmt(addr + offsetof(GCC_RTTI::__base_class_info, vmi_offset_flags), flags.c_str(), false);
	}
	g_KnownTypes[ea] = result;
	return result;
}