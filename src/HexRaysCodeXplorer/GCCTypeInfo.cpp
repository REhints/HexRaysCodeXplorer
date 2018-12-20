#include "GCCTypeInfo.h"
#include "GCCObjectFormatParser.h"
#include "ReconstructableType.h"
#include "offset.hpp"
#include "Utility.h"
#include "Debug.h"
#include "typeinf.hpp"
#if __clang__
// Ignore "offset of on non-standard-layout type" warning
#pragma clang diagnostic ignored "-Winvalid-offsetof"
#endif


GCCTypeInfo::GCCTypeInfo()
	: ea(BADADDR)
	, typeinfo_vtbl(BADADDR)
	, parentsCount(0)
	, parentsTypes(nullptr),
	vtable(0)
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

	GCC_RTTI::type_info tmp;
	if (!get_bytes(&tmp, sizeof(GCC_RTTI::type_info), ea))
		return 0;

	ea_t name_ea = tmp.__type_info_name;

	size_t length = get_max_strlit_length(name_ea, STRTYPE_C, ALOPT_IGNHEADS);
	qstring buffer;

	if (!get_strlit_contents(&buffer, name_ea, length, STRTYPE_C)) {
		return 0;
	}
	qstring name(buffer);
	std::string demangled_name;
	qstring demangled_name_qstring;
	name = qstring("_ZTS") + name;
	int32 res = demangle_name(&demangled_name_qstring, name.c_str(), 0);
	demangled_name = demangled_name_qstring.c_str();
	if (res != (MT_GCC3 | M_AUTOCRT | MT_RTTI))
	{
		return 0;
	}

	demangled_name = demangled_name.substr(19);

	if (tmp.__type_info_vtable != class_type_info_vtbl &&
		tmp.__type_info_vtable != si_class_type_info_vtbl &&
		tmp.__type_info_vtable != vmi_class_type_info_vtbl)
		return 0;


	GCCTypeInfo * result = new GCCTypeInfo();
	result->ea = ea;
	result->size = sizeof(GCC_RTTI::type_info);
	result->typeName = demangled_name;
	result->typeinfo_vtbl = tmp.__type_info_vtable;


	setUnknown(ea , sizeof(GCC_RTTI::type_info));
	MakeName(ea, demangled_name_qstring, "RTTI_", "");

	if (tmp.__type_info_vtable == class_type_info_vtbl)
	{

		tinfo_t tinfo;
		if (tinfo.get_named_type(get_idati(), "GCC_RTTI::type_info")) {
			apply_tinfo(ea, tinfo, TINFO_DEFINITE);
		}
		g_KnownTypes[ea] = result;
		return result;
	}


	if (tmp.__type_info_vtable == si_class_type_info_vtbl) {
		GCC_RTTI::__si_class_type_info si_class;
		if (!get_bytes(&si_class, sizeof(GCC_RTTI::__si_class_type_info), ea))
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

		
		//assert(g_ReconstractedTypes.count(base->typeName));
		//ReconstructableType *baseReType = g_ReconstractedTypes[base->typeName];
		//baseReType->AddSubType(reType);
		//reType->SetParent(baseReType, 0);
		

		setUnknown(ea + ea_t(offsetof(GCC_RTTI::__si_class_type_info, base)), sizeof(GCC_RTTI::__si_class_type_info));
		tinfo_t tinfo;
		if (tinfo.get_named_type(get_idati(), "GCC_RTTI::__si_class_type_info")) {
			apply_tinfo(ea, tinfo, TINFO_DEFINITE);
		}
		result->parentsCount = 1;
		result->parentsTypes = new GCCParentType*[1];
		result->parentsTypes[0] = new GCCParentType();
		result->parentsTypes[0]->ea = base->ea;
		result->parentsTypes[0]->info = base;
		result->parentsTypes[0]->flags = 0;
		result->parentsTypes[0]->offset = 0;
		g_KnownTypes[ea] = result;
		result->size = sizeof(GCC_RTTI::__si_class_type_info);
		return result;
	}

	GCC_RTTI::__vmi_class_type_info vmi_class;
	if (!get_bytes(&vmi_class, sizeof(GCC_RTTI::__vmi_class_type_info), ea))
		return 0;

	// vmi_class.vmi_flags;  // WTF??

	result->parentsCount = vmi_class.vmi_base_count;
	result->parentsTypes = new GCCParentType*[result->parentsCount];
	ea_t addr = ea + ea_t(offsetof(GCC_RTTI::__vmi_class_type_info, vmi_bases));

	setUnknown(ea + ea_t(offsetof(GCC_RTTI::__vmi_class_type_info, vmi_flags)), sizeof(ea_t));
	create_dword(ea + ea_t(offsetof(GCC_RTTI::__vmi_class_type_info, vmi_flags)), sizeof(ea_t));

	setUnknown(ea + ea_t(offsetof(GCC_RTTI::__vmi_class_type_info, vmi_base_count)), sizeof(int));
	create_dword(ea + ea_t(offsetof(GCC_RTTI::__vmi_class_type_info, vmi_base_count)), sizeof(int));

	GCC_RTTI::__base_class_info baseInfo;
	for (int i = 0; i < vmi_class.vmi_base_count; ++i, addr += sizeof(baseInfo))
	{
		if (!get_bytes(&baseInfo, sizeof(baseInfo), addr))
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

		//assert(g_ReconstractedTypes.count(base->typeName));
		//ReconstructableType *baseReType = g_ReconstractedTypes[base->typeName];
		//baseReType->AddSubType(reType);
		//reType->SetParent(baseReType, baseInfo.vmi_offset_flags >> GCC_RTTI::offset_shift);
		
		setUnknown(addr + ea_t(offsetof(GCC_RTTI::__base_class_info, base)), sizeof(ea_t));
		op_plain_offset(addr + offsetof(GCC_RTTI::__base_class_info, base), 0, addr);

		setUnknown(addr + ea_t(offsetof(GCC_RTTI::__base_class_info, vmi_offset_flags)), sizeof(ea_t));
		create_dword(addr + ea_t(offsetof(GCC_RTTI::__base_class_info, vmi_offset_flags)), sizeof(int));
		result->parentsTypes[i] = new GCCParentType();
		result->parentsTypes[i]->ea = base->ea;
		result->parentsTypes[i]->ea = base->ea;
		result->parentsTypes[i]->info = base;
		result->parentsTypes[i]->flags = static_cast<unsigned>(baseInfo.vmi_offset_flags);

		result->parentsTypes[i]->offset = baseInfo.vmi_offset_flags >> GCC_RTTI::offset_shift;

		qstring flags;
		if (baseInfo.vmi_offset_flags & GCC_RTTI::virtual_mask)
			flags += " virtual_mask ";
		if (baseInfo.vmi_offset_flags & GCC_RTTI::public_mask)
			flags += " public_mask ";
		if (baseInfo.vmi_offset_flags >> GCC_RTTI::offset_shift)
			flags += " offset_shift ";
		set_cmt(addr + ea_t(offsetof(GCC_RTTI::__base_class_info, vmi_offset_flags)), flags.c_str(), false);
	}
	result->size = sizeof(GCC_RTTI::__vmi_class_type_info) + (vmi_class.vmi_base_count - 1)*sizeof(GCC_RTTI::__base_class_info);
	g_KnownTypes[ea] = result;
	return result;
}
