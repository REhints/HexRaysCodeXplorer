#include "GCCVtableInfo.h"
#include "GCCObjectFormatParser.h"
#include "GCCTypeInfo.h"
#include "Utility.h"
#include "ObjectExplorer.h"
#include "ReconstructableType.h"


GCCVtableInfo::GCCVtableInfo()
	: ea_start(BADADDR)
	, vtablesCount(0)
	, vtables(nullptr)
	, ea_end(BADADDR)
{
}

GCCVtableInfo::~GCCVtableInfo()
{
	if (vtables)
		delete[]vtables;

}

unsigned int findMethodsCount(ea_t addr)
{
	ea_t func;
	unsigned int methodsCount = 0;
	while (1) {
		func = getEa(addr);
		if (func != 0)
		{
			segment_t *seg = getseg(func);
			if (!seg)
			{
				break;
			}
			if ((seg->perm & SEGPERM_EXEC) == 0)
			{
				break;
			}
		}
		++methodsCount;
		addr += sizeof(ea_t);
	}
	// Now lets remove ending zeroes.
	while (methodsCount) {
		addr -= sizeof(ea_t);
		func = getEa(addr);
		if (func != 0)
			break;
		--methodsCount;
	}
	return methodsCount;
}


GCCVtableInfo *GCCVtableInfo::parseVtableInfo(ea_t ea)
{
	if (g_KnownVtables.count(ea))
		return g_KnownVtables[ea];

	GCC_RTTI::__vtable_info vtable;
	ea_t addr;
	if (!get_bytes(&vtable, sizeof(GCC_RTTI::__vtable_info), ea))
		return nullptr;

	// Check ptrdiff is 0 for origin vtable
	if (vtable.ptrdiff != 0)
		return nullptr;

	GCCTypeInfo *type = GCCTypeInfo::parseTypeInfo(vtable.type_info);
	if (type == 0)
		return nullptr;
	
	unsigned int methodsCount = 0;

	addr = ea + sizeof(GCC_RTTI::__vtable_info);
	methodsCount = findMethodsCount(addr);

	if (methodsCount == 0)
		return nullptr; // Doesnt look like vtable.

	GCCVtableInfo *result = new GCCVtableInfo();
	result->ea_start = ea;
	result->typeInfo = type;
	result->typeName = type->typeName;
	type->vtable = result;
	

	addr += methodsCount * sizeof(ea_t);
	// tid_t vtbl_stru = create_vtbl_struct1(result->ea_start + sizeof(GCC_RTTI::__vtable_info), result->ea_start + sizeof(GCC_RTTI::__vtable_info) + methodsCount * sizeof(ea_t), type->typeName);

	std::string vtbl_name = type->typeName + VTBL_CLSNAME_POSTFIX;

	if (!type->parentsCount)
		result->vtablesCount = 1;
	else
		result->vtablesCount = type->parentsCount;
	result->vtables = new GCCVtable[result->vtablesCount]();

	result->vtables[0].ea = ea;
	result->vtables[0].methodsCount = methodsCount;
	result->vtables[0].ptrDiff = 0;
	result->vtables[0].name = result->typeName; //  +VTBL_CLSNAME_POSTFIX;
	if (type->parentsCount > 1) {
		for (unsigned i = 1; i < type->parentsCount; ++i)
		{
			if (!GCCVtableInfo::parseVtableInnerInfo(addr, &result->vtables[i]))
			{
				type->vtable = 0;
				delete result;
				return nullptr;
			}
			addr += sizeof(GCC_RTTI::__vtable_info);
			addr += result->vtables[i].methodsCount * sizeof(ea_t);
		}
	}

	result->ea_end = addr;
	g_KnownVtables[ea] = result;
	g_KnownVtableNames[result->typeName + VTBL_CLSNAME_POSTFIX] = result;

	setUnknown(ea, sizeof(GCC_RTTI::__vtable_info) + sizeof(ea)*(methodsCount - 1));
	MakeName(ea, qstring(type->typeName.c_str()), "RTTI_", VTBL_NAME_POSTFIX);
	//struc_t* new_struc = get_struc(vtbl_stru);
	//if (!new_struc)
	//	return result;
	
	//tinfo_t tinfo;
	//if (tinfo.get_numbered_type(get_idati(), new_struc->ordinal)) {
	//	apply_tinfo(ea, tinfo, TINFO_DEFINITE);
	//}
	
	return result;
}

bool GCCVtableInfo::parseVtableInnerInfo(ea_t ea, GCCVtable *vtbl)
{
	GCC_RTTI::__vtable_info vtable;
	if (!get_bytes(&vtable, sizeof(GCC_RTTI::__vtable_info), ea))
		return false;

	if (vtable.ptrdiff >= 0)
		return false;

	GCCTypeInfo *type = GCCTypeInfo::parseTypeInfo(vtable.type_info);
	if (!type)
		return false;

	unsigned int methodsCount = 0;

	ea_t addr = ea + sizeof(GCC_RTTI::__vtable_info);
	methodsCount = findMethodsCount(addr);

	if (methodsCount == 0)
		return false; // Doesn't look like vtable.

	vtbl->ea = ea;
	vtbl->methodsCount = methodsCount;
	vtbl->ptrDiff = static_cast<signed long>(vtable.ptrdiff);
	for (unsigned int i = 0; i < type->parentsCount; ++i) {
		if ((type->parentsTypes[i]->offset) == (-vtbl->ptrDiff))
		{
			vtbl->name = /*type->typeName + "::vtable_of_" + */ type->parentsTypes[i]->info->typeName;
			return true;
		}
	}
	vtbl->name = type->typeName + "::vtable_of_UNKNOWN";
	return true;	
}

