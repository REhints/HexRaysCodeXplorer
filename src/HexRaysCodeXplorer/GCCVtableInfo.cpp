#include "GCCVtableInfo.h"
#include "GCCObjectFormatParser.h"
#include "GCCTypeInfo.h"
#include "Utility.h"



GCCVtableInfo::GCCVtableInfo()
	: ea_start(BADADDR)
	, vtbl_start(BADADDR)
	, typeInfo(nullptr)
	, vtablesCount(0)
	, vtables(nullptr)
	, ea_end(BADADDR)
{
}


GCCVtableInfo::~GCCVtableInfo()
{
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

	addr = ea + offsetof(GCC_RTTI::__vtable_info, origin);
	methodsCount = findMethodsCount(addr);

	if (methodsCount == 0)
		return nullptr; // Doesnt look like vtable.

	GCCVtableInfo *result = new GCCVtableInfo();
	result->ea_start = ea;
	result->vtbl_start = ea + offsetof(GCC_RTTI::__vtable_info, origin);
	result->typeInfo = type;
	result->typeName = type->typeName;
	
	addr += methodsCount * sizeof(ea_t);
	if (type->parentsCount > 1) {
		result->vtablesCount = type->parentsCount;
		result->vtables = new GCCVtable[type->parentsCount]();
		for (unsigned i = 0; i < type->parentsCount; ++i)
		{
			if (!GCCVtableInfo::parseVtableInnerInfo(addr, &result->vtables[i]))
			{
				delete result;
				return nullptr;
			}
			addr += offsetof(GCC_RTTI::__vtable_info, origin);
			addr += result->vtables[i].methodsCount * sizeof(ea_t);
		}
	}
	else
	{
		result->vtablesCount = 1;
		result->vtables = new GCCVtable[1]();
		result->vtables[0].ea = ea;
		result->vtables[0].methodsCount = methodsCount;
		result->vtables[0].ptrDiff = 0;
		result->vtables[0].typeInfo = type;
	}
	result->ea_end = addr;
	g_KnownVtables[ea] = result;

	return result;
}
bool GCCVtableInfo::parseVtableInnerInfo(ea_t ea, GCCVtable *vtbl)
{
	/*
				result->vtables[i].ea = ea;
			result->vtables[i].methodsCount = methodsCount;
			result->vtables[i].ptrDiff = 0;
			result->vtables[i].typeInfo = type;
	*/

	GCC_RTTI::__vtable_info vtable;
	if (!get_bytes(&vtable, sizeof(GCC_RTTI::__vtable_info), ea))
		return false;

	if (vtable.ptrdiff >= 0)
		return false;

	GCCTypeInfo *type = GCCTypeInfo::parseTypeInfo(vtable.type_info);
	if (!type)
		return false;

	unsigned int methodsCount = 0;

	ea_t addr = ea + offsetof(GCC_RTTI::__vtable_info, origin);
	methodsCount = findMethodsCount(addr);

	if (methodsCount == 0)
		return false; // Doesn't look like vtable.

	vtbl->ea = ea;
	vtbl->methodsCount = methodsCount;
	vtbl->ptrDiff = static_cast<signed long>(vtable.ptrdiff);
	vtbl->typeInfo = type;
	return true;
}