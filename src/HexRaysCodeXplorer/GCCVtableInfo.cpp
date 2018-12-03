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

tid_t create_vtbl_struct1(ea_t vtbl_addr, ea_t vtbl_addr_end, const qstring& vtbl_name)
{
	struc_error_t error;
	qstring struc_name = vtbl_name;
	struc_name += "::vtable";
	tid_t id = add_struc(BADADDR, struc_name.c_str());
	unsigned long members_count = 0;
	if (id == BADADDR) {
		if (!ask_str(&struc_name, HIST_IDENT, "Default name %s not correct. Enter other structure name: ", struc_name.c_str()))
			return BADNODE;
		id = add_struc(BADADDR, struc_name.c_str());
		if (id == BADADDR)
		{
			msg("failed to add struct: %s\n", struc_name.c_str());
			return BADNODE;
		}
		set_struc_cmt(id, vtbl_name.c_str(), true);
	}

	struc_t* new_struc = get_struc(id);
	if (!new_struc)
		return BADNODE;

	ea_t ea = vtbl_addr;
	ea_t offset = 0;
	for( ea_t ea = vtbl_addr; ea < vtbl_addr_end; ea += sizeof(ea_t))
	{
		++members_count;
		offset = ea - vtbl_addr;
		qstring method_name;
		ea_t method_ea = getEa(ea);

		if (ph.id == PLFM_ARM)
			method_ea &= (ea_t)-2;
		if (method_ea == 0)
			continue;
		if (!is_mapped(method_ea))
			continue; // We not going to check if it valid

		flags_t method_flags = get_flags(method_ea);
		const char* struc_member_name = nullptr;
		if (is_func(method_flags)) {
			method_name = get_short_name(method_ea);
			if (!method_name.empty())
				struc_member_name = method_name.c_str();
		}
#ifndef __EA64__
		error = add_struc_member(new_struc, NULL, offset, dword_flag(), NULL, sizeof(ea_t));
#else
		error = add_struc_member(new_struc, NULL, offset, qword_flag(), NULL, sizeof(ea_t));
#endif
		if (struc_member_name) {
			if (!set_member_name(new_struc, offset, struc_member_name)) {
				get_ea_name(&method_name, method_ea);
				set_member_name(new_struc, offset, struc_member_name);
			}
		}
	}


	qstring rttistruc_name = "RTTI::";
	rttistruc_name += vtbl_name;
	rttistruc_name += "::vtable";
	tid_t rtti_id = add_struc(BADADDR, rttistruc_name.c_str());

	if (rtti_id == BADADDR) {
		if (!ask_str(&rttistruc_name, HIST_IDENT, "Default name %s not correct. Enter other structure name: ", rttistruc_name.c_str()))
			return BADNODE;
		rtti_id = add_struc(BADADDR, rttistruc_name.c_str());
		if (rtti_id == BADADDR)
		{
			msg("failed to add struct: %s\n", rttistruc_name.c_str());
			return BADNODE;
		}
		set_struc_cmt(rtti_id, vtbl_name.c_str(), true);
	}

	struc_t* newrtti_struc = get_struc(rtti_id);
	if (!newrtti_struc)
		return BADNODE;


	opinfo_t info;
	info.tid = get_struc_id("GCC_RTTI::__vtable_info");
	error = add_struc_member(newrtti_struc, "rtti_info", 0, stru_flag(), &info, sizeof(GCC_RTTI::__vtable_info));

	info.tid = id;
	error = add_struc_member(newrtti_struc, "vtable", sizeof(GCC_RTTI::__vtable_info), stru_flag(), &info, vtbl_addr_end - vtbl_addr);
	
	return rtti_id;
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

tid_t GCCVtable::get_tid() {
	return get_struc_id(name.c_str());
}