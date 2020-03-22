#pragma once
#include "Common.h"

class GCCTypeInfo;
class GCCVtableInfo;

class GCCParentType {
public:
	ea_t ea = BADADDR;
	GCCTypeInfo *info = nullptr;
	unsigned long offset;
	unsigned int flags = 0;
};

class GCCTypeInfo
{
public:
	GCCTypeInfo();
	~GCCTypeInfo();

	ea_t ea;
	size_t size;
	std::string typeName;
	ea_t typeinfo_vtbl; // vtable of std::typeinfo.
	unsigned int parentsCount;
	GCCParentType **parentsTypes;
	GCCVtableInfo *vtable;
	static GCCTypeInfo *parseTypeInfo(ea_t ea);
};

