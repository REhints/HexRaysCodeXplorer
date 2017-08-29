#pragma once
#include "Common.h"

class GCCTypeInfo;

class GCCParentType {
public:
	ea_t ea;
	GCCTypeInfo *info;
	unsigned int flags;
};

class GCCTypeInfo
{
public:
	GCCTypeInfo();
	~GCCTypeInfo();
	
	ea_t ea;
	qstring typeName;
	ea_t vtbl; // vtable of std::typeinfo.
	unsigned int parentsCount;
	GCCParentType **parentsTypes;

	static GCCTypeInfo *parseTypeInfo(ea_t ea);
};

