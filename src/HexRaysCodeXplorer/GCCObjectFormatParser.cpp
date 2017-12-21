#include "GCCObjectFormatParser.h"
#include "Common.h"
#include "entry.hpp"
#include "Debug.h"
#include "demangle.hpp"
#include "name.hpp"
#include "offset.hpp"
#include "nalt.hpp"
#include "bytes.hpp"
#include "Utility.h"
#include "stddef.h"
#include "GCCVtableInfo.h"
#include "GCCTypeInfo.h"


#define vmi_class_type_info_name "_ZTVN10__cxxabiv121__vmi_class_type_infoE"
#define class_type_info_name "_ZTVN10__cxxabiv117__class_type_infoE"
#define si_class_type_info_name "_ZTVN10__cxxabiv120__si_class_type_infoE"


extern std::map<ea_t, VTBL_info_t> rtti_vftables;

std::map<ea_t, GCCVtableInfo *>g_KnownVtables;
std::map<ea_t, GCCTypeInfo *>g_KnownTypes;

ea_t class_type_info_vtbl = -1;
ea_t si_class_type_info_vtbl = -1;
ea_t vmi_class_type_info_vtbl = -1;



GCCObjectFormatParser::GCCObjectFormatParser()
{
}


GCCObjectFormatParser::~GCCObjectFormatParser()
{
}

void GCCObjectFormatParser::getRttiInfo()
{
	qstring buffer;
	const size_t count = get_entry_qty();

	// First collect info about __cxxabiv1:: vtables
	for (int i = 0; i < count; ++i) {
		uval_t ordinal = get_entry_ordinal(i);
		get_entry_name(&buffer, ordinal);
		ea_t ea = get_entry(ordinal);
		ea += sizeof(void *) * 2;

		if (buffer == class_type_info_name)
		{
			class_type_info_vtbl = ea;
			set_name(ea, "__cxxabiv1::__class_type_info::vtable", SN_NOWARN);
		}

		if (buffer == si_class_type_info_name)
		{
			si_class_type_info_vtbl = ea;
			set_name(ea, "__cxxabiv1::__si_class_type_info::vtable", SN_NOWARN);
		}

		if (buffer == vmi_class_type_info_name)
		{
			vmi_class_type_info_vtbl = ea;
			set_name(ea, "__cxxabiv1::__vmi_class_type_info::vtable", SN_NOWARN);
		}
	}
	// now we can scan  segments for vtables.
	int segCount = get_segm_qty();
	for (int i = 0; i < segCount; i++)
	{
		if (segment_t *seg = getnseg(i))
		{
			if (seg->type == SEG_DATA)
			{
				scanSeg4Vftables(seg);
			}
		}
	}
}

void GCCObjectFormatParser::scanSeg4Vftables(segment_t *seg)
{
	UINT found = 0;
	if (seg->size() >= sizeof(ea_t))
	{
		ea_t startEA = ((seg->start_ea + sizeof(ea_t)) & ~((ea_t)(sizeof(ea_t) - 1)));
		ea_t endEA = (seg->end_ea - sizeof(ea_t));

		for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(void*))
		{
			// Struct of vtable is following:
			// 0: ptrdiff that tells "Where is the original object according to vtable. This one is 0 of -x;
			// 1*sizeof(void*): ptr to type_info
			// 2*sizeof(void*) ... : the exact functions.
			// So if we can parse type_info as type_info and we see functions, it should be vtable.
			//ea_t ea = getEa(ptr);
			//flags_t flags = get_flags_novalue(ea);
			//if (isData(flags))
			//{
				GCCVtableInfo * info = GCCVtableInfo::parseVtableInfo(ptr);
				if (info)
				{
					VTBL_info_t vtbl_info;
					vtbl_info.ea_begin = info->vtbl_start;
					vtbl_info.ea_end = info->ea_end;
					vtbl_info.vtbl_name = info->typeName;
					vtbl_info.methods = info->vtables[0].methodsCount;
					rtti_vftables[ptr + ea_t(2*sizeof(void*))] = vtbl_info;
					ptr = info->ea_end;
				}
				else {

					GCCTypeInfo *typeInfo = GCCTypeInfo::parseTypeInfo(ptr);
					if (typeInfo)
					{
						;
					}

				}
			//}
		}
	}

	return;
}

void GCCObjectFormatParser::clearInfo()
{
	g_KnownVtables.clear();
	g_KnownTypes.clear();
}