/*
    Compiler-specific RTTI Parser Implementation
    Full support for GCC, Clang, and MSVC
*/

#include "CompilerRTTIParser.h"
#include "GCCObjectFormatParser.h"
#include "Utility.h"
#include <bytes.hpp>
#include <segment.hpp>

//-------------------------------------------------------------------------
// CompilerRTTIParser Implementation
//-------------------------------------------------------------------------

RTTIInfo::CompilerType CompilerRTTIParser::detect_compiler() {
    // Check compiler from IDA info
    if (compilerIs(MSVC_COMPILER_ABBR)) {
        return RTTIInfo::COMPILER_MSVC;
    } else if (compilerIs(CLANG_COMPILER_ABBR) || compilerIs(LLVM_COMPILER_ABBR)) {
        return RTTIInfo::COMPILER_CLANG;
    } else if (compilerIs(GCC_COMPILER_ABBR)) {
        return RTTIInfo::COMPILER_GCC;
    }
    
    // Try to detect from binary patterns
    // Look for compiler-specific strings
    // Note: Simplified detection without text search API
    
    // Check for MSVC patterns by looking at segment names or known addresses
    qstring seg_name;
    segment_t *seg = get_first_seg();
    while (seg != nullptr) {
        get_segm_name(&seg_name, seg);
        if (seg_name.find(".rdata") != qstring::npos || seg_name.find("RTTI") != qstring::npos) {
            // Likely MSVC
            return RTTIInfo::COMPILER_MSVC;
        }
        seg = get_next_seg(seg->start_ea);
    }
    
    // Default to GCC for non-Windows
    #ifdef __MAC__
        return RTTIInfo::COMPILER_CLANG;
    #else
        return RTTIInfo::COMPILER_GCC;
    #endif
    
    return RTTIInfo::COMPILER_UNKNOWN;
}

bool CompilerRTTIParser::parse_rtti(ea_t rtti_addr, RTTIInfo& info) {
    if (rtti_addr == BADADDR || rtti_addr == 0) {
        return false;
    }
    
    info.rtti_addr = rtti_addr;
    info.compiler = detect_compiler();
    
    switch (info.compiler) {
        case RTTIInfo::COMPILER_MSVC:
            return parse_msvc_rtti(rtti_addr, info);
            
        case RTTIInfo::COMPILER_GCC:
        case RTTIInfo::COMPILER_CLANG:
            return parse_gcc_rtti(rtti_addr, info);
            
        default:
            // Try both formats
            if (parse_gcc_rtti(rtti_addr, info)) {
                info.compiler = RTTIInfo::COMPILER_GCC;
                return true;
            }
            if (parse_msvc_rtti(rtti_addr, info)) {
                info.compiler = RTTIInfo::COMPILER_MSVC;
                return true;
            }
            return false;
    }
}

bool CompilerRTTIParser::parse_gcc_rtti(ea_t rtti_addr, RTTIInfo& info) {
    // GCC/Clang use Itanium ABI
    // RTTI is at vtable - sizeof(void*)
    
    GCC_RTTI::type_info ti;
    if (!get_bytes(&ti, sizeof(ti), rtti_addr)) {
        return false;
    }
    
    // Get type name
    info.raw_name = get_gcc_type_name(rtti_addr);
    if (info.raw_name.empty()) {
        return false;
    }
    
    // Demangle name
    info.class_name = demangle_type_name(info.raw_name, info.compiler);
    
    // Check for different RTTI types
    qstring vtable_name;
    get_name(&vtable_name, ti.__type_info_vtable);
    
    if (vtable_name.find("__si_class_type_info") != qstring::npos) {
        // Single inheritance
        parse_gcc_si_class_type_info(rtti_addr, info);
    } else if (vtable_name.find("__vmi_class_type_info") != qstring::npos) {
        // Virtual/multiple inheritance
        parse_gcc_vmi_class_type_info(rtti_addr, info);
    } else if (vtable_name.find("__class_type_info") != qstring::npos) {
        // No inheritance
        parse_gcc_class_type_info(rtti_addr, info);
    }
    
    return true;
}

bool CompilerRTTIParser::parse_gcc_class_type_info(ea_t addr, RTTIInfo& info) {
    // Basic class with no inheritance
    info.num_base_classes = 0;
    info.has_virtual_base = false;
    return true;
}

bool CompilerRTTIParser::parse_gcc_si_class_type_info(ea_t addr, RTTIInfo& info) {
    // Single inheritance
    struct si_class_type_info {
        GCC_RTTI::type_info base;
        ea_t base_type;
    };
    
    si_class_type_info si;
    if (!get_bytes(&si, sizeof(si), addr)) {
        return false;
    }
    
    RTTIInfo::BaseClass base;
    base.type_info_addr = si.base_type;
    base.name = get_gcc_type_name(si.base_type);
    base.offset = 0;
    base.is_virtual = false;
    base.is_public = true;
    
    info.base_classes.push_back(base);
    info.num_base_classes = 1;
    
    return true;
}

bool CompilerRTTIParser::parse_gcc_vmi_class_type_info(ea_t addr, RTTIInfo& info) {
    // Virtual/multiple inheritance
    struct vmi_class_type_info {
        GCC_RTTI::type_info base;
        unsigned int flags;
        unsigned int base_count;
        // Followed by base_info array
    };
    
    struct base_info {
        ea_t base_type;
        long offset_flags;
    };
    
    vmi_class_type_info vmi;
    if (!get_bytes(&vmi, sizeof(vmi), addr)) {
        return false;
    }
    
    info.num_base_classes = vmi.base_count;
    info.has_diamond_inheritance = (vmi.flags & 0x01) != 0;
    
    // Parse base classes
    ea_t base_array = addr + sizeof(vmi);
    for (unsigned int i = 0; i < vmi.base_count; i++) {
        base_info bi;
        if (!get_bytes(&bi, sizeof(bi), base_array + i * sizeof(bi))) {
            continue;
        }
        
        RTTIInfo::BaseClass base;
        base.type_info_addr = bi.base_type;
        base.name = get_gcc_type_name(bi.base_type);
        base.offset = (bi.offset_flags >> 8);
        base.is_virtual = (bi.offset_flags & 0x01) != 0;
        base.is_public = (bi.offset_flags & 0x02) != 0;
        
        info.base_classes.push_back(base);
        
        if (base.is_virtual) {
            info.has_virtual_base = true;
        }
    }
    
    return true;
}

qstring CompilerRTTIParser::get_gcc_type_name(ea_t type_info_addr) {
    if (type_info_addr == BADADDR) {
        return "";
    }
    
    GCC_RTTI::type_info ti;
    if (!get_bytes(&ti, sizeof(ti), type_info_addr)) {
        return "";
    }
    
    // Read null-terminated string
    qstring name;
    if (!get_strlit_contents(&name, ti.__type_info_name, -1, STRTYPE_C)) {
        return "";
    }
    
    return name;
}

bool CompilerRTTIParser::parse_msvc_rtti(ea_t rtti_addr, RTTIInfo& info) {
    // MSVC stores Complete Object Locator before vtable
    MSVC_RTTI::CompleteObjectLocator col;
    if (!get_bytes(&col, sizeof(col), rtti_addr)) {
        return false;
    }
    
    // Verify signature (should be 0 for 32-bit, 1 for 64-bit)
    if (col.signature != 0 && col.signature != 1) {
        return false;
    }
    
    info.msvc_signature = col.signature;
    
    // Parse type descriptor
    info.raw_name = get_msvc_type_name(col.pTypeDescriptor);
    info.class_name = demangle_type_name(info.raw_name, info.compiler);
    
    // Parse class hierarchy
    if (col.pClassDescriptor != BADADDR) {
        parse_msvc_class_hierarchy(col.pClassDescriptor, info);
    }
    
    return true;
}

bool CompilerRTTIParser::parse_msvc_class_hierarchy(ea_t hierarchy_addr, RTTIInfo& info) {
    MSVC_RTTI::ClassHierarchyDescriptor chd;
    if (!get_bytes(&chd, sizeof(chd), hierarchy_addr)) {
        return false;
    }
    
    info.msvc_attributes = chd.attributes;
    info.num_base_classes = chd.numBaseClasses;
    info.has_virtual_base = (chd.attributes & 0x01) != 0;
    
    // Parse base class array
    if (chd.pBaseClassArray != BADADDR) {
        parse_msvc_base_class_array(chd.pBaseClassArray, chd.numBaseClasses, info);
    }
    
    return true;
}

bool CompilerRTTIParser::parse_msvc_base_class_array(ea_t array_addr, DWORD count, RTTIInfo& info) {
    for (DWORD i = 0; i < count; i++) {
        ea_t bcd_addr;
        bcd_addr = get_dword(array_addr + i * sizeof(ea_t));
        if (bcd_addr == 0 || bcd_addr == BADADDR) {
            continue;
        }
        
        MSVC_RTTI::BaseClassDescriptor bcd;
        if (!get_bytes(&bcd, sizeof(bcd), bcd_addr)) {
            continue;
        }
        
        RTTIInfo::BaseClass base;
        base.type_info_addr = bcd.pTypeDescriptor;
        base.name = get_msvc_type_name(bcd.pTypeDescriptor);
        base.offset = bcd.where.mdisp;
        base.is_virtual = (bcd.attributes & 0x04) != 0;
        base.is_public = true;  // MSVC doesn't store this info
        
        // Skip the first entry (it's the class itself)
        if (i > 0) {
            info.base_classes.push_back(base);
        }
    }
    
    return true;
}

qstring CompilerRTTIParser::get_msvc_type_name(ea_t type_desc_addr) {
    if (type_desc_addr == BADADDR) {
        return "";
    }
    
    // Skip vtable pointer and spare
    ea_t name_addr = type_desc_addr + 2 * sizeof(ea_t);
    
    // Read decorated name
    qstring name;
    if (!get_strlit_contents(&name, name_addr, -1, STRTYPE_C)) {
        return "";
    }
    
    return name;
}

qstring CompilerRTTIParser::demangle_type_name(const qstring& mangled_name, RTTIInfo::CompilerType compiler) {
    qstring demangled;
    
    if (compiler == RTTIInfo::COMPILER_MSVC) {
        // MSVC mangling
        if (demangle_name(&demangled, mangled_name.c_str(), MNG_SHORT_FORM) > 0) {
            return demangled;
        }
    } else {
        // GCC/Clang use Itanium ABI mangling
        if (demangle_name(&demangled, mangled_name.c_str(), 0) > 0) {
            return demangled;
        }
    }
    
    // Try generic demangling
    if (demangle_name(&demangled, mangled_name.c_str(), MNG_SHORT_FORM) > 0) {
        return demangled;
    }
    
    return mangled_name;
}

qstring CompilerRTTIParser::extract_class_name(const qstring& type_string) {
    qstring class_name = type_string;
    
    // Remove "class " or "struct " prefix
    if (class_name.find("class ") == 0) {
        class_name.remove(0, 6);
    } else if (class_name.find("struct ") == 0) {
        class_name.remove(0, 7);
    }
    
    // Remove "vtable for'" prefix
    if (class_name.find("vtable for'") == 0) {
        class_name.remove(0, 11);
    }
    
    // Remove template parameters for display
    size_t pos = class_name.find('<');
    if (pos != qstring::npos) {
        class_name.remove(pos, class_name.size() - pos);
    }
    
    // Remove namespace for display (keep last component)
    const char* scope_sep = "::";
    pos = class_name.find(scope_sep);
    if (pos != qstring::npos) {
        // Find last occurrence
        size_t last_pos = pos;
        while ((pos = class_name.find(scope_sep, last_pos + 2)) != qstring::npos) {
            last_pos = pos;
        }
        if (last_pos + 2 < class_name.size()) {
            qstring result;
            result = class_name.c_str() + last_pos + 2;
            return result;
        }
    }
    
    return class_name;
}

bool CompilerRTTIParser::parse_vtable_rtti(const VTBL_info_t& vtbl, RTTIInfo& info) {
    ea_t rtti_addr = get_rtti_address(vtbl.ea_begin);
    if (rtti_addr == BADADDR) {
        return false;
    }
    
    return parse_rtti(rtti_addr, info);
}

ea_t CompilerRTTIParser::get_rtti_address(ea_t vtable_addr) {
    RTTIInfo::CompilerType compiler = detect_compiler();
    
    size_t ptr_size = inf_is_64bit() ? 8 : 4;
    
    if (compiler == RTTIInfo::COMPILER_MSVC) {
        // MSVC: COL is at vtable - sizeof(void*)
        return vtable_addr - ptr_size;
    } else {
        // GCC/Clang: RTTI is at vtable - sizeof(void*)
        ea_t rtti_ptr_addr = vtable_addr - ptr_size;
        ea_t rtti_addr;
        if (inf_is_64bit()) {
            rtti_addr = get_qword(rtti_ptr_addr);
        } else {
            rtti_addr = get_dword(rtti_ptr_addr);
        }
        if (rtti_addr != BADADDR) {
            return rtti_addr;
        }
    }
    
    return BADADDR;
}

bool CompilerRTTIParser::is_valid_rtti(ea_t addr) {
    if (addr == BADADDR || addr == 0) {
        return false;
    }
    
    RTTIInfo info;
    return parse_rtti(addr, info);
}

qstring CompilerRTTIParser::format_rtti_info(const RTTIInfo& info) {
    qstring result;
    
    result.sprnt("Class: %s\n", info.class_name.c_str());
    result.cat_sprnt("Compiler: %s\n", 
                     info.compiler == RTTIInfo::COMPILER_MSVC ? "MSVC" :
                     info.compiler == RTTIInfo::COMPILER_GCC ? "GCC" :
                     info.compiler == RTTIInfo::COMPILER_CLANG ? "Clang" : "Unknown");
    
    if (!info.base_classes.empty()) {
        result.cat_sprnt("Inheritance (%d base%s):\n", 
                        info.num_base_classes,
                        info.num_base_classes > 1 ? "s" : "");
        
        for (const auto& base : info.base_classes) {
            result.cat_sprnt("  %s%s %s", 
                           base.is_public ? "public" : "private",
                           base.is_virtual ? " virtual" : "",
                           base.name.c_str());
            if (base.offset != 0) {
                result.cat_sprnt(" (offset: %d)", base.offset);
            }
            result.append("\n");
        }
    }
    
    if (info.has_virtual_base) {
        result.append("Has virtual base classes\n");
    }
    
    if (info.is_abstract) {
        result.append("Abstract class (has pure virtuals)\n");
    }
    
    return result;
}

qstring CompilerRTTIParser::get_inheritance_tree(const RTTIInfo& info) {
    qstring tree;
    
    tree.sprnt("%s\n", info.class_name.c_str());
    
    for (size_t i = 0; i < info.base_classes.size(); i++) {
        const auto& base = info.base_classes[i];
        bool is_last = (i == info.base_classes.size() - 1);
        
        tree.cat_sprnt("%s %s%s %s\n",
                      is_last ? "└──" : "├──",
                      base.is_public ? "public" : "private",
                      base.is_virtual ? " virtual" : "",
                      base.name.c_str());
    }
    
    return tree;
}

//-------------------------------------------------------------------------
// VTableRTTIAnalyzer Implementation
//-------------------------------------------------------------------------

void VTableRTTIAnalyzer::analyze_all_vtables() {
    extern qvector<VTBL_info_t> vtbl_t_list;
    
    msg("[RTTI] Analyzing RTTI for %d vtables\n", vtbl_t_list.size());
    
    for (const auto& vtbl : vtbl_t_list) {
        RTTIInfo info;
        if (CompilerRTTIParser::parse_vtable_rtti(vtbl, info)) {
            rtti_cache[vtbl.ea_begin] = info;
            msg("[RTTI] Found RTTI for %s (%s)\n", 
                vtbl.vtbl_name.c_str(), info.class_name.c_str());
        }
    }
    
    msg("[RTTI] Analysis complete: %d vtables with RTTI\n", rtti_cache.size());
}

const RTTIInfo* VTableRTTIAnalyzer::get_vtable_rtti(ea_t vtable_addr) {
    auto it = rtti_cache.find(vtable_addr);
    if (it != rtti_cache.end()) {
        return &it->second;
    }
    
    // Try to parse on demand
    RTTIInfo info;
    if (CompilerRTTIParser::parse_rtti(CompilerRTTIParser::get_rtti_address(vtable_addr), info)) {
        rtti_cache[vtable_addr] = info;
        return &rtti_cache[vtable_addr];
    }
    
    return nullptr;
}

//-------------------------------------------------------------------------
// RTTITreeHelper Implementation
//-------------------------------------------------------------------------

qstring RTTITreeHelper::get_node_name(const VTBL_info_t& vtbl, const RTTIInfo* rtti) {
    qstring name;
    
    if (rtti && !rtti->class_name.empty()) {
        // Use RTTI class name
        name = rtti->class_name;
        
        // Add compiler indicator
        switch (rtti->compiler) {
            case RTTIInfo::COMPILER_MSVC:
                name.append(" [MSVC]");
                break;
            case RTTIInfo::COMPILER_GCC:
                name.append(" [GCC]");
                break;
            case RTTIInfo::COMPILER_CLANG:
                name.append(" [Clang]");
                break;
            default:
                break;
        }
        
        // Add inheritance indicator
        if (rtti->num_base_classes > 0) {
            name.cat_sprnt(" (%d base%s)", 
                          rtti->num_base_classes,
                          rtti->num_base_classes > 1 ? "s" : "");
        }
    } else {
        // Fallback to vtable name
        name = vtbl.vtbl_name;
        if (name.find("vtable for") == 0) {
            name.remove(0, 11);
        }
    }
    
    return name;
}

int RTTITreeHelper::get_node_icon(const RTTIInfo* rtti) {
    if (!rtti) {
        return 59;  // Default class icon
    }
    
    if (rtti->is_abstract) {
        return 156;  // Abstract class icon
    }
    
    if (rtti->has_virtual_base) {
        return 60;  // Diamond inheritance icon
    }
    
    if (rtti->num_base_classes > 1) {
        return 61;  // Multiple inheritance icon
    }
    
    if (rtti->num_base_classes == 1) {
        return 62;  // Single inheritance icon
    }
    
    return 59;  // No inheritance
}

uint32 RTTITreeHelper::get_node_color(const RTTIInfo* rtti) {
    if (!rtti) {
        return 0x808080;  // Gray for no RTTI
    }
    
    switch (rtti->compiler) {
        case RTTIInfo::COMPILER_MSVC:
            return 0x0080FF;  // Orange for MSVC
            
        case RTTIInfo::COMPILER_GCC:
            return 0x00FF00;  // Green for GCC
            
        case RTTIInfo::COMPILER_CLANG:
            return 0x00FFFF;  // Yellow for Clang
            
        default:
            return 0x808080;  // Gray for unknown
    }
}

bool RTTITreeHelper::is_pure_virtual(ea_t method_addr) {
    qstring name;
    get_short_name(&name, method_addr);
    
    // Check for common pure virtual patterns
    if (name.find("purecall") != qstring::npos ||
        name.find("pure_virtual") != qstring::npos ||
        name.find("__cxa_pure_virtual") != qstring::npos ||
        name == "_purecall") {
        return true;
    }
    
    return false;
}

bool RTTITreeHelper::is_inherited_method(const VTBL_info_t& vtbl, size_t method_index, qstring& base_class) {
    // This would require more complex analysis
    // For now, return false
    return false;
}