/*
    Compiler-specific RTTI Parser
    Supports GCC, Clang, and MSVC RTTI structures
*/

#ifndef COMPILER_RTTI_PARSER_H
#define COMPILER_RTTI_PARSER_H

#include "Common.h"
#include "ObjectExplorer.h"
#include <name.hpp>
#include <demangle.hpp>

// Forward declarations
namespace GCC_RTTI {
    struct type_info;
    struct __class_type_info;
    struct __si_class_type_info;
    struct __vmi_class_type_info;
}

// MSVC RTTI structures
namespace MSVC_RTTI {
#pragma pack(push, 1)
    
    struct TypeDescriptor {
        ea_t pVFTable;          // Reference to type_info vftable
        ea_t spare;             // Internal runtime reference
        char name[1];           // Mangled type name (variable length)
    };
    
    struct PMD {
        int mdisp;              // Member displacement
        int pdisp;              // Vbtable displacement
        int vdisp;              // Displacement inside vbtable
    };
    
    struct BaseClassDescriptor {
        ea_t pTypeDescriptor;   // Type descriptor of the base class
        DWORD numContainedBases;
        PMD where;              // Placement of base class
        DWORD attributes;
    };
    
    struct ClassHierarchyDescriptor {
        DWORD signature;        // Should be 0
        DWORD attributes;       // Bit flags
        DWORD numBaseClasses;   // Number of base classes
        ea_t pBaseClassArray;   // Pointer to base class array
    };
    
    struct CompleteObjectLocator {
        DWORD signature;
        DWORD offset;           // Offset of this vtable in complete class
        DWORD cdOffset;         // Constructor displacement
        ea_t pTypeDescriptor;
        ea_t pClassDescriptor;
    };
    
#pragma pack(pop)
}

// Unified RTTI information
struct RTTIInfo {
    enum CompilerType {
        COMPILER_UNKNOWN,
        COMPILER_GCC,
        COMPILER_CLANG,
        COMPILER_MSVC
    };
    
    CompilerType compiler;
    ea_t rtti_addr;
    qstring raw_name;           // Mangled name
    qstring class_name;         // Demangled class name
    qstring type_string;        // Full type info string
    
    // Inheritance info
    struct BaseClass {
        qstring name;
        ea_t type_info_addr;
        int offset;
        bool is_virtual;
        bool is_public;
    };
    qvector<BaseClass> base_classes;
    
    // Flags
    bool has_virtual_base;
    bool is_polymorphic;
    bool is_abstract;
    int num_base_classes;
    
    // MSVC specific
    DWORD msvc_signature;
    DWORD msvc_attributes;
    
    // GCC/Clang specific
    bool has_diamond_inheritance;
};

// Main RTTI parser class
class CompilerRTTIParser {
private:
    // Detect compiler from binary
    static RTTIInfo::CompilerType detect_compiler();
    
    // GCC/Clang RTTI parsing
    static bool parse_gcc_rtti(ea_t rtti_addr, RTTIInfo& info);
    static bool parse_gcc_class_type_info(ea_t addr, RTTIInfo& info);
    static bool parse_gcc_si_class_type_info(ea_t addr, RTTIInfo& info);
    static bool parse_gcc_vmi_class_type_info(ea_t addr, RTTIInfo& info);
    static qstring get_gcc_type_name(ea_t type_info_addr);
    
    // MSVC RTTI parsing
    static bool parse_msvc_rtti(ea_t rtti_addr, RTTIInfo& info);
    static bool parse_msvc_complete_object_locator(ea_t addr, RTTIInfo& info);
    static bool parse_msvc_class_hierarchy(ea_t hierarchy_addr, RTTIInfo& info);
    static bool parse_msvc_base_class_array(ea_t array_addr, DWORD count, RTTIInfo& info);
    static qstring get_msvc_type_name(ea_t type_desc_addr);
    
    // Common utilities
    static qstring demangle_type_name(const qstring& mangled_name, RTTIInfo::CompilerType compiler);
    static qstring extract_class_name(const qstring& type_string);
    
public:
    // Main parsing function
    static bool parse_rtti(ea_t rtti_addr, RTTIInfo& info);
    
    // Parse RTTI from vtable
    static bool parse_vtable_rtti(const VTBL_info_t& vtbl, RTTIInfo& info);
    
    // Get RTTI address from vtable
    static ea_t get_rtti_address(ea_t vtable_addr);
    
    // Check if address points to valid RTTI
    static bool is_valid_rtti(ea_t addr);
    
    // Format RTTI for display
    static qstring format_rtti_info(const RTTIInfo& info);
    
    // Get inheritance tree string
    static qstring get_inheritance_tree(const RTTIInfo& info);
};

// VTable analyzer with RTTI support
class VTableRTTIAnalyzer {
private:
    std::map<ea_t, RTTIInfo> rtti_cache;
    
public:
    // Analyze all vtables and extract RTTI
    void analyze_all_vtables();
    
    // Get RTTI for specific vtable
    const RTTIInfo* get_vtable_rtti(ea_t vtable_addr);
    
    // Find derived classes
    qvector<ea_t> find_derived_classes(const qstring& base_class);
    
    // Find base classes
    qvector<qstring> find_base_classes(ea_t vtable_addr);
    
    // Check if class is derived from base
    bool is_derived_from(ea_t derived_vtbl, const qstring& base_class);
    
    // Build complete inheritance hierarchy
    void build_inheritance_hierarchy();
    
    // Get statistics
    struct Stats {
        size_t total_vtables;
        size_t with_rtti;
        size_t gcc_rtti;
        size_t msvc_rtti;
        size_t clang_rtti;
        size_t with_inheritance;
        size_t abstract_classes;
    };
    Stats get_statistics() const;
};

// Helper functions for tree display
class RTTITreeHelper {
public:
    // Create tree node name with RTTI info
    static qstring get_node_name(const VTBL_info_t& vtbl, const RTTIInfo* rtti);
    
    // Get icon based on RTTI info
    static int get_node_icon(const RTTIInfo* rtti);
    
    // Get color based on compiler
    static uint32 get_node_color(const RTTIInfo* rtti);
    
    // Format method with RTTI context
    static qstring format_method(ea_t method_addr, const RTTIInfo* rtti, size_t index);
    
    // Check if method is pure virtual
    static bool is_pure_virtual(ea_t method_addr);
    
    // Check if method is inherited
    static bool is_inherited_method(const VTBL_info_t& vtbl, size_t method_index, qstring& base_class);
};

#endif // COMPILER_RTTI_PARSER_H