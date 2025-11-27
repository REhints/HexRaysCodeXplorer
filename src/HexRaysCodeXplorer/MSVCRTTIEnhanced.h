/*	Copyright (c) 2024
	REhints <info@rehints.com>
	All rights reserved.
	
	==============================================================================
	
	This file is part of HexRaysCodeXplorer

 	HexRaysCodeXplorer is free software: you can redistribute it and/or modify it
 	under the terms of the GNU General Public License as published by
 	the Free Software Foundation, either version 3 of the License, or
 	(at your option) any later version.

 	This program is distributed in the hope that it will be useful, but
 	WITHOUT ANY WARRANTY; without even the implied warranty of
 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 	General Public License for more details.

 	You should have received a copy of the GNU General Public License
 	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	==============================================================================
*/

#pragma once

#include "Common.h"
#include <vector>
#include <map>
#include <memory>
#include <string>

namespace MSVCRTTI {

// Forward declarations
struct CompleteObjectLocator;
struct TypeDescriptor;
struct ClassHierarchyDescriptor;
struct BaseClassDescriptor;
struct VTableLayout;
class RTTIParser;

// MSVC 2019+ uses RVA (Relative Virtual Address) in x64
enum class AddressingMode {
    ABSOLUTE,   // 32-bit absolute addresses
    RVA         // Relative virtual addresses (x64)
};

// Enhanced RTTI Complete Object Locator (COL) for MSVC 2019+
struct CompleteObjectLocator {
    uint32_t signature;              // Always 0 for 32-bit, 1 for 64-bit
    uint32_t offset;                 // Offset of vptr in class
    uint32_t cdOffset;               // Constructor displacement offset
    
    // These are RVAs in x64 MSVC 2019+
    union {
        ea_t pTypeDescriptor;        // 32-bit: direct pointer
        uint32_t typeDescriptorRVA;  // 64-bit: RVA
    };
    
    union {
        ea_t pClassDescriptor;       // 32-bit: direct pointer  
        uint32_t classDescriptorRVA; // 64-bit: RVA
    };
    
    // New in MSVC 2019+
    union {
        ea_t pSelf;                  // 32-bit: pointer to itself (for validation)
        uint32_t selfRVA;            // 64-bit: RVA to itself
    };
    
    // Helper methods
    ea_t get_type_descriptor(ea_t image_base) const;
    ea_t get_class_descriptor(ea_t image_base) const;
    bool validate() const;
};

// Enhanced Type Descriptor with demangling support
struct TypeDescriptor {
    ea_t pVFTable;           // Pointer to type_info vftable
    uint64_t spare;          // Reserved, must be 0
    char name[1];            // Mangled type name (variable length)
    
    std::string get_demangled_name() const;
    size_t get_size() const;
};

// Class Hierarchy Descriptor with enhanced parsing
struct ClassHierarchyDescriptor {
    uint32_t signature;      // Always 0
    uint32_t attributes;     // Bit flags
    uint32_t numBaseClasses; // Number of base classes
    
    union {
        ea_t pBaseClassArray;           // 32-bit: direct pointer
        uint32_t baseClassArrayRVA;     // 64-bit: RVA
    };
    
    // Attribute flags
    enum Attributes : uint32_t {
        CHD_MULTINH   = 0x01,  // Multiple inheritance
        CHD_VIRTINH   = 0x02,  // Virtual inheritance
        CHD_AMBIGUOUS = 0x04,  // Ambiguous base
        CHD_SEALED    = 0x08,  // Class is sealed (C++11)
        CHD_FINAL     = 0x10   // Class is final (C++11)
    };
    
    bool has_multiple_inheritance() const { return attributes & CHD_MULTINH; }
    bool has_virtual_inheritance() const { return attributes & CHD_VIRTINH; }
    bool is_sealed() const { return attributes & CHD_SEALED; }
    
    ea_t get_base_array(ea_t image_base) const;
};

// Enhanced Base Class Descriptor
struct BaseClassDescriptor {
    union {
        ea_t pTypeDescriptor;           // 32-bit: direct pointer
        uint32_t typeDescriptorRVA;     // 64-bit: RVA
    };
    
    uint32_t numContainedBases;  // Number of contained bases
    int32_t mdisp;                // Member displacement
    int32_t pdisp;                // Vftable displacement
    int32_t vdisp;                // Displacement in vbase table
    uint32_t attributes;          // Flags
    
    union {
        ea_t pClassDescriptor;           // 32-bit: direct pointer
        uint32_t classDescriptorRVA;     // 64-bit: RVA
    };
    
    // Helper methods
    ea_t get_type_descriptor(ea_t image_base) const;
    ea_t get_class_descriptor(ea_t image_base) const;
    bool is_virtual_base() const;
};

// Control Flow Guard (CFG) support
struct CFGVirtualCallTarget {
    ea_t target_address;
    uint32_t flags;
    
    enum Flags : uint32_t {
        CFG_VALID_TARGET = 0x01,
        CFG_SUPPRESS_EXPORT = 0x02,
        CFG_EXPORT_SUPPRESSED = 0x04,
        CFG_LONG_JUMP_TARGET = 0x08
    };
    
    bool is_valid_call_target() const { return flags & CFG_VALID_TARGET; }
};

// SEH (Structured Exception Handling) information
struct SEHInfo {
    ea_t handler_address;
    uint32_t try_level;
    std::vector<ea_t> catch_blocks;
    
    // C++20 coroutine support
    ea_t coroutine_frame_handler;
    bool has_coroutine_frame() const { return coroutine_frame_handler != BADADDR; }
};

// Whole Program Optimization (WPO) detection
struct WPOInfo {
    bool is_devirtualized;
    ea_t original_vtable;
    ea_t optimized_call_site;
    
    enum OptimizationType {
        WPO_NONE,
        WPO_INLINED,
        WPO_DIRECT_CALL,
        WPO_ELIMINATED
    } type;
};

// Complete VTable layout for MSVC
struct VTableLayout {
    ea_t vtable_address;
    ea_t col_address;  // Complete Object Locator
    
    std::unique_ptr<CompleteObjectLocator> col;
    std::unique_ptr<TypeDescriptor> type_desc;
    std::unique_ptr<ClassHierarchyDescriptor> class_desc;
    std::vector<std::unique_ptr<BaseClassDescriptor>> base_classes;
    
    // Virtual functions
    struct VirtualFunction {
        ea_t address;
        std::string name;
        bool is_pure_virtual;
        bool is_deleted;  // C++11
        bool has_cfg_check;
        std::shared_ptr<SEHInfo> seh_info;  // Changed to shared_ptr for copyability
    };
    std::vector<VirtualFunction> virtual_functions;
    
    // CFG information
    std::vector<CFGVirtualCallTarget> cfg_targets;
    
    // WPO detection
    std::unique_ptr<WPOInfo> wpo_info;
    
    // Methods
    size_t get_function_count() const { return virtual_functions.size(); }
    ea_t get_function_at(size_t index) const;
    std::string get_class_name() const;
};

// Enhanced MSVC RTTI Parser
class RTTIParser {
public:
    RTTIParser();
    ~RTTIParser();
    
    // Main parsing functions
    std::unique_ptr<VTableLayout> parse_vtable(ea_t vtable_addr);
    bool is_vtable(ea_t addr) const;
    
    // Component parsers
    std::unique_ptr<CompleteObjectLocator> parse_col(ea_t col_addr);
    std::unique_ptr<TypeDescriptor> parse_type_descriptor(ea_t td_addr);
    std::unique_ptr<ClassHierarchyDescriptor> parse_class_hierarchy(ea_t chd_addr);
    std::unique_ptr<BaseClassDescriptor> parse_base_class(ea_t bcd_addr);
    
    // CFG support
    bool has_cfg_checks(ea_t vtable_addr) const;
    std::vector<CFGVirtualCallTarget> get_cfg_targets(ea_t vtable_addr);
    
    // SEH support
    std::shared_ptr<SEHInfo> parse_seh_info(ea_t func_addr);
    
    // WPO detection
    std::unique_ptr<WPOInfo> detect_wpo(ea_t vtable_addr);
    
    // Utility functions
    ea_t find_col_from_vtable(ea_t vtable_addr) const;
    std::unique_ptr<CompleteObjectLocator> parse_col_internal(ea_t col_addr) const;
    AddressingMode get_addressing_mode() const;
    ea_t rva_to_va(uint32_t rva) const;
    
private:
    AddressingMode addr_mode_;
    ea_t image_base_;
    
    // Cache for parsed structures
    mutable std::map<ea_t, std::shared_ptr<VTableLayout>> vtable_cache_;
    mutable std::map<ea_t, std::shared_ptr<CompleteObjectLocator>> col_cache_;
    
    // Helper functions
    bool validate_col(const CompleteObjectLocator& col) const;
    bool validate_vtable_structure(ea_t addr) const;
    std::string demangle_msvc_name(const char* mangled) const;
    
    // Pattern matching
    bool match_vtable_pattern(ea_t addr) const;
    bool match_cfg_check_pattern(ea_t addr) const;
    bool match_seh_pattern(ea_t addr) const;
};

// MSVC C++20 Module support
struct ModuleInfo {
    std::string module_name;
    uint32_t module_signature;
    std::vector<ea_t> exported_vtables;
    std::map<std::string, ea_t> exported_types;
    
    bool has_export(const std::string& type_name) const;
};

// Module parser
class ModuleParser {
public:
    std::unique_ptr<ModuleInfo> parse_module_info(ea_t module_addr);
    std::vector<ea_t> find_all_modules();
    
private:
    bool is_module_section(ea_t addr) const;
};

// Coroutine support for C++20
struct CoroutineInfo {
    ea_t promise_vtable;
    ea_t awaiter_vtable;
    
    struct SuspendPoint {
        ea_t address;
        enum Type { INITIAL, YIELD, FINAL } type;
    };
    std::vector<SuspendPoint> suspend_points;
    
    bool is_coroutine() const { return promise_vtable != BADADDR; }
};

// Coroutine analyzer
class CoroutineAnalyzer {
public:
    std::unique_ptr<CoroutineInfo> analyze_coroutine(ea_t func_addr);
    bool is_coroutine_frame(ea_t addr) const;
    
private:
    bool match_coroutine_pattern(ea_t addr) const;
};

// Main MSVC analyzer combining all features
class MSVCAnalyzer {
public:
    MSVCAnalyzer();
    ~MSVCAnalyzer();
    
    struct ClassInfo {
        std::string class_name;
        ea_t primary_vtable;
        std::unique_ptr<VTableLayout> vtable_layout;
        std::vector<std::string> base_classes;
        std::vector<std::string> virtual_bases;
        
        // Statistics
        size_t total_virtual_functions;
        size_t pure_virtual_count;
        size_t cfg_protected_count;
        bool has_seh_handlers;
        bool is_coroutine_type;
        bool has_wpo_optimizations;
    };
    
    // Analysis functions
    std::unique_ptr<ClassInfo> analyze_class(ea_t vtable_addr);
    std::vector<std::unique_ptr<ClassInfo>> analyze_all_classes();
    
    // Export functions
    void export_to_json(const ClassInfo& info, const std::string& filename);
    void export_to_ida_types(const ClassInfo& info);
    
private:
    std::unique_ptr<RTTIParser> rtti_parser_;
    std::unique_ptr<ModuleParser> module_parser_;
    std::unique_ptr<CoroutineAnalyzer> coroutine_analyzer_;
    
    // Helper functions
    std::vector<ea_t> find_all_vtables() const;
    void analyze_inheritance(ClassInfo& info);
};

} // namespace MSVCRTTI

