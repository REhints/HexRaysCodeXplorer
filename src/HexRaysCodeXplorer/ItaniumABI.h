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

namespace ItaniumABI {

// Forward declarations
struct VTableLayout;
struct VTableEntry;
struct ThunkInfo;
class VTableParser;

// Entry types in Itanium ABI vtables
enum class VTableEntryType {
    VCALL_OFFSET,           // Virtual call offset (for virtual bases)
    VBASE_OFFSET,           // Virtual base offset
    OFFSET_TO_TOP,          // Offset from vptr to top of object
    TYPEINFO_PTR,           // Pointer to RTTI typeinfo
    VIRTUAL_FUNCTION,       // Virtual function pointer
    PURE_VIRTUAL,           // Pure virtual function (__cxa_pure_virtual)
    DELETED_VIRTUAL,        // Deleted virtual function (C++11)
    THUNK,                  // Thunk to virtual function
    GUARD_VARIABLE          // Guard variable for initialization
};

// Complete vtable entry with all information
struct VTableEntry {
    VTableEntryType type;
    ea_t address;           // Address of this entry in the vtable
    
    union {
        ptrdiff_t offset;   // For offset entries
        ea_t ptr;           // For pointer entries
    } value;
    
    // Additional info for specific entry types
    std::shared_ptr<ThunkInfo> thunk_info;  // For thunk entries (shared_ptr for copyability)
    std::string demangled_name;             // For function entries
    
    VTableEntry() : type(VTableEntryType::VIRTUAL_FUNCTION), address(BADADDR) {
        value.ptr = BADADDR;
    }
    
    // Copy constructor
    VTableEntry(const VTableEntry& other) 
        : type(other.type), 
          address(other.address), 
          value(other.value),
          thunk_info(other.thunk_info),
          demangled_name(other.demangled_name) {}
    
    // Assignment operator
    VTableEntry& operator=(const VTableEntry& other) {
        if (this != &other) {
            type = other.type;
            address = other.address;
            value = other.value;
            thunk_info = other.thunk_info;
            demangled_name = other.demangled_name;
        }
        return *this;
    }
};

// Thunk information
struct ThunkInfo {
    enum ThunkType {
        THUNK_THIS_ADJUSTING,      // Adjusts 'this' pointer
        THUNK_COVARIANT_RETURN,    // Adjusts return value
        THUNK_VIRTUAL_BASE         // Virtual base adjustment
    };
    
    ThunkType type;
    ptrdiff_t this_adjustment;     // Fixed adjustment to 'this'
    ptrdiff_t vcall_offset;        // Virtual call offset (0 if none)
    ptrdiff_t return_adjustment;   // Covariant return adjustment
    ea_t target_function;          // Target function address
    
    ThunkInfo() : type(THUNK_THIS_ADJUSTING), 
                  this_adjustment(0), 
                  vcall_offset(0),
                  return_adjustment(0), 
                  target_function(BADADDR) {}
};

// Construction/Destruction VTable info
struct ConstructionVTable {
    enum CDtorType {
        COMPLETE_OBJECT_CTOR,    // C1 - complete object constructor
        BASE_OBJECT_CTOR,        // C2 - base object constructor
        COMPLETE_OBJECT_DTOR,    // D1 - complete object destructor  
        BASE_OBJECT_DTOR,        // D2 - base object destructor
        DELETING_DTOR            // D0 - deleting destructor
    };
    
    CDtorType type;
    ea_t vtt_address;           // Virtual Table Table address
    std::vector<ea_t> sub_vtables;  // Construction vtables
    bool is_virtual_base;
};

// Complete VTable layout following Itanium ABI
struct VTableLayout {
    // Header information
    struct VTableHeader {
        ptrdiff_t offset_to_top;    // Offset to top of complete object
        ea_t typeinfo_ptr;           // Pointer to typeinfo
        size_t vcall_offset_count;   // Number of vcall offsets
        std::vector<ptrdiff_t> vcall_offsets;  // Virtual call offsets
    } header;
    
    // Virtual function entries
    std::vector<VTableEntry> entries;
    
    // Additional vtables (for multiple inheritance)
    std::map<ptrdiff_t, std::shared_ptr<VTableLayout>> secondary_vtables;
    
    // Virtual base information
    struct VirtualBaseInfo {
        ea_t vbase_offset_ptr;      // Pointer to vbase offset
        ptrdiff_t vbase_offset;      // Actual offset
        std::string base_class_name;
    };
    std::vector<VirtualBaseInfo> virtual_bases;
    
    // Construction/destruction vtables
    std::vector<ConstructionVTable> construction_vtables;
    
    // Methods
    ea_t get_function_at(size_t index) const;
    bool has_virtual_bases() const { return !virtual_bases.empty(); }
    size_t get_function_count() const;
};

// Enhanced Itanium ABI VTable Parser
class VTableParser {
public:
    VTableParser() = default;
    ~VTableParser() = default;
    
    // Main parsing function
    std::unique_ptr<VTableLayout> parse_vtable(ea_t vtable_addr);
    
    // Check if address is a vtable
    bool is_vtable(ea_t addr) const;
    
    // Parse specific components
    bool parse_header(ea_t addr, VTableLayout::VTableHeader& header);
    bool parse_entries(ea_t start_addr, std::vector<VTableEntry>& entries);
    bool parse_construction_vtables(ea_t vtt_addr, std::vector<ConstructionVTable>& cvtables);
    
    // Thunk detection and parsing
    bool is_thunk(ea_t addr) const;
    std::shared_ptr<ThunkInfo> parse_thunk(ea_t thunk_addr);
    
    // RTTI parsing
    ea_t get_typeinfo_ptr(ea_t vtable_addr) const;
    std::string get_class_name_from_typeinfo(ea_t typeinfo_addr) const;
    
    // Utility functions
    static bool is_valid_function_ptr(ea_t addr);
    static bool is_pure_virtual(ea_t addr);
    static bool is_deleted_virtual(ea_t addr);
    
    // Demangling (made public for VTTParser)
    std::string demangle_symbol(const char* mangled) const;
    
private:
    // Helper functions
    ea_t read_pointer(ea_t addr) const;
    ptrdiff_t read_offset(ea_t addr) const;
    bool validate_vtable_structure(ea_t addr) const;
    
    // Pattern matching for thunks
    bool match_thunk_pattern(ea_t addr, ThunkInfo& info) const;
    
    // Cache for parsed vtables (avoid re-parsing)
    mutable std::map<ea_t, std::shared_ptr<VTableLayout>> cache_;
};

// Guard variable parser for static initialization
class GuardVariableParser {
public:
    struct GuardInfo {
        ea_t guard_address;
        bool is_initialized;
        uint8_t init_byte;
        ea_t object_address;
    };
    
    bool is_guard_variable(ea_t addr) const;
    std::unique_ptr<GuardInfo> parse_guard(ea_t guard_addr);
    
private:
    bool match_guard_pattern(ea_t addr) const;
};

// VTT (Virtual Table Table) parser
class VTTParser {
public:
    struct VTTLayout {
        ea_t vtt_address;
        std::vector<ea_t> vtable_pointers;
        std::map<size_t, std::string> descriptions;  // Index to description
        
        // Categorized vtables
        struct VTableGroup {
            ea_t primary_vtable;
            std::vector<ea_t> secondary_vtables;
            std::vector<ea_t> virtual_base_vtables;
        } groups;
    };
    
    std::unique_ptr<VTTLayout> parse_vtt(ea_t vtt_addr);
    bool is_vtt(ea_t addr) const;
    
private:
    size_t estimate_vtt_size(ea_t vtt_addr) const;
};

// Covariant return type handler
class CovariantReturnHandler {
public:
    struct CovariantInfo {
        ea_t original_function;
        ea_t overriding_function;
        tinfo_t original_return_type;
        tinfo_t covariant_return_type;
        ptrdiff_t return_adjustment;
    };
    
    bool has_covariant_return(ea_t func_addr) const;
    std::unique_ptr<CovariantInfo> analyze_covariant_return(ea_t override_addr);
    
private:
    bool types_are_covariant(const tinfo_t& base_type, const tinfo_t& derived_type) const;
};

// Main analyzer class that combines all components
class ItaniumABIAnalyzer {
public:
    ItaniumABIAnalyzer();
    ~ItaniumABIAnalyzer();
    
    // Complete analysis of a class
    struct ClassInfo {
        std::string class_name;
        ea_t primary_vtable;
        std::unique_ptr<VTableLayout> vtable_layout;
        std::unique_ptr<VTTParser::VTTLayout> vtt_layout;
        std::vector<std::string> base_classes;
        std::vector<std::string> virtual_bases;
        std::map<std::string, CovariantReturnHandler::CovariantInfo> covariant_returns;
        
        // Statistics
        size_t total_virtual_functions;
        size_t pure_virtual_count;
        size_t deleted_virtual_count;
        size_t thunk_count;
    };
    
    std::unique_ptr<ClassInfo> analyze_class(ea_t vtable_addr);
    
    // Batch analysis
    std::vector<std::unique_ptr<ClassInfo>> analyze_all_vtables();
    
    // Export results
    void export_to_json(const ClassInfo& info, const std::string& filename);
    void export_to_idapy(const ClassInfo& info);
    
private:
    std::unique_ptr<VTableParser> vtable_parser_;
    std::unique_ptr<VTTParser> vtt_parser_;
    std::unique_ptr<GuardVariableParser> guard_parser_;
    std::unique_ptr<CovariantReturnHandler> covariant_handler_;
    
    // Helper for finding all vtables in binary
    std::vector<ea_t> find_all_vtables() const;
};

} // namespace ItaniumABI