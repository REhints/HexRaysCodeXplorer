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

#include "ItaniumABI.h"
#include <name.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <funcs.hpp>
#include <algorithm>

namespace ItaniumABI {

// Constants for Itanium ABI
static const char* PURE_VIRTUAL_NAME = "__cxa_pure_virtual";
static const char* DELETED_VIRTUAL_NAME = "__cxa_deleted_virtual";
static const char* VTABLE_PREFIX = "_ZTV";
static const char* VTT_PREFIX = "_ZTT";
static const char* TYPEINFO_PREFIX = "_ZTI";
static const char* GUARD_PREFIX = "_ZGVZ";

// Helper function to read pointer-sized value
static ea_t read_ea(ea_t addr) {
    return inf_is_64bit() ? get_qword(addr) : get_dword(addr);
}

// Helper function to read signed offset
static sval_t read_sval(ea_t addr) {
    if (inf_is_64bit())
        return get_qword(addr);
    else
        return (sval_t)(int32)get_dword(addr);
}

// ===========================================================================
// VTableLayout Implementation
// ===========================================================================

ea_t VTableLayout::get_function_at(size_t index) const {
    for (const auto& entry : entries) {
        if (entry.type == VTableEntryType::VIRTUAL_FUNCTION && index-- == 0) {
            return entry.value.ptr;
        }
    }
    return BADADDR;
}

size_t VTableLayout::get_function_count() const {
    return std::count_if(entries.begin(), entries.end(),
        [](const VTableEntry& e) { 
            return e.type == VTableEntryType::VIRTUAL_FUNCTION ||
                   e.type == VTableEntryType::THUNK;
        });
}

// ===========================================================================
// VTableParser Implementation
// ===========================================================================

bool VTableParser::is_vtable(ea_t addr) const {
    if (addr == BADADDR || !is_mapped(addr))
        return false;
    
    // Check for vtable symbol name pattern
    qstring name;
    if (get_name(&name, addr) > 0) {
        if (strncmp(name.c_str(), VTABLE_PREFIX, strlen(VTABLE_PREFIX)) == 0)
            return true;
    }
    
    // Heuristic check: look for typeinfo pointer pattern
    // Itanium ABI: offset_to_top, typeinfo_ptr, then functions
    ea_t offset_addr = addr - EA_SIZE;  // offset_to_top is before vtable
    ea_t typeinfo_addr = addr;
    
    if (is_mapped(offset_addr) && is_mapped(typeinfo_addr)) {
        ea_t typeinfo_ptr = read_ea(typeinfo_addr);
        if (typeinfo_ptr != 0 && typeinfo_ptr != BADADDR) {
            // Check if it points to a typeinfo structure
            qstring ti_name;
            if (get_name(&ti_name, typeinfo_ptr) > 0) {
                if (strncmp(ti_name.c_str(), TYPEINFO_PREFIX, strlen(TYPEINFO_PREFIX)) == 0)
                    return true;
            }
        }
    }
    
    return validate_vtable_structure(addr);
}

std::unique_ptr<VTableLayout> VTableParser::parse_vtable(ea_t vtable_addr) {
    // Check cache first
    auto cached = cache_.find(vtable_addr);
    if (cached != cache_.end()) {
        return std::make_unique<VTableLayout>(*cached->second);
    }
    
    auto layout = std::make_unique<VTableLayout>();
    
    // Parse header (offset_to_top and typeinfo)
    if (!parse_header(vtable_addr, layout->header)) {
        return nullptr;
    }
    
    // Parse virtual function entries
    ea_t entry_addr = vtable_addr + EA_SIZE;  // Skip typeinfo pointer
    if (!parse_entries(entry_addr, layout->entries)) {
        return nullptr;
    }
    
    // Look for secondary vtables (multiple inheritance)
    for (const auto& entry : layout->entries) {
        if (entry.type == VTableEntryType::OFFSET_TO_TOP && entry.value.offset != 0) {
            ea_t secondary_addr = entry.address + EA_SIZE;  // Next entry after offset_to_top
            auto secondary = parse_vtable(secondary_addr);
            if (secondary) {
                layout->secondary_vtables[entry.value.offset] = std::move(secondary);
            }
        }
    }
    
    // Parse construction vtables if VTT exists
    qstring vtt_name;
    std::string class_name_str = get_class_name_from_typeinfo(layout->header.typeinfo_ptr);
    qstring class_name(class_name_str.c_str());
    if (!class_name.empty()) {
        // Try to find VTT (Virtual Table Table)
        vtt_name.sprnt("%s%s", VTT_PREFIX, class_name.c_str() + strlen(VTABLE_PREFIX));
        ea_t vtt_addr = get_name_ea(BADADDR, vtt_name.c_str());
        if (vtt_addr != BADADDR) {
            parse_construction_vtables(vtt_addr, layout->construction_vtables);
        }
    }
    
    // Cache the result
    cache_[vtable_addr] = std::make_shared<VTableLayout>(*layout);
    
    return layout;
}

bool VTableParser::parse_header(ea_t addr, VTableLayout::VTableHeader& header) {
    // Offset to top is at addr - EA_SIZE
    ea_t offset_addr = addr - EA_SIZE;
    if (!is_mapped(offset_addr))
        return false;
    
    header.offset_to_top = read_sval(offset_addr);
    
    // Typeinfo pointer is at addr
    header.typeinfo_ptr = read_ea(addr);
    if (header.typeinfo_ptr == 0 || header.typeinfo_ptr == BADADDR)
        return false;
    
    // Check for vcall offsets (for virtual inheritance)
    // These appear before offset_to_top if present
    ea_t vcall_addr = offset_addr - EA_SIZE;
    while (is_mapped(vcall_addr)) {
        sval_t vcall = read_sval(vcall_addr);
        // Vcall offsets are typically negative and small
        if (vcall >= 0 || vcall < -0x10000)
            break;
        header.vcall_offsets.push_back(vcall);
        vcall_addr -= EA_SIZE;
    }
    
    header.vcall_offset_count = header.vcall_offsets.size();
    std::reverse(header.vcall_offsets.begin(), header.vcall_offsets.end());
    
    return true;
}

bool VTableParser::parse_entries(ea_t start_addr, std::vector<VTableEntry>& entries) {
    ea_t addr = start_addr;
    
    while (is_mapped(addr)) {
        VTableEntry entry;
        entry.address = addr;
        
        ea_t ptr = read_ea(addr);
        
        // Check for end of vtable
        if (ptr == 0 || ptr == BADADDR) {
            // Could be offset_to_top for next vtable section
            sval_t offset = read_sval(addr);
            segment_t* seg = getseg(addr);
            if (offset != 0 && seg && addr + EA_SIZE * 2 < seg->end_ea) {
                // Check if next entry is typeinfo
                ea_t next_ti = read_ea(addr + EA_SIZE);
                if (next_ti != 0 && is_mapped(next_ti)) {
                    entry.type = VTableEntryType::OFFSET_TO_TOP;
                    entry.value.offset = offset;
                    entries.push_back(entry);
                    addr += EA_SIZE;
                    continue;
                }
            }
            break;
        }
        
        // Check if it's a function pointer
        if (is_func(get_flags(ptr))) {
            // Check for special functions
            qstring func_name;
            if (get_name(&func_name, ptr) > 0) {
                if (strcmp(func_name.c_str(), PURE_VIRTUAL_NAME) == 0) {
                    entry.type = VTableEntryType::PURE_VIRTUAL;
                } else if (strcmp(func_name.c_str(), DELETED_VIRTUAL_NAME) == 0) {
                    entry.type = VTableEntryType::DELETED_VIRTUAL;
                } else if (is_thunk(ptr)) {
                    entry.type = VTableEntryType::THUNK;
                    entry.thunk_info = parse_thunk(ptr);
                } else {
                    entry.type = VTableEntryType::VIRTUAL_FUNCTION;
                }
                
                // Demangle function name
                entry.demangled_name = demangle_symbol(func_name.c_str());
            } else {
                entry.type = VTableEntryType::VIRTUAL_FUNCTION;
            }
            
            entry.value.ptr = ptr;
        } else {
            // Could be data or offset
            entry.type = VTableEntryType::VBASE_OFFSET;
            entry.value.offset = read_sval(addr);
        }
        
        entries.push_back(entry);
        addr += EA_SIZE;
    }
    
    return !entries.empty();
}

bool VTableParser::parse_construction_vtables(ea_t vtt_addr, std::vector<ConstructionVTable>& cvtables) {
    if (!is_mapped(vtt_addr))
        return false;
    
    ea_t addr = vtt_addr;
    while (is_mapped(addr)) {
        ea_t vtable_ptr = read_ea(addr);
        if (vtable_ptr == 0 || vtable_ptr == BADADDR)
            break;
        
        ConstructionVTable cvtable;
        cvtable.vtt_address = addr;
        
        // Determine constructor/destructor type from name
        qstring name;
        if (get_name(&name, vtable_ptr) > 0) {
            if (strstr(name.c_str(), "C1") != nullptr)
                cvtable.type = ConstructionVTable::COMPLETE_OBJECT_CTOR;
            else if (strstr(name.c_str(), "C2") != nullptr)
                cvtable.type = ConstructionVTable::BASE_OBJECT_CTOR;
            else if (strstr(name.c_str(), "D1") != nullptr)
                cvtable.type = ConstructionVTable::COMPLETE_OBJECT_DTOR;
            else if (strstr(name.c_str(), "D2") != nullptr)
                cvtable.type = ConstructionVTable::BASE_OBJECT_DTOR;
            else if (strstr(name.c_str(), "D0") != nullptr)
                cvtable.type = ConstructionVTable::DELETING_DTOR;
        }
        
        cvtable.sub_vtables.push_back(vtable_ptr);
        cvtables.push_back(cvtable);
        
        addr += EA_SIZE;
    }
    
    return !cvtables.empty();
}

bool VTableParser::is_thunk(ea_t addr) const {
    if (!is_func(get_flags(addr)))
        return false;
    
    // Check function name for thunk patterns
    qstring name;
    if (get_name(&name, addr) > 0) {
        // GCC/Clang thunk naming: _ZThn8_N...
        if (strncmp(name.c_str(), "_ZTh", 4) == 0)
            return true;
        // Virtual thunk: _ZTv
        if (strncmp(name.c_str(), "_ZTv", 4) == 0)
            return true;
        // Covariant thunk: _ZTc
        if (strncmp(name.c_str(), "_ZTc", 4) == 0)
            return true;
    }
    
    // Check for thunk pattern in code
    ThunkInfo info;
    return match_thunk_pattern(addr, info);
}

std::shared_ptr<ThunkInfo> VTableParser::parse_thunk(ea_t thunk_addr) {
    auto thunk = std::make_shared<ThunkInfo>();
    
    qstring name;
    if (get_name(&name, thunk_addr) > 0) {
        // Parse thunk type from mangled name
        if (strncmp(name.c_str(), "_ZThn", 5) == 0) {
            // Non-virtual thunk with adjustment
            thunk->type = ThunkInfo::THUNK_THIS_ADJUSTING;
            // Parse adjustment value from name
            const char* p = name.c_str() + 5;
            char* end;
            thunk->this_adjustment = strtol(p, &end, 10);
        } else if (strncmp(name.c_str(), "_ZTv", 4) == 0) {
            // Virtual thunk
            thunk->type = ThunkInfo::THUNK_VIRTUAL_BASE;
            // Parse vcall offset
            const char* p = name.c_str() + 4;
            if (*p == 'n') {  // negative
                p++;
                char* end;
                thunk->vcall_offset = -strtol(p, &end, 10);
            } else {
                char* end;
                thunk->vcall_offset = strtol(p, &end, 10);
            }
        } else if (strncmp(name.c_str(), "_ZTc", 4) == 0) {
            // Covariant return thunk
            thunk->type = ThunkInfo::THUNK_COVARIANT_RETURN;
        }
    }
    
    // Try to find target function by analyzing thunk code
    if (!match_thunk_pattern(thunk_addr, *thunk)) {
        // Fallback: look for jump/call to target
        func_t* f = get_func(thunk_addr);
        if (f != nullptr) {
            ea_t addr = f->start_ea;
            while (addr < f->end_ea) {
                if (is_code(get_flags(addr))) {
                    // Check if it's a call or jump instruction
                    qstring mnem;
                    print_insn_mnem(&mnem, addr);
                    if (mnem == "call" || mnem == "jmp" || mnem == "b" || mnem == "bl") {
                        thunk->target_function = get_first_fcref_from(addr);
                        if (thunk->target_function != BADADDR)
                            break;
                    }
                }
                addr = next_head(addr, f->end_ea);
            }
        }
    }
    
    return thunk;
}

ea_t VTableParser::get_typeinfo_ptr(ea_t vtable_addr) const {
    // Typeinfo pointer is at the vtable address in Itanium ABI
    return read_ea(vtable_addr);
}

std::string VTableParser::get_class_name_from_typeinfo(ea_t typeinfo_addr) const {
    if (typeinfo_addr == BADADDR || !is_mapped(typeinfo_addr))
        return "";
    
    // Get typeinfo symbol name
    qstring ti_name;
    if (get_name(&ti_name, typeinfo_addr) <= 0)
        return "";
    
    // Demangle to get class name
    return demangle_symbol(ti_name.c_str());
}

bool VTableParser::is_valid_function_ptr(ea_t addr) {
    return addr != BADADDR && addr != 0 && is_func(get_flags(addr));
}

bool VTableParser::is_pure_virtual(ea_t addr) {
    qstring name;
    if (get_name(&name, addr) > 0) {
        return strcmp(name.c_str(), PURE_VIRTUAL_NAME) == 0;
    }
    return false;
}

bool VTableParser::is_deleted_virtual(ea_t addr) {
    qstring name;
    if (get_name(&name, addr) > 0) {
        return strcmp(name.c_str(), DELETED_VIRTUAL_NAME) == 0;
    }
    return false;
}

ea_t VTableParser::read_pointer(ea_t addr) const {
    return read_ea(addr);
}

ptrdiff_t VTableParser::read_offset(ea_t addr) const {
    return read_sval(addr);
}

bool VTableParser::validate_vtable_structure(ea_t addr) const {
    // Basic validation: check if we have valid function pointers
    ea_t test_addr = addr + EA_SIZE;  // Skip typeinfo
    int valid_funcs = 0;
    
    for (int i = 0; i < 10 && is_mapped(test_addr); i++) {
        ea_t ptr = read_ea(test_addr);
        if (is_valid_function_ptr(ptr))
            valid_funcs++;
        test_addr += EA_SIZE;
    }
    
    // Require at least 2 valid function pointers
    return valid_funcs >= 2;
}

std::string VTableParser::demangle_symbol(const char* mangled) const {
    if (mangled == nullptr || mangled[0] == '\0')
        return "";
    
    qstring demangled;
    if (demangle_name(&demangled, mangled, MNG_SHORT_FORM) > 0) {
        return std::string(demangled.c_str());
    }
    
    return std::string(mangled);
}

bool VTableParser::match_thunk_pattern(ea_t addr, ThunkInfo& info) const {
    // This would require architecture-specific pattern matching
    // For now, return false - can be implemented per architecture
    return false;
}

// ===========================================================================
// GuardVariableParser Implementation
// ===========================================================================

bool GuardVariableParser::is_guard_variable(ea_t addr) const {
    qstring name;
    if (get_name(&name, addr) > 0) {
        // Check for guard variable prefix
        if (strncmp(name.c_str(), GUARD_PREFIX, strlen(GUARD_PREFIX)) == 0)
            return true;
        if (strncmp(name.c_str(), "_ZGV", 4) == 0)  // Shorter prefix
            return true;
    }
    
    return match_guard_pattern(addr);
}

std::unique_ptr<GuardVariableParser::GuardInfo> GuardVariableParser::parse_guard(ea_t guard_addr) {
    auto info = std::make_unique<GuardInfo>();
    info->guard_address = guard_addr;
    
    // Guard variables are typically 8 bytes (64-bit) or 4 bytes (32-bit)
    uint64 guard_value = inf_is_64bit() ? get_qword(guard_addr) : get_dword(guard_addr);
    
    // LSB indicates initialization status
    info->is_initialized = (guard_value & 1) != 0;
    info->init_byte = guard_value & 0xFF;
    
    // Try to find the associated object
    qstring guard_name;
    if (get_name(&guard_name, guard_addr) > 0) {
        // Remove guard prefix to get object name
        std::string obj_name = guard_name.c_str();
        if (obj_name.find("_ZGV") == 0) {
            obj_name = "_Z" + obj_name.substr(4);  // Convert guard name to object name
            info->object_address = get_name_ea(BADADDR, obj_name.c_str());
        }
    }
    
    return info;
}

bool GuardVariableParser::match_guard_pattern(ea_t addr) const {
    // Check if this looks like a guard variable (8-byte value with specific pattern)
    if (!is_mapped(addr))
        return false;
    
    size_t guard_size = inf_is_64bit() ? 8 : 4;
    if (!is_data(get_flags(addr)) || get_item_size(addr) != guard_size)
        return false;
    
    // Guard variables are typically in .bss or .data sections
    segment_t* seg = getseg(addr);
    if (seg != nullptr) {
        qstring seg_name;
        get_segm_name(&seg_name, seg);
        if (seg_name == ".bss" || seg_name == ".data" || seg_name.find(".data.rel.ro") == 0)
            return true;
    }
    
    return false;
}

// ===========================================================================
// VTTParser Implementation
// ===========================================================================

std::unique_ptr<VTTParser::VTTLayout> VTTParser::parse_vtt(ea_t vtt_addr) {
    if (!is_vtt(vtt_addr))
        return nullptr;
    
    auto layout = std::make_unique<VTTLayout>();
    layout->vtt_address = vtt_addr;
    
    size_t vtt_size = estimate_vtt_size(vtt_addr);
    ea_t addr = vtt_addr;
    
    for (size_t i = 0; i < vtt_size && is_mapped(addr); i++) {
        ea_t vtable_ptr = read_ea(addr);
        if (vtable_ptr == 0 || vtable_ptr == BADADDR)
            break;
        
        layout->vtable_pointers.push_back(vtable_ptr);
        
        // Categorize vtables
        if (i == 0) {
            layout->groups.primary_vtable = vtable_ptr;
        } else {
            // Check if it's a virtual base vtable
            qstring name;
            if (get_name(&name, vtable_ptr) > 0) {
                if (strstr(name.c_str(), "_vbase_") != nullptr) {
                    layout->groups.virtual_base_vtables.push_back(vtable_ptr);
                } else {
                    layout->groups.secondary_vtables.push_back(vtable_ptr);
                }
                
                // Add description
                VTableParser parser;
                layout->descriptions[i] = parser.demangle_symbol(name.c_str());
            }
        }
        
        addr += EA_SIZE;
    }
    
    return layout;
}

bool VTTParser::is_vtt(ea_t addr) const {
    qstring name;
    if (get_name(&name, addr) > 0) {
        return strncmp(name.c_str(), VTT_PREFIX, strlen(VTT_PREFIX)) == 0;
    }
    
    // Heuristic: VTT is an array of vtable pointers
    for (int i = 0; i < 3; i++) {
        ea_t ptr = read_ea(addr + i * EA_SIZE);
        if (ptr == 0 || ptr == BADADDR)
            return false;
        
        // Each should point to a vtable
        VTableParser parser;
        if (!parser.is_vtable(ptr))
            return false;
    }
    
    return true;
}

size_t VTTParser::estimate_vtt_size(ea_t vtt_addr) const {
    size_t count = 0;
    ea_t addr = vtt_addr;
    
    while (is_mapped(addr)) {
        ea_t ptr = read_ea(addr);
        if (ptr == 0 || ptr == BADADDR)
            break;
        
        // Verify it points to a vtable
        VTableParser parser;
        if (!parser.is_vtable(ptr))
            break;
        
        count++;
        addr += EA_SIZE;
        
        // Reasonable limit
        if (count > 100)
            break;
    }
    
    return count;
}

// ===========================================================================
// CovariantReturnHandler Implementation
// ===========================================================================

bool CovariantReturnHandler::has_covariant_return(ea_t func_addr) const {
    // Check if function name indicates covariant return
    qstring name;
    if (get_name(&name, func_addr) > 0) {
        // Covariant return thunks often have special mangling
        if (strstr(name.c_str(), "_ZTc") != nullptr)
            return true;
    }
    
    // Check function type for different return type than base
    func_t* f = get_func(func_addr);
    if (f != nullptr) {
        tinfo_t func_type;
        if (get_tinfo(&func_type, func_addr)) {
            // Would need to compare with base class method
            // This requires more context about the class hierarchy
        }
    }
    
    return false;
}

std::unique_ptr<CovariantReturnHandler::CovariantInfo> 
CovariantReturnHandler::analyze_covariant_return(ea_t override_addr) {
    auto info = std::make_unique<CovariantInfo>();
    info->overriding_function = override_addr;
    
    // Get function type
    tinfo_t override_type;
    if (!get_tinfo(&override_type, override_addr))
        return nullptr;
    
    // Extract return type
    func_type_data_t ftd;
    if (override_type.get_func_details(&ftd)) {
        info->covariant_return_type = ftd.rettype;
        
        // Try to find the original function
        // This would require analyzing the class hierarchy
        // For now, we just mark that it has covariant return
    }
    
    return info;
}

bool CovariantReturnHandler::types_are_covariant(const tinfo_t& base_type, 
                                                  const tinfo_t& derived_type) const {
    // Check if derived_type is derived from base_type
    if (!base_type.is_ptr() || !derived_type.is_ptr())
        return false;
    
    tinfo_t base_pointed = base_type;
    tinfo_t derived_pointed = derived_type;
    
    base_pointed.remove_ptr_or_array();
    derived_pointed.remove_ptr_or_array();
    
    // Check if both are class types
    if (!base_pointed.is_struct() || !derived_pointed.is_struct())
        return false;
    
    // Would need to check inheritance relationship
    // This requires walking the class hierarchy
    
    return false;  // Conservative default
}

// ===========================================================================
// ItaniumABIAnalyzer Implementation
// ===========================================================================

ItaniumABIAnalyzer::ItaniumABIAnalyzer() 
    : vtable_parser_(std::make_unique<VTableParser>()),
      vtt_parser_(std::make_unique<VTTParser>()),
      guard_parser_(std::make_unique<GuardVariableParser>()),
      covariant_handler_(std::make_unique<CovariantReturnHandler>()) {
}

ItaniumABIAnalyzer::~ItaniumABIAnalyzer() = default;

std::unique_ptr<ItaniumABIAnalyzer::ClassInfo> 
ItaniumABIAnalyzer::analyze_class(ea_t vtable_addr) {
    if (!vtable_parser_->is_vtable(vtable_addr))
        return nullptr;
    
    auto info = std::make_unique<ClassInfo>();
    info->primary_vtable = vtable_addr;
    
    // Parse vtable layout
    info->vtable_layout = vtable_parser_->parse_vtable(vtable_addr);
    if (!info->vtable_layout)
        return nullptr;
    
    // Get class name from typeinfo
    info->class_name = vtable_parser_->get_class_name_from_typeinfo(
        info->vtable_layout->header.typeinfo_ptr);
    
    // Parse VTT if exists
    qstring vtt_name;
    vtt_name.sprnt("%s%s", VTT_PREFIX, 
                   info->class_name.c_str() + strlen(VTABLE_PREFIX));
    ea_t vtt_addr = get_name_ea(BADADDR, vtt_name.c_str());
    if (vtt_addr != BADADDR) {
        info->vtt_layout = vtt_parser_->parse_vtt(vtt_addr);
    }
    
    // Analyze virtual functions
    info->total_virtual_functions = 0;
    info->pure_virtual_count = 0;
    info->deleted_virtual_count = 0;
    info->thunk_count = 0;
    
    for (const auto& entry : info->vtable_layout->entries) {
        switch (entry.type) {
            case VTableEntryType::VIRTUAL_FUNCTION:
                info->total_virtual_functions++;
                
                // Check for covariant return
                if (covariant_handler_->has_covariant_return(entry.value.ptr)) {
                    auto covariant = covariant_handler_->analyze_covariant_return(entry.value.ptr);
                    if (covariant) {
                        info->covariant_returns[entry.demangled_name] = *covariant;
                    }
                }
                break;
                
            case VTableEntryType::PURE_VIRTUAL:
                info->pure_virtual_count++;
                break;
                
            case VTableEntryType::DELETED_VIRTUAL:
                info->deleted_virtual_count++;
                break;
                
            case VTableEntryType::THUNK:
                info->thunk_count++;
                info->total_virtual_functions++;
                break;
                
            default:
                break;
        }
    }
    
    // Extract base classes from secondary vtables
    for (const auto& [offset, secondary] : info->vtable_layout->secondary_vtables) {
        std::string base_name = vtable_parser_->get_class_name_from_typeinfo(
            secondary->header.typeinfo_ptr);
        if (!base_name.empty()) {
            info->base_classes.push_back(base_name);
        }
    }
    
    // Extract virtual bases
    for (const auto& vbase : info->vtable_layout->virtual_bases) {
        info->virtual_bases.push_back(vbase.base_class_name);
    }
    
    return info;
}

std::vector<std::unique_ptr<ItaniumABIAnalyzer::ClassInfo>> 
ItaniumABIAnalyzer::analyze_all_vtables() {
    std::vector<std::unique_ptr<ClassInfo>> results;
    
    for (ea_t vtable : find_all_vtables()) {
        auto info = analyze_class(vtable);
        if (info) {
            results.push_back(std::move(info));
        }
    }
    
    return results;
}

void ItaniumABIAnalyzer::export_to_json(const ClassInfo& info, const std::string& filename) {
    // JSON export implementation would go here
    // This would serialize the ClassInfo structure to JSON format
}

void ItaniumABIAnalyzer::export_to_idapy(const ClassInfo& info) {
    // Export to IDA Python script
    // This would generate Python code to recreate the structures in IDA
}

std::vector<ea_t> ItaniumABIAnalyzer::find_all_vtables() const {
    std::vector<ea_t> vtables;
    
    // Search for all symbols starting with _ZTV
    // Search all segments for vtable symbols
    for (int i = 0; i < get_segm_qty(); i++) {
        segment_t* seg = getnseg(i);
        if (!seg) continue;
        
        ea_t addr = seg->start_ea;
        while (addr < seg->end_ea) {
            qstring name;
            if (get_name(&name, addr) > 0) {
                if (strncmp(name.c_str(), VTABLE_PREFIX, strlen(VTABLE_PREFIX)) == 0) {
                    vtables.push_back(addr);
                }
            }
            addr = next_head(addr, seg->end_ea);
        }
    }
    
    return vtables;
}

} // namespace ItaniumABI