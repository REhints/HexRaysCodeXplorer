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

#include "MSVCRTTIEnhanced.h"
#include <name.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <algorithm>
#include <sstream>

namespace MSVCRTTI {

// MSVC RTTI signature constants
static const uint32_t COL_SIGNATURE_32 = 0;
static const uint32_t COL_SIGNATURE_64 = 1;
static const char* VTABLE_PREFIX = "??_7";  // MSVC vtable prefix
static const char* TYPEINFO_PREFIX = "??_R0";  // Type descriptor prefix
static const char* COL_PREFIX = "??_R4";  // Complete object locator prefix
static const char* CHD_PREFIX = "??_R3";  // Class hierarchy descriptor prefix
static const char* BCD_PREFIX = "??_R2";  // Base class descriptor prefix
static const char* PURE_VIRTUAL_NAME = "_purecall";

// Helper to read pointer based on architecture
static ea_t read_ea_arch(ea_t addr) {
    return inf_is_64bit() ? get_qword(addr) : get_dword(addr);
}

// ===========================================================================
// CompleteObjectLocator Implementation
// ===========================================================================

ea_t CompleteObjectLocator::get_type_descriptor(ea_t image_base) const {
    if (signature == COL_SIGNATURE_64) {
        // 64-bit uses RVA
        return image_base + typeDescriptorRVA;
    } else {
        // 32-bit uses direct pointer
        return pTypeDescriptor;
    }
}

ea_t CompleteObjectLocator::get_class_descriptor(ea_t image_base) const {
    if (signature == COL_SIGNATURE_64) {
        // 64-bit uses RVA
        return image_base + classDescriptorRVA;
    } else {
        // 32-bit uses direct pointer
        return pClassDescriptor;
    }
}

bool CompleteObjectLocator::validate() const {
    // Check signature
    if (signature != COL_SIGNATURE_32 && signature != COL_SIGNATURE_64)
        return false;
    
    // Check self-reference (MSVC 2019+ feature)
    if (signature == COL_SIGNATURE_64 && selfRVA != 0) {
        // selfRVA should point back to this structure
        // This validation would need the actual address of the COL
    }
    
    // Offset and cdOffset should be reasonable
    if (offset > 0x10000 || cdOffset > 0x10000)
        return false;
    
    return true;
}

// ===========================================================================
// TypeDescriptor Implementation
// ===========================================================================

std::string TypeDescriptor::get_demangled_name() const {
    // MSVC type names start after the vtable pointer and spare field
    const char* mangled = name;
    
    qstring demangled;
    if (demangle_name(&demangled, mangled, 0) > 0) {
        // Remove "class " or "struct " prefix if present
        std::string result = demangled.c_str();
        if (result.find("class ") == 0)
            result = result.substr(6);
        else if (result.find("struct ") == 0)
            result = result.substr(7);
        return result;
    }
    
    return std::string(mangled);
}

size_t TypeDescriptor::get_size() const {
    // Size is variable based on name length
    return offsetof(TypeDescriptor, name) + strlen(name) + 1;
}

// ===========================================================================
// ClassHierarchyDescriptor Implementation
// ===========================================================================

ea_t ClassHierarchyDescriptor::get_base_array(ea_t image_base) const {
    if (signature != 0)
        return BADADDR;  // Invalid signature
    
    // Check if using RVA (64-bit) or direct pointer (32-bit)
    if (inf_is_64bit()) {
        return image_base + baseClassArrayRVA;
    } else {
        return pBaseClassArray;
    }
}

// ===========================================================================
// BaseClassDescriptor Implementation
// ===========================================================================

ea_t BaseClassDescriptor::get_type_descriptor(ea_t image_base) const {
    if (inf_is_64bit()) {
        return image_base + typeDescriptorRVA;
    } else {
        return pTypeDescriptor;
    }
}

ea_t BaseClassDescriptor::get_class_descriptor(ea_t image_base) const {
    if (inf_is_64bit()) {
        return image_base + classDescriptorRVA;
    } else {
        return pClassDescriptor;
    }
}

bool BaseClassDescriptor::is_virtual_base() const {
    // Virtual bases have vdisp != -1
    return vdisp != -1;
}

// ===========================================================================
// VTableLayout Implementation
// ===========================================================================

ea_t VTableLayout::get_function_at(size_t index) const {
    if (index < virtual_functions.size()) {
        return virtual_functions[index].address;
    }
    return BADADDR;
}

std::string VTableLayout::get_class_name() const {
    if (type_desc) {
        return type_desc->get_demangled_name();
    }
    return "";
}

// ===========================================================================
// RTTIParser Implementation
// ===========================================================================

RTTIParser::RTTIParser() {
    // Determine addressing mode based on architecture
    addr_mode_ = inf_is_64bit() ? AddressingMode::RVA : AddressingMode::ABSOLUTE;
    
    // Get image base for RVA calculations
    image_base_ = get_imagebase();
}

RTTIParser::~RTTIParser() = default;

bool RTTIParser::is_vtable(ea_t addr) const {
    if (addr == BADADDR || !is_mapped(addr))
        return false;
    
    // Check for MSVC vtable name pattern
    qstring name;
    if (get_name(&name, addr) > 0) {
        if (strncmp(name.c_str(), VTABLE_PREFIX, strlen(VTABLE_PREFIX)) == 0)
            return true;
    }
    
    // Try to find COL
    ea_t col_addr = find_col_from_vtable(addr);
    if (col_addr != BADADDR) {
        auto col = parse_col_internal(col_addr);
        if (col && col->validate())
            return true;
    }
    
    return validate_vtable_structure(addr);
}

std::unique_ptr<VTableLayout> RTTIParser::parse_vtable(ea_t vtable_addr) {
    // No caching for VTableLayout due to unique_ptr members
    // auto cached = vtable_cache_.find(vtable_addr);
    // if (cached != vtable_cache_.end()) {
    //     return std::make_unique<VTableLayout>(*cached->second);
    // }
    
    auto layout = std::make_unique<VTableLayout>();
    layout->vtable_address = vtable_addr;
    
    // Find and parse COL
    layout->col_address = find_col_from_vtable(vtable_addr);
    if (layout->col_address == BADADDR)
        return nullptr;
    
    layout->col = parse_col(layout->col_address);
    if (!layout->col || !layout->col->validate())
        return nullptr;
    
    // Parse type descriptor
    ea_t td_addr = layout->col->get_type_descriptor(image_base_);
    layout->type_desc = parse_type_descriptor(td_addr);
    
    // Parse class hierarchy
    ea_t chd_addr = layout->col->get_class_descriptor(image_base_);
    layout->class_desc = parse_class_hierarchy(chd_addr);
    
    // Parse base classes
    if (layout->class_desc) {
        ea_t base_array = layout->class_desc->get_base_array(image_base_);
        for (uint32_t i = 0; i < layout->class_desc->numBaseClasses; i++) {
            ea_t bcd_addr = read_ea_arch(base_array + i * EA_SIZE);
            if (addr_mode_ == AddressingMode::RVA) {
                bcd_addr = image_base_ + bcd_addr;
            }
            
            auto bcd = parse_base_class(bcd_addr);
            if (bcd) {
                layout->base_classes.push_back(std::move(bcd));
            }
        }
    }
    
    // Parse virtual functions
    ea_t func_addr = vtable_addr;
    while (is_mapped(func_addr)) {
        ea_t func_ptr = read_ea_arch(func_addr);
        if (func_ptr == 0 || func_ptr == BADADDR)
            break;
        
        if (!is_func(get_flags(func_ptr)))
            break;
        
        VTableLayout::VirtualFunction vfunc;
        vfunc.address = func_ptr;
        
        // Get function name
        qstring func_name;
        if (get_name(&func_name, func_ptr) > 0) {
            vfunc.name = demangle_msvc_name(func_name.c_str());
            
            // Check for pure virtual
            vfunc.is_pure_virtual = (strcmp(func_name.c_str(), PURE_VIRTUAL_NAME) == 0);
        }
        
        // Check for CFG
        vfunc.has_cfg_check = match_cfg_check_pattern(func_ptr);
        
        // Parse SEH info
        vfunc.seh_info = parse_seh_info(func_ptr);
        
        layout->virtual_functions.push_back(vfunc);
        func_addr += EA_SIZE;
    }
    
    // Get CFG targets
    if (has_cfg_checks(vtable_addr)) {
        layout->cfg_targets = get_cfg_targets(vtable_addr);
    }
    
    // Detect WPO
    layout->wpo_info = detect_wpo(vtable_addr);
    
    // Don't cache - VTableLayout has unique_ptr members that can't be copied
    // vtable_cache_[vtable_addr] = std::make_shared<VTableLayout>(*layout);
    
    return layout;
}

std::unique_ptr<CompleteObjectLocator> RTTIParser::parse_col_internal(ea_t col_addr) const {
    if (!is_mapped(col_addr))
        return nullptr;
    
    auto col = std::make_unique<CompleteObjectLocator>();
    
    // Read COL fields
    col->signature = get_dword(col_addr);
    col->offset = get_dword(col_addr + 4);
    col->cdOffset = get_dword(col_addr + 8);
    
    if (col->signature == COL_SIGNATURE_64) {
        // 64-bit: RVAs
        col->typeDescriptorRVA = get_dword(col_addr + 12);
        col->classDescriptorRVA = get_dword(col_addr + 16);
        col->selfRVA = get_dword(col_addr + 20);  // MSVC 2019+
    } else {
        // 32-bit: direct pointers
        col->pTypeDescriptor = get_dword(col_addr + 12);
        col->pClassDescriptor = get_dword(col_addr + 16);
        if (get_item_size(col_addr) >= 24) {
            col->pSelf = get_dword(col_addr + 20);  // MSVC 2019+
        }
    }
    
    if (!col->validate())
        return nullptr;
    
    return col;
}

std::unique_ptr<CompleteObjectLocator> RTTIParser::parse_col(ea_t col_addr) {
    if (!is_mapped(col_addr))
        return nullptr;
    
    // Check cache
    auto cached = col_cache_.find(col_addr);
    if (cached != col_cache_.end()) {
        return std::make_unique<CompleteObjectLocator>(*cached->second);
    }
    
    auto col = std::make_unique<CompleteObjectLocator>();
    
    // Read COL fields
    col->signature = get_dword(col_addr);
    col->offset = get_dword(col_addr + 4);
    col->cdOffset = get_dword(col_addr + 8);
    
    if (col->signature == COL_SIGNATURE_64) {
        // 64-bit: RVAs
        col->typeDescriptorRVA = get_dword(col_addr + 12);
        col->classDescriptorRVA = get_dword(col_addr + 16);
        col->selfRVA = get_dword(col_addr + 20);  // MSVC 2019+
    } else {
        // 32-bit: direct pointers
        col->pTypeDescriptor = get_dword(col_addr + 12);
        col->pClassDescriptor = get_dword(col_addr + 16);
        if (get_item_size(col_addr) >= 24) {
            col->pSelf = get_dword(col_addr + 20);  // MSVC 2019+
        }
    }
    
    if (!col->validate())
        return nullptr;
    
    // Cache result (using move to avoid copy)
    auto col_copy = std::make_shared<CompleteObjectLocator>();
    *col_copy = *col;
    col_cache_[col_addr] = col_copy;
    
    return col;
}

std::unique_ptr<TypeDescriptor> RTTIParser::parse_type_descriptor(ea_t td_addr) {
    if (!is_mapped(td_addr))
        return nullptr;
    
    auto td = std::make_unique<TypeDescriptor>();
    
    // Read type descriptor fields
    td->pVFTable = read_ea_arch(td_addr);
    td->spare = inf_is_64bit() ? get_qword(td_addr + 8) : get_dword(td_addr + 4);
    
    // Read mangled name
    ea_t name_addr = td_addr + (inf_is_64bit() ? 16 : 8);
    qstring mangled_name;
    get_strlit_contents(&mangled_name, name_addr, -1, STRTYPE_C);
    
    if (!mangled_name.empty()) {
        qstrncpy(td->name, mangled_name.c_str(), sizeof(td->name) - 1);
        td->name[sizeof(td->name) - 1] = '\0';
    }
    
    return td;
}

std::unique_ptr<ClassHierarchyDescriptor> RTTIParser::parse_class_hierarchy(ea_t chd_addr) {
    if (!is_mapped(chd_addr))
        return nullptr;
    
    auto chd = std::make_unique<ClassHierarchyDescriptor>();
    
    // Read CHD fields
    chd->signature = get_dword(chd_addr);
    chd->attributes = get_dword(chd_addr + 4);
    chd->numBaseClasses = get_dword(chd_addr + 8);
    
    if (inf_is_64bit()) {
        chd->baseClassArrayRVA = get_dword(chd_addr + 12);
    } else {
        chd->pBaseClassArray = get_dword(chd_addr + 12);
    }
    
    return chd;
}

std::unique_ptr<BaseClassDescriptor> RTTIParser::parse_base_class(ea_t bcd_addr) {
    if (!is_mapped(bcd_addr))
        return nullptr;
    
    auto bcd = std::make_unique<BaseClassDescriptor>();
    
    // Read BCD fields
    if (inf_is_64bit()) {
        bcd->typeDescriptorRVA = get_dword(bcd_addr);
    } else {
        bcd->pTypeDescriptor = get_dword(bcd_addr);
    }
    
    bcd->numContainedBases = get_dword(bcd_addr + 4);
    bcd->mdisp = get_dword(bcd_addr + 8);
    bcd->pdisp = get_dword(bcd_addr + 12);
    bcd->vdisp = get_dword(bcd_addr + 16);
    bcd->attributes = get_dword(bcd_addr + 20);
    
    if (inf_is_64bit()) {
        bcd->classDescriptorRVA = get_dword(bcd_addr + 24);
    } else {
        bcd->pClassDescriptor = get_dword(bcd_addr + 24);
    }
    
    return bcd;
}

bool RTTIParser::has_cfg_checks(ea_t vtable_addr) const {
    // Check if any virtual functions have CFG checks
    ea_t func_addr = vtable_addr;
    while (is_mapped(func_addr)) {
        ea_t func_ptr = read_ea_arch(func_addr);
        if (func_ptr == 0 || func_ptr == BADADDR)
            break;
        
        if (match_cfg_check_pattern(func_ptr))
            return true;
        
        func_addr += EA_SIZE;
    }
    
    return false;
}

std::vector<CFGVirtualCallTarget> RTTIParser::get_cfg_targets(ea_t vtable_addr) {
    std::vector<CFGVirtualCallTarget> targets;
    
    // Look for CFG metadata section
    segment_t* cfg_seg = get_segm_by_name(".gfids");
    if (cfg_seg == nullptr)
        return targets;
    
    // Parse CFG targets from .gfids section
    ea_t addr = cfg_seg->start_ea;
    while (addr < cfg_seg->end_ea) {
        CFGVirtualCallTarget target;
        target.target_address = read_ea_arch(addr);
        target.flags = get_dword(addr + EA_SIZE);
        
        // Check if this target is in our vtable
        ea_t func_addr = vtable_addr;
        while (is_mapped(func_addr)) {
            ea_t func_ptr = read_ea_arch(func_addr);
            if (func_ptr == target.target_address) {
                targets.push_back(target);
                break;
            }
            if (func_ptr == 0 || func_ptr == BADADDR)
                break;
            func_addr += EA_SIZE;
        }
        
        addr += EA_SIZE + 4;
    }
    
    return targets;
}

std::shared_ptr<SEHInfo> RTTIParser::parse_seh_info(ea_t func_addr) {
    if (!match_seh_pattern(func_addr))
        return nullptr;
    
    auto seh = std::make_shared<SEHInfo>();
    seh->handler_address = BADADDR;
    seh->coroutine_frame_handler = BADADDR;
    
    // Look for SEH metadata
    func_t* func = get_func(func_addr);
    if (func == nullptr)
        return nullptr;
    
    // Check for __try/__except blocks
    // This would require parsing the UNWIND_INFO structures
    // For now, just detect if SEH is present
    
    qstring func_name;
    if (get_name(&func_name, func_addr) > 0) {
        // Check for coroutine markers
        if (strstr(func_name.c_str(), "coroutine") != nullptr ||
            strstr(func_name.c_str(), "$_ResumeCoro") != nullptr) {
            seh->coroutine_frame_handler = func_addr;
        }
    }
    
    return seh;
}

std::unique_ptr<WPOInfo> RTTIParser::detect_wpo(ea_t vtable_addr) {
    auto wpo = std::make_unique<WPOInfo>();
    wpo->is_devirtualized = false;
    wpo->original_vtable = vtable_addr;
    wpo->type = WPOInfo::WPO_NONE;
    
    // Look for WPO patterns
    // 1. Check if vtable functions are directly called (devirtualization)
    // 2. Check for inlined vtable calls
    // 3. Check for eliminated virtual calls
    
    // This would require control flow analysis
    // For now, just mark if the vtable seems unused
    
    xrefblk_t xb;
    if (!xb.first_to(vtable_addr, XREF_DATA)) {
        // No references to vtable - might be optimized out
        wpo->type = WPOInfo::WPO_ELIMINATED;
        wpo->is_devirtualized = true;
    }
    
    return wpo;
}

ea_t RTTIParser::find_col_from_vtable(ea_t vtable_addr) const {
    // COL is typically at vtable[-1] for MSVC
    ea_t col_ptr_addr = vtable_addr - EA_SIZE;
    if (!is_mapped(col_ptr_addr))
        return BADADDR;
    
    ea_t col_addr = read_ea_arch(col_ptr_addr);
    
    // Validate it's a COL
    if (col_addr != BADADDR && is_mapped(col_addr)) {
        uint32_t signature = get_dword(col_addr);
        if (signature == COL_SIGNATURE_32 || signature == COL_SIGNATURE_64) {
            return col_addr;
        }
    }
    
    return BADADDR;
}

AddressingMode RTTIParser::get_addressing_mode() const {
    return addr_mode_;
}

ea_t RTTIParser::rva_to_va(uint32_t rva) const {
    return image_base_ + rva;
}

bool RTTIParser::validate_col(const CompleteObjectLocator& col) const {
    return col.validate();
}

bool RTTIParser::validate_vtable_structure(ea_t addr) const {
    // Check for valid function pointers
    int valid_funcs = 0;
    ea_t test_addr = addr;
    
    for (int i = 0; i < 10 && is_mapped(test_addr); i++) {
        ea_t ptr = read_ea_arch(test_addr);
        if (ptr != 0 && ptr != BADADDR && is_func(get_flags(ptr))) {
            valid_funcs++;
        }
        test_addr += EA_SIZE;
    }
    
    return valid_funcs >= 2;
}

std::string RTTIParser::demangle_msvc_name(const char* mangled) const {
    qstring demangled;
    if (demangle_name(&demangled, mangled, 0) > 0) {
        return std::string(demangled.c_str());
    }
    return std::string(mangled);
}

bool RTTIParser::match_vtable_pattern(ea_t addr) const {
    // Check for MSVC vtable pattern
    qstring name;
    if (get_name(&name, addr) > 0) {
        return strncmp(name.c_str(), VTABLE_PREFIX, strlen(VTABLE_PREFIX)) == 0;
    }
    return false;
}

bool RTTIParser::match_cfg_check_pattern(ea_t addr) const {
    // Look for CFG check pattern at function entry
    // Typically: test rcx, rcx; jz ...; call __guard_check_icall
    
    // This would require disassembly analysis
    // For now, check for __guard_check_icall references
    
    func_t* func = get_func(addr);
    if (func == nullptr)
        return false;
    
    ea_t check_addr = func->start_ea;
    for (int i = 0; i < 10 && check_addr < func->end_ea; i++) {
        qstring mnem;
        print_insn_mnem(&mnem, check_addr);
        
        if (mnem == "call") {
            ea_t target = get_first_fcref_from(check_addr);
            qstring target_name;
            if (get_name(&target_name, target) > 0) {
                if (strstr(target_name.c_str(), "guard_check") != nullptr ||
                    strstr(target_name.c_str(), "guard_dispatch") != nullptr) {
                    return true;
                }
            }
        }
        
        check_addr = next_head(check_addr, func->end_ea);
    }
    
    return false;
}

bool RTTIParser::match_seh_pattern(ea_t addr) const {
    // Check for SEH patterns
    func_t* func = get_func(addr);
    if (func == nullptr)
        return false;
    
    // Look for exception handler setup
    // This would require parsing UNWIND_INFO
    
    return false;  // Simplified for now
}

// ===========================================================================
// ModuleParser Implementation
// ===========================================================================

std::unique_ptr<ModuleInfo> ModuleParser::parse_module_info(ea_t module_addr) {
    // C++20 module parsing would go here
    // This is a placeholder for future implementation
    return nullptr;
}

std::vector<ea_t> ModuleParser::find_all_modules() {
    std::vector<ea_t> modules;
    // Module detection logic would go here
    return modules;
}

bool ModuleParser::is_module_section(ea_t addr) const {
    segment_t* seg = getseg(addr);
    if (seg != nullptr) {
        qstring seg_name;
        get_segm_name(&seg_name, seg);
        // Check for module-specific sections
        if (seg_name.find(".ifc") != qstring::npos ||
            seg_name.find(".module") != qstring::npos) {
            return true;
        }
    }
    return false;
}

bool ModuleInfo::has_export(const std::string& type_name) const {
    return exported_types.find(type_name) != exported_types.end();
}

// ===========================================================================
// CoroutineAnalyzer Implementation
// ===========================================================================

std::unique_ptr<CoroutineInfo> CoroutineAnalyzer::analyze_coroutine(ea_t func_addr) {
    if (!is_coroutine_frame(func_addr))
        return nullptr;
    
    auto info = std::make_unique<CoroutineInfo>();
    info->promise_vtable = BADADDR;
    info->awaiter_vtable = BADADDR;
    
    // Look for coroutine frame setup
    // This would require analyzing the coroutine frame structure
    
    return info;
}

bool CoroutineAnalyzer::is_coroutine_frame(ea_t addr) const {
    return match_coroutine_pattern(addr);
}

bool CoroutineAnalyzer::match_coroutine_pattern(ea_t addr) const {
    // Check for coroutine patterns
    qstring name;
    if (get_name(&name, addr) > 0) {
        if (strstr(name.c_str(), "$_ResumeCoro") != nullptr ||
            strstr(name.c_str(), "$_DestroyCoro") != nullptr ||
            strstr(name.c_str(), "coroutine_handle") != nullptr) {
            return true;
        }
    }
    return false;
}

// ===========================================================================
// MSVCAnalyzer Implementation
// ===========================================================================

MSVCAnalyzer::MSVCAnalyzer()
    : rtti_parser_(std::make_unique<RTTIParser>()),
      module_parser_(std::make_unique<ModuleParser>()),
      coroutine_analyzer_(std::make_unique<CoroutineAnalyzer>()) {
}

MSVCAnalyzer::~MSVCAnalyzer() = default;

std::unique_ptr<MSVCAnalyzer::ClassInfo> MSVCAnalyzer::analyze_class(ea_t vtable_addr) {
    if (!rtti_parser_->is_vtable(vtable_addr))
        return nullptr;
    
    auto info = std::make_unique<ClassInfo>();
    info->primary_vtable = vtable_addr;
    
    // Parse vtable layout
    info->vtable_layout = rtti_parser_->parse_vtable(vtable_addr);
    if (!info->vtable_layout)
        return nullptr;
    
    // Get class name
    info->class_name = info->vtable_layout->get_class_name();
    
    // Analyze inheritance
    analyze_inheritance(*info);
    
    // Calculate statistics
    info->total_virtual_functions = info->vtable_layout->virtual_functions.size();
    info->pure_virtual_count = 0;
    info->cfg_protected_count = 0;
    info->has_seh_handlers = false;
    
    for (const auto& vfunc : info->vtable_layout->virtual_functions) {
        if (vfunc.is_pure_virtual)
            info->pure_virtual_count++;
        if (vfunc.has_cfg_check)
            info->cfg_protected_count++;
        if (vfunc.seh_info && vfunc.seh_info->handler_address != BADADDR)
            info->has_seh_handlers = true;
        if (vfunc.seh_info && vfunc.seh_info->has_coroutine_frame())
            info->is_coroutine_type = true;
    }
    
    // Check for WPO
    if (info->vtable_layout->wpo_info && info->vtable_layout->wpo_info->is_devirtualized)
        info->has_wpo_optimizations = true;
    
    return info;
}

std::vector<std::unique_ptr<MSVCAnalyzer::ClassInfo>> MSVCAnalyzer::analyze_all_classes() {
    std::vector<std::unique_ptr<ClassInfo>> results;
    
    for (ea_t vtable : find_all_vtables()) {
        auto info = analyze_class(vtable);
        if (info) {
            results.push_back(std::move(info));
        }
    }
    
    return results;
}

void MSVCAnalyzer::export_to_json(const ClassInfo& info, const std::string& filename) {
    // JSON export implementation
    // This would serialize the ClassInfo to JSON
}

void MSVCAnalyzer::export_to_ida_types(const ClassInfo& info) {
    // Create IDA type definitions
    // This would create structures in IDA's type system
}

std::vector<ea_t> MSVCAnalyzer::find_all_vtables() const {
    std::vector<ea_t> vtables;
    
    // Search for MSVC vtable patterns
    for (size_t i = 0; i < get_nlist_size(); i++) {
        ea_t addr = get_nlist_ea(i);
        const char* name = get_nlist_name(i);
        if (name != nullptr) {
            if (strncmp(name, VTABLE_PREFIX, strlen(VTABLE_PREFIX)) == 0) {
                vtables.push_back(addr);
            }
        }
    }
    
    return vtables;
}

void MSVCAnalyzer::analyze_inheritance(ClassInfo& info) {
    if (!info.vtable_layout || !info.vtable_layout->class_desc)
        return;
    
    // Extract base class names
    for (const auto& base : info.vtable_layout->base_classes) {
        ea_t td_addr = base->get_type_descriptor(rtti_parser_->rva_to_va(0));
        auto td = rtti_parser_->parse_type_descriptor(td_addr);
        if (td) {
            std::string base_name = td->get_demangled_name();
            
            if (base->is_virtual_base()) {
                info.virtual_bases.push_back(base_name);
            } else {
                info.base_classes.push_back(base_name);
            }
        }
    }
}

} // namespace MSVCRTTI