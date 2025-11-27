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

#include "ClangVTableParser.h"
#include "Common.h"
#include "Debug.h"
#include <name.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <funcs.hpp>
#include <segment.hpp>

namespace ClangVTableParser {

// Pattern-based vtable detection for Clang/GCC on ARM64 macOS
// This doesn't rely on finding __cxxabiv1 vtables first

static bool is_potential_vtable_by_pattern(ea_t ea) {
    // On ARM64 macOS with Clang, vtables have this layout:
    // -16: offset_to_top (sval_t)
    // -8:  RTTI pointer (ea_t) 
    // 0:   First virtual function pointer
    // 8:   Second virtual function pointer...
    
    // Check if we're at a reasonable alignment (8 bytes for ARM64)
    if (ea % 8 != 0)
        return false;
    
    // Check if there's potential RTTI info before the vtable
    ea_t rtti_ptr_addr = ea - EA_SIZE;
    ea_t offset_addr = ea - 2 * EA_SIZE;
    
    if (!is_mapped(rtti_ptr_addr) || !is_mapped(offset_addr))
        return false;
    
    // Read offset to top (should be 0 for primary vtable)
    sval_t offset_to_top = 0;
    if (inf_is_64bit()) {
        uint64 val = 0;
        if (!get_bytes(&val, sizeof(val), offset_addr))
            return false;
        offset_to_top = (sval_t)val;
    } else {
        uint32 val = 0;
        if (!get_bytes(&val, sizeof(val), offset_addr))
            return false;
        offset_to_top = (sval_t)(int32)val;
    }
    
    // For primary vtables, offset_to_top should be 0
    // For secondary vtables it could be non-zero but reasonable
    if (offset_to_top != 0 && (offset_to_top < -0x10000 || offset_to_top > 0x10000))
        return false;
    
    // Read RTTI pointer
    ea_t rtti_ptr = 0;
    if (inf_is_64bit()) {
        uint64 val = 0;
        if (!get_bytes(&val, sizeof(val), rtti_ptr_addr))
            return false;
        rtti_ptr = val;
    } else {
        uint32 val = 0;
        if (!get_bytes(&val, sizeof(val), rtti_ptr_addr))
            return false;
        rtti_ptr = val;
    }
    
    // RTTI pointer should point to a valid address or be NULL
    if (rtti_ptr != 0 && !is_mapped(rtti_ptr))
        return false;
    
    // Check for function pointers in the vtable
    int valid_func_ptrs = 0;
    for (int i = 0; i < 10; i++) {
        ea_t func_ptr_addr = ea + i * EA_SIZE;
        if (!is_mapped(func_ptr_addr))
            break;
            
        ea_t func_ptr = 0;
        if (inf_is_64bit()) {
            uint64 val = 0;
            if (!get_bytes(&val, sizeof(val), func_ptr_addr))
                break;
            func_ptr = val;
        } else {
            uint32 val = 0;
            if (!get_bytes(&val, sizeof(val), func_ptr_addr))
                break;
            func_ptr = val;
        }
        
        // Check if it's NULL (end of vtable) or valid function
        if (func_ptr == 0) {
            // NULL can indicate end of vtable or pure virtual
            continue;
        }
        
        // On ARM, function pointers might have the thumb bit set
        ea_t clean_ptr = func_ptr;
        if (PH.id == PLFM_ARM) {
            clean_ptr &= ~1;  // Clear thumb bit
        }
        
        // Check if it points to executable code
        if (is_mapped(clean_ptr)) {
            segment_t *seg = getseg(clean_ptr);
            if (seg) {
                if (seg->perm & SEGPERM_EXEC) {
                    valid_func_ptrs++;
                }
            }
        }
    }
    
    // Require at least 2 valid function pointers
    return valid_func_ptrs >= 2;
}

bool find_vtables_by_symbol_pattern(std::vector<VTableInfo>& vtables) {
    msg("[CodeXplorer] ClangVTableParser: Searching for vtables by symbol patterns...\n");
    
    size_t name_count = get_nlist_size();
    int found_count = 0;
    
    for (size_t i = 0; i < name_count; i++) {
        const char* name = get_nlist_name(i);
        if (!name)
            continue;
            
        // Check for Itanium ABI vtable prefix
        if (strncmp(name, "_ZTV", 4) == 0) {
            ea_t ea = get_nlist_ea(i);
            if (ea == BADADDR)
                continue;
                
            // Demangle the name to get class name
            qstring demangled;
            if (demangle_name(&demangled, name, 0) > 0) {
                // Skip typeinfo vtables for __cxxabiv1
                if (strstr(demangled.c_str(), "__cxxabiv1") != nullptr)
                    continue;
                    
                VTableInfo info;
                info.ea = ea;
                info.name = name;
                info.demangled_name = demangled.c_str();
                
                // Extract class name from demangled vtable name
                // Format is usually "vtable for ClassName"
                const char* prefix = "vtable for ";
                const char* class_start = strstr(info.demangled_name.c_str(), prefix);
                if (class_start) {
                    info.class_name = class_start + strlen(prefix);
                } else {
                    info.class_name = info.demangled_name;
                }
                
                vtables.push_back(info);
                found_count++;
                
                msg("[CodeXplorer] ClangVTableParser: Found vtable symbol '%s' at 0x%llx\n", 
                    info.class_name.c_str(), (unsigned long long)ea);
            }
        }
    }
    
    msg("[CodeXplorer] ClangVTableParser: Found %d vtable symbols\n", found_count);
    return found_count > 0;
}

bool find_vtables_by_scanning(std::vector<VTableInfo>& vtables) {
    msg("[CodeXplorer] ClangVTableParser: Scanning memory for vtable patterns...\n");
    
    int found_count = 0;
    int seg_count = get_segm_qty();
    
    for (int i = 0; i < seg_count; i++) {
        segment_t* seg = getnseg(i);
        if (!seg)
            continue;
            
        // Only scan data segments
        if (seg->type != SEG_DATA && seg->type != SEG_BSS)
            continue;
            
        qstring seg_name;
        get_segm_name(&seg_name, seg);
        
        // Skip obviously non-vtable segments
        if (seg_name.find(".text") != qstring::npos ||
            seg_name.find(".plt") != qstring::npos ||
            seg_name.find(".got") != qstring::npos)
            continue;
            
        msg("[CodeXplorer] ClangVTableParser: Scanning segment %s\n", seg_name.c_str());
        
        // Scan segment for potential vtables
        ea_t ea = seg->start_ea;
        ea_t end_ea = seg->end_ea;
        
        // Align to pointer size
        ea = (ea + EA_SIZE - 1) & ~(EA_SIZE - 1);
        
        while (ea < end_ea) {
            // Check if this looks like a vtable
            if (is_potential_vtable_by_pattern(ea)) {
                VTableInfo info;
                info.ea = ea;
                
                // Try to get name if it exists
                qstring name;
                if (get_name(&name, ea) > 0) {
                    info.name = name.c_str();
                    
                    // Try to demangle
                    qstring demangled;
                    if (demangle_name(&demangled, name.c_str(), 0) > 0) {
                        info.demangled_name = demangled.c_str();
                    }
                } else {
                    // Generate a name based on address
                    char buf[64];
                    qsnprintf(buf, sizeof(buf), "vtable_%llx", (unsigned long long)ea);
                    info.name = buf;
                    info.class_name = buf;
                }
                
                vtables.push_back(info);
                found_count++;
                
                msg("[CodeXplorer] ClangVTableParser: Found potential vtable at 0x%llx\n", 
                    (unsigned long long)ea);
                
                // Skip ahead to avoid detecting the same vtable multiple times
                ea += EA_SIZE * 4;
            } else {
                ea += EA_SIZE;
            }
        }
    }
    
    msg("[CodeXplorer] ClangVTableParser: Found %d potential vtables by scanning\n", found_count);
    return found_count > 0;
}

bool parse_vtables_for_rtti(std::unordered_map<ea_t, VTBL_info_t>& rtti_vftables) {
    msg("[CodeXplorer] ClangVTableParser: Starting parse_vtables_for_rtti...\n");
    std::vector<VTableInfo> vtables;
    
    try {
        // First try to find vtables by symbol names
        msg("[CodeXplorer] ClangVTableParser: Searching by symbols...\n");
        bool found_by_symbols = find_vtables_by_symbol_pattern(vtables);
        msg("[CodeXplorer] ClangVTableParser: Symbol search complete, found: %s\n", found_by_symbols ? "yes" : "no");
        
        // If no symbols found, try pattern scanning
        if (!found_by_symbols) {
            msg("[CodeXplorer] ClangVTableParser: No vtable symbols found, trying pattern scan...\n");
            find_vtables_by_scanning(vtables);
            msg("[CodeXplorer] ClangVTableParser: Pattern scan complete\n");
        }
    } catch (...) {
        msg("[CodeXplorer] ERROR: Exception during vtable search\n");
        return false;
    }
    
    msg("[CodeXplorer] ClangVTableParser: Converting %zu vtables to VTBL_info_t format...\n", vtables.size());
    
    // Convert found vtables to VTBL_info_t format
    for (const auto& vtable : vtables) {
        VTBL_info_t info;
        
        // For Itanium ABI, the vtable symbol points to the start of the vtable structure
        // which includes metadata. The actual function pointers start at offset +16 (or +8 on 32-bit)
        // Layout:
        //   vtable.ea - 2*EA_SIZE: offset_to_top
        //   vtable.ea - EA_SIZE:   RTTI pointer
        //   vtable.ea:             First function pointer
        
        // The symbol actually points to the offset_to_top, so we need to skip forward
        ea_t vtable_start = vtable.ea + 2 * EA_SIZE;  // Skip to first method
        info.ea_begin = vtable_start;
        
        msg("[CodeXplorer] ClangVTableParser: Processing vtable '%s' at 0x%llx (methods start at 0x%llx)\n", 
            vtable.class_name.c_str(), (unsigned long long)vtable.ea, (unsigned long long)vtable_start);
        
        // First, let's try to read the RTTI pointer to get type information
        ea_t rtti_ptr_addr = vtable.ea + EA_SIZE;
        ea_t rtti_ptr = 0;
        if (inf_is_64bit()) {
            uint64 val = 0;
            if (get_bytes(&val, sizeof(val), rtti_ptr_addr)) {
                rtti_ptr = val;
                msg("[CodeXplorer] ClangVTableParser: RTTI pointer at 0x%llx points to 0x%llx\n",
                    (unsigned long long)rtti_ptr_addr, (unsigned long long)rtti_ptr);
                
                // Try to read the type name from RTTI
                if (rtti_ptr && is_mapped(rtti_ptr)) {
                    // Itanium ABI type_info structure:
                    // - vtable pointer (8 bytes)
                    // - type name pointer (8 bytes) or inline name
                    ea_t name_ptr_addr = rtti_ptr + EA_SIZE;
                    if (is_mapped(name_ptr_addr)) {
                        uint64 name_ptr = 0;
                        if (get_bytes(&name_ptr, sizeof(name_ptr), name_ptr_addr) && name_ptr) {
                            qstring type_name;
                            if (get_strlit_contents(&type_name, (ea_t)name_ptr, 256, STRTYPE_C) > 0) {
                                msg("[CodeXplorer] ClangVTableParser: RTTI type name: %s\n", type_name.c_str());
                                
                                // Demangle the type name if it's mangled
                                if (type_name.length() > 2 && type_name[0] == '_' && type_name[1] == 'Z') {
                                    qstring demangled;
                                    if (demangle_name(&demangled, type_name.c_str(), 0) > 0) {
                                        msg("[CodeXplorer] ClangVTableParser: Demangled type: %s\n", demangled.c_str());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            uint32 val = 0;
            if (get_bytes(&val, sizeof(val), rtti_ptr_addr)) {
                rtti_ptr = val;
                msg("[CodeXplorer] ClangVTableParser: RTTI pointer at 0x%llx points to 0x%llx\n",
                    (unsigned long long)rtti_ptr_addr, (unsigned long long)rtti_ptr);
                
                // Similar RTTI extraction for 32-bit
                if (rtti_ptr && is_mapped(rtti_ptr)) {
                    ea_t name_ptr_addr = rtti_ptr + EA_SIZE;
                    if (is_mapped(name_ptr_addr)) {
                        uint32 name_ptr = 0;
                        if (get_bytes(&name_ptr, sizeof(name_ptr), name_ptr_addr) && name_ptr) {
                            qstring type_name;
                            if (get_strlit_contents(&type_name, (ea_t)name_ptr, 256, STRTYPE_C) > 0) {
                                msg("[CodeXplorer] ClangVTableParser: RTTI type name: %s\n", type_name.c_str());
                                
                                // Demangle if needed
                                if (type_name.length() > 2 && type_name[0] == '_' && type_name[1] == 'Z') {
                                    qstring demangled;
                                    if (demangle_name(&demangled, type_name.c_str(), 0) > 0) {
                                        msg("[CodeXplorer] ClangVTableParser: Demangled type: %s\n", demangled.c_str());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Count methods starting from the first function pointer
        int method_count = 0;
        ea_t ea = vtable_start;
        while (is_mapped(ea)) {
            // Ensure we can read a full pointer at this address
            if (!is_mapped(ea + EA_SIZE - 1))
                break;
                
            ea_t func_ptr = 0;
            if (inf_is_64bit()) {
                uint64 val = 0;
                if (!get_bytes(&val, sizeof(val), ea))
                    break;
                func_ptr = val;
            } else {
                uint32 val = 0;
                if (!get_bytes(&val, sizeof(val), ea))
                    break;
                func_ptr = val;
            }
            if (func_ptr == 0) {
                // NULL pointer could mean:
                // 1. Pure virtual function (should continue)
                // 2. End of vtable (should break)
                // We'll check if the next entry looks like another vtable or data
                ea_t next_ea = ea + EA_SIZE;
                if (is_mapped(next_ea)) {
                    ea_t next_ptr = 0;
                    if (inf_is_64bit()) {
                        uint64 val = 0;
                        if (get_bytes(&val, sizeof(val), next_ea))
                            next_ptr = val;
                    } else {
                        uint32 val = 0;
                        if (get_bytes(&val, sizeof(val), next_ea))
                            next_ptr = val;
                    }
                    
                    // If next pointer is also NULL or looks like vtable metadata, we're done
                    if (next_ptr == 0 || next_ptr < 0x1000) {
                        break;  // Likely end of vtable
                    }
                }
                // Count this as a pure virtual
                method_count++;
                ea += EA_SIZE;
                continue;
            }
            
            // Clean ARM thumb bit if needed
            if (PH.id == PLFM_ARM) {
                func_ptr &= ~1;
            }
            
            // Check if it's a valid function pointer
            if (!is_mapped(func_ptr)) {
                // This might be the start of another vtable or data structure
                break;
            }
                
            segment_t* seg = getseg(func_ptr);
            if (!seg) {
                break;
            }
            
            // Check if it points to executable code
            if (!(seg->perm & SEGPERM_EXEC)) {
                // Not executable - could be RTTI data or another vtable
                // Check if it might be another vtable's offset_to_top
                if (func_ptr < 0x10000 || func_ptr > 0xFFFFFFFF00000000LL) {
                    // Looks like offset_to_top of next vtable
                    break;
                }
                // Otherwise might be data pointer - continue for now
            }
                
            method_count++;
            ea += EA_SIZE;
            
            // Reasonable limit
            if (method_count > 1000)
                break;
        }
        
        info.ea_end = ea;
        info.methods = method_count;
        info.vtbl_name = vtable.class_name.c_str();
        
        // Store in the map
        rtti_vftables[info.ea_begin] = info;
        
        msg("[CodeXplorer] ClangVTableParser: Added vtable '%s' at 0x%llx with %llu methods\n",
            info.vtbl_name.c_str(), (unsigned long long)info.ea_begin, (unsigned long long)info.methods);
    }
    
    msg("[CodeXplorer] ClangVTableParser: Total vtables found: %zu\n", vtables.size());
    return !vtables.empty();
}

} // namespace ClangVTableParser