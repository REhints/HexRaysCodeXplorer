/*
    Simple Working Improvements to Object Explorer
    Compatible with existing codebase
*/

#include "Common.h"
#include "ObjectExplorer.h"
#include "Utility.h"
#include <map>

extern qvector<VTBL_info_t> vtbl_t_list;
extern qvector<qstring> vtbl_list;

// Enhanced display with more information
void show_enhanced_vtable_info(const VTBL_info_t& vtbl) {
    msg("\n");
    msg("================== VTable Details ==================\n");
    msg("Class Name: %s\n", vtbl.vtbl_name.c_str());
    msg("Address Range: 0x%llx - 0x%llx\n", 
        (unsigned long long)vtbl.ea_begin, 
        (unsigned long long)vtbl.ea_end);
    msg("Methods Count: %d\n", (int)vtbl.methods);
    
    // Show module/segment
    qstring seg_name;
    if (segment_t* seg = getseg(vtbl.ea_begin)) {
        get_segm_name(&seg_name, seg);
        msg("Segment: %s\n", seg_name.c_str());
    }
    
    // Count and show xrefs
    int xref_count = 0;
    for (auto addr = get_first_dref_to(vtbl.ea_begin); 
         addr != BADADDR; 
         addr = get_next_dref_to(vtbl.ea_begin, addr)) {
        xref_count++;
    }
    msg("Cross References: %d\n", xref_count);
    
    // Check for RTTI
    ea_t rtti_ea = vtbl.ea_begin - 2 * EA_SIZE;
    if (is_mapped(rtti_ea + EA_SIZE)) {
        ea_t rtti_ptr = getEa(rtti_ea + EA_SIZE);
        if (rtti_ptr != 0 && is_mapped(rtti_ptr)) {
            msg("RTTI: Present (0x%llx)\n", (unsigned long long)rtti_ptr);
        } else {
            msg("RTTI: Not found\n");
        }
    }
    
    // List methods
    msg("\nVirtual Methods:\n");
    ea_t method_ea = vtbl.ea_begin;
    for (asize_t i = 0; i < vtbl.methods && i < 50; i++) {  // Limit to 50 for display
        ea_t func_ea = getEa(method_ea);
        qstring func_name;
        
        if (func_ea == 0) {
            func_name = "__purecall";
        } else {
            if (PH.id == PLFM_ARM) {
                func_ea &= ~1;  // Clear thumb bit
            }
            get_func_name(&func_name, func_ea);
            if (func_name.empty()) {
                func_name.sprnt("sub_%llx", (unsigned long long)func_ea);
            }
        }
        
        msg("  [%2d] 0x%llx: %s\n", (int)i, (unsigned long long)func_ea, func_name.c_str());
        method_ea += EA_SIZE;
    }
    
    if (vtbl.methods > 50) {
        msg("  ... and %d more methods\n", (int)(vtbl.methods - 50));
    }
    
    msg("====================================================\n\n");
}

// Statistics for all vtables
void show_vtable_statistics() {
    if (vtbl_t_list.empty()) {
        msg("[CodeXplorer] No vtables to analyze\n");
        return;
    }
    
    asize_t total_methods = 0;
    int pure_virtual_count = 0;
    asize_t max_methods = 0;
    qstring largest_class;
    std::map<qstring, int> module_count;
    
    for (const auto& vtbl : vtbl_t_list) {
        total_methods += vtbl.methods;
        
        if (vtbl.methods > max_methods) {
            max_methods = vtbl.methods;
            largest_class = vtbl.vtbl_name;
        }
        
        // Count pure virtuals
        ea_t method_ea = vtbl.ea_begin;
        for (asize_t i = 0; i < vtbl.methods; i++) {
            if (getEa(method_ea) == 0) {
                pure_virtual_count++;
            }
            method_ea += EA_SIZE;
        }
        
        // Count by module
        qstring seg_name;
        if (segment_t* seg = getseg(vtbl.ea_begin)) {
            get_segm_name(&seg_name, seg);
            module_count[seg_name]++;
        }
    }
    
    msg("\n=============== VTable Statistics ===============\n");
    msg("Total VTables: %d\n", (int)vtbl_t_list.size());
    msg("Total Methods: %d\n", (int)total_methods);
    msg("Average Methods per VTable: %.2f\n", 
        (double)total_methods / vtbl_t_list.size());
    msg("Pure Virtual Methods: %d\n", pure_virtual_count);
    msg("Largest Class: %s (%d methods)\n", 
        largest_class.c_str(), (int)max_methods);
    
    msg("\nVTables by Segment:\n");
    for (const auto& pair : module_count) {
        msg("  %s: %d\n", pair.first.c_str(), pair.second);
    }
    msg("=================================================\n\n");
}