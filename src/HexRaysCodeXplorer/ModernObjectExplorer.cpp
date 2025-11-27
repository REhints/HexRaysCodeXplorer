/*
    Modern Object Explorer Implementation
    Using IDA SDK 9.2 chooser_t for enhanced UI
*/

#include "Common.h"
#include "ModernObjectExplorer.h"
#include "ObjectExplorer.h"
#include "Utility.h"
#include <kernwin.hpp>
#include <lines.hpp>
#include <algorithm>

// External vtable lists from ObjectExplorer
extern qvector<VTBL_info_t> vtbl_t_list;
extern qvector<qstring> vtbl_list;

// Global instance
ModernObjectExplorer* g_modern_explorer = nullptr;

//--------------------------------------------------------------------------
// Constructor
//--------------------------------------------------------------------------
// Static column headers
static const char *const vtable_headers[] = {
    "Primary Class",   // The main class name
    "Address",
    "Methods",
    "XRefs",
    "Segment",
    "RTTI",
    "Inheritance"      // Shows inheritance hierarchy
};

// Static column widths with format flags
static const int vtable_widths[] = {
    25,              // Primary Class - shorter since it's just one name
    16 | CHCOL_HEX,  // Address - hex format
    8 | CHCOL_DEC,   // Methods - decimal format
    8 | CHCOL_DEC,   // XRefs - decimal format
    12,              // Segment
    6,               // RTTI (Yes/No)
    50               // Inheritance - wider to show hierarchy
};

ModernObjectExplorer::ModernObjectExplorer() 
    : chooser_t(CH_KEEP | CH_RESTORE | CH_CAN_REFRESH | 
                CH_MULTI |      // Enable multi-selection
                CH_ATTRS,       // Enable custom attributes for colors
                COL_END,
                vtable_widths,
                vtable_headers,
                "VTable Explorer"),
      show_only_with_rtti(false),
      show_only_with_xrefs(false),
      min_methods_filter(0),
      current_sort_column(COL_CLASS_NAME)
{
    msg("[VTable Explorer] Constructor called\n");
    msg("[VTable Explorer] Flags: 0x%x\n", CH_KEEP | CH_RESTORE | CH_CAN_REFRESH);
    msg("[VTable Explorer] Columns: %d\n", COL_END);
    
    // Set popup names for better debugging
    popup_names[0] = "VTable Explorer Popup 1";
    popup_names[1] = "VTable Explorer Popup 2";
    
    // Don't build entries here - wait for init()
    msg("[VTable Explorer] Constructor complete (data will be loaded in init())\n");
}

//--------------------------------------------------------------------------
// Initialize chooser data
//--------------------------------------------------------------------------
bool idaapi ModernObjectExplorer::init() {
    msg("[VTable Explorer] init() called\n");
    
    // Build initial data
    build_entries();
    
    msg("[VTable Explorer] init() complete, %d entries loaded\n", (int)entries.size());
    return true;
}

//--------------------------------------------------------------------------
// Get unique object ID
//--------------------------------------------------------------------------
const void *ModernObjectExplorer::get_obj_id(size_t *len) const {
    static const char chooser_id[] = "VTableExplorer";
    *len = sizeof(chooser_id);
    return chooser_id;
}

//--------------------------------------------------------------------------
// Build cache from global vtable list
//--------------------------------------------------------------------------
void ModernObjectExplorer::build_entries() {
    entries.clear();
    
    msg("[VTable Explorer] Building entries from %d vtables\n", (int)vtbl_t_list.size());
    
    for (const auto& vtbl : vtbl_t_list) {
        vtable_entry_t entry;
        entry.info = vtbl;
        
        // Count xrefs
        entry.xref_count = 0;
        for (auto addr = get_first_dref_to(vtbl.ea_begin); 
             addr != BADADDR; 
             addr = get_next_dref_to(vtbl.ea_begin, addr)) {
            entry.xref_count++;
        }
        
        // Get segment name
        if (segment_t* seg = getseg(vtbl.ea_begin)) {
            get_segm_name(&entry.segment_name, seg);
        } else {
            entry.segment_name = "unknown";
        }
        
        // Check for RTTI (Itanium ABI)
        entry.has_rtti = false;
        entry.rtti_address = BADADDR;
        entry.rtti_type_name.clear();
        entry.demangled_type.clear();
        entry.clean_class_name.clear();
        
        // Debug output
        msg("[VTable Explorer] Processing vtable '%s' at 0x%llx\n", 
            vtbl.vtbl_name.c_str(), (unsigned long long)vtbl.ea_begin);
        
        if (is_mapped(vtbl.ea_begin - EA_SIZE)) {
            ea_t rtti_ptr = getEa(vtbl.ea_begin - EA_SIZE);
            if (rtti_ptr != 0 && is_mapped(rtti_ptr)) {
                entry.has_rtti = true;
                entry.rtti_address = rtti_ptr;
                msg("[VTable Explorer]   RTTI found at 0x%llx\n", (unsigned long long)rtti_ptr);
                
                // Try to extract RTTI type name (Itanium ABI)
                // RTTI structure: offset_to_top, type_name_ptr, ...
                ea_t name_ptr_addr = rtti_ptr + EA_SIZE;  // Skip offset_to_top
                if (is_mapped(name_ptr_addr)) {
                    ea_t name_ptr = getEa(name_ptr_addr);
                    if (name_ptr && is_mapped(name_ptr)) {
                        // Read the type name string
                        qstring type_name;
                        if (get_strlit_contents(&type_name, name_ptr, 256, STRTYPE_C) > 0) {
                            entry.rtti_type_name = type_name;
                            msg("[VTable Explorer]   RTTI type name: %s\n", type_name.c_str());
                            
                            // Try to demangle if it's a mangled name
                            if (type_name.length() > 2 && type_name[0] == '_' && type_name[1] == 'Z') {
                                qstring demangled;
                                if (demangle_name(&demangled, type_name.c_str(), 0) > 0) {
                                    entry.demangled_type = demangled;
                                }
                            } else {
                                // Not mangled, just use as-is
                                entry.demangled_type = type_name;
                            }
                            
                            // Extract clean class name from RTTI type name
                            // Parse Itanium ABI format: [length][name][length][name]...
                            if (type_name.length() > 0) {
                                const char* str = type_name.c_str();
                                
                                // Parse the first class name (primary class)
                                size_t name_len = 0;
                                while (*str && isdigit(*str)) {
                                    name_len = name_len * 10 + (*str - '0');
                                    str++;
                                }
                                
                                if (name_len > 0 && name_len < type_name.length()) {
                                    entry.clean_class_name = qstring(str, name_len);
                                    msg("[VTable Explorer]   Extracted primary class: %s\n", 
                                        entry.clean_class_name.c_str());
                                }
                                
                                // For complex inheritance, also parse additional base classes
                                // We'll show these in a formatted way in Type Info column
                                qstring hierarchy;
                                const char* parse_ptr = type_name.c_str();
                                int class_count = 0;
                                
                                while (*parse_ptr && class_count < 5) { // Limit to first 5 classes
                                    // Skip any non-digit characters (templates, etc)
                                    while (*parse_ptr && !isdigit(*parse_ptr)) parse_ptr++;
                                    if (!*parse_ptr) break;
                                    
                                    // Read length
                                    size_t len = 0;
                                    while (*parse_ptr && isdigit(*parse_ptr)) {
                                        len = len * 10 + (*parse_ptr - '0');
                                        parse_ptr++;
                                    }
                                    
                                    if (len > 0 && (parse_ptr + len <= type_name.c_str() + type_name.length())) {
                                        if (class_count > 0) hierarchy += " : ";
                                        
                                        // Extract class name
                                        qstring class_name(parse_ptr, len);
                                        
                                        // Clean up template syntax for readability
                                        if (class_name.find("Container") != qstring::npos ||
                                            class_name.find("SortedContainer") != qstring::npos) {
                                            hierarchy += class_name;
                                        } else {
                                            hierarchy += class_name;
                                        }
                                        
                                        parse_ptr += len;
                                        class_count++;
                                    } else {
                                        break;
                                    }
                                }
                                
                                // Store formatted hierarchy for display
                                if (class_count > 1) {
                                    entry.demangled_type = hierarchy;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Calculate total size
        entry.total_size = vtbl.methods * EA_SIZE;
        
        entries.push_back(entry);
    }
    
    apply_filters();
}

//--------------------------------------------------------------------------
// Apply filters
//--------------------------------------------------------------------------
void ModernObjectExplorer::apply_filters() {
    // If we need to implement filtering, we would modify the entries vector here
    // For now, we'll keep all entries visible
}

//--------------------------------------------------------------------------
// Get entry at row
//--------------------------------------------------------------------------
const ModernObjectExplorer::vtable_entry_t* ModernObjectExplorer::get_entry(size_t n) const {
    if (n >= entries.size())
        return nullptr;
    return &entries[n];
}

//--------------------------------------------------------------------------
// Get row count
//--------------------------------------------------------------------------
size_t idaapi ModernObjectExplorer::get_count() const {
    return entries.size();
}

//--------------------------------------------------------------------------
// Get row data for display
//--------------------------------------------------------------------------
void idaapi ModernObjectExplorer::get_row(
    qstrvec_t *cols,
    int *icon,
    chooser_item_attrs_t *attrs,
    size_t n) const 
{
    // Debug output for first few rows
    if (n < 3) {
        msg("[VTable Explorer] get_row called for entry %d\n", (int)n);
    }
    
    const vtable_entry_t* entry = get_entry(n);
    if (!entry) {
        msg("[VTable Explorer] ERROR: No entry at index %d\n", (int)n);
        cols->clear();
        return;
    }
    
    // Clear and resize the columns vector
    cols->clear();
    cols->resize(COL_END);
    
    // Class Name - prefer clean RTTI name over vtable symbol name
    qstring display_name;
    if (!entry->clean_class_name.empty()) {
        display_name = entry->clean_class_name;
    } else if (!entry->info.vtbl_name.empty()) {
        // Clean up vtable symbol name  
        display_name = entry->info.vtbl_name;
        // Remove common prefixes
        if (display_name.find("`vtable for'") == 0) {
            display_name.remove(0, strlen("`vtable for'"));
            // Remove trailing quote if present
            if (display_name.length() > 0 && display_name.last() == '\'') {
                display_name.remove_last();
            }
        }
    } else {
        display_name = "<unknown>";
    }
    (*cols)[COL_CLASS_NAME] = display_name;
    
    // Address
    qstring addr_str;
    addr_str.sprnt("0x%llX", (unsigned long long)entry->info.ea_begin);
    (*cols)[COL_ADDRESS] = addr_str;
    
    // Methods
    qstring methods_str;
    methods_str.sprnt("%d", (int)entry->info.methods);
    (*cols)[COL_METHODS] = methods_str;
    
    // XRefs
    qstring xrefs_str;
    xrefs_str.sprnt("%d", (int)entry->xref_count);
    (*cols)[COL_XREFS] = xrefs_str;
    
    // Segment
    (*cols)[COL_SEGMENT] = entry->segment_name;
    
    // RTTI
    (*cols)[COL_RTTI] = entry->has_rtti ? "Yes" : "No";
    
    // Type Info - show parsed hierarchy or raw RTTI
    qstring type_info;
    if (!entry->demangled_type.empty()) {
        // Show the parsed hierarchy if available
        type_info = entry->demangled_type;
        if (type_info.length() > 80) {
            type_info.resize(77);
            type_info += "...";
        }
    } else if (!entry->rtti_type_name.empty()) {
        // Fallback to showing a shortened version of raw RTTI
        // Try to make it more readable by showing just first few classes
        type_info = entry->rtti_type_name;
        if (type_info.length() > 60) {
            type_info.resize(57);
            type_info += "...";
        }
    } else {
        type_info = "-";
    }
    (*cols)[COL_TYPE_INFO] = type_info;
    
    // Debug output for first few rows to verify column data
    if (n < 3) {
        msg("[VTable Explorer] Row %d columns:\n", (int)n);
        for (size_t i = 0; i < cols->size(); i++) {
            msg("[VTable Explorer]   [%d]: %s\n", (int)i, (*cols)[i].c_str());
        }
    }
    
    // Set icon based on characteristics
    if (icon) {
        if (entry->info.methods == 0) {
            *icon = 93;  // Empty icon for vtables with no methods
        } else if (entry->has_rtti) {
            *icon = 95;  // Star icon for RTTI
        } else {
            *icon = 94;  // Normal icon
        }
    }
    
    // Enhanced color coding for better visual scanning
    if (attrs) {
        // Priority-based coloring
        if (entry->info.methods == 0) {
            attrs->color = 0x808080;  // Gray for empty/abstract vtables
        } else if (entry->info.methods > 50) {
            attrs->color = 0xFF6B6B;  // Red tint for very large vtables (complex classes)
            attrs->flags = CHITEM_BOLD;  // Make them bold
        } else if (entry->has_rtti && entry->xref_count > 10) {
            attrs->color = 0xFFD700;  // Gold for important classes (RTTI + heavily used)
            attrs->flags = CHITEM_BOLD;
        } else if (entry->has_rtti) {
            attrs->color = 0x90EE90;  // Light green for RTTI
        } else if (entry->xref_count > 5) {
            attrs->color = 0x87CEEB;  // Sky blue for frequently referenced
        } else if (entry->xref_count > 0) {
            attrs->color = 0xE0E0E0;  // Light gray for referenced
        } else {
            attrs->color = 0xA0A0A0;  // Darker gray for unreferenced
        }
    }
}

//--------------------------------------------------------------------------
// Handle insert (not used for vtables)
//--------------------------------------------------------------------------
chooser_t::cbret_t idaapi ModernObjectExplorer::ins(ssize_t n) {
    msg("[VTable Explorer] Cannot insert vtables manually\n");
    return NOTHING_CHANGED;
}

//--------------------------------------------------------------------------
// Handle delete
//--------------------------------------------------------------------------
chooser_t::cbret_t idaapi ModernObjectExplorer::del(size_t n) {
    msg("[VTable Explorer] Delete not implemented\n");
    return NOTHING_CHANGED;
}

//--------------------------------------------------------------------------
// Handle edit - rename vtable
//--------------------------------------------------------------------------
chooser_t::cbret_t idaapi ModernObjectExplorer::edit(size_t n) {
    const vtable_entry_t* entry = get_entry(n);
    if (!entry)
        return NOTHING_CHANGED;
    
    qstring new_name = entry->info.vtbl_name;
    if (ask_str(&new_name, HIST_IDENT, "Enter new name for vtable:")) {
        if (set_name(entry->info.ea_begin, new_name.c_str())) {
            // Update our cache
            entries[n].info.vtbl_name = new_name;
            return ALL_CHANGED;
        }
    }
    
    return NOTHING_CHANGED;
}

//--------------------------------------------------------------------------
// Handle double-click/enter - jump to vtable
//--------------------------------------------------------------------------
chooser_t::cbret_t idaapi ModernObjectExplorer::enter(size_t n) {
    jump_to_vtable(n);
    return NOTHING_CHANGED;
}

//--------------------------------------------------------------------------
// Handle refresh
//--------------------------------------------------------------------------
chooser_t::cbret_t idaapi ModernObjectExplorer::refresh(ssize_t n) {
    build_entries();
    return ALL_CHANGED;
}

//--------------------------------------------------------------------------
// Handle chooser closed
//--------------------------------------------------------------------------
void idaapi ModernObjectExplorer::closed() {
    msg("[VTable Explorer] Chooser window closed\n");
    // Clear the global pointer when window is closed
    if (g_modern_explorer == this) {
        g_modern_explorer = nullptr;
    }
}

//--------------------------------------------------------------------------
// Set filter text
//--------------------------------------------------------------------------
void ModernObjectExplorer::set_filter(const qstring& text) {
    filter_text = text;
    apply_filters();
}

//--------------------------------------------------------------------------
// Jump to vtable
//--------------------------------------------------------------------------
void ModernObjectExplorer::jump_to_vtable(size_t n) {
    const vtable_entry_t* entry = get_entry(n);
    if (entry) {
        jumpto(entry->info.ea_begin);
    }
}

//--------------------------------------------------------------------------
// Show vtable details
//--------------------------------------------------------------------------
void ModernObjectExplorer::show_vtable_details(size_t n) {
    const vtable_entry_t* entry = get_entry(n);
    if (!entry)
        return;
    
    msg("\n");
    msg("================== VTable Details ==================\n");
    msg("Symbol Name: %s\n", entry->info.vtbl_name.c_str());
    if (!entry->clean_class_name.empty()) {
        msg("Class Name (from RTTI): %s\n", entry->clean_class_name.c_str());
    }
    msg("Address Range: 0x%llX - 0x%llX\n", 
        (unsigned long long)entry->info.ea_begin,
        (unsigned long long)entry->info.ea_end);
    msg("Methods Count: %d\n", (int)entry->info.methods);
    msg("Cross References: %d\n", (int)entry->xref_count);
    msg("Segment: %s\n", entry->segment_name.c_str());
    msg("Has RTTI: %s\n", entry->has_rtti ? "Yes" : "No");
    if (entry->has_rtti) {
        msg("RTTI Address: 0x%llX\n", (unsigned long long)entry->rtti_address);
        if (!entry->rtti_type_name.empty()) {
            msg("RTTI Type Name (raw): %s\n", entry->rtti_type_name.c_str());
        }
        if (!entry->demangled_type.empty() && entry->demangled_type != entry->rtti_type_name) {
            msg("RTTI Type (demangled): %s\n", entry->demangled_type.c_str());
        }
    }
    msg("Total Size: 0x%X bytes\n", (unsigned int)entry->total_size);
    
    // List methods with details
    msg("\nVirtual Methods:\n");
    ea_t method_ea = entry->info.ea_begin;
    size_t display_limit = (entry->info.methods <= 20) ? entry->info.methods : 15;
    
    for (size_t i = 0; i < entry->info.methods && i < display_limit; i++) {
        ea_t func_ea = getEa(method_ea);
        qstring func_name;
        qstring func_details;
        
        if (func_ea == 0) {
            func_name = "__purecall";
            func_details = " [pure virtual]";
        } else {
            if (PH.id == PLFM_ARM) {
                func_ea &= ~1;  // Clear thumb bit
            }
            
            // Get function name
            get_func_name(&func_name, func_ea);
            if (func_name.empty()) {
                func_name.sprnt("sub_%llX", (unsigned long long)func_ea);
            } else {
                // Try to demangle the name for better readability
                qstring demangled;
                if (demangle_name(&demangled, func_name.c_str(), 0) > 0) {
                    func_details = " // ";
                    func_details += demangled;
                }
            }
            
            // Check if it's a thunk
            func_t* func = get_func(func_ea);
            if (func && (func->flags & FUNC_THUNK)) {
                func_details += " [thunk]";
            }
        }
        
        msg("  [%2d] 0x%llX: %s%s\n", 
            (int)i, 
            (unsigned long long)func_ea, 
            func_name.c_str(),
            func_details.c_str());
        method_ea += EA_SIZE;
    }
    
    if (entry->info.methods > display_limit) {
        msg("  ... and %d more methods\n", (int)(entry->info.methods - display_limit));
    }
    
    msg("====================================================\n\n");
}

//--------------------------------------------------------------------------
// Create vtable struct
//--------------------------------------------------------------------------
void ModernObjectExplorer::create_vtable_struct(size_t n) {
    const vtable_entry_t* entry = get_entry(n);
    if (!entry)
        return;
    
    tid_t id = create_vtbl_struct(
        entry->info.ea_begin,
        entry->info.ea_end,
        entry->info.vtbl_name,
        0,
        nullptr
    );
    
    if (id != BADNODE) {
        msg("[VTable Explorer] Created structure: %s\n", entry->info.vtbl_name.c_str());
    } else {
        msg("[VTable Explorer] Failed to create structure\n");
    }
}

//--------------------------------------------------------------------------
// Show xrefs window
//--------------------------------------------------------------------------
void ModernObjectExplorer::show_xrefs(size_t n) {
    const vtable_entry_t* entry = get_entry(n);
    if (!entry)
        return;
    
    // Build xref list
    qstrvec_t xref_list;
    eavec_t xref_addrs;
    
    for (auto addr = get_first_dref_to(entry->info.ea_begin); 
         addr != BADADDR; 
         addr = get_next_dref_to(entry->info.ea_begin, addr)) 
    {
        qstring line;
        qstring func_name;
        get_func_name(&func_name, addr);
        
        line.sprnt("0x%llX: %s", 
                  (unsigned long long)addr,
                  func_name.empty() ? "<unknown>" : func_name.c_str());
        
        xref_list.push_back(line);
        xref_addrs.push_back(addr);
    }
    
    if (xref_list.empty()) {
        msg("[VTable Explorer] No xrefs found for %s\n", entry->info.vtbl_name.c_str());
        return;
    }
    
    // For now, just print to output window
    msg("\nXRefs to %s:\n", entry->info.vtbl_name.c_str());
    for (size_t i = 0; i < xref_list.size(); i++) {
        msg("  %s\n", xref_list[i].c_str());
    }
    msg("\n");
}

//--------------------------------------------------------------------------
// Show the modern chooser window
//--------------------------------------------------------------------------
void ModernObjectExplorer::show() {
    msg("[VTable Explorer] show() called\n");
    
    // Check if we have vtables
    if (vtbl_t_list.empty()) {
        msg("[VTable Explorer] No virtual tables found. Run object analysis first.\n");
        return;
    }
    
    msg("[VTable Explorer] Found %d vtables to display\n", (int)vtbl_t_list.size());
    
    // Check if we already have an instance with an open window
    if (g_modern_explorer) {
        msg("[VTable Explorer] Existing instance found, trying to activate window\n");
        // Try to show the existing chooser again
        ssize_t result = g_modern_explorer->choose();
        if (result >= 0) {
            msg("[VTable Explorer] Existing window reactivated\n");
        } else {
            msg("[VTable Explorer] Could not reactivate, creating new instance\n");
            delete g_modern_explorer;
            g_modern_explorer = nullptr;
        }
        if (g_modern_explorer) {
            return;
        }
    }
    
    msg("[VTable Explorer] Creating new ModernObjectExplorer instance\n");
    g_modern_explorer = new ModernObjectExplorer();
    
    // The init() method will be called by choose(), but we can check if data will be available
    msg("[VTable Explorer] Global vtable list has %d entries\n", (int)vtbl_t_list.size());
    
    // Show the chooser 
    msg("[VTable Explorer] Calling choose() to display window\n");
    msg("[VTable Explorer] Note: init() will be called automatically by choose()\n");
    
    // Call choose() with default selection - init() will be called internally
    ssize_t result = g_modern_explorer->choose();
    msg("[VTable Explorer] choose() returned: %d\n", (int)result);
    
    if (result < 0) {
        msg("[VTable Explorer] Failed to open chooser window (result = %d)\n", (int)result);
        msg("[VTable Explorer] After choose(), data count: %d\n", (int)g_modern_explorer->get_count());
        
        // Debug - try to manually verify data after init
        if (g_modern_explorer->get_count() > 0) {
            msg("[VTable Explorer] Sample data for first entry:\n");
            qstrvec_t test_cols;
            int test_icon = 0;
            chooser_item_attrs_t test_attrs = {};
            g_modern_explorer->get_row(&test_cols, &test_icon, &test_attrs, 0);
            for (size_t i = 0; i < test_cols.size(); i++) {
                msg("[VTable Explorer]   Col[%d]: %s\n", (int)i, test_cols[i].c_str());
            }
        } else {
            msg("[VTable Explorer] ERROR: No data loaded even after choose()/init()\n");
            msg("[VTable Explorer] Manually calling init() for debugging...\n");
            if (g_modern_explorer->init()) {
                msg("[VTable Explorer] Manual init() succeeded, entries: %d\n", (int)g_modern_explorer->get_count());
            }
        }
        
        // Clean up on failure
        delete g_modern_explorer;
        g_modern_explorer = nullptr;
    } else {
        msg("[VTable Explorer] Chooser window opened successfully! Selection: %d\n", (int)result);
        // Don't delete on success - keep the chooser alive
    }
}

//--------------------------------------------------------------------------
// Refresh data
//--------------------------------------------------------------------------
void ModernObjectExplorer::refresh_data() {
    build_entries();
}

// NOTE: The following features are not directly supported in IDA SDK 9.2 chooser_t:
// - get_default_sort_col() 
// - sort()
// - get_item_index() with char* parameter
// - get_chooser_menu_cb()
//
// These would need to be implemented differently or through actions/hotkeys
// For now, we keep the basic functionality and improved visual display

//--------------------------------------------------------------------------
// Show statistics (similar to ImprovedObjectExplorer)
//--------------------------------------------------------------------------
void ModernObjectExplorer::show_statistics() {
    if (entries.empty()) {
        msg("[VTable Explorer] No vtables to analyze\n");
        return;
    }
    
    // Calculate comprehensive statistics
    size_t total_methods = 0;
    size_t pure_virtual_count = 0;
    size_t max_methods = 0;
    qstring largest_class;
    size_t vtables_with_rtti = 0;
    size_t vtables_with_xrefs = 0;
    std::map<qstring, size_t> segment_distribution;
    
    for (const auto& entry : entries) {
        total_methods += entry.info.methods;
        
        if (entry.info.methods > max_methods) {
            max_methods = entry.info.methods;
            largest_class = entry.clean_class_name.empty() ? entry.info.vtbl_name : entry.clean_class_name;
        }
        
        if (entry.has_rtti)
            vtables_with_rtti++;
        
        if (entry.xref_count > 0)
            vtables_with_xrefs++;
        
        // Count pure virtuals
        ea_t method_ea = entry.info.ea_begin;
        for (size_t i = 0; i < entry.info.methods; i++) {
            if (getEa(method_ea) == 0) {
                pure_virtual_count++;
            }
            method_ea += EA_SIZE;
        }
        
        // Segment distribution
        segment_distribution[entry.segment_name]++;
    }
    
    msg("\n");
    msg("============== VTable Statistics ==============\n");
    msg("Total VTables: %d\n", (int)entries.size());
    msg("Total Methods: %d\n", (int)total_methods);
    if (!entries.empty()) {
        msg("Average Methods per VTable: %.2f\n", 
            (double)total_methods / entries.size());
    }
    msg("Pure Virtual Methods: %d\n", (int)pure_virtual_count);
    msg("VTables with RTTI: %d (%.1f%%)\n", 
        (int)vtables_with_rtti,
        entries.empty() ? 0 : (100.0 * vtables_with_rtti / entries.size()));
    msg("VTables with XRefs: %d (%.1f%%)\n",
        (int)vtables_with_xrefs,
        entries.empty() ? 0 : (100.0 * vtables_with_xrefs / entries.size()));
    msg("Largest Class: %s (%d methods)\n",
        largest_class.c_str(),
        (int)max_methods);
    
    msg("\nDistribution by Segment:\n");
    for (const auto& pair : segment_distribution) {
        msg("  %s: %d vtables\n", pair.first.c_str(), (int)pair.second);
    }
    
    // Show RTTI type info analysis if available
    size_t with_type_names = 0;
    for (const auto& entry : entries) {
        if (!entry.rtti_type_name.empty())
            with_type_names++;
    }
    if (with_type_names > 0) {
        msg("\nRTTI Type Information:\n");
        msg("  VTables with type names: %d\n", (int)with_type_names);
        msg("  Type name extraction rate: %.1f%%\n", 
            100.0 * with_type_names / entries.size());
    }
    
    msg("===============================================\n\n");
}

//--------------------------------------------------------------------------
// Get selected items
//--------------------------------------------------------------------------
void ModernObjectExplorer::get_selected_items(sizevec_t* out) const {
    if (out) {
        // For now, just return empty - full implementation would track selection
        out->clear();
    }
}

//--------------------------------------------------------------------------
// Get current selection
//--------------------------------------------------------------------------
size_t ModernObjectExplorer::get_cursel() const {
    // This would normally be tracked by the chooser
    return 0;
}

//--------------------------------------------------------------------------
// Export selected vtables
//--------------------------------------------------------------------------
void ModernObjectExplorer::export_selection(const sizevec_t& selection) {
    if (selection.empty()) {
        msg("[VTable Explorer] No items selected for export\n");
        return;
    }
    
    // Build list of selected entries
    qvector<vtable_entry_t> selected;
    for (size_t idx : selection) {
        if (idx < entries.size()) {
            selected.push_back(entries[idx]);
        }
    }
    
    // Ask for filename
    char filename[QMAXPATH];
    const char* file = ask_file(false, "*.csv", filename, "Export VTables to CSV");
    if (!file) {
        return;
    }
    
    // Export to CSV
    FILE* f = qfopen(filename, "w");
    if (!f) {
        msg("[VTable Explorer] Failed to create file: %s\n", filename);
        return;
    }
    
    // Write header
    qfprintf(f, "Class Name,Address,Methods,XRefs,Segment,Has RTTI,Size\n");
    
    // Write data
    for (const auto& entry : selected) {
        qfprintf(f, "%s,0x%llX,%d,%d,%s,%s,0x%X\n",
                entry.info.vtbl_name.c_str(),
                (unsigned long long)entry.info.ea_begin,
                (int)entry.info.methods,
                (int)entry.xref_count,
                entry.segment_name.c_str(),
                entry.has_rtti ? "Yes" : "No",
                (unsigned int)entry.total_size);
    }
    
    qfclose(f);
    msg("[VTable Explorer] Exported %d vtables to %s\n", (int)selected.size(), filename);
}

//--------------------------------------------------------------------------
// Initialize modern object explorer
//--------------------------------------------------------------------------
void init_modern_object_explorer() {
    // Actions will be registered when needed
    // For now, we'll skip the context menu actions to avoid compilation issues
}

//--------------------------------------------------------------------------
// Cleanup modern object explorer
//--------------------------------------------------------------------------
void term_modern_object_explorer() {
    if (g_modern_explorer) {
        delete g_modern_explorer;
        g_modern_explorer = nullptr;
    }
}

//--------------------------------------------------------------------------
// Calculate statistics
//--------------------------------------------------------------------------
VTableStatsWidget::stats_t VTableStatsWidget::calculate_stats(
    const qvector<ModernObjectExplorer::vtable_entry_t>& entries) 
{
    stats_t stats = {};
    
    for (const auto& entry : entries) {
        stats.total_vtables++;
        stats.total_methods += entry.info.methods;
        
        if (entry.has_rtti)
            stats.vtables_with_rtti++;
        
        if (entry.xref_count > 0)
            stats.vtables_with_xrefs++;
        
        // Track largest class
        if (entry.info.methods > stats.largest_method_count) {
            stats.largest_method_count = entry.info.methods;
            stats.largest_class = entry.info.vtbl_name;
        }
        
        // Count pure virtual methods
        ea_t method_ea = entry.info.ea_begin;
        for (size_t i = 0; i < entry.info.methods; i++) {
            if (getEa(method_ea) == 0) {
                stats.pure_virtual_count++;
            }
            method_ea += EA_SIZE;
        }
        
        // Segment distribution
        stats.segment_distribution[entry.segment_name]++;
    }
    
    return stats;
}

//--------------------------------------------------------------------------
// Show statistics dialog
//--------------------------------------------------------------------------
void VTableStatsWidget::show_stats_dialog(const stats_t& stats) {
    msg("\n");
    msg("============== VTable Statistics ==============\n");
    msg("Total VTables: %d\n", (int)stats.total_vtables);
    msg("Total Methods: %d\n", (int)stats.total_methods);
    if (stats.total_vtables > 0) {
        msg("Average Methods per VTable: %.2f\n", 
            (double)stats.total_methods / stats.total_vtables);
    }
    msg("Pure Virtual Methods: %d\n", (int)stats.pure_virtual_count);
    msg("VTables with RTTI: %d (%.1f%%)\n", 
        (int)stats.vtables_with_rtti,
        stats.total_vtables > 0 ? (100.0 * stats.vtables_with_rtti / stats.total_vtables) : 0);
    msg("VTables with XRefs: %d (%.1f%%)\n",
        (int)stats.vtables_with_xrefs,
        stats.total_vtables > 0 ? (100.0 * stats.vtables_with_xrefs / stats.total_vtables) : 0);
    msg("Largest Class: %s (%d methods)\n",
        stats.largest_class.c_str(),
        (int)stats.largest_method_count);
    
    msg("\nDistribution by Segment:\n");
    for (const auto& pair : stats.segment_distribution) {
        msg("  %s: %d vtables\n", pair.first.c_str(), (int)pair.second);
    }
    msg("===============================================\n\n");
}