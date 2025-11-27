/*
    Modern Object Explorer using IDA SDK 9.2 chooser_t
    Provides sortable, searchable vtable browser with enhanced UI
*/

#ifndef MODERN_OBJECT_EXPLORER_H
#define MODERN_OBJECT_EXPLORER_H

#include "Common.h"
#include "ObjectExplorer.h"
#include <kernwin.hpp>

// Forward declaration of functions from ObjectExplorer
extern tid_t create_vtbl_struct(const ea_t vtbl_addr, const ea_t vtbl_addr_end, const qstring& vtbl_name, uval_t idx, unsigned int* vtbl_len);

// Modern chooser-based Object Explorer
class ModernObjectExplorer : public chooser_t {
public:
    // Column indices
    enum {
        COL_CLASS_NAME = 0,
        COL_ADDRESS,
        COL_METHODS,
        COL_XREFS,
        COL_SEGMENT,
        COL_RTTI,
        COL_TYPE_INFO,
        COL_END
    };

    // Vtable data cache
    struct vtable_entry_t {
        VTBL_info_t info;
        size_t xref_count;
        qstring segment_name;
        bool has_rtti;
        size_t total_size;
        ea_t rtti_address;
        qstring rtti_type_name;     // Raw RTTI type name
        qstring demangled_type;     // Demangled type name
        qstring clean_class_name;   // Clean class name extracted
    };

private:
    
    qvector<vtable_entry_t> entries;
    qstring filter_text;
    bool show_only_with_rtti;
    bool show_only_with_xrefs;
    size_t min_methods_filter;
    int current_sort_column;
    
    // Build cache from global vtable list
    void build_entries();
    
    // Apply current filters
    void apply_filters();
    
    // Get entry at row
    const vtable_entry_t* get_entry(size_t n) const;
    
public:
    ModernObjectExplorer();
    virtual ~ModernObjectExplorer() = default;
    
    // chooser_t overrides
    virtual bool idaapi init() override;
    virtual const void *get_obj_id(size_t *len) const override;
    virtual size_t idaapi get_count() const override;
    virtual void idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
    virtual cbret_t idaapi ins(ssize_t n) override;
    virtual cbret_t idaapi del(size_t n) override;
    virtual cbret_t idaapi edit(size_t n) override;
    virtual cbret_t idaapi enter(size_t n) override;
    virtual cbret_t idaapi refresh(ssize_t n) override;
    
    // Sorting support - not available in IDA SDK 9.2 chooser_t
    // We'll implement custom sorting through refresh
    
    // Quick filter support - simplified for SDK compatibility
    
    // Context menu support
    virtual void idaapi closed() override;
    
    // Quick filter
    void set_filter(const qstring& text);
    void set_min_methods(size_t min_methods);
    void toggle_rtti_filter();
    void toggle_xref_filter();
    
    // Actions
    void show_vtable_details(size_t n);
    void create_vtable_struct(size_t n);
    void show_xrefs(size_t n);
    void jump_to_vtable(size_t n);
    void export_selection(const sizevec_t& selection);
    void show_inheritance_graph(size_t n);
    void decompile_methods(size_t n);
    void rename_class(size_t n);
    void show_statistics();
    void get_selected_items(sizevec_t* out) const;
    size_t get_cursel() const;
    
    // Show the chooser window
    static void show();
    
    // Refresh data
    void refresh_data();
};

// Quick filter widget for the chooser
class VTableFilterWidget : public action_handler_t {
private:
    ModernObjectExplorer* explorer;
    
public:
    VTableFilterWidget(ModernObjectExplorer* exp) : explorer(exp) {}
    
    virtual int idaapi activate(action_activation_ctx_t* ctx) override;
    virtual action_state_t idaapi update(action_update_ctx_t* ctx) override;
};

// Export widget for selected vtables
class VTableExportWidget {
public:
    enum ExportFormat {
        FORMAT_CSV,
        FORMAT_JSON,
        FORMAT_CPP_HEADER,
        FORMAT_IDC_SCRIPT
    };
    
    static bool export_vtables(const qvector<ModernObjectExplorer::vtable_entry_t>& entries, 
                              ExportFormat format, 
                              const char* filename);
};

// Statistics widget
class VTableStatsWidget {
public:
    struct stats_t {
        size_t total_vtables;
        size_t total_methods;
        size_t pure_virtual_count;
        size_t vtables_with_rtti;
        size_t vtables_with_xrefs;
        qstring largest_class;
        size_t largest_method_count;
        std::map<qstring, size_t> segment_distribution;
    };
    
    static stats_t calculate_stats(const qvector<ModernObjectExplorer::vtable_entry_t>& entries);
    static void show_stats_dialog(const stats_t& stats);
};

// Graph visualization widget
class VTableGraphWidget {
public:
    static void show_inheritance_graph(const ModernObjectExplorer::vtable_entry_t& entry);
    static void show_xref_graph(const ModernObjectExplorer::vtable_entry_t& entry);
    static void show_call_graph(const ModernObjectExplorer::vtable_entry_t& entry);
};

// Global instance management
extern ModernObjectExplorer* g_modern_explorer;

// Initialize modern UI (call from plugin init)
void init_modern_object_explorer();

// Cleanup (call from plugin term)
void term_modern_object_explorer();

#endif // MODERN_OBJECT_EXPLORER_H