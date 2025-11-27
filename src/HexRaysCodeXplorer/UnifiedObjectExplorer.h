/*
    Unified Object Explorer - Comprehensive VTable Browser
    Combines hierarchical tree view with modern table functionality
    
    Features:
    - Tree-style hierarchical organization (by namespace, segment, inheritance)
    - Sortable columns with detailed information
    - Advanced RTTI parsing and display
    - Method caching and cross-reference analysis
    - Inheritance detection and visualization
    - Comprehensive search and filtering
    - Export capabilities (JSON, CSV, C++ headers)
    - Modern UI with context menus and keyboard shortcuts
*/

#ifndef UNIFIED_OBJECT_EXPLORER_H
#define UNIFIED_OBJECT_EXPLORER_H

#include "Common.h"
#include "ObjectExplorer.h"
#include "CompilerRTTIParser.h"
#include <kernwin.hpp>
#include <dirtree.hpp>
#include <xref.hpp>
#include <funcs.hpp>
#include <regex>
#include <map>
#include <set>

// Forward declarations
class UnifiedObjectExplorer;
class UnifiedDataManager;
class UnifiedTreeBuilder;
class UnifiedFilterEngine;

//-------------------------------------------------------------------------
// Enhanced Data Structures
//-------------------------------------------------------------------------

// Comprehensive method information
struct unified_method_info_t {
    ea_t address;
    ea_t vtbl_entry_ea;
    qstring name;
    qstring demangled_name;
    qstring clean_name;           // Human-readable name
    size_t method_index;
    
    // Method properties
    bool is_pure_virtual;
    bool is_destructor;
    bool is_constructor;
    bool is_virtual;
    bool is_overridden;
    bool is_thunk;
    bool is_inline;
    
    // Cross-reference analysis
    size_t xref_count;
    qvector<ea_t> callers;
    qvector<ea_t> callees;
    
    // Inheritance tracking
    ea_t original_vtable;         // Where method was first defined
    qstring original_class;
    ea_t overridden_from;         // Which vtable this overrides from
    qvector<ea_t> overrides_in;   // Which vtables override this method
    
    // Analysis metadata
    time_t cached_at;
    bool needs_refresh;
};

// Enhanced RTTI information
struct unified_rtti_info_t {
    qstring class_name;
    qstring mangled_name;
    qstring type_string;
    qstring compiler_name;
    RTTIInfo::CompilerType compiler;
    
    struct base_class_info_t {
        qstring name;
        qstring mangled_name;
        bool is_virtual;
        bool is_public;
        bool is_protected;
        ssize_t offset;
        ea_t vtable_ea;
        int inheritance_depth;
    };
    
    qvector<base_class_info_t> base_classes;
    qvector<qstring> namespaces;
    qvector<qstring> template_params;
    
    // Class properties
    bool has_virtual_destructor;
    bool is_abstract;
    bool is_polymorphic;
    bool is_template;
    bool is_final;
    size_t object_size;
    size_t vtable_size;
    
    // Compiler-specific
    ea_t type_info_ea;
    ea_t vtable_ea;
    qstring hierarchy_string;
    qstring full_signature;
};

// Comprehensive vtable entry
struct unified_vtable_entry_t {
    // Basic vtable info
    VTBL_info_t vtbl_info;
    bool has_vtbl_info;
    
    // Location information
    qstring segment_name;
    ea_t segment_start;
    ea_t segment_end;
    
    // RTTI information
    bool has_rtti;
    unified_rtti_info_t rtti;
    
    // Cross-references
    size_t xref_count;
    size_t direct_xrefs;         // Direct references to vtable
    size_t indirect_xrefs;       // References through methods
    qvector<ea_t> xref_locations;
    
    // Methods analysis
    qvector<unified_method_info_t> methods;
    size_t pure_virtual_count;
    size_t overridden_methods;
    size_t unique_methods;
    
    // Inheritance relationships
    qvector<ea_t> base_vtables;
    qvector<ea_t> derived_vtables;
    float max_similarity;        // Highest similarity to any other vtable
    ea_t most_similar_vtable;
    
    // Organization
    qstring namespace_path;
    qstring class_hierarchy;
    int inheritance_depth;
    
    // UI state
    bool is_expanded;
    bool is_filtered;
    uint32 display_color;
    int display_icon;
    qstring tooltip_text;
    
    // Statistics
    size_t total_size;
    time_t last_analyzed;
    bool needs_refresh;
};

//-------------------------------------------------------------------------
// Data Management and Analysis
//-------------------------------------------------------------------------

class UnifiedDataManager {
public:
    enum organization_mode_t {
        ORG_FLAT,              // Simple flat list
        ORG_BY_SEGMENT,        // Organized by memory segment
        ORG_BY_NAMESPACE,      // Organized by C++ namespace
        ORG_BY_INHERITANCE,    // Organized by inheritance hierarchy
        ORG_BY_COMPILER,       // Organized by compiler type
        ORG_BY_SIZE,           // Organized by vtable size
        ORG_ALPHABETICAL       // Alphabetical by class name
    };
    
    enum analysis_level_t {
        ANALYSIS_BASIC,        // Basic vtable parsing
        ANALYSIS_RTTI,         // Include RTTI analysis
        ANALYSIS_INHERITANCE,  // Include inheritance detection
        ANALYSIS_FULL          // Full analysis with cross-references
    };

private:
    qvector<unified_vtable_entry_t> entries;
    std::map<ea_t, size_t> vtable_to_index;
    std::map<qstring, qvector<size_t>> namespace_groups;
    std::map<qstring, qvector<size_t>> segment_groups;
    std::map<int, qvector<size_t>> depth_groups;
    
    // Analysis components
    organization_mode_t current_organization;
    analysis_level_t analysis_level;
    
    // Cache management
    time_t last_full_analysis;
    bool needs_rebuild;

public:
    UnifiedDataManager();
    ~UnifiedDataManager();
    
    // Data building and analysis
    void build_from_vtables(analysis_level_t level = ANALYSIS_FULL);
    void refresh_data();
    void refresh_entry(size_t index);
    void clear_cache();
    
    // Organization
    void set_organization(organization_mode_t mode);
    organization_mode_t get_organization() const { return current_organization; }
    void rebuild_organization();
    
    // Access methods
    size_t get_count() const { return entries.size(); }
    const unified_vtable_entry_t* get_entry(size_t index) const;
    unified_vtable_entry_t* get_entry_mutable(size_t index);
    size_t find_entry_by_vtable(ea_t vtable_ea) const;
    
    // Analysis methods
    void analyze_inheritance_relationships();
    void analyze_method_overrides();
    void calculate_similarities();
    void update_cross_references();
    
    // Helper methods for analysis
    void analyze_rtti_info(unified_vtable_entry_t& entry);
    void analyze_methods(unified_vtable_entry_t& entry);
    void analyze_method_properties(unified_method_info_t& method);
    void analyze_method_xrefs(unified_method_info_t& method);
    void update_groupings(size_t index);
    int calculate_inheritance_depth(const unified_vtable_entry_t& entry);
    
    // Organization helpers
    const std::map<qstring, qvector<size_t>>& get_namespace_groups() const { return namespace_groups; }
    const std::map<qstring, qvector<size_t>>& get_segment_groups() const { return segment_groups; }
    qvector<size_t> get_entries_by_depth(int depth) const;
    qvector<size_t> get_top_level_classes() const;
    
    // Statistics
    struct statistics_t {
        size_t total_vtables;
        size_t total_methods;
        size_t pure_virtual_methods;
        size_t vtables_with_rtti;
        size_t vtables_with_inheritance;
        size_t abstract_classes;
        size_t template_classes;
        std::map<RTTIInfo::CompilerType, size_t> compiler_distribution;
        std::map<qstring, size_t> segment_distribution;
        std::map<int, size_t> inheritance_depth_distribution;
        qstring largest_class;
        size_t max_methods;
        qstring most_complex_inheritance;
        size_t max_inheritance_depth;
    };
    
    statistics_t get_statistics() const;
};

//-------------------------------------------------------------------------
// Advanced Filtering and Search
//-------------------------------------------------------------------------

class UnifiedFilterEngine {
public:
    enum filter_type_t {
        FILTER_NONE = 0,
        FILTER_CLASS_NAME = 1,
        FILTER_METHOD_NAME = 2,
        FILTER_NAMESPACE = 4,
        FILTER_COMPILER = 8,
        FILTER_HAS_RTTI = 16,
        FILTER_HAS_INHERITANCE = 32,
        FILTER_IS_ABSTRACT = 64,
        FILTER_IS_TEMPLATE = 128,
        FILTER_HAS_XREFS = 256,
        FILTER_MIN_METHODS = 512,
        FILTER_MAX_METHODS = 1024,
        FILTER_SEGMENT = 2048,
        FILTER_SIMILARITY = 4096
    };
    
    enum search_mode_t {
        SEARCH_SIMPLE,         // Simple text matching
        SEARCH_REGEXP,         // Regular expression
        SEARCH_FUZZY,          // Fuzzy matching with scoring
        SEARCH_SEMANTIC        // Semantic search based on properties
    };
    
    struct filter_criteria_t {
        uint32 active_filters;
        qstring class_name_pattern;
        qstring method_name_pattern;
        qstring namespace_pattern;
        RTTIInfo::CompilerType compiler_filter;
        qstring segment_filter;
        size_t min_methods;
        size_t max_methods;
        float min_similarity;
        bool show_abstract_only;
        bool show_template_only;
        bool show_rtti_only;
        bool show_inheritance_only;
        
        filter_criteria_t() : active_filters(FILTER_NONE), compiler_filter(RTTIInfo::COMPILER_UNKNOWN),
                              min_methods(0), max_methods(SIZE_MAX), min_similarity(0.0f),
                              show_abstract_only(false), show_template_only(false),
                              show_rtti_only(false), show_inheritance_only(false) {}
    };
    
    struct search_result_t {
        size_t entry_index;
        qstring matched_text;
        float relevance_score;
        qstring match_context;
    };

private:
    UnifiedDataManager* data_manager;
    filter_criteria_t current_criteria;
    qvector<size_t> filtered_indices;
    qvector<search_result_t> search_results;
    std::regex current_regex;
    bool filter_active;

public:
    UnifiedFilterEngine(UnifiedDataManager* dm);
    
    // Filter management
    void set_filter_criteria(const filter_criteria_t& criteria);
    const filter_criteria_t& get_filter_criteria() const { return current_criteria; }
    void clear_filters();
    bool is_filter_active() const { return filter_active; }
    
    // Apply filters
    void apply_filters();
    const qvector<size_t>& get_filtered_indices() const { return filtered_indices; }
    bool is_entry_visible(size_t index) const;
    
    // Search functionality
    qvector<search_result_t> search(const qstring& query, search_mode_t mode = SEARCH_SIMPLE);
    void clear_search();
    const qvector<search_result_t>& get_search_results() const { return search_results; }
    
    // Quick filters
    void show_only_abstract_classes();
    void show_only_template_classes();
    void show_only_with_rtti();
    void show_only_with_inheritance();
    void show_by_compiler(RTTIInfo::CompilerType compiler);
    void show_by_segment(const qstring& segment);
    void show_similar_to(size_t reference_index, float min_similarity);
    
private:
    bool matches_criteria(size_t index, const filter_criteria_t& criteria) const;
    float calculate_fuzzy_score(const qstring& text, const qstring& pattern) const;
    float calculate_semantic_score(size_t index, const qstring& query) const;
};

//-------------------------------------------------------------------------
// Tree Building and Hierarchy Management
//-------------------------------------------------------------------------

class UnifiedTreeBuilder {
public:
    enum tree_node_type_t {
        NODE_ROOT,
        NODE_FOLDER,
        NODE_VTABLE,
        NODE_METHOD,
        NODE_RTTI_INFO,
        NODE_INHERITANCE,
        NODE_XREF_INFO,
        NODE_STATS
    };
    
    struct tree_node_t {
        tree_node_type_t type;
        qstring name;
        qstring display_name;
        qstring tooltip;
        int icon;
        uint32 color;
        
        // Data references
        size_t vtable_index;        // Index into data manager
        size_t method_index;        // Method index within vtable
        ea_t address;
        
        // Tree structure
        qvector<size_t> children;
        size_t parent;
        int depth;
        bool is_expanded;
        bool is_visible;
        
        tree_node_t() : type(NODE_ROOT), icon(0), color(0), vtable_index(SIZE_MAX),
                       method_index(SIZE_MAX), address(BADADDR), parent(SIZE_MAX),
                       depth(0), is_expanded(false), is_visible(true) {}
    };

private:
    UnifiedDataManager* data_manager;
    UnifiedFilterEngine* filter_engine;
    qvector<tree_node_t> nodes;
    std::map<qstring, size_t> path_to_node;
    size_t root_node;
    UnifiedDataManager::organization_mode_t current_mode;

public:
    UnifiedTreeBuilder(UnifiedDataManager* dm, UnifiedFilterEngine* fe);
    
    // Tree building
    void rebuild_tree(UnifiedDataManager::organization_mode_t mode);
    void refresh_tree();
    void expand_node(size_t node_index);
    void collapse_node(size_t node_index);
    void expand_all();
    void collapse_all();
    
    // Node access
    size_t get_node_count() const { return nodes.size(); }
    const tree_node_t* get_node(size_t index) const;
    size_t get_root_node() const { return root_node; }
    qvector<size_t> get_visible_nodes() const;
    qvector<size_t> get_top_level_nodes() const;
    
    // Tree navigation
    size_t find_node_by_vtable(ea_t vtable_ea) const;
    size_t find_parent_vtable_node(size_t node_index) const;
    qvector<size_t> get_node_path(size_t node_index) const;
    
private:
    // Tree construction helpers
    void build_flat_tree();
    void build_segment_tree();
    void build_namespace_tree();
    void build_inheritance_tree();
    void build_compiler_tree();
    
    size_t create_folder_node(const qstring& name, size_t parent = SIZE_MAX);
    size_t create_vtable_node(size_t vtable_index, size_t parent = SIZE_MAX);
    size_t create_method_node(size_t vtable_index, size_t method_index, size_t parent);
    size_t create_rtti_node(size_t vtable_index, size_t parent);
    size_t create_inheritance_node(size_t vtable_index, size_t parent);
    
    void update_node_visibility();
    void calculate_node_colors();
    void assign_node_icons();
};

//-------------------------------------------------------------------------
// Main Unified Explorer Class
//-------------------------------------------------------------------------

class UnifiedObjectExplorer : public chooser_t {
public:
    // Column definitions
    enum {
        COL_NAME = 0,           // Name with tree indentation
        COL_TYPE,               // Type (VTable/Method/Folder)
        COL_ADDRESS,            // Memory address
        COL_METHODS,            // Method count / index
        COL_XREFS,              // Cross-references count
        COL_RTTI,               // RTTI information
        COL_INHERITANCE,        // Inheritance relationships
        COL_SEGMENT,            // Memory segment
        COL_COMPILER,           // Compiler type
        COL_SIZE,               // Size information
        COL_END
    };
    
    enum view_mode_t {
        VIEW_TREE_HIERARCHY,    // Tree view with hierarchy
        VIEW_TABLE_SORTABLE,    // Sortable table view
        VIEW_HYBRID            // Combination of both
    };

private:
    // Core components
    UnifiedDataManager* data_manager;
    UnifiedFilterEngine* filter_engine;
    UnifiedTreeBuilder* tree_builder;
    
    // View state
    view_mode_t current_view_mode;
    int sort_column;
    bool sort_ascending;
    qvector<size_t> display_indices;     // What's currently displayed
    
    // UI state
    qstring current_search;
    bool search_active;
    size_t selected_item;
    qvector<size_t> multi_selection;
    
    // Actions and context menu
    qvector<action_desc_t> context_actions;

public:
    UnifiedObjectExplorer();
    virtual ~UnifiedObjectExplorer();
    
    // chooser_t overrides
    virtual bool idaapi init() override;
    virtual const void *get_obj_id(size_t *len) const override;
    virtual size_t idaapi get_count() const override;
    virtual void idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
    
    // Navigation and interaction
    virtual cbret_t idaapi enter(size_t n) override;
    virtual cbret_t idaapi refresh(ssize_t n) override;
    virtual void idaapi closed() override;
    
    // View mode management
    void set_view_mode(view_mode_t mode);
    view_mode_t get_view_mode() const { return current_view_mode; }
    
    // Tree operations
    void expand_item(size_t n);
    void collapse_item(size_t n);
    void expand_all();
    void collapse_all();
    void toggle_expansion(size_t n);
    
    // Sorting and organization
    void sort_by_column(int column, bool ascending = true);
    void set_organization_mode(UnifiedDataManager::organization_mode_t mode);
    
    // Search and filtering
    void set_search_query(const qstring& query);
    void clear_search();
    void set_filter_criteria(const UnifiedFilterEngine::filter_criteria_t& criteria);
    void clear_filters();
    void apply_quick_filter(const qstring& filter_name);
    
    // Actions
    void show_vtable_details(size_t n);
    void show_method_details(size_t vtable_index, size_t method_index);
    void show_inheritance_graph(size_t n);
    void show_cross_references(size_t n);
    void show_similar_vtables(size_t n);
    void export_selection(const qvector<size_t>& selection);
    void create_vtable_struct(size_t n);
    void decompile_methods(size_t n);
    void rename_class(size_t n);
    void show_statistics();
    
    // Selection management
    void get_selection(qvector<size_t>* out) const;
    size_t get_current_selection() const { return selected_item; }
    void set_selection(size_t n);
    
    // Utility
    void refresh_data();
    void rebuild_display();
    void jump_to_address(ea_t address);
    void focus_on_vtable(ea_t vtable_ea);
    
    // Show the explorer
    static void show();

private:
    // Internal helpers
    void build_display_list();
    void update_display_list();
    qstring format_tree_name(size_t node_index, int depth) const;
    void register_context_actions();
    void unregister_context_actions();
    const unified_vtable_entry_t* get_vtable_entry(size_t n) const;
    const UnifiedTreeBuilder::tree_node_t* get_tree_node(size_t n) const;
};

//-------------------------------------------------------------------------
// Export and Utility Classes
//-------------------------------------------------------------------------

class UnifiedExporter {
public:
    enum export_format_t {
        FORMAT_CSV,
        FORMAT_JSON,
        FORMAT_XML,
        FORMAT_CPP_HEADER,
        FORMAT_IDC_SCRIPT,
        FORMAT_GRAPHML
    };
    
    struct export_options_t {
        bool include_methods;
        bool include_rtti;
        bool include_inheritance;
        bool include_xrefs;
        bool include_addresses;
        bool include_statistics;
        qstring filter_namespace;
        qstring filter_segment;
    };
    
    static bool export_data(const UnifiedDataManager& data_manager,
                          const qvector<size_t>& indices,
                          export_format_t format,
                          const qstring& filename,
                          const export_options_t& options);

private:
    static bool export_csv(const UnifiedDataManager& data_manager,
                          const qvector<size_t>& indices,
                          const qstring& filename,
                          const export_options_t& options);
    
    static bool export_json(const UnifiedDataManager& data_manager,
                           const qvector<size_t>& indices,
                           const qstring& filename,
                           const export_options_t& options);
    
    static bool export_cpp_header(const UnifiedDataManager& data_manager,
                                 const qvector<size_t>& indices,
                                 const qstring& filename,
                                 const export_options_t& options);
};

class UnifiedStatistics {
public:
    static void show_statistics_dialog(const UnifiedDataManager::statistics_t& stats);
    static void show_inheritance_graph(const UnifiedDataManager& data_manager, size_t entry_index);
    static void show_similarity_matrix(const UnifiedDataManager& data_manager);
    static void show_cross_reference_graph(const unified_vtable_entry_t& entry);
};

//-------------------------------------------------------------------------
// Global Instance and Functions
//-------------------------------------------------------------------------

extern UnifiedObjectExplorer* g_unified_explorer;

// Initialize/terminate
void init_unified_object_explorer();
void term_unified_object_explorer();

// Utility functions
qstring format_inheritance_chain(const unified_rtti_info_t& rtti);
qstring format_method_signature(const unified_method_info_t& method);
qstring format_compiler_info(RTTIInfo::CompilerType compiler);
uint32 calculate_display_color(const unified_vtable_entry_t& entry);
int get_appropriate_icon(const UnifiedTreeBuilder::tree_node_t& node);

#endif // UNIFIED_OBJECT_EXPLORER_H
