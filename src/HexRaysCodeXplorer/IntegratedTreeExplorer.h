/*
    Enhanced Integrated Tree VTable Explorer with advanced features:
    - Method caching system
    - Search/filter functionality  
    - Context menu actions
    - Cross-reference analysis
    - Advanced inheritance detection
    - Enhanced RTTI display
*/

#ifndef INTEGRATED_TREE_EXPLORER_H
#define INTEGRATED_TREE_EXPLORER_H

#include "Common.h"
#include "ObjectExplorer.h"
#include "CompilerRTTIParser.h"
#include <kernwin.hpp>
#include <dirtree.hpp>
#include <xref.hpp>
#include <funcs.hpp>
#include <regex>

// Forward declarations
class VTableSearcher;
class MethodCache;
class InheritanceAnalyzer;
class VTableHierarchySpec;
class IntegratedTreeExplorer;

// Method information with caching
struct method_info_t {
    ea_t address;
    ea_t vtbl_entry_ea;
    qstring name;
    qstring demangled_name;
    bool is_pure_virtual;
    bool is_destructor;
    bool is_constructor;
    bool is_virtual;
    bool is_overridden;
    bool is_thunk;
    size_t xref_count;
    qvector<ea_t> callers;
    qvector<ea_t> callees;
    
    // Inheritance info
    ea_t original_vtable;  // Where method was first defined
    qstring original_class;
    
    // Cache timestamp
    time_t cached_at;
};

// Enhanced RTTI display structure
struct enhanced_rtti_info_t {
    qstring class_name;
    qstring mangled_name;
    qstring type_string;
    qstring compiler_name;
    
    struct base_class_info_t {
        qstring name;
        qstring mangled_name;
        bool is_virtual;
        bool is_public;
        ssize_t offset;
        ea_t vtable_ea;  // If we can find it
    };
    
    qvector<base_class_info_t> base_classes;
    qvector<qstring> namespaces;
    
    // Additional info
    bool has_virtual_destructor;
    bool is_abstract;
    bool is_polymorphic;
    size_t object_size;
    
    // Compiler-specific info
    ea_t type_info_ea;
    ea_t vtable_ea;
    qstring hierarchy_string;  // Full inheritance hierarchy
};

// Method cache for performance
class MethodCache {
private:
    std::map<ea_t, method_info_t> cache;
    time_t cache_duration = 300;  // 5 minutes default
    
public:
    const method_info_t* get_method_info(ea_t method_ea);
    void cache_method(ea_t method_ea, const method_info_t& info);
    void clear_cache();
    void refresh_method(ea_t method_ea);
    bool is_cached(ea_t method_ea) const;
    
    // Batch operations
    void cache_vtable_methods(const VTBL_info_t& vtbl);
    void analyze_xrefs(ea_t method_ea, method_info_t& info);
};

// Advanced inheritance analyzer
class InheritanceAnalyzer {
public:
    struct vtable_layout_t {
        ea_t vtable_ea;
        qstring class_name;
        qvector<ea_t> method_addresses;
        qvector<size_t> method_indices;
        size_t unique_methods;
        size_t overridden_methods;
    };
    
    struct inheritance_relation_t {
        ea_t derived_vtable;
        ea_t base_vtable;
        qstring derived_class;
        qstring base_class;
        size_t common_methods;
        qvector<size_t> overridden_indices;
        qvector<size_t> new_method_indices;
        float similarity_score;  // 0.0 to 1.0
    };
    
private:
    std::map<ea_t, vtable_layout_t> vtable_layouts;
    qvector<inheritance_relation_t> relations;
    std::map<ea_t, qvector<ea_t>> inheritance_tree;  // vtable -> base vtables
    
public:
    void analyze_all_vtables(const qvector<VTBL_info_t>& vtables);
    void detect_inheritance_relationships();
    float calculate_vtable_similarity(ea_t vtbl1, ea_t vtbl2);
    const inheritance_relation_t* get_relation(ea_t derived, ea_t base) const;
    qvector<ea_t> get_base_vtables(ea_t vtable) const;
    qvector<ea_t> get_derived_vtables(ea_t vtable) const;
    bool is_method_overridden(ea_t vtable, size_t method_idx) const;
    ea_t find_method_origin(ea_t vtable, size_t method_idx) const;
};

// Search and filter functionality
class VTableSearcher {
public:
    enum search_type_t {
        SEARCH_CLASS_NAME,
        SEARCH_METHOD_NAME,
        SEARCH_ADDRESS,
        SEARCH_NAMESPACE,
        SEARCH_PATTERN  // Changed from SEARCH_REGEX to avoid potential conflicts
    };
    
    enum filter_type_t {
        FILTER_NONE = 0,
        FILTER_PURE_VIRTUAL = 1,
        FILTER_DESTRUCTORS = 2,
        FILTER_INHERITED = 4,
        FILTER_OVERRIDDEN = 8,
        FILTER_HAS_XREFS = 16,
        FILTER_ABSTRACT_CLASSES = 32,
        FILTER_COMPILER_MSVC = 64,
        FILTER_COMPILER_GCC = 128,
        FILTER_COMPILER_CLANG = 256
    };
    
    struct search_result_t {
        inode_t node;
        qstring matched_text;
        float relevance;  // 0.0 to 1.0
    };
    
private:
    VTableHierarchySpec* spec;
    std::regex current_regex;
    uint32 active_filters;
    
public:
    VTableSearcher(VTableHierarchySpec* s) : spec(s), active_filters(FILTER_NONE) {}
    
    qvector<search_result_t> search(const qstring& query, search_type_t type);
    qvector<inode_t> apply_filters(const qvector<inode_t>& nodes, uint32 filters);
    void set_filters(uint32 filters) { active_filters = filters; }
    uint32 get_filters() const { return active_filters; }
    
    // Quick filters
    qvector<inode_t> find_pure_virtuals();
    qvector<inode_t> find_abstract_classes();
    qvector<inode_t> find_overridden_methods();
    qvector<inode_t> find_by_compiler(RTTIInfo::CompilerType compiler);
    
    // Advanced search
    qvector<search_result_t> fuzzy_search(const qstring& query);
    qvector<inode_t> search_by_inheritance(const qstring& base_class);
};

// Enhanced VTable directory specialization
class VTableHierarchySpec : public dirspec_t {
public:
    // Extended node types
    enum node_type_t {
        NODE_ROOT,           
        NODE_VTABLE,        
        NODE_METHOD,         
        NODE_PURE_VIRTUAL,  
        NODE_INHERITED,     
        NODE_BASE_CLASS,    
        NODE_SEGMENT,       
        NODE_NAMESPACE,
        NODE_RTTI_INFO,      // New: RTTI information node
        NODE_XREF_INFO,      // New: Cross-reference info
        NODE_OVERRIDDEN      // New: Overridden method
    };
    
    // Enhanced node information
    struct node_info_t {
        node_type_t type;
        qstring name;
        qstring display_name;
        ea_t address;
        
        // For vtables - Store by value, not pointer!
        bool has_vtbl_info;
        VTBL_info_t vtbl_data;  // SAFE: Store actual data, not pointer
        ea_t vtbl_ea;  // Store EA for safe lookup
        qstring base_class;
        enhanced_rtti_info_t* rtti_info;  // Enhanced RTTI
        
        // For methods
        size_t method_index;
        method_info_t* method_cache;  // Cached method info
        bool is_pure_virtual;
        bool is_destructor;
        bool is_inherited;
        bool is_overridden;
        qstring inherited_from;
        
        // Cross-references
        size_t xref_count;
        qvector<ea_t> xrefs_to;
        qvector<ea_t> xrefs_from;
        
        // Visual info
        int icon;
        uint32 color;
        qstring tooltip;  // New: tooltip text
        
        // Search metadata
        qvector<qstring> search_tags;
        time_t last_accessed;
    };
    
private:
    std::map<inode_t, node_info_t> nodes;
    std::map<ea_t, inode_t> vtable_to_inode;
    std::map<qstring, qvector<inode_t>> inheritance_map;
    inode_t next_inode;
    
    // New components
    MethodCache* method_cache;
    InheritanceAnalyzer* inheritance_analyzer;
    VTableSearcher* searcher;
    
public:
    VTableHierarchySpec();
    virtual ~VTableHierarchySpec();
    
    // dirspec_t interface
    virtual bool get_name(qstring *out, inode_t inode, uint32 name_flags=DTN_FULL_NAME) override;
    virtual inode_t get_inode(const char *dirpath, const char *name) override;
    virtual qstring get_attrs(inode_t inode) const override;
    virtual bool rename_inode(inode_t inode, const char *newname) override;
    
    // Enhanced node management
    inode_t alloc_inode() { return next_inode++; }
    inode_t add_vtable_node(const VTBL_info_t& vtbl, const enhanced_rtti_info_t* rtti);
    inode_t add_method_node(const VTBL_info_t& vtbl, size_t idx, const method_info_t* minfo);
    inode_t add_inherited_folder(const qstring& base_class, int method_count);
    inode_t add_folder_node(const qstring& name, node_type_t type);
    inode_t add_rtti_node(const enhanced_rtti_info_t& rtti);
    inode_t add_xref_node(ea_t address, const qvector<ea_t>& xrefs);
    
    // Inheritance analysis
    void analyze_inheritance(const VTBL_info_t& vtbl);
    void build_inheritance_hierarchy();
    void detect_overridden_methods(const VTBL_info_t& vtbl);
    
    // Cache operations
    void cache_all_methods();
    void refresh_method_cache(ea_t method_ea);
    
    // Search operations
    VTableSearcher* get_searcher() { 
        if (!searcher) searcher = new VTableSearcher(this);
        return searcher; 
    }
    MethodCache* get_method_cache() { return method_cache; }
    InheritanceAnalyzer* get_inheritance_analyzer() { return inheritance_analyzer; }
    
    // Getters
    const node_info_t* get_node_info(inode_t inode) const;
    inode_t get_vtable_inode(ea_t ea) const;
    qvector<inode_t> get_nodes_by_type(node_type_t type) const;
    const std::map<inode_t, node_info_t>& get_all_nodes() const { return nodes; }
};

// Context menu actions
struct vtree_action_t : public action_handler_t {
    IntegratedTreeExplorer* explorer;
    
    vtree_action_t(IntegratedTreeExplorer* e) : explorer(e) {}
    virtual int idaapi activate(action_activation_ctx_t *ctx) override = 0;
    virtual action_state_t idaapi update(action_update_ctx_t *ctx) override {
        return AST_ENABLE_ALWAYS;
    }
};

// Specific actions
struct analyze_xrefs_action_t : public vtree_action_t {
    using vtree_action_t::vtree_action_t;
    virtual int idaapi activate(action_activation_ctx_t *ctx) override;
};

struct show_inheritance_action_t : public vtree_action_t {
    using vtree_action_t::vtree_action_t;
    virtual int idaapi activate(action_activation_ctx_t *ctx) override;
};

struct export_subtree_action_t : public vtree_action_t {
    using vtree_action_t::vtree_action_t;
    virtual int idaapi activate(action_activation_ctx_t *ctx) override;
};

struct find_similar_vtables_action_t : public vtree_action_t {
    using vtree_action_t::vtree_action_t;
    virtual int idaapi activate(action_activation_ctx_t *ctx) override;
};

// Enhanced Integrated tree explorer
class IntegratedTreeExplorer : public chooser_t {
public:
    enum {
        COL_NAME = 0,
        COL_ADDRESS,
        COL_TYPE,
        COL_INFO,
        COL_XREFS,     // New column
        COL_COMPILER,  // New column
        COL_END
    };
    
private:
    dirtree_t* tree;
    VTableHierarchySpec* spec;
    
    // Inode mapping
    qvector<inode_t> index_to_inode;
    std::map<inode_t, size_t> inode_to_index;
    
    // Search state
    qstring current_search;
    qvector<VTableSearcher::search_result_t> search_results;
    bool search_active;
    
    // Filter state
    uint32 active_filters;
    
    // Context menu actions
    qvector<action_desc_t> context_actions;
    
    // Build operations
    void build_vtable_tree();
    void build_enhanced_vtable_tree();
    void add_vtable_with_hierarchy(const VTBL_info_t& vtbl);
    void populate_index_mapping();
    void populate_enhanced_index_mapping();
    void build_enhanced_rtti_view(const VTBL_info_t& vtbl, enhanced_rtti_info_t& rtti);
    
    // Action handlers
    void register_context_actions();
    void unregister_context_actions();
    
public:
    IntegratedTreeExplorer();
    virtual ~IntegratedTreeExplorer();
    
    // Required chooser_t overrides
    virtual bool idaapi init() override;
    virtual const void *get_obj_id(size_t *len) const override;
    virtual size_t idaapi get_count() const override;
    virtual void idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
    
    // Tree-specific methods
    // virtual dirtree_t *get_dirtree() override { return tree; }  // Not using CH_HAS_DIRTREE
    inode_t index2inode(size_t n) const;
    size_t inode2index(inode_t inode) const;
    
    // Event handlers
    virtual cbret_t idaapi enter(size_t n) override;
    virtual cbret_t idaapi refresh(ssize_t n) override;
    virtual void idaapi closed() override;
    // virtual void idaapi get_actions(contextaction_setter_t &ctx) const override;
    
    // Search and filter
    void search(const qstring& query, VTableSearcher::search_type_t type);
    void clear_search();
    void apply_filter(uint32 filter_mask);
    void clear_filters();
    
    // Analysis operations
    void analyze_selected_xrefs(size_t n);
    void show_inheritance_graph(size_t n);
    void find_similar_vtables(size_t n);
    
    // Export operations
    bool export_to_json(const char* filename);
    bool export_to_graphml(const char* filename);
    bool export_subtree(inode_t root, const char* filename);
    
    // View operations
    void expand_all();
    void collapse_all();
    void show_inheritance_only();
    void show_pure_virtuals();
    void show_overridden_only();
    void reorganize_by_segment();
    void reorganize_by_namespace();
    void reorganize_by_similarity();
    
    // Utility
    inode_t get_selected_inode() const;
    void refresh_node(inode_t node);
    void highlight_search_results();
    
    // Show the explorer
    static void show();
};

// Global instance
extern IntegratedTreeExplorer* g_integrated_tree;

// Initialize/terminate
void init_integrated_tree_explorer();
void term_integrated_tree_explorer();

// Utility functions
qstring format_xref_count(size_t count);
qstring format_compiler_tag(RTTIInfo::CompilerType compiler);
bool analyze_method_xrefs(ea_t method_ea, method_info_t& info);

#endif // INTEGRATED_TREE_EXPLORER_H