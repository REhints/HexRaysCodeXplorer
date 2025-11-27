/*
    Integrated Tree VTable Explorer using chooser_t's built-in dirtree support
    Properly implements CH_HAS_DIRTREE with all required methods
*/

#ifndef INTEGRATED_TREE_EXPLORER_H
#define INTEGRATED_TREE_EXPLORER_H

#include "Common.h"
#include "ObjectExplorer.h"
#include <kernwin.hpp>
#include <dirtree.hpp>

// Enhanced VTable directory specialization with inheritance support
class VTableHierarchySpec : public dirspec_t {
public:
    // Node types in our tree
    enum node_type_t {
        NODE_ROOT,           // Root folder
        NODE_VTABLE,        // Virtual table
        NODE_METHOD,        // Virtual method  
        NODE_PURE_VIRTUAL,  // Pure virtual method
        NODE_INHERITED,     // Inherited methods folder
        NODE_BASE_CLASS,    // Base class folder
        NODE_SEGMENT,       // Segment folder
        NODE_NAMESPACE      // Namespace folder
    };
    
    // Node information
    struct node_info_t {
        node_type_t type;
        qstring name;
        qstring display_name;
        ea_t address;
        
        // For vtables
        const VTBL_info_t* vtbl_info;
        qstring base_class;  // If inherited
        
        // For methods
        size_t method_index;
        bool is_pure_virtual;
        bool is_destructor;
        bool is_inherited;
        qstring inherited_from;
        
        // Icon/color info
        int icon;
        uint32 color;
    };
    
private:
    std::map<inode_t, node_info_t> nodes;
    std::map<ea_t, inode_t> vtable_to_inode;
    std::map<qstring, qvector<inode_t>> inheritance_map;
    inode_t next_inode;
    
public:
    VTableHierarchySpec();
    virtual ~VTableHierarchySpec() = default;
    
    // dirspec_t interface
    virtual bool get_name(qstring *out, inode_t inode, uint32 name_flags=DTN_FULL_NAME) override;
    virtual inode_t get_inode(const char *dirpath, const char *name) override;
    virtual qstring get_attrs(inode_t inode) const override;
    virtual bool rename_inode(inode_t inode, const char *newname) override;
    
    // Node management
    inode_t alloc_inode() { return next_inode++; }
    inode_t add_vtable_node(const VTBL_info_t& vtbl);
    inode_t add_method_node(const VTBL_info_t& vtbl, size_t idx, bool is_inherited, const qstring& from_class);
    inode_t add_inherited_folder(const qstring& base_class, int method_count);
    inode_t add_folder_node(const qstring& name, node_type_t type);
    
    // Inheritance analysis
    void analyze_inheritance(const VTBL_info_t& vtbl);
    void build_inheritance_hierarchy();
    
    // Getters
    const node_info_t* get_node_info(inode_t inode) const;
    inode_t get_vtable_inode(ea_t ea) const;
};

// Integrated tree explorer with proper chooser_t integration
class IntegratedTreeExplorer : public chooser_t {
public:
    enum {
        COL_NAME = 0,
        COL_ADDRESS,
        COL_TYPE,
        COL_INFO,
        COL_END
    };
    
private:
    dirtree_t* tree;
    VTableHierarchySpec* spec;
    
    // Inode mapping for chooser integration
    qvector<inode_t> index_to_inode;
    std::map<inode_t, size_t> inode_to_index;
    
    // Build the tree structure
    void build_vtable_tree();
    void add_vtable_with_hierarchy(const VTBL_info_t& vtbl);
    void populate_index_mapping();
    
public:
    IntegratedTreeExplorer();
    virtual ~IntegratedTreeExplorer();
    
    // Required chooser_t overrides for tree mode
    virtual bool idaapi init() override;
    virtual const void *get_obj_id(size_t *len) const override;
    virtual size_t idaapi get_count() const override;
    virtual void idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
    
    // Tree-specific methods - REQUIRED for CH_HAS_DIRTREE
    virtual dirtree_t *get_dirtree() override { return tree; }
    // Note: index2inode and inode2index might not exist in all SDK versions
    // virtual inode_t index2inode(size_t n) const override;
    // virtual size_t inode2index(inode_t inode) const override;
    inode_t index2inode(size_t n) const;
    size_t inode2index(inode_t inode) const;
    
    // Optional but useful
    virtual cbret_t idaapi enter(size_t n) override;
    virtual cbret_t idaapi refresh(ssize_t n) override;
    virtual void idaapi closed() override;
    
    // Actions
    void expand_all();
    void collapse_all();
    void show_inheritance_only();
    void show_pure_virtuals();
    void reorganize_by_segment();
    void reorganize_by_namespace();
    
    // Show the explorer
    static void show();
};

// Tree builder with inheritance analysis
class VTableInheritanceAnalyzer {
private:
    // Inheritance information
    struct inheritance_info_t {
        qstring derived_class;
        qstring base_class;
        qvector<size_t> overridden_methods;
        qvector<size_t> new_methods;
        size_t base_method_count;
    };
    
    std::map<ea_t, inheritance_info_t> inheritance_data;
    
public:
    // Analyze vtable for inheritance patterns
    void analyze_vtable(const VTBL_info_t& vtbl);
    
    // Detect base class by comparing vtable layouts
    qstring detect_base_class(const VTBL_info_t& vtbl);
    
    // Check if method is overridden
    bool is_method_overridden(const VTBL_info_t& vtbl, size_t idx);
    
    // Get inheritance info
    const inheritance_info_t* get_inheritance_info(ea_t vtbl_ea) const;
    
    // Build complete inheritance tree
    void build_inheritance_tree();
};

// Global instance
extern IntegratedTreeExplorer* g_integrated_tree;

// Initialize/terminate
void init_integrated_tree_explorer();
void term_integrated_tree_explorer();

#endif // INTEGRATED_TREE_EXPLORER_H