/*
    Tree-based VTable Explorer using IDA SDK 9.2 dirtree_t
    Provides hierarchical view of vtables and their methods
*/

#ifndef TREE_VTABLE_EXPLORER_H
#define TREE_VTABLE_EXPLORER_H

#include "Common.h"
#include "ObjectExplorer.h"
#include <kernwin.hpp>
#include <dirtree.hpp>

// VTable tree specialization
class VTableDirSpec : public dirspec_t {
public:
    // Map inodes to vtable/method information
    struct node_info_t {
        enum node_type_t {
            NODE_VTABLE,     // Virtual table
            NODE_METHOD,     // Virtual method
            NODE_NAMESPACE,  // Namespace folder
            NODE_SEGMENT     // Segment folder
        };
        
        node_type_t type;
        qstring name;
        ea_t address;
        
        // For vtables
        VTBL_info_t* vtbl_info;
        
        // For methods
        size_t method_index;
        ea_t method_addr;
        qstring method_name;
        
        // For folders
        qstring folder_path;
    };
    
private:
    std::map<inode_t, node_info_t> nodes;
    inode_t next_inode;
    
    // Generate unique inode
    inode_t alloc_inode() { return next_inode++; }
    
public:
    VTableDirSpec();
    virtual ~VTableDirSpec() = default;
    
    // dirspec_t interface
    virtual bool get_name(qstring *out, inode_t inode, uint32 name_flags=DTN_FULL_NAME) override;
    virtual inode_t get_inode(const char *dirpath, const char *name) override;
    virtual qstring get_attrs(inode_t inode) const override;
    virtual bool rename_inode(inode_t inode, const char *newname) override;
    
    // Add nodes to the tree
    inode_t add_vtable(const VTBL_info_t& vtbl);
    inode_t add_method(inode_t vtable_inode, size_t index, ea_t addr, const char* name);
    inode_t add_namespace(const char* ns_name);
    inode_t add_segment(const char* seg_name);
    
    // Get node information
    const node_info_t* get_node_info(inode_t inode) const;
    bool is_vtable(inode_t inode) const;
    bool is_method(inode_t inode) const;
    bool is_folder(inode_t inode) const;
};

// Tree builder for vtables
class VTableTreeBuilder {
private:
    dirtree_t* tree;
    VTableDirSpec* spec;
    
    // Directory structure
    std::map<qstring, diridx_t> segment_dirs;
    std::map<qstring, diridx_t> namespace_dirs;
    
    // Build directory path for vtable
    qstring get_vtable_path(const VTBL_info_t& vtbl);
    
    // Create directory if not exists
    diridx_t ensure_directory(const char* path);
    
public:
    VTableTreeBuilder(dirtree_t* t, VTableDirSpec* s);
    
    // Build tree from vtable list
    void build_from_vtables();
    
    // Add single vtable to tree
    void add_vtable_to_tree(const VTBL_info_t& vtbl);
    
    // Organize by different criteria
    void organize_by_segment();
    void organize_by_namespace();
    void organize_by_inheritance();
    void organize_flat();
};

// Tree-based VTable Explorer chooser
class TreeVTableExplorer : public chooser_t {
public:
    enum {
        COL_NAME = 0,
        COL_ADDRESS,
        COL_INFO,
        COL_ATTRS,
        COL_END
    };
    
private:
    dirtree_t* tree;
    VTableDirSpec* spec;
    VTableTreeBuilder* builder;
    
    // Current view
    diridx_t current_dir;
    qvector<direntry_t> current_entries;
    
    // Navigation
    void enter_directory(diridx_t dir);
    void go_parent();
    void refresh_current_view();
    
    // Get entry at row
    const direntry_t* get_entry(size_t n) const;
    
public:
    TreeVTableExplorer();
    virtual ~TreeVTableExplorer();
    
    // chooser_t interface
    virtual bool idaapi init() override;
    virtual const void *get_obj_id(size_t *len) const override;
    virtual size_t idaapi get_count() const override;
    virtual void idaapi get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const override;
    virtual cbret_t idaapi enter(size_t n) override;
    virtual cbret_t idaapi refresh(ssize_t n) override;
    virtual void idaapi closed() override;
    
    // Navigation actions
    void navigate_to(const char* path);
    void expand_vtable(size_t n);
    void collapse_vtable(size_t n);
    void show_methods(size_t n);
    
    // Tree operations
    void reorganize(int mode);
    void search_tree(const char* pattern);
    void export_tree();
    
    // Show the tree explorer
    static void show();
};

// Context menu actions for tree explorer
class TreeVTableActions {
public:
    // Register all actions
    static void register_actions();
    
    // Individual actions
    static int expand_node(TreeVTableExplorer* exp, size_t n);
    static int collapse_node(TreeVTableExplorer* exp, size_t n);
    static int jump_to_address(TreeVTableExplorer* exp, size_t n);
    static int show_xrefs(TreeVTableExplorer* exp, size_t n);
    static int decompile_method(TreeVTableExplorer* exp, size_t n);
    static int rename_item(TreeVTableExplorer* exp, size_t n);
    static int create_struct(TreeVTableExplorer* exp, size_t n);
    static int reorganize_tree(TreeVTableExplorer* exp);
};

// Global instance
extern TreeVTableExplorer* g_tree_explorer;

// Initialize tree explorer
void init_tree_vtable_explorer();
void term_tree_vtable_explorer();

#endif // TREE_VTABLE_EXPLORER_H