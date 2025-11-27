/*
    Tree-based VTable Explorer Implementation
    Uses IDA SDK 9.2 dirtree_t for hierarchical display
*/

#include "TreeVTableExplorer.h"
#include "Utility.h"
#include <segment.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <demangle.hpp>

// External vtable list from ObjectExplorer
extern qvector<VTBL_info_t> vtbl_t_list;

// Global instance
TreeVTableExplorer* g_tree_explorer = nullptr;

//-------------------------------------------------------------------------
// VTableDirSpec Implementation
//-------------------------------------------------------------------------

VTableDirSpec::VTableDirSpec() 
    : dirspec_t("vtable_tree", DSF_ORDERABLE), next_inode(1) {
    msg("[VTable Tree] VTableDirSpec created\n");
}

bool VTableDirSpec::get_name(qstring *out, inode_t inode, uint32 name_flags) {
    auto it = nodes.find(inode);
    if (it == nodes.end()) {
        return false;
    }
    
    const node_info_t& info = it->second;
    
    if (out != nullptr) {
        if (name_flags & DTN_DISPLAY_NAME) {
            // Short display name
            if (info.type == node_info_t::NODE_VTABLE) {
                // Extract just class name
                qstring clean_name = info.name;
                if (clean_name.find("vtable for") != qstring::npos) {
                    clean_name.remove(0, 11); // Remove "vtable for'"
                }
                if (clean_name[0] == '\'') {
                    clean_name.remove(0, 1);
                }
                *out = clean_name;
            } else {
                *out = info.name;
            }
        } else {
            // Full name
            *out = info.name;
        }
    }
    
    return true;
}

inode_t VTableDirSpec::get_inode(const char *dirpath, const char *name) {
    // Search for matching node
    for (const auto& pair : nodes) {
        if (pair.second.name == name) {
            // Check if in correct directory
            if (dirpath && dirpath[0]) {
                if (pair.second.folder_path == dirpath) {
                    return pair.first;
                }
            } else {
                return pair.first;
            }
        }
    }
    return inode_t(-1);
}

qstring VTableDirSpec::get_attrs(inode_t inode) const {
    auto it = nodes.find(inode);
    if (it == nodes.end()) {
        return "";
    }
    
    const node_info_t& info = it->second;
    qstring attrs;
    
    switch (info.type) {
        case node_info_t::NODE_VTABLE:
            if (info.vtbl_info) {
                attrs.sprnt("[%d methods]", info.vtbl_info->methods);
            }
            break;
        case node_info_t::NODE_METHOD:
            attrs.sprnt("[%a]", info.method_addr);
            break;
        case node_info_t::NODE_NAMESPACE:
            attrs = "[namespace]";
            break;
        case node_info_t::NODE_SEGMENT:
            attrs = "[segment]";
            break;
    }
    
    return attrs;
}

bool VTableDirSpec::rename_inode(inode_t inode, const char *newname) {
    auto it = nodes.find(inode);
    if (it == nodes.end()) {
        return false;
    }
    
    it->second.name = newname;
    
    // If it's a vtable, rename in IDA
    if (it->second.type == node_info_t::NODE_VTABLE && it->second.vtbl_info) {
        set_name(it->second.vtbl_info->ea_begin, newname, SN_NOWARN);
    }
    
    return true;
}

inode_t VTableDirSpec::add_vtable(const VTBL_info_t& vtbl) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = node_info_t::NODE_VTABLE;
    info.name = vtbl.vtbl_name;
    info.address = vtbl.ea_begin;
    info.vtbl_info = const_cast<VTBL_info_t*>(&vtbl);
    
    nodes[inode] = info;
    return inode;
}

inode_t VTableDirSpec::add_method(inode_t vtable_inode, size_t index, ea_t addr, const char* name) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = node_info_t::NODE_METHOD;
    info.name = name;
    info.method_addr = addr;
    info.method_index = index;
    info.address = addr;
    
    nodes[inode] = info;
    return inode;
}

inode_t VTableDirSpec::add_namespace(const char* ns_name) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = node_info_t::NODE_NAMESPACE;
    info.name = ns_name;
    info.folder_path = ns_name;
    
    nodes[inode] = info;
    return inode;
}

inode_t VTableDirSpec::add_segment(const char* seg_name) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = node_info_t::NODE_SEGMENT;
    info.name = seg_name;
    info.folder_path = seg_name;
    
    nodes[inode] = info;
    return inode;
}

const VTableDirSpec::node_info_t* VTableDirSpec::get_node_info(inode_t inode) const {
    auto it = nodes.find(inode);
    return (it != nodes.end()) ? &it->second : nullptr;
}

bool VTableDirSpec::is_vtable(inode_t inode) const {
    auto it = nodes.find(inode);
    return it != nodes.end() && it->second.type == node_info_t::NODE_VTABLE;
}

bool VTableDirSpec::is_method(inode_t inode) const {
    auto it = nodes.find(inode);
    return it != nodes.end() && it->second.type == node_info_t::NODE_METHOD;
}

bool VTableDirSpec::is_folder(inode_t inode) const {
    auto it = nodes.find(inode);
    return it != nodes.end() && 
           (it->second.type == node_info_t::NODE_NAMESPACE || 
            it->second.type == node_info_t::NODE_SEGMENT);
}

//-------------------------------------------------------------------------
// VTableTreeBuilder Implementation
//-------------------------------------------------------------------------

VTableTreeBuilder::VTableTreeBuilder(dirtree_t* t, VTableDirSpec* s) 
    : tree(t), spec(s) {
    msg("[VTable Tree] TreeBuilder created\n");
}

qstring VTableTreeBuilder::get_vtable_path(const VTBL_info_t& vtbl) {
    qstring path;
    
    // Get segment name
    segment_t* seg = getseg(vtbl.ea_begin);
    if (seg) {
        qstring seg_name;
        get_segm_name(&seg_name, seg);
        path = seg_name;
    }
    
    // Try to extract namespace from name
    qstring clean_name = vtbl.vtbl_name;
    const char* scope_sep = "::";
    if (clean_name.find(scope_sep) != qstring::npos) {
        // Has namespace - find last occurrence
        size_t pos = clean_name.find(scope_sep);
        size_t last_pos = pos;
        while ((pos = clean_name.find(scope_sep, last_pos + 2)) != qstring::npos) {
            last_pos = pos;
        }
        qstring ns;
        ns.append(clean_name.c_str(), last_pos);
        path.append("/");
        path.append(ns);
    }
    
    return path;
}

diridx_t VTableTreeBuilder::ensure_directory(const char* path) {
    // Create directory if it doesn't exist
    dterr_t err = tree->mkdir(path);
    if (err != DTE_OK && err != DTE_ALREADY_EXISTS) {
        msg("[VTable Tree] Failed to create directory %s: %s\n", 
            path, tree->errstr(err));
        return direntry_t::BADIDX;
    }
    
    // Get directory index
    direntry_t de = tree->resolve_path(path);
    if (de.valid() && de.isdir) {
        return de.idx;
    }
    
    return direntry_t::BADIDX;
}

void VTableTreeBuilder::build_from_vtables() {
    msg("[VTable Tree] Building tree from %d vtables\n", vtbl_t_list.size());
    
    // Clear existing tree
    tree->chdir("/");
    
    // Add each vtable
    for (const auto& vtbl : vtbl_t_list) {
        add_vtable_to_tree(vtbl);
    }
    
    msg("[VTable Tree] Tree built successfully\n");
}

void VTableTreeBuilder::add_vtable_to_tree(const VTBL_info_t& vtbl) {
    // Create vtable inode
    inode_t vtbl_inode = spec->add_vtable(vtbl);
    
    // Get path for vtable
    qstring path = get_vtable_path(vtbl);
    
    if (!path.empty()) {
        // Ensure directory exists
        diridx_t dir = ensure_directory(path.c_str());
        if (dir != direntry_t::BADIDX) {
            // Change to directory
            tree->chdir(path.c_str());
        }
    }
    
    // Link vtable to current directory
    dterr_t err = tree->link(vtbl_inode);
    if (err != DTE_OK) {
        msg("[VTable Tree] Failed to link vtable %s: %s\n", 
            vtbl.vtbl_name.c_str(), tree->errstr(err));
        return;
    }
    
    // Create subdirectory for methods
    qstring methods_dir = vtbl.vtbl_name;
    methods_dir.append("_methods");
    err = tree->mkdir(methods_dir.c_str());
    
    if (err == DTE_OK || err == DTE_ALREADY_EXISTS) {
        // Add methods to subdirectory
        tree->chdir(methods_dir.c_str());
        
        for (size_t i = 0; i < vtbl.methods; i++) {
            // Get method name
            qstring method_name;
            size_t ptr_size = inf_is_64bit() ? 8 : 4;
            ea_t method_addr = inf_is_64bit() ? 
                get_qword(vtbl.ea_begin + i * ptr_size) :
                get_dword(vtbl.ea_begin + i * ptr_size);
            get_short_name(&method_name, method_addr);
            
            // Demangle if needed
            qstring demangled;
            if (demangle_name(&demangled, method_name.c_str(), MNG_SHORT_FORM) > 0) {
                method_name = demangled;
            }
            
            // Add method number
            qstring numbered_name;
            numbered_name.sprnt("[%02d] %s", i, method_name.c_str());
            
            // Create method inode
            inode_t method_inode = spec->add_method(vtbl_inode, i, 
                                                    method_addr, 
                                                    numbered_name.c_str());
            
            // Link method
            tree->link(method_inode);
        }
        
        // Return to parent
        tree->chdir("..");
    }
    
    // Return to root
    tree->chdir("/");
}

void VTableTreeBuilder::organize_by_segment() {
    msg("[VTable Tree] Organizing by segment\n");
    
    // Clear and rebuild organized by segment
    tree->chdir("/");
    
    // Group vtables by segment
    std::map<qstring, qvector<const VTBL_info_t*>> by_segment;
    
    for (const auto& vtbl : vtbl_t_list) {
        segment_t* seg = getseg(vtbl.ea_begin);
        if (seg) {
            qstring seg_name;
            get_segm_name(&seg_name, seg);
            by_segment[seg_name].push_back(&vtbl);
        }
    }
    
    // Create segment directories
    for (const auto& pair : by_segment) {
        // Create segment directory
        tree->mkdir(pair.first.c_str());
        tree->chdir(pair.first.c_str());
        
        // Add vtables
        for (const auto* vtbl : pair.second) {
            inode_t vtbl_inode = spec->add_vtable(*vtbl);
            tree->link(vtbl_inode);
        }
        
        tree->chdir("/");
    }
}

void VTableTreeBuilder::organize_by_namespace() {
    msg("[VTable Tree] Organizing by namespace\n");
    
    // Clear and rebuild organized by namespace
    tree->chdir("/");
    
    // Group vtables by namespace
    std::map<qstring, qvector<const VTBL_info_t*>> by_namespace;
    
    for (const auto& vtbl : vtbl_t_list) {
        qstring ns = "global";
        
        // Extract namespace
        size_t pos = vtbl.vtbl_name.find("::");
        if (pos != qstring::npos) {
            ns = vtbl.vtbl_name.substr(0, pos);
        }
        
        by_namespace[ns].push_back(&vtbl);
    }
    
    // Create namespace directories
    for (const auto& pair : by_namespace) {
        // Create namespace directory
        tree->mkdir(pair.first.c_str());
        tree->chdir(pair.first.c_str());
        
        // Add vtables
        for (const auto* vtbl : pair.second) {
            inode_t vtbl_inode = spec->add_vtable(*vtbl);
            tree->link(vtbl_inode);
        }
        
        tree->chdir("/");
    }
}

void VTableTreeBuilder::organize_flat() {
    msg("[VTable Tree] Organizing flat\n");
    
    // Clear and add all vtables to root
    tree->chdir("/");
    
    for (const auto& vtbl : vtbl_t_list) {
        inode_t vtbl_inode = spec->add_vtable(vtbl);
        tree->link(vtbl_inode);
    }
}

//-------------------------------------------------------------------------
// TreeVTableExplorer Implementation
//-------------------------------------------------------------------------

// Column configuration
static const int tree_widths[] = { 30, 12, 20, 15 };
static const char *const tree_headers[] = { 
    "Name", 
    "Address", 
    "Info", 
    "Attributes" 
};

TreeVTableExplorer::TreeVTableExplorer()
    : chooser_t(CH_KEEP | CH_RESTORE | CH_CAN_REFRESH,
                qnumber(tree_widths), tree_widths, tree_headers),
      tree(nullptr), spec(nullptr), builder(nullptr),
      current_dir(direntry_t::ROOTIDX) {
    
    msg("[VTable Tree] TreeVTableExplorer constructor\n");
    
    // Set window title
    title = "VTable Tree Explorer";
    
    // Initialize tree components
    spec = new VTableDirSpec();
    tree = new dirtree_t(spec);
    builder = new VTableTreeBuilder(tree, spec);
}

TreeVTableExplorer::~TreeVTableExplorer() {
    msg("[VTable Tree] TreeVTableExplorer destructor\n");
    
    delete builder;
    delete tree;
    delete spec;
    
    if (g_tree_explorer == this) {
        g_tree_explorer = nullptr;
    }
}

bool TreeVTableExplorer::init() {
    msg("[VTable Tree] init() called\n");
    
    // Build tree from vtables
    builder->build_from_vtables();
    
    // Start at root
    enter_directory(direntry_t::ROOTIDX);
    
    msg("[VTable Tree] init() complete\n");
    return true;
}

const void* TreeVTableExplorer::get_obj_id(size_t *len) const {
    static const char chooser_id[] = "VTableTreeExplorer";
    *len = sizeof(chooser_id);
    return chooser_id;
}

size_t TreeVTableExplorer::get_count() const {
    return current_entries.size();
}

void TreeVTableExplorer::get_row(qstrvec_t *cols, int *icon, 
                                 chooser_item_attrs_t *attrs, size_t n) const {
    const direntry_t* de = get_entry(n);
    if (!de || !de->valid()) {
        return;
    }
    
    // Clear and resize
    cols->clear();
    cols->resize(COL_END);
    
    // Get name
    qstring name;
    if (de->isdir) {
        // Directory
        (*cols)[COL_NAME].sprnt("[%s]", tree->get_entry_name(*de).c_str());
        (*cols)[COL_ADDRESS] = "";
        (*cols)[COL_INFO] = "Directory";
        
        // Get directory size
        ssize_t size = tree->get_dir_size(de->idx);
        (*cols)[COL_ATTRS].sprnt("%d items", size);
        
        // Set icon
        if (icon) {
            *icon = 1; // Folder icon
        }
    } else {
        // File (vtable or method)
        const VTableDirSpec::node_info_t* info = spec->get_node_info(de->idx);
        if (info) {
            (*cols)[COL_NAME] = info->name;
            (*cols)[COL_ADDRESS].sprnt("%a", info->address);
            
            switch (info->type) {
                case VTableDirSpec::node_info_t::NODE_VTABLE:
                    if (info->vtbl_info) {
                        (*cols)[COL_INFO].sprnt("%d methods", 
                                               info->vtbl_info->methods);
                    }
                    if (icon) *icon = 59; // Class icon
                    break;
                    
                case VTableDirSpec::node_info_t::NODE_METHOD:
                    (*cols)[COL_INFO].sprnt("Method #%d", info->method_index);
                    if (icon) *icon = 42; // Function icon
                    break;
                    
                default:
                    (*cols)[COL_INFO] = "Item";
                    break;
            }
            
            (*cols)[COL_ATTRS] = tree->get_entry_attrs(*de);
        }
    }
    
    // Set colors
    if (attrs) {
        if (de->isdir) {
            attrs->color = 0x0000FF; // Red for directories
        } else {
            const VTableDirSpec::node_info_t* info = spec->get_node_info(de->idx);
            if (info) {
                if (info->type == VTableDirSpec::node_info_t::NODE_VTABLE) {
                    attrs->color = 0x00FF00; // Green for vtables
                } else if (info->type == VTableDirSpec::node_info_t::NODE_METHOD) {
                    attrs->color = 0xFF8000; // Blue for methods
                }
            }
        }
    }
}

TreeVTableExplorer::cbret_t TreeVTableExplorer::enter(size_t n) {
    msg("[VTable Tree] enter(%d)\n", n);
    
    const direntry_t* de = get_entry(n);
    if (!de || !de->valid()) {
        return cbret_t();
    }
    
    if (de->isdir) {
        // Enter directory
        enter_directory(de->idx);
        return cbret_t(n, chooser_base_t::ALL_CHANGED);
    } else {
        // Jump to address
        const VTableDirSpec::node_info_t* info = spec->get_node_info(de->idx);
        if (info && info->address != BADADDR) {
            jumpto(info->address);
        }
        return cbret_t(n, chooser_base_t::NOTHING_CHANGED);
    }
}

TreeVTableExplorer::cbret_t TreeVTableExplorer::refresh(ssize_t n) {
    msg("[VTable Tree] refresh(%d)\n", n);
    
    // Rebuild tree
    builder->build_from_vtables();
    
    // Refresh current view
    refresh_current_view();
    
    return cbret_t(n, chooser_base_t::ALL_CHANGED);
}

void TreeVTableExplorer::closed() {
    msg("[VTable Tree] closed()\n");
    
    // Don't delete self - keep instance for reuse
}

void TreeVTableExplorer::enter_directory(diridx_t dir) {
    msg("[VTable Tree] Entering directory %d\n", dir);
    
    current_dir = dir;
    refresh_current_view();
}

void TreeVTableExplorer::go_parent() {
    // TODO: Implement parent navigation
    tree->chdir("..");
    refresh_current_view();
}

void TreeVTableExplorer::refresh_current_view() {
    current_entries.clear();
    
    // Get entries in current directory
    ssize_t size = tree->get_dir_size(current_dir);
    if (size > 0) {
        // Iterate directory entries
        dirtree_iterator_t iter;
        if (tree->findfirst(&iter, "*")) {
            do {
                direntry_t de = tree->resolve_cursor(iter.cursor);
                if (de.valid()) {
                    current_entries.push_back(de);
                }
            } while (tree->findnext(&iter));
        }
    }
    
    msg("[VTable Tree] Current view has %d entries\n", current_entries.size());
}

const direntry_t* TreeVTableExplorer::get_entry(size_t n) const {
    if (n >= current_entries.size()) {
        return nullptr;
    }
    return &current_entries[n];
}

void TreeVTableExplorer::show() {
    msg("[VTable Tree] show() called\n");
    
    if (g_tree_explorer) {
        // Activate existing window
        g_tree_explorer->choose();
    } else {
        // Create new instance
        g_tree_explorer = new TreeVTableExplorer();
        g_tree_explorer->choose();
    }
}

//-------------------------------------------------------------------------
// Global Functions
//-------------------------------------------------------------------------

void init_tree_vtable_explorer() {
    msg("[VTable Tree] Initializing tree explorer\n");
    
    // Register actions
    TreeVTableActions::register_actions();
}

void term_tree_vtable_explorer() {
    msg("[VTable Tree] Terminating tree explorer\n");
    
    if (g_tree_explorer) {
        delete g_tree_explorer;
        g_tree_explorer = nullptr;
    }
}

//-------------------------------------------------------------------------
// TreeVTableActions Implementation
//-------------------------------------------------------------------------

void TreeVTableActions::register_actions() {
    // TODO: Register context menu actions
    msg("[VTable Tree] Actions registered\n");
}