/*
    Integrated Tree VTable Explorer Implementation
    Full CH_HAS_DIRTREE integration with inheritance hierarchy
    Complete compiler support: GCC, Clang, MSVC
*/

#include "IntegratedTreeExplorer.h"
#include "CompilerRTTIParser.h"
#include "ClangVTableParser.h"
#include "Utility.h"
#include <segment.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <demangle.hpp>

// External vtable list
extern qvector<VTBL_info_t> vtbl_t_list;

// Global instance
IntegratedTreeExplorer* g_integrated_tree = nullptr;

//-------------------------------------------------------------------------
// VTableHierarchySpec Implementation
//-------------------------------------------------------------------------

VTableHierarchySpec::VTableHierarchySpec() 
    : dirspec_t("vtable_hierarchy", DSF_ORDERABLE), next_inode(1) {
    msg("[VTable Tree] VTableHierarchySpec initialized\n");
}

bool VTableHierarchySpec::get_name(qstring *out, inode_t inode, uint32 name_flags) {
    auto it = nodes.find(inode);
    if (it == nodes.end()) {
        return false;
    }
    
    const node_info_t& info = it->second;
    
    if (out != nullptr) {
        if (name_flags & DTN_DISPLAY_NAME) {
            *out = info.display_name.empty() ? info.name : info.display_name;
        } else {
            *out = info.name;
        }
    }
    
    return true;
}

inode_t VTableHierarchySpec::get_inode(const char *dirpath, const char *name) {
    for (const auto& pair : nodes) {
        if (pair.second.name == name) {
            return pair.first;
        }
    }
    return inode_t(-1);
}

qstring VTableHierarchySpec::get_attrs(inode_t inode) const {
    auto it = nodes.find(inode);
    if (it == nodes.end()) {
        return "";
    }
    
    const node_info_t& info = it->second;
    qstring attrs;
    
    switch (info.type) {
        case NODE_VTABLE:
            if (info.vtbl_info) {
                attrs.sprnt("%d methods", info.vtbl_info->methods);
            }
            break;
            
        case NODE_METHOD:
            if (info.is_pure_virtual) {
                attrs = "pure virtual";
            } else if (info.is_inherited) {
                attrs.sprnt("inherited from %s", info.inherited_from.c_str());
            } else {
                attrs.sprnt("%a", info.address);
            }
            break;
            
        case NODE_INHERITED:
            attrs = "inherited";
            break;
            
        case NODE_BASE_CLASS:
            attrs = "base class";
            break;
            
        default:
            break;
    }
    
    return attrs;
}

bool VTableHierarchySpec::rename_inode(inode_t inode, const char *newname) {
    auto it = nodes.find(inode);
    if (it == nodes.end()) {
        return false;
    }
    
    it->second.name = newname;
    
    // Rename in IDA if it's a vtable
    if (it->second.type == NODE_VTABLE && it->second.vtbl_info) {
        set_name(it->second.vtbl_info->ea_begin, newname, SN_NOWARN);
    }
    
    return true;
}

inode_t VTableHierarchySpec::add_vtable_node(const VTBL_info_t& vtbl) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = NODE_VTABLE;
    info.name = vtbl.vtbl_name;
    info.address = vtbl.ea_begin;
    info.vtbl_info = &vtbl;
    
    // Try to get RTTI info for better display
    RTTIInfo rtti_info;
    bool has_rtti = CompilerRTTIParser::parse_vtable_rtti(vtbl, rtti_info);
    
    if (has_rtti) {
        // Use RTTI-based display name
        info.display_name = rtti_info.class_name;
        
        // Set icon based on RTTI
        info.icon = RTTITreeHelper::get_node_icon(&rtti_info);
        
        // Set color based on compiler
        info.color = RTTITreeHelper::get_node_color(&rtti_info);
        
        // Add compiler tag
        switch (rtti_info.compiler) {
            case RTTIInfo::COMPILER_MSVC:
                info.display_name.append(" [MSVC]");
                break;
            case RTTIInfo::COMPILER_GCC:
                info.display_name.append(" [GCC]");
                break;
            case RTTIInfo::COMPILER_CLANG:
                info.display_name.append(" [Clang]");
                break;
            default:
                break;
        }
    } else {
        // Fallback to basic extraction
        info.display_name = vtbl.vtbl_name;
        if (info.display_name.find("vtable for") != qstring::npos) {
            info.display_name.remove(0, 11);
        }
        if (info.display_name[0] == '\'') {
            info.display_name.remove(0, 1);
            size_t pos = info.display_name.find('\'');
            if (pos != qstring::npos) {
                info.display_name.remove(pos, 1);
            }
        }
        
        info.icon = 59;  // Default class icon
        info.color = 0x808080;  // Gray for no RTTI
    }
    
    nodes[inode] = info;
    vtable_to_inode[vtbl.ea_begin] = inode;
    
    return inode;
}

inode_t VTableHierarchySpec::add_method_node(const VTBL_info_t& vtbl, size_t idx, 
                                             bool is_inherited, const qstring& from_class) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = NODE_METHOD;
    info.method_index = idx;
    info.is_inherited = is_inherited;
    info.inherited_from = from_class;
    
    // Get method address and name
    // Note: VTBL_info_t only has method count, not actual addresses
    // We would need to read from memory to get actual method addresses
    if (idx < vtbl.methods) {
        // Calculate method address from vtable
        size_t ptr_size = inf_is_64bit() ? 8 : 4;
        info.address = vtbl.ea_begin + idx * ptr_size;
        ea_t method_ea;
        if (inf_is_64bit()) {
            method_ea = get_qword(info.address);
        } else {
            method_ea = get_dword(info.address);
        }
        if (method_ea != BADADDR) {
            info.address = method_ea;
        }
        
        // Get method name
        qstring method_name;
        get_short_name(&method_name, info.address);
        
        // Check for pure virtual
        if (method_name.find("purecall") != qstring::npos || 
            method_name.find("pure_virtual") != qstring::npos) {
            info.is_pure_virtual = true;
            info.type = NODE_PURE_VIRTUAL;
            info.icon = 156;  // Warning icon
            info.color = 0x0000FF;  // Red
        } else {
            info.icon = 42;  // Function icon
            info.color = 0xFF8000;  // Blue
        }
        
        // Check for destructor
        if (method_name[0] == '~' || method_name.find("destructor") != qstring::npos) {
            info.is_destructor = true;
        }
        
        // Demangle name
        qstring demangled;
        if (demangle_name(&demangled, method_name.c_str(), MNG_SHORT_FORM) > 0) {
            method_name = demangled;
        }
        
        // Format display name
        if (info.is_pure_virtual) {
            info.name.sprnt("🔹 %s (pure virtual)", method_name.c_str());
        } else if (info.is_destructor) {
            info.name.sprnt("🔹 ~%s()", method_name.c_str());
        } else {
            info.name.sprnt("🔹 %s", method_name.c_str());
        }
        
        info.display_name = info.name;
    }
    
    nodes[inode] = info;
    return inode;
}

inode_t VTableHierarchySpec::add_inherited_folder(const qstring& base_class, int method_count) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = NODE_INHERITED;
    info.name.sprnt("📁 Inherited from %s [%d methods]", base_class.c_str(), method_count);
    info.display_name = info.name;
    info.base_class = base_class;
    info.icon = 1;  // Folder icon
    info.color = 0x808080;  // Gray
    
    nodes[inode] = info;
    return inode;
}

inode_t VTableHierarchySpec::add_folder_node(const qstring& name, node_type_t type) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = type;
    info.name = name;
    info.display_name = name;
    info.icon = 1;  // Folder icon
    
    switch (type) {
        case NODE_SEGMENT:
            info.color = 0x008080;  // Teal
            break;
        case NODE_NAMESPACE:
            info.color = 0x800080;  // Purple
            break;
        default:
            info.color = 0x808080;  // Gray
            break;
    }
    
    nodes[inode] = info;
    return inode;
}

const VTableHierarchySpec::node_info_t* VTableHierarchySpec::get_node_info(inode_t inode) const {
    auto it = nodes.find(inode);
    return (it != nodes.end()) ? &it->second : nullptr;
}

inode_t VTableHierarchySpec::get_vtable_inode(ea_t ea) const {
    auto it = vtable_to_inode.find(ea);
    return (it != vtable_to_inode.end()) ? it->second : inode_t(-1);
}

//-------------------------------------------------------------------------
// IntegratedTreeExplorer Implementation
//-------------------------------------------------------------------------

// Column configuration
static const int tree_widths[] = { 40, 12, 15, 25 };
static const char *const tree_headers[] = { 
    "Name", 
    "Address", 
    "Type",
    "Info" 
};

IntegratedTreeExplorer::IntegratedTreeExplorer()
    : chooser_t(CH_KEEP | CH_RESTORE | CH_CAN_REFRESH | 
                CH_HAS_DIRTREE | CH_TM_FULL_TREE,  // CRITICAL: Enable tree mode!
                qnumber(tree_widths), tree_widths, tree_headers),
      tree(nullptr), spec(nullptr) {
    
    msg("[VTable Tree] IntegratedTreeExplorer constructor\n");
    
    // Set window title
    title = "VTable Tree Explorer";
    
    // Create tree components
    spec = new VTableHierarchySpec();
    tree = new dirtree_t(spec);
}

IntegratedTreeExplorer::~IntegratedTreeExplorer() {
    msg("[VTable Tree] IntegratedTreeExplorer destructor\n");
    
    delete tree;
    delete spec;
    
    if (g_integrated_tree == this) {
        g_integrated_tree = nullptr;
    }
}

bool IntegratedTreeExplorer::init() {
    msg("[VTable Tree] init() called\n");
    
    // Build the tree structure
    build_vtable_tree();
    
    // Populate index mapping for chooser integration
    populate_index_mapping();
    
    msg("[VTable Tree] init() complete with %d items\n", index_to_inode.size());
    return true;
}

const void* IntegratedTreeExplorer::get_obj_id(size_t *len) const {
    static const char chooser_id[] = "IntegratedVTableTree";
    *len = sizeof(chooser_id);
    return chooser_id;
}

size_t IntegratedTreeExplorer::get_count() const {
    return index_to_inode.size();
}

void IntegratedTreeExplorer::get_row(qstrvec_t *cols, int *icon, 
                                     chooser_item_attrs_t *attrs, size_t n) const {
    if (n >= index_to_inode.size()) {
        return;
    }
    
    inode_t inode = index_to_inode[n];
    const VTableHierarchySpec::node_info_t* info = spec->get_node_info(inode);
    
    if (!info) {
        return;
    }
    
    // Clear and resize
    cols->clear();
    cols->resize(COL_END);
    
    // Fill columns
    (*cols)[COL_NAME] = info->display_name;
    
    if (info->address != BADADDR && info->address != 0) {
        (*cols)[COL_ADDRESS].sprnt("%a", info->address);
    } else {
        (*cols)[COL_ADDRESS] = "";
    }
    
    // Type column
    switch (info->type) {
        case VTableHierarchySpec::NODE_VTABLE:
            (*cols)[COL_TYPE] = "VTable";
            break;
        case VTableHierarchySpec::NODE_METHOD:
            (*cols)[COL_TYPE] = "Method";
            break;
        case VTableHierarchySpec::NODE_PURE_VIRTUAL:
            (*cols)[COL_TYPE] = "Pure Virtual";
            break;
        case VTableHierarchySpec::NODE_INHERITED:
            (*cols)[COL_TYPE] = "Inherited";
            break;
        case VTableHierarchySpec::NODE_BASE_CLASS:
            (*cols)[COL_TYPE] = "Base Class";
            break;
        default:
            (*cols)[COL_TYPE] = "Folder";
            break;
    }
    
    // Info column
    (*cols)[COL_INFO] = spec->get_attrs(inode);
    
    // Set icon and color
    if (icon) {
        *icon = info->icon;
    }
    
    if (attrs) {
        attrs->color = info->color;
    }
}

// CRITICAL: Required for CH_HAS_DIRTREE
inode_t IntegratedTreeExplorer::index2inode(size_t n) const {
    if (n >= index_to_inode.size()) {
        return inode_t(-1);
    }
    return index_to_inode[n];
}

// CRITICAL: Required for CH_HAS_DIRTREE
size_t IntegratedTreeExplorer::inode2index(inode_t inode) const {
    auto it = inode_to_index.find(inode);
    if (it == inode_to_index.end()) {
        return size_t(-1);
    }
    return it->second;
}

IntegratedTreeExplorer::cbret_t IntegratedTreeExplorer::enter(size_t n) {
    if (n >= index_to_inode.size()) {
        return cbret_t();
    }
    
    inode_t inode = index_to_inode[n];
    const VTableHierarchySpec::node_info_t* info = spec->get_node_info(inode);
    
    if (info && info->address != BADADDR && info->address != 0) {
        jumpto(info->address);
    }
    
    return cbret_t(n, chooser_base_t::NOTHING_CHANGED);
}

IntegratedTreeExplorer::cbret_t IntegratedTreeExplorer::refresh(ssize_t n) {
    msg("[VTable Tree] refresh(%d)\n", n);
    
    // Rebuild tree
    build_vtable_tree();
    populate_index_mapping();
    
    return cbret_t(n, chooser_base_t::ALL_CHANGED);
}

void IntegratedTreeExplorer::closed() {
    msg("[VTable Tree] closed()\n");
}

void IntegratedTreeExplorer::build_vtable_tree() {
    msg("[VTable Tree] Building tree from %d vtables\n", vtbl_t_list.size());
    
    // Clear existing tree
    tree->chdir("/");
    
    // Create root folder
    tree->mkdir("📁 VTable Explorer");
    tree->chdir("📁 VTable Explorer");
    
    // Add each vtable with hierarchy
    for (const auto& vtbl : vtbl_t_list) {
        add_vtable_with_hierarchy(vtbl);
    }
    
    // Return to root
    tree->chdir("/");
    
    msg("[VTable Tree] Tree built successfully\n");
}

void IntegratedTreeExplorer::add_vtable_with_hierarchy(const VTBL_info_t& vtbl) {
    // Parse RTTI for this vtable
    RTTIInfo rtti_info;
    bool has_rtti = CompilerRTTIParser::parse_vtable_rtti(vtbl, rtti_info);
    
    // Create vtable node
    inode_t vtbl_inode = spec->add_vtable_node(vtbl);
    
    // Get class name from RTTI or vtable name
    qstring class_name;
    qstring compiler_tag;
    
    if (has_rtti) {
        class_name = rtti_info.class_name;
        
        // Add compiler tag
        switch (rtti_info.compiler) {
            case RTTIInfo::COMPILER_MSVC:
                compiler_tag = " [MSVC]";
                break;
            case RTTIInfo::COMPILER_GCC:
                compiler_tag = " [GCC]";
                break;
            case RTTIInfo::COMPILER_CLANG:
                compiler_tag = " [Clang]";
                break;
            default:
                break;
        }
    } else {
        // Fallback to vtable name
        class_name = vtbl.vtbl_name;
        if (class_name.find("vtable for") != qstring::npos) {
            class_name.remove(0, 11);
        }
        if (class_name[0] == '\'') {
            class_name.remove(0, 1);
            size_t pos = class_name.find('\'');
            if (pos != qstring::npos) {
                class_name.remove(pos, 1);
            }
        }
    }
    
    // Create folder for this vtable with RTTI info
    qstring folder_name;
    if (has_rtti && rtti_info.num_base_classes > 0) {
        folder_name.sprnt("📁 %s%s [%d methods, %d base%s]", 
                         class_name.c_str(), compiler_tag.c_str(),
                         vtbl.methods, 
                         rtti_info.num_base_classes,
                         rtti_info.num_base_classes > 1 ? "s" : "");
    } else {
        folder_name.sprnt("📁 %s%s [%d methods]", 
                         class_name.c_str(), compiler_tag.c_str(),
                         vtbl.methods);
    }
    
    tree->mkdir(folder_name.c_str());
    tree->chdir(folder_name.c_str());
    
    // Analyze methods for pure virtuals
    size_t pure_virtual_count = 0;
    qvector<size_t> pure_indices;
    qvector<size_t> regular_indices;
    
    for (size_t i = 0; i < vtbl.methods; i++) {
        // Get method address from vtable
        size_t ptr_size = inf_is_64bit() ? 8 : 4;
        ea_t method_addr;
        if (inf_is_64bit()) {
            method_addr = get_qword(vtbl.ea_begin + i * ptr_size);
        } else {
            method_addr = get_dword(vtbl.ea_begin + i * ptr_size);
        }
        if (RTTITreeHelper::is_pure_virtual(method_addr)) {
            pure_virtual_count++;
            pure_indices.push_back(i);
        } else {
            regular_indices.push_back(i);
        }
    }
    
    // Add regular methods
    for (size_t idx : regular_indices) {
        inode_t method_inode = spec->add_method_node(vtbl, idx, false, "");
        tree->link(method_inode);
    }
    
    // Add pure virtual methods in separate folder
    if (pure_virtual_count > 0) {
        qstring pure_folder;
        pure_folder.sprnt("📁 Pure Virtual [%d method%s]", 
                         pure_virtual_count,
                         pure_virtual_count > 1 ? "s" : "");
        tree->mkdir(pure_folder.c_str());
        tree->chdir(pure_folder.c_str());
        
        for (size_t idx : pure_indices) {
            inode_t method_inode = spec->add_method_node(vtbl, idx, false, "");
            tree->link(method_inode);
        }
        
        tree->chdir("..");
    }
    
    // Add inheritance information from RTTI
    if (has_rtti && !rtti_info.base_classes.empty()) {
        for (const auto& base : rtti_info.base_classes) {
            qstring inherit_folder;
            inherit_folder.sprnt("📁 Inherited from %s%s", 
                                base.name.c_str(),
                                base.is_virtual ? " (virtual)" : "");
            
            inode_t inherited_folder = spec->add_inherited_folder(base.name, 0);
            tree->link(inherited_folder);
            
            // If we have the base vtable, we could add its methods here
            // This would require cross-referencing vtables
        }
    }
    
    // Add RTTI info node if available
    if (has_rtti) {
        qstring rtti_node_name;
        rtti_node_name.sprnt("📋 RTTI: %s", rtti_info.type_string.c_str());
        
        // Create a special RTTI info node
        inode_t rtti_node = spec->add_folder_node(rtti_node_name, 
                                                  VTableHierarchySpec::NODE_ROOT);
        tree->link(rtti_node);
    }
    
    // Return to parent
    tree->chdir("..");
}

void IntegratedTreeExplorer::populate_index_mapping() {
    index_to_inode.clear();
    inode_to_index.clear();
    
    // Traverse tree and build mapping
    class IndexMapper : public dirtree_visitor_t {
    public:
        qvector<inode_t>* index_to_inode;
        std::map<inode_t, size_t>* inode_to_index;
        
        virtual ssize_t visit(const dirtree_cursor_t &c, const direntry_t &de) override {
            if (!de.isdir && de.idx != inode_t(-1)) {
                size_t index = index_to_inode->size();
                index_to_inode->push_back(de.idx);
                (*inode_to_index)[de.idx] = index;
            }
            return 0;
        }
    };
    
    IndexMapper mapper;
    mapper.index_to_inode = &index_to_inode;
    mapper.inode_to_index = &inode_to_index;
    
    tree->traverse(mapper);
    
    msg("[VTable Tree] Mapped %d items\n", index_to_inode.size());
}

void IntegratedTreeExplorer::show() {
    msg("[VTable Tree] show() called\n");
    
    if (g_integrated_tree) {
        // Reuse existing instance
        g_integrated_tree->choose();
    } else {
        // Create new instance
        g_integrated_tree = new IntegratedTreeExplorer();
        g_integrated_tree->choose();
    }
}

//-------------------------------------------------------------------------
// Global Functions
//-------------------------------------------------------------------------

void init_integrated_tree_explorer() {
    msg("[VTable Tree] Initializing integrated tree explorer\n");
}

void term_integrated_tree_explorer() {
    msg("[VTable Tree] Terminating integrated tree explorer\n");
    
    if (g_integrated_tree) {
        delete g_integrated_tree;
        g_integrated_tree = nullptr;
    }
}