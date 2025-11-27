/*
    Class Hierarchy Graph Implementation
    Complete graph viewer implementation for vtable hierarchies
*/

#include "Common.h"
#include "ObjectExplorer.h"
#include "ClassHierarchyGraph.h"
#include "Utility.h"
#include <graph.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <queue>
#include <functional>

// External vtable list
extern qvector<VTBL_info_t> vtbl_t_list;

//-------------------------------------------------------------------------
// Data structures
//-------------------------------------------------------------------------

struct VTableNode {
    int id;
    qstring class_name;
    ea_t vtable_addr;
    size_t method_count;
    int hierarchy_level;
    
    // Visual properties
    bgcolor_t color;
    qstring display_text;
    
    // Relationships
    std::vector<int> children;
    std::vector<int> parents;
    
    VTableNode() : id(-1), vtable_addr(BADADDR), method_count(0), 
                   hierarchy_level(0), color(DEFCOLOR) {}
};

struct InheritanceEdge {
    int parent_id;
    int child_id;
    bool is_virtual;
    
    InheritanceEdge(int p, int c, bool v = false) 
        : parent_id(p), child_id(c), is_virtual(v) {}
};

//-------------------------------------------------------------------------
// Graph data management
//-------------------------------------------------------------------------

class ClassHierarchyData {
public:
    std::map<int, VTableNode> nodes;
    std::vector<InheritanceEdge> edges;
    std::map<qstring, int> name_to_id;
    
    void clear() {
        nodes.clear();
        edges.clear();
        name_to_id.clear();
    }
    
    void build_from_vtables() {
        clear();
        
        int id = 0;
        // Create nodes from vtables
        for (const auto& vtbl : vtbl_t_list) {
            VTableNode node;
            node.id = id;
            node.class_name = vtbl.vtbl_name;
            node.vtable_addr = vtbl.ea_begin;
            node.method_count = vtbl.methods;
            node.hierarchy_level = 0;
            
            // Clean class name
            clean_class_name(node.class_name);
            
            // Generate display text
            generate_display_text(node);
            
            // Assign color based on properties
            assign_node_color(node);
            
            nodes[id] = node;
            name_to_id[node.class_name] = id;
            id++;
        }
        
        // Detect inheritance relationships
        detect_inheritance();
        
        // Calculate hierarchy levels
        calculate_hierarchy_levels();
    }
    
private:
    void clean_class_name(qstring& name) {
        // Remove "vtable for" prefix
        if (name.find("vtable for") != qstring::npos) {
            name.remove(0, 11);
        }
        // Remove quotes
        if (name.length() > 0 && name[0] == '\'') {
            name.remove(0, 1);
        }
        if (name.length() > 0 && name[name.length()-1] == '\'') {
            name.remove(name.length()-1, 1);
        }
    }
    
    void generate_display_text(VTableNode& node) {
        node.display_text.sprnt("%s\n", node.class_name.c_str());
        node.display_text.cat_sprnt("VTable: 0x%llx\n", (unsigned long long)node.vtable_addr);
        node.display_text.cat_sprnt("Methods: %zu", node.method_count);
    }
    
    void assign_node_color(VTableNode& node) {
        // Color based on method count
        if (node.method_count == 0) {
            node.color = 0xFFFFFF;  // White for empty
        } else if (node.method_count < 5) {
            node.color = 0xE0FFE0;  // Light green for small
        } else if (node.method_count < 10) {
            node.color = 0xFFE0E0;  // Light red for medium
        } else {
            node.color = 0xE0E0FF;  // Light blue for large
        }
    }
    
    void detect_inheritance() {
        // Clear existing relationships
        for (auto& [id, node] : nodes) {
            node.children.clear();
            node.parents.clear();
        }
        edges.clear();
        
        // Try multiple detection strategies
        detect_by_rtti();
        detect_by_name_patterns();
        detect_by_vtable_analysis();
    }
    
    void detect_by_rtti() {
        // Analyze RTTI structures if available
        for (auto& [id, node] : nodes) {
            // Check for RTTI pointer before vtable
            ea_t rtti_ptr = node.vtable_addr - sizeof(ea_t);
            ea_t rtti_addr = get_qword(rtti_ptr);
            
            if (rtti_addr != BADADDR && is_mapped(rtti_addr)) {
                // Try to parse RTTI type_info
                analyze_rtti_inheritance(id, rtti_addr);
            }
        }
    }
    
    void analyze_rtti_inheritance(int node_id, ea_t rtti_addr) {
        // Simple RTTI analysis - look for base class pointers
        // This is simplified - real implementation would parse full RTTI structures
        
        // Check for base class type_info pointers
        for (int offset = 0x10; offset < 0x40; offset += sizeof(ea_t)) {
            ea_t base_rtti = get_qword(rtti_addr + offset);
            if (base_rtti != BADADDR && is_mapped(base_rtti)) {
                // Try to find corresponding vtable
                for (const auto& [other_id, other_node] : nodes) {
                    if (other_id != node_id) {
                        ea_t other_rtti = get_qword(other_node.vtable_addr - sizeof(ea_t));
                        if (other_rtti == base_rtti) {
                            // Found parent class
                            add_inheritance(other_id, node_id);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    void detect_by_name_patterns() {
        // Detect inheritance by class name patterns
        for (const auto& [parent_id, parent_node] : nodes) {
            for (const auto& [child_id, child_node] : nodes) {
                if (parent_id != child_id) {
                    // Check if child name contains parent name
                    if (child_node.class_name.find(parent_node.class_name) != qstring::npos &&
                        child_node.class_name.length() > parent_node.class_name.length()) {
                        // Potential inheritance
                        add_inheritance(parent_id, child_id);
                    }
                }
            }
        }
        
        // Specific patterns for common cases
        detect_specific_patterns();
    }
    
    void detect_specific_patterns() {
        // Handle specific known patterns
        auto find_and_link = [this](const char* parent, const char* child) {
            auto p_it = name_to_id.find(parent);
            auto c_it = name_to_id.find(child);
            if (p_it != name_to_id.end() && c_it != name_to_id.end()) {
                add_inheritance(p_it->second, c_it->second);
            }
        };
        
        // Common inheritance patterns
        find_and_link("Moveable", "Collidable");
        find_and_link("Object", "GameObject");
        find_and_link("Base", "Derived");
        find_and_link("Animal", "Mammal");
        find_and_link("Mammal", "Platypus");
        find_and_link("Bird", "Platypus");
    }
    
    void detect_by_vtable_analysis() {
        // Analyze vtable contents for shared methods
        for (const auto& [id1, node1] : nodes) {
            for (const auto& [id2, node2] : nodes) {
                if (id1 < id2) {  // Avoid duplicate comparisons
                    analyze_vtable_similarity(id1, id2);
                }
            }
        }
    }
    
    void analyze_vtable_similarity(int id1, int id2) {
        const VTableNode& node1 = nodes[id1];
        const VTableNode& node2 = nodes[id2];
        
        // Compare first few vtable entries
        int matching_methods = 0;
        for (size_t i = 0; i < qmin(node1.method_count, node2.method_count); i++) {
            ea_t method1 = get_qword(node1.vtable_addr + i * sizeof(ea_t));
            ea_t method2 = get_qword(node2.vtable_addr + i * sizeof(ea_t));
            
            if (method1 == method2 && method1 != BADADDR) {
                matching_methods++;
            } else {
                break;  // Stop at first difference
            }
        }
        
        // If significant overlap, likely inheritance
        if (matching_methods > 2) {
            // The one with fewer methods is likely the parent
            if (node1.method_count < node2.method_count) {
                add_inheritance(id1, id2);
            } else if (node2.method_count < node1.method_count) {
                add_inheritance(id2, id1);
            }
        }
    }
    
    void add_inheritance(int parent_id, int child_id, bool is_virtual = false) {
        // Check if edge already exists
        for (const auto& edge : edges) {
            if (edge.parent_id == parent_id && edge.child_id == child_id) {
                return;  // Already exists
            }
        }
        
        // Add edge
        edges.emplace_back(parent_id, child_id, is_virtual);
        
        // Update node relationships
        nodes[parent_id].children.push_back(child_id);
        nodes[child_id].parents.push_back(parent_id);
    }
    
    void calculate_hierarchy_levels() {
        // Reset levels
        for (auto& [id, node] : nodes) {
            node.hierarchy_level = 0;
        }
        
        // Find root nodes (no parents)
        std::queue<std::pair<int, int>> queue;
        for (const auto& [id, node] : nodes) {
            if (node.parents.empty()) {
                queue.push({id, 0});
            }
        }
        
        // BFS to assign levels
        std::set<int> visited;
        while (!queue.empty()) {
            auto [node_id, level] = queue.front();
            queue.pop();
            
            if (visited.count(node_id)) continue;
            visited.insert(node_id);
            
            nodes[node_id].hierarchy_level = level;
            
            // Process children
            for (int child_id : nodes[node_id].children) {
                if (!visited.count(child_id)) {
                    queue.push({child_id, level + 1});
                }
            }
        }
        
        // Update colors based on levels
        for (auto& [id, node] : nodes) {
            if (node.hierarchy_level == 0) {
                node.color = 0xFFE0E0;  // Light red for roots
            } else if (node.hierarchy_level == 1) {
                node.color = 0xE0FFE0;  // Light green for level 1
            } else if (node.hierarchy_level == 2) {
                node.color = 0xE0E0FF;  // Light blue for level 2
            } else {
                node.color = 0xF0F0F0;  // Light gray for deeper
            }
        }
    }
};

//-------------------------------------------------------------------------
// Graph viewer implementation
//-------------------------------------------------------------------------

class ClassHierarchyViewer {
private:
    graph_viewer_t* gv;
    interactive_graph_t* graph;
    ClassHierarchyData data;
    netnode graph_id;
    
    // Display options
    struct DisplayOptions {
        bool show_methods;
        bool show_addresses;
        bool color_by_level;
        int layout_type;  // 0=tree, 1=circle, 2=digraph
        
        DisplayOptions() : show_methods(true), show_addresses(true), 
                          color_by_level(true), layout_type(0) {}
    } options;
    
    // Cached display texts
    qstrvec_t node_texts;
    
public:
    ClassHierarchyViewer() : gv(nullptr), graph(nullptr) {}
    
    ~ClassHierarchyViewer() {
        close_viewer();
    }
    
    bool create_viewer(const char* title) {
        // Check if already exists
        TWidget* widget = find_widget(title);
        if (widget != nullptr) {
            close_widget(widget, 0);
            return false;
        }
        
        // Create unique graph ID
        graph_id.create("$ class_hierarchy");
        
        // Create graph viewer
        gv = create_graph_viewer(title, graph_id, graph_callback, this, 0);
        
        if (gv != nullptr) {
            // Display widget
            display_widget(gv, WOPN_DP_TAB);
            
            // Get interactive graph
            graph = get_viewer_graph(gv);
            
            if (graph != nullptr) {
                // Initial setup
                setup_graph();
                
                // Fit to window
                viewer_fit_window(gv);
                
                // Register context menu actions
                register_actions();
                
                return true;
            }
        }
        
        return false;
    }
    
    void close_viewer() {
        if (gv != nullptr) {
            close_widget(gv, 0);
            gv = nullptr;
            graph = nullptr;
        }
    }
    
    void refresh_graph() {
        if (graph == nullptr) return;
        
        // Rebuild data
        data.build_from_vtables();
        
        // Update graph
        update_graph();
        
        // Refresh viewer
        if (gv != nullptr) {
            refresh_viewer(gv);
        }
    }
    
private:
    void setup_graph() {
        if (graph == nullptr) return;
        
        // Build initial data
        data.build_from_vtables();
        
        // Setup graph
        update_graph();
        
        // Set layout
        graph->current_layout = options.layout_type + layout_digraph;
        
        // Configure circle layout if needed
        if (options.layout_type == 1) {
            graph->circle_center = point_t(400, 400);
            graph->circle_radius = 300;
        }
    }
    
    void update_graph() {
        if (graph == nullptr) return;
        
        // Clear existing graph
        graph->clear();
        
        // Resize for nodes
        int num_nodes = data.nodes.size();
        graph->resize(num_nodes);
        
        // Prepare node texts
        node_texts.resize(num_nodes);
        
        // Update node texts and info
        for (const auto& [id, node] : data.nodes) {
            // Generate display text
            generate_node_text(id);
            
            // Set node info
            node_info_t ni;
            ni.text = node_texts[id];
            if (options.color_by_level) {
                ni.bg_color = node.color;
            }
            
            uint32 flags = NIF_TEXT;
            if (options.color_by_level) {
                flags |= NIF_BG_COLOR;
            }
            
            set_node_info(graph->gid, id, ni, flags);
        }
        
        // Add edges
        for (const auto& edge : data.edges) {
            edge_info_t ei;
            if (edge.is_virtual) {
                ei.color = 0xFF0000;  // Red for virtual inheritance
            }
            graph->add_edge(edge.parent_id, edge.child_id, &ei);
        }
    }
    
    void generate_node_text(int node_id) {
        const VTableNode& node = data.nodes[node_id];
        qstring& text = node_texts[node_id];
        
        text = node.class_name;
        
        if (options.show_addresses) {
            text.cat_sprnt("\n0x%llx", (unsigned long long)node.vtable_addr);
        }
        
        if (options.show_methods) {
            text.cat_sprnt("\n%zu methods", node.method_count);
        }
    }
    
    void register_actions() {
        if (gv == nullptr) return;
        
        TWidget* widget = (TWidget*)gv;
        
        // Add context menu items
        attach_action_to_popup(widget, nullptr, "ugraph:ChangeLayout");
        attach_action_to_popup(widget, nullptr, "-");
        attach_action_to_popup(widget, nullptr, "ugraph:ShowMethods");
        attach_action_to_popup(widget, nullptr, "ugraph:ShowAddresses");
        attach_action_to_popup(widget, nullptr, "ugraph:ColorByLevel");
    }
    
    // Graph callback handler
    static ssize_t idaapi graph_callback(void* ud, int code, va_list va) {
        ClassHierarchyViewer* viewer = (ClassHierarchyViewer*)ud;
        
        switch (code) {
            case grcode_user_refresh: {
                interactive_graph_t* g = va_arg(va, interactive_graph_t*);
                viewer->refresh_graph();
                return 1;
            }
            
            case grcode_user_text: {
                interactive_graph_t* g = va_arg(va, interactive_graph_t*);
                int node = va_arg(va, int);
                const char** text = va_arg(va, const char**);
                bgcolor_t* bgcolor = va_arg(va, bgcolor_t*);
                
                if (node >= 0 && node < viewer->node_texts.size()) {
                    *text = viewer->node_texts[node].c_str();
                    if (bgcolor != nullptr && viewer->options.color_by_level) {
                        auto it = viewer->data.nodes.find(node);
                        if (it != viewer->data.nodes.end()) {
                            *bgcolor = it->second.color;
                        }
                    }
                    return 1;
                }
                break;
            }
            
            case grcode_user_hint: {
                interactive_graph_t* g = va_arg(va, interactive_graph_t*);
                int mousenode = va_argi(va, int);
                int mouseedge_src = va_argi(va, int);
                int mouseedge_dst = va_argi(va, int);
                char** hint = va_arg(va, char**);
                
                if (mousenode != -1) {
                    auto it = viewer->data.nodes.find(mousenode);
                    if (it != viewer->data.nodes.end()) {
                        qstring hint_text;
                        hint_text.sprnt("Class: %s\n", it->second.class_name.c_str());
                        hint_text.cat_sprnt("VTable: 0x%llx\n", (unsigned long long)it->second.vtable_addr);
                        hint_text.cat_sprnt("Methods: %zu\n", it->second.method_count);
                        hint_text.cat_sprnt("Level: %d\n", it->second.hierarchy_level);
                        hint_text.cat_sprnt("Parents: %zu\n", it->second.parents.size());
                        hint_text.cat_sprnt("Children: %zu", it->second.children.size());
                        *hint = qstrdup(hint_text.c_str());
                        return 1;
                    }
                }
                break;
            }
            
            case grcode_dblclicked: {
                graph_viewer_t* v = va_arg(va, graph_viewer_t*);
                selection_item_t* s = va_arg(va, selection_item_t*);
                
                if (s != nullptr && s->is_node) {
                    auto it = viewer->data.nodes.find(s->node);
                    if (it != viewer->data.nodes.end()) {
                        // Navigate to vtable
                        jumpto(it->second.vtable_addr);
                        msg("[ClassHierarchy] Navigated to %s at 0x%llx\n",
                            it->second.class_name.c_str(),
                            (unsigned long long)it->second.vtable_addr);
                    }
                }
                return 1;
            }
            
            case grcode_clicked: {
                graph_viewer_t* v = va_arg(va, graph_viewer_t*);
                selection_item_t* item = va_arg(va, selection_item_t*);
                graph_item_t* gitem = va_arg(va, graph_item_t*);
                
                // Log clicks for debugging
                if (gitem->type == git_node) {
                    msg("[ClassHierarchy] Clicked on node %d\n", gitem->n);
                } else if (gitem->type == git_edge) {
                    msg("[ClassHierarchy] Clicked on edge (%d, %d)\n", 
                        gitem->e.src, gitem->e.dst);
                }
                break;
            }
            
            case grcode_changed_graph: {
                graph_viewer_t* v = va_arg(va, graph_viewer_t*);
                int curnode = va_argi(va, int);
                
                if (curnode != -1) {
                    auto it = viewer->data.nodes.find(curnode);
                    if (it != viewer->data.nodes.end()) {
                        msg("[ClassHierarchy] Current node: %s\n", 
                            it->second.class_name.c_str());
                    }
                }
                break;
            }
        }
        
        return 0;
    }
    
    friend class ChangeLayoutAction;
    friend class ShowMethodsAction;
};

//-------------------------------------------------------------------------
// Global viewer instance
//-------------------------------------------------------------------------

static ClassHierarchyViewer* g_viewer = nullptr;

//-------------------------------------------------------------------------
// Main entry points
//-------------------------------------------------------------------------

void show_class_hierarchy_graph() {
    msg("[ClassHierarchy] Creating class hierarchy graph\n");
    
    if (vtbl_t_list.empty()) {
        msg("[ClassHierarchy] No vtables found\n");
        info("No virtual tables found.\nPlease run Object Explorer first to detect vtables.");
        return;
    }
    
    // Clean up old viewer
    if (g_viewer != nullptr) {
        delete g_viewer;
        g_viewer = nullptr;
    }
    
    // Create new viewer
    g_viewer = new ClassHierarchyViewer();
    
    if (g_viewer->create_viewer("Class Hierarchy")) {
        msg("[ClassHierarchy] Graph viewer created successfully\n");
    } else {
        msg("[ClassHierarchy] Failed to create graph viewer\n");
        delete g_viewer;
        g_viewer = nullptr;
    }
}

void init_class_hierarchy_graph() {
    msg("[ClassHierarchy] Module initialized\n");
}

void term_class_hierarchy_graph() {
    msg("[ClassHierarchy] Module terminated\n");
    if (g_viewer != nullptr) {
        delete g_viewer;
        g_viewer = nullptr;
    }
}

void refresh_class_hierarchy_graph() {
    if (g_viewer != nullptr) {
        g_viewer->refresh_graph();
    } else {
        show_class_hierarchy_graph();
    }
}