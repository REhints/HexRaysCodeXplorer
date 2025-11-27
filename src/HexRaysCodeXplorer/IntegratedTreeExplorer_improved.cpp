/*
    Enhanced Integrated Tree VTable Explorer Implementation
    Includes all high-priority improvements and advanced features
*/

#include "IntegratedTreeExplorer_improved.h"
#include "CompilerRTTIParser.h"
#include "ClangVTableParser.h"
#include "Utility.h"
#include <segment.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <algorithm>
#include <ctime>

// External vtable list
extern qvector<VTBL_info_t> vtbl_t_list;

// Global instance
IntegratedTreeExplorer* g_integrated_tree = nullptr;

//-------------------------------------------------------------------------
// MethodCache Implementation
//-------------------------------------------------------------------------

const method_info_t* MethodCache::get_method_info(ea_t method_ea) {
    auto it = cache.find(method_ea);
    if (it != cache.end()) {
        time_t now = time(nullptr);
        if (now - it->second.cached_at < cache_duration) {
            return &it->second;
        }
        // Cache expired, refresh
        refresh_method(method_ea);
        it = cache.find(method_ea);
        return (it != cache.end()) ? &it->second : nullptr;
    }
    
    // Not cached, analyze and cache
    method_info_t info;
    info.address = method_ea;
    info.cached_at = time(nullptr);
    
    // Get method name
    get_short_name(&info.name, method_ea);
    
    // Demangle
    qstring demangled;
    if (demangle_name(&demangled, info.name.c_str(), MNG_SHORT_FORM) > 0) {
        info.demangled_name = demangled;
    } else {
        info.demangled_name = info.name;
    }
    
    // Check for special methods
    info.is_pure_virtual = (info.name.find("purecall") != qstring::npos || 
                           info.name.find("pure_virtual") != qstring::npos);
    info.is_destructor = (info.demangled_name[0] == '~' || 
                         info.demangled_name.find("destructor") != qstring::npos);
    info.is_constructor = (info.demangled_name.find("ctor") != qstring::npos ||
                          info.demangled_name.find("constructor") != qstring::npos);
    
    // Analyze cross-references
    analyze_xrefs(method_ea, info);
    
    // Check if it's a thunk
    func_t* func = get_func(method_ea);
    if (func) {
        if (func->flags & FUNC_THUNK) {
            info.is_thunk = true;
        }
    }
    
    cache[method_ea] = info;
    return &cache[method_ea];
}

void MethodCache::analyze_xrefs(ea_t method_ea, method_info_t& info) {
    info.xref_count = 0;
    info.callers.clear();
    info.callees.clear();
    
    // Get xrefs to this method (callers)
    xrefblk_t xb;
    for (bool ok = xb.first_to(method_ea, XREF_ALL); ok; ok = xb.next_to()) {
        if (xb.type == fl_CN || xb.type == fl_CF) {
            info.callers.push_back(xb.from);
            info.xref_count++;
        }
    }
    
    // Get xrefs from this method (callees)
    func_t* func = get_func(method_ea);
    if (func) {
        ea_t ea = func->start_ea;
        while (ea < func->end_ea) {
            xrefblk_t xb;
            for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
                if (xb.type == fl_CN || xb.type == fl_CF) {
                    info.callees.push_back(xb.to);
                }
            }
            ea = next_head(ea, func->end_ea);
        }
    }
}

void MethodCache::cache_method(ea_t method_ea, const method_info_t& info) {
    cache[method_ea] = info;
    cache[method_ea].cached_at = time(nullptr);
}

void MethodCache::clear_cache() {
    cache.clear();
}

void MethodCache::refresh_method(ea_t method_ea) {
    auto it = cache.find(method_ea);
    if (it != cache.end()) {
        analyze_xrefs(method_ea, it->second);
        it->second.cached_at = time(nullptr);
    }
}

bool MethodCache::is_cached(ea_t method_ea) const {
    return cache.find(method_ea) != cache.end();
}

void MethodCache::cache_vtable_methods(const VTBL_info_t& vtbl) {
    size_t ptr_size = inf_is_64bit() ? 8 : 4;
    
    for (size_t i = 0; i < vtbl.methods; i++) {
        ea_t entry_ea = vtbl.ea_begin + i * ptr_size;
        ea_t method_ea = inf_is_64bit() ? get_qword(entry_ea) : get_dword(entry_ea);
        
        if (method_ea != BADADDR && method_ea != 0) {
            if (!is_cached(method_ea)) {
                get_method_info(method_ea);  // This will cache it
            }
        }
    }
}

//-------------------------------------------------------------------------
// InheritanceAnalyzer Implementation
//-------------------------------------------------------------------------

void InheritanceAnalyzer::analyze_all_vtables(const qvector<VTBL_info_t>& vtables) {
    vtable_layouts.clear();
    
    size_t ptr_size = inf_is_64bit() ? 8 : 4;
    
    for (const auto& vtbl : vtables) {
        vtable_layout_t layout;
        layout.vtable_ea = vtbl.ea_begin;
        layout.class_name = vtbl.vtbl_name;
        layout.unique_methods = 0;
        layout.overridden_methods = 0;
        
        // Extract method addresses
        for (size_t i = 0; i < vtbl.methods; i++) {
            ea_t entry_ea = vtbl.ea_begin + i * ptr_size;
            ea_t method_ea = inf_is_64bit() ? get_qword(entry_ea) : get_dword(entry_ea);
            
            if (method_ea != BADADDR && method_ea != 0) {
                layout.method_addresses.push_back(method_ea);
                layout.method_indices.push_back(i);
            }
        }
        
        vtable_layouts[vtbl.ea_begin] = layout;
    }
    
    // Now detect relationships
    detect_inheritance_relationships();
}

void InheritanceAnalyzer::detect_inheritance_relationships() {
    relations.clear();
    inheritance_tree.clear();
    
    // Compare all vtable pairs
    for (auto& [ea1, layout1] : vtable_layouts) {
        for (auto& [ea2, layout2] : vtable_layouts) {
            if (ea1 >= ea2) continue;  // Skip self and already compared pairs
            
            float similarity = calculate_vtable_similarity(ea1, ea2);
            
            // If similarity is high enough, they might be related
            if (similarity > 0.5) {
                inheritance_relation_t rel;
                
                // Determine which is base and which is derived
                // Generally, derived classes have more methods
                if (layout1.method_addresses.size() > layout2.method_addresses.size()) {
                    rel.derived_vtable = ea1;
                    rel.base_vtable = ea2;
                    rel.derived_class = layout1.class_name;
                    rel.base_class = layout2.class_name;
                } else {
                    rel.derived_vtable = ea2;
                    rel.base_vtable = ea1;
                    rel.derived_class = layout2.class_name;
                    rel.base_class = layout1.class_name;
                }
                
                rel.similarity_score = similarity;
                
                // Find common and overridden methods
                auto& base_layout = (rel.base_vtable == ea1) ? layout1 : layout2;
                auto& derived_layout = (rel.derived_vtable == ea1) ? layout1 : layout2;
                
                rel.common_methods = 0;
                for (size_t i = 0; i < base_layout.method_addresses.size() && 
                                    i < derived_layout.method_addresses.size(); i++) {
                    if (base_layout.method_addresses[i] == derived_layout.method_addresses[i]) {
                        rel.common_methods++;
                    } else {
                        rel.overridden_indices.push_back(i);
                        derived_layout.overridden_methods++;
                    }
                }
                
                // Find new methods in derived
                for (size_t i = base_layout.method_addresses.size(); 
                     i < derived_layout.method_addresses.size(); i++) {
                    rel.new_method_indices.push_back(i);
                    derived_layout.unique_methods++;
                }
                
                relations.push_back(rel);
                inheritance_tree[rel.derived_vtable].push_back(rel.base_vtable);
            }
        }
    }
}

float InheritanceAnalyzer::calculate_vtable_similarity(ea_t vtbl1, ea_t vtbl2) {
    auto it1 = vtable_layouts.find(vtbl1);
    auto it2 = vtable_layouts.find(vtbl2);
    
    if (it1 == vtable_layouts.end() || it2 == vtable_layouts.end()) {
        return 0.0f;
    }
    
    auto& layout1 = it1->second;
    auto& layout2 = it2->second;
    
    // Empty vtables aren't similar
    if (layout1.method_addresses.empty() || layout2.method_addresses.empty()) {
        return 0.0f;
    }
    
    size_t common_methods = 0;
    size_t min_size = qmin(layout1.method_addresses.size(), layout2.method_addresses.size());
    
    // Check how many methods match at the same positions
    for (size_t i = 0; i < min_size; i++) {
        if (layout1.method_addresses[i] == layout2.method_addresses[i]) {
            common_methods++;
        }
    }
    
    // Calculate similarity score
    float position_similarity = (float)common_methods / min_size;
    
    // Also consider the size difference
    float size_ratio = (float)min_size / qmax(layout1.method_addresses.size(), 
                                               layout2.method_addresses.size());
    
    // Combined score
    return (position_similarity * 0.7f + size_ratio * 0.3f);
}

bool InheritanceAnalyzer::is_method_overridden(ea_t vtable, size_t method_idx) const {
    // Check if this method is different from any base class
    auto bases_it = inheritance_tree.find(vtable);
    if (bases_it == inheritance_tree.end()) {
        return false;
    }
    
    auto vtbl_it = vtable_layouts.find(vtable);
    if (vtbl_it == vtable_layouts.end() || method_idx >= vtbl_it->second.method_addresses.size()) {
        return false;
    }
    
    ea_t method_ea = vtbl_it->second.method_addresses[method_idx];
    
    for (ea_t base_vtable : bases_it->second) {
        auto base_it = vtable_layouts.find(base_vtable);
        if (base_it != vtable_layouts.end() && 
            method_idx < base_it->second.method_addresses.size()) {
            if (base_it->second.method_addresses[method_idx] != method_ea) {
                return true;  // Method is different from base
            }
        }
    }
    
    return false;
}

ea_t InheritanceAnalyzer::find_method_origin(ea_t vtable, size_t method_idx) const {
    auto vtbl_it = vtable_layouts.find(vtable);
    if (vtbl_it == vtable_layouts.end() || method_idx >= vtbl_it->second.method_addresses.size()) {
        return vtable;
    }
    
    ea_t method_ea = vtbl_it->second.method_addresses[method_idx];
    ea_t origin = vtable;
    
    // Walk up the inheritance tree to find where this method first appears
    auto bases_it = inheritance_tree.find(vtable);
    if (bases_it != inheritance_tree.end()) {
        for (ea_t base_vtable : bases_it->second) {
            auto base_it = vtable_layouts.find(base_vtable);
            if (base_it != vtable_layouts.end() && 
                method_idx < base_it->second.method_addresses.size() &&
                base_it->second.method_addresses[method_idx] == method_ea) {
                // Method exists in base with same address, so it originates there or higher
                origin = find_method_origin(base_vtable, method_idx);
            }
        }
    }
    
    return origin;
}

//-------------------------------------------------------------------------
// VTableSearcher Implementation
//-------------------------------------------------------------------------

qvector<VTableSearcher::search_result_t> VTableSearcher::search(const qstring& query, search_type_t type) {
    qvector<search_result_t> results;
    
    if (query.empty()) {
        return results;
    }
    
    // Convert query to lowercase for case-insensitive search
    qstring lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);
    
    // Search through all nodes
    for (const auto& [inode, info] : spec->nodes) {
        search_result_t result;
        result.node = inode;
        result.relevance = 0.0f;
        
        qstring lower_name = info.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        qstring lower_display = info.display_name;
        std::transform(lower_display.begin(), lower_display.end(), lower_display.begin(), ::tolower);
        
        switch (type) {
            case SEARCH_CLASS_NAME:
                if (info.type == VTableHierarchySpec::NODE_VTABLE) {
                    if (lower_name.find(lower_query) != qstring::npos) {
                        result.matched_text = info.name;
                        result.relevance = 1.0f - ((float)lower_name.find(lower_query) / lower_name.length());
                        results.push_back(result);
                    } else if (lower_display.find(lower_query) != qstring::npos) {
                        result.matched_text = info.display_name;
                        result.relevance = 0.8f - ((float)lower_display.find(lower_query) / lower_display.length());
                        results.push_back(result);
                    }
                }
                break;
                
            case SEARCH_METHOD_NAME:
                if (info.type == VTableHierarchySpec::NODE_METHOD || 
                    info.type == VTableHierarchySpec::NODE_PURE_VIRTUAL) {
                    if (lower_name.find(lower_query) != qstring::npos) {
                        result.matched_text = info.name;
                        result.relevance = 1.0f;
                        results.push_back(result);
                    }
                }
                break;
                
            case SEARCH_ADDRESS: {
                ea_t search_ea = BADADDR;
                if (query[0] == '0' && (query[1] == 'x' || query[1] == 'X')) {
                    search_ea = strtoull(query.c_str() + 2, nullptr, 16);
                } else {
                    search_ea = strtoull(query.c_str(), nullptr, 16);
                }
                
                if (search_ea != BADADDR && info.address == search_ea) {
                    result.matched_text.sprnt("0x%a", info.address);
                    result.relevance = 1.0f;
                    results.push_back(result);
                }
                break;
            }
                
            case SEARCH_PATTERN:
                try {
                    if (!current_regex._M_automaton) {
                        current_regex = std::regex(query.c_str(), std::regex::icase);
                    }
                    if (std::regex_search(info.name.c_str(), current_regex)) {
                        result.matched_text = info.name;
                        result.relevance = 0.9f;
                        results.push_back(result);
                    }
                } catch (...) {
                    // Invalid regex
                }
                break;
        }
    }
    
    // Sort by relevance
    std::sort(results.begin(), results.end(), 
              [](const search_result_t& a, const search_result_t& b) {
                  return a.relevance > b.relevance;
              });
    
    return results;
}

qvector<inode_t> VTableSearcher::find_pure_virtuals() {
    qvector<inode_t> results;
    
    for (const auto& [inode, info] : spec->nodes) {
        if (info.type == VTableHierarchySpec::NODE_PURE_VIRTUAL ||
            (info.type == VTableHierarchySpec::NODE_METHOD && info.is_pure_virtual)) {
            results.push_back(inode);
        }
    }
    
    return results;
}

qvector<inode_t> VTableSearcher::find_abstract_classes() {
    qvector<inode_t> results;
    std::set<ea_t> abstract_vtables;
    
    // Find vtables with pure virtual methods
    for (const auto& [inode, info] : spec->nodes) {
        if (info.type == VTableHierarchySpec::NODE_PURE_VIRTUAL && info.vtbl_info) {
            abstract_vtables.insert(info.vtbl_info->ea_begin);
        }
    }
    
    // Get the vtable nodes
    for (const auto& [inode, info] : spec->nodes) {
        if (info.type == VTableHierarchySpec::NODE_VTABLE && info.vtbl_info) {
            if (abstract_vtables.count(info.vtbl_info->ea_begin)) {
                results.push_back(inode);
            }
        }
    }
    
    return results;
}

//-------------------------------------------------------------------------
// VTableHierarchySpec Enhanced Implementation
//-------------------------------------------------------------------------

VTableHierarchySpec::VTableHierarchySpec() 
    : dirspec_t("vtable_hierarchy", DSF_ORDERABLE), next_inode(1) {
    
    method_cache = new MethodCache();
    inheritance_analyzer = new InheritanceAnalyzer();
    searcher = new VTableSearcher(this);
    
    msg("[VTable Tree] Enhanced VTableHierarchySpec initialized\n");
}

VTableHierarchySpec::~VTableHierarchySpec() {
    delete method_cache;
    delete inheritance_analyzer;
    delete searcher;
    
    // Clean up enhanced RTTI info
    for (auto& [inode, info] : nodes) {
        if (info.rtti_info) {
            delete info.rtti_info;
        }
        if (info.method_cache) {
            delete info.method_cache;
        }
    }
}

inode_t VTableHierarchySpec::add_vtable_node(const VTBL_info_t& vtbl, const enhanced_rtti_info_t* rtti) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = NODE_VTABLE;
    info.name = vtbl.vtbl_name;
    info.address = vtbl.ea_begin;
    info.vtbl_info = &vtbl;
    
    if (rtti) {
        // Copy enhanced RTTI info
        info.rtti_info = new enhanced_rtti_info_t(*rtti);
        info.display_name = rtti->class_name;
        
        // Add compiler tag
        if (!rtti->compiler_name.empty()) {
            info.display_name.append(" [");
            info.display_name.append(rtti->compiler_name);
            info.display_name.append("]");
        }
        
        // Set icon based on properties
        if (rtti->is_abstract) {
            info.icon = 156;  // Warning icon for abstract
            info.color = 0x0080FF;  // Orange
        } else if (rtti->has_virtual_destructor) {
            info.icon = 59;  // Class icon
            info.color = 0x00FF00;  // Green
        } else {
            info.icon = 59;
            info.color = 0x808080;  // Gray
        }
        
        // Build tooltip
        info.tooltip.sprnt("Class: %s\n", rtti->class_name.c_str());
        if (!rtti->namespaces.empty()) {
            info.tooltip.append("Namespace: ");
            for (size_t i = 0; i < rtti->namespaces.size(); i++) {
                if (i > 0) info.tooltip.append("::");
                info.tooltip.append(rtti->namespaces[i]);
            }
            info.tooltip.append("\n");
        }
        info.tooltip.cat_sprnt("Methods: %d\n", vtbl.methods);
        if (rtti->is_abstract) {
            info.tooltip.append("Abstract: Yes\n");
        }
        if (rtti->has_virtual_destructor) {
            info.tooltip.append("Virtual Destructor: Yes\n");
        }
        if (!rtti->base_classes.empty()) {
            info.tooltip.cat_sprnt("Base Classes: %d\n", rtti->base_classes.size());
            for (const auto& base : rtti->base_classes) {
                info.tooltip.cat_sprnt("  - %s%s\n", 
                                       base.name.c_str(),
                                       base.is_virtual ? " (virtual)" : "");
            }
        }
        
        // Add search tags
        info.search_tags.push_back(rtti->class_name);
        info.search_tags.push_back(rtti->mangled_name);
        for (const auto& ns : rtti->namespaces) {
            info.search_tags.push_back(ns);
        }
    } else {
        // Fallback without RTTI
        info.display_name = vtbl.vtbl_name;
        info.icon = 59;
        info.color = 0x808080;
    }
    
    nodes[inode] = info;
    vtable_to_inode[vtbl.ea_begin] = inode;
    
    return inode;
}

inode_t VTableHierarchySpec::add_method_node(const VTBL_info_t& vtbl, size_t idx, 
                                             const method_info_t* minfo) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.method_index = idx;
    
    if (minfo) {
        // Use cached method info
        info.method_cache = new method_info_t(*minfo);
        info.address = minfo->address;
        info.is_pure_virtual = minfo->is_pure_virtual;
        info.is_destructor = minfo->is_destructor;
        info.is_inherited = minfo->is_overridden ? false : true;
        info.is_overridden = minfo->is_overridden;
        info.xref_count = minfo->xref_count;
        info.xrefs_to = minfo->callers;
        info.xrefs_from = minfo->callees;
        
        // Set type based on method properties
        if (minfo->is_pure_virtual) {
            info.type = NODE_PURE_VIRTUAL;
            info.icon = 156;  // Warning icon
            info.color = 0x0000FF;  // Red
        } else if (minfo->is_overridden) {
            info.type = NODE_OVERRIDDEN;
            info.icon = 42;  // Function icon
            info.color = 0x00FF00;  // Green
        } else {
            info.type = NODE_METHOD;
            info.icon = 42;
            info.color = 0xFF8000;  // Blue
        }
        
        // Format display name with xref count
        if (info.xref_count > 0) {
            info.name.sprnt("%s [%d xrefs]", minfo->demangled_name.c_str(), info.xref_count);
        } else {
            info.name = minfo->demangled_name;
        }
        
        // Build tooltip
        info.tooltip.sprnt("Address: 0x%a\n", minfo->address);
        info.tooltip.cat_sprnt("Name: %s\n", minfo->name.c_str());
        if (!minfo->demangled_name.empty() && minfo->demangled_name != minfo->name) {
            info.tooltip.cat_sprnt("Demangled: %s\n", minfo->demangled_name.c_str());
        }
        info.tooltip.cat_sprnt("Xrefs: %d\n", info.xref_count);
        if (minfo->is_thunk) {
            info.tooltip.append("Type: Thunk\n");
        }
        if (minfo->is_overridden) {
            info.tooltip.append("Status: Overridden\n");
        }
        
    } else {
        // Fallback - calculate method info on the fly
        info.type = NODE_METHOD;
        size_t ptr_size = inf_is_64bit() ? 8 : 4;
        ea_t entry_ea = vtbl.ea_begin + idx * ptr_size;
        ea_t method_ea = inf_is_64bit() ? get_qword(entry_ea) : get_dword(entry_ea);
        
        if (method_ea != BADADDR) {
            info.address = method_ea;
            
            qstring method_name;
            get_short_name(&method_name, method_ea);
            
            // Demangle
            qstring demangled;
            if (demangle_name(&demangled, method_name.c_str(), MNG_SHORT_FORM) > 0) {
                info.name = demangled;
            } else {
                info.name = method_name;
            }
        }
        
        info.icon = 42;
        info.color = 0xFF8000;
    }
    
    info.display_name = info.name;
    nodes[inode] = info;
    
    return inode;
}

inode_t VTableHierarchySpec::add_rtti_node(const enhanced_rtti_info_t& rtti) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = NODE_RTTI_INFO;
    info.name = "RTTI Information";
    info.display_name = "📋 RTTI Details";
    info.icon = 91;  // Info icon
    info.color = 0x00FFFF;  // Yellow
    
    // Build detailed RTTI display
    info.tooltip = "=== RTTI Information ===\n";
    info.tooltip.cat_sprnt("Class: %s\n", rtti.class_name.c_str());
    info.tooltip.cat_sprnt("Mangled: %s\n", rtti.mangled_name.c_str());
    info.tooltip.cat_sprnt("Type String: %s\n", rtti.type_string.c_str());
    info.tooltip.cat_sprnt("Compiler: %s\n", rtti.compiler_name.c_str());
    
    if (!rtti.namespaces.empty()) {
        info.tooltip.append("\nNamespaces:\n");
        for (const auto& ns : rtti.namespaces) {
            info.tooltip.cat_sprnt("  - %s\n", ns.c_str());
        }
    }
    
    if (!rtti.base_classes.empty()) {
        info.tooltip.append("\nInheritance Hierarchy:\n");
        for (const auto& base : rtti.base_classes) {
            info.tooltip.cat_sprnt("  %s %s%s", 
                                   base.is_public ? "public" : "private",
                                   base.is_virtual ? "virtual " : "",
                                   base.name.c_str());
            if (base.offset != 0) {
                info.tooltip.cat_sprnt(" (offset: %d)", base.offset);
            }
            if (base.vtable_ea != BADADDR) {
                info.tooltip.cat_sprnt(" [vtable: 0x%a]", base.vtable_ea);
            }
            info.tooltip.append("\n");
        }
    }
    
    info.tooltip.append("\nProperties:\n");
    info.tooltip.cat_sprnt("  Abstract: %s\n", rtti.is_abstract ? "Yes" : "No");
    info.tooltip.cat_sprnt("  Polymorphic: %s\n", rtti.is_polymorphic ? "Yes" : "No");
    info.tooltip.cat_sprnt("  Virtual Destructor: %s\n", rtti.has_virtual_destructor ? "Yes" : "No");
    if (rtti.object_size > 0) {
        info.tooltip.cat_sprnt("  Object Size: %d bytes\n", rtti.object_size);
    }
    
    nodes[inode] = info;
    return inode;
}

inode_t VTableHierarchySpec::add_xref_node(ea_t address, const qvector<ea_t>& xrefs) {
    inode_t inode = alloc_inode();
    
    node_info_t info;
    info.type = NODE_XREF_INFO;
    info.address = address;
    info.xrefs_to = xrefs;
    info.xref_count = xrefs.size();
    
    info.name.sprnt("Cross-references (%d)", xrefs.size());
    info.display_name = "📊 " + info.name;
    info.icon = 182;  // Graph icon
    info.color = 0xFF00FF;  // Magenta
    
    // Build xref list
    info.tooltip = "Cross-references:\n";
    for (size_t i = 0; i < xrefs.size() && i < 20; i++) {
        qstring func_name;
        get_func_name(&func_name, xrefs[i]);
        if (func_name.empty()) {
            info.tooltip.cat_sprnt("  0x%a\n", xrefs[i]);
        } else {
            info.tooltip.cat_sprnt("  0x%a (%s)\n", xrefs[i], func_name.c_str());
        }
    }
    if (xrefs.size() > 20) {
        info.tooltip.cat_sprnt("  ... and %d more\n", xrefs.size() - 20);
    }
    
    nodes[inode] = info;
    return inode;
}

//-------------------------------------------------------------------------
// Context Menu Actions Implementation
//-------------------------------------------------------------------------

int analyze_xrefs_action_t::activate(action_activation_ctx_t *ctx) {
    if (explorer) {
        size_t n = explorer->get_selected_item();
        if (n != NO_SELECTION) {
            explorer->analyze_selected_xrefs(n);
        }
    }
    return 1;
}

int show_inheritance_action_t::activate(action_activation_ctx_t *ctx) {
    if (explorer) {
        size_t n = explorer->get_selected_item();
        if (n != NO_SELECTION) {
            explorer->show_inheritance_graph(n);
        }
    }
    return 1;
}

int export_subtree_action_t::activate(action_activation_ctx_t *ctx) {
    if (explorer) {
        const char* filename = ask_file(true, "*.json", "Export subtree to JSON");
        if (filename) {
            inode_t node = explorer->get_selected_inode();
            explorer->export_subtree(node, filename);
        }
    }
    return 1;
}

int find_similar_vtables_action_t::activate(action_activation_ctx_t *ctx) {
    if (explorer) {
        size_t n = explorer->get_selected_item();
        if (n != NO_SELECTION) {
            explorer->find_similar_vtables(n);
        }
    }
    return 1;
}

//-------------------------------------------------------------------------
// IntegratedTreeExplorer Enhanced Implementation
//-------------------------------------------------------------------------

// Column configuration
static const int tree_widths[] = { 40, 12, 15, 20, 8, 10 };
static const char *const tree_headers[] = { 
    "Name", 
    "Address", 
    "Type",
    "Info",
    "Xrefs",
    "Compiler"
};

IntegratedTreeExplorer::IntegratedTreeExplorer()
    : chooser_t(CH_KEEP | CH_RESTORE | CH_CAN_REFRESH | 
                CH_HAS_DIRTREE | CH_TM_FULL_TREE,
                qnumber(tree_widths), tree_widths, tree_headers),
      tree(nullptr), spec(nullptr), search_active(false), active_filters(0) {
    
    msg("[VTable Tree] Enhanced IntegratedTreeExplorer constructor\n");
    
    title = "Enhanced VTable Tree Explorer";
    
    spec = new VTableHierarchySpec();
    tree = new dirtree_t(spec);
    
    // Register context menu actions
    register_context_actions();
}

IntegratedTreeExplorer::~IntegratedTreeExplorer() {
    msg("[VTable Tree] Enhanced IntegratedTreeExplorer destructor\n");
    
    unregister_context_actions();
    
    delete tree;
    delete spec;
    
    if (g_integrated_tree == this) {
        g_integrated_tree = nullptr;
    }
}

void IntegratedTreeExplorer::register_context_actions() {
    // Define actions
    static const action_desc_t actions[] = {
        ACTION_DESC_LITERAL("vtree:analyze_xrefs", "Analyze Cross-references", 
                           new analyze_xrefs_action_t(this), "Ctrl+X", nullptr, -1),
        ACTION_DESC_LITERAL("vtree:show_inheritance", "Show Inheritance Graph", 
                           new show_inheritance_action_t(this), "Ctrl+I", nullptr, -1),
        ACTION_DESC_LITERAL("vtree:export_subtree", "Export Subtree...", 
                           new export_subtree_action_t(this), "Ctrl+E", nullptr, -1),
        ACTION_DESC_LITERAL("vtree:find_similar", "Find Similar VTables", 
                           new find_similar_vtables_action_t(this), "Ctrl+F", nullptr, -1),
    };
    
    for (const auto& action : actions) {
        register_action(action);
        context_actions.push_back(action);
    }
}

void IntegratedTreeExplorer::unregister_context_actions() {
    for (const auto& action : context_actions) {
        unregister_action(action.name);
    }
}

bool IntegratedTreeExplorer::init() {
    msg("[VTable Tree] Enhanced init() called\n");
    
    // Analyze all vtables first
    spec->get_inheritance_analyzer()->analyze_all_vtables(vtbl_t_list);
    
    // Cache all methods
    for (const auto& vtbl : vtbl_t_list) {
        spec->get_method_cache()->cache_vtable_methods(vtbl);
    }
    
    // Build the tree structure
    build_vtable_tree();
    
    // Populate index mapping
    populate_index_mapping();
    
    msg("[VTable Tree] Enhanced init() complete with %d items\n", index_to_inode.size());
    return true;
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
    
    cols->clear();
    cols->resize(COL_END);
    
    // Name column
    (*cols)[COL_NAME] = info->display_name;
    
    // Address column
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
        case VTableHierarchySpec::NODE_OVERRIDDEN:
            (*cols)[COL_TYPE] = "Overridden";
            break;
        case VTableHierarchySpec::NODE_INHERITED:
            (*cols)[COL_TYPE] = "Inherited";
            break;
        case VTableHierarchySpec::NODE_RTTI_INFO:
            (*cols)[COL_TYPE] = "RTTI";
            break;
        case VTableHierarchySpec::NODE_XREF_INFO:
            (*cols)[COL_TYPE] = "Xrefs";
            break;
        default:
            (*cols)[COL_TYPE] = "Folder";
            break;
    }
    
    // Info column
    (*cols)[COL_INFO] = spec->get_attrs(inode);
    
    // Xrefs column
    if (info->xref_count > 0) {
        (*cols)[COL_XREFS].sprnt("%d", info->xref_count);
    } else {
        (*cols)[COL_XREFS] = "";
    }
    
    // Compiler column
    if (info->rtti_info && !info->rtti_info->compiler_name.empty()) {
        (*cols)[COL_COMPILER] = info->rtti_info->compiler_name;
    } else {
        (*cols)[COL_COMPILER] = "";
    }
    
    // Set icon and color
    if (icon) {
        *icon = info->icon;
    }
    
    if (attrs) {
        attrs->color = info->color;
        
        // Highlight search results
        if (search_active) {
            for (const auto& result : search_results) {
                if (result.node == inode) {
                    attrs->flags |= CHITEM_BOLD;
                    break;
                }
            }
        }
    }
}

void IntegratedTreeExplorer::get_actions(contextaction_setter_t &ctx) const {
    for (const auto& action : context_actions) {
        ctx.add_action(action.name);
    }
}

void IntegratedTreeExplorer::build_enhanced_rtti_view(const VTBL_info_t& vtbl, 
                                                      enhanced_rtti_info_t& rtti) {
    // Parse basic RTTI
    RTTIInfo basic_rtti;
    bool has_rtti = CompilerRTTIParser::parse_vtable_rtti(vtbl, basic_rtti);
    
    if (has_rtti) {
        // Convert to enhanced format
        rtti.class_name = basic_rtti.class_name;
        rtti.mangled_name = basic_rtti.mangled_name;
        rtti.type_string = basic_rtti.type_string;
        
        // Set compiler name
        switch (basic_rtti.compiler) {
            case RTTIInfo::COMPILER_MSVC:
                rtti.compiler_name = "MSVC";
                break;
            case RTTIInfo::COMPILER_GCC:
                rtti.compiler_name = "GCC";
                break;
            case RTTIInfo::COMPILER_CLANG:
                rtti.compiler_name = "Clang";
                break;
            default:
                rtti.compiler_name = "Unknown";
                break;
        }
        
        // Extract namespaces from class name
        qstring class_name = rtti.class_name;
        size_t pos = 0;
        while ((pos = class_name.find("::")) != qstring::npos) {
            rtti.namespaces.push_back(class_name.substr(0, pos));
            class_name = class_name.substr(pos + 2);
        }
        
        // Convert base classes
        for (const auto& base : basic_rtti.base_classes) {
            enhanced_rtti_info_t::base_class_info_t ebase;
            ebase.name = base.name;
            ebase.is_virtual = base.is_virtual;
            ebase.is_public = true;  // Assume public for now
            ebase.offset = base.offset;
            
            // Try to find base vtable
            for (const auto& other_vtbl : vtbl_t_list) {
                if (other_vtbl.vtbl_name.find(base.name) != qstring::npos) {
                    ebase.vtable_ea = other_vtbl.ea_begin;
                    break;
                }
            }
            
            rtti.base_classes.push_back(ebase);
        }
        
        // Analyze vtable for additional properties
        rtti.vtable_ea = vtbl.ea_begin;
        rtti.is_polymorphic = (vtbl.methods > 0);
        
        // Check for pure virtual methods
        size_t ptr_size = inf_is_64bit() ? 8 : 4;
        for (size_t i = 0; i < vtbl.methods; i++) {
            ea_t method_ea = inf_is_64bit() ? 
                get_qword(vtbl.ea_begin + i * ptr_size) :
                get_dword(vtbl.ea_begin + i * ptr_size);
            
            if (RTTITreeHelper::is_pure_virtual(method_ea)) {
                rtti.is_abstract = true;
                break;
            }
            
            // Check for virtual destructor (usually first or second method)
            if (i < 2) {
                qstring method_name;
                get_short_name(&method_name, method_ea);
                if (method_name.find("destructor") != qstring::npos ||
                    method_name[0] == '~') {
                    rtti.has_virtual_destructor = true;
                }
            }
        }
        
        // Build hierarchy string
        rtti.hierarchy_string = rtti.class_name;
        if (!rtti.base_classes.empty()) {
            rtti.hierarchy_string += " : ";
            for (size_t i = 0; i < rtti.base_classes.size(); i++) {
                if (i > 0) rtti.hierarchy_string += ", ";
                if (rtti.base_classes[i].is_virtual) {
                    rtti.hierarchy_string += "virtual ";
                }
                rtti.hierarchy_string += rtti.base_classes[i].name;
            }
        }
    }
}

void IntegratedTreeExplorer::add_vtable_with_hierarchy(const VTBL_info_t& vtbl) {
    // Build enhanced RTTI info
    enhanced_rtti_info_t rtti;
    build_enhanced_rtti_view(vtbl, rtti);
    
    // Create vtable node with enhanced RTTI
    inode_t vtbl_inode = spec->add_vtable_node(vtbl, &rtti);
    
    // Create folder for this vtable
    qstring folder_name;
    folder_name.sprnt("📁 %s [%d methods]", rtti.class_name.c_str(), vtbl.methods);
    
    tree->mkdir(folder_name.c_str());
    tree->chdir(folder_name.c_str());
    
    // Add RTTI info node if we have it
    if (!rtti.class_name.empty()) {
        inode_t rtti_node = spec->add_rtti_node(rtti);
        tree->link(rtti_node);
    }
    
    // Get inheritance info for this vtable
    auto* inheritance = spec->get_inheritance_analyzer();
    
    // Separate methods by category
    qvector<size_t> pure_virtuals;
    qvector<size_t> overridden;
    qvector<size_t> inherited;
    qvector<size_t> regular;
    
    for (size_t i = 0; i < vtbl.methods; i++) {
        // Get cached method info
        size_t ptr_size = inf_is_64bit() ? 8 : 4;
        ea_t method_ea = inf_is_64bit() ? 
            get_qword(vtbl.ea_begin + i * ptr_size) :
            get_dword(vtbl.ea_begin + i * ptr_size);
        
        const method_info_t* minfo = spec->get_method_cache()->get_method_info(method_ea);
        
        if (minfo) {
            if (minfo->is_pure_virtual) {
                pure_virtuals.push_back(i);
            } else if (inheritance->is_method_overridden(vtbl.ea_begin, i)) {
                overridden.push_back(i);
            } else if (inheritance->find_method_origin(vtbl.ea_begin, i) != vtbl.ea_begin) {
                inherited.push_back(i);
            } else {
                regular.push_back(i);
            }
        } else {
            regular.push_back(i);
        }
    }
    
    // Add regular methods
    if (!regular.empty()) {
        for (size_t idx : regular) {
            size_t ptr_size = inf_is_64bit() ? 8 : 4;
            ea_t method_ea = inf_is_64bit() ? 
                get_qword(vtbl.ea_begin + idx * ptr_size) :
                get_dword(vtbl.ea_begin + idx * ptr_size);
            
            const method_info_t* minfo = spec->get_method_cache()->get_method_info(method_ea);
            inode_t method_inode = spec->add_method_node(vtbl, idx, minfo);
            tree->link(method_inode);
        }
    }
    
    // Add overridden methods folder
    if (!overridden.empty()) {
        qstring override_folder;
        override_folder.sprnt("📁 Overridden [%d methods]", overridden.size());
        tree->mkdir(override_folder.c_str());
        tree->chdir(override_folder.c_str());
        
        for (size_t idx : overridden) {
            size_t ptr_size = inf_is_64bit() ? 8 : 4;
            ea_t method_ea = inf_is_64bit() ? 
                get_qword(vtbl.ea_begin + idx * ptr_size) :
                get_dword(vtbl.ea_begin + idx * ptr_size);
            
            const method_info_t* minfo = spec->get_method_cache()->get_method_info(method_ea);
            inode_t method_inode = spec->add_method_node(vtbl, idx, minfo);
            tree->link(method_inode);
        }
        
        tree->chdir("..");
    }
    
    // Add inherited methods folder
    if (!inherited.empty()) {
        qstring inherit_folder;
        inherit_folder.sprnt("📁 Inherited [%d methods]", inherited.size());
        tree->mkdir(inherit_folder.c_str());
        tree->chdir(inherit_folder.c_str());
        
        for (size_t idx : inherited) {
            size_t ptr_size = inf_is_64bit() ? 8 : 4;
            ea_t method_ea = inf_is_64bit() ? 
                get_qword(vtbl.ea_begin + idx * ptr_size) :
                get_dword(vtbl.ea_begin + idx * ptr_size);
            
            const method_info_t* minfo = spec->get_method_cache()->get_method_info(method_ea);
            inode_t method_inode = spec->add_method_node(vtbl, idx, minfo);
            tree->link(method_inode);
        }
        
        tree->chdir("..");
    }
    
    // Add pure virtual methods folder
    if (!pure_virtuals.empty()) {
        qstring pure_folder;
        pure_folder.sprnt("📁 Pure Virtual [%d methods]", pure_virtuals.size());
        tree->mkdir(pure_folder.c_str());
        tree->chdir(pure_folder.c_str());
        
        for (size_t idx : pure_virtuals) {
            size_t ptr_size = inf_is_64bit() ? 8 : 4;
            ea_t method_ea = inf_is_64bit() ? 
                get_qword(vtbl.ea_begin + idx * ptr_size) :
                get_dword(vtbl.ea_begin + idx * ptr_size);
            
            const method_info_t* minfo = spec->get_method_cache()->get_method_info(method_ea);
            inode_t method_inode = spec->add_method_node(vtbl, idx, minfo);
            tree->link(method_inode);
        }
        
        tree->chdir("..");
    }
    
    // Add base class information if available
    if (!rtti.base_classes.empty()) {
        qstring bases_folder;
        bases_folder.sprnt("📁 Base Classes [%d]", rtti.base_classes.size());
        tree->mkdir(bases_folder.c_str());
        tree->chdir(bases_folder.c_str());
        
        for (const auto& base : rtti.base_classes) {
            qstring base_node_name;
            base_node_name.sprnt("🔗 %s%s", 
                                base.name.c_str(),
                                base.is_virtual ? " (virtual)" : "");
            
            if (base.vtable_ea != BADADDR) {
                base_node_name.cat_sprnt(" [0x%a]", base.vtable_ea);
            }
            
            inode_t base_node = spec->add_folder_node(base_node_name, 
                                                      VTableHierarchySpec::NODE_BASE_CLASS);
            tree->link(base_node);
        }
        
        tree->chdir("..");
    }
    
    // Return to parent
    tree->chdir("..");
}

void IntegratedTreeExplorer::analyze_selected_xrefs(size_t n) {
    if (n >= index_to_inode.size()) {
        return;
    }
    
    inode_t inode = index_to_inode[n];
    const VTableHierarchySpec::node_info_t* info = spec->get_node_info(inode);
    
    if (info && info->address != BADADDR) {
        // Refresh xref analysis for this method
        spec->get_method_cache()->refresh_method(info->address);
        
        // Create xref node
        const method_info_t* minfo = spec->get_method_cache()->get_method_info(info->address);
        if (minfo && !minfo->callers.empty()) {
            inode_t xref_node = spec->add_xref_node(info->address, minfo->callers);
            
            // Add to tree under current node
            dirtree_cursor_t cursor;
            if (tree->resolve_cursor(&cursor, inode)) {
                tree->link(xref_node, &cursor);
            }
        }
        
        refresh(n);
    }
}

void IntegratedTreeExplorer::show_inheritance_graph(size_t n) {
    // This would generate a graph view of the inheritance hierarchy
    // For now, just show a message
    msg("[VTable Tree] Inheritance graph for item %d\n", n);
    
    if (n >= index_to_inode.size()) {
        return;
    }
    
    inode_t inode = index_to_inode[n];
    const VTableHierarchySpec::node_info_t* info = spec->get_node_info(inode);
    
    if (info && info->vtbl_info) {
        auto* analyzer = spec->get_inheritance_analyzer();
        auto bases = analyzer->get_base_vtables(info->vtbl_info->ea_begin);
        auto derived = analyzer->get_derived_vtables(info->vtbl_info->ea_begin);
        
        msg("Base classes: %d\n", bases.size());
        for (ea_t base : bases) {
            msg("  - 0x%a\n", base);
        }
        
        msg("Derived classes: %d\n", derived.size());
        for (ea_t der : derived) {
            msg("  - 0x%a\n", der);
        }
    }
}

void IntegratedTreeExplorer::find_similar_vtables(size_t n) {
    if (n >= index_to_inode.size()) {
        return;
    }
    
    inode_t inode = index_to_inode[n];
    const VTableHierarchySpec::node_info_t* info = spec->get_node_info(inode);
    
    if (info && info->vtbl_info) {
        auto* analyzer = spec->get_inheritance_analyzer();
        
        msg("[VTable Tree] Finding similar vtables to 0x%a\n", info->vtbl_info->ea_begin);
        
        // Find all vtables with high similarity
        qvector<std::pair<ea_t, float>> similar_vtables;
        
        for (const auto& other_vtbl : vtbl_t_list) {
            if (other_vtbl.ea_begin != info->vtbl_info->ea_begin) {
                float similarity = analyzer->calculate_vtable_similarity(
                    info->vtbl_info->ea_begin, other_vtbl.ea_begin);
                
                if (similarity > 0.5) {
                    similar_vtables.push_back({other_vtbl.ea_begin, similarity});
                }
            }
        }
        
        // Sort by similarity
        std::sort(similar_vtables.begin(), similar_vtables.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        msg("Found %d similar vtables:\n", similar_vtables.size());
        for (const auto& [vtbl_ea, similarity] : similar_vtables) {
            msg("  0x%a - %.1f%% similar\n", vtbl_ea, similarity * 100);
        }
    }
}

void IntegratedTreeExplorer::search(const qstring& query, VTableSearcher::search_type_t type) {
    current_search = query;
    search_results = spec->get_searcher()->search(query, type);
    search_active = !search_results.empty();
    
    if (search_active) {
        msg("[VTable Tree] Search found %d results\n", search_results.size());
        highlight_search_results();
    }
    
    refresh(0);
}

void IntegratedTreeExplorer::clear_search() {
    current_search.clear();
    search_results.clear();
    search_active = false;
    refresh(0);
}

void IntegratedTreeExplorer::apply_filter(uint32 filter_mask) {
    active_filters = filter_mask;
    spec->get_searcher()->set_filters(filter_mask);
    refresh(0);
}

void IntegratedTreeExplorer::highlight_search_results() {
    // This will be handled in get_row() by checking search_results
}

inode_t IntegratedTreeExplorer::get_selected_inode() const {
    size_t n = get_selected_item();
    if (n != NO_SELECTION && n < index_to_inode.size()) {
        return index_to_inode[n];
    }
    return inode_t(-1);
}

void IntegratedTreeExplorer::show() {
    msg("[VTable Tree] Enhanced show() called\n");
    
    if (g_integrated_tree) {
        g_integrated_tree->choose();
    } else {
        g_integrated_tree = new IntegratedTreeExplorer();
        g_integrated_tree->choose();
    }
}

//-------------------------------------------------------------------------
// Global Functions
//-------------------------------------------------------------------------

void init_integrated_tree_explorer() {
    msg("[VTable Tree] Initializing enhanced integrated tree explorer\n");
}

void term_integrated_tree_explorer() {
    msg("[VTable Tree] Terminating enhanced integrated tree explorer\n");
    
    if (g_integrated_tree) {
        delete g_integrated_tree;
        g_integrated_tree = nullptr;
    }
}

// Utility functions
qstring format_xref_count(size_t count) {
    if (count == 0) return "";
    if (count == 1) return "1 xref";
    qstring result;
    result.sprnt("%d xrefs", count);
    return result;
}

qstring format_compiler_tag(RTTIInfo::compiler_t compiler) {
    switch (compiler) {
        case RTTIInfo::COMPILER_MSVC: return "[MSVC]";
        case RTTIInfo::COMPILER_GCC: return "[GCC]";
        case RTTIInfo::COMPILER_CLANG: return "[Clang]";
        default: return "";
    }
}

bool analyze_method_xrefs(ea_t method_ea, method_info_t& info) {
    info.xref_count = 0;
    info.callers.clear();
    
    xrefblk_t xb;
    for (bool ok = xb.first_to(method_ea, XREF_ALL); ok; ok = xb.next_to()) {
        if (xb.type == fl_CN || xb.type == fl_CF) {
            info.callers.push_back(xb.from);
            info.xref_count++;
        }
    }
    
    return info.xref_count > 0;
}