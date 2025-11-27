/*
    Unified Object Explorer Implementation
    Combines hierarchical tree view with modern table functionality
*/

#include "UnifiedObjectExplorer.h"
#include "CompilerRTTIParser.h"
#include "ClangVTableParser.h"
#include "Utility.h"
#include <segment.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <algorithm>
#include <ctime>
#include <sstream>

// External vtable list from ObjectExplorer
extern qvector<VTBL_info_t> vtbl_t_list;

// Global instance
UnifiedObjectExplorer* g_unified_explorer = nullptr;

//-------------------------------------------------------------------------
// Helper Functions
//-------------------------------------------------------------------------

void parse_namespaces(const qstring& class_name, qvector<qstring>& namespaces) {
    namespaces.clear();
    qstring remaining = class_name;
    size_t pos = 0;
    while ((pos = remaining.find("::")) != qstring::npos) {
        if (pos > 0) {
            namespaces.push_back(remaining.substr(0, pos));
        }
        remaining = remaining.substr(pos + 2);
    }
}

qstring join_namespaces(const qvector<qstring>& namespaces) {
    qstring result;
    for (size_t i = 0; i < namespaces.size(); i++) {
        if (i > 0) result += "::";
        result += namespaces[i];
    }
    return result;
}

qstring extract_clean_method_name(const qstring& demangled) {
    // Simple extraction - remove template parameters and return just the method name
    qstring clean = demangled;
    
    // Find the last :: to get just the method name
    size_t pos = qstring::npos;
    size_t search_pos = 0;
    while ((search_pos = clean.find("::", search_pos)) != qstring::npos) {
        pos = search_pos;
        search_pos += 2;
    }
    if (pos != qstring::npos) {
        clean = clean.substr(pos + 2);
    }
    
    // Remove template parameters
    pos = clean.find('<');
    if (pos != qstring::npos) {
        clean = clean.substr(0, pos);
    }
    
    // Remove function parameters
    pos = clean.find('(');
    if (pos != qstring::npos) {
        clean = clean.substr(0, pos);
    }
    
    return clean;
}

uint32 calculate_display_color(const unified_vtable_entry_t& entry) {
    if (entry.has_rtti) {
        if (entry.rtti.is_abstract) {
            return 0x202020;  // Very dark gray (near black) for abstract
        } else if (entry.rtti.has_virtual_destructor) {
            return 0x404040;  // Dark gray for safe virtual
        } else {
            return 0x303030;  // Dark gray for regular
        }
    }
    return 0x252525;  // Very dark gray default
}

int get_display_icon(const unified_vtable_entry_t& entry) {
    if (entry.has_rtti && entry.rtti.is_abstract) {
        return 156;  // Warning icon for abstract classes
    }
    if (entry.has_rtti && entry.rtti.has_virtual_destructor) {
        return 59;   // Class icon
    }
    return 59;  // Default class icon
}

qstring build_tooltip_text(const unified_vtable_entry_t& entry) {
    qstring tooltip;
    tooltip.sprnt("VTable: %s\nAddress: 0x%a\nMethods: %llu", 
                  entry.vtbl_info.vtbl_name.c_str(),
                  entry.vtbl_info.ea_begin,
                  (unsigned long long)entry.vtbl_info.methods);
    
    if (entry.has_rtti) {
        tooltip += "\nRTTI: Yes";
        if (!entry.rtti.class_name.empty()) {
            tooltip.cat_sprnt("\nClass: %s", entry.rtti.class_name.c_str());
        }
        if (entry.rtti.is_abstract) {
            tooltip += "\nAbstract: Yes";
        }
    }
    
    if (entry.xref_count > 0) {
        tooltip.cat_sprnt("\nCross-refs: %llu", (unsigned long long)entry.xref_count);
    }
    
    return tooltip;
}

void analyze_method_properties(unified_method_info_t& method) {
    // Check for special method properties
    if (method.demangled_name.find("::~") != qstring::npos) {
        method.is_destructor = true;
    }
    
    // Check for pure virtual call patterns
    if (method.name.find("purecall") != qstring::npos || 
        method.name.find("__cxa_pure_virtual") != qstring::npos) {
        method.is_pure_virtual = true;
    }
    
    // Check if it's a thunk
    func_t* func = get_func(method.address);
    if (func && (func->flags & FUNC_THUNK)) {
        method.is_thunk = true;
    }
}

void analyze_method_xrefs(unified_method_info_t& method) {
    method.xref_count = 0;
    method.callers.clear();
    method.callees.clear();
    
    // Analyze callers
    xrefblk_t xb;
    for (bool ok = xb.first_to(method.address, XREF_ALL); ok; ok = xb.next_to()) {
        if (xb.type == fl_CN || xb.type == fl_CF) {
            method.callers.push_back(xb.from);
            method.xref_count++;
        }
    }
    
    // Analyze callees (what this method calls)
    func_t* func = get_func(method.address);
    if (func) {
        for (ea_t ea = func->start_ea; ea < func->end_ea; ea = next_head(ea, func->end_ea)) {
            insn_t insn;
            if (decode_insn(&insn, ea) > 0) {
                if (is_call_insn(insn)) {
                    // IDA SDK: insn.ops is a fixed array, not a container with size()
                    for (int i = 0; i < UA_MAXOP && insn.ops[i].type != o_void; i++) {
                        if (insn.ops[i].type == o_near || insn.ops[i].type == o_far) {
                            method.callees.push_back(insn.ops[i].addr);
                        }
                    }
                }
            }
        }
    }
}

//-------------------------------------------------------------------------
// UnifiedDataManager Implementation
//-------------------------------------------------------------------------

UnifiedDataManager::UnifiedDataManager() 
    : current_organization(ORG_FLAT), analysis_level(ANALYSIS_FULL),
      last_full_analysis(0), needs_rebuild(true) {
    msg("[Unified Explorer] DataManager initialized\n");
}

UnifiedDataManager::~UnifiedDataManager() {
    clear_cache();
    msg("[Unified Explorer] DataManager destroyed\n");
}

void UnifiedDataManager::build_from_vtables(analysis_level_t level) {
    msg("[Unified Explorer] Building data from %zu vtables (level %d)\n", vtbl_t_list.size(), level);
    
    entries.clear();
    vtable_to_index.clear();
    namespace_groups.clear();
    segment_groups.clear();
    depth_groups.clear();
    
    analysis_level = level;
    
    for (const auto& vtbl : vtbl_t_list) {
        unified_vtable_entry_t entry;
        
        // Copy basic vtable info
        entry.vtbl_info = vtbl;
        entry.has_vtbl_info = true;
        entry.needs_refresh = false;
        entry.last_analyzed = time(nullptr);
        entry.is_expanded = false;
        entry.is_filtered = false;
        entry.inheritance_depth = 0;
        
        // Get segment information
        if (segment_t* seg = getseg(vtbl.ea_begin)) {
            get_segm_name(&entry.segment_name, seg);
            entry.segment_start = seg->start_ea;
            entry.segment_end = seg->end_ea;
        } else {
            entry.segment_name = "unknown";
            entry.segment_start = entry.segment_end = BADADDR;
        }
        
        // Count cross-references
        entry.xref_count = 0;
        entry.direct_xrefs = 0;
        entry.indirect_xrefs = 0;
        entry.xref_locations.clear();
        
        for (auto addr = get_first_dref_to(vtbl.ea_begin); 
             addr != BADADDR; 
             addr = get_next_dref_to(vtbl.ea_begin, addr)) {
            entry.xref_count++;
            entry.direct_xrefs++;
            entry.xref_locations.push_back(addr);
        }
        
        // Initialize RTTI analysis if requested
        entry.has_rtti = false;
        if (level >= ANALYSIS_RTTI) {
            analyze_rtti_info(entry);
        }
        
        // Analyze methods if requested
        if (level >= ANALYSIS_BASIC) {
            analyze_methods(entry);
        }
        
        // Calculate display properties
        entry.display_color = calculate_display_color(entry);
        entry.display_icon = get_display_icon(entry);
        entry.tooltip_text = build_tooltip_text(entry);
        
        // Calculate total size
        entry.total_size = vtbl.methods * (inf_is_64bit() ? 8 : 4);
        
        // Add to collections
        size_t index = entries.size();
        entries.push_back(entry);
        vtable_to_index[vtbl.ea_begin] = index;
        
        // Update groupings
        update_groupings(index);
    }
    
    // Perform higher-level analysis if requested
    if (level >= ANALYSIS_INHERITANCE) {
        analyze_inheritance_relationships();
    }
    
    if (level >= ANALYSIS_FULL) {
        analyze_method_overrides();
        calculate_similarities();
    }
    
    last_full_analysis = time(nullptr);
    needs_rebuild = false;
    
    msg("[Unified Explorer] Built %zu entries with analysis level %d\n", entries.size(), level);
}

void UnifiedDataManager::analyze_rtti_info(unified_vtable_entry_t& entry) {
    RTTIInfo basic_rtti;
    bool has_rtti = CompilerRTTIParser::parse_vtable_rtti(entry.vtbl_info, basic_rtti);
    
    if (has_rtti) {
        entry.has_rtti = true;
        
        // Convert to enhanced format
        entry.rtti.class_name = basic_rtti.class_name;
        entry.rtti.mangled_name = basic_rtti.raw_name;
        entry.rtti.type_string = basic_rtti.type_string;
        entry.rtti.compiler = basic_rtti.compiler;
        
        // Set compiler name
        switch (basic_rtti.compiler) {
            case RTTIInfo::COMPILER_MSVC:
                entry.rtti.compiler_name = "MSVC";
                break;
            case RTTIInfo::COMPILER_GCC:
                entry.rtti.compiler_name = "GCC";
                break;
            case RTTIInfo::COMPILER_CLANG:
                entry.rtti.compiler_name = "Clang";
                break;
            default:
                entry.rtti.compiler_name = "Unknown";
                break;
        }
        
        // Parse namespaces from class name
        parse_namespaces(entry.rtti.class_name, entry.rtti.namespaces);
        entry.namespace_path = join_namespaces(entry.rtti.namespaces);
        
        // Convert base classes
        for (const auto& base : basic_rtti.base_classes) {
            unified_rtti_info_t::base_class_info_t ebase;
            ebase.name = base.name;
            ebase.is_virtual = base.is_virtual;
            ebase.is_public = true;  // Assume public for now
            ebase.is_protected = false;
            ebase.offset = base.offset;
            ebase.inheritance_depth = 1;  // Will be refined later
            
            // Try to find base vtable
            for (const auto& other_vtbl : vtbl_t_list) {
                if (other_vtbl.vtbl_name.find(base.name) != qstring::npos) {
                    ebase.vtable_ea = other_vtbl.ea_begin;
                    break;
                }
            }
            
            entry.rtti.base_classes.push_back(ebase);
        }
        
        // Analyze class properties (placeholder)
        entry.rtti.is_abstract = (entry.pure_virtual_count > 0);
        entry.rtti.has_virtual_destructor = false;  // TODO: Detect virtual destructor
        entry.rtti.is_polymorphic = (entry.vtbl_info.methods > 0);
        entry.rtti.is_template = (entry.rtti.class_name.find('<') != qstring::npos);
        entry.rtti.is_final = false;  // TODO: Detect final classes
        entry.rtti.object_size = entry.total_size;
        entry.rtti.vtable_size = entry.vtbl_info.methods * (inf_is_64bit() ? 8 : 4);
        entry.rtti.type_info_ea = BADADDR;
        entry.rtti.vtable_ea = entry.vtbl_info.ea_begin;
        
        // Build hierarchy string (placeholder)
        entry.rtti.hierarchy_string = entry.rtti.class_name;
        if (!entry.rtti.base_classes.empty()) {
            entry.rtti.hierarchy_string += " : ";
            for (size_t i = 0; i < entry.rtti.base_classes.size(); i++) {
                if (i > 0) entry.rtti.hierarchy_string += ", ";
                if (entry.rtti.base_classes[i].is_virtual) {
                    entry.rtti.hierarchy_string += "virtual ";
                }
                entry.rtti.hierarchy_string += entry.rtti.base_classes[i].name;
            }
        }
        entry.rtti.full_signature = entry.rtti.hierarchy_string;
    }
}

void UnifiedDataManager::analyze_methods(unified_vtable_entry_t& entry) {
    entry.methods.clear();
    entry.pure_virtual_count = 0;
    entry.overridden_methods = 0;
    entry.unique_methods = entry.vtbl_info.methods;
    
    size_t ptr_size = inf_is_64bit() ? 8 : 4;
    
    for (size_t i = 0; i < entry.vtbl_info.methods; i++) {
        unified_method_info_t method;
        method.method_index = i;
        method.vtbl_entry_ea = entry.vtbl_info.ea_begin + i * ptr_size;
        method.address = inf_is_64bit() ? 
            get_qword(method.vtbl_entry_ea) : 
            get_dword(method.vtbl_entry_ea);
        method.cached_at = time(nullptr);
        method.needs_refresh = false;
        
        if (method.address != BADADDR && method.address != 0) {
            // Get method name
            get_short_name(&method.name, method.address);
            
            // Demangle if possible
            qstring demangled;
            if (demangle_name(&demangled, method.name.c_str(), MNG_SHORT_FORM) > 0) {
                method.demangled_name = demangled;
                method.clean_name = extract_clean_method_name(demangled);
            } else {
                method.demangled_name = method.name;
                method.clean_name = method.name;
            }
            
            // Analyze method properties
            analyze_method_properties(method);
            
            // Count as pure virtual if needed
            if (method.is_pure_virtual) {
                entry.pure_virtual_count++;
            }
            
            // Analyze cross-references
            analyze_method_xrefs(method);
        }
        
        entry.methods.push_back(method);
    }
}

void UnifiedDataManager::analyze_method_properties(unified_method_info_t& method) {
    method.is_pure_virtual = (method.name.find("purecall") != qstring::npos || 
                             method.name.find("__cxa_pure_virtual") != qstring::npos);
    
    method.is_destructor = (method.clean_name.find("~") == 0 || 
                           method.demangled_name.find("destructor") != qstring::npos);
    
    method.is_constructor = (method.demangled_name.find("constructor") != qstring::npos ||
                            method.demangled_name.find("::ctor") != qstring::npos);
    
    method.is_virtual = true;  // All vtable methods are virtual
    method.is_overridden = false;  // Will be determined during inheritance analysis
    method.is_inline = false;  // TODO: Detect inline methods
    
    // Check if it's a thunk
    func_t* func = get_func(method.address);
    if (func && (func->flags & FUNC_THUNK)) {
        method.is_thunk = true;
    } else {
        method.is_thunk = false;
    }
}

void UnifiedDataManager::analyze_method_xrefs(unified_method_info_t& method) {
    method.xref_count = 0;
    method.callers.clear();
    method.callees.clear();
    
    // Get xrefs to this method (callers)
    xrefblk_t xb;
    for (bool ok = xb.first_to(method.address, XREF_ALL); ok; ok = xb.next_to()) {
        if (xb.type == fl_CN || xb.type == fl_CF) {
            method.callers.push_back(xb.from);
            method.xref_count++;
        }
    }
    
    // Get xrefs from this method (callees) - simplified for performance
    func_t* func = get_func(method.address);
    if (func) {
        // Just count function calls, don't track all of them for performance
        ea_t ea = func->start_ea;
        while (ea < func->end_ea) {
            // Check for function calls by looking at cross-references
            ea_t target = get_first_fcref_from(ea);
            if (target != BADADDR) {
                method.callees.push_back(target);
            }
            ea = next_head(ea, func->end_ea);
        }
    }
}

void UnifiedDataManager::update_groupings(size_t index) {
    const unified_vtable_entry_t& entry = entries[index];
    
    // Update segment grouping
    segment_groups[entry.segment_name].push_back(index);
    
    // Update namespace grouping
    if (!entry.namespace_path.empty()) {
        namespace_groups[entry.namespace_path].push_back(index);
    } else {
        namespace_groups["global"].push_back(index);
    }
    
    // Update depth grouping
    depth_groups[entry.inheritance_depth].push_back(index);
}

void UnifiedDataManager::analyze_inheritance_relationships() {
    msg("[Unified Explorer] Analyzing inheritance relationships...\n");
    
    // This is a simplified inheritance analysis
    // In a full implementation, this would use more sophisticated techniques
    
    for (size_t i = 0; i < entries.size(); i++) {
        unified_vtable_entry_t& entry = entries[i];
        
        if (entry.has_rtti) {
            // Find base vtables
            for (const auto& base : entry.rtti.base_classes) {
                if (base.vtable_ea != BADADDR) {
                    auto it = vtable_to_index.find(base.vtable_ea);
                    if (it != vtable_to_index.end()) {
                        entry.base_vtables.push_back(base.vtable_ea);
                        entries[it->second].derived_vtables.push_back(entry.vtbl_info.ea_begin);
                    }
                }
            }
            
            // Calculate inheritance depth
            entry.inheritance_depth = calculate_inheritance_depth(entry);
        }
    }
}

int UnifiedDataManager::calculate_inheritance_depth(const unified_vtable_entry_t& entry) {
    if (!entry.has_rtti || entry.rtti.base_classes.empty()) {
        return 0;
    }
    
    int max_depth = 0;
    for (const auto& base : entry.rtti.base_classes) {
        if (base.vtable_ea != BADADDR) {
            auto it = vtable_to_index.find(base.vtable_ea);
            if (it != vtable_to_index.end()) {
                int depth = calculate_inheritance_depth(entries[it->second]) + 1;
                max_depth = qmax(max_depth, depth);
            }
        }
    }
    
    return max_depth;
}

UnifiedDataManager::statistics_t UnifiedDataManager::get_statistics() const {
    statistics_t stats;
    stats.total_vtables = entries.size();
    stats.total_methods = 0;
    stats.pure_virtual_methods = 0;
    stats.vtables_with_rtti = 0;
    stats.vtables_with_inheritance = 0;
    stats.abstract_classes = 0;
    stats.template_classes = 0;
    stats.max_methods = 0;
    stats.max_inheritance_depth = 0;
    
    for (const auto& entry : entries) {
        stats.total_methods += entry.vtbl_info.methods;
        stats.pure_virtual_methods += entry.pure_virtual_count;
        
        if (entry.has_rtti) {
            stats.vtables_with_rtti++;
            stats.compiler_distribution[entry.rtti.compiler]++;
            
            if (!entry.rtti.base_classes.empty()) {
                stats.vtables_with_inheritance++;
            }
            
            if (entry.rtti.is_abstract) {
                stats.abstract_classes++;
            }
            
            if (entry.rtti.is_template) {
                stats.template_classes++;
            }
        }
        
        if (entry.vtbl_info.methods > stats.max_methods) {
            stats.max_methods = entry.vtbl_info.methods;
            stats.largest_class = entry.has_rtti ? entry.rtti.class_name : entry.vtbl_info.vtbl_name;
        }
        
        if (entry.inheritance_depth > stats.max_inheritance_depth) {
            stats.max_inheritance_depth = entry.inheritance_depth;
            stats.most_complex_inheritance = entry.has_rtti ? entry.rtti.class_name : entry.vtbl_info.vtbl_name;
        }
        
        stats.segment_distribution[entry.segment_name]++;
        stats.inheritance_depth_distribution[entry.inheritance_depth]++;
    }
    
    return stats;
}

//-------------------------------------------------------------------------
// UnifiedFilterEngine Implementation  
//-------------------------------------------------------------------------

UnifiedFilterEngine::UnifiedFilterEngine(UnifiedDataManager* dm) 
    : data_manager(dm), filter_active(false) {
}

void UnifiedFilterEngine::set_filter_criteria(const filter_criteria_t& criteria) {
    current_criteria = criteria;
    apply_filters();
}

void UnifiedFilterEngine::apply_filters() {
    filtered_indices.clear();
    
    if (current_criteria.active_filters == FILTER_NONE) {
        filter_active = false;
        // Add all indices
        for (size_t i = 0; i < data_manager->get_count(); i++) {
            filtered_indices.push_back(i);
        }
        return;
    }
    
    filter_active = true;
    
    for (size_t i = 0; i < data_manager->get_count(); i++) {
        if (matches_criteria(i, current_criteria)) {
            filtered_indices.push_back(i);
        }
    }
    
    msg("[Unified Explorer] Applied filters: %zu entries match\n", filtered_indices.size());
}

bool UnifiedFilterEngine::matches_criteria(size_t index, const filter_criteria_t& criteria) const {
    const unified_vtable_entry_t* entry = data_manager->get_entry(index);
    if (!entry) return false;
    
    // Class name filter
    if (criteria.active_filters & FILTER_CLASS_NAME) {
        qstring class_name = entry->has_rtti ? entry->rtti.class_name : entry->vtbl_info.vtbl_name;
        if (class_name.find(criteria.class_name_pattern) == qstring::npos) {
            return false;
        }
    }
    
    // RTTI filter
    if (criteria.active_filters & FILTER_HAS_RTTI) {
        if (!entry->has_rtti) return false;
    }
    
    // Abstract class filter
    if (criteria.active_filters & FILTER_IS_ABSTRACT) {
        if (!entry->has_rtti || !entry->rtti.is_abstract) return false;
    }
    
    // Template filter
    if (criteria.active_filters & FILTER_IS_TEMPLATE) {
        if (!entry->has_rtti || !entry->rtti.is_template) return false;
    }
    
    // Inheritance filter
    if (criteria.active_filters & FILTER_HAS_INHERITANCE) {
        if (entry->base_vtables.empty() && entry->derived_vtables.empty()) return false;
    }
    
    // Method count filters
    if (criteria.active_filters & FILTER_MIN_METHODS) {
        if (entry->vtbl_info.methods < criteria.min_methods) return false;
    }
    
    if (criteria.active_filters & FILTER_MAX_METHODS) {
        if (entry->vtbl_info.methods > criteria.max_methods) return false;
    }
    
    // Segment filter
    if (criteria.active_filters & FILTER_SEGMENT) {
        if (entry->segment_name != criteria.segment_filter) return false;
    }
    
    // Compiler filter
    if (criteria.active_filters & FILTER_COMPILER) {
        if (!entry->has_rtti || entry->rtti.compiler != criteria.compiler_filter) return false;
    }
    
    // XRefs filter
    if (criteria.active_filters & FILTER_HAS_XREFS) {
        if (entry->xref_count == 0) return false;
    }
    
    return true;
}

qvector<UnifiedFilterEngine::search_result_t> UnifiedFilterEngine::search(const qstring& query, search_mode_t mode) {
    search_results.clear();
    
    if (query.empty()) return search_results;
    
    qstring lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);
    
    for (size_t i = 0; i < data_manager->get_count(); i++) {
        const unified_vtable_entry_t* entry = data_manager->get_entry(i);
        if (!entry) continue;
        
        search_result_t result;
        result.entry_index = i;
        result.relevance_score = 0.0f;
        
        // Search in class name
        qstring class_name = entry->has_rtti ? entry->rtti.class_name : entry->vtbl_info.vtbl_name;
        qstring lower_class_name = class_name;
        std::transform(lower_class_name.begin(), lower_class_name.end(), lower_class_name.begin(), ::tolower);
        
        if (lower_class_name.find(lower_query) != qstring::npos) {
            result.matched_text = class_name;
            result.relevance_score = 1.0f;
            result.match_context = "Class name";
            search_results.push_back(result);
        }
        
        // Search in method names if not already matched
        else if (mode != SEARCH_SIMPLE) {
            for (const auto& method : entry->methods) {
                qstring lower_method_name = method.clean_name;
                std::transform(lower_method_name.begin(), lower_method_name.end(), lower_method_name.begin(), ::tolower);
                
                if (lower_method_name.find(lower_query) != qstring::npos) {
                    result.matched_text = method.clean_name;
                    result.relevance_score = 0.8f;
                    result.match_context.sprnt("Method in %s", class_name.c_str());
                    search_results.push_back(result);
                    break;
                }
            }
        }
    }
    
    // Sort by relevance
    std::sort(search_results.begin(), search_results.end(),
              [](const search_result_t& a, const search_result_t& b) {
                  return a.relevance_score > b.relevance_score;
              });
    
    msg("[Unified Explorer] Search for '%s' found %zu results\n", query.c_str(), search_results.size());
    return search_results;
}

//-------------------------------------------------------------------------
// UnifiedTreeBuilder Implementation
//-------------------------------------------------------------------------

UnifiedTreeBuilder::UnifiedTreeBuilder(UnifiedDataManager* dm, UnifiedFilterEngine* fe)
    : data_manager(dm), filter_engine(fe), root_node(0), current_mode(UnifiedDataManager::ORG_FLAT) {
    
    // Create root node
    tree_node_t root;
    root.type = NODE_ROOT;
    root.name = "Root";
    root.display_name = "VTable Explorer";
    root.icon = 1;
    root.color = 0x000000;
    root.is_expanded = true;
    root.is_visible = true;
    root.depth = 0;
    
    nodes.push_back(root);
    root_node = 0;
}

void UnifiedTreeBuilder::rebuild_tree(UnifiedDataManager::organization_mode_t mode) {
    current_mode = mode;
    
    // Clear existing nodes except root
    nodes.resize(1);
    path_to_node.clear();
    nodes[0].children.clear();
    
    switch (mode) {
        case UnifiedDataManager::ORG_FLAT:
            build_flat_tree();
            break;
        case UnifiedDataManager::ORG_BY_SEGMENT:
            build_segment_tree();
            break;
        case UnifiedDataManager::ORG_BY_NAMESPACE:
            build_namespace_tree();
            break;
        case UnifiedDataManager::ORG_BY_INHERITANCE:
            build_inheritance_tree();
            break;
        default:
            build_flat_tree();
            break;
    }
    
    update_node_visibility();
    calculate_node_colors();
    assign_node_icons();
    
    msg("[Unified Explorer] Rebuilt tree with %zu nodes (mode %d)\n", nodes.size(), mode);
}

void UnifiedTreeBuilder::build_flat_tree() {
    // Add all vtables directly under root
    for (size_t i = 0; i < data_manager->get_count(); i++) {
        create_vtable_node(i, root_node);
    }
}

void UnifiedTreeBuilder::build_segment_tree() {
    const auto& segment_groups = data_manager->get_segment_groups();
    
    for (const auto& [segment_name, indices] : segment_groups) {
        size_t segment_folder = create_folder_node(segment_name, root_node);
        
        for (size_t index : indices) {
            create_vtable_node(index, segment_folder);
        }
    }
}

void UnifiedTreeBuilder::build_namespace_tree() {
    const auto& namespace_groups = data_manager->get_namespace_groups();
    
    for (const auto& [namespace_name, indices] : namespace_groups) {
        size_t ns_folder = create_folder_node(namespace_name, root_node);
        
        for (size_t index : indices) {
            create_vtable_node(index, ns_folder);
        }
    }
}

size_t UnifiedTreeBuilder::create_folder_node(const qstring& name, size_t parent) {
    tree_node_t node;
    node.type = NODE_FOLDER;
    node.name = name;
    node.display_name = name;
    node.tooltip.sprnt("Folder: %s", name.c_str());
    node.icon = 1;  // Folder icon
    node.color = 0x1A1A1A;  // Near black for folders
    node.parent = parent;
    node.depth = (parent != SIZE_MAX) ? nodes[parent].depth + 1 : 0;
    node.is_expanded = false;
    node.is_visible = true;
    
    size_t node_index = nodes.size();
    nodes.push_back(node);
    
    if (parent != SIZE_MAX) {
        nodes[parent].children.push_back(node_index);
    }
    
    return node_index;
}

size_t UnifiedTreeBuilder::create_vtable_node(size_t vtable_index, size_t parent) {
    const unified_vtable_entry_t* entry = data_manager->get_entry(vtable_index);
    if (!entry) return SIZE_MAX;
    
    tree_node_t node;
    node.type = NODE_VTABLE;
    node.vtable_index = vtable_index;
    node.address = entry->vtbl_info.ea_begin;
    node.parent = parent;
    node.depth = (parent != SIZE_MAX) ? nodes[parent].depth + 1 : 0;
    node.is_expanded = false;
    node.is_visible = true;
    
    // Set display name
    if (entry->has_rtti && !entry->rtti.class_name.empty()) {
        node.name = entry->rtti.class_name;
        node.display_name = entry->rtti.class_name;
    } else {
        node.name = entry->vtbl_info.vtbl_name;
        node.display_name = entry->vtbl_info.vtbl_name;
    }
    
    // Build tooltip
    node.tooltip.sprnt("VTable: %s\nAddress: 0x%a\nMethods: %zu", 
                      node.name.c_str(), entry->vtbl_info.ea_begin, entry->vtbl_info.methods);
    
    if (entry->has_rtti) {
        node.tooltip.cat_sprnt("\nRTTI: %s", entry->rtti.compiler_name.c_str());
    }
    
    node.icon = 59;  // Class icon
    node.color = entry->display_color;
    
    size_t node_index = nodes.size();
    nodes.push_back(node);
    
    if (parent != SIZE_MAX) {
        nodes[parent].children.push_back(node_index);
    }
    
    // Add method nodes as children
    for (size_t i = 0; i < entry->methods.size(); i++) {
        create_method_node(vtable_index, i, node_index);
    }
    
    return node_index;
}

size_t UnifiedTreeBuilder::create_method_node(size_t vtable_index, size_t method_index, size_t parent) {
    const unified_vtable_entry_t* entry = data_manager->get_entry(vtable_index);
    if (!entry || method_index >= entry->methods.size()) return SIZE_MAX;
    
    const unified_method_info_t& method = entry->methods[method_index];
    
    tree_node_t node;
    node.type = NODE_METHOD;
    node.vtable_index = vtable_index;
    node.method_index = method_index;
    node.address = method.address;
    node.parent = parent;
    node.depth = nodes[parent].depth + 1;
    node.is_expanded = false;
    node.is_visible = true;
    
    // Format method name
    node.name = method.clean_name;
    node.display_name.sprnt("[%02zu] %s", method_index, method.clean_name.c_str());
    
    // Add indicators using proper string concatenation
    qstring prefix;
    if (method.is_pure_virtual) {
        prefix = "[PV] ";
    } else if (method.is_destructor) {
        prefix = "[~] ";
    } else if (method.is_overridden) {
        prefix = "[OV] ";
    }
    
    if (!prefix.empty()) {
        qstring temp = prefix;
        temp.append(node.display_name);
        node.display_name = temp;
    }
    
    // Build tooltip
    node.tooltip.sprnt("Method: %s\nAddress: 0x%a\nXRefs: %zu",
                      method.clean_name.c_str(), method.address, method.xref_count);
    
    if (method.is_pure_virtual) {
        node.tooltip.append("\nPure Virtual");
    }
    if (method.is_thunk) {
        node.tooltip.append("\nThunk");
    }
    
    node.icon = 42;  // Function icon
    node.color = method.is_pure_virtual ? 0x202020 : 0x2A2A2A;  // Dark gray for all methods
    
    size_t node_index = nodes.size();
    nodes.push_back(node);
    nodes[parent].children.push_back(node_index);
    
    return node_index;
}

qvector<size_t> UnifiedTreeBuilder::get_visible_nodes() const {
    qvector<size_t> visible;
    
    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes[i].is_visible) {
            visible.push_back(i);
        }
    }
    
    return visible;
}

//-------------------------------------------------------------------------
// UnifiedObjectExplorer Implementation
//-------------------------------------------------------------------------

// Column configuration
static const int unified_widths[] = { 35, 8, 12, 8, 6, 20, 15, 10, 8, 8 };
static const char *const unified_headers[] = { 
    "Name", "Type", "Address", "Methods", "XRefs", 
    "RTTI", "Inheritance", "Segment", "Compiler", "Size"
};

UnifiedObjectExplorer::UnifiedObjectExplorer()
    : chooser_t(CH_KEEP | CH_RESTORE | CH_CAN_REFRESH | CH_MULTI | CH_ATTRS,
                qnumber(unified_widths), unified_widths, unified_headers),
      data_manager(nullptr), filter_engine(nullptr), tree_builder(nullptr),
      current_view_mode(VIEW_HYBRID), sort_column(COL_NAME), sort_ascending(true),
      search_active(false), selected_item(0) {
    
    msg("[Unified Explorer] Constructor called\n");
    title = "Unified VTable Explorer";
    
    // Initialize components
    data_manager = new UnifiedDataManager();
    filter_engine = new UnifiedFilterEngine(data_manager);
    tree_builder = new UnifiedTreeBuilder(data_manager, filter_engine);
}

UnifiedObjectExplorer::~UnifiedObjectExplorer() {
    msg("[Unified Explorer] Destructor called\n");
    
    delete tree_builder;
    delete filter_engine;
    delete data_manager;
    
    if (g_unified_explorer == this) {
        g_unified_explorer = nullptr;
    }
}

bool idaapi UnifiedObjectExplorer::init() {
    msg("[Unified Explorer] Initializing with %zu vtables\n", vtbl_t_list.size());
    
    if (vtbl_t_list.empty()) {
        msg("[Unified Explorer] No vtables found\n");
        return true;
    }
    
    try {
        // Build data
        data_manager->build_from_vtables(UnifiedDataManager::ANALYSIS_FULL);
        
        // Build tree
        tree_builder->rebuild_tree(UnifiedDataManager::ORG_BY_NAMESPACE);
        
        // Apply initial filters (none)
        filter_engine->apply_filters();
        
        // Build display list
        build_display_list();
        
        msg("[Unified Explorer] Initialization complete with %zu display items\n", display_indices.size());
        return true;
        
    } catch (const std::exception& e) {
        msg("[Unified Explorer] Exception in init(): %s\n", e.what());
        return false;
    } catch (...) {
        msg("[Unified Explorer] Unknown exception in init()\n");
        return false;
    }
}

const void* UnifiedObjectExplorer::get_obj_id(size_t *len) const {
    static const char id[] = "UnifiedObjectExplorer";
    if (len) *len = sizeof(id);
    return id;
}

size_t idaapi UnifiedObjectExplorer::get_count() const {
    return display_indices.size();
}

void idaapi UnifiedObjectExplorer::get_row(qstrvec_t *cols, int *icon, chooser_item_attrs_t *attrs, size_t n) const {
    if (n >= display_indices.size()) return;
    
    size_t node_index = display_indices[n];
    const UnifiedTreeBuilder::tree_node_t* node = tree_builder->get_node(node_index);
    if (!node) return;
    
    cols->clear();
    cols->resize(COL_END);
    
    // Name column with tree indentation
    qstring indent;
    for (int i = 0; i < node->depth; i++) {
        indent.append("  ");
    }
    
    if (node->type == UnifiedTreeBuilder::NODE_FOLDER) {
        qstring folder_name = indent;
        folder_name.append("[DIR] ");
        folder_name.append(node->display_name);
        (*cols)[COL_NAME] = folder_name;
        (*cols)[COL_TYPE] = "Folder";
    } else if (node->type == UnifiedTreeBuilder::NODE_VTABLE) {
        const unified_vtable_entry_t* entry = data_manager->get_entry(node->vtable_index);
        if (entry) {
            // Show expansion indicator
            qstring expansion = node->is_expanded ? "▼ " : "▶ ";
            (*cols)[COL_NAME] = indent + expansion + node->display_name;
            (*cols)[COL_TYPE] = "VTable";
            (*cols)[COL_ADDRESS].sprnt("0x%a", entry->vtbl_info.ea_begin);
            (*cols)[COL_METHODS].sprnt("%zu", entry->vtbl_info.methods);
            (*cols)[COL_XREFS].sprnt("%zu", entry->xref_count);
            
            if (entry->has_rtti) {
                (*cols)[COL_RTTI] = entry->rtti.class_name;
                (*cols)[COL_COMPILER] = entry->rtti.compiler_name;
                
                // Show inheritance info
                if (!entry->rtti.base_classes.empty()) {
                    (*cols)[COL_INHERITANCE].sprnt("%zu base", entry->rtti.base_classes.size());
                }
            }
            
            (*cols)[COL_SEGMENT] = entry->segment_name;
            (*cols)[COL_SIZE].sprnt("%zu", entry->total_size);
        }
    } else if (node->type == UnifiedTreeBuilder::NODE_METHOD) {
        const unified_vtable_entry_t* entry = data_manager->get_entry(node->vtable_index);
        if (entry && node->method_index < entry->methods.size()) {
            const unified_method_info_t& method = entry->methods[node->method_index];
            
            (*cols)[COL_NAME] = indent + node->display_name;
            (*cols)[COL_TYPE] = method.is_pure_virtual ? "Pure Virtual" : "Method";
            (*cols)[COL_ADDRESS].sprnt("0x%a", method.address);
            (*cols)[COL_METHODS].sprnt("#%zu", method.method_index);
            (*cols)[COL_XREFS].sprnt("%zu", method.xref_count);
            (*cols)[COL_RTTI] = method.clean_name;
        }
    }
    
    // Set icon and colors
    if (icon) {
        *icon = node->icon;
    }
    
    if (attrs) {
        attrs->color = node->color;
        
        // Highlight search results
        if (search_active) {
            for (const auto& result : filter_engine->get_search_results()) {
                if (node->type == UnifiedTreeBuilder::NODE_VTABLE && 
                    node->vtable_index == result.entry_index) {
                    attrs->color = 0x606000;  // Dark yellow for search matches
                    break;
                }
            }
        }
    }
}

chooser_t::cbret_t idaapi UnifiedObjectExplorer::enter(size_t n) {
    if (n >= display_indices.size()) return cbret_t();
    
    size_t node_index = display_indices[n];
    const UnifiedTreeBuilder::tree_node_t* node = tree_builder->get_node(node_index);
    if (!node) return cbret_t();
    
    if (node->type == UnifiedTreeBuilder::NODE_FOLDER || 
        node->type == UnifiedTreeBuilder::NODE_VTABLE) {
        // Toggle expansion
        toggle_expansion(n);
        return cbret_t(n, chooser_base_t::ALL_CHANGED);
    } else if (node->address != BADADDR) {
        // Jump to address
        jumpto(node->address);
        return cbret_t(n, chooser_base_t::NOTHING_CHANGED);
    }
    
    return cbret_t();
}

void UnifiedObjectExplorer::toggle_expansion(size_t n) {
    if (n >= display_indices.size()) return;
    
    size_t node_index = display_indices[n];
    tree_builder->expand_node(node_index);  // This will toggle
    
    // Rebuild display list
    build_display_list();
}

void UnifiedObjectExplorer::build_display_list() {
    display_indices.clear();
    
    if (current_view_mode == VIEW_TABLE_SORTABLE) {
        // Table mode - show filtered vtables only
        const auto& filtered = filter_engine->get_filtered_indices();
        for (size_t index : filtered) {
            // Find corresponding tree node
            size_t node_index = tree_builder->find_node_by_vtable(data_manager->get_entry(index)->vtbl_info.ea_begin);
            if (node_index != SIZE_MAX) {
                display_indices.push_back(node_index);
            }
        }
    } else {
        // Tree/hybrid mode - show visible tree nodes
        auto visible_nodes = tree_builder->get_visible_nodes();
        for (size_t node_index : visible_nodes) {
            const UnifiedTreeBuilder::tree_node_t* node = tree_builder->get_node(node_index);
            if (node && node->type != UnifiedTreeBuilder::NODE_ROOT) {
                // Apply filter if active
                if (filter_engine->is_filter_active()) {
                    if (node->type == UnifiedTreeBuilder::NODE_VTABLE) {
                        if (!filter_engine->is_entry_visible(node->vtable_index)) {
                            continue;
                        }
                    } else if (node->type == UnifiedTreeBuilder::NODE_METHOD) {
                        // Check parent vtable
                        if (!filter_engine->is_entry_visible(node->vtable_index)) {
                            continue;
                        }
                    }
                }
                display_indices.push_back(node_index);
            }
        }
    }
    
    msg("[Unified Explorer] Built display list with %zu items\n", display_indices.size());
}

chooser_t::cbret_t idaapi UnifiedObjectExplorer::refresh(ssize_t n) {
    msg("[Unified Explorer] Refresh requested\n");
    
    // Rebuild data
    data_manager->build_from_vtables(UnifiedDataManager::ANALYSIS_FULL);
    tree_builder->rebuild_tree(data_manager->get_organization());
    filter_engine->apply_filters();
    build_display_list();
    
    return cbret_t(n, chooser_base_t::ALL_CHANGED);
}

void idaapi UnifiedObjectExplorer::closed() {
    msg("[Unified Explorer] Window closed\n");
    
    if (g_unified_explorer == this) {
        g_unified_explorer = nullptr;
    }
}

void UnifiedObjectExplorer::show() {
    msg("[Unified Explorer] Show called\n");
    
    // Ensure vtables are loaded
    if (vtbl_t_list.empty()) {
        msg("[Unified Explorer] No vtables loaded, searching for objects first...\n");
        extern void search_objects(bool force);
        search_objects(false);
        
        if (vtbl_t_list.empty()) {
            msg("[Unified Explorer] Still no vtables found after search\n");
            warning("No vtables found in the binary. Please run Object Explorer first.");
            return;
        }
    }
    
    try {
        if (g_unified_explorer) {
            msg("[Unified Explorer] Reactivating existing window\n");
            ssize_t result = g_unified_explorer->choose();
            if (result >= 0) {
                return;
            }
            // If failed to reactivate, create new
            delete g_unified_explorer;
            g_unified_explorer = nullptr;
        }
        
        msg("[Unified Explorer] Creating new instance\n");
        g_unified_explorer = new UnifiedObjectExplorer();
        
        if (!g_unified_explorer) {
            msg("[Unified Explorer] Failed to create instance\n");
            return;
        }
        
        ssize_t result = g_unified_explorer->choose();
        if (result < 0) {
            msg("[Unified Explorer] Failed to display window (result = %ld)\n", (long)result);
            delete g_unified_explorer;
            g_unified_explorer = nullptr;
        } else {
            msg("[Unified Explorer] Window displayed successfully\n");
        }
        
    } catch (const std::exception& e) {
        msg("[Unified Explorer] Exception: %s\n", e.what());
        if (g_unified_explorer) {
            delete g_unified_explorer;
            g_unified_explorer = nullptr;
        }
    } catch (...) {
        msg("[Unified Explorer] Unknown exception\n");
        if (g_unified_explorer) {
            delete g_unified_explorer;
            g_unified_explorer = nullptr;
        }
    }
}

//-------------------------------------------------------------------------
// Missing Function Implementations
//-------------------------------------------------------------------------

// UnifiedDataManager missing functions
const unified_vtable_entry_t* UnifiedDataManager::get_entry(size_t index) const {
    if (index >= entries.size()) return nullptr;
    return &entries[index];
}

unified_vtable_entry_t* UnifiedDataManager::get_entry_mutable(size_t index) {
    if (index >= entries.size()) return nullptr;
    return &entries[index];
}

size_t UnifiedDataManager::find_entry_by_vtable(ea_t vtable_ea) const {
    auto it = vtable_to_index.find(vtable_ea);
    return (it != vtable_to_index.end()) ? it->second : SIZE_MAX;
}

void UnifiedDataManager::set_organization(organization_mode_t mode) {
    current_organization = mode;
    rebuild_organization();
}

void UnifiedDataManager::rebuild_organization() {
    namespace_groups.clear();
    segment_groups.clear();
    depth_groups.clear();
    
    for (size_t i = 0; i < entries.size(); i++) {
        update_groupings(i);
    }
}

void UnifiedDataManager::refresh_data() {
    needs_rebuild = true;
    build_from_vtables(analysis_level);
}

void UnifiedDataManager::refresh_entry(size_t index) {
    if (index >= entries.size()) return;
    unified_vtable_entry_t& entry = entries[index];
    entry.needs_refresh = true;
    entry.last_analyzed = time(nullptr);
}

void UnifiedDataManager::clear_cache() {
    entries.clear();
    vtable_to_index.clear();
    namespace_groups.clear();
    segment_groups.clear();
    depth_groups.clear();
}

qvector<size_t> UnifiedDataManager::get_entries_by_depth(int depth) const {
    auto it = depth_groups.find(depth);
    return (it != depth_groups.end()) ? it->second : qvector<size_t>();
}

qvector<size_t> UnifiedDataManager::get_top_level_classes() const {
    return get_entries_by_depth(0);
}

void UnifiedDataManager::analyze_method_overrides() {
    msg("[Unified Explorer] Analyzing method overrides...\n");
    // Placeholder for method override analysis
}

void UnifiedDataManager::calculate_similarities() {
    msg("[Unified Explorer] Calculating similarities...\n");
    
    for (size_t i = 0; i < entries.size(); i++) {
        unified_vtable_entry_t& entry = entries[i];
        entry.max_similarity = 0.0f;
        entry.most_similar_vtable = BADADDR;
        
        for (size_t j = 0; j < entries.size(); j++) {
            if (i == j) continue;
            
            const unified_vtable_entry_t& other = entries[j];
            if (entry.vtbl_info.methods > 0 && other.vtbl_info.methods > 0) {
                float similarity = (float)qmin(entry.vtbl_info.methods, other.vtbl_info.methods) / 
                                  (float)qmax(entry.vtbl_info.methods, other.vtbl_info.methods);
                
                if (similarity > entry.max_similarity) {
                    entry.max_similarity = similarity;
                    entry.most_similar_vtable = other.vtbl_info.ea_begin;
                }
            }
        }
    }
}

void UnifiedDataManager::update_cross_references() {
    msg("[Unified Explorer] Updating cross-references...\n");
    
    for (auto& entry : entries) {
        entry.indirect_xrefs = 0;
        
        // Count indirect references through methods
        for (const auto& method : entry.methods) {
            entry.indirect_xrefs += method.xref_count;
        }
    }
}

// UnifiedFilterEngine missing functions
void UnifiedFilterEngine::clear_filters() {
    current_criteria = filter_criteria_t();
    filter_active = false;
    apply_filters();
}

bool UnifiedFilterEngine::is_entry_visible(size_t index) const {
    if (!filter_active) return true;
    
    for (size_t filtered_index : filtered_indices) {
        if (filtered_index == index) return true;
    }
    return false;
}

void UnifiedFilterEngine::clear_search() {
    search_results.clear();
}

void UnifiedFilterEngine::show_only_abstract_classes() {
    filter_criteria_t criteria;
    criteria.active_filters = FILTER_IS_ABSTRACT;
    criteria.show_abstract_only = true;
    set_filter_criteria(criteria);
}

void UnifiedFilterEngine::show_only_template_classes() {
    filter_criteria_t criteria;
    criteria.active_filters = FILTER_IS_TEMPLATE;
    criteria.show_template_only = true;
    set_filter_criteria(criteria);
}

void UnifiedFilterEngine::show_only_with_rtti() {
    filter_criteria_t criteria;
    criteria.active_filters = FILTER_HAS_RTTI;
    criteria.show_rtti_only = true;
    set_filter_criteria(criteria);
}

void UnifiedFilterEngine::show_only_with_inheritance() {
    filter_criteria_t criteria;
    criteria.active_filters = FILTER_HAS_INHERITANCE;
    criteria.show_inheritance_only = true;
    set_filter_criteria(criteria);
}

void UnifiedFilterEngine::show_by_compiler(RTTIInfo::CompilerType compiler) {
    filter_criteria_t criteria;
    criteria.active_filters = FILTER_COMPILER;
    criteria.compiler_filter = compiler;
    set_filter_criteria(criteria);
}

void UnifiedFilterEngine::show_by_segment(const qstring& segment) {
    filter_criteria_t criteria;
    criteria.active_filters = FILTER_SEGMENT;
    criteria.segment_filter = segment;
    set_filter_criteria(criteria);
}

void UnifiedFilterEngine::show_similar_to(size_t reference_index, float min_similarity) {
    filter_criteria_t criteria;
    criteria.active_filters = FILTER_SIMILARITY;
    criteria.min_similarity = min_similarity;
    set_filter_criteria(criteria);
}

float UnifiedFilterEngine::calculate_fuzzy_score(const qstring& text, const qstring& pattern) const {
    // Simplified fuzzy matching
    if (text.find(pattern) != qstring::npos) {
        return 1.0f;
    }
    return 0.0f;
}

float UnifiedFilterEngine::calculate_semantic_score(size_t index, const qstring& query) const {
    // Simplified semantic scoring
    return 0.5f;
}

// UnifiedTreeBuilder missing functions
const UnifiedTreeBuilder::tree_node_t* UnifiedTreeBuilder::get_node(size_t index) const {
    if (index >= nodes.size()) return nullptr;
    return &nodes[index];
}

void UnifiedTreeBuilder::refresh_tree() {
    rebuild_tree(current_mode);
}

void UnifiedTreeBuilder::expand_node(size_t node_index) {
    if (node_index >= nodes.size()) return;
    nodes[node_index].is_expanded = !nodes[node_index].is_expanded;
}

void UnifiedTreeBuilder::collapse_node(size_t node_index) {
    if (node_index >= nodes.size()) return;
    nodes[node_index].is_expanded = false;
}

void UnifiedTreeBuilder::expand_all() {
    for (auto& node : nodes) {
        node.is_expanded = true;
    }
}

void UnifiedTreeBuilder::collapse_all() {
    for (auto& node : nodes) {
        node.is_expanded = false;
    }
}

size_t UnifiedTreeBuilder::find_node_by_vtable(ea_t vtable_ea) const {
    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes[i].type == NODE_VTABLE && nodes[i].address == vtable_ea) {
            return i;
        }
    }
    return SIZE_MAX;
}

size_t UnifiedTreeBuilder::find_parent_vtable_node(size_t node_index) const {
    if (node_index >= nodes.size()) return SIZE_MAX;
    
    const tree_node_t& node = nodes[node_index];
    if (node.parent != SIZE_MAX) {
        const tree_node_t& parent = nodes[node.parent];
        if (parent.type == NODE_VTABLE) {
            return node.parent;
        }
        return find_parent_vtable_node(node.parent);
    }
    return SIZE_MAX;
}

qvector<size_t> UnifiedTreeBuilder::get_node_path(size_t node_index) const {
    qvector<size_t> path;
    size_t current = node_index;
    
    while (current != SIZE_MAX) {
        path.insert(path.begin(), current);
        if (current >= nodes.size()) break;
        current = nodes[current].parent;
    }
    
    return path;
}

qvector<size_t> UnifiedTreeBuilder::get_top_level_nodes() const {
    qvector<size_t> top_level;
    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes[i].parent == root_node) {
            top_level.push_back(i);
        }
    }
    return top_level;
}

void UnifiedTreeBuilder::build_inheritance_tree() {
    build_flat_tree();  // Fallback to flat tree for now
}

void UnifiedTreeBuilder::build_compiler_tree() {
    build_flat_tree();  // Fallback to flat tree for now
}

void UnifiedTreeBuilder::update_node_visibility() {
    // Update visibility based on expansion state
    for (auto& node : nodes) {
        node.is_visible = true;  // Simplified - all nodes visible
    }
}

void UnifiedTreeBuilder::calculate_node_colors() {
    // Colors already set during node creation
}

void UnifiedTreeBuilder::assign_node_icons() {
    // Icons already set during node creation  
}

//-------------------------------------------------------------------------
// Helper Functions Implementation  
//-----------------------
// Global Functions
//-------------------------------------------------------------------------

void init_unified_object_explorer() {
    msg("[Unified Explorer] Initializing unified object explorer\n");
}

void term_unified_object_explorer() {
    msg("[Unified Explorer] Terminating unified object explorer\n");
    
    if (g_unified_explorer) {
        delete g_unified_explorer;
        g_unified_explorer = nullptr;
    }
}
