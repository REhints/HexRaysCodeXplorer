/*
    VTable Method Decompilation Integration
    Hex-Rays decompiler integration for virtual method analysis
    IDA SDK 9.2 + Hex-Rays SDK
*/

#include "Common.h"
#include "ObjectExplorer.h"
#include "Utility.h"
#include <hexrays.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <auto.hpp>

// Check if Hex-Rays decompiler is available
static bool is_decompiler_available() {
    return init_hexrays_plugin() && get_hexrays_version() != nullptr;
}

// Structure to hold decompiled method information
struct decompiled_method_t {
    ea_t address;
    qstring name;
    qstring decompiled_code;
    qstring signature;
    mlist_t *microcode;
    cfuncptr_t cfunc;
    bool is_pure_virtual;
    bool is_thunk;
    size_t complexity;  // Cyclomatic complexity
    qstrvec_t called_functions;
    qstrvec_t referenced_globals;
};

// Collection of decompiled methods for a vtable
struct vtable_decompilation_t {
    ea_t vtable_ea;
    qstring class_name;
    std::vector<decompiled_method_t> methods;
    qstring full_class_declaration;
    bool has_constructor;
    bool has_destructor;
    ea_t constructor_ea;
    ea_t destructor_ea;
};

//--------------------------------------------------------------------------
// Decompile a single virtual method
//--------------------------------------------------------------------------
static bool decompile_method(ea_t method_ea, decompiled_method_t &result) {
    if (!is_decompiler_available()) {
        msg("[CodeXplorer] Hex-Rays decompiler not available\n");
        return false;
    }
    
    // Handle ARM thumb bit
    if (PH.id == PLFM_ARM) {
        method_ea &= ~1;
    }
    
    result.address = method_ea;
    result.is_pure_virtual = (method_ea == 0);
    
    // Pure virtual - no code to decompile
    if (result.is_pure_virtual) {
        result.name = "__purecall";
        result.signature = "virtual void __purecall() = 0";
        result.decompiled_code = "// Pure virtual function\n";
        return true;
    }
    
    // Check if it's a valid function
    func_t *func = get_func(method_ea);
    if (!func) {
        msg("[CodeXplorer] Warning: 0x%llx is not a function\n", (unsigned long long)method_ea);
        return false;
    }
    
    // Get function name
    get_func_name(&result.name, method_ea);
    if (result.name.empty()) {
        result.name.sprnt("sub_%llX", (unsigned long long)method_ea);
    }
    
    // Check if it's a thunk
    result.is_thunk = is_func_tail(func) || func->flags & FUNC_THUNK;
    
    // Decompile the function
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT);
    
    if (!cfunc) {
        msg("[CodeXplorer] Failed to decompile %s: %s\n", 
            result.name.c_str(), hf.desc().c_str());
        result.decompiled_code = "// Decompilation failed\n";
        return false;
    }
    
    result.cfunc = cfunc;
    
    // Get the decompiled code
    qstring code;
    cfunc->get_pseudocode(&code);
    result.decompiled_code = code;
    
    // Extract function signature
    tinfo_t func_type = cfunc->type;
    qstring signature;
    if (func_type.print(&signature)) {
        result.signature = signature;
    } else {
        // Build signature from cfunc
        result.signature = "void ";
        result.signature += result.name;
        result.signature += "(";
        
        // Add arguments
        for (size_t i = 0; i < cfunc->argidx.size(); i++) {
            if (i > 0) result.signature += ", ";
            lvar_t &arg = cfunc->lvars[cfunc->argidx[i]];
            qstring arg_type;
            arg.type().print(&arg_type);
            result.signature += arg_type;
            result.signature += " ";
            result.signature += arg.name;
        }
        result.signature += ")";
    }
    
    // Calculate cyclomatic complexity
    result.complexity = calculate_complexity(cfunc.get());
    
    // Extract called functions
    extract_called_functions(cfunc.get(), result.called_functions);
    
    // Extract referenced globals
    extract_referenced_globals(cfunc.get(), result.referenced_globals);
    
    return true;
}

//--------------------------------------------------------------------------
// Calculate cyclomatic complexity of a function
//--------------------------------------------------------------------------
static size_t calculate_complexity(cfunc_t *cfunc) {
    if (!cfunc) return 0;
    
    size_t complexity = 1;  // Base complexity
    
    // Iterate through all statements
    struct complexity_visitor_t : public ctree_visitor_t {
        size_t *complexity_ptr;
        
        complexity_visitor_t(size_t *comp) : ctree_visitor_t(CV_FAST), complexity_ptr(comp) {}
        
        int idaapi visit_expr(cexpr_t *) override { return 0; }
        
        int idaapi visit_insn(cinsn_t *insn) override {
            switch (insn->op) {
                case cit_if:      // if statement
                case cit_while:   // while loop
                case cit_for:     // for loop
                case cit_do:      // do-while loop
                    (*complexity_ptr)++;
                    break;
                case cit_switch:  // switch statement
                    (*complexity_ptr) += insn->cswitch->cases.size();
                    break;
            }
            return 0;
        }
    };
    
    complexity_visitor_t cv(&complexity);
    cv.apply_to(&cfunc->body, nullptr);
    
    return complexity;
}

//--------------------------------------------------------------------------
// Extract all functions called from decompiled code
//--------------------------------------------------------------------------
static void extract_called_functions(cfunc_t *cfunc, qstrvec_t &called_funcs) {
    if (!cfunc) return;
    
    struct call_visitor_t : public ctree_visitor_t {
        qstrvec_t *funcs;
        
        call_visitor_t(qstrvec_t *f) : ctree_visitor_t(CV_FAST), funcs(f) {}
        
        int idaapi visit_expr(cexpr_t *expr) override {
            if (expr->op == cot_call) {
                // Direct call
                if (expr->x && expr->x->op == cot_obj) {
                    ea_t call_ea = expr->x->obj_ea;
                    qstring func_name;
                    get_func_name(&func_name, call_ea);
                    if (func_name.empty()) {
                        func_name.sprnt("sub_%llX", (unsigned long long)call_ea);
                    }
                    funcs->push_back(func_name);
                }
                // Indirect call (virtual function call)
                else if (expr->x && expr->x->op == cot_memptr) {
                    funcs->push_back("[virtual call]");
                }
            }
            return 0;
        }
        
        int idaapi visit_insn(cinsn_t *) override { return 0; }
    };
    
    call_visitor_t cv(&called_funcs);
    cv.apply_to(&cfunc->body, nullptr);
}

//--------------------------------------------------------------------------
// Extract global variables referenced in the function
//--------------------------------------------------------------------------
static void extract_referenced_globals(cfunc_t *cfunc, qstrvec_t &globals) {
    if (!cfunc) return;
    
    struct global_visitor_t : public ctree_visitor_t {
        qstrvec_t *globs;
        
        global_visitor_t(qstrvec_t *g) : ctree_visitor_t(CV_FAST), globs(g) {}
        
        int idaapi visit_expr(cexpr_t *expr) override {
            if (expr->op == cot_obj) {
                // Check if it's a global variable
                ea_t obj_ea = expr->obj_ea;
                if (!get_func(obj_ea)) {  // Not inside a function = likely global
                    qstring name;
                    get_name(&name, obj_ea);
                    if (!name.empty()) {
                        globs->push_back(name);
                    } else {
                        qstring addr_name;
                        addr_name.sprnt("global_%llX", (unsigned long long)obj_ea);
                        globs->push_back(addr_name);
                    }
                }
            }
            return 0;
        }
        
        int idaapi visit_insn(cinsn_t *) override { return 0; }
    };
    
    global_visitor_t gv(&globals);
    gv.apply_to(&cfunc->body, nullptr);
}

//--------------------------------------------------------------------------
// Decompile all methods of a vtable
//--------------------------------------------------------------------------
bool decompile_vtable_methods(ea_t vtbl_ea, vtable_decompilation_t &result) {
    // Find the vtable in our list
    VTBL_info_t *vtbl = nullptr;
    for (auto &v : vtbl_t_list) {
        if (v.ea_begin == vtbl_ea) {
            vtbl = &v;
            break;
        }
    }
    
    if (!vtbl) {
        msg("[CodeXplorer] VTable at 0x%llx not found\n", (unsigned long long)vtbl_ea);
        return false;
    }
    
    result.vtable_ea = vtbl_ea;
    result.class_name = vtbl->vtbl_name;
    
    msg("[CodeXplorer] Decompiling %llu methods for %s...\n", 
        (unsigned long long)vtbl->methods, result.class_name.c_str());
    
    // Decompile each method
    ea_t method_ptr = vtbl->ea_begin;
    for (size_t i = 0; i < vtbl->methods; i++) {
        ea_t method_ea = getEa(method_ptr);
        
        decompiled_method_t method;
        if (decompile_method(method_ea, method)) {
            result.methods.push_back(method);
            
            // Check for constructor/destructor patterns
            if (method.name.find("ctor") != qstring::npos || 
                method.name.find(result.class_name) != qstring::npos) {
                result.has_constructor = true;
                result.constructor_ea = method_ea;
            }
            if (method.name.find("dtor") != qstring::npos || 
                method.name.find("~") != qstring::npos) {
                result.has_destructor = true;
                result.destructor_ea = method_ea;
            }
            
            msg("  [%d] %s - Complexity: %d\n", 
                (int)i, method.name.c_str(), (int)method.complexity);
        }
        
        method_ptr += EA_SIZE;
    }
    
    msg("[CodeXplorer] Decompiled %d/%d methods successfully\n", 
        (int)result.methods.size(), (int)vtbl->methods);
    
    return !result.methods.empty();
}

//--------------------------------------------------------------------------
// Generate complete C++ class from decompiled vtable
//--------------------------------------------------------------------------
qstring generate_class_from_vtable(const vtable_decompilation_t &vtbl_decompile) {
    qstring output;
    
    // Extract clean class name
    qstring class_name = vtbl_decompile.class_name;
    if (class_name.find("vtable for ") == 0) {
        class_name.remove(0, strlen("vtable for "));
    }
    if (class_name.find("`vtable for'") == 0) {
        class_name.remove(0, strlen("`vtable for'"));
        if (class_name.length() > 0 && class_name.last() == '\'')
            class_name.remove_last();
    }
    
    // Header comment
    output += "/*\n";
    output += " * Class: " + class_name + "\n";
    output.cat_sprnt(" * VTable: 0x%llX\n", (unsigned long long)vtbl_decompile.vtable_ea);
    output.cat_sprnt(" * Methods: %d\n", (int)vtbl_decompile.methods.size());
    if (vtbl_decompile.has_constructor) {
        output.cat_sprnt(" * Constructor: 0x%llX\n", (unsigned long long)vtbl_decompile.constructor_ea);
    }
    if (vtbl_decompile.has_destructor) {
        output.cat_sprnt(" * Destructor: 0x%llX\n", (unsigned long long)vtbl_decompile.destructor_ea);
    }
    output += " * Generated by HexRaysCodeXplorer\n";
    output += " */\n\n";
    
    // Class declaration
    output += "class " + class_name + " {\n";
    output += "public:\n";
    
    // Generate method declarations
    for (size_t i = 0; i < vtbl_decompile.methods.size(); i++) {
        const auto &method = vtbl_decompile.methods[i];
        
        output += "    ";
        if (method.is_pure_virtual) {
            output.cat_sprnt("virtual void method_%d() = 0;  // Pure virtual\n", (int)i);
        } else {
            // Try to use the signature
            if (!method.signature.empty()) {
                output += "virtual " + method.signature + ";";
            } else {
                output += "virtual void " + method.name + "();";
            }
            
            // Add comment with address and complexity
            output.cat_sprnt("  // 0x%llX", (unsigned long long)method.address);
            if (method.complexity > 10) {
                output.cat_sprnt(" [Complex: %d]", (int)method.complexity);
            }
            if (method.is_thunk) {
                output += " [Thunk]";
            }
            output += "\n";
        }
    }
    
    output += "};\n\n";
    
    // Add decompiled method implementations
    output += "// ============== Method Implementations ==============\n\n";
    
    for (const auto &method : vtbl_decompile.methods) {
        if (!method.is_pure_virtual && !method.decompiled_code.empty()) {
            output += "// " + class_name + "::" + method.name + "\n";
            output.cat_sprnt("// Address: 0x%llX\n", (unsigned long long)method.address);
            output.cat_sprnt("// Complexity: %d\n", (int)method.complexity);
            
            if (!method.called_functions.empty()) {
                output += "// Calls: ";
                for (size_t i = 0; i < method.called_functions.size(); i++) {
                    if (i > 0) output += ", ";
                    output += method.called_functions[i];
                }
                output += "\n";
            }
            
            if (!method.referenced_globals.empty()) {
                output += "// Globals: ";
                for (size_t i = 0; i < method.referenced_globals.size(); i++) {
                    if (i > 0) output += ", ";
                    output += method.referenced_globals[i];
                }
                output += "\n";
            }
            
            output += method.decompiled_code;
            output += "\n\n";
        }
    }
    
    return output;
}

//--------------------------------------------------------------------------
// Compare virtual methods across multiple classes (polymorphism analysis)
//--------------------------------------------------------------------------
struct method_comparison_t {
    qstring method_name;
    size_t method_index;
    struct implementation_t {
        qstring class_name;
        ea_t address;
        size_t complexity;
        bool is_pure_virtual;
        bool is_identical;  // Same implementation as base
        qstring decompiled_snippet;  // First 10 lines
    };
    std::vector<implementation_t> implementations;
};

bool compare_vtable_methods(const std::vector<ea_t> &vtable_addresses, 
                           std::vector<method_comparison_t> &comparison) {
    if (vtable_addresses.size() < 2) {
        msg("[CodeXplorer] Need at least 2 vtables to compare\n");
        return false;
    }
    
    // Decompile all vtables
    std::vector<vtable_decompilation_t> decompilations;
    size_t max_methods = 0;
    
    for (ea_t vtbl_ea : vtable_addresses) {
        vtable_decompilation_t vtbl_decomp;
        if (decompile_vtable_methods(vtbl_ea, vtbl_decomp)) {
            decompilations.push_back(vtbl_decomp);
            if (vtbl_decomp.methods.size() > max_methods) {
                max_methods = vtbl_decomp.methods.size();
            }
        }
    }
    
    // Compare methods at each index
    for (size_t method_idx = 0; method_idx < max_methods; method_idx++) {
        method_comparison_t comp;
        comp.method_index = method_idx;
        
        for (const auto &vtbl_decomp : decompilations) {
            if (method_idx < vtbl_decomp.methods.size()) {
                const auto &method = vtbl_decomp.methods[method_idx];
                
                method_comparison_t::implementation_t impl;
                impl.class_name = vtbl_decomp.class_name;
                impl.address = method.address;
                impl.complexity = method.complexity;
                impl.is_pure_virtual = method.is_pure_virtual;
                
                // Get first 10 lines of decompiled code
                qstring snippet = method.decompiled_code;
                size_t line_count = 0;
                size_t pos = 0;
                while (pos < snippet.length() && line_count < 10) {
                    pos = snippet.find('\n', pos);
                    if (pos == qstring::npos) break;
                    pos++;
                    line_count++;
                }
                if (pos != qstring::npos) {
                    snippet.truncate(pos);
                }
                impl.decompiled_snippet = snippet;
                
                // Check if implementation is identical to first one
                if (!comp.implementations.empty()) {
                    impl.is_identical = (impl.decompiled_snippet == 
                                       comp.implementations[0].decompiled_snippet);
                }
                
                comp.implementations.push_back(impl);
                
                // Use first non-pure virtual method name
                if (comp.method_name.empty() && !method.is_pure_virtual) {
                    comp.method_name = method.name;
                }
            }
        }
        
        if (comp.method_name.empty()) {
            comp.method_name.sprnt("method_%d", (int)method_idx);
        }
        
        comparison.push_back(comp);
    }
    
    return true;
}

//--------------------------------------------------------------------------
// Export decompiled vtable to file
//--------------------------------------------------------------------------
bool export_decompiled_vtable(const vtable_decompilation_t &vtbl_decomp, 
                             const char *filename) {
    FILE *f = qfopen(filename, "w");
    if (!f) {
        msg("[CodeXplorer] Failed to create file: %s\n", filename);
        return false;
    }
    
    qstring class_code = generate_class_from_vtable(vtbl_decomp);
    qfprintf(f, "%s", class_code.c_str());
    
    qfclose(f);
    msg("[CodeXplorer] Exported decompiled class to %s\n", filename);
    return true;
}

//--------------------------------------------------------------------------
// Interactive method decompilation with Hex-Rays window
//--------------------------------------------------------------------------
void show_decompiled_method(ea_t method_ea) {
    if (!is_decompiler_available()) {
        msg("[CodeXplorer] Hex-Rays decompiler not available\n");
        return;
    }
    
    // Handle ARM thumb bit
    if (PH.id == PLFM_ARM) {
        method_ea &= ~1;
    }
    
    // Open decompiler window
    if (method_ea != 0) {
        open_pseudocode(method_ea, -1);
    } else {
        msg("[CodeXplorer] Cannot decompile pure virtual function\n");
    }
}

//--------------------------------------------------------------------------
// Batch decompile all methods and show in new window
//--------------------------------------------------------------------------
void show_all_decompiled_methods(ea_t vtbl_ea) {
    vtable_decompilation_t vtbl_decomp;
    if (!decompile_vtable_methods(vtbl_ea, vtbl_decomp)) {
        msg("[CodeXplorer] Failed to decompile vtable methods\n");
        return;
    }
    
    // Generate the complete class code
    qstring class_code = generate_class_from_vtable(vtbl_decomp);
    
    // Create a custom viewer to display the code
    qstring title;
    title.sprnt("Decompiled: %s", vtbl_decomp.class_name.c_str());
    
    TWidget *widget = find_widget(title.c_str());
    if (widget) {
        activate_widget(widget, true);
        return;
    }
    
    // Create new widget
    widget = create_empty_widget(title.c_str());
    
    // Create lines for display
    qstrvec_t lines;
    size_t pos = 0;
    while (pos < class_code.length()) {
        size_t next = class_code.find('\n', pos);
        if (next == qstring::npos) {
            lines.push_back(simpleline_t(class_code.substr(pos)));
            break;
        }
        lines.push_back(simpleline_t(class_code.substr(pos, next - pos)));
        pos = next + 1;
    }
    
    // Create custom viewer
    simpleline_place_t s1;
    simpleline_place_t s2((int)lines.size() - 1);
    TWidget *cv = create_custom_viewer("", &s1, &s2, &s1, nullptr, &lines, nullptr, nullptr, widget);
    TWidget *code_view = create_code_viewer(cv, CDVF_STATUSBAR, widget);
    
    display_widget(widget, WOPN_DP_TAB | WOPN_RESTORE);
}

//--------------------------------------------------------------------------
// Apply vtable type information to decompiled code
//--------------------------------------------------------------------------
bool apply_vtable_types_to_decompilation(ea_t vtbl_ea) {
    VTBL_info_t *vtbl = nullptr;
    for (auto &v : vtbl_t_list) {
        if (v.ea_begin == vtbl_ea) {
            vtbl = &v;
            break;
        }
    }
    
    if (!vtbl) return false;
    
    // Extract class name
    qstring class_name = vtbl->vtbl_name;
    if (class_name.find("vtable for ") == 0) {
        class_name.remove(0, strlen("vtable for "));
    }
    
    // Create a structure type for the class
    struc_t *sptr = get_struc(get_struc_id(class_name.c_str()));
    if (!sptr) {
        tid_t sid = add_struc(BADADDR, class_name.c_str());
        if (sid == BADADDR) {
            msg("[CodeXplorer] Failed to create structure for %s\n", class_name.c_str());
            return false;
        }
        sptr = get_struc(sid);
    }
    
    // Add vtable pointer as first member
    tinfo_t ptr_tinfo;
    ptr_tinfo.create_ptr(tinfo_t(BTF_VOID));
    add_struc_member(sptr, "vftable", 0, FF_DATA | FF_QWORD, nullptr, EA_SIZE);
    
    // Set member type
    smt_member_t smt;
    smt.tid = sptr->id;
    smt.member_idx = 0;
    smt.type = ptr_tinfo;
    set_member_tinfo(&smt);
    
    msg("[CodeXplorer] Applied type information for %s\n", class_name.c_str());
    return true;
}