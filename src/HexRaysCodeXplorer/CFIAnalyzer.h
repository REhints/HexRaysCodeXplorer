/*	Copyright (c) 2024
	REhints <info@rehints.com>
	All rights reserved.
	
	==============================================================================
	
	This file is part of HexRaysCodeXplorer

 	HexRaysCodeXplorer is free software: you can redistribute it and/or modify it
 	under the terms of the GNU General Public License as published by
 	the Free Software Foundation, either version 3 of the License, or
 	(at your option) any later version.

 	This program is distributed in the hope that it will be useful, but
 	WITHOUT ANY WARRANTY; without even the implied warranty of
 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 	General Public License for more details.

 	You should have received a copy of the GNU General Public License
 	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	==============================================================================
*/

#pragma once

#include "Common.h"
#include <vector>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>

namespace CFI {

// Forward declarations
class CFIAnalyzer;
class ClangCFIAnalyzer;
class MSVCCFGAnalyzer;
struct CFIMetadata;
struct CFICheck;

// CFI scheme types
enum class CFIScheme {
    NONE,
    CLANG_CFI,      // Clang Control Flow Integrity
    MSVC_CFG,       // Microsoft Control Flow Guard
    INTEL_CET,      // Intel Control-flow Enforcement Technology
    ARM_BTI,        // ARM Branch Target Identification
    ARM_PAC         // ARM Pointer Authentication
};

// CFI check types
enum class CFICheckType {
    VCALL,          // Virtual call check
    NVCALL,         // Non-virtual call check
    CAST,           // Cast check
    UNRELATED_CAST, // Unrelated cast check
    ICALL,          // Indirect call check
    RETURN,         // Return address check
    JUMP            // Indirect jump check
};

// CFI violation actions
enum class CFIViolationAction {
    TRAP,           // Generate trap/breakpoint
    ABORT,          // Call abort()
    REPORT,         // Report and continue
    CUSTOM          // Custom handler
};

// CFI metadata for a function or vtable
struct CFIMetadata {
    ea_t address;
    CFIScheme scheme;
    std::vector<uint32_t> type_hashes;  // Type hashes for Clang CFI
    uint32_t cfg_flags;                 // Flags for MSVC CFG
    
    // Check if type is allowed
    bool is_type_allowed(uint32_t type_hash) const {
        return std::find(type_hashes.begin(), type_hashes.end(), type_hash) != type_hashes.end();
    }
};

// CFI check point in code
struct CFICheck {
    ea_t check_address;
    ea_t target_address;
    CFICheckType type;
    CFIViolationAction violation_action;
    
    // For Clang CFI
    uint32_t expected_type_hash;
    ea_t type_check_function;
    
    // For MSVC CFG
    ea_t guard_check_function;
    bool is_suppressed;
    
    // Analysis results
    bool is_valid;
    std::string violation_reason;
};

// CFI protected call site
struct CFIProtectedCall {
    ea_t call_site;
    ea_t callee;
    CFICheckType check_type;
    
    // Protection metadata
    bool has_type_check;
    bool has_range_check;
    bool has_alignment_check;
    
    // Allowed targets (for indirect calls)
    std::vector<ea_t> allowed_targets;
    
    // Check if target is allowed
    bool is_target_allowed(ea_t target) const {
        if (allowed_targets.empty())
            return true;  // No restrictions
        return std::find(allowed_targets.begin(), allowed_targets.end(), target) != allowed_targets.end();
    }
};

// CFI statistics for analysis
struct CFIStatistics {
    size_t total_indirect_calls;
    size_t protected_calls;
    size_t unprotected_calls;
    size_t total_vtables;
    size_t protected_vtables;
    size_t total_checks;
    size_t valid_checks;
    size_t invalid_checks;
    
    double get_coverage() const {
        if (total_indirect_calls == 0) return 0.0;
        return (double)protected_calls / total_indirect_calls * 100.0;
    }
};

// Base CFI Analyzer
class CFIAnalyzer {
public:
    CFIAnalyzer();
    virtual ~CFIAnalyzer();
    
    // Detection
    virtual CFIScheme detect_cfi_scheme() = 0;
    virtual bool is_cfi_enabled() const = 0;
    
    // Analysis
    virtual std::vector<CFICheck> find_cfi_checks() = 0;
    virtual std::unique_ptr<CFIMetadata> get_metadata(ea_t addr) = 0;
    virtual bool is_protected(ea_t addr) const = 0;
    
    // Validation
    virtual bool validate_check(const CFICheck& check) = 0;
    virtual std::vector<ea_t> find_violations() = 0;
    
    // Statistics
    virtual CFIStatistics get_statistics() = 0;
    
protected:
    CFIScheme scheme_;
    std::map<ea_t, std::shared_ptr<CFIMetadata>> metadata_cache_;
    std::vector<CFICheck> checks_;
};

// Clang CFI Analyzer
class ClangCFIAnalyzer : public CFIAnalyzer {
public:
    ClangCFIAnalyzer();
    ~ClangCFIAnalyzer() override;
    
    // CFI type information
    struct TypeInfo {
        std::string type_name;
        uint32_t type_hash;
        std::vector<ea_t> vtables;
        std::vector<ea_t> functions;
    };
    
    // Overrides
    CFIScheme detect_cfi_scheme() override;
    bool is_cfi_enabled() const override;
    std::vector<CFICheck> find_cfi_checks() override;
    std::unique_ptr<CFIMetadata> get_metadata(ea_t addr) override;
    bool is_protected(ea_t addr) const override;
    bool validate_check(const CFICheck& check) override;
    std::vector<ea_t> find_violations() override;
    CFIStatistics get_statistics() override;
    
    // Clang-specific
    std::vector<TypeInfo> extract_type_info();
    uint32_t calculate_type_hash(const std::string& type_name) const;
    ea_t find_cfi_check_function(CFICheckType type) const;
    bool has_cfi_sanitizer() const;
    
    // CFI scheme detection
    bool has_cfi_vcall() const;
    bool has_cfi_nvcall() const;
    bool has_cfi_cast() const;
    bool has_cfi_icall() const;
    
private:
    std::map<uint32_t, TypeInfo> type_info_map_;
    std::unordered_set<ea_t> protected_functions_;
    
    // Pattern matching
    bool match_cfi_check_pattern(ea_t addr) const;
    bool match_type_check_pattern(ea_t addr) const;
    ea_t find_type_check_impl(ea_t check_addr) const;
};

// MSVC CFG Analyzer
class MSVCCFGAnalyzer : public CFIAnalyzer {
public:
    MSVCCFGAnalyzer();
    ~MSVCCFGAnalyzer() override;
    
    // CFG target information
    struct CFGTarget {
        ea_t address;
        uint32_t flags;
        bool is_export_suppressed;
        bool is_long_jump_target;
    };
    
    // Overrides
    CFIScheme detect_cfi_scheme() override;
    bool is_cfi_enabled() const override;
    std::vector<CFICheck> find_cfi_checks() override;
    std::unique_ptr<CFIMetadata> get_metadata(ea_t addr) override;
    bool is_protected(ea_t addr) const override;
    bool validate_check(const CFICheck& check) override;
    std::vector<ea_t> find_violations() override;
    CFIStatistics get_statistics() override;
    
    // MSVC-specific
    std::vector<CFGTarget> get_cfg_targets();
    bool is_cfg_valid_target(ea_t addr) const;
    ea_t find_guard_check_icall() const;
    ea_t find_guard_dispatch_icall() const;
    bool has_guard_cf_table() const;
    
    // CFG bitmap analysis
    bool analyze_cfg_bitmap();
    bool is_in_cfg_bitmap(ea_t addr) const;
    
private:
    std::vector<CFGTarget> cfg_targets_;
    ea_t guard_check_icall_;
    ea_t guard_dispatch_icall_;
    ea_t cfg_bitmap_base_;
    size_t cfg_bitmap_size_;
    
    // Pattern matching
    bool match_guard_check_pattern(ea_t addr) const;
    bool parse_gfids_section();
    bool parse_load_config();
};

// Intel CET Analyzer
class IntelCETAnalyzer : public CFIAnalyzer {
public:
    IntelCETAnalyzer();
    ~IntelCETAnalyzer() override;
    
    // CET-specific features
    bool has_shadow_stack() const;
    bool has_indirect_branch_tracking() const;
    std::vector<ea_t> find_endbr_instructions();
    
    // Overrides
    CFIScheme detect_cfi_scheme() override;
    bool is_cfi_enabled() const override;
    std::vector<CFICheck> find_cfi_checks() override;
    std::unique_ptr<CFIMetadata> get_metadata(ea_t addr) override;
    bool is_protected(ea_t addr) const override;
    bool validate_check(const CFICheck& check) override;
    std::vector<ea_t> find_violations() override;
    CFIStatistics get_statistics() override;
    
private:
    bool shadow_stack_enabled_;
    bool ibt_enabled_;
    std::vector<ea_t> endbr_locations_;
    
    bool check_cet_flags();
    bool find_endbr_pattern(ea_t addr) const;
};

// ARM BTI/PAC Analyzer
class ARMCFIAnalyzer : public CFIAnalyzer {
public:
    ARMCFIAnalyzer();
    ~ARMCFIAnalyzer() override;
    
    // ARM-specific features
    bool has_bti() const;
    bool has_pac() const;
    std::vector<ea_t> find_bti_instructions();
    std::vector<ea_t> find_pac_instructions();
    
    // Overrides
    CFIScheme detect_cfi_scheme() override;
    bool is_cfi_enabled() const override;
    std::vector<CFICheck> find_cfi_checks() override;
    std::unique_ptr<CFIMetadata> get_metadata(ea_t addr) override;
    bool is_protected(ea_t addr) const override;
    bool validate_check(const CFICheck& check) override;
    std::vector<ea_t> find_violations() override;
    CFIStatistics get_statistics() override;
    
private:
    bool bti_enabled_;
    bool pac_enabled_;
    std::vector<ea_t> bti_locations_;
    std::vector<ea_t> pac_locations_;
    
    bool check_arm_features();
    bool find_bti_pattern(ea_t addr) const;
    bool find_pac_pattern(ea_t addr) const;
};

// Unified CFI Analyzer that detects and uses appropriate analyzer
class UnifiedCFIAnalyzer {
public:
    UnifiedCFIAnalyzer();
    ~UnifiedCFIAnalyzer();
    
    // Auto-detect and initialize appropriate analyzer
    bool initialize();
    
    // Get detected scheme
    CFIScheme get_scheme() const { return scheme_; }
    
    // Analysis functions
    bool analyze_binary();
    CFIStatistics get_statistics() const;
    
    // Find all CFI-protected virtual calls
    std::vector<CFIProtectedCall> find_protected_vcalls();
    
    // Find all CFI-protected indirect calls
    std::vector<CFIProtectedCall> find_protected_icalls();
    
    // Check if a specific call is protected
    bool is_call_protected(ea_t call_site) const;
    
    // Validate all CFI checks in binary
    std::vector<CFICheck> validate_all_checks();
    
    // Find potential CFI bypasses
    std::vector<ea_t> find_potential_bypasses();
    
    // Export results
    void export_to_json(const std::string& filename) const;
    void export_statistics(const std::string& filename) const;
    
private:
    CFIScheme scheme_;
    std::unique_ptr<CFIAnalyzer> analyzer_;
    CFIStatistics stats_;
    std::vector<CFIProtectedCall> protected_calls_;
    
    // Detection helpers
    CFIScheme detect_cfi_scheme() const;
    std::unique_ptr<CFIAnalyzer> create_analyzer(CFIScheme scheme);
};

// Helper functions
bool is_indirect_call(ea_t addr);
bool is_virtual_call(ea_t addr);
ea_t get_indirect_target(ea_t call_site);
std::string cfi_scheme_to_string(CFIScheme scheme);
std::string cfi_check_type_to_string(CFICheckType type);

} // namespace CFI

#endif // CFI_ANALYZER_H