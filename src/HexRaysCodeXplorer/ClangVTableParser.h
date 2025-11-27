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
#include "ObjectExplorer.h"
#include <vector>
#include <string>
#include <unordered_map>

namespace ClangVTableParser {

struct VTableInfo {
    ea_t ea;
    std::string name;
    std::string demangled_name;
    std::string class_name;
};

// Find vtables by looking for _ZTV symbols
bool find_vtables_by_symbol_pattern(std::vector<VTableInfo>& vtables);

// Find vtables by scanning memory patterns
bool find_vtables_by_scanning(std::vector<VTableInfo>& vtables);

// Main entry point - parse vtables and fill the rtti_vftables map
bool parse_vtables_for_rtti(std::unordered_map<ea_t, VTBL_info_t>& rtti_vftables);

} // namespace ClangVTableParser