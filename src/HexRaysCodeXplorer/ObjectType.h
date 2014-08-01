/*	Copyright (c) 2013
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

#ifndef __LINUX__
#include <Windows.h>
#include <tchar.h>
#endif
#include <iterator>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <iostream>


using namespace std;

typedef std::basic_string<TCHAR>	TSTRING;
typedef std::basic_string<WCHAR>	WSTRING;
typedef std::basic_string<CHAR>		ASTRING;
typedef std::vector<UCHAR>			BUFFER;

#ifdef _UNICODE
#define tcout						std::wcout
#else
#define tcout						std::cout
#endif


bool idaapi reconstruct_type(void *ud);
