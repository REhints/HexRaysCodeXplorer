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

#pragma warning (disable: 4996 4800 )

#ifdef __LINUX__
#include <stdint.h>
#define UINT uint32_t
#define PUINT uint32_t *
#define CHAR int8_t
#define UCHAR uint8_t
#define TCHAR uint8_t
#define WCHAR wchar_t
#define BOOL bool
#define TRUE true
#define FALSE false
#define LPCSTR char *const
#define LPCTSTR char *const
#define LPSTR char *
#define DWORD uint32_t
#define PDWORD DWORD*
#define PVOID void*

#define IN
#define OUT

/* Ugly but ... */
#define sprintf_s snprintf
#endif

#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <gdl.hpp>
