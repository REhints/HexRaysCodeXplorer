/*	Copyright (c) 2013-2015
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

#if defined (__LINUX__) || defined (__MAC__)

#pragma GCC diagnostic ignored "-fpermissive"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

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
#define WORD uint16_t
#define DWORD uint32_t
#define PDWORD DWORD*
#define PVOID void*
#define PINT int*
#define UINT64 uint64_t

#define ZeroMemory(dst, length) 	memset(dst, 0, length)

/* Those are header annotations in Visual Studio and can be safely ignored */
#define IN
#define OUT
#define __bcount(element) 

/* Ugly but ... */
#define sprintf_s snprintf
#define _snprintf snprintf
#endif