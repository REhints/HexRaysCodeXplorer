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

#ifndef __H_COMMON__
#define __H_COMMON__

#pragma once

#if !defined (__LINUX__) && !defined (__MAC__)
    #ifdef __MAKEDLL__
    #  define DLLEXPORT __declspec(dllexport)
    #else
    #  define DLLEXPORT __declspec(dllimport)
    #endif
#else
    #define DLLEXPORT
#endif




#if !defined (__LINUX__) && !defined (__MAC__)
#pragma warning (disable: 4996 4800 )
#else
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#if !defined (__LINUX__) && !defined (__MAC__)
#include <windows.h>
#include <tchar.h>
#else
#include "Linux.h"
#endif

#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:4309 4244 4267)           // disable "truncation of constant value" warning from IDA SDK, conversion from 'ssize_t' to 'int', possible loss of data
#endif // __NT__
#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS
#endif
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wvarargs"
#pragma clang diagnostic ignored "-Wlogical-op-parentheses"
#pragma clang diagnostic ignored "-Wunused-private-field"
#endif
#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <gdl.hpp>
#include <struct.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <search.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <demangle.hpp>
#include <typeinf.hpp>
#include <moves.hpp>
#include <bytes.hpp>
#include <unordered_map>


#ifdef __NT__
#pragma warning(pop)
#endif // __NT__
#ifdef __clang__
#pragma clang diagnostic pop
#endif

template<typename T>
struct print1_accepts_qstring
{
    template<typename U, void (U::*)(qstring *, const cfunc_t *) const> struct yay_sfinae {};
    template<typename U> static char test(yay_sfinae<U, &U::print1>*);
    template<typename U> static int test(...);
    static const bool value = sizeof(test<T>(0)) == sizeof(char);
};

// For IDA7.1 and newer
template <class T>
void print1wrapper(std::true_type, const T *e, qstring *qbuf, const cfunc_t *func) {
  e->print1(qbuf, func);
};

// For older SDKs
template <class T>
void print1wrapper(std::false_type, const T *e, qstring *qbuf, const cfunc_t *func) {
  char lbuf[MAXSTR];
  const size_t len = e->print1(lbuf, sizeof(lbuf) - 1, func);
  qstring temp(lbuf, len);
  qbuf->swap(temp);
};

template <class T>
void print1wrapper(const T *e, qstring *qbuf, const cfunc_t *func) {
  return print1wrapper(
      std::integral_constant<bool, print1_accepts_qstring<T>::value>(),
      e, qbuf, func);
}



#include <cstring>
#include <cstdarg>
#include <cstdint>

#include <iterator>
#include <string>
#include <vector>
#include <list>
#include <set>
#include <map>
#include <iostream>
#include <sstream>

#endif

