/*	Copyright (c) 2013-2016
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

#ifndef __H_UTILITY__
#define __H_UTILITY__

#pragma once

#include "Common.h"


// Simple CustomView Form Init
struct string_view_form_info_t
{
	TForm *form;
	TCustomControl *cv;
	TCustomControl *codeview;
	strvec_t sv;
	string_view_form_info_t(TForm *f) : form(f), cv(NULL) {}
};

bool idaapi show_string_in_custom_view(void *ud, qstring title, qstring str);


// Size of string with out terminator
#define SIZESTR(x) (sizeof(x) - 1)


typedef qlist<ea_t> eaList;
typedef std::set<ea_t> eaSet;
typedef std::map<ea_t, UINT> eaRefMap;
struct earef
{
    ea_t ea;
    UINT refs;
};


//
// #pragma message(__LOC__ "important part to be changed")
// #pragma message(__LOC2__ "error C9901: wish that error would exist")

// Get IDA 32 bit value with verification
template <class T> bool getVerify32_t(ea_t eaPtr, T &rValue)
{
	// Location valid?
    if (isLoaded(eaPtr))
	{
		// Get 32bit value
		rValue = (T) get_32bit(eaPtr);
		return true;
	}

	return false;
}


// Check MSVC compiler
bool isMSVC();


// Get address/pointer value
inline ea_t getEa(ea_t ea)
{
    #ifndef __EA64__
    return((ea_t) get_32bit(ea));
    #else
    return((ea_t) get_64bit(ea));
    #endif
}


// Returns TRUE if ea_t sized value flags
inline BOOL isEa(flags_t f)
{
    #ifndef __EA64__
    return(isDwrd(f));
    #else
    return(isQwrd(f));
    #endif
}

#ifndef _SHA_enum_
#define _SHA_enum_
enum
{
	shaSuccess = 0,
	shaNull,  // Null pointer parameter 
	shaInputTooLong, // input data too long
	shaStateError // called Input after Result
};
#endif
#define SHA1HashSize 20

typedef struct SHA1Context
{
	uint32_t Intermediate_Hash[SHA1HashSize / 4]; // Message Digest
	uint32_t Length_Low; // Message length in bits
	uint32_t Length_High; // Message length in bits
						  // Index into message block array
	int_least16_t Message_Block_Index;
	uint8_t Message_Block[64]; // 512-bit message blocks
	int Computed; // Is the digest computed?
	int Corrupted; // Is the message digest corrupted?
} SHA1Context;

int SHA1Reset(SHA1Context *);
int SHA1Input(SHA1Context *, const uint8_t *, unsigned int);
int SHA1Result(SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);
void SHA1MessageDigestToString(uint8_t Message_Digest[SHA1HashSize], char outbuffer[SHA1HashSize * 2]);

void split_qstring(qstring &options, qstring &splitter, qvector<qstring> &result);

#endif
