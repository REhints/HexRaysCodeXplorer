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
 	along with this program.  If not, see
 	<http://www.gnu.org/licenses/>.

	==============================================================================
*/

#include "Common.h"
#include "Utility.h"

#include "Debug.h"

#if defined (__LINUX__) || defined (__MAC__)
#include "Linux.h"
#endif

bool compilerIs(const char *name)
{
	comp_t vc = default_compiler();
	//qstring comp = get_compiler_name(vc); //fullname
	qstring comp = get_compiler_abbr(vc);

	if (comp == name)
		return true;
	return false;
}

bool idaapi show_string_in_custom_view(void *ud, const qstring& title, const qstring& str)
{
	TWidget *widget = create_empty_widget(title.c_str());
	string_view_form_info_t *si = new string_view_form_info_t(widget);
	si->sv.push_back(simpleline_t(str));

	simpleline_place_t s1;
	simpleline_place_t s2(static_cast<int>(si->sv.size()));
	si->cv = create_custom_viewer((title + "_").c_str(), &s1, &s2, &s1, nullptr, &si->sv, nullptr, nullptr, widget);
	si->codeview = create_code_viewer(si->cv, CDVF_NOLINES, widget);
	set_custom_viewer_handlers(si->cv, nullptr, si);
	display_widget(widget, WOPN_RESTORE);

	return false;
}

void split_qstring(const qstring &options, const qstring &splitter, qvector<qstring> &result) {
	size_t start_pos = 0;

	do {
		size_t npos = options.find(splitter, start_pos);
		if (npos != -1) {
			if (npos != start_pos) {
				result.push_back(options.substr(start_pos, npos));
			}
			start_pos = npos + splitter.length();
		}
		else {
			qstring token = options.substr(start_pos);
			if (token.length() != 0)
				result.push_back(token);
			break;
		}
	} while (start_pos < options.length());
}


// SHA1 implementation
#define SHA1CircularShift(bits,word)(((word) << (bits)) | ((word) >> (32-(bits))))

void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

int SHA1Reset(SHA1Context *context)
{
	if (!context)
		return shaNull;

	context->Length_Low = 0;
	context->Length_High = 0;
	context->Message_Block_Index = 0;
	context->Intermediate_Hash[0] = 0x67452301;
	context->Intermediate_Hash[1] = 0xEFCDAB89;
	context->Intermediate_Hash[2] = 0x98BADCFE;
	context->Intermediate_Hash[3] = 0x10325476;
	context->Intermediate_Hash[4] = 0xC3D2E1F0;
	context->Computed = 0;
	context->Corrupted = 0;
	return shaSuccess;
}

int SHA1Result(SHA1Context *context, uint8_t Message_Digest[SHA1HashSize])
{
	int i;
	if (!context || !Message_Digest)
		return shaNull;
	
	if (context->Corrupted)
		return context->Corrupted;
	
	if (!context->Computed)
	{
		SHA1PadMessage(context);
		for (i = 0; i<64; ++i)
			context->Message_Block[i] = 0;
		
		context->Length_Low = 0; /* and clear length */
		context->Length_High = 0;
		context->Computed = 1;
	}
	for (i = 0; i < SHA1HashSize; ++i)
		Message_Digest[i] = context->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));

	return shaSuccess;
}

int SHA1Input(SHA1Context *context, const uint8_t *message_array, unsigned int length)
{
	if (!length)
	{
		return shaSuccess;
	}
	if (!context || !message_array)
	{
		return shaNull;
	}
	if (context->Computed)
	{
		context->Corrupted = shaStateError;
		return shaStateError;
	}
	if (context->Corrupted)
	{
		return context->Corrupted;
	}
	while (length-- && !context->Corrupted)
	{
		context->Message_Block[context->Message_Block_Index++] =
			(*message_array & 0xFF);
		context->Length_Low += 8;
		if (context->Length_Low == 0)
		{
			context->Length_High++;
			if (context->Length_High == 0)
				context->Corrupted = 1;
		}
		if (context->Message_Block_Index == 64)
			SHA1ProcessMessageBlock(context);
		message_array++;
	}
	return shaSuccess;
}

void SHA1ProcessMessageBlock(SHA1Context *context)
{
	const uint32_t K[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
	int t; // Loop counter
	uint32_t temp; // Temporary word value
	uint32_t W[80]; // Word sequence
	uint32_t A, B, C, D, E; // Word buffers
							// Initialize the first 16 words in the array W
	for (t = 0; t < 16; t++)
	{
		W[t] = context->Message_Block[t * 4] << 24;
		W[t] |= context->Message_Block[t * 4 + 1] << 16;
		W[t] |= context->Message_Block[t * 4 + 2] << 8;
		W[t] |= context->Message_Block[t * 4 + 3];
	}

	for (t = 16; t < 80; t++)
		W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	
	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];

	for (t = 0; t < 20; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;
	context->Message_Block_Index = 0;
}

void SHA1PadMessage(SHA1Context *context)
{

	if (context->Message_Block_Index > 55)
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 64)
			context->Message_Block[context->Message_Block_Index++] = 0;
	
		SHA1ProcessMessageBlock(context);
		while (context->Message_Block_Index < 56)
			context->Message_Block[context->Message_Block_Index++] = 0;
	}
	else
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 56)
			context->Message_Block[context->Message_Block_Index++] = 0;
	}

	context->Message_Block[56] = context->Length_High >> 24;
	context->Message_Block[57] = context->Length_High >> 16;
	context->Message_Block[58] = context->Length_High >> 8;
	context->Message_Block[59] = context->Length_High;
	context->Message_Block[60] = context->Length_Low >> 24;
	context->Message_Block[61] = context->Length_Low >> 16;
	context->Message_Block[62] = context->Length_Low >> 8;
	context->Message_Block[63] = context->Length_Low;
	SHA1ProcessMessageBlock(context);
}

char int_to_hex(uint8_t integ) {
	if (integ < 10)
		return '0' + integ;
	else
		return 'a' + (integ - 10);
}

void SHA1MessageDigestToString(uint8_t Message_Digest[SHA1HashSize], char outbuffer[SHA1HashSize * 2]) {
	for (int i = 0; i < SHA1HashSize; i++) {
		outbuffer[i * 2] = int_to_hex(Message_Digest[i] >> 4);
		outbuffer[i * 2 + 1] = int_to_hex(Message_Digest[i] & 0xF);
	}
}

void idaapi setUnknown(ea_t ea, asize_t size)
{
	// TODO: Does the overrun problem still exist?
	//do_unknown_range(ea, (size_t)size, DOUNK_SIMPLE);
	while (size > 0)
	{
		asize_t isize = get_item_size(ea);
		if (isize > size)
			break;

		del_items(ea);
		ea += (ea_t)isize;
		size -= isize;
	};
}


void MakeName(ea_t ea, const qstring& name, const qstring& prefix, const qstring& postfix)
{
	qstring g_name(prefix);
	g_name += name;
	g_name += postfix;

	g_name.replace(" ", "_");
	g_name.replace("*", "_");
	g_name.replace(",", "_");
	g_name.replace("<", "_lt");
	g_name.replace(">", "_ge");
	set_name(ea, g_name.c_str(), SN_NOWARN);
}

bool MakeArray(ea_t ea, size_t nitems)
{
	asize_t itemsize = 0;
	tid_t tid = BADADDR;
	flags_t flags = get_flags(ea);
	if (is_code(flags) || is_tail(flags) || is_align(flags))
		return false;

	if (is_unknown(flags))
		flags = 0;

	if (is_struct(flags))
	{
		opinfo_t ti;
		if (!get_opinfo(&ti, ea, 0, flags))
			return false;
		itemsize = get_data_elsize(ea, flags, &ti);
		tid = ti.tid;
	}
	else
	{
		itemsize = get_item_size(ea);
	}

	return create_data(ea, flags, static_cast<asize_t>(itemsize * nitems), tid);
}
