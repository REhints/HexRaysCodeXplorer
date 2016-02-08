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
 	along with this program.  If not, see
 	<http://www.gnu.org/licenses/>.

	==============================================================================
*/

#include "Common.h"
#include "Debug.h"

#define OUTPUT_FILE "codexplorer_output.txt"
#define ERROR_FILE "codexplorer_error.txt"

#if defined (__LINUX__) || defined (__MAC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static void print_to_output_file(const char *output_msg) {
	int file_id = qopen(OUTPUT_FILE, O_WRONLY | O_APPEND);
	if (file_id == BADADDR)
		file_id = qcreate(OUTPUT_FILE, 511);
	
	if (file_id == -1) {
		msg("FATAL: print_to_output_file failed!\n");
		return;
	}
	
	qwrite(file_id, output_msg, strlen(output_msg));
	
	qclose(file_id);
}

static void print_to_error_file(const char *error_msg) {
	int file_id = qopen(ERROR_FILE, O_WRONLY | O_APPEND);
	if (file_id == BADADDR)
		file_id = qcreate(ERROR_FILE, 511);
	
	if (file_id == -1) {
		msg("FATAL: print_to_error_file failed!\n");
		return;
	}
	
	qwrite(file_id, error_msg, strlen(error_msg));
	
	qclose(file_id);
}

void logmsg(unsigned int level, const char *fmt, ...)
{
    va_list arglist;
	
	if (level > CURRENT_DEBUG_LEVEL)
		return;
	
	va_start(arglist, fmt);
	
	switch (level) {
		case OUTPUT:
			print_to_output_file(fmt);
			break;
		case ERROR:
			print_to_error_file(fmt);
			break;
		default:
			msg(fmt, arglist);
			break;
	}
	
    va_end(arglist);
}