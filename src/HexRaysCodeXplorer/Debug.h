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

void logmsg(unsigned int level, const char *fmt, ...);

#ifndef __H_DEBUG__
#define __H_DEBUG__
#ifdef ERROR
#undef ERROR
#endif

enum DEBUG_LEVELS {
	OUTPUT, // output printed to output file
	ERROR, // error printed to error file
	INFO, // print to IDA
	INTERACTIVE, // show on IDA interface
	DEBUG // print to IDA
};

#define CURRENT_DEBUG_LEVEL ERROR

#endif