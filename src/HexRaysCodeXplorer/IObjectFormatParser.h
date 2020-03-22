/*	Copyright (c) 2013-2020
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
class IObjectFormatParser
{
public:
	virtual ~IObjectFormatParser();

	virtual void get_rtti_info() = 0;
	virtual void clear_info() = 0;
};

extern IObjectFormatParser *object_format_parser;

extern bool init_object_format_parser();
