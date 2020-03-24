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


#ifndef __H_RECONSTRUCTABLETYPE__
#define __H_RECONSTRUCTABLETYPE__

#pragma once
#include "Common.h"

extern int g_replace_id;

enum MemberTypeKind {
	MemberType_Unknown = 0,
	MemberType_Reconsrtucted,
	MemberType_Pointer,
	MemberType_IDAGate
};

enum SyncTypeInfoMethod {
	SyncTypeInfo_Names = 0,
	SyncTypeInfo_Full
};
extern DLLEXPORT SyncTypeInfoMethod syncTypeInfoMethod;

class ReconstructableType;
class ReconstructableMember;
class ReconstructedMemberType;

class DLLEXPORT ReconstructedMemberType {
	MemberTypeKind kind;
public:
	ReconstructedMemberType(MemberTypeKind k);
	ReconstructedMemberType(const ReconstructedMemberType &other);
	MemberTypeKind getKind();

	virtual ~ReconstructedMemberType();
	
	virtual unsigned long getSize() = 0;
	virtual std::string getTypeString() = 0;

	//virtual flags_t get_idaapi_flags() = 0;
	virtual void get_idaapi_tinfo(tinfo_t * out) = 0;

	virtual ReconstructedMemberType * clone() = 0;
};

class DLLEXPORT ReconstructedMemberReType : public ReconstructedMemberType {
public:
	ReconstructableType * reType;

	ReconstructedMemberReType(ReconstructableType *type);
	ReconstructedMemberReType(const ReconstructedMemberReType &other);
	
	virtual ~ReconstructedMemberReType();
	virtual unsigned long getSize();
	virtual std::string getTypeString();
	//virtual flags_t get_idaapi_flags();
	virtual void get_idaapi_tinfo(tinfo_t * out);
	virtual ReconstructedMemberType * clone();
};


class DLLEXPORT MemberTypeIDAFlagsTGate : public ReconstructedMemberType {

	flags_t flags;
	opinfo_t info;

	MemberTypeIDAFlagsTGate(flags_t f, opinfo_t i);
	MemberTypeIDAFlagsTGate(const MemberTypeIDAFlagsTGate &other);
	virtual ~MemberTypeIDAFlagsTGate();

	virtual unsigned long getSize();
	virtual std::string getTypeString();
	//virtual flags_t get_idaapi_flags();
	virtual void get_idaapi_tinfo(tinfo_t * out);
	virtual ReconstructedMemberType * clone();

};

class DLLEXPORT MemberTypeIDATypeInfoGate : public ReconstructedMemberType {

public:
	tinfo_t info;
	MemberTypeIDATypeInfoGate(tinfo_t t);
	MemberTypeIDATypeInfoGate(const MemberTypeIDATypeInfoGate &other);
	virtual ~MemberTypeIDATypeInfoGate();

	virtual unsigned long getSize();
	virtual std::string getTypeString();
	//virtual flags_t get_idaapi_flags();
	virtual void get_idaapi_tinfo(tinfo_t * out);
	virtual ReconstructedMemberType * clone();
};

class DLLEXPORT MemberTypePointer : public ReconstructedMemberType {
public :
	std::string pointedType;
	MemberTypePointer(std::string t);
	MemberTypePointer(const MemberTypePointer &other);
	virtual ~MemberTypePointer();
	virtual unsigned long getSize();
	virtual std::string getTypeString();
	//virtual flags_t get_idaapi_flags();
	virtual void get_idaapi_tinfo(tinfo_t * out);
	virtual ReconstructedMemberType * clone();
};

class DLLEXPORT ReconstructableMember
{
public:
	unsigned long offset;
	std::string name;
	ReconstructedMemberType *memberType;
	unsigned long getSize() { return memberType->getSize(); }
	ReconstructableMember();
	ReconstructableMember(const ReconstructableMember &other);
	~ReconstructableMember();
};

class DLLEXPORT	ReconstructableType
{

	/* members as it is - free from any container */
	std::map<unsigned int, ReconstructableMember *> ownMembers;
	/* members which were grouped to some type */
	std::map<unsigned int, ReconstructableMember*> derivedMembers;
	/* inherited types */
	std::set<ReconstructableType *> childrenTypes;
	std::set<ReconstructableType *> parentTypes;
protected:

	ReconstructableType(const std::string &Name);

public:
	unsigned long id;
	std::string name;
	unsigned int typeId;
	unsigned long maxSize;

	virtual ~ReconstructableType();

	
	virtual bool SetMemberName(unsigned long offset, const char * newName);
	virtual bool SetMemberNameUpcast(unsigned long offset, ReconstructableType *base, const char * newName);

	
	virtual bool SetMemberType(unsigned long offset, ReconstructedMemberType* newType);
	virtual bool SetMemberTypeUpcast(unsigned long offset, ReconstructableType *base, ReconstructedMemberType* newType);
	
	virtual bool AddMember(ReconstructableMember* member);
	virtual bool AddMemberUpcast(ReconstructableMember* member, ReconstructableType *base);
	virtual bool AddDerivedMember(ReconstructableMember* member);

	unsigned getSize();
	ReconstructableMember* findMemberByOffset(unsigned long offset, bool isDerived);


	void CopyMembersToOther(ReconstructableType *other, unsigned long offset, std::string &namePrefix);
	void UndefMembers(unsigned long startOffset, unsigned long size, bool ownMember);
	void AddSubType(ReconstructableType *subType);

	virtual void SyncTypeInfo();

	const std::set<ReconstructableType *> & getParents();
	const std::set<ReconstructableType *> & getChildren();

	const std::map<unsigned int, ReconstructableMember*> & getDerivedMembers();
	const std::map<unsigned int, ReconstructableMember *> & getOwnMembers();

	void SetMaxSize(unsigned long newSize);

	static ReconstructableType * getReconstructableType(const std::string &Name);

};

class DLLEXPORT ReconstructableTypeVtable : public ReconstructableType {

protected:
	ReconstructableTypeVtable(std::string Name, ea_t addr) : ReconstructableType(Name), vtable_address(addr) {};

public:
	ea_t vtable_address;
	
	virtual ~ReconstructableTypeVtable();

	virtual bool SetMemberName(unsigned long offset, const char * newName);
	virtual bool SetMemberType(unsigned long offset, ReconstructedMemberType* new_type);
	virtual bool AddMember(ReconstructableMember* member);
	ea_t to_ea(unsigned long offset) const;

	static ReconstructableTypeVtable * get_reconstructable_type_vtable(const std::string &Name, ea_t addr);
};

DLLEXPORT void re_types_form_init();
DLLEXPORT void re_types_form_fini();

extern DLLEXPORT std::map<std::string, ReconstructableType*> g_ReconstractedTypes;
extern DLLEXPORT ea_t class_type_info_vtbl;
extern DLLEXPORT ea_t si_class_type_info_vtbl;
extern DLLEXPORT ea_t vmi_class_type_info_vtbl;

#endif
