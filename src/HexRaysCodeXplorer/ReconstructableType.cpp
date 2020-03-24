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


#include "ReconstructableType.h"
#include "Common.h"
#include "Debug.h"
#include "Utility.h"
#include "reconstructed_place_t.h"

#define BAD_RETYPE_ID -1

SyncTypeInfoMethod syncTypeInfoMethod = SyncTypeInfo_Full;

std::map<std::string, ReconstructableType*> g_ReconstractedTypes;

bool inside_hook = false;
std::set<ReconstructableType*> g_ChangedTypes;
bool in_type_changing = false;

struct reconstructed_types_info_t
{
	TWidget *widget;
	TWidget *cv;
	TWidget *codeview;
	strvec_t sv;
	reconstructed_types_info_t(TWidget *f) : widget(f), cv(nullptr), codeview(nullptr) {}
};

ReconstructableMember::ReconstructableMember()
{

}

ReconstructableMember::ReconstructableMember(const ReconstructableMember & other) :
	name(other.name),
	offset(other.offset),
	memberType(other.memberType->clone())
{

}

ReconstructableMember::~ReconstructableMember()
{

}

ReconstructableType::ReconstructableType(const std::string &Name) : 
	name(Name), typeId(BAD_RETYPE_ID), maxSize((unsigned long)-1), id(0)
{
}

ReconstructableType::~ReconstructableType()
{
}

unsigned ReconstructableType::getSize()
{
	std::map<unsigned int, ReconstructableMember*>::reverse_iterator last;
	/* Any container should copy its members to ownMembers. */
	unsigned long result = 0;
	if (derivedMembers.size()) {
		result = derivedMembers.rbegin()->second->offset + derivedMembers.rbegin()->second->getSize();
	}
	
	if (ownMembers.size()) {
		last = ownMembers.rbegin();
		if (last->second->offset + last->second->getSize() > result)
			return last->second->offset + last->second->getSize();
	}
	return result;
}

ReconstructableMember* ReconstructableType::findMemberByOffset(unsigned long offset, bool isDerived)
{
	std::map<unsigned int, ReconstructableMember*> *members;
	if (isDerived)
		members = &derivedMembers;
	else
		members = &ownMembers;

	if (members->count(offset))
		return (*members)[offset];
	std::map<unsigned int, ReconstructableMember*>::iterator it = members->lower_bound(offset);
	if (it == members->end())
		return 0;

	if (offset >= it->second->offset && offset < it->second->offset + it->second->getSize()) 
		return it->second;

	return 0;
}

bool ReconstructableType::SetMemberName(unsigned long offset, const char * newName)
{
	ReconstructableMember *member = 0;

	bool cur = in_type_changing;

	if (in_type_changing) {
		if (g_ChangedTypes.count(this))
			return false;
	}
	else {
		in_type_changing = true;
		g_ChangedTypes.clear();
	}
	g_ChangedTypes.emplace(this);

	if (member = findMemberByOffset(offset, false))
	{
		member->name = newName;
		for (std::set<ReconstructableType*>::iterator it = childrenTypes.begin(); it != childrenTypes.end(); ++it) {
			
			(*it)->SetMemberNameUpcast(offset, this, newName);
		}
		// if (cur) // do sync only if we do upcast change
			SyncTypeInfo();
		in_type_changing = cur;
		return true;
	}

	in_type_changing = cur;
	return false;
}

bool ReconstructableType::SetMemberNameUpcast(unsigned long offset, ReconstructableType * base, const char * newName)
{
	assert(in_type_changing);
	if (g_ChangedTypes.count(this))
		return false;

	std::map<unsigned int, ReconstructableMember*>::iterator it = derivedMembers.begin();
	while (it != derivedMembers.end()) {
		assert(it->second->memberType->getKind() == MemberType_Reconsrtucted);
		ReconstructedMemberReType * mType = (ReconstructedMemberReType*)it->second->memberType;
		if (mType->reType == base) {
			offset += it->second->offset;
			SetMemberName(offset, newName);
			return true;
		}
		++it;
	}
	// not found?
	return false;
}

/*

tinfo_t tinfo;
if (tinfo.get_named_type(get_idati(), "GCC_RTTI::type_info")) {
apply_tinfo(ea, tinfo, TINFO_DEFINITE);
}

void ReconstructableType::UndefMembers(unsigned long startOffset, unsigned long size, ReconstructableMemberChange modificator)
{
	assert(modificator == ReconstructableMemberChange_None);
	for (unsigned long offset = startOffset; offset < startOffset + size; ++offset)
	{
		ReconstructableMember *tmpMember = findMemberByOffset(offset, false);
		if (tmpMember) {
			ownMembers.erase(offset);
			delete tmpMember;
		}
	}

}
*/

void ReconstructableType::AddSubType(ReconstructableType * subType)
{
	childrenTypes.emplace(subType);
}

bool ReconstructableType::AddDerivedMember(ReconstructableMember* member)
{
	// sanity checks
	if (!member)
		return false;
	if (member->memberType->getKind() != MemberType_Reconsrtucted)
		return false;
	ReconstructedMemberReType *type = (ReconstructedMemberReType*)member->memberType;
	if (!type->reType)
		return false;
	ReconstructableType * parentType = type->reType;

	parentTypes.emplace(parentType);

	derivedMembers[member->offset] = member;
	parentType->CopyMembersToOther(this, member->offset, member->name);
	parentType->AddSubType(this);
}

void ReconstructableType::CopyMembersToOther(ReconstructableType *other, unsigned long offset, std::string &namePrefix)
{
	for (std::map<unsigned int, ReconstructableMember*>::iterator it = ownMembers.begin(); it != ownMembers.end(); ++it)
	{
		ReconstructableMember *newMember = new ReconstructableMember(*(it->second));

		newMember->offset += offset;
		newMember->name = namePrefix + newMember->name;
		other->AddMember(newMember);
		// assert();

	}
}

void ReconstructableType::UndefMembers(unsigned long startOffset, unsigned long size, bool ownMember)
{
	unsigned long offset = startOffset;
	while (offset < size + startOffset) {
		ReconstructableMember* member = findMemberByOffset(offset, false);
		if (!member) {
			offset++;
			continue;
		}
		delete member->memberType;
		ownMembers.erase(offset);
		delete member;

	}
}

bool ReconstructableType::SetMemberType(unsigned long offset, ReconstructedMemberType* newType)
{

	bool cur = in_type_changing;

	if (in_type_changing) {
		if (g_ChangedTypes.count(this))
			return false;
	}
	else {
		in_type_changing = true;
		g_ChangedTypes.clear();
	}
	g_ChangedTypes.emplace(this);

	ReconstructableMember* member = findMemberByOffset(offset, false);
	if (!member) {
		delete newType;
		in_type_changing = cur;
		return false;
	}
	member->memberType = newType;

	for (std::set<ReconstructableType*>::iterator it = childrenTypes.begin(); it != childrenTypes.end(); ++it) {
		newType = newType->clone();
		(*it)->SetMemberTypeUpcast(offset, this, newType);
	}
	// if (cur)
		SyncTypeInfo();
	in_type_changing = cur;
	return true;
}

bool ReconstructableType::SetMemberTypeUpcast(unsigned long offset, ReconstructableType * base, ReconstructedMemberType * newType)
{
	assert(in_type_changing);
	if (g_ChangedTypes.count(this))
		return false;

	std::map<unsigned int, ReconstructableMember*>::iterator it = derivedMembers.begin();
	while (it != derivedMembers.end()) {
		assert(it->second->memberType->getKind() == MemberType_Reconsrtucted);
		ReconstructedMemberReType * mType = (ReconstructedMemberReType*)it->second->memberType;
		if (mType->reType == base) {
			offset += it->second->offset;
			SetMemberType(offset, newType->clone());
			return true;
		}

		++it;
	}
	// not found?
	delete newType;
	return false;
}
/*
bool ReconstructableType::SetMemberType(unsigned long offset, tinfo_t * info)
{
	ReconstructedMemberType *newMemberType = 0;
	ReconstructableMember* member = findMemberByOffset(offset, false);
	if (!member)
		return false;
	qstring type_string;
	if (!info->print(&type_string)) {
		// failed to print.
		return false;
	}
	if (g_ReconstractedTypes.count(type_string.c_str())) 
		newMemberType = new ReconstructedMemberReType(g_ReconstractedTypes[type_string.c_str()]);
	else 
		newMemberType = new MemberTypeIDATypeInfoGate(*info);
	
	return SetMemberType(offset, newMemberType);
}
*/
bool ReconstructableType::AddMember( ReconstructableMember* member) 
{
	ReconstructableMember *upcastMember = 0;
	ReconstructableMember *newMember = 0;

	bool cur = in_type_changing;

	if (in_type_changing) {
		if (g_ChangedTypes.count(this))
			return false;
	}
	else {
		in_type_changing = true;
		g_ChangedTypes.clear();
	}
	g_ChangedTypes.emplace(this);
	
	if (!findMemberByOffset(member->offset, false))
	{
		ownMembers[member->offset] = member;
		for (std::set<ReconstructableType*>::iterator it = childrenTypes.begin(); it != childrenTypes.end(); ++it) {
			newMember = new ReconstructableMember(*member);
			(*it)->AddMemberUpcast(newMember, this);
		}
		//if (cur) // if we go with children
			SyncTypeInfo();
	}
	
	in_type_changing = cur;
	return true;
}

bool ReconstructableType::AddMemberUpcast(ReconstructableMember * member, ReconstructableType * base)
{
	assert(in_type_changing);
	if (g_ChangedTypes.count(this))
		return false;

	std::map<unsigned int, ReconstructableMember*>::iterator it = derivedMembers.begin();
	while (it != derivedMembers.end()) {
		assert(it->second->memberType->getKind() == MemberType_Reconsrtucted);
		ReconstructedMemberReType * mType = (ReconstructedMemberReType*)it->second->memberType;
		if (mType->reType == base) {
			member->offset += it->second->offset;
			AddMember(member);
			return true;
		}


		++it;
	}
	// not found?
	delete member;
	return false;
}

void ReconstructableType::SyncTypeInfo()
{
	struc_t* struc = 0; 
	bool cur = inside_hook;
	inside_hook = true;

	if (this->typeId != BAD_RETYPE_ID) {
		struc = get_struc(this->typeId);
		if (struc) {
			if (name != get_struc_name(this->typeId).c_str()) {
				// we hade id of other struc I guess
				struc = 0;
			}
		}
	}

	if (struc == 0) {
		tid_t id = get_struc_id(name.c_str());
		if (id == BADADDR)
			id = add_struc(BADADDR, name.c_str());
		this->typeId = id;
		struc = get_struc(id);
		if (!struc)
		{
			inside_hook = cur;
			return;
		}
	}

	if (syncTypeInfoMethod == SyncTypeInfo_Names)
		return;

	/* lets do it in a stupid way 
	if (struc->memqty)
	{
		member_t *tmpArray = new member_t[struc->memqty];
		memcpy(tmpArray, struc->members, sizeof(member_t) *struc->memqty);
		for (unsigned int i = 0; i < struc->memqty; ++i)
		{
			if (!del_struc_member(struc, tmpArray[i].soff))
				msg("failde to delete member of %s with index %d\n", name.c_str(), i);
		}
		delete[] tmpArray;
	}
	*/
  	for (std::map<unsigned int, ReconstructableMember*>::iterator it = ownMembers.begin(); it != ownMembers.end(); ++it)
	{

		opinfo_t info;
		ReconstructableMember * member = it->second;
		std::string typeString = member->memberType->getTypeString();
		const char * typeName = typeString.c_str();
		info.tid = get_struc_id(typeName);

		//flags_t flag = it->second->memberType->get_idaapi_flags();
		tinfo_t mt;
		it->second->memberType->get_idaapi_tinfo(&mt);

		struc_error_t error;
		flags_t flags = 0;
		switch (it->second->getSize()) {
		case 1:
			flags = byte_flag();
			break;
		case 2:
			flags = word_flag();
			break;
		case 4:
			flags = dword_flag();
			break;
		case 8:
			flags = qword_flag();
			break;
		default:
			break;
		}

		error = add_struc_member(struc, it->second->name.c_str(), it->second->offset, flags, 0, it->second->getSize());
		if (error != STRUC_ERROR_MEMBER_OK) {
			msg("Failed to add field %s::%s  cause %d\n", this->name.c_str(), it->second->name.c_str(), error);
		}
		member_t * mptr = get_member(struc, it->second->offset);
		if (!mptr) {
			msg("failed to get member  for  %s::%s . this IDA is so dead lol \n", this->name.c_str(), it->second->name.c_str());
			continue;
		}

		smt_code_t smt_code = set_member_tinfo(struc, mptr, it->second->offset, mt, 0	 );
		if (smt_code != SMT_OK) {
			msg("failed to set type for  %s::%s cause %d\n", this->name.c_str(), it->second->name.c_str(), smt_code);
		}
		/*
		 smt_code_t ida_export set_member_tinfo	(	struc_t * 	sptr,
			member_t * 	mptr,
			uval_t 	memoff,
			const tinfo_t & 	tif,
			int 	flags 
			)	
		
		*/
	}
	inside_hook = cur;
}

const std::set<ReconstructableType*> & ReconstructableType::getParents()
{
	return parentTypes;
}

const std::set<ReconstructableType*> & ReconstructableType::getChildren()
{
	return childrenTypes;
}

const std::map<unsigned int, ReconstructableMember*> & ReconstructableType::getDerivedMembers() {
	return derivedMembers;
}

const std::map<unsigned int, ReconstructableMember *> & ReconstructableType::getOwnMembers() {
	return ownMembers;
}

void ReconstructableType::SetMaxSize(unsigned long newSize)
{
	if (getSize() > newSize) {
		assert(false); // need to undef all who hier.
	}
	if (maxSize > newSize)
		maxSize = newSize;
}

ReconstructableType * ReconstructableType::getReconstructableType(const std::string & Name)
{
	ReconstructableType *reType = 0;
	if (g_ReconstractedTypes.count(Name))
		return g_ReconstractedTypes[Name];
	reType = new ReconstructableType(Name);
	g_ReconstractedTypes[Name] = reType;
	return reType;
}

// ------------------------------------------------ window handlers

static bool idaapi reconstructed_keydown(TWidget *cv, int vk_key, int shift, void *ud) {
	int x, y;
	qstring name;
	place_t *place = get_custom_viewer_place(cv, true, &x, &y);
	if (place == 0)
		return false;
	reconstructed_place_t *replace = (reconstructed_place_t *)place;
	ReconstructableType *reType = replace->getReType();
	if (reType == 0)
		return false;
	msg("current position: typename %s, index %d, pos %d, atOwnMembers %d offset %x\n", replace->typeName.c_str(),
		replace->index, replace->position, replace->atOwnMembers, replace->own_offset);
	switch (vk_key) {

	case 'S':
		/* Sync current type */
		reType->SyncTypeInfo();
		break;
	case 'N':
		/* Set name of struct member */
		if (replace->position != REPLACE_MEMBERS)
			break;
		
		if (ask_str(&name, HIST_IDENT, "Set member name")) {
			reType->SetMemberName(replace->own_offset, name.c_str());
		}
		refresh_custom_viewer(cv);
		break;
	

	case 'D':
		/* Add member with type to the end of struct */
		if (replace->position < REPLACE_MEMBERS)
			break;
		if (replace->own_offset == reType->getSize()) {

			if (ask_str(&name, HIST_TYPE, "Set member type")) {
				tinfo_t tinfo;
				std::string sname = name.c_str();
				if (!ends_with(sname, ";")) {
					sname += ";";
				}
				if (!parse_decl(&tinfo, &name, (til_t *)get_idati(), sname.c_str(), PT_TYP)) {
					msg("Failed to parse declaration %s \n", sname.c_str());
					break;
				}
				ReconstructableMember *member = new ReconstructableMember();
				name.sprnt("field_%x", replace->own_offset);
				member->name = name.c_str();
				member->offset = replace->own_offset;
				member->memberType = new MemberTypeIDATypeInfoGate(tinfo);
				reType->AddMember(member);
				reType->SyncTypeInfo();

				place_t *plce = replace->makeplace((void *)replace->own_offset, reType->typeId, reType->typeId);
				return jumpto(cv, plce, 0, 0);
			}
			refresh_custom_viewer(cv); // this one doesn't seems to work?
			break;
		}
		break;

	case 'Y':
		if (replace->position != REPLACE_MEMBERS)
			break;

		if (ask_str(&name, HIST_TYPE, "Set member type")) {
			ReconstructedMemberType * newType;
			std::string sname = name.c_str();
			if (g_ReconstractedTypes.count(sname)) {
				newType  = new ReconstructedMemberReType(g_ReconstractedTypes[sname]);
			}
			else {
				tinfo_t tinfo;
				if (!ends_with(sname, ";")) {
					sname += ";";
				}
				if (!parse_decl(&tinfo, &name, (til_t *)get_idati(), sname.c_str(), PT_TYP)) {
					msg("Failed to parse declaration %s \n", sname.c_str());
					break;
				}
				newType = new MemberTypeIDATypeInfoGate(tinfo);
			}
			 
			reType->SetMemberType(replace->own_offset, newType);
			// force to sync typeinfo since it will not do it.
			// Yes, I know, bad code.
			reType->SyncTypeInfo();
		}
		refresh_custom_viewer(cv);
		break;

	case 'G':
		if (ask_str(&name, /*HIST_IDENT*/ 0, "Where to jump")) {
			std::string sname = name.c_str();
			if (g_ReconstractedTypes.count(sname)) {
				place_t *plce = replace->makeplace(0, g_ReconstractedTypes[sname]->typeId, g_ReconstractedTypes[sname]->typeId);
				return jumpto(cv, plce, 0, 0);
			}
			else {
				int offset = strtol(sname.c_str(), 0, 16);
				if (reType->getSize() >= offset) {
					place_t *plce = replace->makeplace((void *)offset, reType->typeId, reType->typeId);
					return jumpto(cv, plce, 0, 0);
				}
				msg("bad offset : %s\n", sname.c_str());
			}
		}


	}

	return true;
}

/// The user right clicked. See ::ui_populating_widget_popup, too.
static void idaapi reconstructed_popup(TWidget *cv, void *ud) {
	return;
}

static bool idaapi reconstructed_types_lines_linenum(TWidget *cv, const place_t *p, uval_t *num, void *ud) {
	reconstructed_place_t *replace = (reconstructed_place_t *)p;
	if (replace->position == REPLACE_CLASSNAME_TOP) {
		if (g_ReconstractedTypes.count(replace->typeName) == 0)
			return false;

		// for now i dont like how it works.
		ReconstructableType *reType = g_ReconstractedTypes[replace->typeName];
		*num = reType->id;
		return true;
	}

	return false;
}

static bool idaapi reconstructed_types_dblclick(TWidget *v, int shift, void *ud)
{
	int x, y;
	const auto place = get_custom_viewer_place(v, true, &x, &y);
	if (!place)
		return false;
	auto *replace = dynamic_cast<reconstructed_place_t*>(place);
	const auto ea = replace->toea();
	if (ea != BADADDR)
		return jumpto(ea);
	//return true;
	auto re_type = replace->getReType();
	ReconstructableTypeVtable *re_vtable = nullptr;
	if (re_type == nullptr)
		return false;

	auto members = re_type->getOwnMembers();
	auto derived_members = re_type->getDerivedMembers();
	switch (replace->position) {

	case REPLACE_SPLIT:
	case REPLACE_BLANK:
	case REPLACE_CLASSNAME_TOP:
	case REPLACE_BLANK_BOT:
	case REPLACE_CLASSNAME_BOT:
		if (re_vtable = dynamic_cast<ReconstructableTypeVtable*>(re_type)) {
			return re_vtable->vtable_address;
		}
		break;
	case REPLACE_PARENTS:
	case REPLACE_CHILDREN:
		break; // TODO
	case REPLACE_MEMBERS:
		if (replace->atOwnMembers == false) {
			const auto type_name = derived_members[replace->own_offset]->memberType->getTypeString();
			if (g_ReconstractedTypes.count(type_name)) {
				const auto plce = replace->makeplace(nullptr, g_ReconstractedTypes[type_name]->typeId, g_ReconstractedTypes[type_name]->typeId);
				return jumpto(v, plce, 0,0);
			}
		}
	}
	return false;
}

static void idaapi reconstructed_adjust_place(TWidget *v, lochist_entry_t *loc, void *ud) {
	auto *re_place = dynamic_cast<reconstructed_place_t*>(loc->plce);
	int x, y;
	const auto place = get_custom_viewer_place(v, true, &x, &y);
	auto *replace = dynamic_cast<reconstructed_place_t*>(place);
}

ssize_t hook_idb_events(void *user_data, int notification_code, va_list va) {
	ssize_t result = 0;
	ReconstructableType *re_type;
	tid_t tid{};
	const char *oldname;
	const char *newname;
	struc_t *struc;
	ea_t ea;
	adiff_t diff;
	member_t *member;
	flags_t flags;
	const opinfo_t *info;
	asize_t size;
	tinfo_t tinfo;
	qstring q_string;
	ReconstructableMember *reMember;
	ReconstructedMemberType * reMemberType;
	func_t * func;
	std::map<unsigned int, ReconstructableMember *> members;
	if (inside_hook)
		/// just pass it as is
		return 0;

	inside_hook = true;
	switch (notification_code) {
	case idb_event::struc_created:
		tid = va_arg(va, tid_t);
		struc = get_struc(tid);
		if (!struc)
			// should not happend.
		{
			result = BADADDR;
			break;
		}
		oldname = get_struc_name(tid).c_str();
		// probably we not interested on it
		if (g_ReconstractedTypes.count(oldname) == 0)
		{
			result = 0;
			break;
		}
		g_ReconstractedTypes[oldname]->typeId = tid;
		break;
	case idb_event::deleting_struc:
		struc = va_arg(va, struc_t*);
		oldname = get_struc_name(struc->id).c_str();
		if (g_ReconstractedTypes.count(oldname) == 0)
		{
			result = 0;
			break;
		}
		g_ReconstractedTypes[oldname]->typeId = BADADDR;
		break;
	case idb_event::renaming_struc:
		tid = va_arg(va, tid_t);
		oldname = va_arg(va, const char *);
		newname = va_arg(va, const char *);
		if (g_ReconstractedTypes.count(oldname) == 0)
		{
			result = 0;
			break;
		}
		// deny renaming.
		result = BADADDR;
		break;
	case idb_event::expanding_struc:
		struc = va_arg(va, struc_t*);
		ea = va_arg(va, ea_t);
		diff = va_arg(va, adiff_t);
		oldname = get_struc_name(tid).c_str();
		if (g_ReconstractedTypes.count(oldname) == 0)
			break;
		
		re_type = g_ReconstractedTypes[oldname];
		if (re_type->maxSize < ea + diff)
			// it will corrupt what we have
		{
			result = BADADDR;
			break;
		}
		
		break;
	case idb_event::struc_member_created:
		struc = va_arg(va, struc_t*);
		member = va_arg(va, member_t*);
		q_string = get_struc_name(struc->id);
		oldname = q_string.c_str();
		if (g_ReconstractedTypes.count(oldname) == 0)
			break;
		re_type = g_ReconstractedTypes[oldname];
	
		if (re_type->maxSize < member->eoff)
			// it will corrupt what we have
		{
			result = BADADDR;
			break;
		}
		if (!get_member_tinfo(&tinfo, member))
		{
			if (!get_or_guess_member_tinfo(&tinfo, member)) {
				opinfo_t opinfo{};
				if (retrieve_member_info(&opinfo, member)) {
					result = BADADDR;
					break;
				}
				result = BADADDR;
				break;
			}
		}
		reMember = new ReconstructableMember();
		//get_member_name(member->id)
		get_member_name(&q_string, member->id);
		reMember->name = q_string.c_str();
		reMember->offset = member->soff;

		if (tinfo.get_type_name(&q_string)) {

			if (tinfo.is_ptr()) {
				if (g_ReconstractedTypes.count(q_string.c_str()) != 0)
				{
					reMemberType = new MemberTypePointer(g_ReconstractedTypes[q_string.c_str()]->name);

				}
				else {
					reMemberType = new MemberTypeIDATypeInfoGate(tinfo);
				}

				reMember->memberType = reMemberType;
				re_type->AddMember(reMember);
				break;
			}
			if (g_ReconstractedTypes.count(q_string.c_str()) != 0) {
				reMemberType = new ReconstructedMemberReType(g_ReconstractedTypes[q_string.c_str()]);
				reMember->memberType = reMemberType;
				re_type->AddMember(reMember);
				break;
			}

		}
		reMemberType = new MemberTypeIDATypeInfoGate(tinfo);
		reMember->memberType = reMemberType;
		re_type->AddMember(reMember);

		break;

	case idb_event::deleting_struc_member:
		struc = va_arg(va, struc_t*);
		member = va_arg(va, member_t*);
		q_string = get_struc_name(struc->id);
		oldname = q_string.c_str();
		if (g_ReconstractedTypes.count(oldname) == 0)
			break;
		re_type = g_ReconstractedTypes[oldname];
		re_type->UndefMembers(member->soff, member->eoff - member->soff, true);
		break;

	case idb_event::renaming_struc_member:
		struc = va_arg(va, struc_t*);
		member = va_arg(va, member_t*);
		newname = va_arg(va, const char *);
		q_string = get_struc_name(struc->id);
		oldname = q_string.c_str();
		if (g_ReconstractedTypes.count(oldname) == 0)
			break;
		re_type = g_ReconstractedTypes[oldname];
		re_type->SetMemberName(member->soff, newname);
		break;

	case idb_event::changing_struc_member:
		///< \param sptr    (::struc_t *)
		///< \param mptr    (::member_t *)
		///< \param flag    (::flags_t)
		///< \param ti      (const ::opinfo_t *)
		///< \param nbytes  (::asize_t)
		struc = va_arg(va, struc_t*);
		member = va_arg(va, member_t*);
		flags = va_arg(va, flags_t);
		info = va_arg(va, const opinfo_t *);
		size = va_arg(va, asize_t);
		//msg("Setting member %s.%s to type %s\n", reType->name.c_str(), reMember->name.c_str(), q_string.c_str());
		
		break;
	case idb_event::struc_member_changed:
		struc = va_arg(va, struc_t*);
		member = va_arg(va, member_t*);
		q_string = get_struc_name(struc->id);
		oldname = q_string.c_str();
		if (g_ReconstractedTypes.count(oldname) == 0)
			break;
		re_type = g_ReconstractedTypes[oldname];

		if (!get_member_tinfo(&tinfo, member))
		{
			if (!get_or_guess_member_tinfo(&tinfo, member))
			{
				opinfo_t opinfo;
				if (retrieve_member_info(&opinfo, member)) {
					// placeholder
					result = BADADDR;
					break;
				}
				result = BADADDR;
				break;
			}
		}
	
		members = re_type->getOwnMembers();
		if (members.count(member->soff) == 0)
			assert(false);
		reMember = members[member->soff];
		size = tinfo.get_size();
		if (reMember->getSize() < size) {
			re_type->UndefMembers(reMember->getSize() + reMember->offset, size - reMember->getSize(), true);
		}

		if (!tinfo.print(&q_string)) {
			// failed to print.
			return false;
		}
		msg("Setting member %s.%s to type %s\n", re_type->name.c_str(), reMember->name.c_str(), q_string.c_str());
		//break; // debug
		if (g_ReconstractedTypes.count(q_string.c_str()))
			reMemberType = new ReconstructedMemberReType(g_ReconstractedTypes[q_string.c_str()]);
		else
			reMemberType = new MemberTypeIDATypeInfoGate(tinfo);
		re_type->SetMemberType(member->soff, reMemberType);
		break;
	case idb_event::func_updated:
		func = va_arg(va, func_t *);
		break;
	default:
		break;
	}
	inside_hook = false;
	return result;
}

void re_types_form_init()
{
	hook_to_notification_point(
		HT_IDB,
		hook_idb_events,
		NULL);
	/*if (vtbl_list.empty() || vtbl_t_list.empty())
	{
		warning("ObjectExplorer not found any virtual tables here ...\n");
		logmsg(DEBUG, "ObjectExplorer not found any virtual tables here ...\n");
		return;
	}
	*/
	auto widget = find_widget("Reconstructed Types");
	if (widget)
	{
		warning("Reconstructed Types window already open. Switching to it.\n");
		logmsg(DEBUG, "Reconstructed Types window already open. Switching to it.\n");
		activate_widget(widget, true);
		return;
	}

	widget = create_empty_widget("Reconstructed Types");
	static auto actions_initialized = false;
	if (!actions_initialized)
	{
		actions_initialized = true;
		//register_action(kMakeVTBLStrucActionDesc);
		//register_action(kShowVTBLXrefsWindowActionDesc);
	}

	auto*si = new reconstructed_types_info_t(widget);
	if (!g_ReconstractedTypes.empty()) {
		auto type_name = g_ReconstractedTypes.begin()->first; // bug if no any types found 
		reconstructed_place_t start(type_name);
		type_name = g_ReconstractedTypes.rbegin()->first;
		reconstructed_place_t end(type_name);
		end.lnnum = g_ReconstractedTypes.rbegin()->second->id;
		end.index = g_ReconstractedTypes.rbegin()->second->id;
		// simpleline_place_t s2(static_cast<int>(si->sv.size()) - 1);
		si->cv = create_custom_viewer("", static_cast<place_t*>(&start), static_cast<place_t*>(&end), &start, nullptr, nullptr, nullptr, nullptr, widget);
	}
	else {
		reconstructed_place_t start;
		si->cv = create_custom_viewer("", static_cast<place_t*>(&start), static_cast<place_t*>(&start), &start, nullptr, nullptr, nullptr, nullptr, widget);
	}

	si->codeview = create_code_viewer(si->cv, CDVF_STATUSBAR, widget);
	// ct_object_explorer_keyboard;
	auto cvh = custom_viewer_handlers_t();
	cvh.keyboard = reconstructed_keydown;
	cvh.popup = reconstructed_popup;
	cvh.adjust_place = reconstructed_adjust_place;
	//cvh.get_place_xcoord = reconstructed_get_place_xcoord;

	cvh.dblclick = reconstructed_types_dblclick;
	set_custom_viewer_handlers(si->cv, &cvh, si);
	set_code_viewer_line_handlers(si->codeview, nullptr, nullptr, nullptr, nullptr, reconstructed_types_lines_linenum);
	//hook_to_notification_point(HT_UI, ui_object_explorer_callback, si);
	display_widget(widget, WOPN_DP_TAB | WOPN_RESTORE);
}

void re_types_form_fini() {
	unhook_from_notification_point(HT_IDB,
		hook_idb_events,
		nullptr);
	const auto widget = find_widget("Reconstructed Types");
	// * no widget, no need to handle a thing
	if (!widget)
		return;
}

ReconstructedMemberType::ReconstructedMemberType(MemberTypeKind k) : kind(k) 
{
}

ReconstructedMemberType::ReconstructedMemberType(const ReconstructedMemberType &other) : kind(other.kind)
{
}

ReconstructedMemberType::~ReconstructedMemberType()
{
}

MemberTypeKind ReconstructedMemberType::getKind() 
{ 
	return kind; 
}


ReconstructedMemberReType::ReconstructedMemberReType(ReconstructableType * type) :
	ReconstructedMemberType(MemberType_Reconsrtucted), reType(type)
{
}

ReconstructedMemberReType::ReconstructedMemberReType(const ReconstructedMemberReType &other) :
	ReconstructedMemberType(other), reType(other.reType)
{
}

ReconstructedMemberReType::~ReconstructedMemberReType()
= default;


unsigned long ReconstructedMemberReType::getSize()
{
	return reType->getSize();
}

std::string ReconstructedMemberReType::getTypeString()
{
	return  reType->name;
}

void ReconstructedMemberReType::get_idaapi_tinfo(tinfo_t * out)
{
	tinfo_t result;
	result.get_named_type(get_idati(), reType->name.c_str());
	*out = result;
}

ReconstructedMemberType * ReconstructedMemberReType::clone()
{
	const auto result = new ReconstructedMemberReType(*this);
	return result;
}

MemberTypeIDATypeInfoGate::MemberTypeIDATypeInfoGate(tinfo_t t) : ReconstructedMemberType(MemberType_IDAGate), info(t)
{
}

MemberTypeIDATypeInfoGate::MemberTypeIDATypeInfoGate(const MemberTypeIDATypeInfoGate &other) : ReconstructedMemberType(other), info(other.info)
{
}

MemberTypeIDATypeInfoGate::~MemberTypeIDATypeInfoGate()
= default;


unsigned long MemberTypeIDATypeInfoGate::getSize()
{
	return info.get_size();
}

std::string MemberTypeIDATypeInfoGate::getTypeString()
{
	qstring out;
	info.print(&out);
	const auto name = out.c_str();
	return name;
}

void MemberTypeIDATypeInfoGate::get_idaapi_tinfo(tinfo_t * out)
{
	*out = info;
}

ReconstructedMemberType * MemberTypeIDATypeInfoGate::clone()
{
	return new MemberTypeIDATypeInfoGate(*this);
}

MemberTypePointer::MemberTypePointer(std::string t) :
	ReconstructedMemberType(MemberType_Pointer), pointedType(std::move(t))
{
}

MemberTypePointer::MemberTypePointer(const MemberTypePointer &other) :
	ReconstructedMemberType(other), pointedType(other.pointedType)
{
}

MemberTypePointer::~MemberTypePointer()
= default;

unsigned long MemberTypePointer::getSize()
{
	return sizeof(uval_t);
}

std::string MemberTypePointer::getTypeString()
{
	return pointedType + "*";
}

void MemberTypePointer::get_idaapi_tinfo(tinfo_t * out)
{
	tinfo_t info;
	info.get_named_type(0, pointedType.c_str());
	*out = make_pointer(info);
}

ReconstructedMemberType * MemberTypePointer::clone()
{
	return new MemberTypePointer(*this);
}

MemberTypeIDAFlagsTGate::MemberTypeIDAFlagsTGate(flags_t f, opinfo_t i) :
	ReconstructedMemberType(MemberType_IDAGate), flags(f), info(i)
{
}

MemberTypeIDAFlagsTGate::MemberTypeIDAFlagsTGate(const MemberTypeIDAFlagsTGate &other) :
	ReconstructedMemberType(other), flags(other.flags), info(other.info)
{

}

MemberTypeIDAFlagsTGate::~MemberTypeIDAFlagsTGate()
= default;


unsigned long MemberTypeIDAFlagsTGate::getSize()
{
	assert(false);
	return 0;
}

std::string MemberTypeIDAFlagsTGate::getTypeString()
{
	assert(false);
	return std::string();
}

void MemberTypeIDAFlagsTGate::get_idaapi_tinfo(tinfo_t * out)
{
	assert(false);
}

ReconstructedMemberType * MemberTypeIDAFlagsTGate::clone()
{
	return new MemberTypeIDAFlagsTGate(*this);
}

ReconstructableTypeVtable::~ReconstructableTypeVtable()
= default;

bool ReconstructableTypeVtable::SetMemberName(unsigned long offset, const char * newName)
{
	const auto func_addr = getEa(vtable_address + sizeof(ea_t) * 2 + sizeof(ea_t) * offset);
	auto funcname = newName;
	const auto class_name = name.substr(0, name.length() - sizeof(VTBL_CLSNAME_POSTFIX));
	// name.substr(0, name.length() - sizeof(VTBL_CLSNAME_POSTFIX))
	const auto member = findMemberByOffset(offset, false);
	if (!member)
		return false;
	char *ptr;
	if ((ptr = std::strstr(const_cast<char*>(newName), class_name.c_str()))) {
		ptr += class_name.size();
		if (ptr[0] == ':' && ptr[1] == ':')
		{
			ptr += 2;
		}
		funcname = ptr;
	}
	const auto func = get_func(func_addr);
	if (func) {
		auto long_name = class_name;
		long_name += "::";
		long_name += funcname;
		set_name(func_addr, long_name.c_str(), SN_NON_AUTO | SN_NOWARN | SN_FORCE);
	}
	return ReconstructableType::SetMemberName(offset, newName);
}

bool ReconstructableTypeVtable::SetMemberType(const unsigned long offset, ReconstructedMemberType * new_type)
{
	return ReconstructableType::SetMemberType(offset, new_type);
}

bool ReconstructableTypeVtable::AddMember(ReconstructableMember * member)
{
	//msg("Error: Called ReconstructableTypeVtable::AddMember for %s what usually shouldnt happend\n", name.c_str());
	//return false;
	return ReconstructableType::AddMember(member);
}

ea_t ReconstructableTypeVtable::to_ea(const unsigned long offset) const
{
	const auto res = getEa(vtable_address + sizeof(ea_t) * 2 + offset);

	return res;
}

ReconstructableTypeVtable * ReconstructableTypeVtable::get_reconstructable_type_vtable(const std::string & Name, ea_t addr)
{
	ReconstructableTypeVtable *re_type = nullptr;
	if (g_ReconstractedTypes.count(Name))
		return dynamic_cast<ReconstructableTypeVtable *>(g_ReconstractedTypes[Name]);
	re_type = new ReconstructableTypeVtable(Name, addr);
	g_ReconstractedTypes[Name] = re_type;
	return re_type;
}
