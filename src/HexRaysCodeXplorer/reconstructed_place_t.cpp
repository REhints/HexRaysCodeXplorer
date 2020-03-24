#include "reconstructed_place_t.h"
#include "ReconstructableType.h"
#include "GCCVtableInfo.h"
#include "Utility.h"

extern std::unordered_map<std::string, GCCVtableInfo *>g_KnownVtableNames;

reconstructed_place_t g_replace;


reconstructed_place_t::reconstructed_place_t() : place_t(0), typeName(), index(0), position(REPLACE_SPLIT) {
}

reconstructed_place_t::reconstructed_place_t(std::string n) :  typeName(n), index(0), position(REPLACE_SPLIT),
own_offset(0), atOwnMembers(false)
{
	if (g_ReconstractedTypes.count(n))
		lnnum = g_ReconstractedTypes[n]->id;

	else
		lnnum = 0;
}


reconstructed_place_t::reconstructed_place_t(const reconstructed_place_t &other) : place_t(other.lnnum), typeName(other.typeName), index(other.index),
position(other.position), own_offset(other.own_offset), atOwnMembers(other.atOwnMembers) {
	if (g_ReconstractedTypes.count(typeName))
		lnnum = g_ReconstractedTypes[typeName]->id;

}



void idaapi reconstructed_place_t::print(qstring * out_buf, void * ud) const
{
	if (g_ReconstractedTypes.count(typeName) == 0)
		return;

	ReconstructableType *reType = g_ReconstractedTypes[typeName];
	//assert(!reType);
	out_buf->sprnt("lnnum %d index 0x%x type %s", lnnum, index, typeName.c_str());
}

uval_t idaapi reconstructed_place_t::touval(void * ud) const
{
	return index;
}

place_t *idaapi reconstructed_place_t::clone(void) const
{
	reconstructed_place_t *ptr = new reconstructed_place_t(*this);
	return ptr;
}

void idaapi reconstructed_place_t::copyfrom(const place_t * from)
{
	reconstructed_place_t* other = (reconstructed_place_t*)from;
	typeName = other->typeName;
	lnnum = other->lnnum;
	if (g_ReconstractedTypes.count(typeName))
		lnnum = g_ReconstractedTypes[typeName]->id;
	index = other->index;
	position = other->position;
	own_offset = other->own_offset;
	atOwnMembers = other->atOwnMembers;
}

place_t *idaapi reconstructed_place_t::makeplace(void * ud, uval_t x, int lnnum) const
{
	int offset = (long)ud;
	std::map<std::string, ReconstructableType*>::iterator it = g_ReconstractedTypes.begin();
	while (it != g_ReconstractedTypes.end()) {
		if (it->second->typeId == x)
			break;
		it++;
	}


	if (it == g_ReconstractedTypes.end()) {
		g_replace.index = 0;
		g_replace.typeName = g_ReconstractedTypes.rbegin()->first;
		g_replace.lnnum = 0;
		g_replace.own_offset = 0;
		g_replace.position = REPLACE_SPLIT;
		g_replace.atOwnMembers = false;

	}
	else {
		g_replace.index = x;
		g_replace.typeName = it->second->name;
		g_replace.own_offset = offset;
		g_replace.lnnum = lnnum;
		g_replace.position = REPLACE_SPLIT;
		g_replace.atOwnMembers = false;
		if (offset) {
			g_replace.position = REPLACE_MEMBERS;
			g_replace.atOwnMembers = true;
		}
		
	}
	return &g_replace;
}

int idaapi reconstructed_place_t::compare(const place_t * t2) const
{
	reconstructed_place_t * other = ((reconstructed_place_t*)t2);
	if (lnnum != other->lnnum)
		return lnnum - other->lnnum;
	if (position != other->position)
		return (int)position - (int)other->position;
	if (own_offset != other->own_offset)
		return own_offset - other->own_offset;
	return atOwnMembers - other->atOwnMembers;
}

void idaapi reconstructed_place_t::adjust(void * ud)
{
	if (g_ReconstractedTypes.count(typeName) == 0) {
		if (g_ReconstractedTypes.size())
			typeName = g_ReconstractedTypes.begin()->first;
		else
			typeName = "";
		lnnum = 0;
	}
	else
		lnnum = g_ReconstractedTypes[typeName]->id;
}

reconstructed_place_pos_t& operator--(reconstructed_place_pos_t&pos) {
	switch (pos) {
	case REPLACE_BLANK: return pos = REPLACE_SPLIT;
	case REPLACE_CLASSNAME_TOP: return pos = REPLACE_BLANK;
	case REPLACE_PARENTS: return pos = REPLACE_CLASSNAME_TOP;
	case REPLACE_CHILDREN: return pos = REPLACE_PARENTS;
	case REPLACE_MEMBERS: return pos = REPLACE_CHILDREN;
	case REPLACE_BLANK_BOT: return pos = REPLACE_MEMBERS;
	case REPLACE_CLASSNAME_BOT: return pos = REPLACE_BLANK_BOT;
	default:
		assert(false);
	}

}

reconstructed_place_pos_t& operator++(reconstructed_place_pos_t&pos) {
	switch (pos) {
	case REPLACE_SPLIT: return pos = REPLACE_BLANK;
	case REPLACE_BLANK: return pos = REPLACE_CLASSNAME_TOP;
	case REPLACE_CLASSNAME_TOP: return pos = REPLACE_PARENTS;
	case REPLACE_PARENTS: return pos = REPLACE_CHILDREN;
	case REPLACE_CHILDREN: return pos = REPLACE_MEMBERS;
	case REPLACE_MEMBERS: return pos = REPLACE_BLANK_BOT;
	case REPLACE_BLANK_BOT: return pos = REPLACE_CLASSNAME_BOT;
	default:
		assert(false);
	}
}



bool idaapi reconstructed_place_t::prev(void * ud)
{
	ReconstructableType* t;
	std::map<std::string, ReconstructableType*>::iterator it = g_ReconstractedTypes.find(typeName);
	if (it == g_ReconstractedTypes.end()) {
		index = 0;
		lnnum = 0;
		position = REPLACE_SPLIT;
		typeName = g_ReconstractedTypes.begin()->second->name;
		atOwnMembers = false;
		return false;
	}

	t = it->second;
	std::map<unsigned int, ReconstructableMember *> members = t->getOwnMembers();
	std::map<unsigned int, ReconstructableMember *>::iterator members_it;
	std::map<unsigned int, ReconstructableMember *>::reverse_iterator members_rit;
	std::map<unsigned int, ReconstructableMember *> derivedMembers = t->getDerivedMembers();
	std::map<unsigned int, ReconstructableMember *>::iterator derived_it;
	std::map<unsigned int, ReconstructableMember *>::reverse_iterator derived_rit;
	std::set<ReconstructableType*> parents = t->getParents();
	std::set<ReconstructableType*> children = t->getChildren();
	unsigned int new_offset;

	while (1) {

		switch (position) {
		case REPLACE_SPLIT:
			if (it == g_ReconstractedTypes.begin())
				return false;

			t = (--it)->second;
			position = REPLACE_CLASSNAME_BOT;
			own_offset = t->getSize();
			typeName = t->name;
			index = t->typeId;
			lnnum = t->id;
			return true;

		case REPLACE_CLASSNAME_BOT:
		case REPLACE_PARENTS:
		case REPLACE_CLASSNAME_TOP:
		case REPLACE_BLANK:
			--position;
			return true;

		case REPLACE_CHILDREN:
			--position;
			if (parents.size())
				return true;
			break;

		case REPLACE_BLANK_BOT:
			--position;
			if (members.size() || derivedMembers.size())
			{
				own_offset = 0;
				members_rit = members.rbegin();
				derived_rit = derivedMembers.rbegin();

				if (derived_rit != derivedMembers.rend())
				{
					own_offset = derived_rit->first;
					atOwnMembers = false;
				}

				if (members_rit != members.rend() && members_rit->first >= own_offset) {
					atOwnMembers = true;
					own_offset = members_rit->first;
				}
				return true;
			}
			// no members at all, go back to children				
			--position;
			break;

		case REPLACE_MEMBERS:
		{
			if (atOwnMembers && derivedMembers.count(own_offset)) {
				atOwnMembers = false;
				return true;
			}
			atOwnMembers = false;
			if (own_offset == 0) {
				--position;
				if (children.size())
					return true;
				break;
			}
			new_offset = 0;
			if (derivedMembers.size())
			{
				derived_it = derivedMembers.lower_bound(own_offset);
				if (derived_it == derivedMembers.end())
					new_offset = derivedMembers.rbegin()->first;
				else
				{
					--derived_it;
					if (derived_it != derivedMembers.end())
						new_offset = derived_it->first;
					else
						new_offset = 0;
				}
			}
			if (members.size())
			{
				members_it = members.lower_bound(own_offset);
				if (members_it == members.end()) {
					if (members.rbegin()->first >= new_offset) {
						new_offset = members.rbegin()->first;
						atOwnMembers = true;
					}
				}
				else
				{
					--members_it;
					if (members_it != members.end()) {
						if (new_offset <= members_it->first) {
							new_offset = members_it->first;
							atOwnMembers = true;
						}
					}
					else
					{
						if (new_offset == 0) {
							if (members.begin()->first == 0) {
								new_offset = members_it->first;
								atOwnMembers = true;
							}
						}
					}

				}
			}
			own_offset = new_offset;
			if (atOwnMembers || derivedMembers.count(own_offset))
				return true;
			//assert(false);
			return true;
		}
		default:
			assert(false);
		}

	}
}

bool idaapi reconstructed_place_t::next(void * ud)
{
	ReconstructableType* t;
	std::map<std::string, ReconstructableType*>::iterator it = g_ReconstractedTypes.find(typeName);
	if (it == g_ReconstractedTypes.end())
		return false;
	t = it->second;
	size_t size = t->getSize();
	std::map<unsigned int, ReconstructableMember *> members = t->getOwnMembers();
	std::map<unsigned int, ReconstructableMember *>::iterator members_it;
	std::map<unsigned int, ReconstructableMember *> derivedMembers = t->getDerivedMembers();
	std::map<unsigned int, ReconstructableMember *>::iterator derived_it;
	std::set<ReconstructableType*> parents = t->getParents();
	std::set<ReconstructableType*> children = t->getChildren();


	while (1) {

		switch (position) {
		case REPLACE_SPLIT:
		case REPLACE_BLANK:
		case REPLACE_BLANK_BOT:
			++position;
			return true;
		case REPLACE_CLASSNAME_TOP:
			++position;
			if (parents.size())
				return true;
			break;
		case REPLACE_PARENTS:
			++position;
			if (children.size())
				return true;
			break;
		case REPLACE_CHILDREN:
			++position;
			atOwnMembers = false;
			own_offset = t->getSize();
			if (derivedMembers.size() || members.size()) {
				if (derivedMembers.size()) {
					own_offset = derivedMembers.begin()->first;
				}
				if (members.size()) {
					if (members.begin()->first < own_offset) {
						own_offset = members.begin()->first;
						atOwnMembers = true;
					}

				}
				return true;
			}
			// no members, continue search position
			++position;
			break;
		case REPLACE_MEMBERS:

			//we showed derived member
			if (atOwnMembers == false && members.count(own_offset)) {
				atOwnMembers = true;
				return true;
			}

			members_it = members.upper_bound(own_offset);
			derived_it = derivedMembers.upper_bound(own_offset);

			if (members_it != members.end() || derived_it != derivedMembers.end()) {
				own_offset = size;
				if (members_it != members.end()) {
					own_offset = members_it->first;
					atOwnMembers = true;
				}
				if (derived_it != derivedMembers.end()) {
					if (derived_it->first <= own_offset) {
						own_offset = derived_it->first;
						atOwnMembers = false;
					}
				}
				if (own_offset == size) {
					++position;
					return true;
				}
				return true;
			}
			else {
				own_offset = size;
				++position;
				return true;
			}
			break;
		case REPLACE_CLASSNAME_BOT:
			++it;
			if (it == g_ReconstractedTypes.end())
				return false;
			t = it->second;
			position = REPLACE_SPLIT;
			own_offset = 0;
			typeName = t->name;
			index = t->typeId;
			lnnum = t->id;
			return true;
		default:
			assert(false);
		}

	}
}

bool idaapi reconstructed_place_t::beginning(void * ud) const
{
	if (g_ReconstractedTypes.count(typeName) == 0)
		return true;
	if (g_ReconstractedTypes.empty())
		return true;
	bool is_first = g_ReconstractedTypes.begin()->first.compare(typeName) == 0 &&
		position == REPLACE_SPLIT;
	return is_first;
}

bool idaapi reconstructed_place_t::ending(void * ud) const
{

	if (g_ReconstractedTypes.empty())
		return true;
	if (g_ReconstractedTypes.count(typeName) == 0)
		return true;
	if (g_ReconstractedTypes.rbegin()->first.compare(typeName) == 0)
		if (position == REPLACE_CLASSNAME_BOT)
			return true;
	return false;
}



int idaapi reconstructed_place_t::generate(qstrvec_t * out, int * out_deflnnum,
	color_t * out_pfx_color, bgcolor_t * out_bgcolor, void * ud, int maxsize) const
{
	size_t curSize = out->size();
	if (g_ReconstractedTypes.count(typeName) == 0)
		return 0;
	ReconstructableType *reType = g_ReconstractedTypes[typeName];
	std::set<ReconstructableType *> children = reType->getChildren();
	std::set<ReconstructableType *>::iterator children_it = children.begin();
	std::set<ReconstructableType *> parents = reType->getParents();
	std::set<ReconstructableType *>::iterator parents_it = parents.begin();
	ReconstructableMember *member;
	qstring line;
	line.sprnt(COLSTR(" %08x ", SCOLOR_DREF), own_offset);

	switch (position) {

	case REPLACE_SPLIT:
		line += "; -------------------------------------------------------------------- ";
		break;
	case REPLACE_BLANK:
		break;

	case REPLACE_PARENTS:
		if (parents.size() == 0)
		{
			//parents_pos = 2;
			line += COLSTR(" error XREFS TO: ", SCOLOR_ERROR);
			break;
		}
		line += COLSTR(" XREFS TO: ", SCOLOR_PREFIX);
		for (parents_it = parents.begin(); parents_it != parents.end(); parents_it++) {
			line += (*parents_it)->name.c_str();
			line += " ";
		}
		break;
	case REPLACE_CHILDREN:

		if (children.size() == 0) {
			line += COLSTR(" error XREFS FROM: ", SCOLOR_ERROR);
			break;
		}

		line += COLSTR(" XREFS FROM: ", SCOLOR_PREFIX);
		for (children_it = children.begin(); children_it != children.end(); children_it++)
		{
			line += (*children_it)->name.c_str();
			line += " ";
		}
		break;
	case REPLACE_MEMBERS:
		if (atOwnMembers) {
			if (reType->getOwnMembers().count(own_offset)) {
				char * format = COLSTR("\t %s", SCOLOR_DCHAR) " %s";
				std::map<unsigned int, ReconstructableMember*> derived = reType->getDerivedMembers();
				for (std::map<unsigned int, ReconstructableMember*>::iterator derIt = derived.begin(); derIt != derived.end(); derIt++) {
					if (own_offset == derIt->first || (own_offset > derIt->first && own_offset <= derIt->second->getSize() + derIt->first)) {
						format = COLSTR(" | ", SCOLOR_DNUM)  COLSTR("\t %s", SCOLOR_DCHAR) " %s";
						break;
					}
				}
				member = reType->getOwnMembers().at(own_offset);
				line.cat_sprnt(format,
					member->memberType->getTypeString().c_str(),
					member->name.c_str()
				);
			}
			else
				line += COLSTR(" errormember ", SCOLOR_ERROR);
		}
		else {
			if (reType->getDerivedMembers().count(own_offset)) {
				member = reType->getDerivedMembers().at(own_offset);
				line.cat_sprnt(COLSTR(" %s", SCOLOR_DREF) " %s\t",
					member->memberType->getTypeString().c_str(),
					member->name.c_str()
				);
			}
			else
				line += COLSTR(" errormember ", SCOLOR_ERROR);
		}
		break;
	case REPLACE_BLANK_BOT:
		break;
	case REPLACE_CLASSNAME_TOP:
	case REPLACE_CLASSNAME_BOT:
		line += typeName.c_str();
		break;
	}
	out->push_back(line);
	return 1;
}

void idaapi reconstructed_place_t::serialize(bytevec_t * out) const
{
}

bool idaapi reconstructed_place_t::deserialize(const uchar ** pptr, const uchar * end)
{
	return false;
}

int idaapi reconstructed_place_t::id() const
{
	return g_replace_id;
}

const char *idaapi reconstructed_place_t::name() const
{
	return "reconstructed_place_t";
}

ea_t idaapi reconstructed_place_t::toea() const
{
	if (g_ReconstractedTypes.count(typeName) == 0)
		return BADADDR;
	ReconstructableTypeVtable *reVtable = 0;
	ReconstructableType *reType = g_ReconstractedTypes[typeName];
	std::map<unsigned int, ReconstructableMember *> members = reType->getOwnMembers();
	std::map<unsigned int, ReconstructableMember *> derivedMembers = reType->getDerivedMembers();
	switch (position) {

	case REPLACE_SPLIT:
	case REPLACE_BLANK:
	case REPLACE_CLASSNAME_TOP:
	case REPLACE_BLANK_BOT:
	case REPLACE_CLASSNAME_BOT:
		if (reVtable = dynamic_cast<ReconstructableTypeVtable*>(reType))
			return reVtable->vtable_address;
		break;
	case REPLACE_PARENTS:
	case REPLACE_CHILDREN:
		break; // TODO
	case REPLACE_MEMBERS:
		if (atOwnMembers) {
			if (members.count(own_offset)) {
				if (reVtable = dynamic_cast<ReconstructableTypeVtable*>(reType)) 
					return reVtable->to_ea(own_offset);
			}
		}
	}
	return BADADDR;
}

ReconstructableType * reconstructed_place_t::getReType()
{
	if (g_ReconstractedTypes.count(typeName))
		return g_ReconstractedTypes[typeName];
	return nullptr;
}

bool reconstructed_place_t::isDerived()
{
	return position == REPLACE_MEMBERS && !atOwnMembers;
}

bool reconstructed_place_t::isOwnMember()
{
	return position == REPLACE_MEMBERS && !atOwnMembers;
}
