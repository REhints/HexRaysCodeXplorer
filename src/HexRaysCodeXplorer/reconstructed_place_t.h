#pragma once
#include "Common.h"


enum reconstructed_place_pos_t {
	REPLACE_SPLIT = 0,
	REPLACE_BLANK,
	REPLACE_CLASSNAME_TOP,
	REPLACE_PARENTS,
	REPLACE_CHILDREN,
	REPLACE_MEMBERS,
	REPLACE_BLANK_BOT,
	REPLACE_CLASSNAME_BOT
};


class ReconstructableType;

class reconstructed_place_t : public place_t {

public:
	std::string typeName;             ///< rectype name
	uval_t index;
	reconstructed_place_pos_t position;
	bool atOwnMembers;
	uval_t own_offset;
	reconstructed_place_t();
	reconstructed_place_t(std::string n);
	reconstructed_place_t(const reconstructed_place_t &other);

	virtual void idaapi print(qstring * out_buf, void * ud) const override;
	virtual uval_t idaapi touval(void * ud) const override;
	virtual place_t *idaapi clone(void) const override;
	virtual void idaapi copyfrom(const place_t * from) override;
	virtual place_t *idaapi makeplace(void * ud, uval_t x, int lnnum) const override;
	virtual int idaapi compare(const place_t * t2) const override;
	virtual void idaapi adjust(void * ud) override;
	virtual bool idaapi prev(void * ud) override;
	virtual bool idaapi next(void * ud) override;
	virtual bool idaapi beginning(void * ud) const override;
	virtual bool idaapi ending(void * ud) const override;
	virtual int idaapi generate(qstrvec_t * out, int * out_deflnnum, color_t * out_pfx_color, bgcolor_t * out_bgcolor, void * ud, int maxsize) const override;
	virtual void idaapi serialize(bytevec_t * out) const override;
	virtual bool idaapi deserialize(const uchar ** pptr, const uchar * end) override;
	virtual int idaapi id() const override;
	virtual const char *idaapi name() const override;
	virtual ea_t idaapi toea() const;

	ReconstructableType *getReType();
	bool isDerived();
	bool isOwnMember();

};
