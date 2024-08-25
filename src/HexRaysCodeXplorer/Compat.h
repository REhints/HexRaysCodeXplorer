// compatibility functions needed for IDA 9.0 support. mostly ported from IDAPython's idc module
#pragma once
#include <lines.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>

/// Return values for add_struc_member()
enum struc_error_t
{
	STRUC_ERROR_MEMBER_OK      = 0,  ///< success
	STRUC_ERROR_MEMBER_NAME    = -1, ///< already has member with this name (bad name)
	STRUC_ERROR_MEMBER_OFFSET  = -2, ///< already has member at this offset
	STRUC_ERROR_MEMBER_SIZE    = -3, ///< bad number of bytes or bad sizeof(type)
	STRUC_ERROR_MEMBER_TINFO   = -4, ///< bad typeid parameter
	STRUC_ERROR_MEMBER_STRUCT  = -5, ///< bad struct id (the 1st argument)
	STRUC_ERROR_MEMBER_UNIVAR  = -6, ///< unions can't have variable sized members
	STRUC_ERROR_MEMBER_VARLAST = -7, ///< variable sized member should be the last member in the structure
	STRUC_ERROR_MEMBER_NESTED  = -8, ///< recursive structure nesting is forbidden
};

namespace Compat
{
	tid_t add_struc(uval_t idx, const char* name, bool is_union = false);
	struc_error_t add_struc_member(tid_t sid, const char* fieldname, ea_t offset, flags64_t flag,
								   const opinfo_t* mt, asize_t nbytes);
	int get_member_flag(tid_t sid, asize_t offset);
	tid_t get_member_id(tid_t sid, asize_t offset);
	qstring get_member_name(tid_t sid, asize_t offset);
	asize_t get_member_size(tid_t sid, asize_t offset);
	bool get_member_tinfo(tinfo_t* tif, tid_t sid, asize_t offset);
	ea_t get_struc_first_offset(tid_t id);
	tid_t get_struc_id(const char* name);
	qstring get_struc_name(tid_t id);
	ea_t get_struc_next_offset(tid_t id, ea_t offset);
	bool set_member_name(tid_t sid, ea_t offset, const char* name);
	bool set_member_tinfo(tid_t sid, uval_t memoff, const tinfo_t& tif, int flags);
	bool set_struc_cmt(tid_t id, const char* cmt, bool repeatable);

	/// \defgroup SET_MEMTI_ Set member tinfo flags
	/// Passed as 'flags' parameter to set_member_tinfo()
	//@{
	#define SET_MEMTI_MAY_DESTROY 0x0001 ///< may destroy other members
	#define SET_MEMTI_COMPATIBLE  0x0002 ///< new type must be compatible with the old
	#define SET_MEMTI_FUNCARG     0x0004 ///< mptr is function argument (cannot create arrays)
	#define SET_MEMTI_BYTIL       0x0008 ///< new type was created by the type subsystem
	#define SET_MEMTI_USERTI      0x0010 ///< user-specified type
	//@}
}
