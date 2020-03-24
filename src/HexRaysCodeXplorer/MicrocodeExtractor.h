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


// This code mostly adopted from https://github.com/RolfRolles/HexRaysDeob
// All kudos going to Rolf https://www.hexblog.com/?p=1248


#pragma once


void show_microcode_explorer();
mba_maturity_t ask_desired_maturity();

// Produce a string for an operand type
inline const char* mopt_t_to_string(const mopt_t t)
{
	switch (t)
	{
	case mop_z: return "mop_z";
	case mop_r: return "mop_r";
	case mop_n: return "mop_n";
	case mop_str: return "mop_str";
	case mop_d: return "mop_d";
	case mop_S: return "mop_S";
	case mop_v: return "mop_v";
	case mop_b: return "mop_b";
	case mop_f: return "mop_f";
	case mop_l: return "mop_l";
	case mop_a: return "mop_a";
	case mop_h: return "mop_h";
	case mop_c: return "mop_c";
	case mop_fn: return "mop_fn";
	case mop_p: return "mop_p";
	case mop_sc: return "mop_sc";
	default: ;
	};
	return "???";
}

// Produce a brief representation of a microinstruction, including the types
// of its operands.
inline void mcode_t_to_string(minsn_t* o, char* out_buf, size_t n)
{
	switch (o->opcode)
	{
	case m_nop: snprintf(out_buf, n, "m_nop"); break;
	case m_stx: snprintf(out_buf, n, "m_stx(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_ldx: snprintf(out_buf, n, "m_ldx(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_ldc: snprintf(out_buf, n, "m_ldc(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_mov: snprintf(out_buf, n, "m_mov(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_neg: snprintf(out_buf, n, "m_neg(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_lnot: snprintf(out_buf, n, "m_lnot(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_bnot: snprintf(out_buf, n, "m_bnot(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_xds: snprintf(out_buf, n, "m_xds(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_xdu: snprintf(out_buf, n, "m_xdu(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_low: snprintf(out_buf, n, "m_low(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_high: snprintf(out_buf, n, "m_high(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_add: snprintf(out_buf, n, "m_add(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_sub: snprintf(out_buf, n, "m_sub(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_mul: snprintf(out_buf, n, "m_mul(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_udiv: snprintf(out_buf, n, "m_udiv(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_sdiv: snprintf(out_buf, n, "m_sdiv(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_umod: snprintf(out_buf, n, "m_umod(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_smod: snprintf(out_buf, n, "m_smod(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_or: snprintf(out_buf, n, "m_or(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_and: snprintf(out_buf, n, "m_and(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_xor: snprintf(out_buf, n, "m_xor(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_shl: snprintf(out_buf, n, "m_shl(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_shr: snprintf(out_buf, n, "m_shr(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_sar: snprintf(out_buf, n, "m_sar(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_cfadd: snprintf(out_buf, n, "m_cfadd(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_ofadd: snprintf(out_buf, n, "m_ofadd(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_cfshl: snprintf(out_buf, n, "m_cfshl(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_cfshr: snprintf(out_buf, n, "m_cfshr(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_sets: snprintf(out_buf, n, "m_sets(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_seto: snprintf(out_buf, n, "m_seto(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setp: snprintf(out_buf, n, "m_setp(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setnz: snprintf(out_buf, n, "m_setnz(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setz: snprintf(out_buf, n, "m_setz(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setae: snprintf(out_buf, n, "m_setae(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setb: snprintf(out_buf, n, "m_setb(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_seta: snprintf(out_buf, n, "m_seta(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setbe: snprintf(out_buf, n, "m_setbe(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setg: snprintf(out_buf, n, "m_setg(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setge: snprintf(out_buf, n, "m_setge(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setl: snprintf(out_buf, n, "m_setl(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_setle: snprintf(out_buf, n, "m_setle(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jcnd: snprintf(out_buf, n, "m_jcnd(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_jnz: snprintf(out_buf, n, "m_jnz(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jz: snprintf(out_buf, n, "m_jz(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jae: snprintf(out_buf, n, "m_jae(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jb: snprintf(out_buf, n, "m_jb(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_ja: snprintf(out_buf, n, "m_ja(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jbe: snprintf(out_buf, n, "m_jbe(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jg: snprintf(out_buf, n, "m_jg(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jge: snprintf(out_buf, n, "m_jge(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jl: snprintf(out_buf, n, "m_jl(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jle: snprintf(out_buf, n, "m_jle(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_jtbl: snprintf(out_buf, n, "m_jtbl(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t)); break;
	case m_ijmp: snprintf(out_buf, n, "m_ijmp(%s,%s)", mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_goto: snprintf(out_buf, n, "m_goto(%s)", mopt_t_to_string(o->l.t)); break;
	case m_call: snprintf(out_buf, n, "m_call(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_icall: snprintf(out_buf, n, "m_icall(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_ret: snprintf(out_buf, n, "m_ret"); break;
	case m_push: snprintf(out_buf, n, "m_push(%s)", mopt_t_to_string(o->l.t)); break;
	case m_pop: snprintf(out_buf, n, "m_pop(%s)", mopt_t_to_string(o->d.t)); break;
	case m_und: snprintf(out_buf, n, "m_und(%s)", mopt_t_to_string(o->d.t)); break;
	case m_ext: snprintf(out_buf, n, "m_ext(???)"); break;
	case m_f2i: snprintf(out_buf, n, "m_f2i(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_f2u: snprintf(out_buf, n, "m_f2u(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_i2f: snprintf(out_buf, n, "m_i2f(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_u2f: snprintf(out_buf, n, "m_u2f(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_f2f: snprintf(out_buf, n, "m_f2f(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_fneg: snprintf(out_buf, n, "m_fneg(%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->d.t)); break;
	case m_fadd: snprintf(out_buf, n, "m_fadd(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_fsub: snprintf(out_buf, n, "m_fsub(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_fmul: snprintf(out_buf, n, "m_fmul(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	case m_fdiv: snprintf(out_buf, n, "m_fdiv(%s,%s,%s)", mopt_t_to_string(o->l.t), mopt_t_to_string(o->r.t), mopt_t_to_string(o->d.t)); break;
	}
}

// Produce a string describing the microcode maturity level.
inline const char* micro_maturity_to_string(const mba_maturity_t mmt)
{
	switch (mmt)
	{
	case MMAT_ZERO: return "MMAT_ZERO";
	case MMAT_GENERATED: return "MMAT_GENERATED";
	case MMAT_PREOPTIMIZED: return "MMAT_PREOPTIMIZED";
	case MMAT_LOCOPT: return "MMAT_LOCOPT";
	case MMAT_CALLS: return "MMAT_CALLS";
	case MMAT_GLBOPT1: return "MMAT_GLBOPT1";
	case MMAT_GLBOPT2: return "MMAT_GLBOPT2";
	case MMAT_GLBOPT3: return "MMAT_GLBOPT3";
	case MMAT_LVARS: return "MMAT_LVARS";
	default: return "???";
	}
}

// Copied from http://www.hexblog.com/?p=1198
// I did add code for the mop_d case; it used to return false

//--------------------------------------------------------------------------
// compare operands but ignore the sizes
inline bool equal_mops_ignore_size(const mop_t& lo, const mop_t& ro)
{
	if (lo.t != ro.t)
		return false;

	switch (lo.t)
	{
	case mop_z:         // none
		return true;
	case mop_fn:        // floating point
		return *ro.fpc == *lo.fpc;
	case mop_n:         // immediate
	{
		const auto minsize = qmin(lo.size, ro.size);
		const auto v1 = extend_sign(ro.nnn->value, minsize, false);
		const auto v2 = extend_sign(lo.nnn->value, minsize, false);
		return v1 == v2;
	}
	case mop_S:         // stack variable
		return *ro.s == *lo.s;
	case mop_v:         // global variable
		return ro.g == lo.g;
	case mop_d:         // result of another instruction
		// I added this
		return ro.d->equal_insns(*lo.d, EQ_IGNSIZE | EQ_IGNCODE);
	case mop_b:         // micro basic block (mblock_t)
		return ro.b == lo.b;
	case mop_r:         // register
		return ro.r == lo.r;
	case mop_f:
		break;            // not implemented
	case mop_l:
		return *ro.l == *lo.l;
	case mop_a:
		return lo.a->insize == ro.a->insize
			&& lo.a->outsize == ro.a->outsize
			&& equal_mops_ignore_size(*lo.a, *ro.a);
	case mop_h:
		return streq(ro.helper, lo.helper);
	case mop_str:
		return streq(ro.cstr, lo.cstr);
	case mop_c:
		return *ro.c == *lo.c;
	case mop_p:
		return equal_mops_ignore_size(lo.pair->lop, ro.pair->lop)
			&& equal_mops_ignore_size(lo.pair->hop, ro.pair->hop);
	case mop_sc: // not implemented
		break;
	}
	return false;
}
