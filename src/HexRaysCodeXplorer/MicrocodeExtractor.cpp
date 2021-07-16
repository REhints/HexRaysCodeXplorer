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

#include <memory>
#include <utility>
#include "Common.h"
#include "MicrocodeExtractor.h"



typedef std::shared_ptr<mbl_array_t*> shared_mbl_array_t;

struct mblock_virtual_dumper_t : public vd_printer_t
{
	virtual ~mblock_virtual_dumper_t();
	int nline;
	int serial;
	mblock_virtual_dumper_t();;
	virtual void add_line(qstring& qs);
	AS_PRINTF(3, 4) virtual int print(const int indent, const char* format, ...) override;
};

struct mblock_virtual_dumper_t_impl final : mblock_virtual_dumper_t
{
};


mblock_virtual_dumper_t::mblock_virtual_dumper_t(): nline(0), serial(0)
{
}

int mblock_virtual_dumper_t::print(const int indent, const char* format, ...)
{
	qstring buf;
	if (indent > 0)
		buf.fill(0, ' ', indent);
	va_list va;
	va_start(va, format);
	buf.cat_vsprnt(format, va);
	va_end(va);

	static const char pfx_on[] = {COLOR_ON, COLOR_PREFIX};
	static const char pfx_off[] = {COLOR_OFF, COLOR_PREFIX};
	buf.replace(pfx_on, "");
	buf.replace(pfx_off, "");

	add_line(buf);
	return buf.length();
}

void mblock_virtual_dumper_t::add_line(qstring& qs)
{
}


mblock_virtual_dumper_t::~mblock_virtual_dumper_t()
= default;

struct mblock_qstring_dumper_t final : public mblock_virtual_dumper_t
{
	qstring q_str;
	mblock_qstring_dumper_t() : mblock_virtual_dumper_t() {};

	void add_line(qstring& qs) override
	{
		q_str.append(qs);
	}
};

struct mblock_dumper_t final : public mblock_virtual_dumper_t
{
	strvec_t lines;
	mblock_dumper_t() : mblock_virtual_dumper_t() {};

	void add_line(qstring& qs) override
	{
		lines.push_back(simpleline_t(qs));
	}
};

struct sample_info_t
{
	TWidget* cv;
	mblock_dumper_t md;
	shared_mbl_array_t mba;
	mba_maturity_t mat;
	sample_info_t() : cv(nullptr), mba(nullptr), mat(){}
};


class microcode_instruction_graph
{
public:
	qstring tmp;            // temporary buffer for grcode_user_text
	qstrvec_t m_short_text;
	qstrvec_t m_block_text;
	intvec_t m_edge_colors;
	edgevec_t m_edges;
	int m_num_blocks{};

	void clear();

	void build(minsn_t* top);

protected:
	void add_edge(int i_src, int i_dest, int i_pos);

	int get_incr_block_num();

	int insert(minsn_t* ins, int i_parent);

	int insert(mop_t& op, int i_parent, int i_pos);
};

class microcode_instruction_graph_impl : public microcode_instruction_graph
{
public:
};

class microcode_instruction_graph_container;

static ssize_t idaapi migr_callback(void* ud, int code, va_list va);

class microcode_instruction_graph_container
{
protected:
	TWidget* m_tw_;
	graph_viewer_t* m_gv_;
	qstring m_title_;
	qstring m_gv_name_;

public:
	microcode_instruction_graph m_mg;
	microcode_instruction_graph_container() : m_tw_(nullptr), m_gv_(nullptr) {};

	bool display(minsn_t* top, sample_info_t* si, const int n_block, const int n_serial)
	{
		const auto mba = *si->mba;
		m_mg.build(top);

		m_title_.cat_sprnt("Microinstruction Graph - %a[%s]/%d:%d", mba->entry_ea, micro_maturity_to_string(si->mat), n_block, n_serial);
		m_tw_ = create_empty_widget(m_title_.c_str());
		netnode id;
		id.create();

		m_gv_name_.cat_sprnt("microins_%a_%s_%d_%d", mba->entry_ea, micro_maturity_to_string(si->mat), n_block, n_serial);
		m_gv_ = create_graph_viewer(m_gv_name_.c_str(), id, migr_callback, this, 0, m_tw_);
		activate_widget(m_tw_, true);
		viewer_fit_window(m_gv_);
		return true;
	}
};

void microcode_instruction_graph::clear()
{
	m_short_text.clear();
	m_block_text.clear();
	m_edge_colors.clear();
	m_edges.clear();
	m_num_blocks = 0;
}

void microcode_instruction_graph::build(minsn_t* top)
{
	clear();
	insert(top, -1);
}

void microcode_instruction_graph::add_edge(const int i_src, const int i_dest, const int i_pos)
{
	if (i_src < 0 || i_dest < 0)
		return;

	m_edges.push_back(edge_t(i_src, i_dest));
	m_edge_colors.push_back(i_pos);
}

int microcode_instruction_graph::get_incr_block_num()
{
	return m_num_blocks++;
}

int microcode_instruction_graph::insert(minsn_t* ins, int i_parent)
{
	char l_buf[MAXSTR];
	mcode_t_to_string(ins, l_buf, sizeof(l_buf));
	m_short_text.push_back(l_buf);

	qstring q_str;
	ins->print(&q_str);
	m_block_text.push_back(q_str);

	const auto i_this_block = get_incr_block_num();

	insert(ins->l, i_this_block, 0);
	insert(ins->r, i_this_block, 1);
	insert(ins->d, i_this_block, 2);

	return i_this_block;
}

int microcode_instruction_graph::insert(mop_t& op, const int i_parent, const int i_pos)
{
	if (op.t == mop_z)
		return -1;

	m_short_text.push_back(mopt_t_to_string(op.t));

	qstring q_str;
	op.print(&q_str);
	m_block_text.push_back(q_str);

	const auto i_this_block = get_incr_block_num();
	add_edge(i_parent, i_this_block, i_pos);

	switch (op.t)
	{
	case mop_d: // result of another instruction
		{
			const auto i_dest_block = insert(op.d, i_this_block);
			add_edge(i_this_block, i_dest_block, 0);
			break;
		}
	case mop_f: // list of arguments
		for (auto i = 0; i < op.f->args.size(); ++i)
			insert(op.f->args[i], i_this_block, i);
		break;
	case mop_p: // operand pair
		{
			insert(op.pair->lop, i_this_block, 0);
			insert(op.pair->hop, i_this_block, 1);
			break;
		}
	case mop_a: // result of another instruction
		{
			insert(*op.a, i_this_block, 0);
			break;
		}
	default: ;
	}
	return i_this_block;
}

static ssize_t idaapi migr_callback(void* ud, const int code, va_list va)
{
	auto gcont = static_cast<microcode_instruction_graph_container*>(ud);
	auto microg = &gcont->m_mg;
	auto result = false;

	switch (code)
	{
#if IDA_SDK_VERSION < 760
	case grcode_user_gentext:
		result = true;
		break;
#endif

		// refresh user-defined graph nodes and edges
	case grcode_user_refresh:
		// in:  mutable_graph_t *g
		// out: success
	{
		auto mg = va_arg(va, mutable_graph_t*);

		// we have to resize
		mg->resize(microg->m_num_blocks);

		for (auto& it : microg->m_edges)
			mg->add_edge(it.src, it.dst, nullptr);

		result = true;
	}
	break;

	// retrieve text for user-defined graph node
	case grcode_user_text:
		//mutable_graph_t *g
		//      int node
		//      const char **result
		//      bgcolor_t *bg_color (maybe NULL)
		// out: must return 0, result must be filled
		// NB: do not use anything calling GDI!
	{
		va_arg(va, mutable_graph_t*);
		const auto node = va_arg(va, int);
		const auto text = va_arg(va, const char**);

		microg->tmp = microg->m_short_text[node];
		microg->tmp.append('\n');
		microg->tmp.append(microg->m_block_text[node]);
		*text = microg->tmp.begin();
		result = true;
	}
	break;
	default: ;
	}
	return static_cast<int>(result);
}

static ssize_t idaapi mgr_callback(void* ud, int code, va_list va);

class microcode_graph_container
{
public:
	shared_mbl_array_t m_mba;
	mblock_qstring_dumper_t m_mqd;
	qstring m_title;
	qstring m_gv_name;
	qstring tmp;
	shared_mbl_array_t mba;
	explicit microcode_graph_container(shared_mbl_array_t mba) : m_mba(std::move(mba)), mba(std::move(mba)) {};
	bool display(sample_info_t* si)
	{
		const auto mba = *si->mba;
		m_title.cat_sprnt("Microcode Graph - %a[%s]", mba->entry_ea, micro_maturity_to_string(si->mat));

		const auto tw = create_empty_widget(m_title.c_str());
		netnode id;
		id.create();

		m_gv_name.cat_sprnt("microblkgraph_%a_%s", mba->entry_ea, micro_maturity_to_string(si->mat));
		const auto gv = create_graph_viewer(m_gv_name.c_str(), id, mgr_callback, this, 0, tw);
		activate_widget(tw, true);
		viewer_fit_window(gv);
		return true;
	}

};

static ssize_t idaapi mgr_callback(void* ud, const int code, va_list va)
{
	auto gcont = static_cast<microcode_graph_container*>(ud);
	auto mba = *gcont->m_mba;
	auto result = false;

	switch (code)
	{
#if IDA_SDK_VERSION < 760
	case grcode_user_gentext:
		result = true;
		break;
#endif

		// refresh user-defined graph nodes and edges
	case grcode_user_refresh:
		// in:  mutable_graph_t *g
		// out: success
	{
		mutable_graph_t* mg = va_arg(va, mutable_graph_t*);

		// we have to resize
		mg->resize(mba->qty);

		for (auto i = 0; i < mba->qty; ++i)
			for (auto dst : mba->get_mblock(i)->succset)
				mg->add_edge(i, dst, nullptr);

		result = true;
	}
	break;

	// retrieve text for user-defined graph node
	case grcode_user_text:
		//mutable_graph_t *g
		//      int node
		//      const char **result
		//      bgcolor_t *bg_color (maybe NULL)
		// out: must return 0, result must be filled
		// NB: do not use anything calling GDI!
	{
		va_arg(va, mutable_graph_t*);
		const auto node = va_arg(va, int);
		const auto text = va_arg(va, const char**);

		gcont->m_mqd.q_str.clear();
		mba->get_mblock(node)->print(gcont->m_mqd);
		*text = gcont->m_mqd.q_str.begin();
		result = true;
	}
	break;
	default: ;
	}
	return static_cast<int>(result);
}

static bool idaapi ct_keyboard(TWidget* /*v*/, const int key, const int shift, void* ud)
{
	if (shift == 0)
	{
		auto* si = static_cast<sample_info_t*>(ud);
		switch (key)
		{
		case 'G':
		{
			auto mgc = new microcode_graph_container(si->mba);
			return mgc->display(si);
		}


		// User wants to show a graph of the current instruction
		case 'I':
		{
			qstring buf;
			tag_remove(&buf, get_custom_viewer_curline(si->cv, false));
			const auto p_line = buf.c_str();
			const auto p_dot = strchr(p_line, '.');
			if (p_dot == nullptr)
			{
				warning(
					"Couldn't find the block number on the current line; was the block empty?\n"
					"If it was not empty, and you don't see [int].[int] at the beginning of the lines\n"
					"please run the plugin again to generate a new microcode listing.\n"
					"That should fix it.");
				return true; // reacted to the keypress
			}
			const auto n_block = atoi(p_line);
			const auto n_serial = atoi(p_dot + 1);
			auto mba = *si->mba;

			if (n_block > mba->qty)
			{
				warning("Plugin error: line prefix was %d:%d, but block only has %d basic blocks.", n_block, n_serial, mba->qty);
				return true;
			}

			const auto blk = mba->get_mblock(n_block);
			auto minsn = blk->head;
			int i;
			for (i = 0; i < n_serial; ++i)
			{
				minsn = minsn->next;
				if (minsn == nullptr)
					break;
			}

			if (minsn == nullptr)
			{
				if (i == 0)
					warning(
						"Couldn't get first minsn_t from %d:%d; was the block empty?\n"
						"If it was not empty, and you don't see [int].[int] at the beginning of the lines\n"
						"please run the plugin again to generate a new microcode listing.\n"
						"That should fix it.", n_block, n_serial);
				else
					warning("Couldn't get first minsn_t from %d:%d; last valid instruction was %d", n_block, n_serial, i - 1);
				return true;
			}

			char repr[MAXSTR];
			mcode_t_to_string(minsn, repr, sizeof(repr));
			auto mcg = new microcode_instruction_graph_container;
			return mcg->display(minsn, si, n_block, n_serial);
		}
		case IK_ESCAPE:
			close_widget(si->cv, WCLS_SAVE | WCLS_CLOSE_LATER);
			return true;
	default: ;
		}
	}
	return false;
}

static const custom_viewer_handlers_t handlers(
	ct_keyboard,
	nullptr, // popup
	nullptr, // mouse_moved
	nullptr, // click
	nullptr, // dblclick
	nullptr,
	nullptr, // close
	nullptr, // help
	nullptr);// adjust_place

ssize_t idaapi ui_callback(void* ud, const int code, va_list va)
{
	const auto si = static_cast<sample_info_t*>(ud);
	switch (code)
	{
	case ui_widget_invisible:
	{
		const auto f = va_arg(va, TWidget*);
		if (f == si->cv)
		{
			delete si;
			unhook_from_notification_point(HT_UI, ui_callback);
		}
	}
	break;
default: ;
	}
	return 0;
}

const char* mat_levels[] =
{
	"MMAT_GENERATED",
	"MMAT_PREOPTIMIZED",
	"MMAT_LOCOPT",
	"MMAT_CALLS",
	"MMAT_GLBOPT1",
	"MMAT_GLBOPT2",
	"MMAT_GLBOPT3",
	"MMAT_LVARS"
};

mba_maturity_t ask_desired_maturity()
{
	const char dlg_text[] =
		"Select maturity level\n"
		"<Desired ~maturity level:b:0:::>\n";

	qstrvec_t opts;
	for (auto& mat_level : mat_levels)
		opts.push_back(mat_level);

	auto sel = 0;
	const auto ret = ask_form(dlg_text, &opts, &sel);

	if (ret > 0)
		return static_cast<mba_maturity_t>(static_cast<int>(MMAT_GENERATED) + sel);
	return MMAT_ZERO;
}

void show_microcode_explorer()
{
	const auto pfn = get_func(get_screen_ea());
	if (pfn == nullptr)
	{
		warning("Please position the cursor within a function");
		return;
	}

	const auto mmat = ask_desired_maturity();
	if (mmat == MMAT_ZERO)
		return;

	hexrays_failure_t hf;
	auto mba = gen_microcode(pfn, &hf, nullptr, 0, mmat);
	if (mba == nullptr)
	{
		warning("#error \"%a: %s", hf.errea, hf.desc().c_str());
		return;
	}

	auto si = new sample_info_t;
	si->mba = std::make_shared<mbl_array_t*>(mba);
	si->mat = mmat;
	// Dump the microcode to the output window
	mba->print(si->md);

	simpleline_place_t s1;
	simpleline_place_t s2(si->md.lines.size() - 1);

	qstring title;
	title.cat_sprnt("Microcode Explorer - %a - %s", pfn->start_ea, micro_maturity_to_string(mmat));

	si->cv = create_custom_viewer(
		title.c_str(), // title
		&s1, // minplace
		&s2, // maxplace
		&s1, // curplace
		nullptr, // renderer_info_t *rinfo
		&si->md.lines, // ud
		&handlers, // cvhandlers
		si, // cvhandlers_ud
		nullptr); // parent

	hook_to_notification_point(HT_UI, ui_callback, si);
	display_widget(si->cv, WOPN_DP_TAB | WOPN_RESTORE);
}
