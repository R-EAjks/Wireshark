/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "dfvm.h"

#include <ftypes/ftypes.h>
#include <wsutil/ws_assert.h>

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op)
{
	dfvm_insn_t	*insn;

	insn = g_new(dfvm_insn_t, 1);
	insn->op = op;
	insn->arg1 = -1;
	insn->arg2 = -1;
	insn->arg3 = -1;
	insn->arg4 = -1;
	return insn;
}

void
dfvm_value_free(dfvm_value_t *v)
{
	switch (v->type) {
		case FVALUE:
			fvalue_free(v->value.fvalue);
			break;
		case DRANGE:
			drange_free(v->value.drange);
			break;
		case PCRE:
			ws_regex_free(v->value.pcre);
			break;
		default:
			/* nothing */
			;
	}
	g_free(v);
}

void
dfvm_insn_free(dfvm_insn_t *insn)
{
	g_free(insn);
}


dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type)
{
	dfvm_value_t	*v;

	v = g_new(dfvm_value_t, 1);
	v->type = type;
	return v;
}

static char *
mem_value_str(dfilter_t *df, int addr)
{
	dfvm_value_t *memv;

	memv = g_ptr_array_index(df->constants, addr);
	switch (memv->type) {
		case FVALUE:
			return fvalue_to_debug_repr(NULL, memv->value.fvalue);
		case HFINFO:
			return ws_strdup(memv->value.hfinfo->abbrev);
		case DRANGE:
			return drange_tostr(memv->value.drange);
		case FUNCDEF:
			return ws_strdup(memv->value.funcdef->name);
		case PCRE:
			return ws_strdup(ws_regex_pattern(memv->value.pcre));
		case EMPTY:
			break;
	}
	ws_assert_not_reached();
}

#define OFFSET (8*3)

static const char *
indent(const char *kind)
{
	int len = (int)strlen("0000 ") + (int)strlen(kind);
	int gap = OFFSET - len;

	if (gap <= 0)
		return " ";
	if (gap <= 8)
		return "\t";
	if (gap <= 16)
		return "\t\t";
	return "\t\t\t";
}

void
dfvm_dump(FILE *f, dfilter_t *df)
{
	int		id, length;
	dfvm_insn_t	*insn;
	dfvm_value_t	*memv;
	int		arg1, arg2, arg3, arg4;
	char		*str, *str2;
	const char	*kind;

	/* First dump the constant initializations */
	fprintf(f, "Constants:\n");
	length = df->constants->len;
	for (id = 0; id < length; id++) {

		memv = g_ptr_array_index(df->constants, id);
		str = mem_value_str(df, id);

		switch (memv->type) {
			case FVALUE:
				kind = fvalue_type_name(memv->value.fvalue);
				str2 = ws_strdup_printf("<%s>", kind);
				fprintf(f, "%04d %s%s%s\n",
					id, str2, indent(str2), str);
				g_free(str2);
				break;
			case PCRE:
				kind = "<PCRE>";
				fprintf(f, "%04d %s%s%s\n",
					id, kind, indent(kind), str);
				break;
			case HFINFO:
				kind = "<HFINFO>";
				fprintf(f, "%04d %s%s%s\n",
					id, kind, indent(kind), str);
				break;
			case DRANGE:
				kind = "<DRANGE>";
				fprintf(f, "%04d %s%s%s\n",
					id, kind, indent(kind), str);
				break;
			case FUNCDEF:
				kind = "<FUNCTION>";
				fprintf(f, "%04d %s%s%s\n",
					id, kind, indent(kind), str);
				break;
			default:
				ws_assert_not_reached();
				break;
		}
		g_free(str);
	}

	fprintf(f, "\nInstructions:\n");
	/* Now dump the operations */
	length = df->insns->len;
	for (id = 0; id < length; id++) {

		insn = (dfvm_insn_t	*)g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg4 = insn->arg4;

		switch (insn->op) {
			case CHECK_EXISTS:
				str = mem_value_str(df, arg1);
				kind = "CHECK_EXISTS";
				fprintf(f, "%04d %s%s%s\n",
					id, kind, indent(kind), str);
				g_free(str);
				break;

			case READ_TREE:
				str = mem_value_str(df, arg1);
				kind = "READ_TREE";
				fprintf(f, "%04d %s%s%s -> reg#%d\n",
					id, kind, indent(kind), str, arg2);
				g_free(str);
				break;

			case CALL_FUNCTION:
				str = mem_value_str(df, arg1);
				kind = "CALL_FUNCTION";
				fprintf(f, "%04d %s%s%s(",
					id, kind, indent(kind), str);
				if (arg3 > 0) {
					fprintf(f, "reg#%d", arg3);
				}
				if (arg4 > 0) {
					fprintf(f, ", reg#%d", arg4);
				}
				fprintf(f, ") -> reg#%d\n", arg2);
				g_free(str);
				break;

			case MK_RANGE:
				str = mem_value_str(df, arg3);
				kind = "MK_RANGE";
				fprintf(f, "%04d %s%sreg#%d[%s] -> reg#%d\n",
					id, kind, indent(kind), arg1, str, arg2);
				g_free(str);
				break;

			case ALL_EQ:
				kind = "ALL_EQ";
				fprintf(f, "%04d %s%sreg#%d === reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_EQ:
				kind = "ANY_EQ";
				fprintf(f, "%04d %s%sreg#%d == reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ALL_NE:
				kind = "ALL_NE";
				fprintf(f, "%04d %s%sreg#%d != reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_NE:
				kind = "ANY_NE";
				fprintf(f, "%04d %s%sreg#%d !== reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_GT:
				kind = "ANY_GT";
				fprintf(f, "%04d %s%sreg#%d > reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_GE:
				kind = "ANY_GE";
				fprintf(f, "%04d %s%sreg#%d >= reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_LT:
				kind = "ANY_LT";
				fprintf(f, "%04d %s%sreg#%d < reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_LE:
				kind = "ANY_LE";
				fprintf(f, "%04d %s%sreg#%d < reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_BITWISE_AND:
				kind = "ANY_BITWISE_AND";
				fprintf(f, "%04d %s%sreg#%d & reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ANY_CONTAINS:
				kind = "ANY_CONTAINS";
				fprintf(f, "%04d %s%sreg#%d contains reg#%d\n",
					id, kind, indent(kind), arg1, arg2);
				break;

			case ALL_EQ_M:
				str = mem_value_str(df, arg2);
				kind = "ALL_EQ";
				fprintf(f, "%04d %s%sreg#%d === %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_EQ_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_EQ";
				fprintf(f, "%04d %s%sreg#%d == %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ALL_NE_M:
				str = mem_value_str(df, arg2);
				kind = "ALL_NE";
				fprintf(f, "%04d %s%sreg#%d != %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_NE_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_NE";
				fprintf(f, "%04d %s%sreg#%d !== %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_GT_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_GT";
				fprintf(f, "%04d %s%sreg#%d > %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_GE_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_GE";
				fprintf(f, "%04d %s%sreg#%d >= %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_LT_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_LT";
				fprintf(f, "%04d %s%sreg#%d < %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_LE_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_LE";
				fprintf(f, "%04d %s%sreg#%d <= %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_BITWISE_AND_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_BITWISE_AND";
				fprintf(f, "%04d %s%sreg#%d & %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_CONTAINS_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_CONTAINS";
				fprintf(f, "%04d %s%sreg#%d contains %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_MATCHES_M:
				str = mem_value_str(df, arg2);
				kind = "ANY_MATCHES";
				fprintf(f, "%04d %s%sreg#%d ~ %s\n",
					id, kind, indent(kind), arg1, str);
				g_free(str);
				break;

			case ANY_INSET2_M:
				str = mem_value_str(df, arg2);
				str2 = mem_value_str(df, arg3);
				kind = "ANY_INSET2";
				fprintf(f, "%04d %s%sreg#%d in {%s .. %s}\n",
					id, kind, indent(kind), arg1, str, str2);
				g_free(str);
				g_free(str2);
				break;

			case NOT:
				fprintf(f, "%04d NOT\n", id);
				break;

			case RETURN:
				fprintf(f, "%04d RETURN\n", id);
				break;

			case IF_TRUE_GOTO:
				kind = "IF_TRUE_GOTO";
				fprintf(f, "%04d %s%s%d\n",
					id, kind, indent(kind), arg1);
				break;

			case IF_FALSE_GOTO:
				kind = "IF_FALSE_GOTO";
				fprintf(f, "%04d %s%s%d\n",
					id, kind, indent(kind), arg1);
				break;

			default:
				ws_assert_not_reached();
				break;
		}
	}
}

/* Reads a field from the proto_tree and loads the fvalues into a register,
 * if that field has not already been read. */
static gboolean
read_tree(dfilter_t *df, proto_tree *tree, header_field_info *hfinfo, int reg)
{
	GPtrArray	*finfos;
	field_info	*finfo;
	int		i, len;
	GList		*fvalues = NULL;
	gboolean	found_something = FALSE;

	/* Already loaded in this run of the dfilter? */
	if (df->attempted_load[reg]) {
		if (df->registers[reg]) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}

	df->attempted_load[reg] = TRUE;

	while (hfinfo) {
		finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);
		if ((finfos == NULL) || (g_ptr_array_len(finfos) == 0)) {
			hfinfo = hfinfo->same_name_next;
			continue;
		}
		else {
			found_something = TRUE;
		}

		len = finfos->len;
		for (i = 0; i < len; i++) {
			finfo = (field_info *)g_ptr_array_index(finfos, i);
			fvalues = g_list_prepend(fvalues, &finfo->value);
		}

		hfinfo = hfinfo->same_name_next;
	}

	if (!found_something) {
		return FALSE;
	}

	df->registers[reg] = fvalues;
	// These values are referenced only, do not try to free it later.
	df->owns_memory[reg] = FALSE;
	return TRUE;
}

static GList *
load_fvalue(dfilter_t *df, int addr)
{
	dfvm_value_t *val = g_ptr_array_index(df->constants, addr);
	return g_list_prepend(NULL, val->value.fvalue);
}

static GList *
load_pcre(dfilter_t *df, int addr)
{
	dfvm_value_t *val = g_ptr_array_index(df->constants, addr);
	return g_list_prepend(NULL, val->value.pcre);
}

enum match_how {
	MATCH_ANY,
	MATCH_ALL
};

typedef gboolean (*DFVMCompareFunc)(const fvalue_t *, const fvalue_t *);

static gboolean
cmp_test(enum match_how how, DFVMCompareFunc match_func, GList *arg1, GList *arg2)
{
	GList	*list_a, *list_b;
	gboolean want_all = (how == MATCH_ALL);
	gboolean want_any = (how == MATCH_ANY);
	gboolean have_match;

	list_a = arg1;

	while (list_a) {
		list_b = arg2;
		while (list_b) {
			have_match = match_func(list_a->data, list_b->data);
			if (want_all && !have_match) {
				return FALSE;
			}
			else if (want_any && have_match) {
				return TRUE;
			}
			list_b = g_list_next(list_b);
		}
		list_a = g_list_next(list_a);
	}
	/* want_all || !want_any */
	return want_all;
}

static inline gboolean
any_test(dfilter_t *df, DFVMCompareFunc cmp, int reg1, int reg2)
{
	GList *arg1 = df->registers[reg1];
	GList *arg2 = df->registers[reg2];

	/* cmp(A) <=> cmp(a1) OR cmp(a2) OR cmp(a3) OR ... */
	gboolean ret = cmp_test(MATCH_ANY, cmp, arg1, arg2);
	return ret;
}

static inline gboolean
all_test(dfilter_t *df, DFVMCompareFunc cmp, int reg1, int reg2)
{
	GList *arg1 = df->registers[reg1];
	GList *arg2 = df->registers[reg2];

	/* cmp(A) <=> cmp(a1) AND cmp(a2) AND cmp(a3) AND ... */
	gboolean ret = cmp_test(MATCH_ALL, cmp, arg1, arg2);
	return ret;
}

static inline gboolean
any_test_m(dfilter_t *df, DFVMCompareFunc cmp, int reg1, int addr)
{
	GList *arg1 = df->registers[reg1];
	GList *arg2 = load_fvalue(df, addr);

	gboolean ret = cmp_test(MATCH_ANY, cmp, arg1, arg2);
	g_list_free(arg2);
	return ret;
}

static inline gboolean
all_test_m(dfilter_t *df, DFVMCompareFunc cmp, int reg1, int addr)
{
	GList *arg1 = df->registers[reg1];
	GList *arg2 = load_fvalue(df, addr);

	gboolean ret = cmp_test(MATCH_ALL, cmp, arg1, arg2);
	g_list_free(arg2);
	return ret;
}

static inline gboolean
any_matches_m(dfilter_t *df, int reg1, int addr)
{
	GList *arg1 = df->registers[reg1];
	GList *arg2 = load_pcre(df, addr);

	gboolean ret = cmp_test(MATCH_ANY, (DFVMCompareFunc)fvalue_matches, arg1, arg2);
	g_list_free(arg2);
	return ret;
}

static gboolean
any_inset2_m(dfilter_t *df, int reg1, int addr1, int addr2)
{
	GList	*list1, *list_low, *list_high;
	fvalue_t *low, *high;
	gboolean ret = FALSE;

	list1 = df->registers[reg1];
	list_low = load_fvalue(df, addr1);
	list_high = load_fvalue(df, addr2);

	/* The first register contains the values associated with a field, the
	 * second and third arguments are expected to be a single value for the
	 * lower and upper bound respectively. These cannot be fields and thus
	 * the list length MUST be one. This should have been enforced by
	 * grammar.lemon.
	 */
	ws_assert(list_low && !g_list_next(list_low));
	ws_assert(list_high && !g_list_next(list_high));
	low = list_low->data;
	high = list_high->data;

	while (list1) {
		fvalue_t *value = list1->data;
		if (fvalue_ge(value, low) && fvalue_le(value, high)) {
			ret = TRUE;
			break;
		}
		list1 = g_list_next(list1);
	}

	g_list_free(list_low);
	g_list_free(list_high);
	return ret;
}


static void
free_owned_register(gpointer data, gpointer user_data _U_)
{
	fvalue_t *value = (fvalue_t *)data;
	fvalue_free(value);
}

/* Clear registers that were populated during evaluation (leaving constants
 * intact). If we created the values, then these will be freed as well. */
static void
free_register_overhead(dfilter_t* df)
{
	guint i;

	for (i = 0; i < df->num_registers; i++) {
		df->attempted_load[i] = FALSE;
		if (df->registers[i]) {
			if (df->owns_memory[i]) {
				g_list_foreach(df->registers[i], free_owned_register, NULL);
				df->owns_memory[i] = FALSE;
			}
			g_list_free(df->registers[i]);
			df->registers[i] = NULL;
		}
	}
}

/* Takes the list of fvalue_t's in a register, uses fvalue_slice()
 * to make a new list of fvalue_t's (which are ranges, or byte-slices),
 * and puts the new list into a new register. */
static void
mk_range(dfilter_t *df, int from_reg, int to_reg, int drange_addr)
{
	GList		*from_list, *to_list;
	fvalue_t	*old_fv, *new_fv;
	dfvm_value_t	*memv;

	to_list = NULL;
	from_list = df->registers[from_reg];
	memv = g_ptr_array_index(df->constants, drange_addr);

	while (from_list) {
		old_fv = (fvalue_t*)from_list->data;
		new_fv = fvalue_slice(old_fv, memv->value.drange);
		/* Assert here because semcheck.c should have
		 * already caught the cases in which a slice
		 * cannot be made. */
		ws_assert(new_fv);
		to_list = g_list_append(to_list, new_fv);

		from_list = g_list_next(from_list);
	}

	df->registers[to_reg] = to_list;
	df->owns_memory[to_reg] = TRUE;
}



gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree)
{
	int		id, length;
	gboolean	accum = TRUE;
	dfvm_insn_t	*insn;
	dfvm_value_t	*memv;
	int		arg1, arg2, arg3, arg4;
	header_field_info	*hfinfo;
	GList		*param1;
	GList		*param2;

	ws_assert(tree);

	length = df->insns->len;

	for (id = 0; id < length; id++) {

	  AGAIN:
		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;
		arg4 = insn->arg4;

		switch (insn->op) {
			case CHECK_EXISTS:
				memv = g_ptr_array_index(df->constants, arg1);
				hfinfo = memv->value.hfinfo;
				while(hfinfo) {
					accum = proto_check_for_protocol_or_field(tree,
							hfinfo->id);
					if (accum) {
						break;
					}
					else {
						hfinfo = hfinfo->same_name_next;
					}
				}
				break;

			case READ_TREE:
				memv = g_ptr_array_index(df->constants, arg1);
				accum = read_tree(df, tree,
						memv->value.hfinfo, arg2);
				break;

			case CALL_FUNCTION:
				memv = g_ptr_array_index(df->constants, arg1);
				param1 = NULL;
				param2 = NULL;
				if (arg3 >= 0) {
					param1 = df->registers[arg3];
				}
				if (arg4 >= 0) {
					param2 = df->registers[arg4];
				}
				accum = memv->value.funcdef->function(param1, param2,
						&df->registers[arg2]);
				// functions create a new value, so own it.
				df->owns_memory[arg2] = TRUE;
				break;

			case MK_RANGE:
				mk_range(df, arg1, arg2, arg3);
				break;

			case ALL_EQ:
				accum = all_test(df, fvalue_eq, arg1, arg2);
				break;

			case ANY_EQ:
				accum = any_test(df, fvalue_eq, arg1, arg2);
				break;

			case ALL_NE:
				accum = all_test(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_NE:
				accum = any_test(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_GT:
				accum = any_test(df, fvalue_gt, arg1, arg2);
				break;

			case ANY_GE:
				accum = any_test(df, fvalue_ge, arg1, arg2);
				break;

			case ANY_LT:
				accum = any_test(df, fvalue_lt, arg1, arg2);
				break;

			case ANY_LE:
				accum = any_test(df, fvalue_le, arg1, arg2);
				break;

			case ANY_BITWISE_AND:
				accum = any_test(df, fvalue_bitwise_and, arg1, arg2);
				break;

			case ANY_CONTAINS:
				accum = any_test(df, fvalue_contains, arg1, arg2);
				break;

			case ALL_EQ_M:
				accum = all_test_m(df, fvalue_eq, arg1, arg2);
				break;

			case ANY_EQ_M:
				accum = any_test_m(df, fvalue_eq, arg1, arg2);
				break;

			case ALL_NE_M:
				accum = all_test_m(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_NE_M:
				accum = any_test_m(df, fvalue_ne, arg1, arg2);
				break;

			case ANY_GT_M:
				accum = any_test_m(df, fvalue_gt, arg1, arg2);
				break;

			case ANY_GE_M:
				accum = any_test_m(df, fvalue_ge, arg1, arg2);
				break;

			case ANY_LT_M:
				accum = any_test_m(df, fvalue_lt, arg1, arg2);
				break;

			case ANY_LE_M:
				accum = any_test_m(df, fvalue_le, arg1, arg2);
				break;

			case ANY_BITWISE_AND_M:
				accum = any_test_m(df, fvalue_bitwise_and, arg1, arg2);
				break;

			case ANY_CONTAINS_M:
				accum = any_test_m(df, fvalue_contains, arg1, arg2);
				break;

			case ANY_MATCHES_M:
				accum = any_matches_m(df, arg1, arg2);
				break;

			case ANY_INSET2_M:
				accum = any_inset2_m(df, arg1, arg2, arg3);
				break;

			case NOT:
				accum = !accum;
				break;

			case RETURN:
				free_register_overhead(df);
				return accum;

			case IF_TRUE_GOTO:
				if (accum) {
					id = arg1;
					goto AGAIN;
				}
				break;

			case IF_FALSE_GOTO:
				if (!accum) {
					id = arg1;
					goto AGAIN;
				}
				break;

			default:
				ws_assert_not_reached();
				break;
		}
	}

	ws_assert_not_reached();
	return FALSE; /* to appease the compiler */
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
