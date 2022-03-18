/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "dfilter-int.h"
#include "gencode.h"
#include "dfvm.h"
#include "syntax-tree.h"
#include "sttype-range.h"
#include "sttype-test.h"
#include "sttype-set.h"
#include "sttype-function.h"
#include "ftypes/ftypes.h"
#include <wsutil/ws_assert.h>

static void
fixup_jumps(gpointer data, gpointer user_data);

static void
gencode(dfwork_t *dfw, stnode_t *st_node);

static int
gen_entity(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr);

static void
dfw_append_insn(dfwork_t *dfw, dfvm_insn_t *insn)
{
	insn->id = dfw->next_insn_id;
	dfw->next_insn_id++;
	g_ptr_array_add(dfw->insns, insn);
}

/* returns memory address */
static int
dfw_append_const(dfwork_t *dfw, dfvm_value_t *val)
{
	g_ptr_array_add(dfw->constants, val);
	return dfw->constants->len - 1; // 0 based index
}

static int
dfw_append_const_hfinfo(dfwork_t *dfw, header_field_info *hfinfo)
{
	dfvm_value_t *val = dfvm_value_new(HFINFO);
	val->value.hfinfo = hfinfo;
	return dfw_append_const(dfw, val);
}

/* returns register number */
static int
dfw_append_read_tree(dfwork_t *dfw, header_field_info *hfinfo)
{
	dfvm_insn_t	*insn;
	int		reg = -1;
	gboolean	added_new_hfinfo = FALSE;

	/* Rewind to find the first field of this name. */
	while (hfinfo->same_name_prev_id != -1) {
		hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
	}

	/* Keep track of which registers
	 * were used for which hfinfo's so that we
	 * can re-use registers. */
	reg = GPOINTER_TO_INT(
			g_hash_table_lookup(dfw->loaded_fields, hfinfo));
	if (reg) {
		/* Reg's are stored in has as reg+1, so
		 * that the non-existence of a hfinfo in
		 * the hash, or 0, can be differentiated from
		 * a hfinfo being loaded into register #0. */
		reg--;
	}
	else {
		reg = dfw->next_register++;
		g_hash_table_insert(dfw->loaded_fields,
			hfinfo, GINT_TO_POINTER(reg + 1));

		added_new_hfinfo = TRUE;
	}

	insn = dfvm_insn_new(READ_TREE);
	insn->arg1 = dfw_append_const_hfinfo(dfw, hfinfo);
	insn->arg2 = reg;
	dfw_append_insn(dfw, insn);

	if (added_new_hfinfo) {
		while (hfinfo) {
			/* Record the FIELD_ID in hash of interesting fields. */
			g_hash_table_insert(dfw->interesting_fields,
			    GINT_TO_POINTER(hfinfo->id),
			    GUINT_TO_POINTER(TRUE));
			hfinfo = hfinfo->same_name_next;
		}
	}

	return reg;
}

/* returns memory address */
static int
dfw_append_const_fvalue(dfwork_t *dfw, fvalue_t *fv)
{
	dfvm_value_t *val = dfvm_value_new(FVALUE);
	val->value.fvalue = fv;
	return dfw_append_const(dfw, val);
}

/* returns memory address */
static int
dfw_append_const_drange(dfwork_t *dfw, drange_t *dr)
{
	dfvm_value_t *val = dfvm_value_new(DRANGE);
	val->value.drange = dr;
	return dfw_append_const(dfw, val);
}

/* returns memory address */
static int
dfw_append_const_funcdef(dfwork_t *dfw, df_func_def_t *fd)
{
	dfvm_value_t *val = dfvm_value_new(FUNCDEF);
	val->value.funcdef = fd;
	return dfw_append_const(dfw, val);
}

/* returns register number */
static int
dfw_append_mk_range(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	int			hf_reg, reg, addr;
	stnode_t                *entity;
	dfvm_insn_t		*insn;
	drange_t		*drange;

	entity = sttype_range_entity(node);

	/* XXX, check if p_jmp logic is OK */
	hf_reg = gen_entity(dfw, entity, jumps_ptr);

	insn = dfvm_insn_new(MK_RANGE);
	insn->arg1 = hf_reg;
	reg = dfw->next_register++;
	insn->arg2 = reg;
	drange = sttype_range_drange_steal(node);
	addr = dfw_append_const_drange(dfw, drange);
	insn->arg3 = addr;
	dfw_append_insn(dfw, insn);

	return reg;
}

/* returns register number that the functions's result will be in. */
static int
dfw_append_mk_function(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	GSList *params;
	int reg;
	GSList *param_jumps = NULL;
	dfvm_insn_t	*insn;
	int		addr, p1, p2;

	/* Create the new DFVM instruction */
	insn = dfvm_insn_new(CALL_FUNCTION);
	addr = dfw_append_const_funcdef(dfw, sttype_function_funcdef(node));
	insn->arg1 = addr;
	reg = dfw->next_register++;
	insn->arg2 = reg;
	insn->arg3 = -1;
	insn->arg4 = -1;
	params = sttype_function_params(node);
	if (params) {
		p1 = gen_entity(dfw, params->data, &param_jumps);
		insn->arg3 = p1;
		params = params->next;
	}
	if (params) {
		p2 = gen_entity(dfw, params->data, &param_jumps);
		insn->arg4 = p2;
	}
	dfw_append_insn(dfw, insn);

	/* If any of our parameters failed, send them to
	 * our own failure instruction. This *has* to be done
	 * after we caled dfw_append_insn above so that
	 * we know what the next DFVM insruction is, via
	 * dfw->next_insn_id */
	g_slist_foreach(param_jumps, fixup_jumps, dfw);
	g_slist_free(param_jumps);
	param_jumps = NULL;

	/* We need another instruction to jump to another exit
	 * place, if the call() of our function failed for some reaosn */
	insn = dfvm_insn_new(IF_FALSE_GOTO);
	dfw_append_insn(dfw, insn);
	*jumps_ptr = g_slist_prepend(*jumps_ptr, &insn->arg1);

	return reg;
}

/* returns memory address */
static int
dfw_append_const_pcre(dfwork_t *dfw, ws_regex_t *pcre)
{
	dfvm_value_t *val = dfvm_value_new(PCRE);
	val->value.pcre = pcre;
	return dfw_append_const(dfw, val);
}

/* returns register number */
static int
dfw_append_mk_field(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr)
{
	dfvm_insn_t *insn;
	header_field_info *hfinfo;
	int reg;

	hfinfo = stnode_data(st_arg);
	reg = dfw_append_read_tree(dfw, hfinfo);
	insn = dfvm_insn_new(IF_FALSE_GOTO);
	dfw_append_insn(dfw, insn);
	*jumps_ptr = g_slist_prepend(*jumps_ptr, &insn->arg1);
	return reg;
}

/**
 * Adds an instruction for a relation operator where the values are already
 * loaded in registers.
 */
static void
gen_relation_vals(dfwork_t *dfw, dfvm_opcode_t op, int val1, int val2)
{
	dfvm_insn_t	*insn;

	insn = dfvm_insn_new(op);
	insn->arg1 = val1;
	insn->arg2 = val2;
	dfw_append_insn(dfw, insn);
}

static void
gen_relation(dfwork_t *dfw, dfvm_opcode_t op, stnode_t *st_arg1, stnode_t *st_arg2)
{
	GSList		*jumps = NULL;
	int		reg1 = -1, reg2 = -1;
	int		addr = -1;

	reg1 = gen_entity(dfw, st_arg1, &jumps);

	if (stnode_type_id(st_arg2) == STTYPE_FVALUE ||
		stnode_type_id(st_arg2) == STTYPE_PCRE) {
		/* Create code for the RHS of the relation */
		addr = gen_entity(dfw, st_arg2, &jumps);
		/* Then combine them in a DFVM insruction */
		gen_relation_vals(dfw, op + 1, reg1, addr);
	}
	else {
		/* Create code for the RHS of the relation */
		reg2 = gen_entity(dfw, st_arg2, &jumps);
		/* Then combine them in a DFVM insruction */
		gen_relation_vals(dfw, op, reg1, reg2);
	}

	/* If either of the relation arguments need an "exit" instruction
	 * to jump to (on failure), mark them */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	jumps = NULL;
}

static void
fixup_jumps(gpointer data, gpointer user_data)
{
	int *jmp = data;
	dfwork_t *dfw = user_data;

	if (jmp) {
		*jmp = dfw->next_insn_id;
	}
}

static void
gen_relation_matches(dfwork_t *dfw, stnode_t *st_arg1, stnode_t *st_arg2)
{
	GSList		*jumps = NULL;
	int		reg1 = -1, addr = -1;

	reg1 = gen_entity(dfw, st_arg1, &jumps);

	/* Create code for the RHS of the relation */
	ws_assert(stnode_type_id(st_arg2) == STTYPE_PCRE);
	addr = gen_entity(dfw, st_arg2, &jumps);
	/* Then combine them in a DFVM insruction */
	gen_relation_vals(dfw, ANY_MATCHES_M, reg1, addr);

	/* If either of the relation arguments need an "exit" instruction
	 * to jump to (on failure), mark them */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	jumps = NULL;
}

/* Generate the code for the in operator.  It behaves much like an OR-ed
 * series of == tests, but without the redundant existence checks. */
static void
gen_relation_in(dfwork_t *dfw, stnode_t *st_arg1, stnode_t *st_arg2)
{
	dfvm_insn_t	*insn;
	GSList		*jumps = NULL;
	GSList		*node_jumps = NULL;
	int		reg1;
	stnode_t	*node1, *node2;
	GSList		*nodelist_head, *nodelist;

	/* Create code for the LHS of the relation */
	reg1 = gen_entity(dfw, st_arg1, &jumps);

	/* Create code for the set on the RHS of the relation */
	nodelist_head = nodelist = (GSList*)stnode_steal_data(st_arg2);
	while (nodelist) {
		node1 = (stnode_t*)nodelist->data;
		nodelist = g_slist_next(nodelist);
		node2 = (stnode_t*)nodelist->data;
		nodelist = g_slist_next(nodelist);

		if (node2) {
			int	addr1, addr2;

			/* Range element: add lower/upper bound test. */
			// XXX: Assert we have an address and not a register
			addr1 = gen_entity(dfw, node1, &node_jumps);
			addr2 = gen_entity(dfw, node2, &node_jumps);

			/* Add test to see if the item is in range. */
			insn = dfvm_insn_new(ANY_INSET2_M);
			insn->arg1 = reg1;
			insn->arg2 = addr1;
			insn->arg3 = addr2;
			dfw_append_insn(dfw, insn);
		} else {
			int	addr1;

			/* Normal element: add equality test. */
			// XXX: Assert we have an address and not a register
			addr1 = gen_entity(dfw, node1, &node_jumps);

			/* Add test to see if the item matches */
			gen_relation_vals(dfw, ANY_EQ_M, reg1, addr1);
		}

		/* Exit as soon as we find a match */
		if (nodelist) {
			insn = dfvm_insn_new(IF_TRUE_GOTO);
			dfw_append_insn(dfw, insn);
			jumps = g_slist_prepend(jumps, &insn->arg1);
		}

		/* If an item is not present, just jump to the next item */
		g_slist_foreach(node_jumps, fixup_jumps, dfw);
		g_slist_free(node_jumps);
		node_jumps = NULL;
	}

	/* Jump here if the LHS entity was not present */
	/* Jump here if any of the items in the set matched */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	jumps = NULL;

	set_nodelist_free(nodelist_head);
}

/* Parse an entity, returning the reg that it gets put into.
 * p_jmp will be set if it has to be set by the calling code; it should
 * be set to the place to jump to, to return to the calling code,
 * if the load of a field from the proto_tree fails. */
static int
gen_entity(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr)
{
	sttype_id_t e_type = stnode_type_id(st_arg);

	if (e_type == STTYPE_FIELD) {
		return dfw_append_mk_field(dfw, st_arg, jumps_ptr);
	}
	else if (e_type == STTYPE_FVALUE) {
		return dfw_append_const_fvalue(dfw, stnode_steal_data(st_arg));
	}
	else if (e_type == STTYPE_RANGE) {
		return dfw_append_mk_range(dfw, st_arg, jumps_ptr);
	}
	else if (e_type == STTYPE_FUNCTION) {
		return dfw_append_mk_function(dfw, st_arg, jumps_ptr);
	}
	else if (e_type == STTYPE_PCRE) {
		return dfw_append_const_pcre(dfw, stnode_steal_data(st_arg));
	}
	ws_assert_not_reached();
}


static void
gen_test(dfwork_t *dfw, stnode_t *st_node)
{
	test_op_t	st_op;
	stnode_t	*st_arg1, *st_arg2;
	dfvm_insn_t	*insn;

	header_field_info	*hfinfo;

	sttype_test_get(st_node, &st_op, &st_arg1, &st_arg2);

	switch (st_op) {
		case TEST_OP_UNINITIALIZED:
			ws_assert_not_reached();
			break;

		case TEST_OP_EXISTS:
			hfinfo = stnode_data(st_arg1);

			/* Rewind to find the first field of this name. */
			while (hfinfo->same_name_prev_id != -1) {
				hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
			}
			insn = dfvm_insn_new(CHECK_EXISTS);
			insn->arg1 = dfw_append_const_hfinfo(dfw, hfinfo);
			dfw_append_insn(dfw, insn);

			/* Record the FIELD_ID in hash of interesting fields. */
			while (hfinfo) {
				g_hash_table_insert(dfw->interesting_fields,
					GINT_TO_POINTER(hfinfo->id),
					GUINT_TO_POINTER(TRUE));
				hfinfo = hfinfo->same_name_next;
			}

			break;

		case TEST_OP_NOT:
			gencode(dfw, st_arg1);
			insn = dfvm_insn_new(NOT);
			dfw_append_insn(dfw, insn);
			break;

		case TEST_OP_AND:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(IF_FALSE_GOTO);
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			insn->arg1 = dfw->next_insn_id;
			break;

		case TEST_OP_OR:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(IF_TRUE_GOTO);
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			insn->arg1 = dfw->next_insn_id;
			break;

		case TEST_OP_ALL_EQ:
			gen_relation(dfw, ALL_EQ, st_arg1, st_arg2);
			break;

		case TEST_OP_ANY_EQ:
			gen_relation(dfw, ANY_EQ, st_arg1, st_arg2);
			break;

		case TEST_OP_ALL_NE:
			gen_relation(dfw, ALL_NE, st_arg1, st_arg2);
			break;

		case TEST_OP_ANY_NE:
			gen_relation(dfw, ANY_NE, st_arg1, st_arg2);
			break;

		case TEST_OP_GT:
			gen_relation(dfw, ANY_GT, st_arg1, st_arg2);
			break;

		case TEST_OP_GE:
			gen_relation(dfw, ANY_GE, st_arg1, st_arg2);
			break;

		case TEST_OP_LT:
			gen_relation(dfw, ANY_LT, st_arg1, st_arg2);
			break;

		case TEST_OP_LE:
			gen_relation(dfw, ANY_LE, st_arg1, st_arg2);
			break;

		case TEST_OP_BITWISE_AND:
			gen_relation(dfw, ANY_BITWISE_AND, st_arg1, st_arg2);
			break;

		case TEST_OP_CONTAINS:
			gen_relation(dfw, ANY_CONTAINS, st_arg1, st_arg2);
			break;

		case TEST_OP_MATCHES:
			gen_relation_matches(dfw, st_arg1, st_arg2);
			break;

		case TEST_OP_IN:
			gen_relation_in(dfw, st_arg1, st_arg2);
			break;
	}
}

static void
gencode(dfwork_t *dfw, stnode_t *st_node)
{
	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			gen_test(dfw, st_node);
			break;
		default:
			ws_assert_not_reached();
	}
}


void
dfw_gencode(dfwork_t *dfw)
{
	int		id, id1, length;
	dfvm_insn_t	*insn, *insn1, *prev;
	int		arg1;

	dfw->insns = g_ptr_array_new();
	dfw->constants = g_ptr_array_new();
	dfw->loaded_fields = g_hash_table_new(g_direct_hash, g_direct_equal);
	dfw->interesting_fields = g_hash_table_new(g_direct_hash, g_direct_equal);
	gencode(dfw, dfw->st_root);
	dfw_append_insn(dfw, dfvm_insn_new(RETURN));

	/* fixup goto */
	length = dfw->insns->len;

	for (id = 0, prev = NULL; id < length; prev = insn, id++) {
		insn = g_ptr_array_index(dfw->insns, id);
		arg1 = insn->arg1;
		if (insn->op == IF_TRUE_GOTO || insn->op == IF_FALSE_GOTO) {
			dfvm_opcode_t revert = (insn->op == IF_FALSE_GOTO) ? IF_TRUE_GOTO : IF_FALSE_GOTO;
			id1 = arg1;
			do {
				insn1 = g_ptr_array_index(dfw->insns, id1);
				if (insn1->op == revert) {
					/* this one is always false and the branch is not taken*/
					id1 = id1 +1;
					continue;
				}
				else if (insn1->op == READ_TREE && prev && prev->op == READ_TREE &&
						prev->arg2 == insn1->arg2) {
					/* hack if it's the same register it's the same field
					 * and it returns the same value
					 */
					id1 = id1 +1;
					continue;
				}
				else if (insn1->op != insn->op) {
					/* bail out */
					arg1 = insn->arg1;
					insn->arg1 = id1;
					break;
				}
				arg1 = insn1->arg1;
				id1 = arg1;
			} while (1);
		}
	}
}



typedef struct {
	int i;
	int *fields;
} hash_key_iterator;

static void
get_hash_key(gpointer key, gpointer value _U_, gpointer user_data)
{
	int field_id = GPOINTER_TO_INT(key);
	hash_key_iterator *hki = (hash_key_iterator *)user_data;

	hki->fields[hki->i] = field_id;
	hki->i++;
}

int*
dfw_interesting_fields(dfwork_t *dfw, int *caller_num_fields)
{
	int num_fields = g_hash_table_size(dfw->interesting_fields);

	hash_key_iterator hki;

	if (num_fields == 0) {
		*caller_num_fields = 0;
		return NULL;
	}

	hki.fields = g_new(int, num_fields);
	hki.i = 0;

	g_hash_table_foreach(dfw->interesting_fields, get_hash_key, &hki);
	*caller_num_fields = num_fields;
	return hki.fields;
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
