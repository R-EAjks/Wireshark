/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFVM_H
#define DFVM_H

#include <wsutil/regex.h>
#include <epan/proto.h>
#include "dfilter-int.h"
#include "syntax-tree.h"
#include "drange.h"
#include "dfunctions.h"

typedef enum {
	EMPTY,
	FVALUE,
	HFINFO,
	INSN_NUMBER,
	REGISTER,
	INTEGER,
	DRANGE,
	FUNCTION_DEF,
	PCRE,
	MEMADDR,
} dfvm_value_type_t;

typedef struct {
	dfvm_value_type_t	type;

	union {
		fvalue_t		*fvalue;
		guint32			numeric;
		drange_t		*drange;
		header_field_info	*hfinfo;
		df_func_def_t		*funcdef;
		ws_regex_t		*pcre;
	} value;

} dfvm_value_t;


/* The M op codes use memory addressing. The order must be preserved.
 * They *must* appear right after the normal register op. */
typedef enum {
	IF_TRUE_GOTO,
	IF_FALSE_GOTO,
	CHECK_EXISTS,
	NOT,
	RETURN,
	READ_TREE,
	CALL_FUNCTION,
	MK_RANGE,
	ALL_EQ,
	ALL_EQ_M,
	ANY_EQ,
	ANY_EQ_M,
	ALL_NE,
	ALL_NE_M,
	ANY_NE,
	ANY_NE_M,
	ANY_GT,
	ANY_GT_M,
	ANY_GE,
	ANY_GE_M,
	ANY_LT,
	ANY_LT_M,
	ANY_LE,
	ANY_LE_M,
	ANY_BITWISE_AND,
	ANY_BITWISE_AND_M,
	ANY_CONTAINS,
	ANY_CONTAINS_M,
	ANY_MATCHES_M,
	ANY_INSET2_M,
} dfvm_opcode_t;

typedef struct {
	int		id;
	dfvm_opcode_t	op;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3;
	dfvm_value_t	*arg4;
} dfvm_insn_t;

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op);

void
dfvm_insn_free(dfvm_insn_t *insn);

dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type);

void
dfvm_value_free(dfvm_value_t *v);

void
dfvm_dump(FILE *f, dfilter_t *df);

gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree);

#endif
