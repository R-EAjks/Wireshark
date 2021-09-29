/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ftypes/ftypes.h"
#include "ftypes/ftypes-int.h"
#include "syntax-tree.h"

/*
 * Tries to convert an STTYPE_UNPARSED to a STTYPE_FIELD. STTYPE_UNPARSED is
 * usually a protocol field but the syntax allows it to be also a string or array,
 * depending on context (this is more flexible - some would say ambiguous - but it
 * can be confusing). For example one immediate consequence is that the semantic
 * meaning of a filter expression can change during execution of the program if
 * a protocol is registered (for example by dynamically loading a dissector plugin).
 */
sttype_id_t
stnode_field_from_unparsed(stnode_t *node)
{
	sttype_id_t type;
	const char *name;
	header_field_info *hfinfo;

	type = stnode_type_id(node);
	if (type != STTYPE_UNPARSED)
		return type;

	name = (const char *)stnode_data(node);

	hfinfo = proto_registrar_get_byname(name);
	if (hfinfo) {
		/* It's a field name */
		stnode_replace(node, STTYPE_FIELD, hfinfo);
		return STTYPE_FIELD;
	}

	hfinfo = proto_registrar_get_byalias(name);
	if (hfinfo) {
		/* It's an aliased field name */
		stnode_replace(node, STTYPE_FIELD, hfinfo);
		return STTYPE_FIELD;
	}

	return type;
}

static void
fvalue_free(gpointer value)
{
	fvalue_t *fvalue = (fvalue_t*)value;

	/* If the data was not claimed with stnode_steal_data(), free it. */
	if (fvalue) {
		FVALUE_FREE(fvalue);
	}
}

static void
pcre_free(gpointer value)
{
	GRegex	*pcre = (GRegex*)value;

	/* If the data was not claimed with stnode_steal_data(), free it. */
	if (pcre) {
		/*
		 * They're reference-counted, so just drop the reference
		 * count; it'll get freed when the reference count drops
		 * to 0.
		 */
		g_regex_unref(pcre);
	}
}

void
sttype_register_pointer(void)
{
	static sttype_t field_type = {
		STTYPE_FIELD,
		"FIELD",
		NULL,
		NULL,
		NULL
	};
	static sttype_t fvalue_type = {
		STTYPE_FVALUE,
		"FVALUE",
		NULL,
		fvalue_free,
		NULL
	};
	static sttype_t pcre_type = {
		STTYPE_PCRE,
		"PCRE",
		NULL,
		pcre_free,
		NULL
	};

	sttype_register(&field_type);
	sttype_register(&fvalue_type);
	sttype_register(&pcre_type);
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
