/* packet-textlogger.c
 *
 * A generic dissector to pick out logged text sent over TCP.
 * TCP port and offset into TCP payload are user preferences.
 * TODO: add an option to search bytes for start of continous text?
 * TODO: table so can have different text offset for each port?
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_textlogger(void);
void proto_reg_handoff_textlogger (void);

static int proto_textlogger = -1;
static int hf_textlogger_text = -1;

static gint ett_textlogger = -1;
static dissector_handle_t textlogger_handle;


/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

static range_t *global_textlogger_port_range = NULL;
guint global_textlogger_text_offset = 0;


/******************************/
/* Main dissection function.  */
static int
dissect_textlogger(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *textlogger_tree;
    proto_item *root_ti;
    gint offset = 0;

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TextLogger");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_textlogger, tvb, offset, -1, ENC_ASCII|ENC_NA);
    textlogger_tree = proto_item_add_subtree(root_ti, ett_textlogger);

    guint length = tvb_captured_length(tvb);

    /* Is there anything after offset? */
    if (length < global_textlogger_text_offset) {
        /* TODO: report expert info? */
        return 0;
    }
    offset = global_textlogger_text_offset;

    /* Assume rest is text, but if it ends with \r\n, lop them off */
    if (tvb_get_guint8(tvb, length-1) == '\n') {
        length -= 1;
    }
    if (tvb_get_guint8(tvb, length-1) == '\r') {
        length -= 1;
    }

    /* Text itself */
    proto_tree_add_item(textlogger_tree, hf_textlogger_text, tvb, offset, length-offset, ENC_UTF_8|ENC_NA);

    /* Also show in Info column */
    const char *str = (const char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset,
                                         length-offset, ENC_UTF_8|ENC_NA);
    col_set_str(pinfo->cinfo, COL_INFO, str);

    proto_item_append_text(root_ti, " (%s)", str);

    return length;
}


void
proto_register_textlogger(void)
{
  static hf_register_info hf[] = {
    { &hf_textlogger_text,
      { "Text", "textlogger.text", FT_STRING, BASE_NONE,
        NULL, 0x0, "Logged Text", HFILL }},
    };

    static gint *ett[] = {
        &ett_textlogger,
    };


    module_t *textlogger_module;

    proto_textlogger = proto_register_protocol("TextLogger", "TextLogger", "textlogger");
    proto_register_field_array(proto_textlogger, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    textlogger_handle = register_dissector("textlogger", dissect_textlogger, proto_textlogger);

    /* Preferences */
    textlogger_module = prefs_register_protocol(proto_textlogger, NULL);

    prefs_register_uint_preference(textlogger_module, "text_offset",
                                   "Text Offset",
                                   "",
                                   10, &global_textlogger_text_offset);
}

static void
apply_textlogger_prefs(void)
{
    global_textlogger_port_range = prefs_get_range_value("textlogger", "tcp.port");
}

void
proto_reg_handoff_textlogger(void)
{
    dissector_add_uint_range_with_preference("tcp.port", "", textlogger_handle);
    apply_textlogger_prefs();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
