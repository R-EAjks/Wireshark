/* packet-elsucopy.c
 *
 * TCP-based protocol between adaptor and L2 server.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include "config.h"

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/proto_data.h>

/* TODO: if python throws exception, error comes straight out over this socket, so if all of payload is ASCII, just show as text? */

void proto_register_elsucopy(void);

static int proto_elsucopy = -1;

/* Header */
static int hf_elsucopy_code = -1;
static int hf_elsucopy_len = -1;
static int hf_elsucopy_payload = -1;
static int hf_elsucopy_exception_text = -1;

/* Subtrees */
static gint ett_elsucopy = -1;
static gint ett_elsucopy_header = -1;

static dissector_handle_t elsucopy_handle;
static dissector_handle_t elsucopy_message_handle;

void proto_reg_handoff_elsucopy(void);


/* User definable values */
static range_t *global_elsucopy_port_range = NULL;

static const value_string code_vals[] = {
    { 1,          "String" },
    { 3,          "Adaptor Log Copy" },
    { 4,          "getreport archive name" },
    { 5,          "lsugetreport Copy" },
    { 9,          "Exit" },
    { 0,   NULL }
};




/* Bytes 4-7 have the PDU length in little-endian order */
static guint
get_elsucopy_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    //printf("%s()\n", __func__);

    // First, look to see if first 5 bytes of data are all printable - if yes, can assume exception has been thrown and
    // that this isn't really a protocol PDU.
    if (tvb_ascii_isprint(tvb, offset, 5)) {
        return tvb_reported_length(tvb);
    }
    else {
        // Assume that is is an actual protocol message.
        return 5 + (guint)tvb_get_guint32(tvb, offset + 1, ENC_LITTLE_ENDIAN);
    }
}

/* Dissect one PDU.  Guaranteed that the tvb is the right size */
static int
dissect_elsucopy_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    //printf("%s()\n", __func__);
    proto_tree *elsucopy_tree;
    proto_item *root_ti;
    gint offset = 0;

    /* Create a data source just for L2 payload.  This makes it easier to spot offsets inside message */
    /* TODO: there must be a more elegant way to do this? */
    tvbuff_t *elsu_tvb = tvb_new_child_real_data(tvb, tvb_get_ptr(tvb, 0, tvb_reported_length(tvb)),
                                               tvb_reported_length(tvb), tvb_reported_length(tvb));
    add_new_data_source(pinfo, elsu_tvb, "L2 Message");

    /* Protocol column */
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_INFO);

    /* Add divider if not first PDU in this frame */
    gboolean *already_set = (gboolean*)p_get_proto_data(wmem_file_scope(), pinfo, proto_elsucopy, 0);
    if (already_set && *already_set) {
         col_append_str(pinfo->cinfo, COL_PROTOCOL, "|");
         col_append_str(pinfo->cinfo, COL_INFO, "  ||  ");
    }

    col_append_str(pinfo->cinfo, COL_PROTOCOL, "elsucopy");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_elsucopy, elsu_tvb, offset, -1, ENC_NA);
    elsucopy_tree = proto_item_add_subtree(root_ti, ett_elsucopy);

    /* If first 5 bytes are printable, it is just exceptions being thrown, so show all as text. */
    if (tvb_ascii_isprint(tvb, offset, 5)) {
        proto_tree_add_item(elsucopy_tree, hf_elsucopy_exception_text, tvb, offset, -1, ENC_ASCII);
        // Write text to Info column
        col_add_lstr(pinfo->cinfo, COL_INFO,
                     "stdout: ",
                     tvb_format_text(wmem_packet_scope(), tvb, offset, tvb_captured_length(tvb)),
                     COL_ADD_LSTR_TERMINATOR);
        return tvb_reported_length(tvb);
    }


    /* Code */
    guint32 code;
    proto_tree_add_item_ret_uint(elsucopy_tree, hf_elsucopy_code, elsu_tvb, offset, 1, ENC_LITTLE_ENDIAN, &code);
    offset += 1;

    /* Len */
    guint32 len;
    proto_tree_add_item_ret_uint(elsucopy_tree, hf_elsucopy_len, elsu_tvb, offset, 4, ENC_LITTLE_ENDIAN, &len);
    offset += 4;

    /* Payload */
    proto_tree_add_item(elsucopy_tree, hf_elsucopy_payload, tvb, offset, len, ENC_NA);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Code=%u (%15s)  Len=%u", code, val_to_str_const(code, code_vals, "Unknown"), len);
    proto_item_append_text(root_ti, " (Code=%u (%s)  Len=%u)", code, val_to_str_const(code, code_vals, "Unknown"), len);

    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    col_set_fence(pinfo->cinfo, COL_INFO);

    /* Record that at least one PDU has already been seen in this frame */
    static gboolean true_value = TRUE;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_elsucopy, 0, &true_value);

    return offset+len;
}


/******************************/
/* Main dissection function.  */
static int
dissect_elsucopy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    //printf("%s()\n", __func__);

    /* Frame starts off with no PDUs seen */
    static gboolean false_value = FALSE;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_elsucopy, 0, &false_value);

    /* Find whole PDUs and send them to dissect_elsucopy_message() */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, /* desegment */
                     5, get_elsucopy_message_len,
                     dissect_elsucopy_message, data);
    return tvb_reported_length(tvb);
}


void
proto_register_elsucopy(void)
{
    static hf_register_info hf[] = {
      { &hf_elsucopy_code,
        { "Code", "elsucopy.code", FT_UINT8, BASE_DEC,
          VALS(code_vals), 0x0, NULL, HFILL }},
      { &hf_elsucopy_len,
        { "Len", "elsucopy.len", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_elsucopy_payload,
        { "Payload", "elsucopy.payload", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_elsucopy_exception_text,
        { "Stdout output", "elsucopy.stdout-output", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_elsucopy,
        &ett_elsucopy_header
     };


    proto_elsucopy = proto_register_protocol("elsucopy", "elsucopy", "elsucopy");
    proto_register_field_array(proto_elsucopy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    elsucopy_message_handle = register_dissector("elsucopy-message", dissect_elsucopy_message, proto_elsucopy);
    elsucopy_handle = register_dissector("elsucopy", dissect_elsucopy, proto_elsucopy);

    /* Preferences */
}

static void
apply_elsucopy_prefs(void)
{
    global_elsucopy_port_range = prefs_get_range_value("elsucopy", "tcp.port");
}

void
proto_reg_handoff_elsucopy(void)
{
    dissector_add_uint_range_with_preference("tcp.port", "1080", elsucopy_handle);
    apply_elsucopy_prefs();
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
