/* packet-example.c
 *
 *   example is a dissector for the data information of extcap-example.py,
 *   the python script which demonstrates
 *
 * By Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

static int proto_example = -1;

static gint ett_example = -1;

static struct expert_field ei_protocol_error = EI_INIT;
static struct expert_field ei_protocol_warning = EI_INIT;

static int hf_example_verify = -1;
static int hf_example_remote_length = -1;
static int hf_example_remote_name = -1;
static int hf_example_message_length = -1;
static int hf_example_message_data = -1;

/* Preference variables */
static gboolean global_show_message   = TRUE;
static guint global_cut_at_n_length   = 40;

void proto_register_example(void);
void proto_reg_handoff_example(void);

static const true_false_string tfs_example_verify   = { "Verified", "Not Verified" };

static guint8
read_8bit_ascii(tvbuff_t *message_tvb, guint offset)
{
    guint8 val = 0;
    guint8 result = 0;

    val = tvb_get_guint8(message_tvb, offset);
    if ( val >= 0x30 && val <= 0x39 )
        result = val - 0x30;

    return result;
}

static guint16
read_16bit_ascii(tvbuff_t *message_tvb, guint offset)
{
    return ( read_8bit_ascii(message_tvb, offset) << 8 ) + read_8bit_ascii(message_tvb, offset + 1);
}

static gboolean
dissect_example(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_item * ti = NULL, *item = NULL;
    gint offset = 0;
    guint16 length = 0, real_length = 0;
    guint8 * textdata = NULL;
    guint8 rem_length = 0;
    gboolean show_expert = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Example");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    ti = proto_tree_add_item(tree, proto_example, message_tvb, offset, -1, ENC_NA);
    proto_tree *example_tree = proto_item_add_subtree(ti, ett_example);

    length = read_16bit_ascii(message_tvb, offset);
    proto_tree_add_uint(example_tree, hf_example_remote_length, message_tvb, offset, 2, length);
    offset += 2;

    textdata = tvb_get_string_enc(wmem_packet_scope(), message_tvb, offset, length, ENC_BIG_ENDIAN);
    proto_tree_add_string(example_tree, hf_example_remote_name, message_tvb, offset, length, textdata);
    offset += length;

    length = read_16bit_ascii(message_tvb, offset);
    proto_tree_add_item(example_tree, hf_example_message_length, message_tvb, offset, 2, length);
    offset += 2;

    rem_length = tvb_captured_length_remaining(message_tvb, offset);
    real_length = length;
    if ( length != rem_length )
    {
        real_length = rem_length > length ? length : rem_length - 1;
        show_expert = TRUE;
    }

    textdata = tvb_get_string_enc(wmem_packet_scope(), message_tvb, offset, real_length, ENC_BIG_ENDIAN);
    item = proto_tree_add_string(example_tree, hf_example_message_data, message_tvb, offset, real_length, textdata);
    offset += real_length;
    if (show_expert)
    {
        expert_add_info_format(pinfo, item, &ei_protocol_warning,
                "Calculation for payload length [%d] yielded result longer then remaining length [%d]",
                (guint) rem_length, (guint) real_length );
    }

    proto_tree_add_item(example_tree, hf_example_verify, message_tvb, offset, 1, ENC_BIG_ENDIAN);

    return TRUE;
}

void
proto_register_example(void)
{
    /* Setup list of header fields */
    static hf_register_info hf_example[] = {
        /* UDP transport specific fields */
        { &hf_example_verify,
          { "Verification", "example.verify",
            FT_BOOLEAN, 8, TFS(&tfs_example_verify),  0x01, NULL, HFILL } },
        { &hf_example_remote_length,
          { "Remote Interface Name Length", "example.remote.length",
            FT_UINT16,  BASE_DEC, NULL,  0x0, NULL, HFILL } },
        { &hf_example_remote_name,
          { "Remote Interface", "example.remote.name",
            FT_STRING,  STR_UNICODE, NULL,  0x0, NULL, HFILL } },
        { &hf_example_message_length,
          { "Message Length", "example.message.length",
            FT_UINT16,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_example_message_data,
          { "Message Data", "example.message.data",
            FT_STRING,  STR_UNICODE, NULL,    0x0, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_example,
        #if 0
        &ett_example_message,
        #endif
    };

    static ei_register_info ei[] = {
        { &ei_protocol_error,
          { "example.error.protocol", PI_PROTOCOL, PI_ERROR,
            "There has been an error in the protocol implementation", EXPFILL } },
        { &ei_protocol_warning,
          { "example.warning.protocol", PI_PROTOCOL, PI_WARN,
            "There has been a warning for the protocol implementation", EXPFILL } },
    };

    module_t *example_module;
    expert_module_t *expert_example;

    /* Register the protocol name and description */
    proto_example = proto_register_protocol("Example dissector implementation", "Example",  "example");
    example_module = prefs_register_protocol(proto_example, NULL);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_example, hf_example, array_length(hf_example));
    proto_register_subtree_array(ett, array_length(ett));

    expert_example = expert_register_protocol ( proto_example );
    expert_register_field_array ( expert_example, ei, array_length (ei ) );

    /* register user preferences */
    prefs_register_bool_preference(example_module, "show_message",
                 "Show message transmitted as data",
                 "Automatically show the transmitted message as data dissector packet",
                 &global_show_message);

    prefs_register_uint_preference(example_module, "cut_at_n_length",
                "Cut message after n byte",
                "Cut the message after n byte have been displayed", 10,
                &global_cut_at_n_length);

}

void
proto_reg_handoff_example(void)
{
    static dissector_handle_t example_handle;

    /* Registering default dissector */
    example_handle = register_dissector("example", dissect_example, proto_example );

    /* IP Protocol registration */
    dissector_add_uint("ip.proto", 254, example_handle);

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
