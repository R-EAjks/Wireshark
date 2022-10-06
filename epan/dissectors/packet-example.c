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
#include <epan/conversation_filter.h>
#include <epan/reassemble.h>
#include <epan/conversation_table.h>
#include <epan/stats_tree.h>

static int proto_example = -1;

static gint ett_example = -1;
static gint ett_example_fragment = -1;
static gint ett_example_fragments = -1;

static struct expert_field ei_protocol_error = EI_INIT;
static struct expert_field ei_protocol_warning = EI_INIT;

static int hf_example_verify = -1;
static int hf_example_remote_length = -1;
static int hf_example_remote_name = -1;
static int hf_example_data_offset = -1;
static int hf_example_data_total = -1;
static int hf_example_data_fragment_id = -1;
static int hf_example_data_partlength = -1;
static int hf_example_data_message = -1;
static int hf_example_message_length = -1;
static int hf_example_message_data = -1;

static int hf_example_fragments = -1;
static int hf_example_fragment = -1;
static int hf_example_fragment_overlap = -1;
static int hf_example_fragment_overlap_conflicts = -1;
static int hf_example_fragment_multiple_tails = -1;
static int hf_example_fragment_too_long_fragment = -1;
static int hf_example_fragment_error = -1;
static int hf_example_fragment_count = -1;
static int hf_example_reassembled_in = -1;
static int hf_example_reassembled_length = -1;
static int hf_example_reassembled_data = -1;

static reassembly_table example_reassembly_table;

/* Preference variables */
static gboolean global_show_message   = TRUE;
static guint global_cut_at_n_length   = 40;

void proto_register_example(void);
void proto_reg_handoff_example(void);

static const true_false_string tfs_example_verify   = { "Verified", "Not Verified" };

typedef struct _example_packet_info
{
    gchar interface[3];
    guint msg_length;
    guint packet_type;
} example_packet_info;

static const value_string packettypenames[] = {

    /* SSDO abort codes */
    { 0x01, "Default Package" },
    { 0x02, "End Package" },
    { 0, NULL }
};

static int example_tap = -1;

static const fragment_items example_frag_items = {
    /* Fragment subtrees */
    &ett_example_fragment,
    &ett_example_fragments,
    /* Fragment fields */
    &hf_example_fragments,
    &hf_example_fragment,
    &hf_example_fragment_overlap,
    &hf_example_fragment_overlap_conflicts,
    &hf_example_fragment_multiple_tails,
    &hf_example_fragment_too_long_fragment,
    &hf_example_fragment_error,
    &hf_example_fragment_count,
    /* Reassembled in field */
    &hf_example_reassembled_in,
    /* Reassembled length field */
    &hf_example_reassembled_length,
    /* Reassembled data */
    &hf_example_reassembled_data,
    /* Tag */
    "Message fragments"
};

static gboolean
dissect_example(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_item * ti = NULL, *item = NULL;
    gint offset = 0;
    guint16 length = 0, real_length = 0, partlength = 0, dataOffset = 0, total = 0, fragmentId = 0;
    guint8 * textdata = NULL;
    guint8 rem_length = 0;
    gboolean show_expert = FALSE;
    example_packet_info * packet;
    fragment_head *frag_msg = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Example");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    packet = wmem_alloc0(pinfo->pool, sizeof(example_packet_info));

    ti = proto_tree_add_item(tree, proto_example, message_tvb, offset, -1, ENC_NA);
    proto_tree *example_tree = proto_item_add_subtree(ti, ett_example);

    length = tvb_get_guint8(message_tvb, offset);
    proto_tree_add_uint(example_tree, hf_example_remote_length, message_tvb, offset, 1, length);
    offset += 1;

    textdata = tvb_get_string_enc(wmem_packet_scope(), message_tvb, offset, length, ENC_BIG_ENDIAN);
    memcpy(packet->interface, textdata, 3);
    proto_tree_add_string(example_tree, hf_example_remote_name, message_tvb, offset, length, textdata);
    offset += length;

    dataOffset = tvb_get_guint8(message_tvb, offset);
    proto_tree_add_item(example_tree, hf_example_data_offset, message_tvb, offset, 1, ENC_NA);
    offset += 1;

    total = tvb_get_guint8(message_tvb, total);
    proto_tree_add_item(example_tree, hf_example_data_total, message_tvb, offset, 1, ENC_NA);
    offset += 1;

    fragmentId = tvb_get_guint8(message_tvb, offset);
    proto_tree_add_item(example_tree, hf_example_data_fragment_id, message_tvb, offset, 1, ENC_NA);
    offset += 1;

    partlength = tvb_get_guint8(message_tvb, offset);
    proto_tree_add_item(example_tree, hf_example_data_partlength, message_tvb, offset, 1, ENC_NA);
    offset += 1;

    packet->packet_type = dataOffset < total ? 0x01 : 0x02;

    /* fragment reassembly */
    pinfo->fragmented = TRUE;
    frag_msg = fragment_add_seq_check(&example_reassembly_table, message_tvb, offset, pinfo,
                                fragmentId, NULL,
                                dataOffset, partlength,
                                dataOffset < total ? TRUE : FALSE);

    if ( frag_msg != NULL )
    {
      process_reassembled_data(message_tvb, offset, pinfo, "Reassembled Message",
          frag_msg, &example_frag_items, NULL, example_tree );
    }

    offset += partlength;

    length = tvb_get_guint8(message_tvb, offset);
    packet->msg_length = length;
    proto_tree_add_item(example_tree, hf_example_message_length, message_tvb, offset, 1, length);
    offset += 1;

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

    tap_queue_packet(example_tap , pinfo, packet);

    return TRUE;
}

static const char* example_conv_get_filter_type(conv_item_t* conv _U_, conv_filter_type_e filter _U_)
{
    if (filter == CONV_FT_SRC_ADDRESS) {
      return "example.name";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t example_ct_dissector_info = {&example_conv_get_filter_type};

static const char* example_get_filter_type(hostlist_talker_t* host _U_, conv_filter_type_e filter _U_)
{
    if (filter == CONV_FT_ANY_ADDRESS)
      return "example.name";

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t example_dissector_info = {&example_get_filter_type};

static tap_packet_status
example_conversation_packet(void *pct, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    address *src = (address *)wmem_alloc0(pinfo->pool, sizeof(address));
    address *dst = (address *)wmem_alloc0(pinfo->pool, sizeof(address));
    conv_hash_t *hash = (conv_hash_t*) pct;
    const example_packet_info *exampleinfo = (const example_packet_info *)vip;

    hash->flags = flags;

    alloc_address_wmem(pinfo->pool, src, AT_STRINGZ, 3, &exampleinfo->interface);
    alloc_address_wmem(pinfo->pool, dst, AT_STRINGZ, 3, &exampleinfo->interface);

    add_conversation_table_data(hash, src, dst, 0, 0, 1, exampleinfo->msg_length, &pinfo->rel_ts, &pinfo->abs_ts,
            &example_ct_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static tap_packet_status
example_hostlist_packet(void *pit, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    address *src = (address *)wmem_alloc0(pinfo->pool, sizeof(address));
    conv_hash_t *hash = (conv_hash_t*) pit;
    const example_packet_info *exampleinfo = (const example_packet_info *)vip;

    hash->flags = flags;

    alloc_address_wmem(pinfo->pool, src, AT_STRINGZ, 3, &exampleinfo->interface);

    add_hostlist_table_data(hash, src, 0, TRUE,  1, exampleinfo->msg_length, &example_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static const guint8* st_str_packets = "Total Packets";
static const guint8* st_str_packet_types = "Example Packet Types";
static int st_node_packets = -1;
static int st_node_packet_types = -1;

static void example_stats_tree_init(stats_tree* st)
{
    st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, TRUE);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static tap_packet_status example_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
  example_packet_info *pi = (example_packet_info *)p;
  tick_stat_node(st, st_str_packets, 0, FALSE);
  stats_tree_tick_pivot(st, st_node_packet_types,
          val_to_str(pi->packet_type, packettypenames, "Unknown packet type (%d)"));

  return TAP_PACKET_REDRAW;
}


/* register all BACnet Ststistic trees */
static void
register_example_stat_trees(void)
{
    stats_tree_register("example", "example", "Extcap Example Stats", 0,
        example_stats_tree_packet, example_stats_tree_init, NULL);
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
            FT_UINT8,  BASE_DEC, NULL,  0x0, NULL, HFILL } },
        { &hf_example_remote_name,
          { "Remote Interface", "example.remote.name",
            FT_STRING,  BASE_NONE, NULL,  0x0, NULL, HFILL } },
        { &hf_example_data_offset,
          { "Data Part Offset", "example.data.offset",
            FT_UINT8,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_example_data_fragment_id,
          { "Data Fragment ID", "example.data.fragmentID",
            FT_UINT8,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_example_data_total,
          { "Data Total", "example.data.total",
            FT_UINT8,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_example_data_partlength,
          { "Data part length", "example.data.partlength",
            FT_UINT8,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_example_data_message,
          { "Data Message", "example.data.message",
            FT_UINT8,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_example_message_length,
          { "Message Length", "example.message.length",
            FT_UINT8,  BASE_HEX_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_example_message_data,
          { "Message Data", "example.message.data",
            FT_STRING,  BASE_NONE, NULL,    0x0, NULL, HFILL } },

        {&hf_example_fragments,
         {"Message fragments", "example.fragments",
          FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_example_fragment,
         {"Message fragment", "example.fragment",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_example_fragment_overlap,
         {"Message fragment overlap", "example.fragment.overlap",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_example_fragment_overlap_conflicts,
         {"Message fragment overlapping with conflicting data",
          "example.fragment.overlap.conflicts",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_example_fragment_multiple_tails,
         {"Message has multiple tail fragments", "example.fragment.multiple_tails",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_example_fragment_too_long_fragment,
         {"Message fragment too long", "example.fragment.too_long_fragment",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_example_fragment_error,
         {"Message defragmentation error", "example.fragment.error",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_example_fragment_count,
         {"Message fragment count", "example.fragment.count",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_example_reassembled_in,
         {"Reassembled in", "example.reassembled.in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_example_reassembled_length,
         {"Reassembled length", "example.reassembled.length",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_example_reassembled_data,
         {"Reassembled Data", "example.reassembled.data",
          FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_example,
        &ett_example_fragment,
        &ett_example_fragments,
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

    example_tap = register_tap("example");

    /* register user preferences */
    prefs_register_bool_preference(example_module, "show_message",
                 "Show message transmitted as data",
                 "Automatically show the transmitted message as data dissector packet",
                 &global_show_message);

    prefs_register_uint_preference(example_module, "cut_at_n_length",
                "Cut message after n byte",
                "Cut the message after n byte have been displayed", 10,
                &global_cut_at_n_length);

    register_conversation_table(proto_example, TRUE, example_conversation_packet, example_hostlist_packet);
}

void
proto_reg_handoff_example(void)
{
    static dissector_handle_t example_handle;

    /* Registering default dissector */
    example_handle = register_dissector("example", dissect_example, proto_example );

    /* IP Protocol registration */
    dissector_add_uint("ip.proto", 254, example_handle);

    reassembly_table_register(&example_reassembly_table, &addresses_reassembly_table_functions);
    register_example_stat_trees();
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
