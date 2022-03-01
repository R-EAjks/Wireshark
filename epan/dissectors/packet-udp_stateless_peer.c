/* packet-udp_stateless_peer.c
 *
 * Routines for udp_stateless_peer packet dissection (UDP-based reliable communication protocol).
 * Described in the Open Base Station Initiative Reference Point 1 Specification
 * (see https://web.archive.org/web/20171206005927/http://www.obsai.com/specs/RP1%20Spec%20v2_1.pdf, Appendix A)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>

void proto_register_udp_stateless_peer(void);

static int proto_udp_stateless_peer = -1;

static int hf_udp_stateless_peer_ixiastream = -1;
static int hf_udp_stateless_peer_streamno = -1;
static int hf_udp_stateless_peer_seqno = -1;
static int hf_udp_stateless_peer_timestamp = -1;


/* Subtrees */
static gint ett_udp_stateless_peer = -1;


static dissector_handle_t udp_stateless_peer_handle;


void proto_reg_handoff_udp_stateless_peer (void);

/* User definable values */
static range_t *global_udp_stateless_peer_port_range = NULL;



/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/


/******************************/
/* Main dissection function.  */
static int
dissect_udp_stateless_peer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *udp_stateless_peer_tree;
    proto_item *root_ti;
    gint offset = 0;

    /* Must be at least 16 bytes (+ "ixiastream" for trigger) */
    if (tvb_captured_length(tvb) < 16) {
        return 0;
    }


    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_udp_stateless_peer, tvb, offset, -1, ENC_NA);
    udp_stateless_peer_tree = proto_item_add_subtree(root_ti, ett_udp_stateless_peer);

    gint length = tvb_captured_length(tvb);


    /* Look for "ixiastream" */
    gboolean trigger = FALSE;
    gint ixiastream_len = 0;
    const char *ixiastream = tvb_get_const_stringz(tvb, length-26, &ixiastream_len);
    if (strcmp(ixiastream, "ixiastream") == 0) {
        proto_tree_add_item(udp_stateless_peer_tree,
                            hf_udp_stateless_peer_ixiastream,
                            tvb,
                            length-26, 10, ENC_ASCII|ENC_NA);
        trigger = TRUE;
    }

    /* Streamno */
    guint32 streamno;
    proto_tree_add_item_ret_uint(udp_stateless_peer_tree,
                                 hf_udp_stateless_peer_streamno, tvb, length-16, 4, ENC_BIG_ENDIAN, &streamno);
    offset += 4;

    /* Seqno */
    guint32 seqno;
    proto_tree_add_item_ret_uint(udp_stateless_peer_tree,
                                 hf_udp_stateless_peer_seqno, tvb, length-12, 4, ENC_BIG_ENDIAN, &seqno);
    offset += 4;

    /* Timestamp */
    guint64 ts;
    proto_tree_add_item_ret_uint64(udp_stateless_peer_tree,
                                   hf_udp_stateless_peer_timestamp, tvb, length-8, 8, ENC_BIG_ENDIAN, &ts);
    offset += 4;

    /* Add summary to Info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, "stream=%u, seq=%u", streamno, seqno);
    if (trigger) {
        col_append_str(pinfo->cinfo, COL_INFO, " (Trigger)");
    }

    return offset;
}


void
proto_register_udp_stateless_peer(void)
{
  static hf_register_info hf[] = {
    { &hf_udp_stateless_peer_ixiastream,
      { "Ixiastream", "udp_stateless_peer.ixiastream", FT_STRING, BASE_NONE,
        NULL, 0x0, "Seen only in trigger frames", HFILL }},
    { &hf_udp_stateless_peer_streamno,
      { "Streamno", "udp_stateless_peer.streamno", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Stream number", HFILL }},
    { &hf_udp_stateless_peer_seqno,
      { "Msg Type", "udp_stateless_peer.seqno", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_udp_stateless_peer_timestamp,
      { "Timestamp", "udp_stateless_peer.timestamp", FT_UINT64, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_udp_stateless_peer
    };


    //module_t *udp_stateless_peer_module;

    proto_udp_stateless_peer = proto_register_protocol("UDP Stateless Peer", "USP", "udp_stateless_peer");
    proto_register_field_array(proto_udp_stateless_peer, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    udp_stateless_peer_handle = register_dissector("USP", dissect_udp_stateless_peer, proto_udp_stateless_peer);


    /* Preferences */
    //udp_stateless_peer_module = prefs_register_protocol(proto_udp_stateless_peer, NULL);

}

static void
apply_udp_stateless_peer_prefs(void)
{
    global_udp_stateless_peer_port_range = prefs_get_range_value("udp_stateless_peer", "udp.port");
}

void
proto_reg_handoff_udp_stateless_peer(void)
{
    dissector_add_uint_range_with_preference("udp.port", "1", udp_stateless_peer_handle);
    apply_udp_stateless_peer_prefs();
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
