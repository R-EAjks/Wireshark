/* packet-rcp.c
 * Routines for decoding Microsoft Cluster Heartbeat Route Control Protocol (RCP)
 * Copyright 2022, Will Aftring <william.aftring@outlook.com>
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * 
*/


#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>


#define RCP_PORT 3343
#define RCP_REQUEST 0
#define RCP_RESPONSE 1



static const value_string packettypenames[] = {
    { 0, "REQUEST" },
    { 1, "RESPONSE" }
};

static const value_string headertypenames[] = {
    {0, "RCP EXTENSION NONE",},
    {1, "RCP IPv4 Pair"},
    {2, "RCP IPv6 Pair"},
    {3, "RCP Signature"},
    {4, "RCP Maximum"}
};

typedef struct _rcp_conv_info_t {
    wmem_tree_t* pdus;
} rcp_conv_info_t;

typedef struct _rcp_transaction_t {
    guint32 req_frame;
    guint32 rep_frame;
    nstime_t req_time;
    guint32 seq;
    gboolean matched;
} rcp_transaction_t;

static int proto_rcp = -1;
static int hf_rcp_id = -1;
static int hf_rcp_type = -1;
static int hf_rcp_vers = -1;
static int hf_rcp_reserved = -1;
static int hf_rcp_next_header = -1;
static int hf_rcp_len = -1;
static int hf_rcp_seq = -1;
static int hf_rcp_response_in = -1;
static int hf_rcp_response_to = -1;
static int hf_rcp_ext_header = -1;
static int hf_rcp_ext_next_header = -1;
static int hf_rcp_ext_len = -1;
static int hf_rcp_ext_res = -1;
static int hf_rcp_ext_src_addr = -1;
static int hf_rcp_ext_dst_addr = -1;
static gint ett_rcp = -1;
static gint ett_rcp_nxt = -1;

static expert_field ei_rcp_no_resp = EI_INIT;
static guint32 retransmission_timer = 1;

// Handles for subparsing
static dissector_handle_t eth_handle;

static int
dissect_rcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{

    /*
        Rough Packet layout:
        Identifier:         4 bytes
        Version:            1 byte
        Reserved:           1 byte
        Type:               2 bytes
        NextHeader:         2 bytes
        Total Length:       2 bytes
        SeqNum:             4 bytes
        ExtHeader:          40 bytes
            NextHeader:     2 bytes
            Length:         2 bytes
            Reserved:       4 bytes
            SrcAddr:        16 bytes
            DstAddr:        16 bytes
    */
    guint tree_offset = 0;
    gint data_offset = 0;

    proto_tree* rcp_tree, * nxt_tree;
    proto_item* ti, * nxt_ti;
    tvbuff_t* next_tvb;
    guint32         seq;
    guint16         type;

    // variables for our expert analysis
    conversation_t* conv = NULL;
    rcp_conv_info_t* rcp_info = NULL;
    rcp_transaction_t* rcp_trans;
    wmem_tree_key_t  key[3];
    gboolean retransmission = FALSE;

    // NOTE: Doing this to make sure my byte math is right
    data_offset += 4;
    data_offset += 1;
    data_offset += 1;
    type = tvb_get_guint8(tvb, data_offset);
    data_offset += 2;
    data_offset += 2;
    data_offset += 2;
    seq = tvb_get_guint32(tvb, data_offset, ENC_LITTLE_ENDIAN);


    conv = find_or_create_conversation(pinfo);
    rcp_info = (rcp_conv_info_t*)conversation_get_proto_data(conv, proto_rcp);
    if (!rcp_info)
    {
        rcp_info = wmem_new(wmem_file_scope(), rcp_conv_info_t);
        rcp_info->pdus = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_rcp, rcp_info);
    }
    
    key[0].length = 1;
    key[0].key = &seq;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;
    key[2].key = NULL;
    if ((type == RCP_REQUEST) || (type == RCP_RESPONSE))
    {
        if (!pinfo->fd->visited)
        {
            if (type == RCP_REQUEST)
            {
                gboolean new_request = FALSE;
                rcp_trans = (rcp_transaction_t*)wmem_tree_lookup32_array_le(rcp_info->pdus, key);
                if ((rcp_trans == NULL) || (rcp_trans->seq != seq) || (rcp_trans->rep_frame > 0))
                {
                    new_request = TRUE;
                }
                else
                {
                    /* We don't retransmit but lets help out in case a packet passes through NDIS
                        more than once...*/
                    nstime_t request_delta;

                    nstime_delta(&request_delta, &pinfo->abs_ts, &rcp_trans->req_time);
                    if ((guint32)nstime_to_sec(&request_delta) < retransmission_timer)
                    {
                        retransmission = TRUE;
                    }
                    else
                    {
                        new_request = TRUE;
                    }
                }

                if (new_request)
                {
                    rcp_trans = wmem_new(wmem_file_scope(), rcp_transaction_t);
                    rcp_trans->req_frame = pinfo->num;
                    rcp_trans->rep_frame = 0;
                    rcp_trans->req_time = pinfo->abs_ts;
                    rcp_trans->seq = seq;
                    rcp_trans->matched = FALSE;
                    wmem_tree_insert32_array(rcp_info->pdus, key, (void*)rcp_trans);
                }
            }
            else
            {
                rcp_trans = (rcp_transaction_t*)wmem_tree_lookup32_array_le(rcp_info->pdus, key);
                if (rcp_trans)
                {
                    if (rcp_trans->seq != seq)
                    {
                        rcp_trans = NULL;
                    }
                    else if (rcp_trans->rep_frame == 0)
                    {
                        rcp_trans->rep_frame = pinfo->num;
                        rcp_trans->matched = TRUE;
                    }
                    else
                    {
                        retransmission = TRUE;
                    }
                }
            }
        }
        else
        {
            rcp_trans = (rcp_transaction_t*)wmem_tree_lookup32_array_le(rcp_info->pdus, key);
            if (rcp_trans)
            {
                if (rcp_trans->seq != seq)
                {
                    rcp_trans = NULL;
                }
                else if ((!(type == RCP_RESPONSE)) && (rcp_trans->req_frame != pinfo->num))
                {
                    rcp_transaction_t* retrans_rcp = wmem_new(wmem_packet_scope(), rcp_transaction_t);
                    retrans_rcp->req_frame = rcp_trans->req_frame;
                    retrans_rcp->rep_frame = 0;
                    retrans_rcp->req_time = pinfo->abs_ts;
                    rcp_trans = retrans_rcp;

                    retransmission = TRUE;
                }
                else if ((type == RCP_RESPONSE) && (rcp_trans->rep_frame != pinfo->num))
                {
                    retransmission = TRUE;
                }
            }
        }
        if (!rcp_trans)
        {
            rcp_trans = wmem_new(wmem_packet_scope(), rcp_transaction_t);
            rcp_trans->req_frame = 0;
            rcp_trans->rep_frame = 0;
            rcp_trans->req_time = pinfo->abs_ts;
            rcp_trans->matched = FALSE;
        }
    }


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RCP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ID %d (0x%X)",
        val_to_str(type, packettypenames, "TCP over RCP"), seq, seq);


    ti = proto_tree_add_item(tree, proto_rcp, tvb, 0, -1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, "Type %s",
        val_to_str(type, packettypenames, "TCP over RCP"));
    rcp_tree = proto_item_add_subtree(ti, ett_rcp);
    
    if (type == RCP_REQUEST || type == RCP_RESPONSE)
    {
        proto_item* it;
        proto_tree_add_item(rcp_tree, hf_rcp_id, tvb, 0, 4, ENC_BIG_ENDIAN);
        tree_offset += 4;
        proto_tree_add_item(rcp_tree, hf_rcp_vers, tvb, tree_offset, 1, ENC_LITTLE_ENDIAN);
        tree_offset += 1;
        proto_tree_add_item(rcp_tree, hf_rcp_reserved, tvb, tree_offset, 1, ENC_LITTLE_ENDIAN);
        tree_offset += 1;
        proto_tree_add_item(rcp_tree, hf_rcp_type, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(rcp_tree, hf_rcp_next_header, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(rcp_tree, hf_rcp_len, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        it = proto_tree_add_item(rcp_tree, hf_rcp_seq, tvb, tree_offset, 4, ENC_LITTLE_ENDIAN);
        tree_offset += 4;

        if (rcp_trans->matched)
        {
            if ((rcp_trans->req_frame) && (type == RCP_RESPONSE))
            {
                it = proto_tree_add_uint(rcp_tree, hf_rcp_response_to, tvb, 0, 0, rcp_trans->req_frame);
                proto_item_set_generated(it);

            }
            else if ((rcp_trans->rep_frame) && (type == RCP_REQUEST))
            {
                it = proto_tree_add_uint(rcp_tree, hf_rcp_response_in, tvb, 0, 0, rcp_trans->rep_frame);
                proto_item_set_generated(it);
            }
        }
        else
        {
            expert_add_info(pinfo, it, &ei_rcp_no_resp);
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Missing RCP Response]");
        }
        
        
        nxt_ti = proto_tree_add_item(rcp_tree, hf_rcp_ext_header, tvb, 0, 0, ENC_NA);
        nxt_tree = proto_item_add_subtree(nxt_ti, ett_rcp_nxt);
        proto_tree_add_item(nxt_tree, hf_rcp_ext_next_header, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(nxt_tree, hf_rcp_ext_len, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(nxt_tree, hf_rcp_ext_res, tvb, tree_offset, 4, ENC_LITTLE_ENDIAN);

    }
    else
    {
        next_tvb = tvb_new_subset_remaining(tvb, 0);
        call_dissector(eth_handle, next_tvb, pinfo, rcp_tree);
    }

    return tvb_captured_length(tvb);
}


void
proto_register_rcp(void)
{
    expert_module_t* expert_rcp;

    static hf_register_info hf[] = {
    { &hf_rcp_id,
    { "RCP ID", "rcp.id",
        FT_UINT32, BASE_DEC_HEX,
        NULL, 0x0,
        NULL, HFILL },
    },
    { &hf_rcp_vers,
        { "Version", "rcp.vers",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_reserved,
        { "Reserved", "rcp.reserved",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
    },
    { &hf_rcp_type,
        { "RCP Type", "rcp.type",
        FT_UINT16, BASE_DEC,
        VALS(packettypenames), 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_next_header,
        { "Next Header", "rcp.nxt_header",
        FT_UINT16, BASE_DEC,
        VALS(headertypenames), 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_len,
        {"Total Length", "rcp.len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_seq,
        { "Sequence Number", "rcp.seq",
        FT_UINT32, BASE_DEC_HEX,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_response_in,
        { "Response In", "rcp.response_in",
           FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
           "The response to this RCP request is in this frame", HFILL}
    },
    { &hf_rcp_response_to,
        { "Request In", "rcp.response_to",
           FT_FRAMENUM,BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
           "This is a response to an RCP request in this frame", HFILL}
    },
    { &hf_rcp_ext_header,
        { "Extension Header", "rcp.ext",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_ext_next_header,
        { "Next Header", "rcp.ext_nxt_header",
        FT_UINT16, BASE_DEC,
        VALS(headertypenames), 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_ext_len,
        {"Length", "rcp.ext_len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_ext_res,
        { "Reserved", "rcp.nxt_res",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_rcp_ext_src_addr,
        {"Source Address", "rcp.nxt_srcaddr",
            FT_IPv6, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
    },
    { &hf_rcp_ext_dst_addr,
        {"Destination Address", "rcp.nxt_dstaddr",
            FT_IPv6, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
    }
    };

    static gint* ett[] = {
            &ett_rcp,
            &ett_rcp_nxt
    };

    static ei_register_info ei[] = {
        {
            &ei_rcp_no_resp,
            { "rcp.no_resp", PI_SEQUENCE, PI_WARN,
                "RCP Response not found", EXPFILL }
        }
    };

    proto_rcp = proto_register_protocol(
        "RCP Protocol",
        "RCP",
        "rcp"
    );


    proto_register_field_array(proto_rcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rcp = expert_register_protocol(proto_rcp);
    expert_register_field_array(expert_rcp, ei, array_length(ei));
}

void
proto_reg_handoff_rcp(void)
{
    static dissector_handle_t rcp_handle;

    eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_rcp);
    rcp_handle = create_dissector_handle(dissect_rcp, proto_rcp);
    dissector_add_uint("udp.port", RCP_PORT, rcp_handle);
}
