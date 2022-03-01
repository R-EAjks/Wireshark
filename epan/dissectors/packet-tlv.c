/* packet-tlv.c
 *
 * pdcprrc protocol (defined by Lizard TLV framework).
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
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-pdcp-nr.h"

void proto_register_pdcprrc(void);

static int proto_pdcprrc = -1;

static int hf_pdcprrc_message_type = -1;
static int hf_pdcprrc_length = -1;
static int hf_pdcprrc_tag = -1;
static int hf_pdcprrc_len = -1;
static int hf_pdcprrc_ueid = -1;
static int hf_pdcprrc_txid = -1;
static int hf_pdcprrc_srbid = -1;
static int hf_pdcprrc_carrier_type = -1;
static int hf_pdcprrc_cell_group = -1;

static int hf_pdcprrc_status = -1;
static int hf_pdcprrc_rrc_pdu_type = -1;
static int hf_pdcprrc_rrc_dl_msg_type = -1;
static int hf_pdcprrc_pdcp_id = -1;

static int hf_pdcprrc_rrc_data = -1;
static int hf_pdcprrc_pdcp_data = -1;
static int hf_pdcprrc_data_length = -1;


/* Subtrees */
static gint ett_pdcprrc = -1;

static dissector_handle_t pdcprrc_handle;


void proto_reg_handoff_pdcprrc (void);

/* User definable values */
static range_t *global_pdcprrc_port_range = NULL;


static const value_string message_type_vals[] = {
    {1,   "PdcpDataReq"},
    {2,   "PdcpDataResp"},
    {3,   "RrcDataReq"},
    {4,   "RrcDataResp"},
    {5,   "PdcpRrcInitReq"},
    {6,   "PdcpRrcInitResp"},
    {0, NULL }
};

static const value_string carrier_type_vals[] = {
    {1,   "NR"},
    {2,   "LTE"},
    {0, NULL }
};

static const value_string status_vals[] = {
    {1,   "Success"},
    {2,   "Failure"},
    {3,   "UE Not Found"},
    {4,   "Bearer Not Found"},
    {5,   "Integrity Failure"},
    {0, NULL }
};

static const value_string rrc_pdu_type_vals[] = {
    {1,   "DL CCCH"},
    {2,   "UL CCCH"},
    {3,   "UL CCCH1"},
    {4,   "DL DCCH"},
    {5,   "UL DCCH"},
    {0, NULL }
};

static const value_string rrc_dl_msg_type_vals[] = {
    {1,   "RRCSetup"},
    {2,   "RRCReject"},
    {3,   "RRCReconfiguration"},
    {4,   "RRCResume"},
    {5,   "RRCRelease"},
    {6,   "RRCReestablishment"},
    {7,   "UECapabilityEnquiry"},
    {8,   "CounterCheck"},
    {9,   "MobilityFromNRCommand"},
    {0, NULL }
};



static dissector_handle_t nr_rrc_ul_ccch;
static dissector_handle_t nr_rrc_ul_ccch1;
static dissector_handle_t nr_rrc_dl_ccch;
static dissector_handle_t nr_rrc_pcch;
static dissector_handle_t nr_rrc_ul_dcch;
static dissector_handle_t nr_rrc_dl_dcch;
static dissector_handle_t data_dh;

static dissector_handle_t pdcp_nr_handle;

extern int proto_pdcp_nr;


static expert_field ei_pdcprrc_wrong_length = EI_INIT;
static expert_field ei_pdcprrc_should_not_be_in_message = EI_INIT;


/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

/* Call NR RRC dissector */
static gboolean global_pdcprrc_call_rrc = TRUE;
static gboolean global_pdcprrc_show_tag_and_len = TRUE;


// TODO: add channel type param, and check direction.
static dissector_handle_t look_up_rrc_dissector(guint8 message_type _U_, guint32 rrc_pdu_type)
{
    switch (rrc_pdu_type) {
        case 1:
            return nr_rrc_dl_ccch;
        case 2:
            return nr_rrc_ul_ccch;
        case 3:
            return nr_rrc_ul_ccch1;
        case 4:
            return nr_rrc_dl_dcch;
        case 5:
            return nr_rrc_ul_dcch;

        default:
            return data_dh;
    }

#if 0
    // TODO: use rrc_pdu_type!
    switch (message_type) {
        case 1:  // PdcpDataReq
        case 2:  // PdcpDataResp
            return nr_rrc_ul_dcch;
            break;
        case 3:  // RrcDataReq
        case 4:  // RrcDataResp
            return nr_rrc_ul_dcch;
            break;

        default:
            return data_dh;
    }
#endif
}


/******************************/
/* Main dissection function.  */
static int
dissect_pdcprrc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *pdcprrc_tree;
    proto_item *root_ti;
    gint offset = 0;
    gboolean has_pdcp = FALSE;
    pdcp_nr_info pdcp_info;
    memset(&pdcp_info, 0, sizeof(pdcp_info));

    /* Must be at least 12 bytes */
    if (tvb_reported_length(tvb) < 12) {
        return 0;
    }

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "pdcprrc");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_pdcprrc, tvb, offset, -1, ENC_NA);
    pdcprrc_tree = proto_item_add_subtree(root_ti, ett_pdcprrc);

    /* Message type */
    guint32 message_type;
    proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_message_type, tvb, offset, 1, ENC_BIG_ENDIAN, &message_type);
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s: ", val_to_str_const(message_type, message_type_vals, "Unknown"));
    proto_item_append_text(root_ti, " (%s)", val_to_str_const(message_type, message_type_vals, "Unknown"));
    offset += 1;

    switch (message_type) {
        case 2:
            has_pdcp = TRUE;
            pdcp_info.direction = PDCP_NR_DIRECTION_DOWNLINK;
            break;
        case 3:
            has_pdcp = TRUE;
            pdcp_info.direction = PDCP_NR_DIRECTION_UPLINK;
            break;
        default:
            break;

    }

    if (has_pdcp) {
        pdcp_info.plane = NR_SIGNALING_PLANE;
        pdcp_info.maci_present = TRUE;
        pdcp_info.sdap_header = FALSE;
        // Leave rohc_info as 0 bytes...
        pdcp_info.is_retx = 0;
    }

    /* Overall length */
    guint32 length;
    proto_item *ti = proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
    offset += 2;
    /* Expert error if signalled length not matching frame length */
    if (length != (guint)tvb_captured_length_remaining(tvb, offset)) {
        expert_add_info(pinfo, ti, &ei_pdcprrc_wrong_length);
    }

    guint32 pdu_type = 0;

    /* TLVs follow. */
    while (length) {
        guint32 tag;
        ti = proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_tag, tvb, offset++, 1, ENC_BIG_ENDIAN, &tag);
        if (!global_pdcprrc_show_tag_and_len) {
            PROTO_ITEM_SET_HIDDEN(ti);
        }
        guint32 len;
        ti = proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_len, tvb, offset++, 1, ENC_BIG_ENDIAN, &len);
        if (!global_pdcprrc_show_tag_and_len) {
            PROTO_ITEM_SET_HIDDEN(ti);
        }

        guint32 val32 = 0;
        guint64 val64 = 0;

        switch (tag) {
            case 2:
                /* UEId */
                proto_tree_add_item_ret_uint64(pdcprrc_tree, hf_pdcprrc_ueid, tvb, offset, len, ENC_BIG_ENDIAN, &val64);
                col_append_fstr(pinfo->cinfo, COL_INFO, "UEId=%3u ", (guint32)val64);
                pdcp_info.ueid = (guint32)val64;
                break;
            case 5:
                /* TXId */
                proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_txid, tvb, offset, len, ENC_BIG_ENDIAN, &val32);
                col_append_fstr(pinfo->cinfo, COL_INFO, "Txid=%3u ", val32);
                break;
            case 3:
                /* SRB Id */
                proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_srbid, tvb, offset, len, ENC_BIG_ENDIAN, &val32);
                col_append_fstr(pinfo->cinfo, COL_INFO, "SRBId=%u ", val32);
                pdcp_info.bearerType = Bearer_DCCH;  // TODO: depends upon message_type!
                pdcp_info.bearerId = val32;
                break;
            case 4:
                /* Cell Grouop */
                proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_cell_group, tvb, offset, len, ENC_BIG_ENDIAN, &val32);
                col_append_fstr(pinfo->cinfo, COL_INFO, "CellGroup=%u ", val32);
                break;
            case 6:
                /* Carrier Type */
                proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_carrier_type, tvb, offset, len, ENC_BIG_ENDIAN, &val32);
                col_append_fstr(pinfo->cinfo, COL_INFO, "CarrierType=%s ", val_to_str_const(val32, carrier_type_vals, "Unknown"));
                break;

            /* Payloads (RRC Data, PDCP Data) */
            case 7:
            case 8:
                length = 0;

                /* Data length */
                offset--;
                guint32 data_length;
                ti = proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &data_length);
                offset += 2;
                if ((guint16)tvb_reported_length_remaining(tvb, offset) != data_length) {
                    expert_add_info(pinfo, ti, &ei_pdcprrc_wrong_length);
                }

                proto_tree_add_item(pdcprrc_tree, (tag==7) ? hf_pdcprrc_rrc_data : hf_pdcprrc_pdcp_data, tvb, offset, -1, ENC_NA);

                if (has_pdcp) {
                    pdcp_info.pdu_length = tvb_reported_length_remaining(tvb, offset);


                    // Create separate PDCP tvb
                    tvbuff_t *pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
                    /* Store struct info in packet */
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, &pdcp_info);

                    add_new_data_source(pinfo, pdcp_tvb, "PDCP-NR Payload");
                    call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);
                }
                else if (global_pdcprrc_call_rrc) {
                    /* Send data to RRC correct dissector */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " | ");
                    col_set_fence(pinfo->cinfo, COL_INFO);
                    dissector_handle_t rrc_handle = look_up_rrc_dissector(message_type, pdu_type);
                    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
                    call_dissector_only(rrc_handle, next_tvb, pinfo, tree, NULL);
                }
                break;

            case 9:
                /* Status */
                proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_status, tvb, offset, 1, ENC_NA, &val32);
                col_append_fstr(pinfo->cinfo, COL_INFO, "Status=%s ", val_to_str_const(val32, status_vals, "Unknown"));
                break;

            case 12:
                /* Rrc DL Msg Type */
                ti = proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_rrc_dl_msg_type, tvb, offset, 1, ENC_NA, &val32);
                col_append_fstr(pinfo->cinfo, COL_INFO, "DL-MsgType=%s ", val_to_str_const(val32, rrc_dl_msg_type_vals, "Unknown"));

                /* Check if appropriate for this message */
                if (message_type >= 3) {
                    expert_add_info(pinfo, ti, &ei_pdcprrc_should_not_be_in_message);
                }
                break;

            case 10:
                /* RRC PDU Type */
                ti = proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_rrc_pdu_type, tvb, offset, len, ENC_BIG_ENDIAN, &pdu_type);
                col_append_fstr(pinfo->cinfo, COL_INFO, "PDUType=%s ", val_to_str_const(pdu_type, rrc_pdu_type_vals, "Unknown"));

                /* Check if appropriate for this message */
                if (message_type < 3) {
                    expert_add_info(pinfo, ti, &ei_pdcprrc_should_not_be_in_message);
                }

                break;

            case 11:
                /* PDCP Id */
                proto_tree_add_item_ret_uint(pdcprrc_tree, hf_pdcprrc_pdcp_id, tvb, offset, len, ENC_BIG_ENDIAN, &val32);
                col_append_fstr(pinfo->cinfo, COL_INFO, "PdcpId=%u ", val32);
                break;

            default:
                // TODO: expert info for unknown tag
                break;
        }

        if (length == 0) {
            // Don't want to show raw data again if RRC was has already written to Info column.
            //col_append_fstr(pinfo->cinfo, COL_INFO, "Data=");
            //for (guint o = offset-1; o < tvb_reported_length(tvb); o++) {
            //    col_append_fstr(pinfo->cinfo, COL_INFO, "%02x", tvb_get_guint8(tvb, o));
            //}
            break;
        }

        offset += len;

        length -= (2 + len);
    }

    return offset;
}


void
proto_register_pdcprrc(void)
{
  static hf_register_info hf[] = {
      { &hf_pdcprrc_message_type,
        { "MsgType", "pdcprrc.message-type", FT_UINT8, BASE_DEC,
          VALS(message_type_vals), 0x0, NULL, HFILL }},
      { &hf_pdcprrc_length,
        { "Length", "pdcprrc.length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_tag,
        { "Tag", "pdcprrc.tag", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_len,
        { "Len", "pdcprrc.len", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_ueid,
        { "UEId", "pdcprrc.ueid", FT_UINT64, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_txid,
        { "Txid", "pdcprrc.txid", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_srbid,
        { "SRB Id", "pdcprrc.srbid", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_carrier_type,
        { "Carrier Type", "pdcprrc.carrier-type", FT_UINT8, BASE_DEC,
          VALS(carrier_type_vals), 0x0, NULL, HFILL }},
      { &hf_pdcprrc_cell_group,
        { "Cell Group", "pdcprrc.cell-group", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_status,
        { "Status", "pdcprrc.status", FT_UINT8, BASE_DEC,
          VALS(status_vals), 0x0, NULL, HFILL }},
      { &hf_pdcprrc_rrc_pdu_type,
        { "RRC PDU Type", "pdcprrc.rrc-pdu-type", FT_UINT8, BASE_DEC,
          VALS(rrc_pdu_type_vals), 0x0, NULL, HFILL }},
      { &hf_pdcprrc_rrc_dl_msg_type,
        { "RRC DL Msg Type", "pdcprrc.rrc-dl-msg-type", FT_UINT8, BASE_DEC,
          VALS(rrc_dl_msg_type_vals), 0x0, NULL, HFILL }},
      { &hf_pdcprrc_pdcp_id,
        { "PDCP Id", "pdcprrc.pdcp-id", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_pdcprrc_rrc_data,
        { "RRC Data", "pdcprrc.rrc-data", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_pdcp_data,
        { "PDCP Data", "pdcprrc.pdcp-data", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_pdcprrc_data_length,
        { "Data Length", "pdcprrc.data-length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_pdcprrc,
    };

    static ei_register_info ei[] = {
        { &ei_pdcprrc_wrong_length,               { "pdcprrc.wrong-length",  PI_MALFORMED, PI_ERROR, "Signalled length does not match packet length", EXPFILL }},
        { &ei_pdcprrc_should_not_be_in_message,   { "pdcprrc.unexpected-ie", PI_MALFORMED, PI_ERROR, "Element should not appear in this message", EXPFILL }}
    };

    module_t *pdcprrc_module;
    expert_module_t *expert_pdcprrc;

    proto_pdcprrc = proto_register_protocol("pdcprrc", "pdcprrc", "pdcprrc");
    proto_register_field_array(proto_pdcprrc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pdcprrc = expert_register_protocol(proto_pdcprrc);
    expert_register_field_array(expert_pdcprrc, ei, array_length(ei));

    pdcprrc_handle = register_dissector("pdcprrc", dissect_pdcprrc, proto_pdcprrc);

    /* Preferences */
    pdcprrc_module = prefs_register_protocol(proto_pdcprrc, NULL);

    /* Whether to try NR-RRC dissector on payload. */
    prefs_register_bool_preference(pdcprrc_module, "attempt_rrc_decode",
        "Call NR-RRC dissector for payload",
        "",
        &global_pdcprrc_call_rrc);

    /* Whether to show tags in tree (or to hide). */
    prefs_register_bool_preference(pdcprrc_module, "show_tag_and_len_fields",
        "Show tag and length fields",
        "",
        &global_pdcprrc_show_tag_and_len);

}

static void
apply_pdcprrc_prefs(void)
{
    global_pdcprrc_port_range = prefs_get_range_value("pdcprrc", "udp.port");
}

void
proto_reg_handoff_pdcprrc(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", pdcprrc_handle);

    nr_rrc_ul_ccch         = find_dissector_add_dependency("nr-rrc.ul.ccch",  proto_pdcprrc);
    nr_rrc_ul_ccch1        = find_dissector_add_dependency("nr-rrc.ul.ccch1", proto_pdcprrc);
    nr_rrc_dl_ccch         = find_dissector_add_dependency("nr-rrc.dl.ccch",  proto_pdcprrc);
    nr_rrc_pcch            = find_dissector_add_dependency("nr-rrc.pcch",     proto_pdcprrc);
    nr_rrc_ul_dcch         = find_dissector_add_dependency("nr-rrc.ul.dcch",  proto_pdcprrc);
    nr_rrc_dl_dcch         = find_dissector_add_dependency("nr-rrc.dl.dcch",  proto_pdcprrc);
    data_dh                = find_dissector_add_dependency("data",            proto_pdcprrc);

    pdcp_nr_handle = find_dissector("pdcp-nr");

    apply_pdcprrc_prefs();
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
