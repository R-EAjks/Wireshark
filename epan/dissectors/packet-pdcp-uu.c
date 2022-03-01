/* packet-pdcp_uu.c
 *
 * Routines for pdcp_uu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <stdio.h>

#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-pdcp-lte.h"
#include "packet-pdcp-nr.h"

void proto_register_pdcp_uu(void);

static int proto_pdcp_uu = -1;

static int hf_pdcp_uu_cell_lcid = -1;
static int hf_pdcp_uu_cell_lcid_len = -1;
static int hf_pdcp_uu_ue_id_lcid = -1;
static int hf_pdcp_uu_ue_id_lcid_len = -1;
static int hf_pdcp_uu_ueid = -1;
static int hf_pdcp_uu_srbid = -1;
static int hf_pdcp_uu_drbid = -1;
static int hf_pdcp_uu_cellid = -1;
static int hf_pdcp_uu_rlc_channel_type = -1;
static int hf_pdcp_uu_rlc_op = -1;
static int hf_pdcp_uu_bcch_transport = -1;
static int hf_pdcp_uu_lcid = -1;
static int hf_pdcp_uu_carrier_type = -1;
static int hf_pdcp_uu_carrier_id = -1;
static int hf_pdcp_uu_cell_group_id = -1;

static int hf_pdcp_uu_rlc_fi = -1;
static int hf_pdcp_uu_rlc_mui = -1;
static int hf_pdcp_uu_rlc_cnf = -1;
static int hf_pdcp_uu_rlc_discard_req = -1;
static int hf_pdcp_uu_external_time_stamp = -1;

static int hf_pdcp_uu_edrx_timing = -1;
static int hf_pdcp_uu_edrx_timing_hyper_sfn = -1;
static int hf_pdcp_uu_edrx_timing_sysframe_no = -1;
static int hf_pdcp_uu_edrx_timing_subframe_no = -1;

static int hf_pdcp_uu_data_volume_request = -1;
static int hf_pdcp_uu_erroneous = -1;

static int hf_pdcp_uu_header_len = -1;

/* Subtrees */
static gint ett_pdcp_uu = -1;
static gint ett_pdcp_uu_ue_id_lcid = -1;
static gint ett_pdcp_uu_cell_lcid = -1;
static gint ett_pdcp_uu_edrx_timing = -1;

extern int proto_pdcp_lte;
extern int proto_pdcp_nr;

static dissector_handle_t pdcp_uu_handle;
static dissector_handle_t pdcp_lte_handle;
static dissector_handle_t pdcp_nr_handle;


void proto_reg_handoff_pdcp_uu (void);

/* User definable values */
static range_t *global_pdcp_uu_port_range = NULL;


static const value_string rlc_logical_channel_vals[] = {
    { Channel_DCCH,     "DCCH"},
    { Channel_BCCH,     "BCCH"},
    { Channel_CCCH,     "CCCH"},
    { Channel_PCCH,     "PCCH"},
//    { Channel_MCCH,     "MCCH"},
//    { Channel_BR_BCCH,  "BR_BCCH"},
    { 0,             NULL}
};



#define RLC_AM_DATA_REQ                 0x60
#define RLC_AM_DATA_IND                 0x61
#define RLC_AM_DATA_CONF                0x62
#define RLC_UM_DATA_REQ                 0x70
#define RLC_UM_DATA_IND                 0x71
#define RLC_UM_DATA_CONF                0x74
#define RLC_TR_DATA_REQ                 0x80
#define RLC_TR_DATA_IND                 0x81
#define RLC_TR_DATA_CONF                0x83
#define RLC_AM_SN_UE_ACK                0x94
#define RLC_DATA_VOLUME_IND             0xa1

static const value_string rlc_op_vals[] = {
    { RLC_AM_DATA_REQ,     "[UL][AM] am_data_req" },
    { RLC_AM_DATA_IND,     "[DL][AM] am_data_ind" },
    { RLC_AM_DATA_CONF,    "[DL][AM] am_data_cnf" },
    { RLC_UM_DATA_REQ,     "[UL][UM] um_data_req"},
    { RLC_UM_DATA_IND,     "[DL][UM] um_data_ind"},
    { RLC_TR_DATA_REQ,     "[UL][TM] tm_data_req"},
    { RLC_TR_DATA_IND,     "[DL][TM] tm_data_ind"},
    { RLC_AM_SN_UE_ACK,    "rlc_am_mui_ack"},
    { RLC_DATA_VOLUME_IND, "rlc_data_volume_ind"},
    { 0,   NULL }
};

#define LTE_UE_ID_TAG 0x10   /* For UE_ID_LCId */


static const value_string bcch_transport_vals[] = {
    { BCH_TRANSPORT,    "BCH" },
    { DLSCH_TRANSPORT,  "DLSCH" },
    { 0,   NULL },
};

static const value_string carrier_type_vals[] = {
    { 0,    "LTE" },
    { 1,    "CatM" },
    { 2,    "NBIoT" },
    { 3,    "NR" },
    { 0,   NULL },
};

/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

// Configure which PDCP dissector to call
enum pdcp_to_call {
    PDCP_None,
    PDCP_LTE,
    PDCP_NR
};
static const enum_val_t pdcp_type_vals[] = {
    {"pdcp-nr",            "None",            PDCP_None},
    {"pdcp-lte",           "LTE",             PDCP_LTE},
    {"pdcp-nr",            "NR",              PDCP_NR},
    {NULL, NULL, -1}
};
static gint global_pdcp_type = (gint)PDCP_LTE;


// Configure number of DRB SN sequence bits?
enum pdcp_for_drb {
    PDCP_drb_SN_7=7,
    PDCP_drb_SN_12=12,
    PDCP_drb_SN_15=15,
    PDCP_drb_SN_18=18
};
static const enum_val_t pdcp_drb_col_vals[] = {
    {"pdcp-drb-sn-7",          "7-bit SN",            PDCP_drb_SN_7},
    {"pdcp-drb-sn-12",         "12-bit SN",           PDCP_drb_SN_12},
    {"pdcp-drb-sn-15",         "15-bit SN",           PDCP_drb_SN_15},
    {"pdcp-drb-sn-18",         "18-bit SN",           PDCP_drb_SN_18},
    {NULL, NULL, -1}
};
static gint global_call_pdcp_for_drb = (gint)PDCP_drb_SN_12;


static gboolean global_skip_mystery_byte = FALSE;

#if 0
/* Return the number of bytes used to encode the length field
   (we're not interested in the length value itself) */
static int skipASNLength(guint8 value)
{
    if ((value & 0x80) == 0)
    {
        return 1;
    }
    else
    {
        return ((value & 0x03) == 1) ? 2 : 3;
    }
}
#endif

/* UE_Id_LCId */
static gint dissect_ue_id_lcid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                               struct pdcp_lte_info *p_pdcp_lte_info,
                               struct pdcp_nr_info  *p_pdcp_nr_info)
{
    guint8 channelId;

    /* Subtree */
    proto_item *ue_id_lcid_ti = proto_tree_add_string_format(tree, hf_pdcp_uu_ue_id_lcid, tvb, offset-1, -1, "", "UE_ID_LCId (");
    proto_tree *ue_id_lcid_tree = proto_item_add_subtree(ue_id_lcid_ti, ett_pdcp_uu_ue_id_lcid);

    /* Length will fit in one byte here */
    guint32 len;
    proto_tree_add_item_ret_uint(ue_id_lcid_tree, hf_pdcp_uu_ue_id_lcid_len, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
    offset++;
    proto_item_set_len(ue_id_lcid_ti, 1+1+len);

    p_pdcp_lte_info->channelType = Channel_DCCH;
    p_pdcp_nr_info->bearerType = Bearer_DCCH;

    /* UEId */
    guint32 ueid;
    proto_tree_add_item_ret_uint(ue_id_lcid_tree, hf_pdcp_uu_ueid, tvb, offset, 2, ENC_BIG_ENDIAN, &ueid);
    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " UEId=%u", ueid);
    proto_item_append_text(ue_id_lcid_ti, "UEId=%u", ueid);
    p_pdcp_lte_info->ueid = ueid;
    p_pdcp_nr_info->ueid = ueid;
    offset += 2;

    /* Get tag of channel/bearer type */
    guint8 tag = tvb_get_guint8(tvb, offset++);

    switch (tag) {
        case 0:  /* SRB */
            offset++;
            channelId = tvb_get_guint8(tvb, offset);
            col_append_fstr(pinfo->cinfo, COL_INFO, " SRB:%u",
                            channelId);
            proto_item_append_text(ue_id_lcid_ti, " SRB:%u", channelId);
            proto_tree_add_item(ue_id_lcid_tree, hf_pdcp_uu_srbid,
                                tvb, offset++, 1, ENC_BIG_ENDIAN);

            p_pdcp_lte_info->channelId = channelId;
            p_pdcp_lte_info->plane = SIGNALING_PLANE;

            p_pdcp_nr_info->bearerId = channelId;
            p_pdcp_nr_info->plane = NR_SIGNALING_PLANE;
            break;
        case 1: /* DRB */
            offset++;
            channelId = tvb_get_guint8(tvb, offset);
            col_append_fstr(pinfo->cinfo, COL_INFO, " DRB:%u",
                            channelId);
            proto_item_append_text(ue_id_lcid_ti, " DRB:%u", channelId);
            proto_tree_add_item(ue_id_lcid_tree, hf_pdcp_uu_drbid,
                                tvb, offset++, 1, ENC_BIG_ENDIAN);
            p_pdcp_lte_info->channelId = channelId;
            p_pdcp_lte_info->plane = USER_PLANE;

            p_pdcp_nr_info->bearerId = channelId;
            p_pdcp_nr_info->plane = NR_USER_PLANE;

            // N.B. from preference...
            p_pdcp_lte_info->seqnum_length = global_call_pdcp_for_drb;
            p_pdcp_nr_info->seqnum_length = global_call_pdcp_for_drb;
            break;

        default:
            /* Unexpected channel type */
            return offset;
    }

    if (len > 5) {
        /* LCID field */
        tag = tvb_get_guint8(tvb, offset++);
        if (tag == 2) {
            /* Skip len */
            offset++;
            guint32 lcid;
            proto_tree_add_item_ret_uint(ue_id_lcid_tree, hf_pdcp_uu_lcid,
                                         tvb, offset++, 1, ENC_BIG_ENDIAN, &lcid);
            proto_item_append_text(ue_id_lcid_ti, " LCID:%u", lcid);
        }
    }

    proto_item_append_text(ue_id_lcid_ti, ")");
    return offset;
}


/* Cell_LCId */
static gint dissect_cell_lcid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset,
                              struct pdcp_lte_info *p_pdcp_lte_info,
                              struct pdcp_nr_info  *p_pdcp_nr_info)
{
    guint32 ueid;
    guint32 transport;

    /* Subtree */
    proto_item *cell_lcid_ti = proto_tree_add_string_format(tree, hf_pdcp_uu_cell_lcid, tvb, offset-1, -1, "", "CELL_LCId (");
    proto_tree *cell_lcid_tree = proto_item_add_subtree(cell_lcid_ti, ett_pdcp_uu_cell_lcid);

    /* Skip length */
    guint32 len;
    proto_tree_add_item_ret_uint(cell_lcid_tree, hf_pdcp_uu_cell_lcid_len, tvb, offset, 1, ENC_BIG_ENDIAN, &len);
    offset++;
    proto_item_set_len(cell_lcid_ti, 1+1+len);

    /* Cell-id */
    guint32 cellid;
    proto_tree_add_item_ret_uint(cell_lcid_tree, hf_pdcp_uu_cellid, tvb, offset, 2, ENC_BIG_ENDIAN, &cellid);
    proto_item_append_text(cell_lcid_ti, "CellId=%u", cellid);
    offset += 2;

    /* Logical bearer/channel type */
    proto_tree_add_item(cell_lcid_tree, hf_pdcp_uu_rlc_channel_type,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    p_pdcp_lte_info->channelType = (LogicalChannelType)tvb_get_guint8(tvb, offset);
    p_pdcp_nr_info->bearerType = (NRBearerType)tvb_get_guint8(tvb, offset);
    offset++;

    /* TODO: separate vals for NR ? */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                    val_to_str_const(p_pdcp_lte_info->channelType, rlc_logical_channel_vals,
                                     "UNKNOWN-CHANNEL"));
    proto_item_append_text(cell_lcid_ti, " BearerType=%s ",
                           val_to_str_const(p_pdcp_lte_info->channelType, rlc_logical_channel_vals,
                                            "UNKNOWN-CHANNEL"));

    switch (p_pdcp_lte_info->channelType) {
        case Channel_BCCH:
            /* Skip length */
            offset++;

            /* Transport channel type */
            proto_tree_add_item_ret_uint(cell_lcid_tree, hf_pdcp_uu_bcch_transport,
                                         tvb, offset, 1, ENC_BIG_ENDIAN, &transport);
            proto_item_append_text(cell_lcid_ti, "(%s)",
                                   val_to_str_const(transport, bcch_transport_vals, "Unknown"));

            p_pdcp_lte_info->BCCHTransport = (BCCHTransportType)tvb_get_guint8(tvb, offset);
            if (p_pdcp_lte_info->BCCHTransport == BCH_TRANSPORT) {
                p_pdcp_nr_info->bearerType = Bearer_BCCH_BCH;
            }
            else {
                p_pdcp_nr_info->bearerType = Bearer_BCCH_DL_SCH;
            }

            offset++;
            break;

        case Channel_CCCH:
            /* Skip length */
            offset++;

            /* UEId */
            proto_tree_add_item(cell_lcid_tree, hf_pdcp_uu_ueid,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            ueid = tvb_get_ntohs(tvb, offset);
            offset += 2;

            p_pdcp_nr_info->bearerType = Bearer_CCCH;

            col_append_fstr(pinfo->cinfo, COL_INFO, " UEId=%u", ueid);
            break;

        case Channel_PCCH:
            p_pdcp_lte_info->channelType = Channel_PCCH;
            p_pdcp_nr_info->bearerType = Bearer_PCCH;
            break;

        default:
            break;
    }
    p_pdcp_lte_info->plane = SIGNALING_PLANE;
    p_pdcp_nr_info->plane = NR_SIGNALING_PLANE;

    proto_item_append_text(cell_lcid_ti, ")");

    return offset;
}



/******************************/
/* Main dissection function.  */
/* N.B. Copied from dissect_pdcp_lte() from packet-catapult-dct2000.c */
static int
dissect_pdcp_uu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *pdcp_uu_tree;
    proto_item *root_ti;

    gint                  offset = 0;
    guint8                opcode;
    guint8                tag;
    struct pdcp_lte_info *p_pdcp_lte_info = NULL;
    struct pdcp_nr_info  *p_pdcp_nr_info = NULL;

    tvbuff_t             *pdcp_tvb;
    proto_item *ti;

    /* Protocol column */
    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-UU|");
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_pdcp_uu, tvb, offset, -1, ENC_NA);
    pdcp_uu_tree = proto_item_add_subtree(root_ti, ett_pdcp_uu);


    /* N.B. Allocating both LTE and NR context structs, as only find out later which one applies */

    /* Allocate & zero struct (LTE) */
    p_pdcp_lte_info = wmem_new0(wmem_file_scope(), pdcp_lte_info);
    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0, p_pdcp_lte_info);
    /* Look this up so can update channel info */
    p_pdcp_lte_info = (struct pdcp_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0);
    if (p_pdcp_lte_info == NULL) {
        /* This really should be set...can't dissect anything without it */
        return offset;
    }

    /* Allocate & zero struct (NR) */
    p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
    /* Look this up so can update channel info */
    p_pdcp_nr_info = (struct pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
    if (p_pdcp_nr_info == NULL) {
        /* This really should be set...can't dissect anything without it */
        return offset;
    }


    /* Skip it if configured to! */
    if (global_skip_mystery_byte) {
        offset++;
    }

    /* Top-level opcode */
    opcode = tvb_get_guint8(tvb, offset);
    /* Move on if we see the 'mystery byte' */
    if (opcode == 0x04) {
        offset++;
        opcode = tvb_get_guint8(tvb, offset);
    }

    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_rlc_op, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;


    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, rlc_op_vals, "Unknown"));
    proto_item_append_text(root_ti, " (%s)", val_to_str_const(opcode, rlc_op_vals, "Unknown"));

    /* Assume UE side, so REQ is UL, IND is DL */
    switch (opcode) {
       case RLC_AM_DATA_REQ:
       case RLC_UM_DATA_REQ:
       case RLC_TR_DATA_REQ:
           p_pdcp_lte_info->direction = DIRECTION_UPLINK;
           p_pdcp_nr_info->direction = PDCP_NR_DIRECTION_UPLINK;
           break;

       default:
           p_pdcp_lte_info->direction = DIRECTION_DOWNLINK;
           p_pdcp_nr_info->direction = PDCP_NR_DIRECTION_DOWNLINK;
    }

    /* Parse header */
    switch (opcode) {
        /* Data messages */
        case RLC_AM_DATA_REQ:
        case RLC_AM_DATA_IND:
        case RLC_UM_DATA_REQ:
        case RLC_UM_DATA_IND:
        case RLC_TR_DATA_REQ:
        case RLC_TR_DATA_IND:
        case RLC_AM_DATA_CONF:

            /* Get next tag */
            tag = tvb_get_guint8(tvb, offset++);
            switch (tag) {
                case LTE_UE_ID_TAG:    /* UE_Id_LCId */
                    /* Dedicated channel info */
                    offset = dissect_ue_id_lcid(tvb, pinfo, pdcp_uu_tree, offset, p_pdcp_lte_info, p_pdcp_nr_info);
                    break;

                case 0x1a:     /* Cell_LCId */

                    /* Common channel info */
                    offset = dissect_cell_lcid(tvb, pinfo, pdcp_uu_tree, offset, p_pdcp_lte_info, p_pdcp_nr_info);
                    break;

                default:
                    /* Unexpected tag */
                    return offset;
            }

            /* Other optional fields may follow */
            tag = tvb_get_guint8(tvb, offset++);
            while ((tag != 0x41) && (tvb_reported_length_remaining(tvb, offset) > 2)) {

                if (tag == 0x62) {
                    /* This is FI */
                    offset++;
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_rlc_fi,
                                        tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                else
                if (tag == 0x35) {
                    /* This is MUI (3 bytes for NR, 2 for LTE) */
                    guint8 len = tvb_get_guint8(tvb, offset);
                    offset++;
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_rlc_mui,
                                        tvb, offset, len, ENC_BIG_ENDIAN);
                    offset += len;

                    /* CNF follows MUI in AM */
                    if ((opcode == RLC_AM_DATA_REQ) || (opcode == RLC_AM_DATA_IND)) {
                        proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_rlc_cnf,
                                               tvb, offset, 1, ENC_NA);
                        offset++;
                    }
                }
                else if (tag == 0x45) {
                    /* Discard Req */
                    offset++;
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_rlc_discard_req,
                                           tvb, offset, 1, ENC_NA);
                    offset++;
                }
                else if (tag == 0x1e) {
                    /* Carrier Id */
                    offset++;
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_carrier_id,
                                           tvb, offset, 1, ENC_NA);
                    offset++;
                }
                else if (tag == 0x20) {
                    /* Carrier Type */
                    offset++;
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_carrier_type,
                                           tvb, offset, 1, ENC_NA);
                    offset++;
                }
                else if (tag == 0x22) {
                    /* Cell Group Id */
                    offset++;
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_cell_group_id,
                                           tvb, offset, 1, ENC_NA);
                    offset++;
                }
                else if (tag == 0x9a) {
                    /* External Time Stamp */
                    guint8 len = tvb_get_guint8(tvb, offset++);  /* will be 8 */
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_external_time_stamp,
                                        tvb, offset, len, ENC_NA);
                    offset += len;
                }
                else if (tag == 0x32) {
                    /* eDRX Timing */

                    /* Subtree */
                    proto_item *edrx_timing_ti = proto_tree_add_string_format(tree, hf_pdcp_uu_edrx_timing, tvb, offset-1, -1, "", "UE_ID_LCId (");
                    proto_tree *edrx_timing_tree = proto_item_add_subtree(edrx_timing_ti, ett_pdcp_uu_edrx_timing);

                    /* Overall length */
                    guint8 len = tvb_get_guint8(tvb, offset++);
                    proto_item_set_len(edrx_timing_ti, len+2);

                    offset += 2; /* skip tag and len for hyperSFN */

                    /* HyperSFN */
                    proto_tree_add_item(edrx_timing_tree, hf_pdcp_uu_edrx_timing_hyper_sfn,
                                           tvb, offset, 2, ENC_NA);
                    offset += 2;
                    /* SysFrame Number */
                    proto_tree_add_item(edrx_timing_tree, hf_pdcp_uu_edrx_timing_sysframe_no,
                                           tvb, offset, 2, ENC_NA);
                    offset += 2;
                    /* SubFrame Number */
                    proto_tree_add_item(edrx_timing_tree, hf_pdcp_uu_edrx_timing_subframe_no,
                                           tvb, offset, 1, ENC_NA);
                    offset++;
                }
                else if (tag == 0x9b) {
                    /* DataVolumeRequest */
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_data_volume_request,
                                        tvb, offset-1, 1, ENC_NA);
                }
                else if (tag == 0x29) {
                    /* Erroneous */
                    proto_tree_add_item(pdcp_uu_tree, hf_pdcp_uu_erroneous,
                                        tvb, offset-1, 1, ENC_NA);
                    /* For some reason, there is a length and value... */
                    offset += 2;
                }


                else {
                    /* Unrecognised tag... */
                }

                // Get next tag (if there is one..)
                if (tvb_reported_length_remaining(tvb, offset) >= 1) {
                    tag = tvb_get_guint8(tvb, offset++);
                }
                else {
                    return offset;
                }
            }


            /********************************/
            /* Should be at data tag now    */

            // Show length of header..
            ti = proto_tree_add_uint(pdcp_uu_tree, hf_pdcp_uu_header_len,
                                     tvb, 0, offset, offset);
            proto_item_set_generated(ti);


            if (global_pdcp_type == PDCP_LTE) {
                /* Call PDCP LTE dissector */
                pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
                p_pdcp_lte_info->pdu_length = tvb_reported_length(pdcp_tvb);
                call_dissector_only(pdcp_lte_handle, pdcp_tvb, pinfo, tree, NULL);
            }

            if (global_pdcp_type == PDCP_NR) {
                switch (p_pdcp_nr_info->bearerType) {
                    case Bearer_DCCH:
                    {
                        /* Call PDCP NR dissector */
                        pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
                        p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_tvb);
                        call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);
                    }
                    break;

                    case Bearer_BCCH_BCH:
                    {
                        pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
                        dissector_handle_t rrc_handle;
                        rrc_handle = find_dissector_add_dependency("nr-rrc.bcch.bch", proto_pdcp_nr);
                        call_dissector_only(rrc_handle, pdcp_tvb, pinfo, tree, NULL);
                    }
                    break;

                    case Bearer_BCCH_DL_SCH:
                    {
                        pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
                        dissector_handle_t rrc_handle;
                        rrc_handle = find_dissector_add_dependency("nr-rrc.bcch.dl.sch", proto_pdcp_nr);
                        call_dissector_only(rrc_handle, pdcp_tvb, pinfo, tree, NULL);
                    }
                    break;

                default:
                    // Ignoring.
                    break;
                }
            }


            break;

        case RLC_AM_SN_UE_ACK:  /* rlc_am_mui_ack */
            /* TODO: will want to see this.. */
            //printf("RLC_AM_SN_UE_ACK\n");

            /* Dedicated channel info */
            offset = dissect_ue_id_lcid(tvb, pinfo, pdcp_uu_tree, offset, p_pdcp_lte_info, p_pdcp_nr_info);

            /* TODO: CellGroup?? */
            /* TODO: FI */
            /* TODO: MUI */
            break;

        case RLC_DATA_VOLUME_IND:
            /* TODO: don't think we'll see this... */
            break;

        default:
            return offset;
    }

    return offset;
}


void
proto_register_pdcp_uu(void)
{
  static hf_register_info hf[] = {
    { &hf_pdcp_uu_cell_lcid,
      { "Cell_LCId", "pdcp-uu.cell_lcid", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_cell_lcid_len,
      { "Length", "pdcp-uu.cell_lcid.len", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_ue_id_lcid,
      { "UE_Id_LCId", "pdcp-uu.ue_id_lcid", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_ue_id_lcid_len,
      { "Length", "pdcp-uu.ue_id_lcid.len", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_ueid,
      { "UE Id", "pdcp-uu.ueid", FT_UINT16, BASE_DEC,
        NULL, 0x0, "User Equipment Identifier", HFILL}},
    { &hf_pdcp_uu_srbid,
      { "SRB Id", "pdcp-uu.srbid", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_drbid,
       { "DRB Id", "pdcp-uu.drbid", FT_UINT16, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_cellid,
       { "Cell Id", "pdcp-uu.cellid", FT_UINT16, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_rlc_channel_type,
       { "RLC Logical Channel Type", "pdcp-uu.rlc-logchan-type", FT_UINT8, BASE_DEC,
         VALS(rlc_logical_channel_vals), 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_rlc_op,
       { "RLC Op", "pdcp-uu.rlc-op", FT_UINT8, BASE_HEX,
         VALS(rlc_op_vals), 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_bcch_transport,
       { "BCCH Transport", "pdcp-uu.bcch-transport", FT_UINT16, BASE_DEC,
         VALS(bcch_transport_vals), 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_lcid,
       { "LCID", "pdcp-uu.lcid", FT_UINT8, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_carrier_id,
       { "Carrier Id", "pdcp-uu.carrier-id", FT_UINT8, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_carrier_type,
       { "Carrier Type", "pdcp-uu.carrier-type", FT_UINT8, BASE_DEC,
         VALS(carrier_type_vals), 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_cell_group_id,
       { "Cell Group Id", "pdcp-uu.cell-group-id", FT_UINT8, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},

    { &hf_pdcp_uu_rlc_fi,
       { "FI", "pdcp-uu.fi", FT_UINT8, BASE_DEC,
         NULL, 0x0, "Frame Indicator", HFILL}},
    { &hf_pdcp_uu_rlc_mui,
       { "MUI", "pdcp-uu.rlc-mui", FT_UINT24, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_rlc_cnf,
       { "CNF", "pdcp-uu.rlc-cnf", FT_BOOLEAN, BASE_NONE,
         TFS(&tfs_yes_no), 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_rlc_discard_req,
       { "Discard Req", "pdcp-uu.discard-req", FT_BOOLEAN, BASE_NONE,
         TFS(&tfs_yes_no), 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_external_time_stamp,
       { "External Time Stamp", "pdcp-uu.external-time-stamp", FT_UINT64, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},

    { &hf_pdcp_uu_edrx_timing,
      { "eDRX Timing", "pdcp-uu.edrx-timing", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_edrx_timing_hyper_sfn,
       { "HyperSFN", "pdcp-uu.edrx-timing.hyper-sfn", FT_UINT16, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_edrx_timing_sysframe_no,
       { "SysFrame No", "pdcp-uu.edrx-timing.sysframe-no", FT_UINT16, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_edrx_timing_subframe_no,
       { "SubFrame No", "pdcp-uu.edrx-timing.subframe-no", FT_UINT8, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},

    { &hf_pdcp_uu_data_volume_request,
       { "Data Volume Request", "pdcp-uu.data-volume-request", FT_NONE, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},
    { &hf_pdcp_uu_erroneous,
       { "Erroneous", "pdcp-uu.erroneous", FT_NONE, BASE_NONE,
         NULL, 0x0, NULL, HFILL}},

    { &hf_pdcp_uu_header_len,
       { "Header Length", "pdcp-uu.header-len", FT_UINT32, BASE_DEC,
         NULL, 0x0, NULL, HFILL}},
  };


    static gint *ett[] = {
        &ett_pdcp_uu,
        &ett_pdcp_uu_ue_id_lcid,
        &ett_pdcp_uu_cell_lcid,
        &ett_pdcp_uu_edrx_timing
    };

    module_t *pdcp_uu_module;

    proto_pdcp_uu = proto_register_protocol("pdcp-uu", "pdcp-uu", "pdcp-uu");
    proto_register_field_array(proto_pdcp_uu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pdcp_uu_handle = register_dissector("pdcp_uu", dissect_pdcp_uu, proto_pdcp_uu);

    /* Preferences */
    pdcp_uu_module = prefs_register_protocol(proto_pdcp_uu, NULL);

    prefs_register_enum_preference(pdcp_uu_module, "pdcp_layer",
        "PDCP flavour for payload",
        "",
        &global_pdcp_type, pdcp_type_vals, FALSE);

    prefs_register_enum_preference(pdcp_uu_module, "sn_bits_for_drb",
        "PDCP SN bits for DRB PDUs",
        "",
        &global_call_pdcp_for_drb, pdcp_drb_col_vals, FALSE);

    prefs_register_bool_preference(pdcp_uu_module, "skip_mystery_byte", "Skip mystery byte (CSCS_UE_RLCPRIM_TAG?)",
        "This appears to be CSCS_UE_RLCPRIM_TAG (value 0x05), which will be seen if the message comes through the proxy",
        &global_skip_mystery_byte);
}

static void
apply_pdcp_uu_prefs(void)
{
    global_pdcp_uu_port_range = prefs_get_range_value("pdcp-uu", "udp.port");
}

void
proto_reg_handoff_pdcp_uu(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", pdcp_uu_handle);
    apply_pdcp_uu_prefs();

    pdcp_lte_handle = find_dissector("pdcp-lte");
    pdcp_nr_handle = find_dissector("pdcp-nr");
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
