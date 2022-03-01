/* packet-pdcp_gtpu.c
 *
 * Routines for pdcp_gtpu
 * Used with PDCP layer tests.
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

#include <stdint.h>

#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-pdcp-nr.h"

void proto_register_pdcp_gtpu(void);

static int proto_pdcp_gtpu = -1;

static int hf_pdcp_gtpu_ueid = -1;
static int hf_pdcp_gtpu_drbid = -1;
static int hf_pdcp_gtpu_tunnelid = -1;


/* Subtrees */
static gint ett_pdcp_gtpu = -1;

extern int proto_pdcp_nr;

static dissector_handle_t pdcp_gtpu_handle;
static dissector_handle_t pdcp_nr_handle;


void proto_reg_handoff_pdcp_gtpu (void);

/* User definable values */
static range_t *global_pdcp_gtpu_port_range = NULL;

#ifdef  _WIN32
#define PACKED
#else
#define PACKED __attribute__((packed))
#endif

/*=========================== Type Definitions ================================= */
// control structure for Pdcp<->GTPu
typedef struct  PACKED ctlhdr_st_ {
   uint8_t ctlType; // see PDCP_GTPU_CTYPE_*
   uint32_t ueId; /* for S1 and X2 this is local ueId; for F1 it is DU ueId */
   uint8_t drbId;
   uint8_t tunnelId; /* pdcp->gtp */
   uint8_t cellGrpId;
   uint8_t intfType; // see PDCP_GTP_INTFTYPE_*
//   union {
     // finFrame_st ff; // no additional state need for final frame sent
//   };
} ctlhdr_st;

// initialize all fields to 0. Not all fields are used in all cases
// used in both pdcp->l1ap and l1ap->pdcp direction
typedef struct PACKED uebearer_st_ {
  uint32_t ueId; /* for S1 and X2 this is local ueId; for F1 it is DU ueId */
  uint8_t drbId; /* gtp->pdcp */
  uint8_t tunnelId; /* pdcp->gtp; F1-from f1ap; S1 & X2 - epsBearerId from cpdcpproto */
  uint8_t cellGrpId;
  uint8_t intfType; // see PDCP_GTP_INTFTYPE_*
  uint8_t nrContainerLength; // 0 if not there, n if NR UP hdr before Pdcp PDU
  uint8_t flags; // see PDCP_GTP_UEB_FLGS_*
} uebearer_st;

typedef struct PACKED pdcpToGTP_st_ {
  uint8_t frameType; // see PDCP_GTP_FTYPE_*
  union {
    uebearer_st ueb;
    ctlhdr_st ctl;
  };
} pdcpToGTP_st;



/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

// Configure number of DRB SN sequence bits?
enum pdcp_for_drb {
    PDCP_drb_SN_12=12,
    PDCP_drb_SN_18=18
};
static const enum_val_t pdcp_drb_col_vals[] = {
    {"pdcp-drb-sn-12",         "12-bit SN",           PDCP_drb_SN_12},
    {"pdcp-drb-sn-18",         "18-bit SN",           PDCP_drb_SN_18},
    {NULL, NULL, -1}
};
static gint global_call_pdcp_for_drb = (gint)PDCP_drb_SN_12;

static gboolean global_ul_sdap = FALSE;
static gboolean global_dl_sdap = FALSE;


/******************************/
/* Main dissection function.  */
static int
dissect_pdcp_gtpu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint                  offset = 0;
    struct pdcp_nr_info *p_pdcp_nr_info;
    tvbuff_t             *pdcp_nr_tvb;

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-GTPU|");
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);

    /* Protocol root */
    proto_item *root_ti = proto_tree_add_item(tree, proto_pdcp_gtpu, tvb, offset, -1, ENC_NA);
    proto_tree *pdcp_gtpu_tree = proto_item_add_subtree(root_ti, ett_pdcp_gtpu);

    pdcpToGTP_st *meta = (pdcpToGTP_st*)tvb_get_ptr(tvb, 0, sizeof(pdcpToGTP_st));
    proto_tree_add_uint(pdcp_gtpu_tree, hf_pdcp_gtpu_ueid, tvb, 1+offsetof(uebearer_st, ueId), 4, meta->ueb.ueId);
    proto_tree_add_uint(pdcp_gtpu_tree, hf_pdcp_gtpu_drbid, tvb, 1+offsetof(uebearer_st, drbId), 1, meta->ueb.drbId);
    proto_tree_add_uint(pdcp_gtpu_tree, hf_pdcp_gtpu_tunnelid, tvb, 1+offsetof(uebearer_st, tunnelId), 1, meta->ueb.tunnelId);
    proto_item_append_text(root_ti, " (UE_Id=%u, drbid=%u, tunnelId=%u)", meta->ueb.ueId, meta->ueb.drbId, meta->ueb.tunnelId);

    /* Allocate & zero struct */
    p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);

    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);

    /* Move past the struct */
    offset += sizeof(pdcpToGTP_st);
    proto_item_set_len(root_ti, offset);

    p_pdcp_nr_info->ueid = meta->ueb.ueId;
    p_pdcp_nr_info->bearerType = Bearer_DCCH;
    p_pdcp_nr_info->bearerId = meta->ueb.drbId;
    p_pdcp_nr_info->direction = (pinfo->srcport == 5523) ? PDCP_NR_DIRECTION_UPLINK : PDCP_NR_DIRECTION_DOWNLINK;
    p_pdcp_nr_info->plane = NR_USER_PLANE;
    p_pdcp_nr_info->seqnum_length = global_call_pdcp_for_drb;

    p_pdcp_nr_info->sdap_header = 0;
    if (global_ul_sdap) {
        p_pdcp_nr_info->sdap_header |= PDCP_NR_UL_SDAP_HEADER_PRESENT;
    }
    if (global_dl_sdap) {
        p_pdcp_nr_info->sdap_header |= PDCP_NR_DL_SDAP_HEADER_PRESENT;
    }

    /* Call PDCP NR dissector on all data. */
    pdcp_nr_tvb = tvb_new_subset_remaining(tvb, offset);
    p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_nr_tvb);
    call_dissector_only(pdcp_nr_handle, pdcp_nr_tvb, pinfo, tree, NULL);

    return tvb_reported_length(tvb);
}


void
proto_register_pdcp_gtpu(void)
{
    static hf_register_info hf[] = {
        { &hf_pdcp_gtpu_ueid,
            { "UEId",
              "pdcp-gtpu.ueid", FT_UINT32, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_pdcp_gtpu_drbid,
            { "DRBId",
              "pdcp-gtpu.drbid", FT_UINT8, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
        { &hf_pdcp_gtpu_tunnelid,
            { "TunnelId",
              "pdcp-gtpu.tunnelid", FT_UINT8, BASE_DEC,
              NULL, 0x0, NULL, HFILL
            }
        },
    };


    static gint *ett[] = {
        &ett_pdcp_gtpu,
    };

    module_t *pdcp_gtpu_module;

    proto_pdcp_gtpu = proto_register_protocol("pdcp-gtpu", "pdcp-gtpu", "pdcp-gtpu");
    proto_register_field_array(proto_pdcp_gtpu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pdcp_gtpu_handle = register_dissector("pdcp_gtpu", dissect_pdcp_gtpu, proto_pdcp_gtpu);

    /* Preferences */
    pdcp_gtpu_module = prefs_register_protocol(proto_pdcp_gtpu, NULL);

    prefs_register_enum_preference(pdcp_gtpu_module, "sn_bits_for_drb",
        "PDCP SN bits for DRB PDUs",
        "",
        &global_call_pdcp_for_drb, pdcp_drb_col_vals, FALSE);

    prefs_register_bool_preference(pdcp_gtpu_module, "ul_sdap",
                                   "UL SDAP",
                                   "",
                                   &global_ul_sdap);

    prefs_register_bool_preference(pdcp_gtpu_module, "dl_sdap",
                                   "DL SDAP",
                                   "",
                                   &global_dl_sdap);

}

static void
apply_pdcp_gtpu_prefs(void)
{
    global_pdcp_gtpu_port_range = prefs_get_range_value("pdcp-gtpu", "udp.port");
}

void
proto_reg_handoff_pdcp_gtpu(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", pdcp_gtpu_handle);
    apply_pdcp_gtpu_prefs();

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
