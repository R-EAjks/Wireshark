/* packet-dlblock.c
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <epan/reassemble.h>
#include <epan/prefs.h>

#include "packet-mac-nr.h"

// TODO:
// ?

/*
 * Based upon the type NRDecFpgaCodeBlockHeader_t from NRDecFpga.h
 *
// Header that the Decoder FPGA sends with each decoded code block
typedef struct
{
   // Word 1
   uint16_t ueId;                          // UE ID utilized by the Phy and FPGAs
   uint16_t rnti;                          // RNTI assigned to the UE

   uint16_t SlotInFrame;                   // bits 32-47, Slot number in within a frame, 4 bits subfame and Mu LSBs slot
   uint8_t  carrier;                       // Provided from a lookup table in the Decoder FPGA
   uint8_t  harqId;                        // HARQ ID

   // Word 2
   uint16_t codeBlockNum;                  // Numbered 0 to (N - 1)
   uint16_t totalCodeBlocks;               // N code blocks

   uint16_t codeBlockLen;
   uint8_t  LDPCIterations;                // Iterations for this CB
   uint8_t  maxLDPCIterations;             // Max interations over all CBs for this TB

   // Word 3
   uint32_t transportBlockLen;             // Valid only when last code block is sent

   uint16_t TbDmrsPower;                   // DMRS power, bits 160..175

#ifdef __BIG_ENDIAN__
   uint8_t  DecPathSel              : 1;    // bit 183
   uint8_t  seqNum                  : 2;    // bit 182..181
   uint8_t  NDI                     : 1;    // bit 180
   uint8_t  k1                      : 4;    // bits 176..19

   uint8_t  RarIndication           : 1;   // Used by Phy to differentiate RAR and non-RAR CBs
   uint8_t  parityCheckPassed       : 1;
   uint8_t  termNoChangeInHardBits  : 1;
   uint8_t  termParityCheckPassed   : 1;
   uint8_t  transportBlockCRC       : 1;   // Error=1, Valid only when last code block are sent
   uint8_t  transportBlock          : 1;
   uint8_t  codeBlockCRC            : 1;   // Error=1
   uint8_t  ReTxIndicator           : 1;   // bit 184, 0-NewTx/1-ReTx
#else
   uint8_t  k1                      : 4;    // bits 176..19
   uint8_t  NDI                     : 1;    // bit 180
   uint8_t  seqNum                  : 2;    // bit 182..181
   uint8_t  DecPathSel              : 1;    // bit 183

   uint8_t  ReTxIndicator           : 1;   // bit 184, 0-NewTx/1-ReTx
   uint8_t  codeBlockCRC            : 1;   // Error=1
   uint8_t  transportBlock          : 1;
   uint8_t  transportBlockCRC       : 1;   // Error=1, Valid only when last code block is sent
   uint8_t  termParityCheckPassed   : 1;
   uint8_t  termNoChangeInHardBits  : 1;
   uint8_t  parityCheckPassed       : 1;
   uint8_t  RarIndication           : 1;   // Used by Phy to differentiate RAR and non-RAR CBs
#endif

} PACK_THIS NRDecFpgaCodeBlockHeader_t;


// Codeblock message that the user application code will utilize.
// The payload will optionally not be sent when a CRC error is identified.
typedef struct
{
   NRDecFpgaCodeBlockHeader_t Header;

   uint8_t Payload[NRDEFS_MAX_BYTES_PER_CODEBLOCK];

} PACK_THIS NRDecFpgaCodeBlock_t;
*/


static dissector_handle_t dlblock_handle;

static dissector_handle_t mac_nr_handle;

/*******************************/
/* DL Blocks fields             */
static int proto_dlblock           = -1;

static int hf_dlblock_ueid = -1;
static int hf_dlblock_rnti = -1;

static int hf_dlblock_slotnumber = -1;
static int hf_dlblock_subframe_number = -1;
static int hf_dlblock_carrier = -1;
static int hf_dlblock_harqid = -1;

static int hf_dlblock_codeblock_num = -1;
static int hf_dlblock_total_codeblocks = -1;

static int hf_dlblock_codeblock_len = -1;
static int hf_dlblock_ldpc_iterations = -1;
static int hf_dlblock_max_ldpc_iterations = -1;

static int hf_dlblock_transport_blocklen = -1;

static int hf_dlblock_tb_drms_power = -1;

static int hf_dlblock_decpathsel = -1;
static int hf_dlblock_seqnum= -1;
static int hf_dlblock_ndi = -1;
static int hf_dlblock_k1 = -1;

static int hf_dlblock_rar_indication = -1;
static int hf_dlblock_parity_check_passed = -1;
static int hf_dlblock_term_no_change_hard_bits = -1;
static int hf_dlblock_term_parity_check_passed = -1;
static int hf_dlblock_transport_block_crc = -1;
static int hf_dlblock_transport_block = -1;
static int hf_dlblock_code_block_crc = -1;
static int hf_dlblock_new_data_ind = -1;

static int hf_dlblock_payload = -1;

static int hf_dlblock_first_frame = -1;


static int hf_dlblock_fragments = -1;
static int hf_dlblock_fragment = -1;
static int hf_dlblock_fragment_overlap = -1;
static int hf_dlblock_fragment_overlap_conflict = -1;
static int hf_dlblock_fragment_multiple_tails = -1;
static int hf_dlblock_fragment_too_long_fragment = -1;
static int hf_dlblock_fragment_error = -1;
static int hf_dlblock_fragment_count = -1;
static int hf_dlblock_reassembled_in = -1;
static int hf_dlblock_reassembled_length = -1;
static int hf_dlblock_reassembled_data = -1;


/* Subtrees. */
static int ett_dlblock = -1;
static gint ett_dlblock_fragments = -1;
static gint ett_dlblock_fragment  = -1;

static const fragment_items dlblock_frag_items = {
  &ett_dlblock_fragment,
  &ett_dlblock_fragments,
  &hf_dlblock_fragments,
  &hf_dlblock_fragment,
  &hf_dlblock_fragment_overlap,
  &hf_dlblock_fragment_overlap_conflict,
  &hf_dlblock_fragment_multiple_tails,
  &hf_dlblock_fragment_too_long_fragment,
  &hf_dlblock_fragment_error,
  &hf_dlblock_fragment_count,
  &hf_dlblock_reassembled_in,
  &hf_dlblock_reassembled_length,
  &hf_dlblock_reassembled_data,
  "DL Block fragments"
};



typedef struct {
    guint32 first_block_frame;
    // TODO: last_block_frame, timings?
    guint8  carrier;
    guint8  harq_id;
    // TODO: what else is needed here?
} BlockState_t;

// Go from BlockKey_t -> BlockState_t
static GHashTable *dlblock_hash = NULL;

// Store from block frame -> BlockState_t
static GHashTable *dlblock_result_hash = NULL;

static gpointer makeBlockKey(guint16 rnti, guint8 carrier, guint8 harq_id)
{
    guint value = rnti + (carrier << 16) + (harq_id << 24);
    return GUINT_TO_POINTER(value);
}



/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

static gint global_dlblock_dissect_mac_pdus = FALSE;


/* Expert info */
static expert_field ei_dl_block_cb_crc_error = EI_INIT;
static expert_field ei_dl_block_tb_crc_error = EI_INIT;

/* Forward declarations we need below */
void proto_register_dlblock(void);
void proto_reg_handoff_dlblock(void);
static gint dissect_dlblock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);



/* Initializes the hash tables each time a new
 * file is loaded or re-loaded in wireshark */
static void dlblock_init_protocol(void)
{
    dlblock_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    dlblock_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

/* Cleanup */
static void dlblock_cleanup_protocol(void)
{
    g_hash_table_destroy(dlblock_hash);
    g_hash_table_destroy(dlblock_result_hash);
}



/* Reassembly state */
static reassembly_table dlblock_reassembly_table;

static guint dlblock_grant_hash(gconstpointer k _U_)
{
    // Already passing in as key, so just convert to uint.
    return GPOINTER_TO_UINT(k);
}

static gpointer dlblock_grant_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data _U_)
{
    return (gpointer)data;
}

static gpointer dlblock_grant_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_,
                                            const void *data)
{
    return (gpointer)data;
}

static void dlblock_grant_free_temporary_key(gpointer ptr _U_)
{
}

static void dlblock_grant_free_persistent_key(gpointer ptr _U_)
{
}

static reassembly_table_functions dlblock_reassembly_table_functions =
{        dlblock_grant_hash,
         g_direct_equal,
         dlblock_grant_temporary_key,
         dlblock_grant_persistent_key,
         dlblock_grant_free_temporary_key,
         dlblock_grant_free_persistent_key
};



// Main dissection function.

static gint
dissect_dlblock( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLBLOCK");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *root_ti = proto_tree_add_item(tree, proto_dlblock, tvb, 0, -1, ENC_NA);
    proto_tree *dlblock_tree = proto_item_add_subtree(root_ti, ett_dlblock);

    // ueId
    guint32 ueid, rnti;
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_ueid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ueid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   UEId=%3u", ueid);
    offset += 2;
    // rnti
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_rnti, tvb, offset, 2, ENC_LITTLE_ENDIAN, &rnti);
    offset += 2;

    // slotNumber
    proto_tree_add_item(dlblock_tree, hf_dlblock_slotnumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    // subframeNumber
    proto_tree_add_item(dlblock_tree, hf_dlblock_subframe_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    // carrier
    guint32 carrier;
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_carrier, tvb, offset, 1, ENC_LITTLE_ENDIAN, &carrier);
    offset++;
    col_append_fstr(pinfo->cinfo, COL_INFO, "   CarrierId=%u", carrier);

    // harqId
    guint32 harq_id;
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_harqid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &harq_id);
    offset++;

    // codeBlockNum
    guint32 code_block_num, total_code_blocks, code_block_len;
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_codeblock_num, tvb, offset, 2, ENC_LITTLE_ENDIAN, &code_block_num);
    offset += 2;
    // totalCodeBlocks
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_total_codeblocks, tvb, offset, 2, ENC_LITTLE_ENDIAN, &total_code_blocks);
    offset += 2;

    // codeBlockLen
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_codeblock_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &code_block_len);
    offset += 2;
    // LDPCIterations
    proto_tree_add_item(dlblock_tree, hf_dlblock_ldpc_iterations, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    // maxLDPCIterations
    proto_tree_add_item(dlblock_tree, hf_dlblock_max_ldpc_iterations, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    col_append_fstr(pinfo->cinfo, COL_INFO, "   Block %u of %u (size=%u)",
                    code_block_num, total_code_blocks, code_block_len);

    // transportBlockLen (last segment only)
    guint32 transport_block_len;
    proto_tree_add_item_ret_uint(dlblock_tree, hf_dlblock_transport_blocklen, tvb, offset, 4, ENC_LITTLE_ENDIAN, &transport_block_len);
    offset += 4;
//    if (code_block_num == total_code_blocks-1) {
//        col_append_fstr(pinfo->cinfo, COL_INFO, "   TransportBlockLen=%u", transport_block_len);
//    }

    // TB DMRS Power.  TODO: wrong way around?
    proto_tree_add_item(dlblock_tree, hf_dlblock_tb_drms_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(dlblock_tree, hf_dlblock_decpathsel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dlblock_tree, hf_dlblock_seqnum, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dlblock_tree, hf_dlblock_ndi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dlblock_tree, hf_dlblock_k1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;


    //----------------------------------------------------------------------------------------
    // 8 bit flags follow...
    // RarIndication
    proto_tree_add_item(dlblock_tree, hf_dlblock_rar_indication, tvb, offset, 1, ENC_NA);
    // parityCheckPassed
    proto_tree_add_item(dlblock_tree, hf_dlblock_parity_check_passed, tvb, offset, 1, ENC_NA);
    // termNoChangeInHardBits
    proto_tree_add_item(dlblock_tree, hf_dlblock_term_no_change_hard_bits, tvb, offset, 1, ENC_NA);
    // termParityCheckPassed
    proto_tree_add_item(dlblock_tree, hf_dlblock_term_parity_check_passed, tvb, offset, 1, ENC_NA);

    // transportBlockCRC (only on last CB of TB)
    // TODO: should really remember setting so won't reassemble if last CB is not final one with valid flag...
    gboolean transport_block_crc = false;
    if (code_block_num >= total_code_blocks-1) {
        proto_item *tb_crc_ti = proto_tree_add_item_ret_boolean(dlblock_tree, hf_dlblock_transport_block_crc, tvb, offset, 1, ENC_NA, &transport_block_crc);
        if (transport_block_crc) {
            expert_add_info_format(pinfo, tb_crc_ti, &ei_dl_block_tb_crc_error,
                                   "TB CRC incorrect!");
        }
    }

    // transportBlock
    proto_tree_add_item(dlblock_tree, hf_dlblock_transport_block, tvb, offset, 1, ENC_NA);
    // codeBlockCRC
    gboolean code_block_crc;
    proto_item *cb_crc_ti = proto_tree_add_item_ret_boolean(dlblock_tree, hf_dlblock_code_block_crc, tvb, offset, 1, ENC_NA, &code_block_crc);
    if (code_block_crc) {
        expert_add_info_format(pinfo, cb_crc_ti, &ei_dl_block_cb_crc_error,
                               "CB CRC incorrect!");
    }

    // newDataInd
    proto_tree_add_item(dlblock_tree, hf_dlblock_new_data_ind, tvb, offset, 1, ENC_NA);
    offset++;

    if (code_block_crc) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   CRC-ERROR!");
    }

    // Payload
    proto_tree_add_item(dlblock_tree, hf_dlblock_payload, tvb, offset, code_block_len, ENC_NA);


    // On first pass through, maintain mapping, and set entry in result table.
    guint first_frame_number = 0;

    if (!PINFO_FD_VISITED(pinfo)) {
        // Look up this PDU in table.
        BlockState_t *blockState = (BlockState_t*)g_hash_table_lookup(dlblock_hash, makeBlockKey(rnti, carrier, harq_id));
        if (blockState == NULL) {
            // Initialise.
            blockState = wmem_new0(wmem_file_scope(), BlockState_t);
            blockState->first_block_frame = pinfo->num;
            blockState->carrier = carrier;
            blockState->harq_id = harq_id;
        }

        // TODO: Update for new frame.

        // Add to current table.
        g_hash_table_insert(dlblock_hash, makeBlockKey(rnti, carrier, harq_id), blockState);

        // Also add to result table (snapshot of current)
        BlockState_t *blockResultState = wmem_new(wmem_file_scope(), BlockState_t);
        memcpy(blockResultState, blockState, sizeof(BlockState_t));
        g_hash_table_insert(dlblock_result_hash, GUINT_TO_POINTER(pinfo->num), blockResultState);

        first_frame_number = blockState->first_block_frame;

        // If this was the final frame, remove entry from current table to avoid matching against stale entry.
        if (code_block_num == total_code_blocks-1) {
            g_hash_table_remove(dlblock_hash, makeBlockKey(rnti, carrier, harq_id));
        }
    }
    else {
        // Subsequent passes, find struct.
        BlockState_t *blockState = (BlockState_t*)g_hash_table_lookup(dlblock_result_hash, GUINT_TO_POINTER(pinfo->num));
        if (blockState != NULL) {
            proto_item *ti;

            // First data frame
            ti = proto_tree_add_uint(dlblock_tree, hf_dlblock_first_frame,
                                     tvb, 0, 0, blockState->first_block_frame);
            PROTO_ITEM_SET_GENERATED(ti);

            first_frame_number = blockState->first_block_frame;
        }
    }


    // Reassembly
    if (global_dlblock_dissect_mac_pdus && !transport_block_crc) {
        // Set fragmented flag.
        gboolean save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        fragment_head *fh;
        guint frag_data_len = tvb_reported_length_remaining(tvb, offset);

        fh = fragment_add_seq_check(&dlblock_reassembly_table, tvb, offset, pinfo,
                              first_frame_number,                                                 /* id (make same as next) */
                              GUINT_TO_POINTER(first_frame_number),                               /* data */
                              code_block_num,                                                     /* frag_number */
                              frag_data_len,                                                      /* frag_data_len */
                              code_block_num < total_code_blocks-1                                /* more_frags */
                              );

        gboolean update_col_info = TRUE;
        tvbuff_t *next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled MAC PDU",
                                                      fh, &dlblock_frag_items,
                                                      &update_col_info, dlblock_tree);

        if (next_tvb) {
            add_new_data_source(pinfo, next_tvb, "Reassembled UL MAC-NR PDU");

            // Get together MAC-NR details for this UL frame.
            struct mac_nr_info *p_mac_nr_info;
            // TODO: Only need to set info once per session??
            //p_mac_nr_info = get_mac_nr_proto_data(pinfo);

            /* Allocate & zero struct */
            p_mac_nr_info = wmem_new0(wmem_file_scope(), struct mac_nr_info);

            /* Populate the struct from outhdr values */
            p_mac_nr_info->radioType = FDD_RADIO;
            p_mac_nr_info->rntiType = C_RNTI;
            p_mac_nr_info->direction = DIRECTION_DOWNLINK;
            p_mac_nr_info->rnti = rnti;
            p_mac_nr_info->ueid = ueid;

            //p_mac_nr_info->phr_type2_pcell = FALSE;
            p_mac_nr_info->phr_type2_othercell = FALSE;

            p_mac_nr_info->length = tvb_reported_length(next_tvb);

            /* Store info in packet */
            set_mac_nr_proto_data(pinfo, p_mac_nr_info);

            // Call the MAC dissector!
            call_dissector_only(mac_nr_handle, next_tvb, pinfo, tree, NULL);
        }

        pinfo->fragmented = save_fragmented;

    }

    offset += code_block_len;

    return tvb_captured_length(tvb);
}

/* Register dlblock */

void
proto_register_dlblock(void)
{
    static hf_register_info hf[] =
    {
        { &hf_dlblock_ueid,
          { "UEId", "dlblock.ueid",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "UE ID utilized by the Phy and FPGAs", HFILL  }},
        { &hf_dlblock_rnti,
          { "RNTI", "dlblock.rnti",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "RNTI assigned to the UE", HFILL  }},

        { &hf_dlblock_slotnumber,
          { "Slot Number", "dlblock.slot-number",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_dlblock_subframe_number,
          { "Subframe Number", "dlblock.subframe-number",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_dlblock_carrier,
          { "Carrier", "dlblock.carrier",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Provided from a lookup table in the Decoder FPGA", HFILL  }},
        { &hf_dlblock_harqid,
          { "Harq-Id", "dlblock.harqid",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_dlblock_codeblock_num,
          { "Codeblock Number", "dlblock.codeblock-number",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Numbered 0 to (N - 1)", HFILL  }},
        { &hf_dlblock_total_codeblocks,
          { "Total Codeblocks", "dlblock.total-code-blocks",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "N code blocks", HFILL  }},

        { &hf_dlblock_codeblock_len,
          { "Codeblock len", "dlblock.codeblock-len",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_dlblock_ldpc_iterations,
          { "LDPC Iterations", "dlblock.ldpc-iterations",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_dlblock_max_ldpc_iterations,
          { "Max LDPC Iterations", "dlblock.max-ldpc-iterations",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_dlblock_transport_blocklen,
          { "Transport Block Length", "dlblock.transport-blocklen",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Valid only on last block", HFILL  }},

        { &hf_dlblock_tb_drms_power,
          { "TB DMRS Power", "dlblock.tbdmrspower",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},


        { &hf_dlblock_decpathsel,
          { "DecPathSel", "dlblock.decpathsel",
          FT_UINT8, BASE_DEC, NULL, 0x80,
          NULL, HFILL  }},
        { &hf_dlblock_seqnum,
          { "seqNum", "dlblock.seqnum",
          FT_UINT8, BASE_DEC, NULL, 0x60,
          "Actually only 2 bits", HFILL  }},
        { &hf_dlblock_ndi,
          { "NDI", "dlblock.ndi",
          FT_UINT8, BASE_DEC, NULL, 0x01,
          NULL, HFILL  }},
        { &hf_dlblock_k1,
          { "k1", "dlblock.k1",
          FT_UINT8, BASE_DEC, NULL, 0x0f,
          NULL, HFILL  }},

        { &hf_dlblock_rar_indication,
          { "RAR Indication", "dlblock.rar-indication",
          FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL  }},
        { &hf_dlblock_parity_check_passed,
          { "Parity check passed", "dlblock.parity-check-passed",
          FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL  }},
        { &hf_dlblock_term_no_change_hard_bits,
          { "Term No Change In HardBits", "dlblock.term-no-change-in-hard-bits",
          FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL  }},
        { &hf_dlblock_term_parity_check_passed,
          { "Term Parity Check Passed", "dlblock.term-parity-check-passed",
          FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL  }},
        { &hf_dlblock_transport_block_crc,
          { "Transport Block CRC", "dlblock.transport-block-crc",
          FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL  }},
        { &hf_dlblock_transport_block,
          { "Transport Block", "dlblock.transport-block",
          FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL  }},
        { &hf_dlblock_code_block_crc,
          { "Code Block CRC", "dlblock.code-block-crc",
          FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL  }},
        { &hf_dlblock_new_data_ind,
          { "New Data Ind", "dlblock.new-data-ind",
          FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL  }},

        { &hf_dlblock_payload,
          { "Payload", "dlblock.payload",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_dlblock_first_frame,
          { "First frame", "dlblock.first-frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_dlblock_fragment,
          { "DL Block block", "dlblock.code-block", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_dlblock_fragments,
          { "DL Blocks", "dlblock.code-blocks", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_dlblock_fragment_overlap,
          { "Fragment overlap", "dlblock.fragment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
        { &hf_dlblock_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap", "dlblock.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_dlblock_fragment_multiple_tails,
          { "Multiple tail fragments found", "dlblock.fragment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_dlblock_fragment_too_long_fragment,
          { "Fragment too long", "dlblock.fragment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},
        { &hf_dlblock_fragment_error,
          { "Defragmentation error", "dlblock.fragment.error", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_dlblock_fragment_count,
          { "Fragment count", "dlblock.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_dlblock_reassembled_in,
          { "Reassembled MAC-NR in frame", "dlblock.reassembled_in", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "This MAC-NR packet is reassembled in this frame", HFILL }},
        { &hf_dlblock_reassembled_length,
          { "Reassembled MAC-NR length", "dlblock.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x0, "The total length of the reassembled payload", HFILL }},
        { &hf_dlblock_reassembled_data,
          { "Reassembled codeblocks", "dlblock.reassembled.data", FT_BYTES, BASE_NONE,
            NULL, 0x0, "The reassembled payload", HFILL }},


    };

    static gint *ett[] =
    {
        &ett_dlblock,
        &ett_dlblock_fragments,
        &ett_dlblock_fragment
    };

    module_t *dlblock_module;

    static ei_register_info ei[] = {
        { &ei_dl_block_cb_crc_error, { "dlblock.cb-crc-error", PI_CHECKSUM, PI_WARN, "Incorrect CB Checksum", EXPFILL }},
        { &ei_dl_block_tb_crc_error, { "dlblock.tb-crc-error", PI_CHECKSUM, PI_WARN, "Incorrect TB Checksum", EXPFILL }},
    };

    expert_module_t* expert_dlblock;

    proto_dlblock = proto_register_protocol("DL Block", "DLBLOCK", "dlblock");


    proto_register_field_array(proto_dlblock, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_dlblock = expert_register_protocol(proto_dlblock);
    expert_register_field_array(expert_dlblock, ei, array_length(ei));

    dlblock_handle = register_dissector("dlblock", dissect_dlblock, proto_dlblock);

    /* Preferences */
    dlblock_module = prefs_register_protocol(proto_dlblock, NULL);

    // Reassemble code blocks in MAC PDUs.
    prefs_register_bool_preference(dlblock_module, "dissect_mac_pdus",
        "Reassemble code blocks into MAC PDUs and dissect",
        "",
        &global_dlblock_dissect_mac_pdus);


    register_init_routine(&dlblock_init_protocol);
    register_cleanup_routine(&dlblock_cleanup_protocol);


    // Register reassembly table.
    reassembly_table_register(&dlblock_reassembly_table,
                              &dlblock_reassembly_table_functions);

}

void proto_reg_handoff_dlblock(void)
{
    dlblock_handle = create_dissector_handle(dissect_dlblock, proto_dlblock);
    // TODO: what is the a good default port number?
    dissector_add_uint_range_with_preference("udp.port", "6666", dlblock_handle);

    mac_nr_handle = find_dissector("mac-nr");
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
