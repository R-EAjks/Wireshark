/* packet-ulgrant.c
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

//#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>

#include "packet-mac-nr.h"

// TODO:
// - ?


/*
 * Based upon the type NRUplinkGrant_t from PhyMacMsg.h
 *
typedef struct
{
    // Transport block and code block segmentation information
    // MAC generates a transport block of A bits in 6.2.1, TS38.212
    //
    // For single code block, A = SizeInBytesOfCodeblock*8
    //
    // For multiple code blocks, A = NumberOfCodeblocks*SizeInBytesOfCodeblock*8 - L
    // The first (NumberOfCodeblocks-l) code blocks have SizeInBytesOfCodeblock*8 bits
    // The last code block has SizeInBytesOfCodeblock*8 - L bits
    // L=24 is the length of the TB CRC
    //
    uint8_t     Reserved0;
    uint8_t     NumberOfCodeblocks;     // Total number of CBs in the transport block
    uint8_t     ReTxIndicator;          // 0:NewTx, 1:ReTx
    uint8_t     SlotNumberInFrame;      // 4 MSBs are subframe number, Mu LSBs are slot number
    uint8_t     BwpId;                  // [0..3]
    uint8_t     BufferIndex;            // [0..7] for 8 buffers per BWP
    uint16_t    SizeInBytesOfCodeblock; // Number of bytes of each code block, except that the last CB includes the TB CRC in multiple CB case

    uint32_t    DataOffsetInBytes;      // Data offset into the FPGA buffer for this TB
    uint16_t    UE_ID;                  // UE identifier
    uint16_t    RNTI;                   // RNTI value

    // The above data fields are aligned with NRULFpgaPuschDataHeader_t

    uint8_t     HarqProcessNumber;      // [0..15]
    uint8_t     RNTI_Type;              // NRDefsRNTI_Type_t
    uint8_t     GrantType;              // NRDefsUlGrantType_t
    uint8_t     CarrierId;              // Carrier identifier
    uint8_t     CellIndex;              // Serving cell index
    uint8_t     SubcarrierSpacing;      // SubcarrierSpacing_t
    uint16_t    PuschDurationInUs;      // PUSCH Duration in microseconds

    uint32_t    TimeInMs;               // Time stamp in milliseconds
    uint8_t     WaitingForRAR;
    uint8_t     CellGroupId;               // Indicate the cellGroupId this grant is for
    uint16_t    Reserved0;

    uint8_t     PhrLength;
#define MAX_PHR_BYTES 21                 // enough for Multiple Entry PHR (one-byte C flags)
    uint8_t     PhrSubPdu[MAX_PHR_BYTES];
} NRUplinkGrant_t;

 *
 * Based upon the type NRULFpgaPuschDataHeader_t from NRULFpga.h
 *

// PUSCH header in the data interface between hi-MAC and UL FPGA
typedef struct
{
    // Transport block and code block segmentation information
    // Each CB has SizeInBytesOfCodeblock bytes of data from MAC, except the last CB contains a L-bits place holder for the TB CRC
    // TB size is (NumberOfCodeblocks*SizeInBytesOfCodeblock - L/8) bytes (A bits in 6.2.1, TS38.212)
    // L=24 if TBS > 3824 bits, otherwise L =16
    uint8_t     CodeblockIndex;         // Index of this CB, 0..(NumberOfCodeblocks-1)
    uint8_t     NumberOfCodeblocks;     // Total number of CBs in the transport block
    uint8_t     ReTxIndicator;          // 0:NewTx, 1:ReTx
    uint8_t     SlotNumberInFrame;      // 4 MSBs are subfarme number, Mu LSBs are slot number
    uint8_t     CarrierId;              // Carrier Id
    uint8_t     BufferIndex;            // [0..7] for 8 buffers per BWP
    uint16_t    SizeInBytesOfCodeblock; // Number of bytes of each code block excluding CB CRC, (K'/8)-3

    uint32_t    DataOffsetInBytes;      // Data offset into the FPGA buffer for this TB
    uint16_t    UE_ID;
    uint16_t    RNTI;

} PACK_THIS NRULFpgaPuschDataHeader_t;
 */


static dissector_handle_t ulgrant_handle;
static dissector_handle_t uldata_handle;

static dissector_handle_t mac_nr_handle;

/*******************************/
/* UL Grant fields             */
static int proto_ulgrant           = -1;

static int hf_ulgrant_puschindex = -1;
static int hf_ulgrant_numberofcodeblocks = -1;
static int hf_ulgrant_retxindicator= -1;
static int hf_ulgrant_slotnumberinframe = -1;
static int hf_ulgrant_bwpid = -1;
static int hf_ulgrant_bufferindex = -1;
static int hf_ulgrant_sizeinbytesofcodeblock = -1;

static int hf_ulgrant_dataoffsetinbytes = -1;
static int hf_ulgrant_ue_id = -1;
static int hf_ulgrant_rnti = -1;

static int hf_ulgrant_harqprocessnumber = -1;
static int hf_ulgrant_rnti_type = -1;
static int hf_ulgrant_granttype = -1;
static int hf_ulgrant_carrierid = -1;
static int hf_ulgrant_cellindex = -1;
static int hf_ulgrant_subcarrierspacing = -1;
static int hf_ulgrant_puschdurationinus = -1;

static int hf_ulgrant_timeinms = -1;
static int hf_ulgrant_delta_timeinms = -1;
static int hf_ulgrant_waitingforrar = -1;
static int hf_ulgrant_cellgroupid = -1;
static int hf_ulgrant_reserved0 = -1;
static int hf_ulgrant_phrlength = -1;
static int hf_ulgrant_phrbytes = -1;

static int hf_ulgrant_l1app_delay = -1;

static int hf_ulgrant_first_data_frame = -1;
static int hf_ulgrant_first_data_frame_delay = -1;
static int hf_ulgrant_last_data_frame = -1;
static int hf_ulgrant_last_data_frame_delay = -1;

/* Subtrees. */
static int ett_ulgrant = -1;



static const value_string rnti_type_vals[] =
{
    { 0, "NOT ALLOCATED"},
    { 1, "SI_RNTI"},
    { 2, "P_RNTI"},
    { 3, "RA_RNTI"},
    { 4, "TEMPORARY_C_RNTI"},
    { 5, "C_RNTI"},
    // TODO: others..
    { 0, NULL }
};

static const value_string ulgrant_type_vals[] =
{
    { 0, "PDCCH"},
    { 1, "RAR"},
    { 2, "CS"},
    { 0, NULL }
};


/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

// Timing defaults supplied by Fatma.
static gint global_uldata_first_expected_delay = 200;
static gint global_uldata_last_expected_delay = 500;
static gint global_uldata_previous_expected_delay = 15;

static gint global_uldata_dissect_mac_pdus = FALSE;

static gboolean global_uldata_match_by_dataoffset = FALSE;
static gboolean global_ulgrant_l1app_delay = FALSE;


//------------------------------------------------------------------
// Global vars maintained during first pass.
static guint32  g_first_data_frame = 0;

// Refers to time/timestamp of previous grant (for any UE).
static guint32  g_previous_time_in_ms = 0;
nstime_t        g_previous_time_in_ms_ts;



// State of a grant.  Used both during the first pass, and for storing results
// to show for grant frames later.
typedef struct {
    guint32     grant_frame;
    nstime_t    grant_time;
    guint32     l1app_delay;
    guint8      harq_id;

    guint32     first_data_frame;
    nstime_t    first_data_time;

    guint32     last_data_frame;
    nstime_t    last_data_time;
    guint32     last_block_seen;

    gint32      time_in_ms_delta;
    guint32     us_since_previous_grant;

    guint       number_data_frames;
} GrantState_t;

// Go from GrantKey_t -> GrantState_t
static GHashTable *ulgrant_grants_hash = NULL;

// Store from grant frame -> GrantState_t
static GHashTable *ulgrant_grants_result_hash = NULL;

// Called with key fields by both ulgrant and uldata dissectors.
static gpointer makeGrantKey(guint8 slotNumberInFrame, guint8 bufferIndex, guint8 carrierId, guint16 ueid, guint8 numCodeBlocks, guint32 dataOffset)
{
    if (global_uldata_match_by_dataoffset) {
        return GUINT_TO_POINTER(dataOffset);
    }
    else {
        guint value = slotNumberInFrame +
                      (bufferIndex << 5) +
                      (carrierId << 10) +
                      (ueid << 16) +
                      (numCodeBlocks << 25);
        return GUINT_TO_POINTER(value);
    }
}

static gint32 get_us_diff(nstime_t begin, nstime_t end)
{
    time_t micro_begin = (begin.secs*1000000) + (time_t)(begin.nsecs/1000.0);
    time_t micro_end =   (end.secs*1000000) +   (time_t)(end.nsecs/1000.0);

    return (int)(micro_end-micro_begin);
}



// State to associate with adata frame to show in subsequent passes.
typedef struct {
    guint32     grant_frame;
    guint32     us_since_grant;

    guint32     previous_data_frame;
    guint32     us_since_previous_data;

    gboolean    block_number_error;
    guint32     expected_block_number;

    guint8      harqId;
} DataState_t;

// Store from data frame -> DataState_t*
static GHashTable *uldata_result_hash = NULL;




/*******************************/
/* UL Data fields             */
static int proto_uldata           = -1;

static int hf_uldata_codeblockindex = -1;
static int hf_uldata_numberofcodeblocks = -1;
static int hf_uldata_retxindicator= -1;
static int hf_uldata_slotnumberinframe = -1;
static int hf_uldata_carrierid = -1;
static int hf_uldata_bufferindex = -1;
static int hf_uldata_sizeinbytesofcodeblock = -1;
static int hf_uldata_dataoffsetinbytes = -1;
static int hf_uldata_ue_id = -1;
static int hf_uldata_rnti = -1;
static int hf_uldata_payload = -1;

static int hf_uldata_grant_frame = -1;
static int hf_uldata_grant_frames_since_grant = -1;
static int hf_uldata_grant_delay = -1;
static int hf_uldata_previous_frame = -1;
static int hf_uldata_previous_frame_delay = -1;

static int hf_uldata_fragments = -1;
static int hf_uldata_fragment = -1;
static int hf_uldata_fragment_overlap = -1;
static int hf_uldata_fragment_overlap_conflict = -1;
static int hf_uldata_fragment_multiple_tails = -1;
static int hf_uldata_fragment_too_long_fragment = -1;
static int hf_uldata_fragment_error = -1;
static int hf_uldata_fragment_count = -1;
static int hf_uldata_reassembled_in = -1;
static int hf_uldata_reassembled_length = -1;
static int hf_uldata_reassembled_data = -1;


/* Subtrees. */
static gint ett_uldata = -1;
static gint ett_uldata_fragments = -1;
static gint ett_uldata_fragment  = -1;


static const fragment_items uldata_frag_items = {
  &ett_uldata_fragment,
  &ett_uldata_fragments,
  &hf_uldata_fragments,
  &hf_uldata_fragment,
  &hf_uldata_fragment_overlap,
  &hf_uldata_fragment_overlap_conflict,
  &hf_uldata_fragment_multiple_tails,
  &hf_uldata_fragment_too_long_fragment,
  &hf_uldata_fragment_error,
  &hf_uldata_fragment_count,
  &hf_uldata_reassembled_in,
  &hf_uldata_reassembled_length,
  &hf_uldata_reassembled_data,
  "UL data fragments"
};



/* Expert info */
/* TODO: most of these should be in uldata! */
static expert_field ei_ulgrant_first_data_delay = EI_INIT;
static expert_field ei_ulgrant_last_data_delay = EI_INIT;
static expert_field ei_ulgrant_subsequent_data_delay = EI_INIT;
static expert_field ei_ulgrant_unexpected_block_number = EI_INIT;
static expert_field ei_ulgrant_time_in_ms_disparity = EI_INIT;


/* Forward declarations we need below */
void proto_register_ulgrant(void);
void proto_reg_handoff_ulgrant(void);
static gint dissect_ulgrant(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

void proto_register_uldata(void);
void proto_reg_handoff_uldata(void);
static gint dissect_uldata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);


/* Reassembly state */
static reassembly_table uldata_reassembly_table;

static guint uldata_grant_hash(gconstpointer k _U_)
{
    // Already passing in as key, so just convert to uint.
    return GPOINTER_TO_UINT(k);
}


static gpointer uldata_grant_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data _U_)
{
    return (gpointer)data;
}

static gpointer uldata_grant_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_,
                                            const void *data)
{
    return (gpointer)data;
}

static void uldata_grant_free_temporary_key(gpointer ptr _U_)
{
}

static void uldata_grant_free_persistent_key(gpointer ptr _U_)
{
}

static reassembly_table_functions uldata_reassembly_table_functions =
{        uldata_grant_hash,
         g_direct_equal,
         uldata_grant_temporary_key,
         uldata_grant_persistent_key,
         uldata_grant_free_temporary_key,
         uldata_grant_free_persistent_key
};

/* Initializes the hash tables each time a new
 * file is loaded or re-loaded in wireshark */
static void ulgrant_init_protocol(void)
{
    g_first_data_frame = 0;
    g_previous_time_in_ms = 0;
    g_previous_time_in_ms_ts.nsecs = 0;
    g_previous_time_in_ms_ts.secs = 0;

    ulgrant_grants_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    ulgrant_grants_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    uldata_result_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

/* Cleanup */
static void ulgrant_cleanup_protocol(void)
{
    g_hash_table_destroy(ulgrant_grants_hash);
    g_hash_table_destroy(ulgrant_grants_result_hash);
    g_hash_table_destroy(uldata_result_hash);
}



// Main dissection function.

static gint
dissect_ulgrant( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    proto_item *ti;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ULGRANT");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *root_ti = proto_tree_add_item(tree, proto_ulgrant, tvb, 0, -1, ENC_NA);
    proto_tree *ulgrant_tree = proto_item_add_subtree(root_ti, ett_ulgrant);

    // PUSCH Index
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_puschindex, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Number of code blocks
    guint numberofcodeblocks;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_numberofcodeblocks, tvb, offset, 1, ENC_BIG_ENDIAN, &numberofcodeblocks);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Codeblocks=%3u", numberofcodeblocks);
    offset++;

    // Retx
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_retxindicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Slot number in frame
    guint32 slotNumberInFrame;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_slotnumberinframe, tvb, offset, 1, ENC_BIG_ENDIAN, &slotNumberInFrame);
    offset++;

    // BwpId
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_bwpid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Buffer Index
    guint bufferIndex;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_bufferindex, tvb, offset, 1, ENC_BIG_ENDIAN, &bufferIndex);
    offset++;

    // Size in bytes of code block
    guint sizeofcodeblock;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_sizeinbytesofcodeblock, tvb, offset, 2, ENC_BIG_ENDIAN, &sizeofcodeblock);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   CodeBlockSize=%4u", sizeofcodeblock);
    offset += 2;

    // Data offset in bytes
    guint32 data_offset;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_dataoffsetinbytes, tvb, offset, 4, ENC_BIG_ENDIAN, &data_offset);
    offset += 4;

    // UE Id
    guint ueid;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_ue_id, tvb, offset, 2, ENC_BIG_ENDIAN, &ueid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   UEId=%4u", ueid);
    offset += 2;

    // RNTI
    guint rnti;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_rnti, tvb, offset, 2, ENC_BIG_ENDIAN, &rnti);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   RNTI=%4u", rnti);
    offset += 2;

    // Harq Process Number
    guint harqId;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_harqprocessnumber, tvb, offset, 1, ENC_BIG_ENDIAN, &harqId);
    offset++;

    // RNTI Type
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_rnti_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Grant Type
    guint granttype;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_granttype, tvb, offset, 1, ENC_BIG_ENDIAN, &granttype);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   Type=%5s", val_to_str_const(granttype, ulgrant_type_vals, "Unknown"));
    offset++;

    // CarrierId
    guint carrierId;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_carrierid, tvb, offset, 1, ENC_BIG_ENDIAN, &carrierId);
    offset++;

    // CellIndex
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_cellindex, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // SubcarrierSpacing
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_subcarrierspacing, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Pusch duration in us
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_puschdurationinus, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // Time in ms
    guint32 time_in_ms;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_timeinms, tvb, offset, 4, ENC_BIG_ENDIAN, &time_in_ms);
    offset += 4;

    // WaitingForRAR
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_waitingforrar, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    // cellgroupid
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_cellgroupid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    // reserved0
    proto_tree_add_item(ulgrant_tree, hf_ulgrant_reserved0, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // PHR Length
    guint32 phrLength;
    proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_phrlength, tvb, offset, 1, ENC_BIG_ENDIAN, &phrLength);
    offset += 1;

    if (phrLength) {
        // PHR Bytes
        proto_tree_add_item(ulgrant_tree, hf_ulgrant_phrbytes, tvb, offset, phrLength, ENC_NA);
    }
    offset += phrLength;


    // l1app_delay (written in little endian..)
    guint32 l1app_delay;
    if (global_ulgrant_l1app_delay) {
        ti = proto_tree_add_item_ret_uint(ulgrant_tree, hf_ulgrant_l1app_delay, tvb, offset+14, 4, ENC_BIG_ENDIAN, &l1app_delay);
        offset++;
        col_append_fstr(pinfo->cinfo, COL_INFO, "   L1_App delay was %u us", l1app_delay);
        PROTO_ITEM_SET_GENERATED(ti);
    }



    // On first pass through, add mapping to table.
    if (!PINFO_FD_VISITED(pinfo)) {
        // Initialise grant state.
        GrantState_t *grantState = wmem_new0(wmem_file_scope(), GrantState_t);
        grantState->grant_frame = pinfo->num;
        grantState->grant_time = pinfo->abs_ts;
        grantState->l1app_delay = l1app_delay;
        grantState->harq_id = harqId;
        grantState->number_data_frames = 0;
        grantState->last_block_seen = -1;   // i.e. expecting 0 next!

        // Diff for first grant is not meaningful..
        if (g_previous_time_in_ms) {
            grantState->time_in_ms_delta = time_in_ms - g_previous_time_in_ms;
            grantState->us_since_previous_grant = get_us_diff(g_previous_time_in_ms_ts, pinfo->abs_ts);
        }

        // Set previous entries to current.
        g_previous_time_in_ms = time_in_ms;
        g_previous_time_in_ms_ts = pinfo->abs_ts;

        // Add to table.
        g_hash_table_insert(ulgrant_grants_hash, makeGrantKey(slotNumberInFrame, bufferIndex, carrierId, ueid, numberofcodeblocks, data_offset), grantState);
    }
    else {
        // Subsequent passes, find struct.
        GrantState_t *grantState = (GrantState_t*)g_hash_table_lookup(ulgrant_grants_result_hash, GUINT_TO_POINTER(pinfo->num));
        if (grantState != NULL) {
            // First data frame
            ti = proto_tree_add_uint(ulgrant_tree, hf_ulgrant_first_data_frame,
                                     tvb, 0, 0, grantState->first_data_frame);
            PROTO_ITEM_SET_GENERATED(ti);

            // Delay until first data frame seen
            ti = proto_tree_add_uint(ulgrant_tree, hf_ulgrant_first_data_frame_delay,
                                     tvb, 0, 0,
                                     get_us_diff(grantState->grant_time, grantState->first_data_time));
            PROTO_ITEM_SET_GENERATED(ti);


            // Last data frame
            ti = proto_tree_add_uint(ulgrant_tree, hf_ulgrant_last_data_frame,
                                     tvb, 0, 0, grantState->last_data_frame);
            PROTO_ITEM_SET_GENERATED(ti);

            // Delay until last data frame seen
            ti = proto_tree_add_uint(ulgrant_tree, hf_ulgrant_last_data_frame_delay,
                                     tvb, 0, 0,
                                     get_us_diff(grantState->grant_time, grantState->last_data_time));
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_int(ulgrant_tree, hf_ulgrant_delta_timeinms, tvb, 0, 0, grantState->time_in_ms_delta);
            PROTO_ITEM_SET_GENERATED(ti);

            if (((grantState->time_in_ms_delta*1000) - grantState->us_since_previous_grant) > 1000) {
                expert_add_info_format(pinfo, ti, &ei_ulgrant_time_in_ms_disparity,
                                       "TimeInMs diff is %d, but that grant was %u us ago)",
                                       grantState->time_in_ms_delta, grantState->us_since_previous_grant);
            }
        }
    }

    return tvb_captured_length(tvb);
}

/* uldata main dissection function */
static gint
dissect_uldata( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ULDATA");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *root_ti = proto_tree_add_item(tree, proto_uldata, tvb, 0, -1, ENC_NA);
    proto_tree *uldata_tree = proto_item_add_subtree(root_ti, ett_uldata);

    // CodeblockIndex
    guint codeblockindex;
    proto_item *ti_codeblockindex = proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_codeblockindex, tvb, offset, 1, ENC_BIG_ENDIAN, &codeblockindex);
    col_append_fstr(pinfo->cinfo, COL_INFO, "CodeblockIndex=%5u", codeblockindex);
    offset++;

    // Number of code blocks
    guint numberofcodeblocks;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_numberofcodeblocks, tvb, offset, 1, ENC_BIG_ENDIAN, &numberofcodeblocks);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   Codeblocks=%3u", numberofcodeblocks);
    offset++;

    // Retx
    proto_tree_add_item(uldata_tree, hf_uldata_retxindicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Slot number in frame
    guint32 slotNumberInFrame;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_slotnumberinframe, tvb, offset, 1, ENC_BIG_ENDIAN, &slotNumberInFrame);
    offset++;

    // CarrierId
    guint carrierId;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_carrierid, tvb, offset, 1, ENC_BIG_ENDIAN, &carrierId);
    offset++;

    // Buffer Index
    guint bufferIndex;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_bufferindex, tvb, offset, 1, ENC_BIG_ENDIAN, &bufferIndex);
    offset++;

    // Size in bytes of code block
    guint sizeofcodeblock;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_sizeinbytesofcodeblock, tvb, offset, 2, ENC_BIG_ENDIAN, &sizeofcodeblock);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   CodeBlockSize=%4u", sizeofcodeblock);
    offset += 2;

    // Data offset in bytes
    guint32 data_offset;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_dataoffsetinbytes, tvb, offset, 4, ENC_BIG_ENDIAN, &data_offset);
    offset += 4;

    // UE Id
    guint ueid;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_ue_id, tvb, offset, 2, ENC_BIG_ENDIAN, &ueid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   UEId=%4u", ueid);
    offset += 2;

    // RNTI
    guint rnti;
    proto_tree_add_item_ret_uint(uldata_tree, hf_uldata_rnti, tvb, offset, 2, ENC_BIG_ENDIAN, &rnti);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   RNTI=%4u", rnti);
    offset += 2;

    // Payload
    proto_tree_add_item(uldata_tree, hf_uldata_payload, tvb, offset, -1, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, "   (payload=%4u bytes)", tvb_reported_length_remaining(tvb, offset));

    GrantState_t *grantState = NULL;

    // On first pass through, look up grant, and update its state.
    if (!PINFO_FD_VISITED(pinfo)) {
        // Lookup grant state.
        grantState = (GrantState_t*)g_hash_table_lookup(ulgrant_grants_hash, makeGrantKey(slotNumberInFrame, bufferIndex, carrierId, ueid, numberofcodeblocks, data_offset));
        if (grantState) {

            // On first pass through, add mapping to data result table.
            DataState_t *dataState = wmem_new0(wmem_file_scope(), DataState_t);
            dataState->grant_frame = grantState->grant_frame;
            dataState->us_since_grant = get_us_diff(grantState->grant_time, pinfo->abs_ts);
            dataState->harqId = grantState->harq_id;

            // Is this the first frame?
            if (grantState->number_data_frames == 0) {
                grantState->first_data_frame = pinfo->num;
                grantState->first_data_time = pinfo->abs_ts;
            }

            grantState->number_data_frames++;

            // This is the most recent frame.
            if (grantState->number_data_frames > 1) {
                // Store previous last details in struct.
                dataState->previous_data_frame = grantState->last_data_frame ;
                dataState->us_since_previous_data = get_us_diff(grantState->last_data_time, pinfo->abs_ts);
            }
            else {
                dataState->previous_data_frame = 0;
                dataState->us_since_previous_data  = 0;
            }
            grantState->last_data_frame = pinfo->num;
            grantState->last_data_time = pinfo->abs_ts;

            if (g_first_data_frame == 0) {
                g_first_data_frame = pinfo->num;
            }

            // Check for unexpected block number.
            if ((g_first_data_frame != pinfo->num) && (codeblockindex != (grantState->last_block_seen+1))) {
                dataState->block_number_error = TRUE;
                dataState->expected_block_number = grantState->last_block_seen+1;
            }
            else {
                dataState->block_number_error = FALSE;
            }

            // Regardless, this is where we are now.
            grantState->last_block_seen = codeblockindex;

            // If this is the last code-block, deep-copy state and associate with grant frame.
            if (codeblockindex == numberofcodeblocks-1) {

                GrantState_t *grantResultState = wmem_new(wmem_file_scope(), GrantState_t);
                memcpy(grantResultState, grantState, sizeof(GrantState_t));

                // Add to result table.
                g_hash_table_insert(ulgrant_grants_result_hash, GUINT_TO_POINTER(grantState->grant_frame), grantResultState);
            }

            // Add to result table.
            g_hash_table_insert(uldata_result_hash, GUINT_TO_POINTER(pinfo->num), dataState);
        }
    }

    // Look up data result data, and add to tree.
    DataState_t *dataState = (DataState_t*)g_hash_table_lookup(uldata_result_hash,
                                                               GUINT_TO_POINTER(pinfo->num));
    if (dataState) {
        proto_item *ti;

        // Link back to grant
        proto_item *grant_ti = proto_tree_add_uint(uldata_tree, hf_uldata_grant_frame,
                                                   tvb, 0, 0, dataState->grant_frame);
        PROTO_ITEM_SET_GENERATED(grant_ti);

        // Frames since grant
        ti = proto_tree_add_uint(uldata_tree, hf_uldata_grant_frames_since_grant,
                                 tvb, 0, 0, pinfo->num - dataState->grant_frame);
        PROTO_ITEM_SET_GENERATED(ti);


        // Delay since grant
        ti = proto_tree_add_uint(uldata_tree, hf_uldata_grant_delay,
                                 tvb, 0, 0, dataState->us_since_grant);
        PROTO_ITEM_SET_GENERATED(ti);
        col_append_fstr(pinfo->cinfo, COL_INFO, "   [%u us since grant]", dataState->us_since_grant);

        if (codeblockindex > 0) {
            // Link back to previous data frame
            ti = proto_tree_add_uint(uldata_tree, hf_uldata_previous_frame,
                                     tvb, 0, 0, dataState->previous_data_frame);
            PROTO_ITEM_SET_GENERATED(ti);

            // Delay since previous data frame
            ti = proto_tree_add_uint(uldata_tree, hf_uldata_previous_frame_delay,
                                     tvb, 0, 0, dataState->us_since_previous_data);
            PROTO_ITEM_SET_GENERATED(ti);

            // If delayed, warn using expert info.
            if (dataState->us_since_previous_data >= (guint)global_uldata_previous_expected_delay) {
                expert_add_info_format(pinfo, ti, &ei_ulgrant_subsequent_data_delay,
                                       "Subsequent data delayed by %u us (threshold in preference is %u)",
                                       dataState->us_since_previous_data, global_uldata_previous_expected_delay);
            }
        }
        else {
            // For first data response, also report if delayed.
            if (dataState->us_since_grant >= (guint)global_uldata_first_expected_delay) {
                expert_add_info_format(pinfo, ti, &ei_ulgrant_first_data_delay,
                                       "First data delayed by %u us (threshold in preference is %u)",
                                       dataState->us_since_grant, global_uldata_first_expected_delay);
            }
        }

        // Also warn if last block is late.
        if (codeblockindex == (numberofcodeblocks-1)) {
            if (dataState->us_since_grant   >= (guint)global_uldata_last_expected_delay) {
                expert_add_info_format(pinfo, grant_ti, &ei_ulgrant_last_data_delay,
                                       "Last data delayed by %u us (threshold in preference is %u)",
                                       dataState->us_since_grant, global_uldata_last_expected_delay);
            }
        }

        // And warn if block number wasn't as expected.
        if (dataState->block_number_error) {
            expert_add_info_format(pinfo, ti_codeblockindex, &ei_ulgrant_unexpected_block_number,
                                   "Expected block number %u, got %u instead)",
                                   dataState->expected_block_number, codeblockindex);
        }
    }

    // Reassembly.
    if (global_uldata_dissect_mac_pdus && dataState) {

        // Set fragmented flag.
        gboolean save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        fragment_head *fh;
        guint frag_data_len = tvb_reported_length_remaining(tvb, offset);
        // If multiple code blocks, don't reassembly last 3 bytes as they are CRC.
        if (codeblockindex && (codeblockindex == (numberofcodeblocks-1))) {
            frag_data_len -= 3;
        }

        fh = fragment_add_seq_check(&uldata_reassembly_table, tvb, offset, pinfo,
                              dataState->grant_frame,                                          /* id */
                              // Just needs to be unique per grant..
                              GUINT_TO_POINTER(dataState->grant_frame),                        /* data */
                              codeblockindex,                                                  /* frag_number */
                              frag_data_len,                                                   /* frag_data_len */
                              (codeblockindex < (numberofcodeblocks-1))                        /* more_frags */
                              );

        gboolean update_col_info = TRUE;
        tvbuff_t *next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled MAC PDU",
                                                      fh, &uldata_frag_items,
                                                      &update_col_info, uldata_tree);

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
            p_mac_nr_info->direction = DIRECTION_UPLINK;
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

    return tvb_captured_length(tvb);
}



/* Register ulgrant */

void
proto_register_ulgrant(void)
{
    static hf_register_info hf[] =
    {
        { &hf_ulgrant_puschindex,
          { "Pusch-Index", "ulgrant.pusch-index",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_numberofcodeblocks,
          { "Number of Code Blocks", "ulgrant.number-of-code-blocks",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_retxindicator,
          { "ReTx Indicator", "ulgrant.retx",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_slotnumberinframe,
          { "Slot Number in Frame", "ulgrant.slot-number-in-frame",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_bwpid,
          { "BwpId", "ulgrant.bwpid",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_bufferindex,
          { "BufferIndex", "ulgrant.buffer-index",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_sizeinbytesofcodeblock,
          { "Size in bytes of code block", "ulgrant.size-in-bytes-of-code-block",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_ulgrant_dataoffsetinbytes,
          { "Data offset", "ulgrant.data-offset",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Data offset in bytes", HFILL  }},
        { &hf_ulgrant_ue_id,
          { "UE Id", "ulgrant.ue-id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_rnti,
          { "RNTI", "ulgrant.rnti",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_ulgrant_harqprocessnumber,
          { "HARQ Process Number", "ulgrant.harq-id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_rnti_type,
          { "RNTI Type", "ulgrant.rnti-type",
          FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_granttype,
          { "Grant Type", "ulgrant.grant-type",
          FT_UINT8, BASE_DEC, VALS(ulgrant_type_vals), 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_carrierid,
          { "CarrierId", "ulgrant.carrier-id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_cellindex,
          { "CellIndex", "ulgrant.cell-index",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_subcarrierspacing,
          { "SubcarrerSpacing", "ulgrant.subcarrier-spacing",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_puschdurationinus,
          { "PUSCH Duration in Us", "ulgrant.pusch-duration",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_ulgrant_l1app_delay,
          { "L1_App delay", "ulgrant.l1app-delay",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Delay from time grant is sent from PHY to when frame is sent to high-mac", HFILL  }},


        { &hf_ulgrant_timeinms,
          { "Time in ms", "ulgrant.time-in-ms",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_delta_timeinms,
          { "Delta Time in ms", "ulgrant.delta-time-in-ms",
          FT_INT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_ulgrant_waitingforrar,
          { "Waiting for RAR", "ulgrant.waiting-for-rar",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_cellgroupid,
          { "CellGroupId", "ulgrant.cellgroupid",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_reserved0,
          { "Reserved0", "ulgrant.reserved0",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_phrlength,
          { "PHRLength", "ulgrant.phrlength",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_phrbytes,
          { "PHR Bytes", "ulgrant.phrbytes",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},


        // Generated/tracking fields.
        { &hf_ulgrant_first_data_frame,
          { "First data frame", "ulgrant.first-data-frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_first_data_frame_delay,
          { "First data frame delay (us)", "ulgrant.first-data-frame-delay",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_ulgrant_last_data_frame,
          { "Last data frame", "ulgrant.last-data-frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_ulgrant_last_data_frame_delay,
          { "Last data frame delay (us)", "ulgrant.last-data-frame-delay",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},
    };

    static gint *ett[] =
    {
        &ett_ulgrant,
    };

    static ei_register_info ei[] = {
        { &ei_ulgrant_first_data_delay,        { "ulgrant.first-data-delay",        PI_SEQUENCE, PI_WARN, "First data delayed", EXPFILL }},
        { &ei_ulgrant_last_data_delay,         { "ulgrant.last-data-delay",         PI_SEQUENCE, PI_WARN, "Last data delayed", EXPFILL }},
        { &ei_ulgrant_subsequent_data_delay,   { "ulgrant.subsequent-data-delay",   PI_SEQUENCE, PI_WARN, "Subsequent data delayed", EXPFILL }},
        { &ei_ulgrant_unexpected_block_number, { "ulgrant.unexpected-block-number", PI_SEQUENCE, PI_WARN, "Unexpected block number", EXPFILL }},
        { &ei_ulgrant_time_in_ms_disparity,    { "ulgrant.time-in-ms-disparity",    PI_SEQUENCE, PI_WARN, "Time diff disparity", EXPFILL }},
    };

    expert_module_t* expert_ulgrant;

    proto_ulgrant = proto_register_protocol("UL Grant", "ULGRANT", "ulgrant");

    proto_register_field_array(proto_ulgrant, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ulgrant = expert_register_protocol(proto_ulgrant);
    expert_register_field_array(expert_ulgrant, ei, array_length(ei));

    ulgrant_handle = register_dissector("ulgrant", dissect_ulgrant, proto_ulgrant);
    //ulgrant_module = prefs_register_protocol(proto_ulgrant, proto_reg_handoff_ulgrant);

    register_init_routine(&ulgrant_init_protocol);
    register_cleanup_routine(&ulgrant_cleanup_protocol);
}



/* Register uldata */

void
proto_register_uldata(void)
{
    static hf_register_info hf[] =
    {
        { &hf_uldata_codeblockindex,
          { "Code Block Index", "uldata.code-block-index",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_numberofcodeblocks,
          { "Number of Code Blocks", "uldata.number-of-code-blocks",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_retxindicator,
          { "ReTx Indicator", "uldata.retx",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_slotnumberinframe,
          { "Slot Number in Frame", "uldata.slot-number-in-frame",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_carrierid,
          { "CarrierId", "uldata.carrier-id",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_bufferindex,
          { "BufferIndex", "uldata.buffer-index",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_sizeinbytesofcodeblock,
          { "Size in bytes of code block", "uldata.size-in-bytes-of-code-block",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_uldata_dataoffsetinbytes,
          { "Data offset", "uldata.data-offset",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Data offset in bytes", HFILL  }},
        { &hf_uldata_ue_id,
          { "UE Id", "uldata.ue-id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_rnti,
          { "RNTI", "uldata.rnti",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_payload,
          { "Payload", "uldata.payload",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},

        { &hf_uldata_grant_frame,
          { "Grant frame", "uldata.grant-frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_grant_frames_since_grant,
          { "Frames since grant", "uldata.frames-since-grant",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_grant_delay,
          { "Delay since grant", "uldata.grant-delay",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Delay since grant in microseconds", HFILL  }},
        { &hf_uldata_previous_frame,
          { "Previous data frame", "uldata.previous-frame",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL  }},
        { &hf_uldata_previous_frame_delay,
          { "Delay since previous data frame", "uldata.previous-frame-delay",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Delay since previous data frame in microseconds", HFILL  }},


        { &hf_uldata_fragment,
          { "UL Code block", "uldata.code-block", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_uldata_fragments,
          { "UL Code Blocks", "uldata.code-blocks", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_uldata_fragment_overlap,
          { "Fragment overlap", "uldata.fragment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
        { &hf_uldata_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap", "uldata.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_uldata_fragment_multiple_tails,
          { "Multiple tail fragments found", "uldata.fragment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_uldata_fragment_too_long_fragment,
          { "Fragment too long", "uldata.fragment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},
        { &hf_uldata_fragment_error,
          { "Defragmentation error", "uldata.fragment.error", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_uldata_fragment_count,
          { "Fragment count", "uldata.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_uldata_reassembled_in,
          { "Reassembled MAC-NR in frame", "uldata.reassembled_in", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "This MAC-NR packet is reassembled in this frame", HFILL }},
        { &hf_uldata_reassembled_length,
          { "Reassembled MAC-NR length", "uldata.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x0, "The total length of the reassembled payload", HFILL }},
        { &hf_uldata_reassembled_data,
          { "Reassembled codeblocks", "uldata.reassembled.data", FT_BYTES, BASE_NONE,
            NULL, 0x0, "The reassembled payload", HFILL }},
    };

    static gint *ett[] =
    {
        &ett_uldata,
        &ett_uldata_fragments,
        &ett_uldata_fragment
    };

    module_t *uldata_module;

    // Register protocol.
    proto_uldata = proto_register_protocol("UL Data", "ULDATA", "uldata");
    proto_register_field_array(proto_uldata, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    //expert_uldata = expert_register_protocol(proto_uldata);
    uldata_handle = register_dissector("uldata", dissect_uldata, proto_uldata);

    /* Preferences */
    uldata_module = prefs_register_protocol(proto_uldata, NULL);

    // Threshold for warning about slow first data frame
    prefs_register_uint_preference(uldata_module, "first_data_warn",
        "Delay in microseconds for first data frame to warn about",
        "",
        10, &global_uldata_first_expected_delay);

    // Threshold for warning about slow last data frame
    prefs_register_uint_preference(uldata_module, "la_data_warn",
        "Delay in microseconds for last data frame to warn about",
        "",
        10, &global_uldata_last_expected_delay);

    // Threshold for warning about slow subsequent data frame
    prefs_register_uint_preference(uldata_module, "previous_data_warn",
        "Delay in microseconds since previous data frame to warn about",
        "",
        10, &global_uldata_previous_expected_delay);

    // Reassemble code blocks in MAC PDUs.
    prefs_register_bool_preference(uldata_module, "dissect_mac_pdus",
        "Reassemble code blocks into MAC PDUs and dissect",
        "",
        &global_uldata_dissect_mac_pdus);

    // Whether to match grants to data based upon dataOffset, or other keys
    prefs_register_bool_preference(uldata_module, "match_with_dataoffset",
        "Match UL Grants to data frames using data-offset",
        "",
        &global_uldata_match_by_dataoffset);

    // Look for l1_app delay in PHR bytes.  TODO: should be a ulgrant pref!
    prefs_register_bool_preference(uldata_module, "l1app_delay",
        "Look for L1App delay in PHR bytes",
        "",
        &global_ulgrant_l1app_delay);


    // Register reassembly table.
    reassembly_table_register(&uldata_reassembly_table,
                              &uldata_reassembly_table_functions);
}




void proto_reg_handoff_ulgrant(void)
{
    ulgrant_handle = create_dissector_handle(dissect_ulgrant, proto_ulgrant);
    dissector_add_uint_range_with_preference("udp.port", "23001", ulgrant_handle);
}

void proto_reg_handoff_uldata(void)
{
    uldata_handle = create_dissector_handle(dissect_uldata, proto_uldata);
    dissector_add_uint_range_with_preference("udp.port", "5400", uldata_handle);

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
