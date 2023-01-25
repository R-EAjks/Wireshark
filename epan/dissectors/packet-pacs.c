/* packet-pacs.c
 *
 * PACS as used by AXE.
 * Based on definitions in AXE_FPGA_specification document.
 * N.B. Written as 2 dissectors:
 * - PACS for headers
 * - CDD for command-specific message payloads
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

void proto_register_pacs(void);
void proto_register_cdd(void);

static int proto_pacs = -1;
static int proto_cdd = -1;

static int hf_pacs_preamble = -1;
static int hf_pacs_length_in_words = -1;

/* PKI Header */
static int hf_pacs_pki = -1;
static int hf_pacs_w = -1;
static int hf_pacs_raw = -1;
static int hf_pacs_utag = -1;
static int hf_pacs_uqpg = -1;
static int hf_pacs_io = -1;
static int hf_pacs_pm = -1;
static int hf_pacs_sl = -1;
static int hf_pacs_utt = -1;
static int hf_pacs_tt = -1;
static int hf_pacs_qpg = -1;

/* FPGA Header */
static int hf_pacs_fpga_header = -1;
static int hf_pacs_fpga = -1;
static int hf_pacs_port = -1;
static int hf_pacs_pacs = -1;

/* SDPC Header */
static int hf_pacs_sdpc = -1;
static int hf_pacs_f = -1;
static int hf_pacs_mf = -1;
static int hf_pacs_fragment_offset = -1;
static int hf_pacs_pacs_counter = -1;

static int hf_pacs_zero_word = -1;
static int hf_pacs_length = -1;
static int hf_pacs_cdd = -1;

static expert_field ei_pacs_wrong_length = EI_INIT;
static expert_field ei_pacs_qpg_out_of_range = EI_INIT;

/* CDD fields */
static int hf_cdd_client_id = -1;
static int hf_cdd_flow_id = -1;
static int hf_cdd_payload_checksum_start_offset = -1;
static int hf_cdd_signature_insert_offset = -1;

static int hf_cdd_tt = -1;
static int hf_cdd_p = -1;
static int hf_cdd_f = -1;
static int hf_cdd_c_type = -1;

static int hf_cdd_bssid = -1;
static int hf_cdd_wlan_type = -1;
static int hf_cdd_msdu_length = -1;
static int hf_cdd_mpdu_length = -1;
static int hf_cdd_mcs = -1;
static int hf_cdd_ip_total_length = -1;

static int hf_cdd_u = -1;
static int hf_cdd_utype = -1;
static int hf_cdd_ulength = -1;
static int hf_cdd_uoffset = -1;
static int hf_cdd_udata = -1;
static int hf_cdd_ufdata = -1;

static int hf_cdd_txdata = -1;

static int hf_cdd_nss = -1;
static int hf_cdd_sbw = -1;
static int hf_cdd_plcp = -1;
static int hf_cdd_sl = -1;
static int hf_cdd_pix = -1;

static int hf_cdd_rx_l1_info_a = -1;
static int hf_cdd_rx_l1_info_b = -1;
static int hf_cdd_rx_l1_info_c = -1;
static int hf_cdd_rx_l1_info_d = -1;

static int hf_cdd_power_a = -1;
static int hf_cdd_power_b = -1;
static int hf_cdd_power_c = -1;
static int hf_cdd_power_d = -1;
static int hf_cdd_power_e = -1;
static int hf_cdd_power_f = -1;
static int hf_cdd_power_g = -1;
static int hf_cdd_power_h = -1;

static int hf_cdd_bm = -1;
static int hf_cdd_bv = -1;
static int hf_cdd_cv = -1;
static int hf_cdd_to_ds = -1;
static int hf_cdd_fr_ds = -1;

static int hf_cdd_start_time = -1;

static int hf_cdd_plcp_0 = -1;
static int hf_cdd_plcp_1 = -1;
static int hf_cdd_plcp_2 = -1;
static int hf_cdd_plcp_3 = -1;
static int hf_cdd_plcp_4 = -1;
static int hf_cdd_plcp_5 = -1;
static int hf_cdd_plcp_6 = -1;
static int hf_cdd_plcp_7 = -1;
static int hf_cdd_plcp_8 = -1;
static int hf_cdd_plcp_9 = -1;
static int hf_cdd_plcp_10 = -1;
static int hf_cdd_plcp_11 = -1;
static int hf_cdd_plcp_12 = -1;
static int hf_cdd_plcp_13 = -1;
static int hf_cdd_plcp_14 = -1;
static int hf_cdd_plcp_15 = -1;
static int hf_cdd_plcp_16 = -1;
static int hf_cdd_plcp_17 = -1;
static int hf_cdd_plcp_18 = -1;
static int hf_cdd_plcp_19 = -1;

static int hf_cdd_rfid= -1;
static int hf_cdd_data = -1;
static int hf_cdd_data_crc = -1;

static int hf_cdd_stype = -1;
static int hf_cdd_stats_control_index = -1;
static int hf_cdd_stats_entry_control = -1;
static int hf_cdd_stats_request_time = -1;




static int hf_cdd_register_address = -1;
static int hf_cdd_register_data = -1;


/* Subtrees */
static gint ett_pacs = -1;
static gint ett_pacs_pki = -1;
static gint ett_pacs_fpga = -1;
static gint ett_pacs_sdpc = -1;

static gint ett_cdd = -1;
static gint ett_cdd_u = -1;

// PACS Message types.
typedef enum {
    Command_NULL = 0x0,
    Command_Client_Complete = 0x1,
    Command_Client_Failed_To_Complete = 0x2,
    Command_Flow_Complete = 0x3,
    Command_Flow_Trouble = 0x4,

    Command_TCP_Retransmit_Denial = 0x6,
    Command_TCP_Flow_Start = 0x7,

    Command_Register_Read = 0x10,
    Command_Register_Read_Response = 0x11,

    Command_Register_Write = 0x18,
    Command_Register_Write_Response = 0x19,

    Command_RX_Frame = 0x20,

    Command_RX_Compressed_TCP_Frame = 0x21,
    Command_RX_Compressed_non_TCP_Frame = 0x22,

    Command_RX_Partial_Frame = 0x28,

    Command_TX_Generated_Frame = 0x30,
    Comamnd_TX_Generated_Frame_Response = 0x31,

    Command_TX_STATS = 0x32,
    Command_Request_Log = 0x40,
    Command_Request_Log_Response = 0x41,

    Command_Request_Stats = 0x50,
    Command_Request_Stats_Response = 0x51,

    Command_RF_Metric = 0x60,

    Command_Info_Request = 0x68,
    Command_Info_Response = 0x69,

    Command_Sawyer_Pull_Request = 0x70,
    Command_Sawyer_Pull_Response = 0x71,
    Command_Sawyer_Push_Request = 0x72,
    Command_Sawyer_Push_Response = 0x73,

    Command_PACS_Status_Request = 0xF0,
    Command_PACS_Status_Response = 0xF1,

} PACS_Command_e;

// TODO: lots of values missing.
static const value_string pacs_command_vals[] = {
    {Command_NULL,                        "Null"},
    {Command_Client_Complete,             "Client Complete"},
    {Command_Client_Failed_To_Complete,   "Client Failed To Complete"},
    {Command_Flow_Complete,               "Flow Complete"},
    {Command_Flow_Trouble,                "Flow Trouble"},

    {Command_TCP_Retransmit_Denial,       "TCP Retransmit Denial"},
    {Command_TCP_Flow_Start,              "TCP Flow Start"},

    {Command_Register_Read,               "Register Read"},
    {Command_Register_Read_Response,      "Read Response"},

    {Command_Register_Write,              "Register Write"},
    {Command_Register_Write_Response,     "Write Response"},

    {Command_RX_Frame,                    "RX Frame"},

    {Command_RX_Compressed_TCP_Frame,     "RX Compressed TCP Frame"},
    {Command_RX_Compressed_non_TCP_Frame, "RX Compressed non TCP Frame"},

    {Command_RX_Partial_Frame,            "RX Partial Frame"},

    {Command_TX_Generated_Frame,          "TX Generated Frame"},
    {Comamnd_TX_Generated_Frame_Response, "TX Generated Frame Response"},

    {Command_TX_STATS,                    "TX STATS"},
    {Command_Request_Log,                 "Request Log"},
    {Command_Request_Log_Response,        "Request Log Response"},

    {Command_Request_Stats,               "Request Stats"},
    {Command_Request_Stats_Response,      "Request Stats Response"},

    {Command_RF_Metric,                   "RF Metric"},

    {Command_Info_Request,                "Info Request"},
    {Command_Info_Response,               "Info Response"},

    {Command_Sawyer_Pull_Request,         "Sawyer Pull Request"},
    {Command_Sawyer_Pull_Response,        "Sawyer Pull Response"},
    {Command_Sawyer_Push_Request,         "Sawyer Push Request"},
    {Command_Sawyer_Push_Response,        "Sawyer Push Response"},

    {Command_PACS_Status_Request,         "PACS Status Request"},
    {Command_PACS_Status_Response,        "PACS Status Response"},
    { 0, NULL }
};

static const value_string tt_vals[] = {
    {0,           "Basic Rate Frame"},
    {1,           "Non-QOS Frame"},
    {2,           "QOS based Frame (TID is valid)"},
    {3,           "Reserved"},
    {0,   NULL }
};

static const value_string p_vals[] = {
    {0,           "Normal ACK"},
    {1,           "No ACK"},
    {2,           "Reserved"},
    {3,           "Block ACK"},
    {0,   NULL }
};

static const value_string c_type_vals[] = {
    {0,           "Open"},
    {1,           "Crypto WEP Encapsulated"},
    {2,           "Crypto TKIP Encapsulated"},
    {3,           "Crypto CCMP Encapsulated"},
    {4,           "Crypto BIP Integrity Checked Encapsulated"},
    {5,           "Crypto GCMP Encapsulated"},
    {6,           "Reserved"},
    {7,           "Reserved"},
    {0,   NULL }
};

static const value_string u_type_vals[] = {
    {0,           "Null: Do Nothing"},
    {1,           "Checksum - standard IP checksum"},
    {2,           "Increment/Decrement"},
    {3,           "Auto Sequence Number Generator"},
    {4,           "Reserved"},
    {5,           "Reserved"},
    {6,           "Reserved"},
    {7,           "Reserved"},
    {0,   NULL }
};

static const value_string sbw_vals[] = {
    {0,           "5MHz"},
    {1,           "10MHz"},
    {2,           "20MHz"},
    {3,           "40MHz"},
    {4,           "80MHz"},
    {5,           "80+80MHz"},
    {6,           "160MHz"},
    {0,   NULL }
};

static const value_string plcp_vals[] = {
    {0,           "Legacy (CCK/OFDM) "},
    {1,           "HT Mixed Mode"},
    {2,           "HT Green Field (Not supported)"},
    {3,           "VHT Mixed Mode"},
    {4,           "HE SU"},
    {5,           "HE MU "},
    {6,           "HE TB"},
    {7,           "HE ER SU"},
    {0,   NULL }
};

static const value_string stype_vals[] = {
    {0,           "RX Port Stats (Wi-Fi and Ethernet)"},
    {1,           "TX Port Stats (Wi-Fi and Ethernet)"},
    {2,           "RX and TX Port Stats (Wi-Fi and Ethernet)"},
    {3,           "RX Client Stats (Wi-Fi only)"},
    {4,           "TX Client Stats (Wi-Fi only)"},
    {5,           "RX and TX Client Stats (Not currently supported)"},
    {6,           "RX Flow Stats (Wi-Fi and Ethernet)"},
    {7,           "TX Flow Stats (Wi-Fi and Ethernet)"},
    {8,           "RX and TX Flow Stats (Not currently supported)"},
    {9,           "Port Stats SU/MU-MIMO (Wi-Fi only)"},
    {10,          "Client Stats SU/MU-MIMO (Wi-Fi only)"},
    {0,   NULL }
};

static dissector_handle_t pacs_handle;
void proto_reg_handoff_pacs(void);

static dissector_handle_t cdd_handle;
void proto_reg_handoff_cdd(void);



//------------------------------------------------------------------------------------
// Dissect individual message type payloads (CDD)


static gint dissect_register_read_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    guint32 register_address;

    gint offset = 0;
    proto_tree_add_item_ret_uint(tree, hf_cdd_register_address, tvb, offset, 4, ENC_BIG_ENDIAN, &register_address);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (addr=0x%08x)", register_address);

    offset = 20;
    return offset;
}

static gint dissect_register_read_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    guint32 register_address, register_data;

    gint offset = 0;
    proto_tree_add_item_ret_uint(tree, hf_cdd_register_address, tvb, offset, 4, ENC_BIG_ENDIAN, &register_address);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_cdd_register_data, tvb, offset, 4, ENC_BIG_ENDIAN, &register_data);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (addr=0x%08x, data=0x%08x)", register_address, register_data);

    offset = 20;
    return offset;
}

static gint dissect_register_write_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    guint32 register_address, register_data;

    gint offset = 0;
    proto_tree_add_item_ret_uint(tree, hf_cdd_register_address, tvb, offset, 4, ENC_BIG_ENDIAN, &register_address);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_cdd_register_data, tvb, offset, 4, ENC_BIG_ENDIAN, &register_data);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (addr=0x%08x, data=0x%08x)", register_address, register_data);

    offset = 20;
    return offset;
}

static gint dissect_register_write_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    guint32 register_address, register_data;

    gint offset = 0;
    proto_tree_add_item_ret_uint(tree, hf_cdd_register_address, tvb, offset, 4, ENC_BIG_ENDIAN, &register_address);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_cdd_register_data, tvb, offset, 4, ENC_BIG_ENDIAN, &register_data);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (addr=0x%08x, data=0x%08x)", register_address, register_data);
    offset += 4;

    offset = 20;
    return offset;
}

// TX Generated Frame.
static gint dissect_tx_generated_frame(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    // TODO: missing lots of fields..
    gint offset = 0;

    // Payload Checksum Start Offset
    proto_tree_add_item(tree, hf_cdd_payload_checksum_start_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    // Signature Insert Offset
    proto_tree_add_item(tree, hf_cdd_signature_insert_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // TT
    proto_tree_add_item(tree, hf_cdd_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
    // P
    proto_tree_add_item(tree, hf_cdd_p, tvb, offset, 1, ENC_BIG_ENDIAN);
    // F
    proto_tree_add_item(tree, hf_cdd_f, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    offset++;

    // C-Type
    proto_tree_add_item(tree, hf_cdd_c_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    offset += 2;

    // Bssid
    proto_tree_add_item(tree, hf_cdd_bssid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Client ID
    guint32 client_id;
    proto_tree_add_item_ret_uint(tree, hf_cdd_client_id, tvb, offset, 2, ENC_BIG_ENDIAN, &client_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Client-ID=%u", client_id);
    offset += 2;

    // MPDU Length
    guint32 mpdu_length;
    proto_tree_add_item_ret_uint(tree, hf_cdd_mpdu_length, tvb, offset, 2, ENC_BIG_ENDIAN, &mpdu_length);
    offset += 2;

    // Flow ID
    guint32 flow_id;
    proto_tree_add_item_ret_uint(tree, hf_cdd_flow_id, tvb, offset, 2, ENC_BIG_ENDIAN, &flow_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Flow-ID=%u", flow_id);
    offset += 2;

    // WLAN Type
    proto_tree_add_item(tree, hf_cdd_wlan_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    offset += 1;

    // MSDU Length
    guint msdu_length;
    proto_tree_add_item_ret_uint(tree, hf_cdd_msdu_length, tvb, offset, 2, ENC_BIG_ENDIAN, &msdu_length);
    offset += 2;

    offset += 6;

    // IP Total Length
    guint ip_total_length;
    proto_tree_add_item_ret_uint(tree, hf_cdd_ip_total_length, tvb, offset, 2, ENC_BIG_ENDIAN, &ip_total_length);
    offset += 2;

    // 'Packet Decode'
    offset += 4;

    // N.B. These modifiers are only for flow frame generation.
    // Not client frame generation.

    // Updates.  TODO: should be 0,1,2,3
    for (int i=0; i < 4; i++) {
        gint u_start = offset;
        proto_item *u_ti = proto_tree_add_string_format(tree, hf_cdd_u,
                                              tvb, 0, 0, "", "Data Modification %u", i);
        proto_tree *u_tree = proto_item_add_subtree(u_ti, ett_cdd_u);

        guint32 u_type, u_length, u_offset;
        proto_tree_add_item_ret_uint(u_tree, hf_cdd_utype, tvb, offset, 1, ENC_BIG_ENDIAN, &u_type);
        offset++;
        proto_tree_add_item_ret_uint(u_tree, hf_cdd_ulength, tvb, offset, 1, ENC_BIG_ENDIAN, &u_length);
        offset++;
        proto_tree_add_item_ret_uint(u_tree, hf_cdd_uoffset, tvb, offset, 2, ENC_BIG_ENDIAN, &u_offset);
        offset += 2;
        proto_tree_add_item(u_tree, hf_cdd_udata, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_item_append_text(u_ti, " (%s, len=%u, offset=%u)",
                               val_to_str_const(u_type, u_type_vals, "Unknown"), u_length, u_offset);
        proto_item_set_len(u_ti, offset-u_start);
    }

    // UFData.  TODO: should be 0,1,2,3
    for (int i=0; i < 4; i++) {
        proto_tree_add_item(tree, hf_cdd_ufdata, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    // Remainder is TXData
    proto_tree_add_item(tree, hf_cdd_txdata, tvb, offset, -1, ENC_NA);


    // Summary of lengths.
    col_append_fstr(pinfo->cinfo, COL_INFO, "  [MPDU-Length=%u, MSDU-Length=%u, IP-total-Length=%u]",
                    mpdu_length, msdu_length, ip_total_length);

    return offset;
}

static gint dissect_tx_generated_frame_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    // TODO: missing lots of fields..

    gint offset = 2;

    // Client ID
    guint32 client_id;
    proto_tree_add_item_ret_uint(tree, hf_cdd_client_id, tvb, offset, 2, ENC_BIG_ENDIAN, &client_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Client-ID=%u", client_id);
    offset += 2;

    return offset;
}

static gint dissect_rx_frame(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    // TODO: missing lots of fields..
    gint offset = 0;

    // NSS
    proto_tree_add_item(tree, hf_cdd_nss, tvb, offset, 1, ENC_BIG_ENDIAN);
    // MCS
    proto_tree_add_item(tree, hf_cdd_mcs, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // SBW
    proto_tree_add_item(tree, hf_cdd_sbw, tvb, offset, 1, ENC_BIG_ENDIAN);
    // PLCP
    proto_tree_add_item(tree, hf_cdd_plcp, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // SL (Short/Long Select)
    proto_tree_add_item(tree, hf_cdd_sl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // PIX
    proto_tree_add_item(tree, hf_cdd_pix, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Rx L1 Info A
    proto_tree_add_item(tree, hf_cdd_rx_l1_info_a, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Rx L1 Info B
    proto_tree_add_item(tree, hf_cdd_rx_l1_info_b, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Rx L1 Info C
    proto_tree_add_item(tree, hf_cdd_rx_l1_info_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Rx L1 Info D
    proto_tree_add_item(tree, hf_cdd_rx_l1_info_d, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Power A
    proto_tree_add_item(tree, hf_cdd_power_a, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Power B
    proto_tree_add_item(tree, hf_cdd_power_b, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Power C
    proto_tree_add_item(tree, hf_cdd_power_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Power D
    proto_tree_add_item(tree, hf_cdd_power_d, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Power E
    proto_tree_add_item(tree, hf_cdd_power_e, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Power F
    proto_tree_add_item(tree, hf_cdd_power_f, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Power G
    proto_tree_add_item(tree, hf_cdd_power_g, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    // Power H
    proto_tree_add_item(tree, hf_cdd_power_h, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    offset++;

    // MPDU Length
    guint32 mpdu_length;
    proto_tree_add_item_ret_uint(tree, hf_cdd_mpdu_length, tvb, offset, 3, ENC_BIG_ENDIAN, &mpdu_length);
    offset +=3;

    // BM
    proto_tree_add_item(tree, hf_cdd_bm, tvb, offset, 1, ENC_BIG_ENDIAN);
    // BV
    proto_tree_add_item(tree, hf_cdd_bv, tvb, offset, 1, ENC_BIG_ENDIAN);
    // CV
    proto_tree_add_item(tree, hf_cdd_cv, tvb, offset, 1, ENC_BIG_ENDIAN);
    // TO DS
    proto_tree_add_item(tree, hf_cdd_to_ds, tvb, offset, 1, ENC_BIG_ENDIAN);
    // FR DS
    proto_tree_add_item(tree, hf_cdd_fr_ds, tvb, offset, 1, ENC_BIG_ENDIAN);
    // 3 bits unused
    offset++;

    // Bssid
    proto_tree_add_item(tree, hf_cdd_bssid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Client ID
    guint32 client_id;
    proto_tree_add_item_ret_uint(tree, hf_cdd_client_id, tvb, offset, 2, ENC_BIG_ENDIAN, &client_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Client-ID=%u", client_id);
    offset += 2;

    // Start time
    proto_tree_add_item(tree, hf_cdd_start_time, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;


    // PLCP Entries
    proto_tree_add_item(tree, hf_cdd_plcp_0, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_1, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_2, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_3, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_4, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_5, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_6, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_7, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_8, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_9, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_10, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_11, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_12, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_13, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_14, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_15, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_16, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_17, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_18, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_cdd_plcp_19, tvb, offset++, 1, ENC_BIG_ENDIAN);

    // Skip reserved bytes.
    offset += 11;

    // RFID
    proto_tree_add_item(tree, hf_cdd_rfid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // Data (mpdu_bytes?)
    proto_tree_add_item(tree, hf_cdd_data, tvb, offset, mpdu_length, ENC_NA);
    offset += mpdu_length;

    // CRC
    proto_tree_add_item(tree, hf_cdd_data_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;


    col_append_fstr(pinfo->cinfo, COL_INFO, "  [MPDU-Length=%u]", mpdu_length);

    return offset;
}

static gint dissect_client_complete(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    gint offset = 2;

    // Client ID
    guint32 client_id;
    proto_tree_add_item_ret_uint(tree, hf_cdd_client_id, tvb, offset, 2, ENC_BIG_ENDIAN, &client_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Client-ID=%u", client_id);
    offset += 2;

    return offset;
}

static gint dissect_request_stats(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    gint offset = 0;

    // SType
    guint32 stype;
    proto_tree_add_item_ret_uint(tree, hf_cdd_stype, tvb, offset, 1, ENC_BIG_ENDIAN, &stype);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Stype==%s", val_to_str_const(stype, stype_vals, "Unknown"));
    offset++;

    // Index (over 17 bits).  Each bit associated with a counter number..
    proto_tree_add_item(tree, hf_cdd_stats_control_index, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    // TODO: Entry control (96 bits).
    proto_tree_add_item(tree, hf_cdd_stats_entry_control, tvb, offset, 12, ENC_NA);
    offset += 12;

    return offset;
}

static gint dissect_request_stats_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb)
{
    gint offset = 0;

    // SType
    guint32 stype;
    proto_tree_add_item_ret_uint(tree, hf_cdd_stype, tvb, offset, 1, ENC_BIG_ENDIAN, &stype);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Stype==%s", val_to_str_const(stype, stype_vals, "Unknown"));
    offset++;

    // Index (over 17 bits).  Each bit associated with a counter number..
    proto_tree_add_item(tree, hf_cdd_stats_control_index, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    // Skip 3 words of zeroes.
    offset += 12;

    // Time of current request (8 bytes)
    proto_tree_add_item(tree, hf_cdd_stats_request_time, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    // TODO: remainder is dependent upon Stype...
    switch (stype) {
        default:
            break;
    }

    return offset;
}



/******************************/
/* Main dissection function.  */
static int
dissect_pacs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *pacs_tree;
    proto_item *root_ti;
    gint offset = 0;

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PACS");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_pacs, tvb, offset, -1, ENC_NA);
    pacs_tree = proto_item_add_subtree(root_ti, ett_pacs);

    /* Look at first word to see if this looks like a tx frame with preamble + length */
    guint32 preamble = tvb_get_ntohl(tvb, 0);
    if (preamble == 0x706b6c6e) {
        // Preamble.
        proto_tree_add_item(pacs_tree, hf_pacs_preamble, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        // Length in 64-bit words
        guint32 words;
        proto_item *ti = proto_tree_add_item_ret_uint(pacs_tree, hf_pacs_length_in_words, tvb, offset, 4, ENC_BIG_ENDIAN, &words);
        offset += 4;

        // Check actual length against this. Note that this first 64-bit word doesn't count.
        if (tvb_captured_length(tvb) != ((words+1)*8)) {
            expert_add_info_format(pinfo, ti, &ei_pacs_wrong_length,
                                   "Length set to %u (%u) in header, but %u bytes logged",
                                   words, (words+1)*8, tvb_captured_length(tvb));
        }
    }

    /* PKI root */
    gint pki_start_offset = offset;
    proto_item *pki_ti = proto_tree_add_string_format(pacs_tree, hf_pacs_pki,
                                                      tvb, offset, 0, "", "PKI Header");
    proto_tree *pki_tree = proto_item_add_subtree(pki_ti, ett_pacs_pki);

    /* W */
    proto_tree_add_item(pki_tree, hf_pacs_w, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* raw */
    proto_tree_add_item(pki_tree, hf_pacs_raw, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* utag */
    proto_tree_add_item(pki_tree, hf_pacs_utag, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* uqpg */
    proto_tree_add_item(pki_tree, hf_pacs_uqpg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* io */
    proto_tree_add_item(pki_tree, hf_pacs_io, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* pm */
    proto_tree_add_item(pki_tree, hf_pacs_pm, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* sl */
    proto_tree_add_item(pki_tree, hf_pacs_sl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* utt */
    proto_tree_add_item(pki_tree, hf_pacs_utt, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* tt */
    proto_tree_add_item(pki_tree, hf_pacs_tt, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* qpg (256-511) */
    guint qpg;
    proto_item *qpg_ti = proto_tree_add_item_ret_uint(pki_tree, hf_pacs_qpg, tvb, offset, 2, ENC_BIG_ENDIAN, &qpg);
    offset += 2;
    if ((qpg < 256) || (qpg > 511)) {
        // TODO: grumble with expert info.
        expert_add_info_format(pinfo, qpg_ti, &ei_pacs_qpg_out_of_range,
                               "PKI.QPG must be in (256,511), but %u seen", qpg);
    }
    proto_item_append_text(pki_ti, " (QPG=%u, so PKI_WQE_S[GRP] is %u)])", qpg, qpg-256);
    proto_item_set_len(pki_ti, offset-pki_start_offset);


    /* FPGA root */
    gint fpga_start_offset = offset;
    proto_item *fpga_ti = proto_tree_add_string_format(pacs_tree, hf_pacs_fpga_header,
                                                      tvb, offset, 0, "", "FPGA Header");
    proto_tree *fpga_tree = proto_item_add_subtree(fpga_ti, ett_pacs_fpga);

    /* FPGA */
    guint32 fpga, port, command;
    proto_tree_add_item_ret_uint(fpga_tree, hf_pacs_fpga, tvb, offset, 1, ENC_BIG_ENDIAN, &fpga);
    /* Port */
    proto_tree_add_item_ret_uint(fpga_tree, hf_pacs_port, tvb, offset, 1, ENC_BIG_ENDIAN, &port);
    offset++;
    /* Reserved */
    offset++;
    /* PACS (command) */
    proto_tree_add_item_ret_uint(fpga_tree, hf_pacs_pacs, tvb, offset, 2, ENC_BIG_ENDIAN, &command);
    offset += 2;

    /* Update root items and Info column with these fields */
    proto_item_append_text(fpga_ti, " (FPGA=%u, Port=%2u, Command=0x%2x %s)",
                           fpga, port, command, val_to_str_const(command, pacs_command_vals, "Unknown"));
    proto_item_append_text(root_ti, " (FPGA=%u, Port=%u, Command=0x%x %s)",
                           fpga, port, command, val_to_str_const(command, pacs_command_vals, "Unknown"));
    col_append_fstr(pinfo->cinfo, COL_INFO, "FPGA=%u Port=%2u %30s(0x%02x)",
                    fpga, port, val_to_str_const(command, pacs_command_vals, "Unknown"), command);

    proto_item_set_len(fpga_ti, offset-fpga_start_offset);


    /* SDPC root */
    gint sdpc_start_offset = offset;
    proto_item *sdpc_ti = proto_tree_add_string_format(pacs_tree, hf_pacs_sdpc,
                                                      tvb, offset, 0, "", "SDPC Header");
    proto_tree *sdpc_tree = proto_item_add_subtree(sdpc_ti, ett_pacs_sdpc);

    /* F */
    proto_tree_add_item(sdpc_tree, hf_pacs_f, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* MF */
    proto_tree_add_item(sdpc_tree, hf_pacs_mf, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Fragment Offset */
    proto_tree_add_item(sdpc_tree, hf_pacs_fragment_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* PACS Counter */
    guint32 pacs_counter;
    proto_tree_add_item_ret_uint(sdpc_tree, hf_pacs_pacs_counter, tvb, offset, 3, ENC_BIG_ENDIAN, &pacs_counter);
    offset += 3;

    proto_item_append_text(sdpc_ti, " (PACS Counter=%u)", pacs_counter);
    proto_item_set_len(sdpc_ti, offset-sdpc_start_offset);


    // All messages have 4 unused bytes now.
    proto_tree_add_item(pacs_tree, hf_pacs_zero_word, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    // Show overall length as a generated field.
    proto_item *ti = proto_tree_add_uint(pacs_tree, hf_pacs_length, tvb, 0, 0, tvb_captured_length(tvb));
    PROTO_ITEM_SET_GENERATED(ti);

    // CDD is remainder. highlight now to make clearer.
    proto_tree_add_item(pacs_tree, hf_pacs_cdd, tvb, offset, -1, ENC_NA);

    // Create TVB just for CDD data.
    gint cdd_length = tvb_captured_length_remaining(tvb, offset);
    // TODO: Just leaking this for now...
    guint8 *cdd_data = (guint8 *)g_malloc(cdd_length+1);
    for (gint n=0; n < cdd_length; n++) {
        cdd_data[n] = tvb_get_guint8(tvb, offset+n);
    }

    //tvb_memcpy(tvb, cdd_data, offset, tvb_captured_length_remaining(tvb, offset));
    //tvbuff_t *cdd_tvb = tvb_new_subset_remaining(tvb, offset);

    // Want to have own data source/tvb/tab for CDD.
    tvbuff_t *cdd_tvb = tvb_new_real_data(cdd_data, cdd_length, cdd_length);

    add_new_data_source(pinfo, cdd_tvb, "CDD message payload");
    // Call CDD dissector
    cdd_handle = find_dissector("cdd");  // Should already have????
    call_dissector_only(cdd_handle, cdd_tvb, pinfo, tree, GUINT_TO_POINTER(command));

    return offset;
}

/******************************/
/* Main dissection function.  */
static int
dissect_cdd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    PACS_Command_e command = (PACS_Command_e)data;
    proto_tree *cdd_tree;
    proto_item *root_ti;
    gint offset=0;

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_cdd, tvb, offset, -1, ENC_NA);
    cdd_tree = proto_item_add_subtree(root_ti, ett_cdd);
    proto_item_append_text(root_ti, " (%s)", val_to_str_const(command, pacs_command_vals, "Unknown"));


    /* Now deal with per-command CDD payload */
    switch ((PACS_Command_e)command) {
        case Command_NULL:
        case Command_Client_Complete:
            offset = dissect_client_complete(pinfo, cdd_tree, tvb);
            break;

        case Command_Client_Failed_To_Complete:
        case Command_Flow_Complete:
        case Command_Flow_Trouble:

        case Command_TCP_Retransmit_Denial:
        case Command_TCP_Flow_Start:
            break;

        case Command_Register_Read:
            offset = dissect_register_read_request(pinfo, cdd_tree, tvb);
            break;
        case Command_Register_Read_Response:
            offset = dissect_register_read_response(pinfo, cdd_tree, tvb);
            break;

        case Command_Register_Write:
            offset = dissect_register_write_request(pinfo, cdd_tree, tvb);
            break;
        case Command_Register_Write_Response:
            offset = dissect_register_write_response(pinfo, cdd_tree, tvb);
            break;

        case Command_RX_Frame:
            offset = dissect_rx_frame(pinfo, cdd_tree, tvb);
            break;

        case Command_RX_Compressed_TCP_Frame:
        case Command_RX_Compressed_non_TCP_Frame:
        case Command_RX_Partial_Frame:
            break;

        case Command_TX_Generated_Frame:
            offset = dissect_tx_generated_frame(pinfo, cdd_tree, tvb);
            break;
        case Comamnd_TX_Generated_Frame_Response:
            offset = dissect_tx_generated_frame_response(pinfo, cdd_tree, tvb);
            break;

        case Command_TX_STATS:
        case Command_Request_Log:
        case Command_Request_Log_Response:
        case Command_Request_Stats:
            dissect_request_stats(pinfo, cdd_tree, tvb);
            break;
        case Command_Request_Stats_Response:
            dissect_request_stats_response(pinfo, cdd_tree, tvb);
            break;
        case Command_RF_Metric:
        case Command_Info_Request:
        case Command_Info_Response:
        case Command_Sawyer_Pull_Request:
        case Command_Sawyer_Pull_Response:
        case Command_Sawyer_Push_Request:
        case Command_Sawyer_Push_Response:
        case Command_PACS_Status_Request:
        case Command_PACS_Status_Response:
            break;
    }

    return offset;
}



void
proto_register_pacs(void)
{
    static hf_register_info hf[] = {
        /* PKI Header */

        { &hf_pacs_preamble,
            {   "Preambles", "pacs.preamble", FT_UINT32, BASE_HEX,
                NULL, 0x0, "Signature - start of outgoing message", HFILL }
        },
        { &hf_pacs_length_in_words,
            {   "Length in words", "pacs.length-in-words", FT_UINT32, BASE_DEC,
                NULL, 0x0, "Length of outgoing message in 64-bit words", HFILL }
        },

        { &hf_pacs_pki,
            {   "PKI Header", "pacs.pki", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_pacs_w,
            {   "W", "pacs.w", FT_UINT8, BASE_HEX,
                NULL, 0x80, "Width (unused, should be 1)", HFILL }
        },
        { &hf_pacs_raw,
            {   "RAW", "pacs.raw", FT_UINT8, BASE_HEX,
                NULL, 0x40, "Turn off RED. Must be set to 1", HFILL }
        },
        { &hf_pacs_utag,
            {   "UTAG", "pacs.utag", FT_UINT8, BASE_HEX,
                NULL, 0x20, "Ignore TAG field and set this to 0", HFILL }
        },
        { &hf_pacs_uqpg,
            {   "UQPG", "pacs.uqpg", FT_UINT8, BASE_DEC,
                NULL, 0x10, "Ignore TAG field and set this to 0", HFILL }
        },
        // TODO (tfs)
        { &hf_pacs_io,
            {   "IO", "pacs.io", FT_UINT8, BASE_HEX,
                NULL, 0x08, "Direction", HFILL }
        },
        { &hf_pacs_pm,
            {   "PM", "pacs.pm", FT_UINT8, BASE_HEX,
                NULL, 0x07, "Set to 0x7 to do no other parsing other than the header", HFILL }
        },
        { &hf_pacs_sl,
            {   "SL", "pacs.sl", FT_UINT8, BASE_HEX,
                NULL, 0x00, "Set to 0x4.  Indicates the number of bytes to advance to find the next parse item", HFILL }
        },
        { &hf_pacs_utt,
            {   "UTT", "pacs.utt", FT_UINT8, BASE_HEX,
                NULL, 0x80, "Set to 0", HFILL }
        },
        { &hf_pacs_tt,
            {   "TT", "pacs.tt", FT_UINT8, BASE_HEX,
                NULL, 0x60, "If UTT is set, this field will be used to compute the PKI_WQE_S[TT]. Set to 0", HFILL }
        },
        { &hf_pacs_qpg,
            {   "QPG", "pacs.qpg", FT_UINT16, BASE_DEC,
                NULL, 0x07ff, "256-511", HFILL }
        },

        /* FPGA Header */
        { &hf_pacs_fpga_header,
            {   "FPGA Header", "pacs.fpga-header", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_pacs_fpga,
            {   "FPGA", "pacs.fpga", FT_UINT8, BASE_HEX,
                NULL, 0xf0, "0=A, 1=B, etc", HFILL }
        },
        { &hf_pacs_port,
            {   "Port", "pacs.port", FT_UINT8, BASE_HEX,
                NULL, 0x0f, "0-7", HFILL }
        },
        { &hf_pacs_pacs,
            {   "PACS", "pacs.command", FT_UINT8, BASE_HEX,
                VALS(pacs_command_vals), 0x0, "PACS Command", HFILL }
        },

        /* SDPC Header */
        { &hf_pacs_sdpc,
            {   "SDPC Header", "pacs.sdpc", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_pacs_f,
            {   "F", "pacs.f", FT_UINT8, BASE_HEX,
                NULL, 0x80, "Fragmentation", HFILL }
        },
        { &hf_pacs_mf,
            {   "MF", "pacs.mf", FT_UINT8, BASE_HEX,
                NULL, 0x40, "Additional fragments", HFILL }
        },
        { &hf_pacs_fragment_offset,
            {   "Fragment Offset", "pacs.fragment-offset", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_pacs_pacs_counter,
            {   "PACS Counter", "pacs.commands-counter", FT_UINT24, BASE_DEC,
                NULL, 0x0, "PACS Command Counter", HFILL }
        },

        { &hf_pacs_zero_word,
            {   "Zero Word", "pacs.zero-word", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_pacs_length,
            {   "PACS Length", "pacs.length", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_pacs_cdd,
            {   "CDD", "pacs.cdd", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_pacs,
        &ett_pacs_pki,
        &ett_pacs_fpga,
        &ett_pacs_sdpc
    };

    static ei_register_info ei[] = {
        { &ei_pacs_wrong_length, { "pacs.length-not-as-signalled", PI_MALFORMED, PI_ERROR, "PACS signalled length doesn't match frame length", EXPFILL }},
        { &ei_pacs_qpg_out_of_range, { "pacs.qpg-out-of-range", PI_MALFORMED, PI_ERROR, "QPG is out of allowed range", EXPFILL }},
    };

    expert_module_t* expert_pacs;

    //module_t *pacs_module;

    proto_pacs = proto_register_protocol("AXE PACS", "PACS", "pacs");
    proto_register_field_array(proto_pacs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pacs = expert_register_protocol(proto_pacs);
    expert_register_field_array(expert_pacs, ei, array_length(ei));

    pacs_handle = register_dissector("pacs", dissect_pacs, proto_pacs);


    /* Preferences */
    //pacs_module = prefs_register_protocol(proto_pacs, NULL);
}

void
proto_register_cdd(void)
{
    static hf_register_info hf[] = {
        // Fields that appear in CCD payloads.
        { &hf_cdd_client_id,
            {   "Client ID", "cdd.client-id", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_flow_id,
            {   "Flow ID", "cdd.flow-id", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_payload_checksum_start_offset,
            {   "Payload Checksum Start Offset", "cdd.payload-checksum-start-offset", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_signature_insert_offset,
            {   "Signature Insert Offset", "cdd.signature-insert-offset", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },

        { &hf_cdd_tt,
            {   "TT", "cdd.tt", FT_UINT8, BASE_HEX,
                VALS(tt_vals), 0xc0, "Frame Type", HFILL }
        },
        { &hf_cdd_p,
            {   "P", "cdd.p", FT_UINT8, BASE_HEX,
                VALS(p_vals), 0x0c, "Packet Buffer ACK Policy", HFILL }
        },
        { &hf_cdd_f,
            {   "F", "cdd.f", FT_UINT8, BASE_HEX,
                NULL, 0x02, NULL, HFILL }
        },

        { &hf_cdd_c_type,
            {   "C-Type", "cdd.c-type", FT_UINT8, BASE_HEX,
                VALS(c_type_vals), 0x70, NULL, HFILL }
        },

        { &hf_cdd_bssid,
            {   "BSSID", "cdd.bssid", FT_UINT8, BASE_HEX,
                NULL, 0x7f, NULL, HFILL }
        },
        { &hf_cdd_wlan_type,
            {   "WLAN Type", "cdd.wlan-type", FT_UINT8, BASE_HEX_DEC,
                NULL, 0x3f, NULL, HFILL }
        },
        { &hf_cdd_msdu_length,
            {   "MSDU Length", "cdd.msdu-length", FT_UINT16, BASE_HEX_DEC,
                NULL, 0x0, "Length of this frame in bytes. Max 11454 bytes.", HFILL }
        },
        { &hf_cdd_mpdu_length,
            {   "MPDU Length", "cdd.mpdu-length", FT_UINT16, BASE_HEX_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_mcs,
            {   "MCS", "cdd.mcs", FT_UINT8, BASE_HEX_DEC,
                NULL, 0xf, NULL, HFILL }
        },
        { &hf_cdd_ip_total_length,
            {   "IP Total Length", "cdd.ip-total-length", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },

        // N.B. These modifiers are only for flow frame generation.
        // Not client frame generation.
        { &hf_cdd_u,
            {   "Data Modifier", "cdd.data-modifier", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_utype,
            {   "UType", "cdd.utype", FT_UINT8, BASE_DEC,
                VALS(u_type_vals), 0x60, "Update Type", HFILL }
        },
        { &hf_cdd_ulength,
            {   "ULength", "cdd.ulength", FT_UINT8, BASE_DEC,
                NULL, 0x07, "Length in bytes of field that will be updated", HFILL }
        },
        { &hf_cdd_uoffset,
            {   "UOffset", "cdd.uoffset", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Bytes to offset before applying update", HFILL }
        },
        { &hf_cdd_udata,
            {   "UData", "cdd.udata", FT_UINT32, BASE_DEC,
                NULL, 0x0, "Data associated with the update", HFILL }
        },
        { &hf_cdd_ufdata,
            {   "UFData", "cdd.ufdata", FT_UINT32, BASE_DEC,
                NULL, 0x0, "Data field that is actually updated", HFILL }
        },
        { &hf_cdd_txdata,
            {   "Tx Data", "cdd.txdata", FT_BYTES, BASE_NONE,
                NULL, 0x0, "Frame Data", HFILL }
        },

        { &hf_cdd_register_address,
            {   "Register Address", "cdd.reg-address", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        // TODO: do we want separate read and write data fields?
        { &hf_cdd_register_data,
            {   "Register Data", "cdd.reg-data", FT_UINT32, BASE_HEX_DEC,
                NULL, 0x0, NULL, HFILL }
        },

        { &hf_cdd_nss,
            {   "NSS", "cdd.nss", FT_UINT8, BASE_HEX,
                NULL, 0xf0, "Number os Spatial Streams", HFILL }
        },
        { &hf_cdd_sbw,
            {   "SBW", "cdd.sbw", FT_UINT8, BASE_HEX,
                VALS(sbw_vals), 0xf0, "Channel Bandwidth", HFILL }
        },
        { &hf_cdd_plcp,
            {   "PLCP", "cdd.plcp", FT_UINT8, BASE_HEX,
                VALS(plcp_vals), 0x0f, "PLCP PDU Type", HFILL }
        },


        { &hf_cdd_sl,
            {   "Short / Long Select", "cdd.sl", FT_UINT8, BASE_HEX,
                NULL, 0xc0, NULL, HFILL }
        },
        { &hf_cdd_pix,
            {   "PHY Index", "cdd.pix", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },

        { &hf_cdd_rx_l1_info_a,
            {   "Rx L1 Info A", "cdd.rx-l1-info-a", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_rx_l1_info_b,
            {   "Rx L1 Info B", "cdd.rx-l1-info-b", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_rx_l1_info_c,
            {   "Rx L1 Info C", "cdd.rx-l1-info-c", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_rx_l1_info_d,
            {   "Rx L1 Info D", "cdd.rx-l1-info-d", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },

        { &hf_cdd_power_a,
            {   "Power A", "cdd.power-a", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_power_b,
            {   "Power B", "cdd.power-b", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_power_c,
            {   "Power C", "cdd.power-c", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_power_d,
            {   "Power D", "cdd.power-d", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_power_e,
            {   "Power A", "cdd.power-e", FT_UINT8, BASE_HEX,
                NULL, 0xE0, NULL, HFILL }
        },
        { &hf_cdd_power_f,
            {   "Power F", "cdd.power-f", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_power_g,
            {   "Power G", "cdd.power-g", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_cdd_power_h,
            {   "Power H", "cdd.power-h", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },

        { &hf_cdd_bm,
            {   "Broadcast-Multicast", "cdd.bm", FT_UINT8, BASE_HEX,
                NULL, 0x80, NULL, HFILL }
        },
        { &hf_cdd_bv,
            {   "BV", "cdd.bv", FT_UINT8, BASE_HEX,
                NULL, 0x40, NULL, HFILL }
        },
        { &hf_cdd_cv,
            {   "CV", "cdd.cv", FT_UINT8, BASE_HEX,
                NULL, 0x20, NULL, HFILL }
        },
        { &hf_cdd_to_ds,
            {   "TO DS", "cdd.to-ds", FT_UINT8, BASE_HEX,
                NULL, 0x10, NULL, HFILL }
        },
        { &hf_cdd_fr_ds,
            {   "FR DS", "cdd.fr-ds", FT_UINT8, BASE_HEX,
                NULL, 0x08, NULL, HFILL }
        },

        { &hf_cdd_start_time,
            {   "StartTime", "cdd.start-time", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },

        { &hf_cdd_plcp_0,
            {   "PLCP 0", "cdd.plcp-0", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_1,
            {   "PLCP 1", "cdd.plcp-1", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_2,
            {   "PLCP 2", "cdd.plcp-2", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_3,
            {   "PLCP 3", "cdd.plcp-3", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_4,
            {   "PLCP 4", "cdd.plcp-4", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_5,
            {   "PLCP 5", "cdd.plcp-5", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_6,
            {   "PLCP 6", "cdd.plcp-6", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_7,
            {   "PLCP 7", "cdd.plcp-7", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_8,
            {   "PLCP 8", "cdd.plcp-8", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_9,
            {   "PLCP 9", "cdd.plcp-9", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_10,
            {   "PLCP 10", "cdd.plcp-10", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_11,
            {   "PLCP 11", "cdd.plcp-11", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_12,
            {   "PLCP 12", "cdd.plcp-12", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_13,
            {   "PLCP 13", "cdd.plcp-13", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_14,
            {   "PLCP 14", "cdd.plcp-14", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_15,
            {   "PLCP 15", "cdd.plcp-15", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_16,
            {   "PLCP 16", "cdd.plcp-16", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_17,
            {   "PLCP 17", "cdd.plcp-17", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_18,
            {   "PLCP 18", "cdd.plcp-18", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_plcp_19,
            {   "PLCP 19", "cdd.plcp-19", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },


        { &hf_cdd_rfid,
            {   "RFID", "cdd.rfid", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_data,
            {   "Data", "cdd.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_data_crc,
            {   "CRC", "cdd.crc", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL },
        },


        { &hf_cdd_stype,
            {   "Stype", "cdd.stype", FT_UINT8, BASE_DEC,
                VALS(stype_vals), 0xf0, NULL, HFILL },
        },
        { &hf_cdd_stats_control_index,
            {   "Index", "cdd.stats-control-index", FT_UINT24, BASE_HEX,
                NULL, 0x01ffff, NULL, HFILL },
        },
        { &hf_cdd_stats_entry_control,
            {   "Entry Control", "cdd.stats-entry-control", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL },
        },
        { &hf_cdd_stats_request_time,
            {   "Time of current request", "cdd.stats-request_time", FT_UINT64, BASE_HEX,
                NULL, 0x0, NULL, HFILL },
        },


    };

    static gint *ett[] = {
        &ett_cdd,
        &ett_cdd_u
    };



    proto_cdd = proto_register_protocol("CDD", "CDD", "cdd");
    proto_register_field_array(proto_cdd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    //expert_cdd = expert_register_protocol(proto_pacs);
    //expert_register_field_array(expert_cdd, ei, array_length(ei));

    cdd_handle = register_dissector("cdd", dissect_cdd, proto_cdd);
}


static void
apply_pacs_prefs(void)
{
    //global_pacs_port_range = prefs_get_range_value("pacs", "udp.port");
}

void
proto_reg_handoff_pacs(void)
{
    //dissector_add_uint_range_with_preference("udp.port", "", pacs_handle);
    apply_pacs_prefs();
}

void
proto_reg_handoff_cdd(void)
{
    //dissector_add_uint_range_with_preference("udp.port", "", pacs_handle);
    //apply_pacs_prefs();
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
