/* packet-l2server.c
 *
 * TCP-based protocol between adapter and L2 server.
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
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/proto_data.h>

#include "packet-pdcp-nr.h"

#ifdef WIN32
typedef char          int8_t;
//typedef unsigned      int16_t;
typedef unsigned long ulong;
#endif
typedef guint8        uint8_t;
typedef guint16       uint16_t;
typedef guint32       uint32_t;
typedef guint64       uint64_t;
typedef unsigned char uchar;

typedef guint32 comgen_qnxPPUIDt;

#include "L2ServerMessages.h"

//#include "lte-l2_Srv.h"        // causes conflicts...
#include "lte-l2_Sap.h"
#include "nr5g-rlcmac_Data.h"
//#include "nr5g-rlcmac_Crlc.h"  // causes conflicts
//#include "nr5g-pdcp_Ctrl.h"    // nope


void proto_register_l2server(void);

static int proto_l2server = -1;

/* SAPI Header */
static int hf_l2server_header = -1;
static int hf_l2server_sapi = -1;
static int hf_l2server_type = -1;
static int hf_l2server_len = -1;
static int hf_l2server_payload = -1;

/* Fields from message payloads */
static int hf_l2server_cellid = -1;
static int hf_l2server_physical_cellid = -1;
static int hf_l2server_l1verbosity = -1;
static int hf_l2server_l1ulreport = -1;
static int hf_l2server_enablecapstest = -1;

static int hf_l2server_client_name = -1;
static int hf_l2server_start_cmd_type = -1;
static int hf_l2server_ueid = -1;
static int hf_l2server_beamidx = -1;
static int hf_l2server_rbtype = -1;
static int hf_l2server_rbid = -1;
static int hf_l2server_lch = -1;
static int hf_l2server_ref = -1;
static int hf_l2server_mui = -1;
static int hf_l2server_datavolume = -1;
static int hf_l2server_scgid = -1;
static int hf_l2server_lcid = -1;
static int hf_l2server_ullogref = -1;
static int hf_l2server_reest = -1;
static int hf_l2server_esbf = -1;
static int hf_l2server_dllogref = -1;

static int hf_l2server_rlcsn = -1;
static int hf_l2server_info = -1;
static int hf_l2server_frame = -1;
static int hf_l2server_slot = -1;
static int hf_l2server_numpduforsdu = -1;

static int hf_l2server_ueflags = -1;
static int hf_l2server_stkinst = -1;
static int hf_l2server_udg_stkinst = -1;

static int hf_l2server_crnti = -1;
static int hf_l2server_result_code = -1;
static int hf_l2server_ra_res = -1;
static int hf_l2server_no_preambles_sent = -1;
static int hf_l2server_contention_detected = -1;

static int hf_l2server_maxuppwr = -1;
static int hf_l2server_brsrp = -1;
static int hf_l2server_ue_category = -1;
static int hf_l2server_ra_flags = -1;
static int hf_l2server_ra_rnti = -1;
static int hf_l2server_discard_rar_num = -1;
static int hf_l2server_ul_subcarrier_spacing = -1;
static int hf_l2server_no_data = -1;
static int hf_l2server_crid = -1;
static int hf_l2server_rel_cellid = -1;
static int hf_l2server_add_cellid = -1;
static int hf_l2server_scg_type = -1;
static int hf_l2server_drb_continue_rohc = -1;
static int hf_l2server_mac_config_len = -1;

static int hf_l2server_bwpmask = -1;
static int hf_l2server_ra_info = -1;
static int hf_l2server_bwpid = -1;
static int hf_l2server_prach_configindex = -1;
static int hf_l2server_preamble_receive_target_power = -1;
static int hf_l2server_rsrp_thresholdssb = -1;
static int hf_l2server_csirs_threshold = -1;
static int hf_l2server_sul_rsrp_threshold = -1;
static int hf_l2server_ra_preambleindex = -1;
static int hf_l2server_preamble_power_ramping_step = -1;
static int hf_l2server_ra_ssb_occassion_mask_index = -1;
static int hf_l2server_preamble_tx_max = -1;
static int hf_l2server_totalnumberofra_preambles = -1;

static int hf_l2server_l1cell_dedicated_config_len = -1;
static int hf_l2server_l2_test_mode = -1;
static int hf_l2server_l2_cell_dedicated_config = -1;
static int hf_l2server_l2_cell_dedicated_config_len = -1;

static int hf_l2server_l1_cell_dedicated_config = -1;
static int hf_l2server_num_of_rb_cfg = -1;
static int hf_l2server_rb_config =-1;
static int hf_l2server_num_of_rb_rel = -1;
static int hf_l2server_rb_rel =-1;

static int hf_l2server_rl_failure_timer;
static int hf_l2server_rl_syncon_timer;
static int hf_l2server_seg_cnt;
static int hf_l2server_enable_pmi_reporting;
static int hf_l2server_ra_for_sul;
static int hf_l2server_rlc_mode;
static int hf_l2server_rlc_er;

static int hf_l2server_mac_cell_group_config =-1;
static int hf_l2server_spcell_config =-1;
static int hf_l2server_scell_list =-1;

static int hf_l2server_pdcp_pdu = -1;
static int hf_l2server_traffic = -1;
static int hf_l2server_traffic_tm = -1;
static int hf_l2server_traffic_um = -1;
static int hf_l2server_traffic_am = -1;
static int hf_l2server_traffic_cnf = -1;
static int hf_l2server_traffic_ul = -1;
static int hf_l2server_traffic_dl = -1;
static int hf_l2server_traffic_bch = -1;


static int hf_l2server_rach = -1;
static int hf_l2server_reestablishment = -1;
static int hf_l2server_params = -1;

static int hf_l2server_rlc_config_tx = -1;
static int hf_l2server_rlc_config_rx = -1;

static int hf_l2server_rlc_snlength = -1;
static int hf_l2server_rlc_t_poll_retransmit = -1;
static int hf_l2server_rlc_poll_pdu = -1;
static int hf_l2server_rlc_poll_byte = -1;
static int hf_l2server_rlc_max_retx_threshold = -1;
static int hf_l2server_rlc_discard_timer = -1;
static int hf_l2server_rlc_t_reassembly = -1;
static int hf_l2server_rlc_t_status_prohibit = -1;

static int hf_l2server_spare1 = -1;
static int hf_l2server_spare2 = -1;
static int hf_l2server_spare4 = -1;
static int hf_l2server_package_type = -1;
static int hf_l2server_dbeamid = -1;
static int hf_l2server_dbeam_status = -1;
static int hf_l2server_num_beams = -1;
static int hf_l2server_logstr = -1;

static int hf_l2server_ncelllte = -1;
static int hf_l2server_ncellnr = -1;
static int hf_l2server_numltepropdu = -1;
static int hf_l2server_numnrpropdu = -1;
static int hf_l2server_cellidlteitem = -1;

static int hf_l2server_field_mask_1 = -1;
static int hf_l2server_field_mask_1_ded_present = -1;
static int hf_l2server_field_mask_1_common_present = -1;
static int hf_l2server_field_mask_2 = -1;
static int hf_l2server_field_mask_4 = -1;

static int hf_l2server_nb_scell_cfg_add = -1;
static int hf_l2server_nb_scell_cfg_del = -1;

static int hf_l2server_ph_cell_config = -1;
static int hf_l2server_ph_cell_dcp_config_present = -1;
static int hf_l2server_ph_pdcch_blind_detection_present = -1;
static int hf_l2server_harq_ack_spatial_bundling_pucch = -1;
static int hf_l2server_harq_ack_spatial_bundling_pusch = -1;
static int hf_l2server_pmax_nr = -1;
static int hf_l2server_pdsch_harq_ack_codebook = -1;

static int hf_l2server_sp_cell_cfg_ded = -1;

static int hf_l2server_sp_cell_cfg_tdd_ded_present = -1;
static int hf_l2server_sp_cell_cfg_dl_ded_present = -1;
static int hf_l2server_sp_cell_cfg_ul_ded_present = -1;
static int hf_l2server_sp_cell_cfg_sup_ul_present = -1;
static int hf_l2server_sp_cell_cfg_cross_carrier_sched_present = -1;
static int hf_l2server_sp_cell_cfg_lte_crs_tomatcharound_present = -1;
static int hf_l2server_sp_cell_cfg_dormantbwp_present = -1;
static int hf_l2server_sp_cell_cfg_lte_crs_pattern_list1_present = -1;
static int hf_l2server_sp_cell_cfg_lte_crs_pattern_list2_present = -1;

static int hf_l2server_sp_cell_cfg_tdd = -1;
static int hf_l2server_sp_cell_cfg_dl = -1;
static int hf_l2server_sp_cell_cfg_ul = -1;
static int hf_l2server_sp_cell_cfg_sup_ul = -1;
static int hf_l2server_sp_cell_cfg_cross_carrier_sched = -1;
static int hf_l2server_sp_cell_cfg_lte_crs_tomatcharound = -1;
static int hf_l2server_sp_cell_cfg_dormantbwp = -1;
static int hf_l2server_sp_cell_cfg_lte_crs_pattern_list1 = -1;
static int hf_l2server_sp_cell_cfg_lte_crs_pattern_list2 = -1;




static int hf_l2server_serv_cell_idx = -1;
static int hf_l2server_bwp_inactivity_timer = -1;
static int hf_l2server_tag_id = -1;
static int hf_l2server_scell_deact_timer = -1;
static int hf_l2server_pathloss_ref_linking = -1;
static int hf_l2server_serv_cell_mo = -1;
static int hf_l2server_default_dl_bwpid = -1;
static int hf_l2server_supp_ul_rel = -1;
static int hf_l2server_ca_slot_offset_is_valid = -1;
static int hf_l2server_nb_lte_srs_patternlist_1 = -1;
static int hf_l2server_nb_lte_srs_patternlist_2 = -1;
static int hf_l2server_ca_slot_offset_r16 = -1;

static int hf_l2server_csi_rs_valid_with_dci_r16 = -1;
static int hf_l2server_crs_rate_match_per_coreset_poolidx_r16 = -1;
static int hf_l2server_first_active_ul_bwp_pcell = -1;

static int hf_l2server_sp_cell_cfg_common = -1;

static int hf_l2server_config_cmd_type = -1;
static int hf_l2server_side = -1;
static int hf_l2server_bot_layer = -1;
static int hf_l2server_trf = -1;
static int hf_l2server_technology = -1;
static int hf_l2server_enbsim = -1;

static int hf_l2server_rx_lch_info = -1;
static int hf_l2server_tx_lch_info = -1;
static int hf_l2server_lcg = -1;
static int hf_l2server_priority = -1;
static int hf_l2server_prioritized_bit_rate = -1;
static int hf_l2server_bucket_size_duration = -1;
static int hf_l2server_allowed_serving_cells = -1;
static int hf_l2server_allowed_scs_list = -1;
static int hf_l2server_max_pusch_duration = -1;
static int hf_l2server_configured_grant_type_allowed = -1;
static int hf_l2server_logical_channel_sr_mask = -1;
static int hf_l2server_logical_channel_sr_delay_timer_configured = -1;
static int hf_l2server_request_duplicates_from_pdcp = -1;
static int hf_l2server_scheduling_request_id = -1;
static int hf_l2server_bit_rate_query_prohibit_timer = -1;
static int hf_l2server_allowed_phy_priority_index = -1;

static int hf_l2server_setparm_cmd_type = -1;
static int hf_l2server_max_ue = -1;
static int hf_l2server_max_pdcp = -1;
static int hf_l2server_max_nat = -1;
static int hf_l2server_max_udg_sess = -1;
static int hf_l2server_max_cntr = -1;

static int hf_l2server_mac_cell_group_len = -1;

static int hf_l2server_cmac_status = -1;

static int hf_l2server_drx_config = -1;
static int hf_l2server_drx_len = -1;
static int hf_l2server_drx_ondurationtimer_isvalid = -1;
static int hf_l2server_drx_ondurationtimer = -1;
static int hf_l2server_drx_inactivitytimer = -1;
static int hf_l2server_drx_harq_rtt_timerdl = -1;
static int hf_l2server_drx_harq_rtt_timerul = -1;
static int hf_l2server_drx_retransmission_timerdl = -1;
static int hf_l2server_drx_retransmission_timerul = -1;
static int hf_l2server_drx_longcyclestartoffset_isvalid = -1;
static int hf_l2server_drx_longcyclestartoffset = -1;
static int hf_l2server_drx_short_cycle = -1;
static int hf_l2server_drx_short_cycle_timer = -1;
static int hf_l2server_drx_slot_offset = -1;

static int hf_l2server_log = -1;

static int hf_l2server_spcell_config_ded = -1;
static int hf_l2server_spcell_config_ded_len = -1;

static int hf_l2server_radio_condition_group = -1;
static int hf_l2server_radio_condition_profile_index = -1;

static int hf_l2server_fname = -1;

static int hf_l2server_nbslotspeccfg_addmod = -1;
static int hf_l2server_nbslotspeccfg_del = -1;

static int hf_l2server_nbdlbwpidtoadd = -1;
static int hf_l2server_nbdlbwpidtodel = -1;

static int hf_l2server_sibfilterflag = -1;


static const value_string lch_vals[] =
{
    { 0x0,   "SPARE" },
    { 0x1,   "BCCHHoBCH" },
    { 0x2,   "BCCHoDLSCH" },
    { 0x3,   "PCCH" },
    { 0x4,   "CCCH" },
    { 0x5,   "DCCH" },
    { 0x6,   "DTCH" },
    { 0x0,   NULL }
};

static const value_string rb_type_vals[] =
{
    { 1,   "nr5g_SIG" },
    { 2,   "nr5g_UP" },
    { 0x0,   NULL }
};

static const value_string ra_res_vals[] =
{
    { 1,   "RA Success" },
    { 2,   "RA Recover from Problem" },
    { 3,   "RA Unsuccessful" },
    { 4,   "CR Unsuccessful" },
    { 0x0,   NULL }
};

static const value_string ul_subcarrier_spacing_vals[] =
{
    { 0,     "kHz15"},
    { 1,     "kHz30"},
    { 2,     "kHz60"},
    { 3,     "kHz120"},
    { 4,     "kHz240"},
    { 255,   "none"},
    { 0x0,   NULL }
};

static const value_string discard_rar_num_vals[] =
{
    { 0,     "Do not discard any RAR (default)"},
    { 1,     "Discard 1 RAR"},
    { 2,     "Discard 2 RARs"},
    { 3,     "Discard 3 RARs"},
    { 4,     "Discard 4 RARs"},
    /* TODO: more if see them IRL */
    { 0xFF,  "Discard all RARs"},
    { 0x0,   NULL }
};

static const value_string l2_test_mode_vals[] =
{
    { 0,   "No test mode" },
    { 1,   "UL and DL are active, RA not expected" },
    { 2,   "RA without contention" },
    { 0,   NULL }
};

static const value_string rlc_mode_vals[] =
{
    { nr5g_TM,   "TM" },
    { nr5g_UM,   "UM" },
    { nr5g_AM,   "AM" },
    { 0,   NULL }
};

/* nr5g_rlcmac_Crlc_ER_v from n45g-rlcmac_Crlc.h */
static const value_string rlc_er_vals[] =
{
    { 0,          "Void / no action" },
    { 1,          "Establish" },
    { 2,          "Re-establish" },
    { 3,          "Modify" },
    { 4,          "Release" },
    { 5,          "Suspend" },
    { 6,          "Resume" },
    { 0,   NULL }
};

static const value_string config_cmd_type_vals[] =
{
    { nr5g_l2_Srv_CFG_01tTYPE,     "nr5g_l2_Srv_CFG_01tTYPE" },
    { nr5g_l2_Srv_CFG_02tTYPE,     "nr5g_l2_Srv_CFG_02tTYPE" },
    // TODO: not sure if others (starting with Type) are alterantives..
    { 0,   NULL }
};

static const value_string setparm_cmd_type_vals[] =
{
    { nr5g_l2_Srv_SETPARM_03,     "nr5g_l2_Srv_SETPARM_03" },
    // TODO: not sure if others (starting with Type) are alterntives..
    { 0,   NULL }
};


static const value_string interface_side_vals[] =
{
    { lte_USER,     "User" },
    { lte_NET,      "Net" },
    { lte_DEB_USER, "Debug User" },
    { lte_DEB_NET,  "Debug Net" },
    { 0,   NULL }
};

static const value_string technology_vals[] =
{
    { nr5g_l2_Srv_LTE,     "LTE" },
    { nr5g_l2_Srv_NR,      "NR" },
    { 0,   NULL }
};


static const value_string version_server_type_vals[] =
{
    { 1,   "MULTI OS" },
    { 0,   NULL }
};

static const value_string dbeam_status_vals[] =
{
    { nr5g_rlcmac_Cmac_STATUS_DBEAM_BOOTING_UP,       "Booting Up"},
    { nr5g_rlcmac_Cmac_STATUS_DBEAM_SYNC,             "Sync"},
    { nr5g_rlcmac_Cmac_STATUS_DBEAM_NO_SIGNAL,        "No Signal"},
    { nr5g_rlcmac_Cmac_STATUS_DBEAM_SYNC_NOT_FOUND,   "Sync Not Found"},
    { nr5g_rlcmac_Cmac_STATUS_DBEAM_UNSTABLE_CLOCK,   "Unstable Clock"},
    { nr5g_rlcmac_Cmac_STATUS_DBEAM_SYNC_UNLOCKED,    "Sync Unlocked"},
    { 0,   NULL }
};

static const value_string bot_layer_vals[] =
{
    { nr5g_BOT_PDCP,     "PDCP" },
    { nr5g_BOT_RLCMAC,   "RLCMAC" },
    { nr5g_BOT_PHY,      "PHY" },
    { 0,   NULL }
};

static const value_string trf_vals[] =
{
    { nr5g_TRF_PDCP,         "PDCP" },
    { nr5g_TRF_UDG,          "UDG" },
    { nr5g_TRF_CNTR_UDG,     "CNTR_UDG" },
    { nr5g_TRF_TM_HARQ,      "TM_HARQ" },
    { nr5g_TRF_TM_MAC,       "TM_MAC" },
    { nr5g_TRF_TM_RLC,       "TM_RLC" },
    { nr5g_TRF_TM_PDCP,      "TM_PDCP" },
    { nr5g_TRF_TM_NAS,       "TM_NAS" },
    { nr5g_TRF_RLC,          "TM_RLC" },
    { 0,   NULL }
};

static const value_string enbsim_vals[] =
{
    { nr5g_l2_Srv_ENBSIM_00,     "ENBSIM_00" },
    { nr5g_l2_Srv_ENBSIM_01,      "ENBSIM_01" },
    { 0,   NULL }
};

static const value_string cmac_status_vals[] =
{
    { nr5g_rlcmac_Cmac_STATUS_NONE,                      "None" },
    { nr5g_rlcmac_Cmac_STATUS_RA_RECOVER_FROM_PROBLEM,   "RA Recover From Problem" },
    { nr5g_rlcmac_Cmac_STATUS_PUCCH_SRS_RELEASE,         "PUCCH SRS Release" },
    { nr5g_rlcmac_Cmac_STATUS_RNTI_DUP_RELEASE,          "RNTI DUP Release" },
    { nr5g_rlcmac_Cmac_STATUS_LOWER_LAYER_NAK,           "Lower Layer NAK" },
    { nr5g_rlcmac_Cmac_STATUS_RLF_HARQ_CSI_OFF,          "RLF HARQ CSI Off" },
    { nr5g_rlcmac_Cmac_STATUS_RL_SYNC_ON,                "RL Sync On" },
    { 0,   NULL }
};

static const value_string drx_onduration_timer_long_cycle_vals[] =
{
    { nr5g_rlcmac_Cmac_DRX_ON_DURATION_TIMER_SUBMILLISEC,    "SubMillisec" },
    { nr5g_rlcmac_Cmac_DRX_ON_DURATION_TIMER_MILLISEC,       "Millisec" },
    { 0,   NULL }
};

static const value_string drx_long_cycle_start_offset_vals[] =
{
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS10,    "ms10" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS20,    "ms20" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS32,    "ms32" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS40,    "ms40" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS60,    "ms60" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS64,    "ms64" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS70,    "ms70" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS80,    "ms80" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS128,   "ms128" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS160,   "ms160" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS256,   "ms256" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS320,   "ms320" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS512,   "ms512" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS640,   "ms640" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS1024,  "ms1024" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS1280,  "ms1280" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS2048,  "ms2048" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS2560,  "ms2560" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS5120,  "ms5120" },
    { nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS10240, "ms10240" },
    { 0,   NULL }
};

static const value_string  drx_inactivity_timer_vals[] =
{
    { 0,    "ms0" },
    { 1,    "ms1" },
    { 2,    "ms2" },
    { 3,    "ms3" },
    { 4,    "ms4" },
    { 5,    "ms5" },
    { 6,    "ms6" },
    { 7,    "ms8" },
    { 8,    "ms10" },
    { 9,    "ms20" },
    { 10,   "ms30" },
    { 11,   "ms40" },
    { 12,   "ms50" },
    { 13,   "ms60" },
    { 14,   "ms80" },
    { 15,   "ms100" },
    { 16,   "ms200" },
    { 17,   "ms300" },
    { 18,   "ms400" },
    { 19,   "ms500" },
    { 20,   "ms600" },
    { 21,   "ms800" },
    { 22,   "ms1000" },
    { 23,   "ms1200" },
    { 35,   "ms1600" },
    { 0,   NULL }
};

static const value_string  drx_retransmission_timer_vals[] =
{
    { 0,    "sl0" },
    { 1,    "sl1" },
    { 2,    "sl2" },
    { 3,    "sl4" },
    { 4,    "sl16" },
    { 5,    "sl24" },
    { 6,    "sl33" },
    { 7,    "sl40" },
    { 8,    "sl64" },
    { 9,    "sl80" },
    { 10,   "sl96" },
    { 11,   "sl112" },
    { 12,   "sl128" },
    { 13,   "sl160" },
    { 14,   "sl320" },
    { 0,   NULL }
};

static const value_string  drx_short_cycle_vals[] =
{
    { 0,    "ms2" },
    { 1,    "ms3" },
    { 2,    "ms4" },
    { 3,    "ms5" },
    { 4,    "ms6" },
    { 5,    "ms7" },
    { 6,    "ms10" },
    { 7,    "ms14" },
    { 8,    "ms16" },
    { 9,    "ms20" },
    { 10,   "ms30" },
    { 11,   "ms32" },
    { 12,   "ms40" },
    { 13,   "ms64" },
    { 14,   "ms80" },
    { 15,   "ms128" },
    { 16,   "ms160" },
    { 17,   "ms256" },
    { 18,   "ms320" },
    { 19,   "ms512" },
    { 20,   "ms640" },
    { 0,   NULL }
};


/* Subtrees */
static gint ett_l2server = -1;
static gint ett_l2server_header = -1;
static gint ett_l2server_ra_info = -1;
static gint ett_l2server_params = -1;
static gint ett_l2server_l2_cell_dedicated_config = -1;
static gint ett_l2server_l1_cell_dedicated_config = -1;
static gint ett_l2server_rb_config = -1;
static gint ett_l2server_rb_release = -1;
static gint ett_l2server_rlc_config_tx = -1;
static gint ett_l2server_rlc_config_rx = -1;
static gint ett_l2server_ph_cell_config = -1;
static gint ett_l2server_sp_cell_cfg_ded = -1;
static gint ett_l2server_sp_cell_cfg_common = -1;
static gint ett_l2server_rx_lch_info = -1;
static gint ett_l2server_tx_lch_info = -1;
static gint ett_l2server_drx_config = -1;
static gint ett_l2server_mac_cell_group_config = -1;
static gint ett_l2server_spcell_config_ded = -1;

static gint ett_l2server_sp_cell_cfg_tdd = -1;
static gint ett_l2server_sp_cell_cfg_dl = -1;
static gint ett_l2server_sp_cell_cfg_ul = -1;
static gint ett_l2server_sp_cell_cfg_sup_ul = -1;
static gint ett_l2server_sp_cell_cfg_cross_carrier_sched = -1;
static gint ett_l2server_sp_cell_cfg_lte_crs_tomatcharound = -1;
static gint ett_l2server_sp_cell_cfg_dormantbwp = -1;
static gint ett_l2server_sp_cell_cfg_lte_crs_pattern_list1 = -1;
static gint ett_l2server_sp_cell_cfg_lte_crs_pattern_list2 = -1;


static expert_field ei_l2server_sapi_unknown = EI_INIT;
static expert_field ei_l2server_type_unknown = EI_INIT;

extern int proto_pdcp_nr;

static dissector_handle_t l2server_handle;
static dissector_handle_t pdcp_nr_handle;

void proto_reg_handoff_l2server (void);


/* Preferences */
static gboolean global_call_pdcp_for_drb = TRUE;
static gboolean global_call_pdcp_for_tm = TRUE;

// Configure number of DRB SN sequence bits?
enum pdcp_for_drb {
    PDCP_drb_SN_7=7,
    PDCP_drb_SN_12=12,
    PDCP_drb_SN_15=15,
    PDCP_drb_SN_18=18
};
static const enum_val_t pdcp_drb_col_vals[] = {
    {"pdcp-drb-sn-12",         "12-bit SN",           PDCP_drb_SN_12},
    {"pdcp-drb-sn-18",         "18-bit SN",           PDCP_drb_SN_18},
    {NULL, NULL, -1}
};
static gint global_pdcp_drb_sn_length = (gint)PDCP_drb_SN_18;




/* Using the same tabular approach in packet-prisma-sdr (from Lucio) */
typedef  void (*flds_funct)(proto_tree *, tvbuff_t *tvb, packet_info *, guint, guint);

typedef struct type_fun
{
    guint32      type;
    const gchar *prim_name;
    flds_funct   prim_fun;
} TYPE_FUN;


typedef struct sapi_fun
{
    guint32      sapi;
    const gchar *sapi_name;
    TYPE_FUN    *sapi_funs;
} SAPI_FUN;



/************************************************************************************/
/* Dissector functions for individual struct/message types                          */
static void dissect_sapi_type_dummy(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len)
{
    /* Payload (undissected) */
    proto_tree_add_item(tree, hf_l2server_payload, tvb, offset, len, ENC_NA);
}

/* Forward declarations */
static void dissect_rlcmac_cmac_config_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset _U_, guint len _U_);

static void dissect_login_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                              guint offset, guint len)
{
    /* CliName */
    proto_tree_add_item(tree, hf_l2server_client_name, tvb, offset, len, ENC_NA);
}

static void dissect_srv_start_cmd(proto_tree *tree _U_, tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                                  guint offset _U_, guint len _U_)
{
    /* N.B. Seems like the L2 server doesn't like payload, so don't expect it now... */
    /* Type - Not sure if should be like in header...? */
    //proto_tree_add_item(tree, hf_l2server_start_cmd_type, tvb, offset, 2, ENC_NA);
}

static void dissect_open_cell_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* L1Verbosity */
    proto_tree_add_item(tree, hf_l2server_l1verbosity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* L1Ulreport */
    proto_tree_add_item(tree, hf_l2server_l1ulreport, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* EnableCapsTest */
    proto_tree_add_item(tree, hf_l2server_enablecapstest, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_open_cell_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_cell_parm_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* CellId (but only 1 byte!) */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void dissect_cell_parm_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* CellId (1 byte) */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /**********************************/
    /* Parm (nr5g_l2_Srv_Cell_Parm_t) */
    /* TODO: add parm subtree */
    /* phy_cell_id */
    proto_tree_add_item(tree, hf_l2server_physical_cellid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    /* dlFreq[2] */
    offset += 8;
    /* dlEarfcn[2]*/
    offset += 8;
    /* ulFreq[2] */
    offset += 8;
    /* ulEarfcn[2] */
    offset += 8;
    /* SsbArfcn */
    offset += 4;

    /* NumDbeam */
    offset += 4;
    /* Dbeam */
}

/* This is nr5g_l2_Srv_RCP_LOADt from nr5g-l2_Srv.h */
static void dissect_rcp_load_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset, guint len _U_)
{
    /* RcGroup */
    proto_tree_add_item(tree, hf_l2server_radio_condition_group, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* DbeamId */
    proto_tree_add_item(tree, hf_l2server_dbeamid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Fname */
    proto_tree_add_item(tree, hf_l2server_fname, tvb, offset, -1, ENC_NA);
}


typedef enum rlc_mode_e { TM, UM, AM } rlc_mode_e;

static void dissect_rlcmac_data_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_,
                                    rlc_mode_e mode)
{
    /* Create pdcp-nr context info in case we are set to call dissector */
    struct pdcp_nr_info  *p_pdcp_nr_info = NULL;
    /* Allocate & zero struct (NR) */
    p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
    /* Look this up so can update channel info */
    p_pdcp_nr_info = (struct pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
    p_pdcp_nr_info->direction = PDCP_NR_DIRECTION_UPLINK;

    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item_ret_int(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN,
                                 (uint32_t*)&p_pdcp_nr_info->ueid);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* RbType */
    guint32 rbtype;
    proto_tree_add_item_ret_uint(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rbtype);
    offset += 1;
    /* enums align.. */
    p_pdcp_nr_info->plane = (enum pdcp_nr_plane)rbtype;

    /* SN Length */
    p_pdcp_nr_info->seqnum_length = global_pdcp_drb_sn_length;

    /* RbId */
    proto_tree_add_item_ret_uint(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN,
                                 (guint32*)&p_pdcp_nr_info->bearerId);
    offset++;
    /* LCH */
    guint32 lch;
    proto_tree_add_item_ret_uint(tree, hf_l2server_lch, tvb, offset, 1, ENC_LITTLE_ENDIAN, &lch);
    offset += 1;

    if (p_pdcp_nr_info->plane == NR_USER_PLANE) {
        p_pdcp_nr_info->bearerType = Bearer_DCCH;
    }
    else {
        p_pdcp_nr_info->seqnum_length = 12;

        // TODO: switch with all types (allowed in this direction).
        if (lch == 0x4) {
            p_pdcp_nr_info->bearerType = Bearer_CCCH;
        }
        else {
            p_pdcp_nr_info->bearerType = Bearer_DCCH;
        }
    }

    /* Ref(erence for CNF) */
    proto_tree_add_item(tree, hf_l2server_ref, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* MUI */
    proto_tree_add_item(tree, hf_l2server_mui, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* DataVolume */
    proto_tree_add_item(tree, hf_l2server_datavolume, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* ScGid */
    proto_tree_add_item(tree, hf_l2server_scgid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* Lcid */
    proto_tree_add_item(tree, hf_l2server_lcid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* UlLogRef */
    proto_tree_add_item(tree, hf_l2server_ullogref, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Traffic filter */
    proto_item *traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(traffic_ti);
    traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_ul, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(traffic_ti);

    switch (mode) {
        case TM:
            traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_tm, tvb, 0, 0, ENC_NA);
            proto_item_set_hidden(traffic_ti);
            p_pdcp_nr_info->seqnum_length = 0;
            p_pdcp_nr_info->maci_present = FALSE;
            break;
        case UM:
            traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_um, tvb, 0, 0, ENC_NA);
            proto_item_set_hidden(traffic_ti);
            break;
        case AM:
            traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_am, tvb, 0, 0, ENC_NA);
            proto_item_set_hidden(traffic_ti);
            break;
    }

    proto_item *pdcp_ti = proto_tree_add_item(tree, hf_l2server_pdcp_pdu, tvb, offset, len+8-offset, ENC_LITTLE_ENDIAN);

    /* Optionally call pdcp-nr dissector for this payload. */

    if (global_call_pdcp_for_drb && p_pdcp_nr_info->plane == NR_USER_PLANE) {
        // User-plane.
        tvbuff_t *pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_tvb);
        call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);

        proto_item_set_hidden(pdcp_ti);
    }
    // TODO: need more prefs...
    else if (p_pdcp_nr_info->plane == NR_SIGNALING_PLANE) {
        printf("%u: calling pdcp for signalling & UL\n", pinfo->num);
        tvbuff_t *pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_tvb);
        printf("Calling with length %u\n", p_pdcp_nr_info->pdu_length);
        call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);

        proto_item_set_hidden(pdcp_ti);
    }
}

static void dissect_rlcmac_data_req_tm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                       guint offset, guint len _U_)
{
    dissect_rlcmac_data_req(tree, tvb, pinfo, offset, len, TM);
}

static void dissect_rlcmac_data_req_um(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                       guint offset, guint len _U_)
{
    dissect_rlcmac_data_req(tree, tvb, pinfo, offset, len, UM);
}


static void dissect_rlcmac_data_req_am(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                       guint offset, guint len _U_)
{
    dissect_rlcmac_data_req(tree, tvb, pinfo, offset, len, AM);
}


static void dissect_rlcmac_data_cnf(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* RbType */
    proto_tree_add_item(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* RbId */
    proto_tree_add_item(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    /* LCH */
    proto_tree_add_item(tree, hf_l2server_lch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* Ref(erence for CNF) */
    proto_tree_add_item(tree, hf_l2server_ref, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* ScGid */
    proto_tree_add_item(tree, hf_l2server_scgid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* MUI */
    proto_tree_add_item(tree, hf_l2server_mui, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Traffic filters */
    proto_item *traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(traffic_ti);
    traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_am, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(traffic_ti);
    traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_cnf, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(traffic_ti);
}

static void dissect_rlcmac_data_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_, rlc_mode_e mode)
{
    /* Create pdcp-nr context info in case we are set to call dissector */
    struct pdcp_nr_info  *p_pdcp_nr_info = NULL;
    /* Allocate & zero struct (NR) */
    p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
    /* Store info in packet */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
    /* Look this up so can update channel info */
    p_pdcp_nr_info = (struct pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
    p_pdcp_nr_info->direction = PDCP_NR_DIRECTION_DOWNLINK;

    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item_ret_int(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN,
                                (uint32_t*)&p_pdcp_nr_info->ueid);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* RbType */
    guint32 rbtype;
    proto_tree_add_item_ret_uint(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rbtype);
    offset += 1;

    /* RbId */
    proto_tree_add_item_ret_uint(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN,
                                 (guint32*)&p_pdcp_nr_info->bearerId);
    offset++;
    /* LCH */
    guint32 lch;
    proto_tree_add_item_ret_uint(tree, hf_l2server_lch, tvb, offset, 1, ENC_LITTLE_ENDIAN, &lch);
    offset += 1;

    /* Filter for BCH traffic */
    switch (lch) {
        case 0x1:
        case 0x2:
        {
            proto_item *bch_ti = proto_tree_add_item(tree, hf_l2server_traffic_bch, tvb, 0, 0, ENC_NA);
            proto_item_set_hidden(bch_ti);
            break;
        }
        default:
            break;
    }

    /* enums align.. */
    p_pdcp_nr_info->plane = (enum pdcp_nr_plane)rbtype;
    if (p_pdcp_nr_info->plane == NR_USER_PLANE) {
        p_pdcp_nr_info->bearerType = Bearer_DCCH;
    }
    else {
        p_pdcp_nr_info->seqnum_length = 12;

        // TODO: switch with all types (allowed in this direction).
        if (lch == 0x4) {
            p_pdcp_nr_info->bearerType = Bearer_CCCH;
        }
        else if (lch == 0x2) {
            p_pdcp_nr_info->bearerType = Bearer_BCCH_DL_SCH;
        }
        else if (lch ==  0x1) {
            // TODO: what about SIBs and PCH?
            p_pdcp_nr_info->bearerType = Bearer_BCCH_BCH;
        }
        else {
            p_pdcp_nr_info->bearerType = Bearer_DCCH;
        }
    }


    /* ReEst */
    proto_tree_add_item(tree, hf_l2server_reest, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* Esbf */
    proto_tree_add_item(tree, hf_l2server_esbf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* DlLogRef (UeId(4) + RbId(1) + numPduForSdu(1) + SduInfo(4)) */
    //proto_tree_add_item(tree, hf_l2server_dllogref, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_l2server_numpduforsdu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    offset += 4;

    /* RlcMacInfo (RlcSn(4) + Info(1) + Frame(2) + Slot(2)) */
    proto_tree_add_item(tree, hf_l2server_rlcsn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_info, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_l2server_frame, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_l2server_slot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Traffic filter */
    proto_item *traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(traffic_ti);
    traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_dl, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(traffic_ti);

    switch (mode) {
        case TM:
            traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_tm, tvb, 0, 0, ENC_NA);
            proto_item_set_hidden(traffic_ti);
            p_pdcp_nr_info->seqnum_length = 0;
            break;
        case UM:
            traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_um, tvb, 0, 0, ENC_NA);
            proto_item_set_hidden(traffic_ti);
            break;
        case AM:
            traffic_ti = proto_tree_add_item(tree, hf_l2server_traffic_am, tvb, 0, 0, ENC_NA);
            proto_item_set_hidden(traffic_ti);
            break;
    }

    proto_item *pdcp_ti = proto_tree_add_item(tree, hf_l2server_pdcp_pdu, tvb, offset, len+8-offset, ENC_LITTLE_ENDIAN);

    /* Optionally call pdcp-nr dissector for this payload. */
    if (global_call_pdcp_for_drb && p_pdcp_nr_info->plane == NR_USER_PLANE) {
        /* SN Length */
        p_pdcp_nr_info->seqnum_length = global_pdcp_drb_sn_length;

        /* Call dissector with data */
        tvbuff_t *pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_tvb);
        call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);

        proto_item_set_hidden(pdcp_ti);
    }

    if (global_call_pdcp_for_tm && (mode == TM)) {
        p_pdcp_nr_info->maci_present = FALSE;

        /* Call dissector with data */
        tvbuff_t *pdcp_tvb;
        if (mode == TM) {
            pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        }
        else {
            pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        }
        p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_tvb);
        call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);

        proto_item_set_hidden(pdcp_ti);
    }
}

static void dissect_rlcmac_data_ind_tm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                       guint offset, guint len _U_)
{
    dissect_rlcmac_data_ind(tree, tvb, pinfo, offset, len, TM);
}

static void dissect_rlcmac_data_ind_um(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                       guint offset, guint len _U_)
{
    dissect_rlcmac_data_ind(tree, tvb, pinfo, offset, len, UM);
}


static void dissect_rlcmac_data_ind_am(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                       guint offset, guint len _U_)
{
    dissect_rlcmac_data_ind(tree, tvb, pinfo, offset, len, AM);
}


// nr5g_l2_Srv_CELL_CONFIGt from L2ServerMessages.h
static void dissect_cell_config_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_)
{
    // Spare
    offset += 4;
    // CellId
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // TA
    offset += 1;
    // RaInfoValid
    // RachProbeReq
    offset += 1;
    // RA_Info
    // if (ra_info_valid) {
    //    guint32 bwpid = 0;
    //    dissect_rlcmac_cmac_ra_info(tree, tvb, pinfo, offset, len, &bwpid);
    // }

    // CellCfg (nr5g_rlcmac_Cmac_CellCfg_t)
    // TODO:
}



static void dissect_create_ue_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* UeFlags */
    proto_tree_add_item(tree, hf_l2server_ueflags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* StkInst */
    proto_tree_add_item(tree, hf_l2server_stkinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* UdgStkInst */
    proto_tree_add_item(tree, hf_l2server_udg_stkinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_create_ue_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void dissect_delete_ue_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_delete_ue_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}



static void dissect_handover_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* RelCellId */
    proto_tree_add_item(tree, hf_l2server_rel_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* AddCellId */
    proto_tree_add_item(tree, hf_l2server_add_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* ScgType */
    proto_tree_add_item(tree, hf_l2server_scg_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* drb_ContinueROHC */
    proto_tree_add_item(tree, hf_l2server_drb_continue_rohc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* MacConfigLen */
    guint32 mac_config_len;
    proto_tree_add_item_ret_uint(tree, hf_l2server_mac_config_len,
                                 tvb, offset, 4, ENC_LITTLE_ENDIAN, &mac_config_len);
    offset += 4;
    /* TODO: put inside a subtree? */
    dissect_rlcmac_cmac_config_cmd(tree, tvb, pinfo, offset, mac_config_len);
}

static void dissect_handover_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_ra_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                           guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* RbType */
    proto_tree_add_item(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* RbId */
    proto_tree_add_item(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    /* Lch */
    proto_tree_add_item(tree, hf_l2server_lch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* MaxUpPwr */
    proto_tree_add_item(tree, hf_l2server_maxuppwr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* BRSRP */
    proto_tree_add_item(tree, hf_l2server_brsrp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* UE Category */
    proto_tree_add_item(tree, hf_l2server_ue_category, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Flags */
    proto_tree_add_item(tree, hf_l2server_ra_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* ScGid */
    proto_tree_add_item(tree, hf_l2server_scgid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* Spare 11 bytes */
    offset += 11;
    /* Rt_Preamble */
    offset ++;
    /* Rt_RaRnti */
    proto_tree_add_item(tree, hf_l2server_ra_rnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* UlSubCarrSpacing */
    proto_tree_add_item(tree, hf_l2server_ul_subcarrier_spacing, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    /* DiscardRarNum */
    proto_tree_add_item(tree, hf_l2server_discard_rar_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    /* NoData */
    proto_tree_add_item(tree, hf_l2server_no_data, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    /* Data/msg3... */

    // Add rach filter
    proto_item *rach_ti = proto_tree_add_item(tree, hf_l2server_rach, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(rach_ti);
}

static void dissect_ra_cnf(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                           guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Result code */
    proto_tree_add_item(tree, hf_l2server_result_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    /* RaRes */
    proto_tree_add_item(tree, hf_l2server_ra_res, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* Crnti */
    proto_tree_add_item(tree, hf_l2server_crnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* numberOfPreamblesSent */
    proto_tree_add_item(tree, hf_l2server_no_preambles_sent, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* contentionDetected */
    proto_tree_add_item(tree, hf_l2server_contention_detected, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    // Add rach filter
    proto_item *rach_ti = proto_tree_add_item(tree, hf_l2server_rach, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(rach_ti);
}

static void dissect_ra_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                           guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Result code */
    proto_tree_add_item(tree, hf_l2server_result_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    /* Crnti */
    proto_tree_add_item(tree, hf_l2server_crnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* CR Id */
    proto_tree_add_item(tree, hf_l2server_crid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // Add rach filter
    proto_item *rach_ti = proto_tree_add_item(tree, hf_l2server_rach, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(rach_ti);
}


/* Also format for RE_EST_END_IND */
static void dissect_re_est_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                               guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* RbType */
    proto_tree_add_item(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* RbId */
    proto_tree_add_item(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_item *reest_ti = proto_tree_add_item(tree, hf_l2server_reestablishment, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(reest_ti);
}

static void dissect_l1t_log_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                guint offset _U_, guint len _U_)
{
    /* Log filter */
    proto_item *log_ti = proto_tree_add_item(tree, hf_l2server_log, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(log_ti);

    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // bbInst (CellId + DbeamId)
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_l2server_dbeamid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // LogStr
    proto_tree_add_item(tree, hf_l2server_logstr, tvb, offset, 8+len-offset, ENC_LITTLE_ENDIAN);

    col_set_str(pinfo->cinfo, COL_INFO,
                tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 8+len-offset, ENC_UTF_8|ENC_NA));
}


// nr5g_rlcmac_Cmac_RA_Info_t (from nr5g-rlcmac_Cmac.h)
static guint dissect_rlcmac_cmac_ra_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                        guint offset, guint len _U_, guint32 *bwpid)
{
    int ra_start = offset;

    /* Subtree */
    proto_item *ra_info_ti = proto_tree_add_string_format(tree, hf_l2server_ra_info, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Cmac_RA_Info_t),
                                                          "", "RA Info ");
    proto_tree *ra_info_tree = proto_item_add_subtree(ra_info_ti, ett_l2server_header);

    // bwpId
    proto_tree_add_item_ret_int(ra_info_tree, hf_l2server_bwpid, tvb, offset, 4, ENC_LITTLE_ENDIAN, bwpid);
    offset += 4;
    // prach_ConfigIndex
    proto_tree_add_item(ra_info_tree, hf_l2server_prach_configindex, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // preambleReceivedTargetPower
    proto_tree_add_item(ra_info_tree, hf_l2server_preamble_receive_target_power, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // rsrp_ThresholdSSB
    proto_tree_add_item(ra_info_tree, hf_l2server_rsrp_thresholdssb, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // csirs_Threshold
    proto_tree_add_item(ra_info_tree, hf_l2server_csirs_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // sul_RSRP_Threshold
    proto_tree_add_item(ra_info_tree, hf_l2server_sul_rsrp_threshold, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // raPreambleIndex
    gint32 ra_preamble_index;
    proto_tree_add_item_ret_int(ra_info_tree, hf_l2server_ra_preambleindex, tvb, offset, 1, ENC_LITTLE_ENDIAN, &ra_preamble_index);
    offset++;
    // preamblePowerRampingStep
    proto_tree_add_item(ra_info_tree, hf_l2server_preamble_power_ramping_step, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // ra_ssb_OccassionMaskIndex
    proto_tree_add_item(ra_info_tree, hf_l2server_ra_ssb_occassion_mask_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // preambleTxMax
    proto_tree_add_item(ra_info_tree, hf_l2server_preamble_tx_max, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // totalNumberOfRA_Preambles
    gint32 num_preambles;
    proto_tree_add_item_ret_int(ra_info_tree, hf_l2server_totalnumberofra_preambles, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_preambles);
    offset++;

    // Add rach filter
    proto_item *rach_ti = proto_tree_add_item(ra_info_tree, hf_l2server_rach, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(rach_ti);

    // Summary.
    proto_item_append_text(ra_info_ti, " (BwpId=%d, ra-preambleIndex=%d, totalNumberOfRA_Preambles=%d)",
                           *bwpid, ra_preamble_index, num_preambles);

    // Move to start of next one..
    offset = ra_start + sizeof(nr5g_rlcmac_Cmac_RA_Info_t);
    return offset;
}

static guint dissect_rlcmac_cmac_ra_info_empty(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                               guint offset _U_, guint len _U_)
{
    int ra_start = offset;

    /* Subtree */
    proto_item *ra_info_ti = proto_tree_add_string_format(tree, hf_l2server_ra_info, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Cmac_RA_Info_t),
                                                          "", "RA Info ");
    //proto_tree *ra_info_tree = proto_item_add_subtree(ra_info_ti, ett_l2server_header);

    proto_item_append_text(ra_info_ti, " (Not in bwpMask)");

    // Move to start of next one..
    offset = ra_start + sizeof(nr5g_rlcmac_Cmac_RA_Info_t);
    return offset;
}

// bb_nr5g_PH_CELL_GROUP_CONFIGt (from bb-nr5g_struct.h)
static int dissect_ph_cell_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset)
{
    guint start_offset = offset;
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_ph_cell_config, tvb,
                                                         offset, sizeof(bb_nr5g_PH_CELL_GROUP_CONFIGt),
                                                          "", "PH Cell Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_ph_cell_config);

    // Fieldmask
    guint32 fieldmask;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                 ENC_LITTLE_ENDIAN, &fieldmask);
    gboolean dcp_config_present, pdcch_blind_detection_present;
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_ph_cell_dcp_config_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &dcp_config_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_ph_pdcch_blind_detection_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pdcch_blind_detection_present);

    offset += 4;

    // HarqACKSpatialBundlingPUCCH
    proto_tree_add_item(config_tree, hf_l2server_harq_ack_spatial_bundling_pucch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // HarqACKSpatialBundlingPUSCH
    proto_tree_add_item(config_tree, hf_l2server_harq_ack_spatial_bundling_pusch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // PmaxNR
    proto_tree_add_item(config_tree, hf_l2server_pmax_nr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // PdschHarqACKCodebook
    proto_tree_add_item(config_tree, hf_l2server_pdsch_harq_ack_codebook, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // McsRntValid
    offset += 1;
    // McsCRnti
    offset += 2;

    // PUE_FR1 [30..33]
    offset += 1;
    // TpcSrsRNTI
    offset += 4;
    // TpcPucchRNTI
    offset += 4;
    // TpcPuschRNTI
    offset += 4;
    // SpCsiRNTI
    offset += 4;
    // CsRNTI
    offset += 4;

    // Pdcch_BlindDetection (1..15)
    offset += 1;

    // TODO lots more...
    offset += 22;

    if (dcp_config_present) {
        // N.B. Size of this is fixed.
        offset += sizeof(bb_nr5g_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16t);
    }

    if (pdcch_blind_detection_present) {
        // N.B. Size of this is fixed.
        offset += sizeof(bb_nr5g_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16t);
    }

    proto_item_set_len(config_ti, offset-start_offset);

    return offset;
}

// bb_nr5g_SERV_CELL_CONFIGt (from bb-nr5g_struct.h)
static int dissect_sp_cell_cfg_ded(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset)
{
    //guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_sp_cell_cfg_ded, tvb,
                                                         offset, 0,
                                                          "", "SP Cell Cfg Dedicated");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_sp_cell_cfg_ded);

    // FieldMask
    proto_tree_add_item(config_tree, hf_l2server_field_mask_4, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    gboolean tdd_ded_present, dl_ded_present, ul_ded_present, sup_ul_present;
    gboolean cross_carrier_sched_present, lte_crs_tomatcharound_present;
    gboolean dormantbwp_present, lte_crs_pattern_list1_present, lte_crs_pattern_list2_present;

    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_tdd_ded_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &tdd_ded_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_dl_ded_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &dl_ded_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_ul_ded_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ul_ded_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_sup_ul_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sup_ul_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_cross_carrier_sched_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &cross_carrier_sched_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_lte_crs_tomatcharound_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &lte_crs_tomatcharound_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_dormantbwp_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &dormantbwp_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_lte_crs_pattern_list1_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &lte_crs_pattern_list1_present);
    proto_tree_add_item_ret_boolean(config_tree, hf_l2server_sp_cell_cfg_lte_crs_pattern_list2_present, tvb, offset, 4, ENC_LITTLE_ENDIAN, &lte_crs_pattern_list2_present);
    offset += 4;

    // ServCellIdx
    proto_tree_add_item(config_tree, hf_l2server_serv_cell_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // BwpInactivityTimer
    proto_tree_add_item(config_tree, hf_l2server_bwp_inactivity_timer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // TagId
    proto_tree_add_item(config_tree, hf_l2server_tag_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // SCellDeactTimer
    proto_tree_add_item(config_tree, hf_l2server_scell_deact_timer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // Dummy
    offset += 1;
    // PathlossRefLinking
    proto_tree_add_item(config_tree, hf_l2server_pathloss_ref_linking, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // ServCellMO
    proto_tree_add_item(config_tree, hf_l2server_serv_cell_mo, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // DefaultDlBwpId
    proto_tree_add_item(config_tree, hf_l2server_default_dl_bwpid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // SupplUlRel
    proto_tree_add_item(config_tree, hf_l2server_supp_ul_rel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // CaSlotOffsetIsValid
    proto_tree_add_item(config_tree, hf_l2server_ca_slot_offset_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // NbLteSrsPatternList1_r16
    proto_tree_add_item(config_tree, hf_l2server_nb_lte_srs_patternlist_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // NbLteCrsPatternList2_r16
    proto_tree_add_item(config_tree, hf_l2server_nb_lte_srs_patternlist_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // CaSlotOffset_r16 (actually a union)
    proto_tree_add_item(config_tree, hf_l2server_ca_slot_offset_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // N.B. Not really interested in r16-only fields for now..
    // CsiRsValidWithDCI_r16
    proto_tree_add_item(config_tree, hf_l2server_csi_rs_valid_with_dci_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // CrsRateMatchPerCORESETPoolIdx_r16
    offset += 1;
    // EnableTwoDefaultTCIStates_r16
    offset += 1;
    // EnableDefTCIStatePerCoresetPoolIdx_r16
    offset += 1;
    // EnableBeamSwitchTiming_r16
    offset += 1;
    // CbgTxDiffTBsProcessingType1_r16
    offset += 1;
    // CbgTxDiffTBsProcessingType2_r16
    offset += 1;
    // FirstActiveUlBwp_pCell
    proto_tree_add_item(config_tree, hf_l2server_first_active_ul_bwp_pcell, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // These groups all depend upon fieldmask's present flags.

    // TddDlUlConfDed (bb_nr5g_TDD_UL_DL_CONFIG_DEDICATEDt)
    if (tdd_ded_present) {
        guint32 start_offset = offset;
        proto_item *ded_ti = proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_tdd, tvb,
                                                          offset, sizeof(bb_nr5g_TDD_UL_DL_CONFIG_DEDICATEDt),
                                                          "", "TDD UL DL Config");
        proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_tdd);

        // NbSlotSpecCfgAddMod
        // TODO: add field!!!! - getting huge values...
        uint32_t nbSlotSpecCfgAddMod;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_nbslotspeccfg_addmod, tvb, offset, 2, ENC_LITTLE_ENDIAN, &nbSlotSpecCfgAddMod);
        offset += 2;
        // NbSlotSpecCfgDel
        uint32_t nbSlotSpecCfgDel;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_nbslotspeccfg_del, tvb, offset, 2, ENC_LITTLE_ENDIAN, &nbSlotSpecCfgDel);
        offset += 2;
        // SlotSpecCfgAddMod
        offset += (nbSlotSpecCfgAddMod * sizeof(bb_nr5g_TDD_UL_DL_SLOT_CONFIGt));
        // SlotSpecCfgDel
        offset += (nbSlotSpecCfgDel * sizeof(uint32_t));

        proto_item_set_len(ded_ti, offset-start_offset);
    }

    // DlCellCfgDed (bb_nr5g_DOWNLINK_DEDICATED_CONFIGt)
    if (dl_ded_present) {
        guint start_offset = offset;
        proto_item *ded_ti = proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_dl, tvb,
                                                              offset, 0,
                                                              "", "DL Config");
        proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_dl);

        // FieldMask
        guint32 field_mask;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_field_mask_4, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field_mask);
        offset += 4;

        // FirstActiveDlBwp
        offset += 1;
        // DefaultDlBwp
        offset += 1;
        // NbDlBwpIdToDel
        guint32 nbDlBwpIdToDel;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_nbdlbwpidtodel, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nbDlBwpIdToDel);
        offset += 1;
        // NbDlBwpIdToAdd
        guint32 nbDlBwpIdToAdd;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_nbdlbwpidtoadd, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nbDlBwpIdToAdd);
        offset += 1;
//    }
#if 1
        // NbDlBwpScsSpecCarrier
        guint8 nbDlBwpScsSpecCarrier = tvb_get_guint8(tvb, offset);
        offset += 1;
        // NbRateMatchPatternDedToAdd
        guint32 nbRateMatchPatternDedToAdd = tvb_get_guint8(tvb, offset);
        offset += 1;
        // NbRateMatchPatternDedToDel
        guint32 nbRateMatchPatternDedToDel = tvb_get_guint8(tvb, offset);
        offset += 1;
        // Pad
        offset += 1;
        // DlBwpIdToDel
        offset += (1 * bb_nr5g_MAX_NB_BWPS);


        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_INITIAL_DL_BWP_PRESENT) {
            // TODO: has several present flags and Nb fields...
            offset += sizeof(bb_nr5g_BWP_DOWNLINKDEDICATEDt);
        }
        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDSCH_PRESENT) {
            // TODO: contains a list..
            offset += sizeof(bb_nr5g_PDSCH_SERVING_CELL_CFGt);
        }
        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDCCH_PRESENT) {
            offset += sizeof(bb_nr5g_PDCCH_SERVING_CELL_CFGt);
        }
        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_CSI_MEAS_CFG_PRESENT) {
            // TODO: a lot more to do in here...
            offset += sizeof(bb_nr5g_CSI_MEAS_CFGt);
        }

        // DlBwpIdToAdd
        offset += (nbDlBwpIdToAdd * sizeof(bb_nr5g_BWP_DOWNLINKt));
        // DlChannelBwPerScs
        offset += (nbDlBwpScsSpecCarrier * sizeof(bb_nr5g_SCS_SPEC_CARRIERt));
        // RateMatchPatternDedToAdd
        offset += (nbRateMatchPatternDedToAdd * sizeof(bb_nr5g_RATE_MATCH_PATTERNt));
        // RateMatchPatternDedToDel
        offset += (nbRateMatchPatternDedToDel * sizeof(bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS));

        proto_item_set_len(ded_ti, offset-start_offset);
    }

    // UlCellCfgDed (bb_nr5g_UPLINK_DEDICATED_CONFIGt)
    if (ul_ded_present) {
        guint start_offset = offset;
        proto_item *ded_ti = proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_ul, tvb,
                                                              offset, sizeof(bb_nr5g_UPLINK_DEDICATED_CONFIGt),
                                                              "", "UL Config");
        proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_ul);

        // FieldMask
        guint32 field_mask;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_field_mask_4, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field_mask);
        offset += 4;
        // FirstActiveUlBwp
        offset += 1;
        // PowerBoostPi2BPSK
        offset += 1;
        // NbUlBwpIdToDel
        offset += 1;
        // NbUlBwpIdToAdd
        offset += 1;
        // NbUlBwpScsSpecCarrier
        offset += 1;
        // Pad
        offset += 3;
        // UlBwpIdToDel
        offset += (bb_nr5g_MAX_NB_BWPS * 1);

        // InitialUlBwp
        if (field_mask & bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_INITIAL_UL_BWP_PRESENT) {
            // TODO:
        }


        proto_item_set_len(ded_ti, offset-start_offset);
    }

    // SulCellCfgDed (bb_nr5g_UPLINK_DEDICATED_CONFIGt)
    if (sup_ul_present) {
        /*proto_item *ded_ti =*/ proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_sup_ul, tvb,
                                                              offset, sizeof(bb_nr5g_UPLINK_DEDICATED_CONFIGt),
                                                              "", "SUP UL Config");
        //proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_sup_ul);
        offset += sizeof(bb_nr5g_UPLINK_DEDICATED_CONFIGt);
    }

    // CrossCarrierSchedulingConfig (bb_nr5g_CROSS_CARRIER_SCHEDULING_CONFIGt)
    if (cross_carrier_sched_present) {
        /*proto_item *ded_ti =*/ proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_cross_carrier_sched, tvb,
                                                              offset, sizeof(bb_nr5g_UPLINK_DEDICATED_CONFIGt),
                                                              "", "Cross Carrier Sched");
        //proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_cross_carrier_sched);
        offset += sizeof(bb_nr5g_CROSS_CARRIER_SCHEDULING_CONFIGt);
    }

    // LteCrsToMatchAround (bb_nr5g_RATE_MATCH_PATTERN_LTEt)
    if (lte_crs_tomatcharound_present) {
        /*proto_item *ded_ti =*/ proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_lte_crs_tomatcharound, tvb,
                                                              offset, sizeof(bb_nr5g_RATE_MATCH_PATTERN_LTEt),
                                                              "", "tomatcharound");
        //proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_lte_crs_tomatcharound);
        offset += sizeof(bb_nr5g_RATE_MATCH_PATTERN_LTEt);
    }

    // DormantBWP_Config_r16 (bb_nr5g_DORMANTBWP_CONFIGt)
    if (dormantbwp_present) {
        /*proto_item *ded_ti =*/ proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_dormantbwp, tvb,
                                                              offset, sizeof(bb_nr5g_DORMANTBWP_CONFIGt),
                                                              "", "Dormant-BWP Config");
        //proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_dormantbwp);
        offset += sizeof(bb_nr5g_DORMANTBWP_CONFIGt);
    }

    // LteCrsPatternList1_r16 (bb_nr5g_RATE_MATCH_PATTERN_LTEt)
    if (lte_crs_pattern_list1_present) {
        /*proto_item *ded_ti =*/ proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_lte_crs_pattern_list1, tvb,
                                                              offset, sizeof(bb_nr5g_RATE_MATCH_PATTERN_LTEt),
                                                              "", "LTE CRS Pattern List1");
        //proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_lte_crs_pattern_list1);
        offset += sizeof(bb_nr5g_RATE_MATCH_PATTERN_LTEt);
    }

    // LteCrsPatternList2_r16 (bb_nr5g_RATE_MATCH_PATTERN_LTEt)
    if (lte_crs_pattern_list2_present) {
        /*proto_item *ded_ti =*/ proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_lte_crs_pattern_list2, tvb,
                                                              offset, sizeof(bb_nr5g_RATE_MATCH_PATTERN_LTEt),
                                                              "", "LTE CRS Pattern List2");
        //proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_lte_crs_pattern_list2);
        offset += sizeof(bb_nr5g_RATE_MATCH_PATTERN_LTEt);
    }


    //proto_item_set_len(config_ti, offset-start_offset);
    proto_item_set_len(config_ti, sizeof(bb_nr5g_SERV_CELL_CONFIGt));
#endif
    return offset;
}

// bb_nr5g_SERV_CELL_CONFIG_COMMONt (from bb-nr5g_struct.h)
static int dissect_sp_cell_cfg_common(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset)
{
    //guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_sp_cell_cfg_common, tvb,
                                                         offset, 0,
                                                          "", "SP Cell Cfg Common");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_sp_cell_cfg_common);

    // FieldMask
    proto_tree_add_item(config_tree, hf_l2server_field_mask_4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // ServCellIdx
    proto_tree_add_item(config_tree, hf_l2server_serv_cell_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // TODO:
    // SsbPeriodicityServCell
    offset += 1;
    // DmrsTypeAPos
    offset += 1;

    // TODO: !

    return offset;
}

static guint dissect_tx_lch_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset)
{
    guint start_offset = offset;
    proto_item *lch_info_ti = proto_tree_add_string_format(tree, hf_l2server_tx_lch_info, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Cmac_TxLchInfo_t),
                                                          "", "TxLchInfo ");
    proto_tree *lch_info_tree = proto_item_add_subtree(lch_info_ti, ett_l2server_tx_lch_info);


    // logicalChannelIdentity
    proto_tree_add_item(lch_info_tree, hf_l2server_lcid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // logicalChannelGroup
    proto_tree_add_item(lch_info_tree, hf_l2server_lcg, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // priority
    proto_tree_add_item(lch_info_tree, hf_l2server_priority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // prioritisedBitRate
    proto_tree_add_item(lch_info_tree, hf_l2server_prioritized_bit_rate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // bucketSizeDuration
    proto_tree_add_item(lch_info_tree, hf_l2server_bucket_size_duration, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // allowedServingCells
    proto_tree_add_item(lch_info_tree, hf_l2server_allowed_serving_cells, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // allowedSCS_List
    proto_tree_add_item(lch_info_tree, hf_l2server_allowed_scs_list, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // maxPUSCH_Duration
    proto_tree_add_item(lch_info_tree, hf_l2server_max_pusch_duration, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // configuredGrantTypeAllowed
    proto_tree_add_item(lch_info_tree, hf_l2server_configured_grant_type_allowed, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // logicalChannelSR_Mask
    proto_tree_add_item(lch_info_tree, hf_l2server_logical_channel_sr_mask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // logicalChannelSR_DelayTimerConfigured
    proto_tree_add_item(lch_info_tree, hf_l2server_logical_channel_sr_delay_timer_configured, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // requestDuplicatesFromPDCP
    proto_tree_add_item(lch_info_tree, hf_l2server_request_duplicates_from_pdcp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // schedulingRequestID
    proto_tree_add_item(lch_info_tree, hf_l2server_scheduling_request_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // bitRateQueryProhibitTimer
    proto_tree_add_item(lch_info_tree, hf_l2server_bit_rate_query_prohibit_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // allowedPHY_PriorityIndex
    proto_tree_add_item(lch_info_tree, hf_l2server_allowed_phy_priority_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return start_offset + sizeof(nr5g_rlcmac_Cmac_TxLchInfo_t);
}

static guint dissect_rx_lch_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset)
{
    guint start_offset = offset;
    proto_item *lch_info_ti = proto_tree_add_string_format(tree, hf_l2server_rx_lch_info, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Cmac_RxLchInfo_t),
                                                          "", "RxLchInfo ");
    proto_tree *lch_info_tree = proto_item_add_subtree(lch_info_ti, ett_l2server_rx_lch_info);


    // logicalChannelIdentity
    proto_tree_add_item(lch_info_tree, hf_l2server_lcid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    return start_offset + sizeof(nr5g_rlcmac_Cmac_RxLchInfo_t);
}

// nr5g_rlcmac_Cmac_DRX_CONFIGt (from nr5g-rlcmac_Cmac-bb.h)
static int dissect_rlcmac_drx_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                     guint offset)
{
    int start_offset = offset;

    proto_item *drx_ti = proto_tree_add_string_format(tree, hf_l2server_drx_config, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Cmac_DRX_CONFIGt),
                                                          "", "DRX Config ");
    proto_tree *drx_tree = proto_item_add_subtree(drx_ti, ett_l2server_drx_config);

    // Len
    proto_tree_add_item(drx_tree, hf_l2server_drx_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // Spare
    proto_tree_add_item(drx_tree, hf_l2server_spare4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_onDurationTimer_IsValid
    proto_tree_add_item(drx_tree, hf_l2server_drx_ondurationtimer_isvalid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // drx_onDurationTimer
    proto_tree_add_item(drx_tree, hf_l2server_drx_ondurationtimer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_InactivityTimer
    proto_tree_add_item(drx_tree, hf_l2server_drx_inactivitytimer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_HARQ_RTT_TimerDL
    proto_tree_add_item(drx_tree, hf_l2server_drx_harq_rtt_timerdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // drx_HARQ_RTT_TimerUL
    proto_tree_add_item(drx_tree, hf_l2server_drx_harq_rtt_timerul, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // drx_RetransmissionTimerDL
    proto_tree_add_item(drx_tree, hf_l2server_drx_retransmission_timerdl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_RetransmissionTimerUL
    proto_tree_add_item(drx_tree, hf_l2server_drx_retransmission_timerul, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_LongCycleStartOffset_IsValid
    proto_tree_add_item(drx_tree, hf_l2server_drx_longcyclestartoffset_isvalid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // drx_LongCycleStartOffset
    proto_tree_add_item(drx_tree, hf_l2server_drx_longcyclestartoffset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_ShortCycle
    proto_tree_add_item(drx_tree, hf_l2server_drx_short_cycle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_ShortCycleTimer
    proto_tree_add_item(drx_tree, hf_l2server_drx_short_cycle_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // drx_SlotOffset
    proto_tree_add_item(drx_tree, hf_l2server_drx_slot_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return start_offset + sizeof(nr5g_rlcmac_Cmac_DRX_CONFIGt);
}


// Type is nr5g_rlcmac_Cmac_CONFIG_CMD_t
static void dissect_rlcmac_cmac_config_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset, guint len _U_)
{
    // UEId
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    //------------------------------------------------------------------
    // Params (of type nr5g_rlcmac_Cmac_CfgParams_t)
    /* Subtree */
    guint params_offset = offset;
    proto_item *params_ti = proto_tree_add_string_format(tree, hf_l2server_params, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Cmac_CfgParams_t),
                                                          "", "Params");
    proto_tree *params_tree = proto_item_add_subtree(params_ti, ett_l2server_params);

    // Beam Id
    offset += 4;
    // Crnti
    gint32 crnti;
    proto_tree_add_item_ret_int(params_tree, hf_l2server_crnti, tvb, offset, 4, ENC_LITTLE_ENDIAN, &crnti);
    proto_item_append_text(params_ti, " (C-RNTI=%d", crnti);
    offset += 4;
    // BwpMask
    guint32 bwpmask;
    proto_tree_add_item_ret_uint(params_tree, hf_l2server_bwpmask, tvb, offset, 4, ENC_LITTLE_ENDIAN, &bwpmask);
    offset += 4;

    // RA_Info array (type nr5g_rlcmac_Cmac_RA_Info_t)
    // Only dissect those positions with bwpmask fields set
    for (int n=0; n < bb_nr5g_MAX_NB_BWPS+1; n++) {
        if (bwpmask & (1 << n)) {
            guint32 bwpid;
            offset = dissect_rlcmac_cmac_ra_info(params_tree, tvb, pinfo, offset, len, &bwpid);
            /* Add summary to params root */
            proto_item_append_text(params_ti, " RAInfo(BwpId=%u)", bwpid);
        }
        else {
            offset = dissect_rlcmac_cmac_ra_info_empty(params_tree, tvb, pinfo, offset, len);
            //offset += sizeof(nr5g_rlcmac_Cmac_RA_Info_t);
        }
    }

    //-----------------------------------------------------------------
    // RbIE
    // NumOfRbCfg
    guint32 num_of_rb_cfg;
    proto_tree_add_item_ret_uint(params_tree, hf_l2server_num_of_rb_cfg, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_of_rb_cfg);
    offset++;
    for (guint n=0; n < num_of_rb_cfg; n++) {
        // Subtree.
        proto_item *rb_config_ti = proto_tree_add_string_format(params_tree, hf_l2server_rb_config, tvb,
                                                              offset, sizeof(nr5g_rlcmac_Cmac_RbCfg_t),
                                                              "", "RBConfig ");
        proto_tree *rb_info_tree = proto_item_add_subtree(rb_config_ti, ett_l2server_rb_config);

        // RbType
        guint32 rbtype;
        proto_tree_add_item_ret_uint(rb_info_tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rbtype);
        offset += 1;
        // RbId
        guint32 rbid;
        proto_tree_add_item_ret_uint(rb_info_tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rbid);
        offset += 1;
        // reestablishRLC
        offset += 1;
        // RbMappingInfo

        // TxLchInfo
        offset = dissect_tx_lch_info(rb_info_tree, tvb, pinfo, offset);
        // RxLchInfo
        offset = dissect_rx_lch_info(rb_info_tree, tvb, pinfo, offset);
        //zoffset += sizeof(nr5g_rlcmac_Cmac_RbMappingInfo_t);

        proto_item_append_text(rb_config_ti, "(%s-%u)", (rbtype==1) ? "SRB" : "DRB", rbid);
        proto_item_append_text(params_ti, " RBCfg(%s-%u)", (rbtype==1) ? "SRB" : "DRB", rbid);
    }
    // Remaining unused entries.
    for (guint n=num_of_rb_cfg; n < nr5g_MaxNrOfRB; n++) {
        // Subtree.
        /*proto_item *rb_config_ti = */ proto_tree_add_string_format(params_tree, hf_l2server_rb_config, tvb,
                                                              offset, sizeof(nr5g_rlcmac_Cmac_RbCfg_t),
                                                              "", "RBConfig %u (not in use)", n+1);
        //proto_tree *ra_info_tree = proto_item_add_subtree(ra_info_ti, ett_l2server_rb_config);

        offset += sizeof(nr5g_rlcmac_Cmac_RbCfg_t);
    }

    // NumOfRbRel
    guint32 num_of_rb_rel;
    proto_tree_add_item_ret_uint(params_tree, hf_l2server_num_of_rb_rel, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_of_rb_rel);
    offset++;
    for (guint n=0; n < num_of_rb_rel; n++) {
        // Subtree.
        proto_item *rb_del_ti = proto_tree_add_string_format(params_tree, hf_l2server_rb_rel, tvb,
                                                             offset, 2,
                                                              "", "RBDel");
        proto_tree *rb_info_tree = proto_item_add_subtree(rb_del_ti, ett_l2server_rb_release);

        // RbType
        guint32 rbtype;
        proto_tree_add_item_ret_uint(rb_info_tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rbtype);
        offset += 1;
        // RbId
        guint32 rbid;
        proto_tree_add_item_ret_uint(rb_info_tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rbid);
        offset += 1;

        proto_item_append_text(rb_del_ti, "(%s-%u)", (rbtype==1) ? "SRB" : "DRB", rbid);
        proto_item_append_text(params_ti, " RBRel(%s-%u)", (rbtype==1) ? "SRB" : "DRB", rbid);
    }
    // Remaining unused entries.
    for (guint n=num_of_rb_rel; n < nr5g_MaxNrOfRB; n++) {
        // Subtree.
        /*proto_item *rb_config_ti = */ proto_tree_add_string_format(params_tree, hf_l2server_rb_rel, tvb,
                                                              offset, sizeof(nr5g_rlcmac_Cmac_RbRel_t),
                                                              "", "RBRel %u (not in use)", n+1);
        //proto_tree *ra_info_tree = proto_item_add_subtree(ra_info_ti, ett_l2server_rb_release);

        offset += sizeof(nr5g_rlcmac_Cmac_RbRel_t);
    }
    proto_item_append_text(params_ti, ")");
    //-----------------------------------------------------------------


    // mac_CellGroupConfig
    proto_tree_add_string_format(params_tree, hf_l2server_mac_cell_group_config, tvb,
                                 offset, sizeof(nr5g_rlcmac_Cmac_MAC_CellGroupConfig_t),
                                 "", "MAC Cell Group Config");
    offset += sizeof(nr5g_rlcmac_Cmac_MAC_CellGroupConfig_t);

    // spCellConfig
    proto_tree_add_string_format(params_tree, hf_l2server_spcell_config, tvb,
                                 offset, sizeof(nr5g_rlcmac_Cmac_SpCellConfig_t),
                                 "", "spCell Config");
    offset += sizeof(nr5g_rlcmac_Cmac_SpCellConfig_t);

    // sCellList
    proto_tree_add_string_format(params_tree, hf_l2server_scell_list, tvb,
                                 offset, sizeof(nr5g_rlcmac_Cmac_SCellList_t),
                                 "", "sCell List");
    offset += sizeof(nr5g_rlcmac_Cmac_SCellList_t);
    offset = params_offset + sizeof(nr5g_rlcmac_Cmac_CfgParams_t);

    //------------------------------------------------------------------

    // L2TestMode (not set by rrcCOM.c)
    proto_tree_add_item(tree, hf_l2server_l2_test_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    // RL_Failure_Timer
    proto_tree_add_item(tree, hf_l2server_rl_failure_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // RL_SyncOn_Timer
    proto_tree_add_item(tree, hf_l2server_rl_syncon_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // SegCnt (apparently not set?)
    proto_tree_add_item(tree, hf_l2server_seg_cnt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    // enablePmiReporting
    proto_tree_add_item(tree, hf_l2server_enable_pmi_reporting, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // RA_InfoIsForSUL
    proto_tree_add_item(tree, hf_l2server_ra_for_sul, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // Spare1[2]
    offset += 2;
    // Spare[3]
    offset += (3*4);

    // L1CellDedicatedConfig_Len (apparently not set in rrcCOM.c)
    int l1cell_dedicated_config_len;
    proto_tree_add_item_ret_int(tree, hf_l2server_l1cell_dedicated_config_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &l1cell_dedicated_config_len);
    offset += 4;
    //---------------------------------------------------------------
    // L2CellDedicatedConfig (nr5g_rlcmac_Cmac_CELL_DEDICATED_CONFIGt)
    // TODO: get length from Len field.
    guint32 dedicated_start = offset;

    guint32 l2_len = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_item *l2_dedicated_config_ti = proto_tree_add_string_format(tree, hf_l2server_l2_cell_dedicated_config, tvb,
                                                          offset, l2_len,
                                                          "", "L2 Cell Dedicated Config");
    proto_tree *l2_dedicated_config_tree = proto_item_add_subtree(l2_dedicated_config_ti, ett_l2server_l2_cell_dedicated_config);

    // Len
    proto_tree_add_item(l2_dedicated_config_tree, hf_l2server_l2_cell_dedicated_config_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // FieldMask (2 bytes)
    guint32 field_mask;
    proto_tree_add_item_ret_uint(l2_dedicated_config_tree, hf_l2server_field_mask_2, tvb, offset, 2, ENC_LITTLE_ENDIAN, &field_mask);
    offset += 2;

    // NbSCellCfgDel
    offset += 1;
    // NbSCellCgDel
    offset += 1;
    // PhyCellConfig (CsRNTI)
    offset += 4;

    // SpCellCfgDed
    if (field_mask & nr5g_rlcmac_Cmac_STRUCT_SPCELL_CONFIG_DED_PRESENT) {
        guint ded_start_offset = offset;

        proto_item *spcell_config_ded_ti = proto_tree_add_string_format(l2_dedicated_config_tree, hf_l2server_spcell_config_ded, tvb,
                                                                        offset, 0,
                                                              "", "spCell Config Dedicated");
        proto_tree *spcell_config_ded_tree = proto_item_add_subtree(spcell_config_ded_ti, ett_l2server_spcell_config_ded);

        // Len
        guint32 ded_len;
        proto_tree_add_item_ret_uint(spcell_config_ded_tree, hf_l2server_spcell_config_ded_len, tvb, offset, 4,
                                     ENC_LITTLE_ENDIAN, &ded_len);
        offset += 4;

        proto_item_set_len(spcell_config_ded_ti, ded_len);
        offset = ded_start_offset + ded_len;
    }

    // MAC_CellGroupConfig(nr5g_rlcmac_Cmac_MAC_CELL_GROUP_CONFIGt)
    // TODO: field_mask not as expected!!!!!
    if (field_mask & nr5g_rlcmac_Cmac_STRUCT_MAC_CELL_GROUP_CONFIG_PRESENT) {
        proto_item *mac_cell_group_ti = proto_tree_add_string_format(l2_dedicated_config_tree, hf_l2server_mac_cell_group_config, tvb,
                                                              offset, 0,
                                                              "", "MAC Cell Group");
        proto_tree *mac_cell_group_tree = proto_item_add_subtree(mac_cell_group_ti, ett_l2server_mac_cell_group_config);

        // Len
        guint32 mac_cell_group_len;
        proto_tree_add_item_ret_uint(mac_cell_group_tree, hf_l2server_mac_cell_group_len, tvb, offset, 4,
                                     ENC_LITTLE_ENDIAN, &mac_cell_group_len);
        offset += 4;
        // FieldMask
        guint32 field_mask_4;
        proto_tree_add_item_ret_uint(mac_cell_group_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                     ENC_LITTLE_ENDIAN, &field_mask_4);
        offset += 4;
        // lch_BasedPrioritization_r16
        offset += 1;
        // Spare[3]
        offset += 3;

        //------------------------------------
        // DrxConfig here (nr5g_rlcmac_Cmac_DRX_CONFIGt)
        if (field_mask_4 & nr5g_rlcmac_Cmac_STRUCT_DRX_CONFIG_PRESENT) {
            offset = dissect_rlcmac_drx_config(mac_cell_group_tree, tvb, pinfo, offset);
            proto_item_append_text(mac_cell_group_ti, " (DRX)");
        }

        proto_item_set_len(mac_cell_group_ti, mac_cell_group_len);
    }

    // Skip to pass this.
    offset = dedicated_start +  l2_len;


    //---------------------------------------------------------------
    // L1CellDedicatedConfig (bb_nr5g_CELL_DEDICATED_CONFIGt)
    if (l1cell_dedicated_config_len > 0) {
        dedicated_start = offset;
        proto_item *l1_dedicated_config_ti = proto_tree_add_string_format(tree, hf_l2server_l1_cell_dedicated_config, tvb,
                                                              offset, l1cell_dedicated_config_len,
                                                              "", "L1 Cell Dedicated Config");
        proto_tree *l1_dedicated_config_tree = proto_item_add_subtree(l1_dedicated_config_ti, ett_l2server_l1_cell_dedicated_config);
        // NbSCellCfgAdd
        proto_tree_add_item(l1_dedicated_config_tree, hf_l2server_nb_scell_cfg_add, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // NbSCellCfgDel
        proto_tree_add_item(l1_dedicated_config_tree, hf_l2server_nb_scell_cfg_del, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // FieldMask
        proto_tree_add_item(l1_dedicated_config_tree, hf_l2server_field_mask_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        gboolean ded_present, common_present;
        proto_tree_add_item_ret_boolean(l1_dedicated_config_tree, hf_l2server_field_mask_1_ded_present, tvb, offset, 1, ENC_LITTLE_ENDIAN, &ded_present);
        proto_tree_add_item_ret_boolean(l1_dedicated_config_tree, hf_l2server_field_mask_1_common_present, tvb, offset, 1, ENC_LITTLE_ENDIAN, &common_present);
        offset += 1;

        // PhyCellCnf (bb_nr5g_PH_CELL_GROUP_CONFIGt)
        offset = dissect_ph_cell_config(l1_dedicated_config_tree, tvb, pinfo, offset);

        // TODO: don't understand why we seem to be out here!!!!!????
        offset += 6;

        if (ded_present) {
        // SpCellCfgDed
            offset = dissect_sp_cell_cfg_ded(l1_dedicated_config_tree, tvb, pinfo, offset);
        }

        if (common_present) {
            // SpCellCfgCommon
            offset = dissect_sp_cell_cfg_common(l1_dedicated_config_tree, tvb, pinfo, offset);
        }

        // Skip to pass this.
        offset = dedicated_start + l1cell_dedicated_config_len;
    }
}

// I don't actually see a type for this message!!!!
static void dissect_rlcmac_cmac_config_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset, guint len _U_)
{
    // UEId
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    //offset += 4;
}


//  "To Debug Rach Access" - we don't seem to be sending it.
static void dissect_cmac_rach_cfg_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // RA_Info
    guint32 bwpid;
    offset = dissect_rlcmac_cmac_ra_info(tree, tvb, pinfo, offset, len, &bwpid);
}

static void dissect_crlc_tm_config(proto_tree *tree _U_, tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                                   guint offset _U_)
{
    /* TODO */
}

static void dissect_crlc_um_config(proto_tree *tree _U_, tvbuff_t *tvb _U_, packet_info *pinfo _U_,
                                   guint offset _U_)
{
    /* TODO */
}

static void dissect_crlc_am_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    /* Tx */
    proto_item *tx_ti = proto_tree_add_string_format(tree, hf_l2server_rlc_config_tx, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Crlc_TxAmParm_t),
                                                          "", "Tx");
    proto_tree *tx_tree = proto_item_add_subtree(tx_ti, ett_l2server_rlc_config_tx);
    /* SnLength */
    guint32 sn_length;
    proto_tree_add_item_ret_uint(tx_tree, hf_l2server_rlc_snlength, tvb, offset, 1, ENC_LITTLE_ENDIAN, &sn_length);
    offset += 1;
    /* t_PollRetransmit */
    proto_tree_add_item(tx_tree, hf_l2server_rlc_t_poll_retransmit, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* pollPDU */
    proto_tree_add_item(tx_tree, hf_l2server_rlc_poll_pdu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* pollByte */
    proto_tree_add_item(tx_tree, hf_l2server_rlc_poll_byte, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    /* maxRetxThreshold */
    proto_tree_add_item(tx_tree, hf_l2server_rlc_max_retx_threshold, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* discardTimer */
    proto_tree_add_item(tx_tree, hf_l2server_rlc_discard_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_append_text(tx_ti, " (SN-Length=%u)", sn_length);

    /* Rx */
    proto_item *rx_ti = proto_tree_add_string_format(tree, hf_l2server_rlc_config_rx, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Crlc_RxAmParm_t),
                                                          "", "Rx");
    proto_tree *rx_tree = proto_item_add_subtree(rx_ti, ett_l2server_rlc_config_rx);
    /* SnLength */
    proto_tree_add_item_ret_uint(rx_tree, hf_l2server_rlc_snlength, tvb, offset, 1, ENC_LITTLE_ENDIAN, &sn_length);
    offset += 1;
    /* t_Reassembly */
    proto_tree_add_item(rx_tree, hf_l2server_rlc_t_reassembly, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* t_StatusProhibit */
    proto_tree_add_item(rx_tree, hf_l2server_rlc_t_status_prohibit, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_append_text(rx_ti, " (SN-Length=%u)", sn_length);
}

static void dissect_crlc_config_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* RbId */
    proto_tree_add_item(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* ER */
    proto_tree_add_item(tree, hf_l2server_rlc_er, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* RbType */
    proto_tree_add_item(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* RlcMode */
    guint32 rlc_mode;
    proto_tree_add_item_ret_uint(tree, hf_l2server_rlc_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rlc_mode);
    offset += 1;

    /* TODO: not filled in if doing e.g. release? */
    /* Parm */
    switch (rlc_mode) {
        case nr5g_TM:
            /* (nr5g_rlcmac_Crlc_TmParm_t) */
            dissect_crlc_tm_config(tree, tvb, pinfo, offset);
            break;
        case nr5g_UM:
            /* (nr5g_rlcmac_Crlc_UmParm_t) */
            dissect_crlc_um_config(tree, tvb, pinfo, offset);
            break;
        case nr5g_AM:
            /* (nr5g_rlcmac_Crlc_AmParm_t) */
            dissect_crlc_am_config(tree, tvb, pinfo, offset);
            break;
    }
}

// nr5g_rlcmac_Crlc_ACK_t (from nr5g-rlcmac_Crlc.h)
// Doesn't seem to match properly though... (params ordered changed? One of them is ER?)
static void dissect_crlc_config_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* RbType */
    proto_tree_add_item(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* RbId */
    proto_tree_add_item(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
}


static void dissect_version_info_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                     guint offset, guint len _U_)
{
    // Spare (should be zero)
    proto_tree_add_item(tree, hf_l2server_spare2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

static void dissect_version_info_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                     guint offset, guint len _U_)
{
    // Package type
    proto_tree_add_item(tree, hf_l2server_package_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // N.B. L2 doesn't seem to encode these!
    // PackageVersion (up to 60 bytes)
    // AmmVerion (up to 60 bytes)
}

static void dissect_dbeam_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                              guint offset, guint len _U_)
{
    // Spare
    proto_tree_add_item(tree, hf_l2server_spare4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // CellId
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // DbeamId
    proto_tree_add_item(tree, hf_l2server_dbeamid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // Status
    proto_tree_add_item(tree, hf_l2server_dbeam_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // NumBeam
    proto_tree_add_item(tree, hf_l2server_num_beams, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_ppu_list_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset, guint len _U_)
{
    // NCellLte
    proto_tree_add_item(tree, hf_l2server_ncelllte, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // NCellNr
    proto_tree_add_item(tree, hf_l2server_ncellnr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // NumLteProPdu
    guint32 num_lte_pro_pdu;
    proto_tree_add_item_ret_uint(tree, hf_l2server_numltepropdu, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_lte_pro_pdu);
    offset += 1;
    // NumNrProPdu
    proto_tree_add_item(tree, hf_l2server_numnrpropdu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // CellIdNrList[].
    for (guint32 n=0; n < num_lte_pro_pdu; n++) {
        proto_tree_add_item(tree, hf_l2server_cellidlteitem, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
}

// Showing nr5g_l2_Srv_CFG_02t from L2ServerMesages.h
// (variation controlled by type field)
static void dissect_l2_srv_cfg_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset, guint len _U_)
{
    // Type (i.e. which type of struct this is).
    proto_tree_add_item(tree, hf_l2server_config_cmd_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // Side (lte_Side_v)
    proto_tree_add_item(tree, hf_l2server_side, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // BotLayer
    proto_tree_add_item(tree, hf_l2server_bot_layer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // Trf
    proto_tree_add_item(tree, hf_l2server_trf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // TODO:
    // UDG timeout configuration
    // Alive
    offset += 4;
    // TxErr
    offset += 4;
    // StartTO
    offset += 4;
    // TermTO
    offset += 4;
    // TermAckTO
    offset += 4;
    // NLost
    offset += 4;
    // NStartRetry
    offset += 4;
    // NTermRetry
    offset += 4;

    // UDG Tamp config
    // TstMsk
    offset += 4;
    // UlBLim
    offset += 4;
    // UlRampDt
    offset += 4;
    // DlBLim
    offset += 4;
    // DlRmpDt
    offset += 4;
    // SendBuf
    offset += 4;
    // RecvBuf
    offset += 4;

    // En (Interface number)
    offset += 4;
    // GiIp
    offset += 4;
    // GiMask
    offset += 4;
    // GiIp6
    offset += 16;
    // Prefix
    offset += 4;
    // Technology (LTE=1, NR=2)
    proto_tree_add_item(tree, hf_l2server_technology, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // EnbSim
    proto_tree_add_item(tree, hf_l2server_enbsim, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // Flags
    offset += 4;
    // L2MaintenanceFlags
    offset += 4;


    // TODO:
}

// nr5g_l2_Srv_SETPARM_03t (from L2ServerMessages.h)
static void dissect_setparm_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                guint offset, guint len _U_)
{
    // Type
    proto_tree_add_item(tree, hf_l2server_setparm_cmd_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // MaxUE
    proto_tree_add_item(tree, hf_l2server_max_ue, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // MaxPdcp
    proto_tree_add_item(tree, hf_l2server_max_pdcp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // MaxNat
    proto_tree_add_item(tree, hf_l2server_max_nat, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // MaxUdgSess
    proto_tree_add_item(tree, hf_l2server_max_udg_sess, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // MaxCntr
    proto_tree_add_item(tree, hf_l2server_max_cntr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // TODO: more fields
}



static void dissect_rlcmac_error(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset, guint len _U_)
{
    /* Log filter */
    proto_item *log_ti = proto_tree_add_item(tree, hf_l2server_log, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(log_ti);

    // Not sure what this is...
    offset += 2;
    // LogStr
    proto_tree_add_item(tree, hf_l2server_logstr, tvb, offset, len-offset+8, ENC_LITTLE_ENDIAN);

    col_set_str(pinfo->cinfo, COL_INFO,
                tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len-offset+8, ENC_UTF_8|ENC_NA));

}



static void dissect_cmac_status_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_)
{
    /* Log filter */
    proto_item *log_ti = proto_tree_add_item(tree, hf_l2server_log, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(log_ti);

    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Cmac Status. */
    guint32 status;
    proto_tree_add_item_ret_uint(tree, hf_l2server_cmac_status, tvb, offset, 1, ENC_LITTLE_ENDIAN, &status);
    offset += 1;

    col_set_str(pinfo->cinfo, COL_INFO, "CMAC Status Ind - ");
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(status, cmac_status_vals, "Unknown"));
}

static void dissect_rcp_ue_set_group_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Radio condition group */
    proto_tree_add_item(tree, hf_l2server_radio_condition_group, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_rcp_ue_set_group_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_rcp_set_ue_index_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Radio Condition Profile Index */
    proto_tree_add_item(tree, hf_l2server_radio_condition_profile_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_rcp_set_ue_index_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_cmac_reset_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

// N.B. also used for ack, where type is identical.
static void dissect_sib_filter_act_deact_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                             guint offset, guint len _U_)
{
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* SibFilterFlag */
    offset += 4;
}

static void dissect_sib_filter_act_deact_nak(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                             guint offset, guint len _U_)
{
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* TODO: Err */
    offset += 2;
}


/************************************************************************************/



/* OM */
static TYPE_FUN om_type_funs[] =
{
        { lte_l2_Srv_LOGIN_CMD,              "lte_L2_Srv_LOGIN_CMD",       dissect_login_cmd },
        { lte_l2_Srv_LOGIN_ACK,              "lte_L2_Srv_LOGIN_ACK",       dissect_sapi_type_dummy /* TODO */},
        { lte_l2_Srv_LOGIN_NAK,              "lte_L2_Srv_LOGIN_NAK",       dissect_sapi_type_dummy /* TODO */},

        { lte_l2_Srv_VERSION_INFO_CMD,       "lte_l2_Srv_VERSION_INFO_CMD",       dissect_version_info_cmd},
        { lte_l2_Srv_VERSION_INFO_ACK,       "lte_l2_Srv_VERSION_INFO_ACK",       dissect_version_info_ack},
        { lte_l2_Srv_VERSION_INFO_NAK,       "lte_l2_Srv_VERSION_INFO_NAK",       dissect_sapi_type_dummy /* TODO */},

        { nr5g_l2_Srv_BASE_TYPE,             "nr5g_l2_Srv_BASE_TYPE",       dissect_sapi_type_dummy /* TODO */},

        { nr5g_l2_Srv_CFG_CMD,               "nr5g_l2_Srv_CFG_CMD",       dissect_l2_srv_cfg_cmd},
        { nr5g_l2_Srv_CFG_ACK,               "nr5g_l2_Srv_CFG_ACK",       dissect_sapi_type_dummy /* TODO */},
        { nr5g_l2_Srv_CFG_NAK,               "nr5g_l2_Srv_CFG_NAK",       dissect_sapi_type_dummy /* TODO */},

        { nr5g_l2_Srv_CELL_PPU_LIST_CMD,     "nr5g_l2_Srv_CELL_PPU_LIST_CMD",       dissect_sapi_type_dummy },
        { nr5g_l2_Srv_CELL_PPU_LIST_ACK,     "nr5g_l2_Srv_CELL_PPU_LIST_ACK",       dissect_ppu_list_ack },
        { nr5g_l2_Srv_CELL_PPU_LIST_NAK,     "nr5g_l2_Srv_CELL_PPU_LIST_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_SETPARM_CMD,           "nr5g_l2_Srv_SETPARM_CMD",       dissect_setparm_cmd },
        { nr5g_l2_Srv_SETPARM_ACK,           "nr5g_l2_Srv_SETPARM_ACK",       dissect_sapi_type_dummy },
        { nr5g_l2_Srv_SETPARM_NAK,           "nr5g_l2_Srv_SETPARM_NAK",       dissect_sapi_type_dummy },

        { lte_l2_Srv_START_CMD,              "lte_l2_Srv_START_CMD",       dissect_srv_start_cmd },
        { lte_l2_Srv_START_ACK,              "lte_l2_Srv_START_ACK",       dissect_sapi_type_dummy },
        { lte_l2_Srv_START_NAK,              "lte_l2_Srv_START_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_OPEN_CELL_CMD,         "NR5G_L2_SRV_OPEN_CELL_CMD",       dissect_open_cell_cmd},
        { nr5g_l2_Srv_OPEN_CELL_ACK,         "NR5G_L2_SRV_OPEN_CELL_ACK",       dissect_open_cell_ack /* TODO */},
        { nr5g_l2_Srv_OPEN_CELL_NAK,         "NR5G_L2_SRV_OPEN_CELL_NAK",       dissect_sapi_type_dummy },

        { lte_l2_Srv_GETINFO_CMD,            "lte_l2_Srv_GETINFO_CMD",       dissect_sapi_type_dummy },
        { lte_l2_Srv_GETINFO_ACK,            "lte_l2_Srv_GETINFO_ACK",       dissect_sapi_type_dummy },
        { lte_l2_Srv_GETINFO_NAK,            "lte_l2_Srv_GETINFO_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_CELL_CONFIG_CMD,       "nr5g_l2_Srv_CELL_CONFIG_CMD",       dissect_cell_config_cmd },
        { nr5g_l2_Srv_CELL_CONFIG_ACK,       "nr5g_l2_Srv_CELL_CONFIG_ACK",       dissect_sapi_type_dummy },
        { nr5g_l2_Srv_CELL_CONFIG_NAK,       "nr5g_l2_Srv_CELL_CONFIG_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_RCP_LOAD_CMD,       "nr5g_l2_Srv_RCP_LOAD_CMD",       dissect_rcp_load_cmd },
        { nr5g_l2_Srv_RCP_LOAD_ACK,       "nr5g_l2_Srv_RCP_LOAD_ACK",       dissect_sapi_type_dummy },
        { nr5g_l2_Srv_RCP_LOAD_NAK,       "nr5g_l2_Srv_RCP_LOAD_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_RCP_LOAD_END_CMD,       "nr5g_l2_Srv_RCP_LOAD_END_CMD",       dissect_sapi_type_dummy },
        { nr5g_l2_Srv_RCP_LOAD_END_ACK,       "nr5g_l2_Srv_RCP_LOAD_END_ACK",       dissect_sapi_type_dummy },
        { nr5g_l2_Srv_RCP_LOAD_END_NAK,       "nr5g_l2_Srv_RCP_LOAD_END_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_CELL_PARM_CMD,         "nr5g_l2_Srv_CELL_PARM_CMD",       dissect_cell_parm_cmd },
        { nr5g_l2_Srv_CELL_PARM_ACK,         "nr5g_l2_Srv_CELL_PARM_ACK",       dissect_cell_parm_ack },
        { nr5g_l2_Srv_CELL_PARM_NAK,         "nr5g_l2_Srv_CELL_PARM_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_CREATE_UE_CMD,            "nr5g_l2_Srv_CREATE_UE_CMD",       dissect_create_ue_cmd },
        { nr5g_l2_Srv_CREATE_UE_ACK,            "nr5g_l2_Srv_CREATE_UE_ACK",       dissect_create_ue_ack },
        { nr5g_l2_Srv_CREATE_UE_NAK,            "nr5g_l2_Srv_CREATE_UE_NAK",       dissect_sapi_type_dummy },

        { lte_l2_Srv_DELETE_UE_CMD,            "nr5g_l2_Srv_DELETE_UE_CMD",       dissect_delete_ue_cmd },
        { lte_l2_Srv_DELETE_UE_ACK,            "nr5g_l2_Srv_DELETE_UE_ACK",       dissect_delete_ue_ack },
        { lte_l2_Srv_DELETE_UE_NAK,            "nr5g_l2_Srv_DELETE_UE_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD,     "nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD",       dissect_rcp_ue_set_group_cmd },
        { nr5g_l2_Srv_RCP_UE_SET_GROUP_ACK,     "nr5g_l2_Srv_RCP_UE_SET_GROUP_ACK",       dissect_rcp_ue_set_group_ack },
        { nr5g_l2_Srv_RCP_UE_SET_GROUP_NAK,     "nr5g_l2_Srv_RCP_UE_SET_GROUP_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD,     "nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD",       dissect_rcp_set_ue_index_cmd },
        { nr5g_l2_Srv_RCP_UE_SET_INDEX_ACK,     "nr5g_l2_Srv_RCP_UE_SET_INDEX_ACK",       dissect_rcp_set_ue_index_ack },
        { nr5g_l2_Srv_RCP_UE_SET_INDEX_NAK,     "nr5g_l2_Srv_RCP_UE_SET_INDEX_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_HANDOVER_CMD,     "nr5g_l2_Srv_HANDOVER_CMD",       dissect_handover_cmd },
        /* TODO: what types are these? */
        { nr5g_l2_Srv_HANDOVER_ACK,     "nr5g_l2_Srv_HANDOVER_ACK",       dissect_handover_ack },
        { nr5g_l2_Srv_HANDOVER_NAK,     "nr5g_l2_Srv_HANDOVER_NAK",       dissect_sapi_type_dummy },


        { 0x00,                               NULL,                             NULL }
};
#define MAX_OM_TYPE_VALS      array_length(om_type_funs)
static value_string  om_type_vals[MAX_OM_TYPE_VALS];


/* NR RLCMAC AUX */
static TYPE_FUN aux_type_funs[] =
{
    { nr5g_rlcmac_Data_RA_REQ,               "nr5g_rlcmac_Data_RA_REQ",               dissect_ra_req},
    { nr5g_rlcmac_Data_RA_CNF,               "nr5g_rlcmac_Data_RA_CNF",               dissect_ra_cnf},
    { nr5g_rlcmac_Data_RA_IND,               "nr5g_rlcmac_Data_RA_IND",               dissect_ra_ind},
    { nr5g_rlcmac_Data_RE_EST_IND,           "nr5g_rlcmac_Data_RE_EST_IND",           dissect_re_est_ind /* TODO */},
    { nr5g_rlcmac_Data_RE_EST_END_IND,       "nr5g_rlcmac_Data_RE_EST_END_IND",       dissect_re_est_ind /* TODO */},
    { nr5g_rlcmac_Data_RLC_BUFFER_REQ,       "nr5g_rlcmac_Data_RLC_BUFFER_REQ",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Data_RLC_BUFFER_IND,       "nr5g_rlcmac_Data_RLC_BUFFER_IND",       dissect_sapi_type_dummy /* TODO */},
    { 0x00,                               NULL,                             NULL }
};
#define MAX_AUX_TYPE_VALS      array_length(aux_type_funs)
static value_string  aux_type_vals[MAX_AUX_TYPE_VALS];


/* NR RLCMAC TM */
static TYPE_FUN nr_rlcmac_tm_type_funs[] =
{
    { nr5g_rlcmac_Data_TM_DATA_REQ,    "nr5g_rlcmac_Data_TM_DATA_REQ",       dissect_rlcmac_data_req_tm },
    { nr5g_rlcmac_Data_TM_DATA_IND,    "nr5g_rlcmac_Data_TM_DATA_IND",       dissect_rlcmac_data_ind_tm },
    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_TM_TYPE_VALS      array_length(nr_rlcmac_tm_type_funs)
static value_string  nr_rlcmac_tm_type_vals[MAX_NR_RLCMAC_TM_TYPE_VALS];


/* NR RLCMAC UM */
static TYPE_FUN nr_rlcmac_um_type_funs[] =
{
    { nr5g_rlcmac_Data_UM_DATA_REQ,    "nr5g_rlcmac_Data_UM_DATA_REQ",    dissect_rlcmac_data_req_um },
    { nr5g_rlcmac_Data_UM_DATA_IND,    "nr5g_rlcmac_Data_UM_DATA_IND",    dissect_rlcmac_data_ind_um },
    { 0x00,                               NULL,                           NULL }
};
#define MAX_NR_RLCMAC_UM_TYPE_VALS      array_length(nr_rlcmac_um_type_funs)
static value_string  nr_rlcmac_um_type_vals[MAX_NR_RLCMAC_UM_TYPE_VALS];


/* NR RLCMAC AM */
static TYPE_FUN nr_rlcmac_am_type_funs[] =
{
    { nr5g_rlcmac_Data_AM_DATA_REQ,     "nr5g_rlcmac_Data_AM_DATA_REQ",       dissect_rlcmac_data_req_am },
    { nr5g_rlcmac_Data_AM_DATA_CNF,     "nr5g_rlcmac_Data_AM_DATA_CNF",       dissect_rlcmac_data_cnf },
    { nr5g_rlcmac_Data_AM_DATA_IND,     "nr5g_rlcmac_Data_AM_DATA_IND",       dissect_rlcmac_data_ind_am },
    { nr5g_rlcmac_Data_AM_MAX_RETX_IND, "nr5g_rlcmac_Data_AM_MAX_RETX_IND",   dissect_sapi_type_dummy /* TODO */},
    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_AM_TYPE_VALS      array_length(nr_rlcmac_am_type_funs)
static value_string  nr_rlcmac_am_type_vals[MAX_NR_RLCMAC_AM_TYPE_VALS];




/* NR RLCMAC L1 TEST */
static TYPE_FUN nr_rlcmac_l1_test_type_funs[] =
{
    { nr5g_rlcmac_Cmac_L1T_START_TEST_CMD,    "nr5g_rlcmac_Cmac_L1T_START_TEST_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1T_START_TEST_ACK,    "nr5g_rlcmac_Cmac_L1T_START_TEST_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1T_START_TEST_NAK,    "nr5g_rlcmac_Cmac_L1T_START_TEST_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD,    "nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1T_STOP_TEST_ACK,    "nr5g_rlcmac_Cmac_L1T_STOP_TEST_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1T_STOP_TEST_NAK,    "nr5g_rlcmac_Cmac_L1T_STOP_TEST_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_L1T_LOG_IND,    "nr5g_rlcmac_Cmac_L1T_LOG_IND",       dissect_l1t_log_ind},

    { nr5g_rlcmac_Cmac_L1L2T_START_TEST_CMD,    "nr5g_rlcmac_Cmac_L1L2T_START_TEST_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_START_TEST_ACK,    "nr5g_rlcmac_Cmac_L1L2T_START_TEST_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_START_TEST_NAK,    "nr5g_rlcmac_Cmac_L1L2T_START_TEST_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_CMD,    "nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_ACK,    "nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_NAK,    "nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD,    "nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_ACK,    "nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_NAK,    "nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD,    "nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_ACK,    "nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_NAK,    "nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD,    "nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_ACK,    "nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_NAK,    "nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_NAK",       dissect_sapi_type_dummy /* TODO */},

    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_L1_TEST_TYPE_VALS      array_length(nr_rlcmac_l1_test_type_funs)
static value_string  nr_rlcmac_l1_test_type_vals[MAX_NR_RLCMAC_L1_TEST_TYPE_VALS];

static TYPE_FUN nr_rlcmac_error_type_funs[] =
{
    { nr5g_rlcmac_Cmac_STAT_UE_LO_IND,    "lte_l2_Sap_NR_RLCMAC_ERROR",     dissect_rlcmac_error},
    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_ERROR_TYPE_VALS      array_length(nr_rlcmac_error_type_funs)
static value_string  nr_rlcmac_error_type_vals[MAX_NR_RLCMAC_ERROR_TYPE_VALS];






/* NR RLCMAC CMAC */
static TYPE_FUN nr_rlcmac_cmac_type_funs[] =
{
    { nr5g_rlcmac_Cmac_DBEAM_IND,    "nr5g_rlcmac_Cmac_DBEAM_IND",       dissect_dbeam_ind },

    { nr5g_rlcmac_Cmac_CONFIG_CMD,     "nr5g_rlcmac_Cmac_CONFIG_CMD",       dissect_rlcmac_cmac_config_cmd},
    { nr5g_rlcmac_Cmac_CONFIG_ACK,     "nr5g_rlcmac_Cmac_CONFIG_ACK",       dissect_rlcmac_cmac_config_ack},
    { nr5g_rlcmac_Cmac_CONFIG_NAK,     "nr5g_rlcmac_Cmac_CONFIG_NAK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_SEG_CONFIG_REQ, "nr5g_rlcmac_Cmac_SEG_CONFIG_REQ",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD, "nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RRC_STATE_CFG_ACK, "nr5g_rlcmac_Cmac_RRC_STATE_CFG_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RRC_STATE_CFG_NAK, "nr5g_rlcmac_Cmac_RRC_STATE_CFG_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD, "nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_ACK, "nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_NAK, "nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_RESET_CMD, "nr5g_rlcmac_Cmac_RESET_CMD",       dissect_cmac_reset_cmd },
    { nr5g_rlcmac_Cmac_RESET_ACK, "nr5g_rlcmac_Cmac_RESET_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RESET_NAK, "nr5g_rlcmac_Cmac_RESET_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_RELEASE_CMD, "nr5g_rlcmac_Cmac_RELEASE_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RELEASE_ACK, "nr5g_rlcmac_Cmac_RELEASE_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RELEASE_NAK, "nr5g_rlcmac_Cmac_RELEASE_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_STATUS_REQ, "nr5g_rlcmac_Cmac_STATUS_REQ",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_STATUS_IND, "nr5g_rlcmac_Cmac_STATUS_IND",       dissect_cmac_status_ind},
    { nr5g_rlcmac_Cmac_CELL_STATUS_REQ, "nr5g_rlcmac_Cmac_CELL_STATUS_REQ",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_CELL_STATUS_CNF, "nr5g_rlcmac_Cmac_CELL_STATUS_CNF",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_CELL_STATUS_IND, "nr5g_rlcmac_Cmac_CELL_STATUS_IND",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_STATUS_CNF, "nr5g_rlcmac_Cmac_STATUS_CNF",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_DBEAM_IND, "nr5g_rlcmac_Cmac_DBEAM_IND",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_DCI_IND, "nr5g_rlcmac_Cmac_DCI_IND",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_MEAS_SET_REQ, "nr5g_rlcmac_Cmac_MEAS_SET_REQ",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_RACH_CFG_CMD, "nr5g_rlcmac_Cmac_RACH_CFG_CMD",       dissect_cmac_rach_cfg_cmd },
    { nr5g_rlcmac_Cmac_RACH_CFG_ACK, "nr5g_rlcmac_Cmac_RACH_CFG_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RACH_CFG_NAK, "nr5g_rlcmac_Cmac_RACH_CFG_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_RACH_ACC_CMD, "nr5g_rlcmac_Cmac_RACH_ACC_CMD",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RACH_ACC_ACK, "nr5g_rlcmac_Cmac_RACH_ACC_ACK",       dissect_sapi_type_dummy /* TODO */},
    { nr5g_rlcmac_Cmac_RACH_ACC_NAK, "nr5g_rlcmac_Cmac_RACH_ACC_NAK",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_RACH_ACC_IND, "nr5g_rlcmac_Cmac_RACH_ACC_IND",       dissect_sapi_type_dummy /* TODO */},

    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_CMAC_TYPE_VALS      array_length(nr_rlcmac_cmac_type_funs)
static value_string  nr_rlcmac_cmac_type_vals[MAX_NR_RLCMAC_CMAC_TYPE_VALS];


/* NR RLCMAC CRLC */
static TYPE_FUN nr_rlcmac_crlc_type_funs[] =
{
    { nr5g_rlcmac_Crlc_CONFIG_CMD,         "nr5g_rlcmac_Crlc_CONFIG_CMD",       dissect_crlc_config_cmd },
    { nr5g_rlcmac_Crlc_CONFIG_ACK,         "nr5g_rlcmac_Crlc_CONFIG_ACK",       dissect_crlc_config_ack },
    { nr5g_rlcmac_Crlc_CONFIG_NAK,         "nr5g_rlcmac_Crlc_CONFIG_NAK",       dissect_sapi_type_dummy },

    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_CRLC_TYPE_VALS      array_length(nr_rlcmac_crlc_type_funs)
static value_string  nr_rlcmac_crlc_type_vals[MAX_NR_RLCMAC_CRLC_TYPE_VALS];


/* LTE PDCP CTRL */
static TYPE_FUN lte_pdcp_ctrl_type_funs[] =
{
    { nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD,           "nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD",       dissect_sib_filter_act_deact_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK,           "nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK",       dissect_sib_filter_act_deact_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK,           "nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK",       dissect_sib_filter_act_deact_nak },
    { nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD,         "nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD",     dissect_sib_filter_act_deact_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK,         "nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK",     dissect_sib_filter_act_deact_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK,         "nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK",     dissect_sib_filter_act_deact_nak },

    { 0x00,                               NULL,                             NULL }
};
#define MAX_LTE_PDCP_CTRL_TYPE_VALS      array_length(lte_pdcp_ctrl_type_funs)
static value_string  lte_pdcp_ctrl_type_vals[MAX_LTE_PDCP_CTRL_TYPE_VALS];




static SAPI_FUN sapi_fun_vals[] = {
    /* Server */
    { lte_l2_Sap_SRV_ERROR,         "SRV ERROR", NULL },
    { lte_l2_Sap_OM,                "OM", om_type_funs  },
    { lte_l2_Sap_LIC,               "LIC", NULL  },
    { lte_l2_Sap_OM_TM,             "OM TM", NULL  },

    /* RLCMAC */
    { lte_l2_Sap_RLCMAC_ERROR,      "RLCMAC ERROR", NULL  },
    { lte_l2_Sap_RLCMAC_CMAC,       "RLCMAC CMAC", NULL  },
    { lte_l2_Sap_RLCMAC_CRLC,       "RLCMAC CRLC", NULL  },
    { lte_l2_Sap_RLCMAC_STAT,       "RLCMAC STAT", NULL  },
    { lte_l2_Sap_RLCMAC_TEST,       "RLCMAC TEST", NULL  },
    { lte_l2_Sap_RLCMAC_CMAC_TM,    "RLCMAC CMAC TM", NULL  },
    { lte_l2_Sap_RLCMAC_CRLC_TM,    "RLCMAC RLC TM", NULL  },
    { lte_l2_Sap_RLCMAC_SCHED,      "RLCMAC SCHED", NULL  },
    { lte_l2_Sap_RLCMAC_MBMS,       "RLCMAC MBMS", NULL  },
    { lte_l2_Sap_RLCMAC_DRLC_TM,    "RLCMAC DRLC TM", NULL  },
    { lte_l2_Sap_RLCMAC_STAT_TM,    "RLCMAC STAT TM", NULL  },

    /* PDCP */
    { lte_l2_Sap_PDCP_ERROR,        "PDCP ERROR", NULL  },
    { lte_l2_Sap_PDCP_CTRL,         "PDCP CTRL", lte_pdcp_ctrl_type_funs  },
    { lte_l2_Sap_PDCP_AUX,          "PDCP AUX", NULL  },
    { lte_l2_Sap_PDCP_DATA,         "PDCP DATA", NULL  },
    { lte_l2_Sap_PDCP_STAT,         "PDCP STAT", NULL  },
    { lte_l2_Sap_PDCP_CTRL_TM,      "PDCP CTRL TM", NULL  },
    { lte_l2_Sap_NR_PDCP_CTRL,      "NR PDCP CTRL", NULL  },
    { lte_l2_Sap_NR_PDCP_AUX,       "NR PDCP AUX", NULL  },
    { lte_l2_Sap_NR_PDCP_DATA,      "NR PDCP DATA", NULL  },
    { lte_l2_Sap_NR_PDCP_STAT,      "NR PDCP STAT", NULL  },
    { lte_l2_Sap_NR_PDCP_CTRL_TM,   "NR PDCP CTRL TM", NULL  },

    /* UUDG */
    { lte_l2_Sap_UUDG_ERROR,       "UUGD ERROR", NULL  },
    { lte_l2_Sap_UUDG_UUDG,        "UUGD UUDG", NULL  },
    { lte_l2_Sap_UUDG_NAT,         "UUGD NAT", NULL  },
    { lte_l2_Sap_UUDG_NAT6,        "UUGD NAT6", NULL  },
    { lte_l2_Sap_UUDG_ICMP6,       "UUGD IGMP6", NULL  },
    { lte_l2_Sap_UUDG_CTL,         "UUGD CTL", NULL  },

    /* NUDG */
    { lte_l2_Sap_NUDG_ERROR,       "NUDG ERROR", NULL  },
    { lte_l2_Sap_NUDG_NUDG,        "NUDG NUDH", NULL  },
    { lte_l2_Sap_NUDG_GI,          "NUDG GI", NULL  },
    { lte_l2_Sap_NUDG_GI6,         "NUDG GI6", NULL  },
    { lte_l2_Sap_NUDG_CTL,         "NUDG CTL", NULL  },

    /* Data Source for TM */
    { lte_l2_Sap_TM_DATA_ERROR,      "TM DATA ERROR", NULL  },
    { lte_l2_Sap_TM_DATA_PATT,       "TM DATA PATT", NULL  },
    { lte_l2_Sap_TM_DATA_LOOP,       "TM DATA LOOP", NULL  },
    { lte_l2_Sap_TM_DATA_PRBS,       "TM DATA PRBS", NULL  },
    { lte_l2_Sap_TM_DATA_XTRN,       "TM DATA XTRN", NULL  },
    { lte_l2_Sap_TM_DATA_TSRV,       "TM DATA TSRV", NULL  },

    /* CNTR */
    { lte_l2_Sap_CNTR_ERROR,           "CNTR ERROR", NULL  },
    { lte_l2_Sap_CNTR_CNTR,            "CNTR CNTR", NULL  },

    /* MSWITCH */
    { lte_l2_Sap_MSWITCH_ERROR,       "MSWITCH ERROR", NULL  },
    { lte_l2_Sap_MSWITCH_MSWITCH,     "MSWITCH MSWITCH", NULL  },

    /* ROHC */
    { lte_l2_Sap_ROHC_ERROR,            "ROHC ERROR", NULL  },
    { lte_l2_Sap_ROHC_ROHC,             "ROHC ROHC", NULL  },

    /* NR RLCMAC */
    { lte_l2_Sap_NR_RLCMAC_ERROR,        "NR RLCMAC ERROR",  nr_rlcmac_error_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_L1_TEST,      "NR RLCMAC L1 TEST",  nr_rlcmac_l1_test_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_CMAC,         "NR RLCMAC CMAC", nr_rlcmac_cmac_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_CRLC,         "NR RLCMAC CRLC", nr_rlcmac_crlc_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_CMAC_TM,      "NR RLCMAC CMAC TM", NULL  },
    { lte_l2_Sap_NR_RLCMAC_CRLC_TM,      "NR RLCMAC CRLC TM", NULL  },
    { lte_l2_Sap_NR_RLCMAC_DRLC_TM,      "NR RLCMAC dRLC TM", NULL  },
    { lte_l2_Sap_NR_RLCMAC_AUX,          "NR RLCMAC AUX", aux_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_TM,           "NR RLCMAC TM", nr_rlcmac_tm_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_UM,           "NR RLCMAC UM", nr_rlcmac_um_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_AM,           "NR RLCMAC AM", nr_rlcmac_am_type_funs  },
    { lte_l2_Sap_NR_RLCMAC_STAT,         "NR RLCMAC STAT", NULL  },
    { lte_l2_Sap_NR_RLCMAC_STAT_TM,      "NR RLCMAC STAT TM", NULL  },
    { lte_l2_Sap_NR_SCG_RLCMAC_CMAC,     "NR SCG RLCMAC CMAC", NULL  },
    { lte_l2_Sap_NR_SCG_RLCMAC_CRLC,     "NR SCG RLCMAC CRLC", NULL  },
    { lte_l2_Sap_NR_SCG_RLCMAC_CMAC_TM,  "NR SCG RLCMAC CMAC TM", NULL  },
    { lte_l2_Sap_NR_SCG_RLCMAC_CRLC_TM,  "NR SCG RLCMAC CRLC TM", NULL  },
    { lte_l2_Sap_NR_SCG_RLCMAC_DRLC_TM,  "NR SCG RLCMAC DRLC TM", NULL  },
    { lte_l2_Sap_NR_SCG_RLCMAC_STAT,     "NR SCG RLCMAC STAT", NULL  },
    { 0x00,          	 NULL,                             NULL }
};
#define MAX_SAPI_VALS      array_length(sapi_fun_vals)

static value_string  sapi_vals[MAX_SAPI_VALS]; /* sapi_fun_vals table is 0 terminated */

static void init_sapi_value_string(value_string *vals, SAPI_FUN *msg, guint max_msg)
{
    guint i;

    for(i = 0; i < max_msg; i++) {
	vals[i].value = msg[i].sapi;
	vals[i].strptr = msg[i].sapi_name;
    }
}

static void init_prim_value_string(value_string *vals, TYPE_FUN *msg, guint max_msg)
{
    guint i;

    for(i = 0; i < max_msg; i++) {
	vals[i].value = msg[i].type;
	vals[i].strptr = msg[i].prim_name;
    }
}

static TYPE_FUN *get_type_fun(guint32 type, TYPE_FUN *tbl)
{
    if (tbl == NULL)
	return NULL;

    while (tbl->prim_name != NULL) {
	if (tbl->type == type)
	    return tbl;

	tbl++;
    }
    return NULL;
}

static SAPI_FUN *get_sapi_fun(guint32 sapi, SAPI_FUN *tbl)
{
    if (tbl == NULL)
	return NULL;

    while(tbl->sapi_name !=NULL) {
	if(tbl->sapi == sapi)
	    return tbl;

	tbl++;
    }
    return NULL;
};



/* User definable values */
static range_t *global_l2server_port_range = NULL;


/* Bytes 4-7 have the PDU length in little-endian order */
static guint
get_l2server_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    return 8 + (guint)tvb_get_guint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);
}

/* Dissect one PDU.  Guaranteed that the tvb is the right size */
static int
dissect_l2server_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *l2server_tree;
    proto_item *root_ti;
    gint offset = 0;

    /* Protocol column */
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_INFO);

    /* Add divider if not first PDU in this frame */
    gboolean *already_set = (gboolean*)p_get_proto_data(wmem_file_scope(), pinfo, proto_l2server, 0);
    if (*already_set) {
         col_append_str(pinfo->cinfo, COL_PROTOCOL, "|");
         col_append_str(pinfo->cinfo, COL_INFO, "  ||  ");
    }

    col_append_str(pinfo->cinfo, COL_PROTOCOL, "L2Server");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_l2server, tvb, offset, -1, ENC_NA);
    l2server_tree = proto_item_add_subtree(root_ti, ett_l2server);

    /* Header subtree */
    proto_item *header_ti = proto_tree_add_string_format(l2server_tree, hf_l2server_header, tvb, offset, 8, "", "Header  ");
    proto_tree *header_tree = proto_item_add_subtree(header_ti, ett_l2server_header);

    /* SAPI */
    guint32 sapi;
    proto_item *sapi_ti = proto_tree_add_item_ret_uint(header_tree, hf_l2server_sapi, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sapi);
    offset += 2;
    /* Type */
    guint32 type;
    proto_item *type_ti = proto_tree_add_item_ret_uint(header_tree, hf_l2server_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &type);
    offset += 2;
    /* Len */
    guint32 len;
    proto_tree_add_item_ret_uint(header_tree, hf_l2server_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &len);
    offset += 4;

    /**********************************/
    /* Now parse payload using tables */
    SAPI_FUN *sapi2fun = NULL;
    TYPE_FUN *type2fun = NULL;

    /* Lookup SAPI */
    sapi2fun = get_sapi_fun((guint32)sapi, sapi_fun_vals);
    if (sapi2fun == NULL) {
        expert_add_info_format(pinfo, sapi_ti, &ei_l2server_sapi_unknown,
                               "L2Server SAPI not recognised (%u)", sapi);
        return tvb_captured_length(tvb);
    }
    else {
        /* Lookup dissector function from type (for this SAPI) */
        type2fun = get_type_fun(type, sapi2fun->sapi_funs);
        if (type2fun == NULL) {
            expert_add_info_format(pinfo, type_ti, &ei_l2server_sapi_unknown,
                                   "L2Server Type (%u) not recognised for SAPI %u", type, sapi);
            return tvb_captured_length(tvb);
        }

        /* Header summary */
        proto_item_append_text(header_ti, "%s(0x%x) %s(0x%x) len=%u",
                               val_to_str_const(sapi, sapi_vals, "Unknown"), sapi,
                               type2fun->prim_name, type,
                               len);

        /* Add summary to Info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, "Sapi=%18s,  %30s (0x%x),  Len=%4u",
                        val_to_str_const(sapi, sapi_vals, "Unknown"),
                        (type2fun) ? type2fun->prim_name : "Unknown", type, len);
        proto_item_append_text(root_ti, " (%s, type=%s (0x%x), len=%u)", val_to_str_const(sapi, sapi_vals, "Unknown"),
                               (type2fun) ? type2fun->prim_name : "Unknown",
                               type, len);

        /* Call dissector function for this sapi/type? */
        if (type2fun->prim_fun) {
                (*type2fun->prim_fun)(l2server_tree, tvb, pinfo, 8, len);
        }
        //col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", type2fun->prim_name);
        proto_item_append_text(type_ti, " (%s)", type2fun->prim_name);
    }

    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    col_set_fence(pinfo->cinfo, COL_INFO);

    /* Record that at least one PDU has already been seen in this frame */
    static gboolean true_value = TRUE;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_l2server, 0, &true_value);

    return offset+len;
}


/******************************/
/* Main dissection function.  */
static int
dissect_l2server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Frame starts off with no PDUs seen */
    static gboolean false_value = FALSE;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_l2server, 0, &false_value);

    /* Find whole PDUs and send them to dissect_l2server_message() */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, /* desegment */
                     8, get_l2server_message_len,
                     dissect_l2server_message, data);
    return tvb_reported_length(tvb);
}


void
proto_register_l2server(void)
{
    init_sapi_value_string(sapi_vals, sapi_fun_vals, MAX_SAPI_VALS);

    init_prim_value_string(om_type_vals, om_type_funs, MAX_OM_TYPE_VALS);
    init_prim_value_string(aux_type_vals, aux_type_funs, MAX_AUX_TYPE_VALS);
    init_prim_value_string(nr_rlcmac_tm_type_vals, nr_rlcmac_tm_type_funs, MAX_NR_RLCMAC_TM_TYPE_VALS);
    init_prim_value_string(nr_rlcmac_um_type_vals, nr_rlcmac_um_type_funs, MAX_NR_RLCMAC_UM_TYPE_VALS);
    init_prim_value_string(nr_rlcmac_am_type_vals, nr_rlcmac_am_type_funs, MAX_NR_RLCMAC_AM_TYPE_VALS);
    init_prim_value_string(nr_rlcmac_cmac_type_vals, nr_rlcmac_cmac_type_funs, MAX_NR_RLCMAC_CMAC_TYPE_VALS);
    init_prim_value_string(nr_rlcmac_crlc_type_vals, nr_rlcmac_crlc_type_funs, MAX_NR_RLCMAC_CRLC_TYPE_VALS);
    init_prim_value_string(nr_rlcmac_l1_test_type_vals, nr_rlcmac_l1_test_type_funs, MAX_NR_RLCMAC_L1_TEST_TYPE_VALS);
    init_prim_value_string(nr_rlcmac_error_type_vals, nr_rlcmac_error_type_funs, MAX_NR_RLCMAC_ERROR_TYPE_VALS);
    init_prim_value_string(lte_pdcp_ctrl_type_vals, lte_pdcp_ctrl_type_funs, MAX_LTE_PDCP_CTRL_TYPE_VALS);

    static hf_register_info hf[] = {
      { &hf_l2server_header,
        { "Header", "l2server.header", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_sapi,
        { "SAPI", "l2server.sapi", FT_UINT16, BASE_DEC,
          VALS(sapi_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_type,
        { "Type", "l2server.type", FT_UINT16, BASE_HEX_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_len,
        { "Len", "l2server.len", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_payload,
        { "Payload", "l2server.payload", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_cellid,
        { "CellId", "l2server.cellid", FT_INT32, BASE_DEC, /* UINT so can show -1 */
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_physical_cellid,
        { "Physical CellId", "l2server.physical-cellid", FT_INT16, BASE_DEC, /* UINT so can show -1 */
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_l1verbosity,
        { "L1Verbosity", "l2server.l1verbosity", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_l1ulreport,
        { "L1UlReport", "l2server.l1ulreport", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_enablecapstest,
        { "EnableCapsTest", "l2server.enablecapstest", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_client_name,
        { "Client Name", "l2server.client-name", FT_STRINGZ, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_start_cmd_type,
        { "Type", "l2server.start-cmd-type", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ueid,
        { "UeId", "l2server.UeId", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_beamidx,
        { "BeamIdx", "l2server.BeamIdx", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rbtype,
        { "RbType", "l2server.RbType", FT_UINT8, BASE_DEC,
          VALS(rb_type_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_rbid,
        { "RbId", "l2server.RbId", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_lch,
        { "Logical Channel Type", "l2server.Lch", FT_UINT32, BASE_DEC,
          VALS(lch_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_ref,
        { "Ref", "l2server.ref", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Reference for CNF", HFILL }},
      { &hf_l2server_mui,
        { "MUI", "l2server.mui", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_datavolume,
        { "DataVolume", "l2server.datavolume", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_scgid,
        { "ScGid", "l2server.scgid", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_lcid,
        { "LcId", "l2server.lcid", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ullogref,
        { "UlLogRef", "l2server.ullogref", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Actually PDCP SN", HFILL }},
      { &hf_l2server_reest,
        { "Reest", "l2server.reest", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_esbf,
        { "Ebsf", "l2server.esbf", FT_INT16, BASE_DEC,
          NULL, 0x0, "Extended L1 SFN/SBF number", HFILL }},
      { &hf_l2server_dllogref,
        { "DlLogRef", "l2server.dllogref", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Actually PDCP SN", HFILL }},
      { &hf_l2server_rlcsn,
        { "RlcSn", "l2server.rlcsn", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_info,
        { "Info", "l2server.info", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_frame,
        { "Frame", "l2server.frame", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_slot,
        { "Slot", "l2server.slot", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_numpduforsdu,
        { "Num PDU for SDU", "l2server.numpduforsdu", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ueflags,
        { "UeFlags", "l2server.ueflags", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_stkinst,
        { "StkInst", "l2server.stkinst", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_udg_stkinst,
        { "UdgStkInst", "l2server.udg-stkinst", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_crnti,
        { "C-RNTI", "l2server.crnti", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_result_code,
        { "Result Code", "l2server.res", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_res,
        { "RA Result Code", "l2server.ra-res", FT_UINT8, BASE_DEC,
          VALS(ra_res_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_no_preambles_sent,
        { "Number of preambles sent", "l2server.number-of-preambles-sent", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Number of RACH preambles that were transmitted. Corresponds to parameter PREAMBLE_TRANSMISSION_COUNTER in TS 36.321", HFILL }},
      { &hf_l2server_contention_detected,
        { "Contention Detected", "l2server.contention-detected", FT_UINT8, BASE_DEC,
          NULL, 0x0, "If set contention was detected for at least one of the transmitted preambles", HFILL }},
      { &hf_l2server_maxuppwr,
        { "MaxUpPwr", "l2server.maxuppwr", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Maximum uplink power (in dBm)", HFILL }},
      { &hf_l2server_brsrp,
        { "BRSRP", "l2server.brsrp", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ue_category,
        { "UE Category", "l2server.ue-category", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_flags,
        { "Flags", "l2server.ra-flags", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_rnti,
        { "RA-RNTI", "l2server.rarnti", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_subcarrier_spacing,
        { "UL Subcarrier Spacing", "l2server.ul-subcarrier-spacing", FT_UINT8, BASE_DEC,
          VALS(ul_subcarrier_spacing_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_discard_rar_num,
        { "Discard RAR Num", "l2server.discard-rar-num", FT_UINT8, BASE_DEC,
          VALS(discard_rar_num_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_no_data,
        { "NoData", "l2server.no-data", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_crid,
        { "CRId", "l2server.cr-id", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Contention Resolution Id", HFILL }},
      { &hf_l2server_rel_cellid,
        { "RelCellId", "l2server.rel-cellid", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Cell Identifier for release", HFILL }},
      { &hf_l2server_add_cellid,
        { "AddCellId", "l2server.add-cellid", FT_UINT32, BASE_DEC,
          NULL, 0x0, "Cell Identifier for addition", HFILL }},
      { &hf_l2server_scg_type,
        { "SCG Type", "l2server.scg-type", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_drb_continue_rohc,
        { "drb-ContinueROHC", "l2server.drb-continue-rohc", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_mac_config_len,
        { "MacConfig Length", "l2server.mac-config-len", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_bwpmask,
        { "BwpMask", "l2server.bwpmask", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_info,
        { "RA Info", "l2server.ra-info", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_bwpid,
        { "BwpId", "l2server.bwpid", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_prach_configindex,
        { "PRACH ConfigIndex", "l2server.prach-configindex", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_preamble_receive_target_power,
        { "Preamble Receive Target Power", "l2server.preamble-receive-target-power", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rsrp_thresholdssb,
        { "RSRP ThresholdSSB", "l2server.rsrp-threshold-ssb", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csirs_threshold,
        { "CSIRS Threshold", "l2server.csirs-threshold", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_sul_rsrp_threshold,
        { "SUL RSRP Threshold", "l2server.sul-rsrp-threshold", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_preambleindex,
        { "RA PreambleIndex", "l2server.ra_preambleindex", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_preamble_power_ramping_step,
         { "Preamble Power Ramping Step", "l2server.preamble-power-ramping-step", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_ssb_occassion_mask_index,
         { "RA SSB Occassion Mask Index", "l2server.ra-ssb-occassion-mask-index", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_preamble_tx_max,
         { "Preamble Tx Max", "l2server.preamble-tx-max", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_totalnumberofra_preambles,
        { "totalNumberOfRA-Preambles", "l2server.totalnumberofra-preambles", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_l1cell_dedicated_config_len,
        { "L1CellDedicatedConfig-Len", "l2server.l1cell-dedicated-config-len", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_l2_test_mode,
        { "L2 Test Mode", "l2server.l2_test_mode", FT_UINT8, BASE_DEC,
          VALS(l2_test_mode_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_l2_cell_dedicated_config,
        { "L2 Cell Dedicated Config", "l2server.l2-cell-dedicated-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_l2_cell_dedicated_config_len,
        { "Len", "l2server.l2-cell-dedicated-config.len", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_l1_cell_dedicated_config,
        { "L1 Cell Dedicated Config", "l2server.l1-cell-dedicated-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},


      { &hf_l2server_num_of_rb_cfg,
        { "Number of RBs add/mod", "l2server.num-rb-cfg", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rb_config,
        { "RB Config", "l2server.rb-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_num_of_rb_rel,
        { "Number of RBs to release", "l2server.num-rb-rel", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rb_rel,
        { "RB Release", "l2server.rb-rel", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rl_failure_timer,
        { "RL Failure Timer", "l2server.rl-failure-timer", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rl_syncon_timer,
        { "RL SyncOn Timer", "l2server.rl-syncon-timer", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_seg_cnt,
        { "SegCnt", "l2server.seg-cnt", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_enable_pmi_reporting,
        { "Enable PMI Reporting", "l2server.enable-pmi-reporting", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_for_sul,
        { "RA Info is for SUL", "l2server.ra-info-is-for-sul", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rlc_mode,
        { "RLC Mode", "l2server.rlc-mode", FT_UINT8, BASE_DEC,
          VALS(rlc_mode_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_er,
        { "Establish-Release", "l2server.rlc-er", FT_UINT8, BASE_DEC,
          VALS(rlc_er_vals), 0x0, NULL, HFILL }},


      { &hf_l2server_mac_cell_group_config,
        { "MAC Cell Group Config", "l2server.mac-cell-group-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_spcell_config,
        { "spCell Config", "l2server.spcell-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_scell_list,
        { "sCell List", "l2server.scell-list", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},



      { &hf_l2server_traffic,
        { "Traffic", "l2server.traffic", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_traffic_tm,
        { "Traffic TM", "l2server.traffic.tm", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_traffic_um,
        { "Traffic UM", "l2server.traffic.um", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_traffic_am,
        { "Traffic AM", "l2server.traffic.am", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_traffic_cnf,
        { "Traffic CNF", "l2server.traffic.cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_traffic_ul,
        { "Traffic UL", "l2server.traffic.ul", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_traffic_dl,
        { "Traffic DL", "l2server.traffic.dl", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_traffic_bch,
        { "Traffic BCH", "l2server.traffic.bch", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},


      { &hf_l2server_pdcp_pdu,
        { "PDCP PDU", "l2server.pdcp-pdu", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rach,
        { "RACH", "l2server.rach", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_reestablishment,
        { "Reestablishment", "l2server.reestablishment", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_params,
        { "Params", "l2server.params", FT_STRING, FT_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rlc_config_tx,
        { "Tx", "l2server.rlc-config.tx", FT_STRING, FT_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_config_rx,
        { "Rx", "l2server.rlc-config.rx", FT_STRING, FT_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rlc_snlength,
        { "SN Length", "l2server.rlc-config.snlength", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_t_poll_retransmit,
        { "t_PollRetransmit", "l2server.rlc-config.t-pollretransmit", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_poll_pdu,
        { "Poll PDU", "l2server.rlc-config.poll-pdu", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_poll_byte,
        { "Poll Byte", "l2server.rlc-config.poll-byte", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_max_retx_threshold,
        { "Max Retx Threshold", "l2server.rlc-config.max-retx-threshold", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_discard_timer,
        { "Discard Timer", "l2server.rlc-config.discard-timer", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rlc_t_reassembly,
        { "t-Reassembly", "l2server.rlc-config.t-reassembly", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rlc_t_status_prohibit,
        { "t-StatusProhibit", "l2server.rlc-config.t-status-prohibit", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_spare1,
        { "Spare", "l2server.spare", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_spare2,
        { "Spare", "l2server.spare", FT_INT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_spare4,
        { "Spare", "l2server.spare", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_package_type,
        { "PackageType", "l2server.package-type", FT_UINT8, BASE_DEC,
          VALS(version_server_type_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_dbeamid,
         { "DbeamId", "l2server.dbeamid", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_dbeam_status,
         { "Status", "l2server.dbeam-status", FT_UINT8, BASE_DEC,
          VALS(dbeam_status_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_num_beams,
         { "Num beams", "l2server.num-beams", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_logstr,
         { "LogStr", "l2server.logstr", FT_STRINGZ, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_field_mask_1,
        { "FieldMask", "l2server.field-mask", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_field_mask_1_ded_present,
        { "Dedicated Present", "l2server.field-mask.dedicated-present", FT_BOOLEAN, 8,
          NULL, 0x1, NULL, HFILL }},
      { &hf_l2server_field_mask_1_common_present,
        { "Common Present", "l2server.field-mask.common-present", FT_BOOLEAN, 8,
          NULL, 0x2, NULL, HFILL }},

      { &hf_l2server_field_mask_2,
        { "FieldMask", "l2server.field-mask", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_field_mask_4,
        { "FieldMask", "l2server.field-mask", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},


      { &hf_l2server_ncelllte,
        { "NCellLte", "l2server.ncelllte", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ncellnr,
        { "NCellNr", "l2server.ncellnr", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_numltepropdu,
        { "NumLteProPdu", "l2server.numltepropdu", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_numnrpropdu,
        { "NumNrProPdu", "l2server.numnrpropdu", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_cellidlteitem,
        { "CellIdLteItem", "l2server.cellidlteitem", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nb_scell_cfg_add,
        { "NbSCellCfgAdd", "l2server.number-scell-cfg-add", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_scell_cfg_del,
        { "NbSCellCfgDel", "l2server.number-scell-cfg-del", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ph_cell_config,
        { "PH Cell Config", "l2server.ph-cell-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ph_cell_dcp_config_present,
        { "DCP Config Present", "l2server.field-mask.dcp-config-present", FT_BOOLEAN, 8,
          NULL, bb_nr5g_STRUCT_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16_PRESENT, NULL, HFILL }},
      { &hf_l2server_ph_pdcch_blind_detection_present,
        { "PDCCh Blind Detection Present", "l2server.field-mask.pdcch-blind-detection-present", FT_BOOLEAN, 8,
          NULL, bb_nr5g_STRUCT_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16_PRESENT, NULL, HFILL }},
      { &hf_l2server_harq_ack_spatial_bundling_pucch,
        { "HARQ ACK Spacial Bundling PUCCH", "l2server.harq-ack-spatial-bundling-pucch", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_harq_ack_spatial_bundling_pusch,
        { "HARQ ACK Spacial Bundling PUSCH", "l2server.harq-ack-spatial-bundling-pusch", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pmax_nr,
        { "pMax NR", "l2server.pmax-nr", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pdsch_harq_ack_codebook,
        { "PDSCH HARQ ACK Codebook", "l2server.pdsch-harq-ack-codebook", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_sp_cell_cfg_ded,
        { "SP Cell Cfg Dedicated", "l2server.sp-cell-cfg-ded", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_sp_cell_cfg_tdd_ded_present,
        { "TDD Present", "l2server.sp-cell-cfg-ded.tdd-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_TDD_DED_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_dl_ded_present,
        { "DL Present", "l2server.sp-cell-cfg-ded.dl-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_DOWNLINK_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_ul_ded_present,
        { "UL Present", "l2server.sp-cell-cfg-ded.ul-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_UPLINK_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_sup_ul_present,
        { "SUP UL Present", "l2server.sp-cell-cfg-ded.sup-ul-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_SUP_UPLINK_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_cross_carrier_sched_present,
        { "Cross Carriers Sched Present", "l2server.sp-cell-cfg-ded.cross-carrier-sched-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_CROSS_CARRIER_SCHED_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_lte_crs_tomatcharound_present,
        { "LTE CRS tomatcharound Present", "l2server.sp-cell-cfg-ded.lte-crs-tomatcharound-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_TOMATCHAROUND_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_dormantbwp_present,
        { "DormantBWP Present", "l2server.sp-cell-cfg-ded.dormantbwp-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_DORMANTBWP_CONFIG_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_lte_crs_pattern_list1_present,
        { "CRS Pattern List1 Present", "l2server.sp-cell-cfg-ded.crs-pattern-list1-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_PATTERN_LIST1_PRESENT, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_lte_crs_pattern_list2_present,
        { "CRS Pattern List2 Present", "l2server.sp-cell-cfg-ded.crs-pattern-list2-present", FT_BOOLEAN, 32,
          NULL, bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_PATTERN_LIST2_PRESENT, NULL, HFILL }},


      { &hf_l2server_sp_cell_cfg_tdd,
        { "TDD dedicated", "l2server.sp-cell-cfg-ded.tdd", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_dl,
        { "DL dedicated", "l2server.sp-cell-cfg-ded.dl", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_ul,
        { "UL dedicated", "l2server.sp-cell-cfg-ded.ul", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_sup_ul,
        { "SUP UL", "l2server.sp-cell-cfg-ded.sup-ul", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_cross_carrier_sched,
        { "Cross carrier SChed", "l2server.sp-cell-cfg-ded.cross-carrier-sched", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_lte_crs_tomatcharound,
        { "LTE CRS tomatcharound", "l2server.sp-cell-cfg-ded.lte-crs-tomatcharound", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_dormantbwp,
        { "DormantBWP", "l2server.sp-cell-cfg-ded.dormantBWP", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_lte_crs_pattern_list1,
        { "LTE CRS PatternList1", "l2server.sp-cell-cfg-ded.lte-crs-patternlist1", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},
      { &hf_l2server_sp_cell_cfg_lte_crs_pattern_list2,
        { "LTE CRS PatternList2", "l2server.sp-cell-cfg-ded.lte-crs-patternlist2", FT_STRING, FT_NONE,
          NULL, 0X0, NULL, HFILL }},


      { &hf_l2server_serv_cell_idx,
        { "ServCellIdx", "l2server.serving-cell-index", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_bwp_inactivity_timer,
        { "BwpInactivityTimer", "l2server.bwp-inactivity-timer", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_tag_id,
        { "TagId", "l2server.tag-id", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_scell_deact_timer,
        { "SCell Deact Timer", "l2server.scell-deact-timer", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pathloss_ref_linking,
        { "Pathloss Ref Linking", "l2server.pathloss-ref-linking", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_serv_cell_mo,
        { "Serv Cell MO", "l2server.serv-cell-mo", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_default_dl_bwpid,
        { "Default DL Bwpid", "l2server.default-dl-bwpid", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_supp_ul_rel,
        { "Supp UL Rel", "l2server.supp-ul-rel", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ca_slot_offset_is_valid,
        { "CA Slot Offset Is Valid", "l2server.ca-slot-offset-is-valid", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_lte_srs_patternlist_1,
        { "Nb LTE SRS PatternList 1", "l2server.nb-lte-srs-patternlist-1", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_lte_srs_patternlist_2,
        { "Nb LTE SRS PatternList 2", "l2server.nb-lte-srs-patternlist-2", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ca_slot_offset_r16,
        { "CA Slot Offset R16", "l2server.ca-slot-offset-r16", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_csi_rs_valid_with_dci_r16,
        { "CsiRsValidWithDCI-r16", "l2server.csi-rs-valid-with-dci-r16", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_crs_rate_match_per_coreset_poolidx_r16,
        { "CrsRateMatchPerCORESETPoolIdx-r16", "l2server.crs-rate-match-per-coreset-poolidx-r16", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_first_active_ul_bwp_pcell,
        { "First Active UL BWP pCell", "l2server.first-active-ul-bwp-pcell", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_sp_cell_cfg_common,
        { "SP Cell Cfg Common", "l2server.sp-cell-cfg-common", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_config_cmd_type,
        { "Type", "l2server.config-cmd-type", FT_UINT16, BASE_DEC,
          VALS(config_cmd_type_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_side,
        { "Interface Side", "l2server.side", FT_UINT8, BASE_DEC,
          VALS(interface_side_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_bot_layer,
        { "Bot Layer", "l2server.bot-layer", FT_UINT8, BASE_DEC,
          VALS(bot_layer_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_trf,
        { "Trf", "l2server.trf", FT_UINT8, BASE_DEC,
          VALS(trf_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_technology,
        { "Technology", "l2server.technology", FT_UINT8, BASE_DEC,
          VALS(technology_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_enbsim,
        { "ENbSim", "l2server.enbsim", FT_UINT8, BASE_DEC,
          VALS(enbsim_vals), 0x0, "Control simulation of LTE Uu on eNB. (18)", HFILL }},

      { &hf_l2server_rx_lch_info,
        { "RxLchInfo", "l2server.rx-lch-info", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_tx_lch_info,
        { "TxLchInfo", "l2server.tx-lch-info", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_lcg,
        { "Logical Channel Group", "l2server.lcg", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_priority,
        { "Priority", "l2server.priority", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_prioritized_bit_rate,
        { "Prioritized bit rate", "l2server.prioritized-bit-rate", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_bucket_size_duration,
        { "Bucket Size Duration", "l2server.bucket-size-duration", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_allowed_serving_cells,
        { "Allowed Serving Cells", "l2server.allowed-serving-cells", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_allowed_scs_list,
        { "Allowed SCS List", "l2server.allowed-scs-list", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_max_pusch_duration,
        { "Max PUSCH Duration", "l2server.max-pusch-duration", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_configured_grant_type_allowed,
        { "Configured Grant Type Allowed", "l2server.configured-grant-type-allowed", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_logical_channel_sr_mask,
        { "Logical Channel SR Mask", "l2server.logical-channel-sr-mask", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_logical_channel_sr_delay_timer_configured,
        { "Logical Channel SR Delay Timer Configured", "l2server.logical-channel-sr-delay-timer-configured", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_request_duplicates_from_pdcp,
        { "Request Duplicates from PDCP", "l2server.request-duplicates-from-pdcp", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_scheduling_request_id,
        { "Scheduling Request ID", "l2server.scheduling-request-id", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_bit_rate_query_prohibit_timer,
        { "Bit Rate Query Prohibit Timer", "l2server.bit-rate-query-prohibit-timer", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_allowed_phy_priority_index,
        { "Allowed PHY Priority Index", "l2server.allowed-phy-priority-index", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_setparm_cmd_type,
        { "Type", "l2server.setparm-cmd-type", FT_UINT16, BASE_DEC,
          VALS(setparm_cmd_type_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_max_ue,
        { "Max Ue", "l2server.max-ue", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_max_pdcp,
        { "Max PDCP", "l2server.max-pdcp", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_max_nat,
        { "Max Nat bearers", "l2server.max-nat", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_max_udg_sess,
        { "Max UDG Sess", "l2server.max-udg-sess", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_max_cntr,
        { "Max Cntr", "l2server.max-cntr", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_cmac_status,
        { "CMAC Status", "l2server.cmac-status", FT_UINT8, BASE_DEC,
          VALS(cmac_status_vals), 0x0, NULL, HFILL }},

      /* DRX config */
      { &hf_l2server_drx_config,
        { "DRX Config", "l2server.drx-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_drx_len,
        { "Length", "l2server.drx-lenth", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_drx_ondurationtimer_isvalid,
        { "onDurationTimer_IsValid", "l2server.ondurationtimer-isvalid", FT_UINT8, BASE_DEC,
          VALS(drx_onduration_timer_long_cycle_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_drx_ondurationtimer,
        { "onDurationTimer", "l2server.ondurationtimer", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_drx_inactivitytimer,
        { "InactivityTimer", "l2server.inactivitytimer", FT_UINT32, BASE_DEC,
          VALS(drx_inactivity_timer_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_drx_harq_rtt_timerdl,
        { "Harq RTT Timer DL", "l2server.harq-rtt-timerdl", FT_UINT8, BASE_DEC,
          NULL, 0x0,  "(0..56). Value in number of symbols", HFILL }},
      { &hf_l2server_drx_harq_rtt_timerul,
        { "Harq RTT Timer UL", "l2server.harq-rtt-timerul", FT_UINT8, BASE_DEC,
          NULL, 0x0,  "(0..56). Value in number of symbols", HFILL }},
      { &hf_l2server_drx_retransmission_timerdl,
        { "Retransmission Timer DL", "l2server.retransmission-timerdl", FT_UINT32, BASE_DEC,
          VALS(drx_retransmission_timer_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_drx_retransmission_timerul,
        { "Retransmission Timer UL", "l2server.retransmission-timerul", FT_UINT32, BASE_DEC,
          VALS(drx_retransmission_timer_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_drx_longcyclestartoffset_isvalid,
        { "LongCycleStartOffset isValid", "l2server.longcyclestartoffset-isvalid", FT_UINT8, BASE_DEC,
          VALS(drx_long_cycle_start_offset_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_drx_longcyclestartoffset,
        { "LongCycleStartOffset", "l2server.longcyclestartoffset", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_drx_short_cycle,
        { "ShortCycle", "l2server.shortcycle", FT_INT32, BASE_DEC,
          VALS(drx_short_cycle_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_drx_short_cycle_timer,
        { "ShortCycleTimer", "l2server.shortcycletimer", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_drx_slot_offset,
        { "SlotOffset", "l2server.slotoffset", FT_UINT8, BASE_DEC,
          NULL, 0x0, "(0..31). Value is 1/32 ms", HFILL }},

      { &hf_l2server_log,
        { "Log", "l2server.log", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_mac_cell_group_len,
        { "Length", "l2server.mac-cell-group-len", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_spcell_config_ded,
        { "spCell Config Dedicated", "l2server.spcell-config-ded", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_spcell_config_ded_len,
        { "Length", "l2server.spcell-config-ded-len", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_radio_condition_group,
        { "Radio Condition Group", "l2server.radio-condition-group", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_radio_condition_profile_index,
        { "Radio Condition Profile Index", "l2server.radio-condition-profile-index", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_fname,
        { "fname", "l2server.fname", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nbslotspeccfg_addmod,
        { "NbSlotSpecCfg AddMod", "l2server.nbslotspeccfg-addmod", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nbslotspeccfg_del,
        { "NbSlotSpecCfg Del", "l2server.nbslotspeccfg-del", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nbdlbwpidtoadd,
        { "Nb DL BwpId to add", "l2server.nbsdlbwpidtoadd", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nbdlbwpidtodel,
        { "Nb DL BwpId to del", "l2server.nbsdlbwpidtodel", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_sibfilterflag,
        { "SibFilterFlag", "l2server.sib-filter-flag", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_l2server,
        &ett_l2server_header,
        &ett_l2server_ra_info,
        &ett_l2server_params,
        &ett_l2server_l2_cell_dedicated_config,
        &ett_l2server_l1_cell_dedicated_config,
        &ett_l2server_rb_config,
        &ett_l2server_rb_release,
        &ett_l2server_rlc_config_tx,
        &ett_l2server_rlc_config_rx,
        &ett_l2server_ph_cell_config,
        &ett_l2server_sp_cell_cfg_ded,
        &ett_l2server_sp_cell_cfg_common,
        &ett_l2server_rx_lch_info,
        &ett_l2server_tx_lch_info,
        &ett_l2server_drx_config,
        &ett_l2server_mac_cell_group_config,
        &ett_l2server_spcell_config_ded,
        &ett_l2server_sp_cell_cfg_tdd,
        &ett_l2server_sp_cell_cfg_dl,
        &ett_l2server_sp_cell_cfg_ul,
        &ett_l2server_sp_cell_cfg_sup_ul,
        &ett_l2server_sp_cell_cfg_cross_carrier_sched,
        &ett_l2server_sp_cell_cfg_lte_crs_tomatcharound,
        &ett_l2server_sp_cell_cfg_dormantbwp,
        &ett_l2server_sp_cell_cfg_lte_crs_pattern_list1,
        &ett_l2server_sp_cell_cfg_lte_crs_pattern_list2
    };

    static ei_register_info ei[] = {
        { &ei_l2server_sapi_unknown, { "l2server.sapi-unknown", PI_UNDECODED, PI_WARN, "Unknown SAPI", EXPFILL }},
        { &ei_l2server_type_unknown, { "l2server.type-unknown", PI_UNDECODED, PI_WARN, "Unknown Type for SAPI", EXPFILL }},
    };

    module_t *l2server_module;
    expert_module_t* expert_l2server;

    proto_l2server = proto_register_protocol("L2Server", "L2Server", "l2server");
    proto_register_field_array(proto_l2server, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_l2server = expert_register_protocol(proto_l2server);
    expert_register_field_array(expert_l2server, ei, array_length(ei));

    l2server_handle = register_dissector("l2server", dissect_l2server, proto_l2server);

    /* Preferences */
    l2server_module = prefs_register_protocol(proto_l2server, NULL);

    prefs_register_bool_preference(l2server_module, "call_pdcp_drbs", "Call PDCP for DRBs",
        "",
        &global_call_pdcp_for_drb);

    prefs_register_bool_preference(l2server_module, "call_pdcp_tm", "Call PDCP for TM PDUs",
        "",
        &global_call_pdcp_for_tm);

    prefs_register_enum_preference(l2server_module, "sn_bits_for_drb",
        "PDCP SN bits for DRB PDUs",
        "",
        &global_pdcp_drb_sn_length, pdcp_drb_col_vals, FALSE);
}

static void
apply_l2server_prefs(void)
{
    global_l2server_port_range = prefs_get_range_value("l2server", "tcp.port");
}

void
proto_reg_handoff_l2server(void)
{
    dissector_add_uint_range_with_preference("tcp.port", "4000", l2server_handle);
    apply_l2server_prefs();

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
