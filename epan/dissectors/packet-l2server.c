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

static int hf_l2server_nr5gid = -1;
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
static int hf_l2server_msg3_data = -1;
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
static int hf_l2server_ra_ssb_occasion_mask_index = -1;
static int hf_l2server_preamble_tx_max = -1;
static int hf_l2server_totalnumberofra_preambles = -1;

static int hf_l2server_ssb_perrach_occasion = -1;
static int hf_l2server_cb_preamblesperssb = -1;
static int hf_l2server_ra_msg3sizegroupa = -1;
static int hf_l2server_numberofra_preamblesgroupa = -1;
static int hf_l2server_delta_preamble_msg3 = -1;
static int hf_l2server_message_power_offset_groupb = -1;
static int hf_l2server_ra_responsewindow = -1;
static int hf_l2server_ra_contentionresolutiontimer = -1;

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

static int hf_l2server_config = -1;

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
static int hf_l2server_spare = -1;
static int hf_l2server_pad = -1;

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
static int hf_l2server_cellidnritem = -1;

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
static int hf_l2server_mcs_crnti_valid = -1;
static int hf_l2server_mcs_crnti = -1;
static int hf_l2server_pue_fr1 = -1;

static int hf_l2server_tpc_srs_rnti = -1;
static int hf_l2server_tpc_pucch_rnti = -1;
static int hf_l2server_tpc_pusch_rnti = -1;
static int hf_l2server_sp_csi_rnti = -1;
static int hf_l2server_cs_rnti = -1;
static int hf_l2server_pdcch_blind_detection = -1;

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
static int hf_l2server_cmac_cell_status = -1;

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

static int hf_l2server_num_pdcp_actions = -1;

static int hf_l2server_ta = -1;
static int hf_l2server_ra_info_valid = -1;
static int hf_l2server_rach_probe_req = -1;

static int hf_l2server_rrc_state = -1;

static int hf_l2server_cell_config_cellcfg = -1;

static int hf_l2server_nb_aggr_cell_cfg_common = -1;

static int hf_l2server_dlfreq_0 = -1;
static int hf_l2server_dlfreq_1 = -1;
static int hf_l2server_dl_earfcn_0 = -1;
static int hf_l2server_dl_earfcn_1 = -1;
static int hf_l2server_ulfreq_0 = -1;
static int hf_l2server_ulfreq_1 = -1;
static int hf_l2server_ul_earfcn_0 = -1;
static int hf_l2server_ul_earfcn_1 = -1;
static int hf_l2server_ssb_arfcn = -1;
static int hf_l2server_num_dbeam = -1;

static int hf_l2server_ul_cell_cfg_ded = -1;
static int hf_l2server_ul_cell_cfg_ded_len = -1;
static int hf_l2server_first_active_ul_bwp = -1;
static int hf_l2server_num_ul_bwpid_to_add = -1;

static int hf_l2server_initial_ul_bwp = -1;
static int hf_l2server_initial_ul_bwp_len = -1;

static int hf_l2server_ul_bwp = -1;
static int hf_l2server_ul_bwp_len = -1;

static int hf_l2server_ul_bwp_common = -1;

static int hf_l2server_ul_bwp_common_pdcch = -1;
static int hf_l2server_ul_bwp_common_search_space_sib1 = -1;
static int hf_l2server_ul_bwp_common_search_space_sib = -1;
static int hf_l2server_ul_bwp_common_pag_search_space = -1;
static int hf_l2server_ul_bwp_common_ra_search_space = -1;
static int hf_l2server_ul_bwp_common_ra_ctrl_res_set = -1;
static int hf_l2server_ul_bwp_common_nb_common_ctrl_res_sets = -1;
static int hf_l2server_ul_bwp_common_nb_common_search_spaces = -1;
static int hf_l2server_ul_bwp_common_control_resource_set_zero = -1;
static int hf_l2server_ul_bwp_common_search_space_zero = -1;
static int hf_l2server_ul_bwp_common_first_pdcch_moni_occ_of_po_valid = -1;
static int hf_l2server_ul_bwp_common_nb_first_pdcch_monit_occ_of_po = -1;
static int hf_l2server_ul_bwp_common_nb_common_search_spaces_ext = -1;

static int hf_l2server_ul_bwp_common_first_pdcch_moni_occ_of_po = -1;

static int hf_l2server_ul_bwp_common_pdsch = -1;


static int hf_l2server_rach_common = -1;

static int hf_l2server_rach_generic = -1;
static int hf_l2server_msg1_fdm = -1;
static int hf_l2server_msg1_frequency_start = -1;
static int hf_l2server_zero_corr_zone = -1;
static int hf_l2server_preamble_rec_target_pwr = -1;

static int hf_l2server_msg1_subcarrier_spacing = -1;
static int hf_l2server_rest_set_conf = -1;
static int hf_l2server_msg3_tranform_precoding = -1;
static int hf_l2server_rsrp_threshold_ssb = -1;
static int hf_l2server_rsrp_threshold_ssb_sul = -1;
static int hf_l2server_prach_root_seq_index_is_valid = -1;
static int hf_l2server_ssb_per_rach_is_valid = -1;
static int hf_l2server_prach_root_seq_index = -1;
static int hf_l2server_ssb_per_rach = -1;
// TODO: break down and add fields
//static int hf_l2server_group_b_configured = -1;
static int hf_l2server_ra_contention_resolution_timer = -1;


static int hf_l2server_freq_info_dl = -1;
static int hf_l2server_abs_freq_ssb = -1;
static int hf_l2server_abs_freq_point_a = -1;
static int hf_l2server_ssb_subcarrier_offset = -1;
static int hf_l2server_nb_freq_band_list = -1;
static int hf_l2server_nb_scs_spec_carrier = -1;
static int hf_l2server_freq_band_list = -1;

static int hf_l2server_ssb_periodicity_serv_cell = -1;
static int hf_l2server_dmrs_type_a_pos = -1;
static int hf_l2server_sub_car_spacing = -1;
static int hf_l2server_ssb_pos_in_burst_is_valid = -1;
static int hf_l2server_n_timing_advance_offset = -1;
static int hf_l2server_ssb_pos_in_burst_short = -1;
static int hf_l2server_ssb_pos_in_burst_medium = -1;
static int hf_l2server_ssb_pos_in_burst_long = -1;
static int hf_l2server_pbch_block_power = -1;
static int hf_l2server_nb_rate_match_pattern_to_add_mod = -1;
static int hf_l2server_nb_rate_match_pattern_to_del = -1;

static int hf_l2server_bwp_dl_common = -1;
static int hf_l2server_freq_info_ul_common = -1;
static int hf_l2server_bwp_ul_common = -1;
static int hf_l2server_freq_info_sul_common = -1;
static int hf_l2server_bwp_sul_common = -1;
static int hf_l2server_tdd_common = -1;

static int hf_l2server_beamid = -1;

static int hf_l2server_rlcmac_verbosity = -1;
static int hf_l2server_dl_harq_mode = -1;
static int hf_l2server_ul_fs_advance = -1;
static int hf_l2server_max_rach = -1;
static int hf_l2server_num_nr_cell = -1;

static int hf_l2server_num_up_stk_ppu = -1;
static int hf_l2server_num_dwn_stk_ppu = -1;
static int hf_l2server_num_nr_pro_ppu = -1;

static int hf_l2server_up_stk_ppu = -1;
static int hf_l2server_dwn_stk_ppu = -1;
static int hf_l2server_nr_pro_ppu = -1;

static int hf_l2server_setup_reconf = -1;

static int hf_l2server_mac_config = -1;

static int hf_l2server_lch_basedprioritization_r16 = -1;

static int hf_l2server_initial_dl_bwp_present = -1;
static int hf_l2server_pdsch_present = -1;
static int hf_l2server_pdcch_present = -1;
static int hf_l2server_csi_meas_config_present = -1;

static int hf_l2server_first_active_dl_bwp = -1;
static int hf_l2server_nb_dl_bwp_scs_spec_carrier = -1;
static int hf_l2server_dl_bwp_id_to_del = -1;

static int hf_l2server_bwp_dl_dedicated = -1;
static int hf_l2server_nb_sps_conf_to_add_r16 = -1;
static int hf_l2server_nb_config_deactivation_state_r16 = -1;

static int hf_l2server_pdsch_serving_cell = -1;
static int hf_l2server_xoverhead = -1;
static int hf_l2server_nb_harq_processes_for_pdsch = -1;

static int hf_l2server_nb_code_block_group_transmission_r16 = -1;

static int hf_l2server_pdcch_serving_cell = -1;

static int hf_l2server_csi_meas_config = -1;
static int hf_l2server_nb_nzp_csi_rs_res_to_add = -1;
static int hf_l2server_nb_nzp_csi_rs_res_to_del = -1;
static int hf_l2server_nb_nzp_csi_rs_res_set_to_add = -1;
static int hf_l2server_nb_nzp_csi_rs_res_set_to_del = -1;
static int hf_l2server_nb_csi_im_res_to_add = -1;
static int hf_l2server_nb_csi_im_res_to_del = -1;
static int hf_l2server_nb_csi_im_res_set_to_add = -1;
static int hf_l2server_nb_csi_im_res_set_to_del = -1;
static int hf_l2server_nb_csi_ssb_res_set_to_add = -1;
static int hf_l2server_nb_csi_ssb_res_set_to_del = -1;
static int hf_l2server_nb_csi_res_cfg_to_add = -1;
static int hf_l2server_nb_csi_res_cfg_to_del = -1;
static int hf_l2server_nb_csi_rep_cfg_to_add = -1;
static int hf_l2server_nb_csi_rep_cfg_to_del = -1;
static int hf_l2server_nb_aper_trigger_state_list = -1;
static int hf_l2server_nb_sp_on_pusch_trigger_state = -1;
static int hf_l2server_report_trigger_size = -1;
static int hf_l2server_report_trigger_size_dci02_r16 = -1;

static int hf_l2server_nzp_csi_rs_res_config = -1;
static int hf_l2server_resource_id = -1;
static int hf_l2server_power_control_offset = -1;
static int hf_l2server_power_control_offset_ss = -1;
static int hf_l2server_qcl_info_periodic_csi_rs = -1;
static int hf_l2server_scramblingid = -1;

static int hf_l2server_nzp_csi_rs_res_set_config = -1;
static int hf_l2server_resource_set_id = -1;
static int hf_l2server_repetition = -1;
static int hf_l2server_aper_trigger_offset = -1;
static int hf_l2server_trs_info = -1;
static int hf_l2server_aper_trigger_offset_r16 = -1;
static int hf_l2server_nb_nzp_csi_rs_res_lis = -1;
static int hf_l2server_nzp_csi_rs_res_list = -1;

static int hf_l2server_csi_im_res_config = -1;

static int hf_l2server_csi_im_res_set_config = -1;
static int hf_l2server_res_set_id = -1;
static int hf_l2server_csi_im_res_list = -1;

static int hf_l2server_csi_ssb_res_set_config = -1;
static int hf_l2server_csi_ssb_res_list = -1;

static int hf_l2server_csi_res_config = -1;
static int hf_l2server_csi_res_id = -1;
static int hf_l2server_csi_res_type = -1;
static int hf_l2server_csi_rs_res_set_list_is_valid = -1;

static int hf_l2server_csi_rep_config = -1;
static int hf_l2server_carrier = -1;
static int hf_l2server_csi_rep_config_id = -1;

static int hf_l2server_nb_mon_pmi_port_ind = -1;

static int hf_l2server_report_config_type_is_valid = -1;
static int hf_l2server_report_quantity_is_valid = -1;
static int hf_l2server_cri_ri_pmi_cqi = -1;

static int hf_l2server_semipersistent_on_pucch = -1;

static int hf_l2server_codebook_config = -1;
static int hf_l2server_codebook_type_is_valid = -1;

static int hf_l2server_codebook_config_type1 = -1;
static int hf_l2server_codebook_subtype1_is_valid = -1;

static int hf_l2server_codebook_config_type1_single_panel = -1;
static int hf_l2server_nb_of_ant_ports_is_valid = -1;

static int hf_l2server_aperiodic = -1;
static int hf_l2server_nb_rep_slow_offset_list = -1;
static int hf_l2server_nb_rep_slow_offset = -1;

static int hf_l2server_csi_report_freq_config = -1;
static int hf_l2server_cqi_cmd_indicator = -1;
static int hf_l2server_pmi_cmd_indicator = -1;
static int hf_l2server_csi_reporting_band_is_valid = -1;
static int hf_l2server_csi_reporting_band = -1;

static int hf_l2server_ul_am_cnf_frame = -1;
static int hf_l2server_ul_am_req_frame = -1;

static int hf_l2server_nzp_csi_rs_res_to_del = -1;
static int hf_l2server_nzp_csi_rs_res_set_to_del = -1;
static int hf_l2server_csi_im_res_to_del = -1;
static int hf_l2server_csi_im_res_set_to_del = -1;
static int hf_l2server_csi_ssb_res_set_to_del = -1;
static int hf_l2server_csi_res_cfg_to_del = -1;
static int hf_l2server_csi_rep_cfg_to_del = -1;

static int hf_l2server_control_res_set = -1;
static int hf_l2server_control_res_set_id = -1;
static int hf_l2server_control_res_set_duration = -1;
static int hf_l2server_prec_granualarity = -1;
static int hf_l2server_cce_reg_map_type = -1;
static int hf_l2server_reg_bundle_size = -1;
static int hf_l2server_interleave_size = -1;
static int hf_l2server_shift_index = -1;
static int hf_l2server_freq_dom_res = -1;

static int hf_l2server_search_space = -1;
static int hf_l2server_search_space_id = -1;

static int hf_l2server_n1n2 = -1;

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
    { 5,     "Discard 5 RARs"},
    { 6,     "Discard 6 RARs"},
    { 7,     "Discard 7 RARs"},
    { 8,     "Discard 8 RARs"},
    { 9,     "Discard 9 RARs"},
    { 10,    "Discard 10 RARs"},
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

static const value_string  rrc_state_vals[] =
{
    { nr5g_rlcmac_Cmac_Rrc_State_IDLE,       "IDLE" },
    { nr5g_rlcmac_Cmac_Rrc_State_MAC_RESET,  "MAC_RESET" },
    { 0,   NULL }
};


static const value_string  sib_folder_flag_vals[] =
{
    { 0,    "Legacy" },
    { 0,   NULL }
};

static const value_string ssb_perrach_occasion_vals[] = {
    { nr5g_lc_Cmac_oneEighth,  "oneEighth" },
    { nr5g_lc_Cmac_oneFourth,  "oneFourth" },
    { nr5g_lc_Cmac_oneHalf,    "oneHalf" },
    { nr5g_lc_Cmac_one,        "one" },
    { nr5g_lc_Cmac_two,        "two" },
    { nr5g_lc_Cmac_four,       "four" },
    { nr5g_lc_Cmac_eight,      "eight" },
    { nr5g_lc_Cmac_sixteen,    "sixteen" },
    { 0,   NULL }
};

static const value_string ssb_pos_in_burst_vals[] = {
    { bb_nr5g_SSB_POS_IN_BURST_SHORT,    "Short" },
    { bb_nr5g_SSB_POS_IN_BURST_MEDIUM,   "Medium" },
    { bb_nr5g_SSB_POS_IN_BURST_LONG,     "Long" },
    { bb_nr5g_SSB_POS_IN_BURST_DEFAULT,  "Default" },
    { 0,   NULL }
};

static const value_string scg_type_vals[] = {
    { 1,    "SCG NR" },
    { 0,   NULL }
};

static const value_string setup_reconf_vals[] = {
    { 1,    "RRC-setup" },
    { 2,    "RRC-Reconfiguration" },
    { 0,   NULL }
};

static const value_string xoverhead_vals[] = {
    { 0,    "x0h6" },
    { 1,    "x0h12" },
    { 2,    "x0h18" },
    { 0,   NULL }
};

static const value_string csi_rs_res_set_list_is_valid_vals[] = {
    { bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_NZP_CSI_RS_SSB,    "NZP CSI RS SSB" },
    { bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_CSI_IM,            "CSI IM" },
    { bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_DEFAULT,           "DEFAULT" },
    { 0,   NULL }
};


static const value_string report_config_type_is_valid_vals[] = {
    { bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODIC,                    "Periodic" },
    { bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCH,      "Semi-persistent-on-pucch" },
    { bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH,      "Semi-persistent-on-pusch" },
    { bb_nr5g_CSI_REPORT_CFG_TYPE_APERIODIC,                   "Aperiodic" },
    { bb_nr5g_CSI_REPORT_CFG_TYPE_DEFAULT,                     "Default" },
    { 0,   NULL }
};

static const value_string report_quantity_is_valid_vals[] = {
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_NONE,                    "NONE" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_PMI_CQI,          "CRI RI PMI CQI" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_I1,               "CRI RI T1" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_I1_CQI,           "CRI TI T1 CQI" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_CQI,              "CRI RI CQI" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RSRP,                "CRI RSRP" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_SSBINDEX_RSRP,           "SSBINDEX RSRP" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_LII_PMI_CQI,      "RI LTI PMI CQI" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_CRI_SINR,            "R16 CRI SINR" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_SSB_INDEX_SINR,      "R16 SSB Index SINR" },
    { bb_nr5g_CSI_REPORT_CFG_QUANTITY_DEFAULT,                 "Default" },
    { 0,   NULL }
};

static const value_string codebook_type_is_valid_vals[] = {
    { bb_nr5g_CODEBOOK_TYPE_1,    "Type 1" },
    { bb_nr5g_CODEBOOK_TYPE_2,    "Type 2" },
    { 0,   NULL }
};

static const value_string cqi_fmt_indicator_vals[] = {
    { 0,    "widebandCQI" },
    { 1,    "subbandCQI" },
    { 0,   NULL }
};

static const value_string pmi_fmt_indicator_vals[] = {
    { 0,    "widebandPMI" },
    { 1,    "subbandPMI" },
    { 0,   NULL }
};

static const value_string csi_reporting_band_id_valid_vals[] = {
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_3,       "subband3" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_4,       "subband4" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_5,       "subband5" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_6,       "subband6" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_7,       "subband7" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_8,       "subband8" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_9,       "subband9" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_10,      "subband10" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_11,      "subband11" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_12,      "subband12" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_13,      "subband13" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_14,      "subband14" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_15,      "subband15" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_16,      "subband16" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_17,      "subband17" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_18,      "subband18" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_19,      "subband19" },
    { bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_DEFAULT, "DEFAULT" },
    { 0,   NULL }
};

static const value_string subtype1_is_valid_vals[] = {
    { bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_I_SINGLE_PANEL,    "Single Panel" },
    { bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_I_MULTI_PANEL,     "Multi Panel" },
    { bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_DEFAULT,           "DEFAULT" },
    { 0,   NULL }
};

static const value_string csi_res_type_vals[] = {
    { 0,    "Aperiodic" },
    { 1,    "Semi-persistent" },
    { 2,    "Periodic" },
    { 0,   NULL }
};

static const value_string cmac_cell_status_vals[] = {
    { nr5g_rlcmac_Cmac_CELL_STATUS_NONE,                "NONE" },
    { nr5g_rlcmac_Cmac_CELL_STATUS_IN_SERVICE,          "In Service" },
    { nr5g_rlcmac_Cmac_CELL_STATUS_RACH_PROBE_FAILURE,  "RACH Probe Failure" },
    { 0,   NULL }
};

static const value_string pdcch_moni_occ_of_po_valid_vals[] = {
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS15KHZoneT,                "SCS15KHZoneT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS30KHZoneT_SCS15KHZhalfT,  "SCS30KHZoneT_SCS15KHZhalfT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS60KHZoneT_SCS30KHZhalfT_SCS15KHZquarterT,                "SCS60KHZoneT_SCS30KHZhalfT_SCS15KHZquarterT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZoneT_SCS60KHZhalfT_SCS30KHZquarterT_SCS15KHZoneEighthT,                "SCS120KHZoneT_SCS60KHZhalfT_SCS30KHZquarterT_SCS15KHZoneEighthT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZhalfT_SCS60KHZquarterT_SCS30KHZoneEighthT_SCS15KHZoneSixteenthT,                "SCS120KHZhalfT_SCS60KHZquarterT_SCS30KHZoneEighthT_SCS15KHZoneSixteenthT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZquarterT_SCS60KHZoneEighthT_SCS30KHZoneSixteenthT,                "SCS120KHZquarterT_SCS60KHZoneEighthT_SCS30KHZoneSixteenthT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZoneEighthT_SCS60KHZoneSixteenthT,                "SCS120KHZoneEighthT_SCS60KHZoneSixteenthT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZoneSixteenthT,                "SCS120KHZoneSixteenthT" },
    { bb_nr5g_FIRST_PDCCH_MON_OCC_DEFAULT,                "DEFAULT" },
    { 0,   NULL }
};

static const value_string nb_of_ant_ports_is_valid_vals[] = {
    { bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_TWO,          "Two" },
    { bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_MORETHANTWO,  "More Than Two" },
    { bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_DEFAULT,      "Default" },
    { 0,   NULL }
};



static const true_false_string nodata_data_vals =
{
    "No Msg3 bytes present",
    "Msg3 bytes present"
};

static const true_false_string continue_rohc_vls =
{
    "true",
    "Not configured/false"
};

//--------------------------------------------------------------------------------
// Want to check for UL AM frames that have no CNF
static gpointer mui_key(guint16 ueid, guint8 cellid _U_, guint8 rbid, guint8 lct, guint mui)
{
    // cellid not being set in CNF...
    return GUINT_TO_POINTER(ueid | /*(cellid << 12) |*/ (rbid<<18) | (lct<<26) | (guint64)mui<<32);
}

// Both tables are from mui_key -> frame_number
static wmem_map_t *ul_req_table = NULL;
static wmem_map_t *ul_cnf_table = NULL;



/* Subtrees */
static gint ett_l2server = -1;
static gint ett_l2server_header = -1;
static gint ett_l2server_nr5gid = -1;
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
static gint ett_l2server_cell_config_cellcfg = -1;
static gint ett_l2server_ul_ded_config = -1;
static gint ett_l2server_initial_ul_bwp = -1;
static gint ett_l2server_ul_bwp = -1;
static gint ett_l2server_ul_bwp_common = -1;
static gint ett_l2server_ul_bwp_common_pdcch = -1;
static gint ett_l2server_ul_bwp_common_pdsch = -1;
static gint ett_l2server_rach_common = -1;
static gint ett_l2server_rach_generic = -1;
static gint ett_l2server_freq_info_dl = -1;

static gint ett_l2server_bwp_dl_common = -1;
static gint ett_l2server_freq_info_ul_common = -1;
static gint ett_l2server_bwp_ul_common = -1;
static gint ett_l2server_freq_info_sul_common = -1;
static gint ett_l2server_bwp_sul_common = -1;
static gint ett_l2server_tdd_common = -1;
static gint ett_l2server_mac_config = -1;
static gint ett_l2server_bwp_dl_dedicated = -1;
static gint ett_l2server_pdsch_serving_cell = -1;
static gint ett_l2server_pdcch_serving_cell = -1;
static gint ett_l2server_csi_meas_config = -1;
static gint ett_l2server_nzp_csi_rs_res_config = -1;
static gint ett_l2server_nzp_csi_rs_res_set_config = -1;
static gint ett_l2server_csi_im_res_config = -1;
static gint ett_l2server_csi_im_res_set_config = -1;
static gint ett_l2server_csi_ssb_res_set_config = -1;
static gint ett_l2server_csi_res_config = -1;
static gint ett_l2server_csi_rep_config = -1;
static gint ett_l2server_semipersistent_on_pucch = -1;
static gint ett_l2server_codebook_config = -1;
static gint ett_l2server_codebook_config_type1 = -1;
static gint ett_l2server_codebook_config_type1_single_panel = -1;
static gint ett_l2server_aperiodic = -1;
static gint ett_l2server_csi_report_freq_config = -1;
static gint ett_l2server_control_res_set = -1;
static gint ett_l2server_search_space = -1;


static expert_field ei_l2server_sapi_unknown = EI_INIT;
static expert_field ei_l2server_type_unknown = EI_INIT;
static expert_field ei_l2server_ul_no_cnf = EI_INIT;
static expert_field ei_l2server_ul_no_req = EI_INIT;


extern int proto_pdcp_nr;

static dissector_handle_t l2server_handle;
static dissector_handle_t l2server_message_handle;
static dissector_handle_t pdcp_nr_handle;

void proto_reg_handoff_l2server (void);


/* Preferences */
static gboolean global_call_pdcp_for_drb = TRUE;
static gboolean global_call_pdcp_for_srb = TRUE;
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
                                           guint offset, guint len _U_);

static guint dissect_rlcmac_cmac_ra_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                        guint offset, guint len _U_, guint32 *bwpid);

static guint dissect_rlcmac_cmac_ra_info_empty(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                               guint offset _U_, guint len _U_, gboolean from_bwp_mask);

static int dissect_ph_cell_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset);

static int dissect_sp_cell_cfg_common(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset);



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

// nr5g_l2_Srv_CELL_PARM_ACKt from L2ServerMessages.h
static void dissect_cell_parm_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* CellId (1 byte) */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /**********************************/
    /* Parm (nr5g_l2_Srv_Cell_Parm_t) */
    /* phy_cell_id */
    proto_tree_add_item(tree, hf_l2server_physical_cellid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* dlFreq[2] */
    proto_tree_add_item(tree, hf_l2server_dlfreq_0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_dlfreq_1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* dlEarfcn[2]*/
    proto_tree_add_item(tree, hf_l2server_dl_earfcn_0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_dl_earfcn_0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* ulFreq[2] */
    proto_tree_add_item(tree, hf_l2server_ulfreq_0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_ulfreq_1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* ulEarfcn[2] */
    proto_tree_add_item(tree, hf_l2server_ul_earfcn_0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_l2server_ul_earfcn_0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* SsbArfcn */
    proto_tree_add_item(tree, hf_l2server_ssb_arfcn, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* NumDbeam */
    proto_tree_add_item(tree, hf_l2server_num_dbeam, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* Dbeam */
    for (int n=0; n < nr5g_MaxDbeam; n++) {
        /* TODO: */
        /* Ppu (comgen_qnxPPUIDt from qnx_gen.h)*/
        /* DbeamId */
        offset += 2;
    }
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

/* Nr5gId (UEId + CellId + BeamIdx) */
static guint dissect_nr5gid(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset, guint32 *ueid, guint32 *cellid)
{
    proto_item *nr5gid_ti = proto_tree_add_string_format(tree, hf_l2server_nr5gid, tvb,
                                                          offset, 12,
                                                          "", "Nr5gId ");
    proto_tree *nr5gid_tree = proto_item_add_subtree(nr5gid_ti, ett_l2server_nr5gid);

    proto_tree_add_item_ret_int(nr5gid_tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN, ueid);
    offset += 4;
    proto_tree_add_item_ret_int(nr5gid_tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN, cellid);
    offset += 4;
    gint beamidx;
    proto_tree_add_item_ret_int(nr5gid_tree, hf_l2server_beamidx, tvb, offset, 4, ENC_LITTLE_ENDIAN, &beamidx);
    offset += 4;

    proto_item_append_text(nr5gid_ti, "(UeId=%u, cellId=%d, beamIdx=%d)", *ueid, *cellid, beamidx);
    return offset;
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
    guint32 cellid;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, (guint32*)&p_pdcp_nr_info->ueid, &cellid);

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

        // TODO: switch on all types (allowed in this direction).
        switch (lch) {
            case 0x4:
                p_pdcp_nr_info->bearerType = Bearer_CCCH;
                break;
            default:
                p_pdcp_nr_info->bearerType = Bearer_DCCH;
                break;
        }
    }

    /* Ref(erence for CNF) */
    proto_tree_add_item(tree, hf_l2server_ref, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* MUI */
    guint32 mui;
    proto_item *mui_ti = proto_tree_add_item_ret_uint(tree, hf_l2server_mui, tvb, offset, 1, ENC_LITTLE_ENDIAN, &mui);
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

    // Store these on first pass.
    if ((mode == AM) && !PINFO_FD_VISITED(pinfo)) {
        wmem_map_insert(ul_req_table,
                        mui_key(p_pdcp_nr_info->ueid, cellid, p_pdcp_nr_info->bearerId, lch, mui),
                        GUINT_TO_POINTER(pinfo->num));
    }
    // Look up CNF on further passes.
    else {
        guint32 *cnf_frame = (guint32*)wmem_map_lookup(ul_cnf_table,
                                                       mui_key(p_pdcp_nr_info->ueid, cellid, p_pdcp_nr_info->bearerId, lch, mui));
        if (cnf_frame) {
            proto_tree_add_uint(tree, hf_l2server_ul_am_cnf_frame,
                                tvb, 0, 0, GPOINTER_TO_UINT(cnf_frame));
        }
        else {
            // Add expert info
            expert_add_info_format(pinfo, mui_ti, &ei_l2server_ul_no_cnf,
                                   "No CNF received for MUI (%u)", mui);
        }
    }

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
    else if (global_call_pdcp_for_srb && p_pdcp_nr_info->plane == NR_SIGNALING_PLANE) {
        tvbuff_t *pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_tvb);
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


// nr5g_rlcmac_Data_MUI_t (from nr5g-rlcmac_Data.h)
static void dissect_rlcmac_data_cnf(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    guint32 ueid, cellid, rbid, lct;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, &ueid, &cellid);

    /* RbType */
    proto_tree_add_item(tree, hf_l2server_rbtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* RbId */
    proto_tree_add_item_ret_uint(tree, hf_l2server_rbid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rbid);
    offset++;
    /* LCH */
    proto_tree_add_item_ret_uint(tree, hf_l2server_lch, tvb, offset, 1, ENC_LITTLE_ENDIAN, &lct);
    offset += 1;
    /* Ref(erence for CNF) */
    proto_tree_add_item(tree, hf_l2server_ref, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* ScGid */
    proto_tree_add_item(tree, hf_l2server_scgid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* MUI */
    guint32 mui;
    proto_item *mui_ti = proto_tree_add_item_ret_uint(tree, hf_l2server_mui, tvb, offset, 1, ENC_LITTLE_ENDIAN, &mui);
    offset += 1;

    // Store these on first pass.
    if (!PINFO_FD_VISITED(pinfo)) {
        wmem_map_insert(ul_cnf_table,
                        mui_key(ueid, cellid, rbid, lct, mui),
                        GUINT_TO_POINTER(pinfo->num));
    }
    // Look up REQ on further passes.
    else {
        guint32 *req_frame = (guint32*)wmem_map_lookup(ul_req_table,
                                                       mui_key(ueid, cellid, rbid, lct, mui));
        if (req_frame) {
            proto_tree_add_uint(tree, hf_l2server_ul_am_req_frame,
                                tvb, 0, 0, GPOINTER_TO_UINT(req_frame));
        }
        else {
            // Add expert info
            expert_add_info_format(pinfo, mui_ti, &ei_l2server_ul_no_req,
                                   "No REQ received for MUI (%u) see in CNF", mui);
        }
    }

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
    guint32 cellid;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, (uint32_t*)&p_pdcp_nr_info->ueid, &cellid);

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
    else if (global_call_pdcp_for_srb && p_pdcp_nr_info->plane == NR_SIGNALING_PLANE) {
        tvbuff_t *pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        p_pdcp_nr_info->pdu_length = tvb_reported_length(pdcp_tvb);
        call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);

        proto_item_set_hidden(pdcp_ti);
    }


    if (global_call_pdcp_for_tm && (mode == TM)) {
        p_pdcp_nr_info->maci_present = FALSE;

        /* Call dissector with data */
        tvbuff_t *pdcp_tvb;

        pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
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
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

    // Spare
    proto_tree_add_item(tree, hf_l2server_spare4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // CellId
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // TA
    proto_tree_add_item(tree, hf_l2server_ta, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // RaInfoValid
    gboolean ra_info_valid;
    proto_tree_add_item_ret_boolean(tree, hf_l2server_ra_info_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &ra_info_valid);
    offset += 1;
    // RachProbeReq
    proto_tree_add_item(tree, hf_l2server_rach_probe_req, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // RA_Info (nr5g_rlcmac_Cmac_RA_Info_t) -> (bb_nr5g_CELL_GROUP_CONFIGt in bb-nr5g_struct.h)
    if (ra_info_valid) {
        guint32 bwpid = 0;
        offset = dissect_rlcmac_cmac_ra_info(tree, tvb, pinfo, offset, len, &bwpid);
    }
    else {
        // Still there, but skip.
        offset = dissect_rlcmac_cmac_ra_info_empty(tree, tvb, pinfo, offset, len, FALSE);
    }


    // CellCfg (nr5g_rlcmac_Cmac_CellCfg_t from nr5g-rlcmac_Cmac.h ->
    //          bb_nr5g_CELL_GROUP_CONFIGt from bb-nr5g_struct_macro.h)
    gint start_offset = offset;
    proto_item *cellcfg_ti = proto_tree_add_string_format(tree, hf_l2server_cell_config_cellcfg, tvb,
                                                          offset, 4,
                                                          "", "CellCfg ");
    proto_tree *cellcfg_tree = proto_item_add_subtree(cellcfg_ti, ett_l2server_cell_config_cellcfg);

    //     PhyCellConf
    offset = dissect_ph_cell_config(cellcfg_tree, tvb, pinfo, offset);

    //     CellCfgCommon
    offset = dissect_sp_cell_cfg_common(cellcfg_tree, tvb, pinfo, offset);

    proto_item_set_len(cellcfg_ti, offset-start_offset);


#if 0
    // FieldMask
    guint32 fieldmask;
    proto_tree_add_item_ret_uint(cellcfg_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                 ENC_LITTLE_ENDIAN, &fieldmask);
    offset += 4;

    if (fieldmask & bb_nr5g_STRUCT_CELL_GROUP_CONFIG_PHY_CELL_CONF_PRESENT) {
        // PhyCellConf
        offset = dissect_ph_cell_config(cellcfg_tree, tvb, pinfo, offset);
    }

    if (fieldmask & bb_nr5g_STRUCT_CELL_GROUP_CONFIG_CELL_CFG_COMMON_PRESENT) {
        // CellCfgCommon
        offset = dissect_sp_cell_cfg_common(cellcfg_tree, tvb, pinfo, offset);
    }

    // NbAggrCellCfgCommon (number of valid elements)
    gint32 nb;
    proto_tree_add_item_ret_int(cellcfg_tree, hf_l2server_nb_aggr_cell_cfg_common, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb);
    offset += 1;

    // AggrCellCfgCommon (elements in array)
    if (nb == -1) {
        nb = 0;
    }
    for (gint32 n=0; n < nb; ++n) {
        // TODO: bb_nr5g_SERV_CELL_CONFIG_COMMONt
        // (ServingCellConfigCommon from RRC!).
        // contains several present flags + variable arrays.
        offset = dissect_sp_cell_cfg_common(cellcfg_tree, tvb, pinfo, offset);
    }

    proto_item_set_len(cellcfg_ti, offset-start_offset);
#endif
}

static void dissect_cell_config_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, guint len _U_)
{
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

    // CellId
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_create_ue_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

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
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

// TODO: can't find full description
static void dissect_create_ue_nak(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    /* 2 more bytes */
}

static void dissect_delete_ue_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_delete_ue_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

// : can't find full description
static void dissect_delete_ue_nak(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset, guint len _U_)
{
    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    /* 2 more bytes */
}

// nr5g_l2_Srv_SCG_REL_AND_ADDt (nr5g_l2_Srv_HANDOVERt) from L2ServerMessages.h
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

    /* The rest of the message is CMAC_Config_cmd body */
    proto_item *mac_ti = proto_tree_add_string_format(tree, hf_l2server_mac_config, tvb,
                                                          offset, mac_config_len,
                                                          "", "MAC Config ");
    proto_tree *mac_tree = proto_item_add_subtree(mac_ti, ett_l2server_mac_config);
    dissect_rlcmac_cmac_config_cmd(mac_tree, tvb, pinfo, offset, mac_config_len);
}

static void dissect_handover_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset, guint len _U_)
{
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

    /* UeId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

/* nr5g_rlcmac_Data_RA_REQ_t in nr5g-rlcmac_Data.h */
static void dissect_ra_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                           guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    guint32 ueid, cellid;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, &ueid, &cellid);

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
    proto_tree_add_item(tree, hf_l2server_spare, tvb, offset, 11, ENC_LITTLE_ENDIAN);
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
    gboolean nodata;
    proto_tree_add_item_ret_boolean(tree, hf_l2server_no_data, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nodata);
    offset++;

    /* Data/msg3... */
    if (!nodata) {
        proto_tree_add_string_format(tree, hf_l2server_msg3_data, tvb, offset,
                                     -1, "", "Msg3");

        /* Don't want RRC dissector to overwrite Info column */
        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);

        /* Call UL CCCH dissector for these bytes */
        dissector_handle_t msg3_handle = find_dissector_add_dependency("nr-rrc.ul.ccch", proto_pdcp_nr);
        tvbuff_t *msg3_payload_tvb = tvb_new_subset_length(tvb, offset, -1);
        call_dissector_only(msg3_handle, msg3_payload_tvb, pinfo, tree, NULL);

        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
    }

    // Add rach filter
    proto_item *rach_ti = proto_tree_add_item(tree, hf_l2server_rach, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(rach_ti);
}

static void dissect_ra_cnf(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                           guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    guint32 ueid, cellid;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, &ueid, &cellid);

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
    guint32 ueid, cellid;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, &ueid, &cellid);

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
    guint32 ueid, cellid;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, &ueid, &cellid);

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
    proto_tree *ra_info_tree = proto_item_add_subtree(ra_info_ti, ett_l2server_ra_info);

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
    // ra_ssb_OccasionMaskIndex
    proto_tree_add_item(ra_info_tree, hf_l2server_ra_ssb_occasion_mask_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // preambleTxMax
    proto_tree_add_item(ra_info_tree, hf_l2server_preamble_tx_max, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // totalNumberOfRA_Preambles
    gint32 num_preambles;
    proto_tree_add_item_ret_int(ra_info_tree, hf_l2server_totalnumberofra_preambles, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_preambles);
    offset++;
    // ssb_perRACH_Occasion
    proto_tree_add_item(ra_info_tree, hf_l2server_ssb_perrach_occasion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    // CB_PreamblesPerSSB
    proto_tree_add_item(ra_info_tree, hf_l2server_cb_preamblesperssb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // groupBconfigured
    //   ra_Msg3SizeGroupA
    proto_tree_add_item(ra_info_tree, hf_l2server_ra_msg3sizegroupa, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    //   numberofRA_PreamblesGroupA
    proto_tree_add_item(ra_info_tree, hf_l2server_numberofra_preamblesgroupa, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    //   deltaPreambleMsg3
    proto_tree_add_item(ra_info_tree, hf_l2server_delta_preamble_msg3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    //   messagePowerOffsetGroupB
    proto_tree_add_item(ra_info_tree, hf_l2server_message_power_offset_groupb, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // ra_ResponseWindow
    proto_tree_add_item(ra_info_tree, hf_l2server_ra_responsewindow, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // ra_ContentionResolutionTimer
    proto_tree_add_item(ra_info_tree, hf_l2server_ra_contentionresolutiontimer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

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
                                               guint offset _U_, guint len _U_, gboolean from_bwp_mask)
{
    int ra_start = offset;

    /* Subtree */
    proto_item *ra_info_ti = proto_tree_add_string_format(tree, hf_l2server_ra_info, tvb,
                                                          offset, sizeof(nr5g_rlcmac_Cmac_RA_Info_t),
                                                          "", "RA Info ");

    proto_item_append_text(ra_info_ti, (from_bwp_mask) ? " (Not in bwpMask)" : " (Not present)");

    // Move to start of next one..
    offset = ra_start + sizeof(nr5g_rlcmac_Cmac_RA_Info_t);
    return offset;
}

// bb_nr5g_PH_CELL_GROUP_CONFIGt (from bb-nr5g_struct.h)
static int dissect_ph_cell_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_ph_cell_config, tvb,
                                                         offset, 0,
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
    proto_tree_add_item(config_tree, hf_l2server_mcs_crnti_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // McsCRnti
    proto_tree_add_item(config_tree, hf_l2server_mcs_crnti, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // PUE_FR1 [-30..33]
    proto_tree_add_item(config_tree, hf_l2server_pue_fr1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // TpcSrsRNTI
    proto_tree_add_item(config_tree, hf_l2server_tpc_srs_rnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // TpcPucchRNTI
    proto_tree_add_item(config_tree, hf_l2server_tpc_pucch_rnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // TpcPuschRNTI
    proto_tree_add_item(config_tree, hf_l2server_tpc_pusch_rnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // SpCsiRNTI
    proto_tree_add_item(config_tree, hf_l2server_sp_csi_rnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // CsRNTI
    proto_tree_add_item(config_tree, hf_l2server_cs_rnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // Pdcch_BlindDetection (1..15)
    proto_tree_add_item(config_tree, hf_l2server_pdcch_blind_detection, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // TODO
    // Harq_ACK_SpatialBundlingPUCCH_secondaryPUCCHgroup_r16
    offset += 1;
    // Harq_ACK_SpatialBundlingPUSCH_secondaryPUCCHgroup_r16
    offset += 1;
    // Pdsch_HARQ_ACK_Codebook_secondaryPUCCHgroup_r16
    offset += 1;
    // P_NR_FR2_r16
    offset += 1;
    // P_UE_FR2_r16
    offset += 1;
    // Nrdc_PCmode_FR1_r16
    offset += 1;
    // Nrdc_PCmode_FR2_r16
    offset += 1;
    // Pdsch_HARQ_ACK_Codebook_r16
    offset += 1;
    // Nfi_TotalDAI_Included_r16
    offset += 1;
    // Ul_TotalDAI_Included_r16
    offset += 1;
    // Pdsch_HARQ_ACK_OneShotFeedback_r16
    offset += 1;
    // pdsch_HARQ_ACK_OneShotFeedbackNDI_r16
    offset += 1;
    // pdsch_HARQ_ACK_OneShotFeedbackCBG_r16
    offset += 1;
    // DownlinkAssignmentIndexDCI_0_2_r16
    offset += 1;
    // DownlinkAssignmentIndexDCI_1_2_r16
    offset += 1;
    // NbPdsch_HARQ_ACK_CodebookList_r16
    offset += 1;
    // AckNackFeedbackMode_r16
    offset += 1;
    // Pdcch_BlindDetection2_r16
    offset += 1;
    // Pdcch_BlindDetection3_r16
    offset += 1;
    // BdFactorR_r16
    offset += 1;
    // Pdsch_HARQ_ACK_CodebookList_r16[2]
    offset += 2;
    // Pad
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // These 2 are included (0xff) in message even present flags not set..

    // Dcp_Config_r16 (bb_nr5g_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16t)
    if (dcp_config_present) {
        // N.B. Size of this is fixed.
        // TODO:
    }
    offset += sizeof(bb_nr5g_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16t);


    // Pdcch_BlindDetectionCA_CombIndicator_r16 (bb_nr5g_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16t)
    if (pdcch_blind_detection_present) {
        // N.B. Size of this is fixed.
        // TODO:
    }
    offset += sizeof(bb_nr5g_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16t);

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_BWP_DOWNLINKDEDICATEDt from bb-nr5g_struct.h
static int dissect_bwp_dl_dedicated(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                    guint offset, const char *title)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_bwp_dl_dedicated, tvb,
                                                         offset, 0,
                                                          "", "%s", title);
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_bwp_dl_dedicated);

    // FieldMask
    guint32 field_mask;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_field_mask_4, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field_mask);
    // TODO: add individual flag fields.
    offset += 4;

    // NbSpsConfToAdd_r16
    guint32 nb_sps_conf_to_add_r16;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_sps_conf_to_add_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_sps_conf_to_add_r16);
    offset += 1;

    // NbConfigDeactivationState_r16
    guint32 nb_config_deactivation_state_r16;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_config_deactivation_state_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_config_deactivation_state_r16);
    offset += 1;

    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // PdcchConfDed
    if (field_mask & bb_nr5g_STRUCT_BWP_DOWNLINK_DED_PDCCH_CFG_PRESENT) {
        // TODO: bb_nr5g_PDCCH_CONF_DEDICATEDt
    }
    // PdschConfDed (bb_nr5g_PDSCH_CONF_DEDICATEDt)
    if (field_mask & bb_nr5g_STRUCT_BWP_DOWNLINK_DED_PDSCH_CFG_PRESENT) {
        // TODO:
    }
    // SpsConfDed
    if (field_mask & bb_nr5g_STRUCT_BWP_DOWNLINK_DED_SPS_CFG_PRESENT) {
        // TODO: (bb_nr5g_SPS_CONF_DEDICATEDt)
    }
    // SpsConfToDel_r16
    if (field_mask & bb_nr5g_STRUCT_BWP_DOWNLINK_DED_SPS_CFG_R16_PRESENT) {
        // TODO: (bb_nr5g_SPS_CONFIG_INDEXt)
    }
    // PdcchConfDedR16
    if (field_mask & bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_R16_PRESENT) {
        // TODO: (bb_nr5g_PDCCH_CONF_DEDICATED_R16t)
    }

    // TODO
    // SpsConfToAdd_r16
    for (guint n=0; n < nb_sps_conf_to_add_r16; n++) {
        // TODO:
    }
    // ConfigDeactivationState_r16
    for (guint n=0; n < nb_config_deactivation_state_r16; n++) {
        // TODO:
    }

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_PDSCH_SERVING_CELL_CFGt from bb-nr5g_struct.h
static int dissect_pdsch_dedicated(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_pdsch_serving_cell,  tvb,
                                                         offset, 0,
                                                          "", "PDSCH Serving Cell");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_pdsch_serving_cell);

    // xOverhead
    proto_tree_add_item(config_tree, hf_l2server_xoverhead, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // NbHarqProcessesForPDSCH
    proto_tree_add_item(config_tree, hf_l2server_nb_harq_processes_for_pdsch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // PucchCell
    offset += 2;
    // MaxMimoLayers
    offset += 1;
    // ProcessingType2Enabled
    offset += 1;

    // NbCodeBlockGroupTransmission_r16
    guint32 nb_code_block_group_transmission_r16;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_code_block_group_transmission_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN,
                                 &nb_code_block_group_transmission_r16);
    offset += 1;

    // Pad
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;


    // CodeBlockGroupTrans (bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt)
    offset += 4;

    // CodeBlockGroupTransmissionList_r16 (bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt)
    // TODO: this is a hack
    nb_code_block_group_transmission_r16 = 4;
    for (guint n=0; n < nb_code_block_group_transmission_r16; n++) {
        offset += sizeof(bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt);
    }

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_PDCCH_SERVING_CELL_CFGt (-> bb_nr5g_SLOT_FMT_INDICATORt) from bb-nr5g_struct.h
static int dissect_pdcch_dedicated(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_pdcch_serving_cell,  tvb,
                                                         offset, 0,
                                                          "", "PDCCH Serving Cell");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_pdcch_serving_cell);

    // DciPayloadSize
    offset += 1;
    // NbSlotFormatCombToAdd
    guint32 nb_slot_format_comb_to_add = tvb_get_guint8(tvb, offset);
    offset += 1;
    // NbSlotFormatCombToDel
    guint32 nb_slot_format_comb_to_del = tvb_get_guint8(tvb, offset);
    offset += 1;

    // Pad
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // Rnti
    offset += 2;

    // SlotFormatCombToDel
    offset += (nb_slot_format_comb_to_del & sizeof(uint32_t));
    // slotFormatCombToAdd
    offset += (nb_slot_format_comb_to_add & sizeof(bb_nr5g_SLOT_FMT_COMBSPERCELLt));

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}


// bb_nr5g_NZP_CSI_RS_RES_CFGt
static int dissect_nzp_csi_rs_res_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_nzp_csi_rs_res_config,  tvb,
                                                         offset, 0,
                                                          "", "NZP CSI RS Res Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_nzp_csi_rs_res_config);

    // ResourceId
    guint32 resource_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_resource_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &resource_id);
    offset += 1;
    // PwrCtrlOffset
    proto_tree_add_item(config_tree, hf_l2server_power_control_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // PwrCtrlOffsetSS
    proto_tree_add_item(config_tree, hf_l2server_power_control_offset_ss, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // QclInfoPeriodicCsiRs
    proto_tree_add_item(config_tree, hf_l2server_qcl_info_periodic_csi_rs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // ScramblingID
    proto_tree_add_item(config_tree, hf_l2server_scramblingid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // TODO:
    // ResourceMapping
    offset += sizeof(bb_nr5g_CSI_RS_RES_MAPPINGt);
    // PeriodicityAndOffset
    offset += sizeof(bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt);

    proto_item_append_text(config_ti, " (resourceId=%u)", resource_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_NZP_CSI_RS_RES_SET_CFGt
static int dissect_nzp_csi_rs_res_set_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                             guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_nzp_csi_rs_res_set_config,  tvb,
                                                         offset, 0,
                                                          "", "NZP CSI RS Res Set Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_nzp_csi_rs_res_set_config);

    // ResSetId
    guint32 resource_set_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_resource_set_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &resource_set_id);
    offset += 1;
    // Repetition
    proto_tree_add_item(config_tree, hf_l2server_repetition, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // AperTriggerOffset
    proto_tree_add_item(config_tree, hf_l2server_aper_trigger_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // TrsInfo
    proto_tree_add_item(config_tree, hf_l2server_trs_info, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // AperTriggerOffset_r16
    proto_tree_add_item(config_tree, hf_l2server_aper_trigger_offset_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // NbNzpCsiRsResLis.
    guint32 nb_nzp_csi_rs_res_lis;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_nzp_csi_rs_res_lis, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_nzp_csi_rs_res_lis);
    offset += 1;
    // NzpCsiRsResList
    for (guint n=0; n < nb_nzp_csi_rs_res_lis; n++) {
        proto_tree_add_item(config_tree, hf_l2server_nzp_csi_rs_res_list, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    // Unset items (but still encoded).
    offset += (bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES_PER_SET-nb_nzp_csi_rs_res_lis);

    proto_item_append_text(config_ti, " (resourceSetId=%u)", resource_set_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}


// bb_nr5g_CSI_IM_RES_CFGt
static int dissect_csi_im_res_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                     guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_nzp_csi_rs_res_set_config,  tvb,
                                                         offset, 0,
                                                          "", "CSI IM Res Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_csi_im_res_config);

    // ResourceId
    guint32 resource_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_resource_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &resource_id);
    offset += 1;

    // Pad[3]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    // ResElemPattern
    offset += sizeof(bb_nr5g_CSI_IM_RES_ELEM_PATTERN_CFGt);
    // FreqBand
    offset += sizeof(bb_nr5g_CSI_FREQUENCY_OCCt);
    // PeriodicityAndOffset
    offset += sizeof(bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt);

    proto_item_append_text(config_ti, " (resourceId=%u)", resource_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CSI_IM_RES_SET_CFGt
static int dissect_csi_im_res_set_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_nzp_csi_rs_res_set_config,  tvb,
                                                         offset, 0,
                                                          "", "CSI IM Res Set Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_csi_im_res_set_config);

    // ResSetId
    guint32 res_set_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_res_set_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &res_set_id);
    offset += 1;

    // NbCsiImResList
    guint32 nb_csi_im_res_list;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_csi_im_res_list, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_im_res_list);
    offset += 1;

    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // CsiImResList
    offset += (nb_csi_im_res_list);
    offset += (bb_nr5g_MAX_NB_CSI_IM_RESOURCES_PER_SET-nb_csi_im_res_list);

    proto_item_append_text(config_ti, " (resourceSetId=%u)", res_set_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CSI_SSB_RES_SET_CFGt
static int dissect_csi_ssb_res_set_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_csi_ssb_res_set_config,  tvb,
                                                         offset, 0,
                                                          "", "CSI SSB Res Set Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_csi_ssb_res_set_config);

    // ResSetId
    guint32 res_set_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_res_set_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &res_set_id);
    offset += 1;

    // NbCsiSsbResList
    guint32 nb_csi_ssb_res_list;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_csi_ssb_res_list, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_ssb_res_list);
    offset += 1;

    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // CsiSsbResList
    offset += (nb_csi_ssb_res_list);
    offset += (bb_nr5g_MAX_NB_CSI_SSB_RESOURCES_PER_SET-nb_csi_ssb_res_list);

    proto_item_append_text(config_ti, " (resourceSetId=%u)", res_set_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}


// bb_nr5g_CSI_RESOURCE_CFGt
static int dissect_csi_res_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_csi_res_config,  tvb,
                                                         offset, 0,
                                                          "", "CSI Res Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_csi_res_config);

    // CsiResId
    guint32 csi_res_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_csi_res_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &csi_res_id);
    offset += 1;

    // BwpId
    gint32 bwpid;
    proto_tree_add_item_ret_int(config_tree, hf_l2server_bwpid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &bwpid);
    offset += 1;

    // CsiResType
    proto_tree_add_item(config_tree, hf_l2server_csi_res_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // CsiRsResSetListIsValid
    guint32 csi_rs_res_set_list_is_valid;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_csi_rs_res_set_list_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &csi_rs_res_set_list_is_valid);
    offset += 1;

    // CsiRsResSetListType
    switch (csi_rs_res_set_list_is_valid) {
        case bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_NZP_CSI_RS_SSB:
            // NzpCsiRsSsbResSetType
            offset += sizeof(bb_nr5g_CSI_RESOURCE_CFG_NZP_CSI_RS_SSBt);
            break;
        case  bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_CSI_IM:
            // CsiImResSetType
            offset += sizeof(bb_nr5g_CSI_RESOURCE_CFG_CSI_IMt);
            break;
    }

    proto_item_append_text(config_ti, " (CsiResId=%u, BwpId=%d)", csi_res_id, bwpid);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCHt
static int dissect_semipersistent_on_pucch(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_semipersistent_on_pucch,  tvb,
                                                         offset, 0,
                                                          "", "Semi-persistent on PUCCH");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_semipersistent_on_pucch);

    // NbPucchCsiResList
    guint32 nb_pucch_csi_res_list;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_csi_rs_res_set_list_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_pucch_csi_res_list);
    offset += 1;

    // Pad[3]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    // RepSlotCfg
    offset += sizeof(bb_nr5g_CSI_REPORT_PERIODICITYANDOFFSETt);

    // PucchCsiResList (bb_nr5g_MAX_NB_BWPS entries?)
    offset += (nb_pucch_csi_res_list * sizeof(bb_nr5g_PUCCH_CSI_RESOURCEt));

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}


// bb_nr5g_CSI_REPORT_CFG_TYPE_APERIODICt. Just memcpy'd in serialization.
static int dissect_aperiodic(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_aperiodic,  tvb,
                                                         offset, 0,
                                                          "", "APeriodic");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_aperiodic);

    // NbRepSlotOffsetList
    guint32 nb_rep_slow_offset_list;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_rep_slow_offset_list, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_rep_slow_offset_list);
    offset += 1;

    // Pad[3]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    // RepSlotOffsetList (bb_nr5g_MAX_NB_UL_ALLOCS entries?)
    // TODO: nb_rep_slow_offset_list elements instead?
    for (guint n=0; n < bb_nr5g_MAX_NB_UL_ALLOCS; n++) {
        proto_item *ti = proto_tree_add_item(config_tree, hf_l2server_nb_rep_slow_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        if (n >= nb_rep_slow_offset_list) {
            proto_item_append_text(ti, " (no in use)");
        }
        offset++;
    }

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_CFGt
static int dissect_and_ports_more_than_two(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset)
{
    guint start_offset = offset;

    // Subtree.  TODO: own subtree item/ett!
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_codebook_config_type1_single_panel,  tvb,
                                                         offset, 0,
                                                          "", "More than 2 Ants");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_codebook_config_type1_single_panel);

    // N1N2IsValid
    offset += 1;
    // TypeISinglePanelCodebookSubsetRestrI2IsValid
    offset += 1;
    // TypeISinglePanelCodebookSubsetRestrI2
    offset += 2;
    // N1N2[32]
    proto_tree_add_item(config_tree, hf_l2server_n1n2, tvb, offset, 32, ENC_LITTLE_ENDIAN);
    offset += 32;

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CODEBOOK_SUBTYPE1_SINGLE_PANEL_CFGt
static int dissect_codebook_type_1_single_panel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_codebook_config_type1_single_panel,  tvb,
                                                         offset, 0,
                                                          "", "Single Panel");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_codebook_config_type1_single_panel);

    // NbOfAntPortsIsValid
    guint32 nb_of_ant_ports_is_valid;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_of_ant_ports_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_of_ant_ports_is_valid);
    offset += 1;
    // TypeISinglePanelRiRestr
    offset += 1;
    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    switch (nb_of_ant_ports_is_valid) {
        case bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_TWO:
            // TODO:
            break;
        case bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_MORETHANTWO:
            dissect_and_ports_more_than_two(config_tree, tvb, pinfo, offset);
            break;
    }

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CODEBOOK_TYPE1_CFGt
static int dissect_codebook_type_1(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_codebook_config_type1,  tvb,
                                                         offset, 0,
                                                          "", "Codebook Type 1");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_codebook_config_type1);

    // CodeBookSubType1IsValid
    guint32 codebook_subtype1_is_valid;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_codebook_subtype1_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &codebook_subtype1_is_valid);
    offset += 1;

    // CodebookMode
    offset += 1;

    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // CodeBookSubType1 (union)
    switch (codebook_subtype1_is_valid) {
        case bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_I_SINGLE_PANEL:
            offset = dissect_codebook_type_1_single_panel(config_tree, tvb, pinfo, offset);
            break;
        case bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_I_MULTI_PANEL:
            offset += sizeof(bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_CFGt);
            break;

        case bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_DEFAULT:
            break;
    }

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CODEBOOK_CFGt
static int dissect_codebook_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_codebook_config,  tvb,
                                                         offset, 0,
                                                          "", "Codebook Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_codebook_config);

    // CodeBookTypeIsValid
    guint32 codebook_type_is_valid;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_codebook_type_is_valid, tvb, offset, 1,
                                 ENC_LITTLE_ENDIAN, &codebook_type_is_valid);
    offset += 1;

    // Pad[3]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    // CodebookType
    switch (codebook_type_is_valid) {
        case bb_nr5g_CODEBOOK_TYPE_1:
            // TODO: bb_nr5g_CODEBOOK_TYPE1_CFGt (variable size)
            offset = dissect_codebook_type_1(config_tree, tvb, pinfo, offset);
            break;
        case bb_nr5g_CODEBOOK_TYPE_2:
            // TODO: bb_nr5g_CODEBOOK_TYPE2_CFGt
            break;
        default:
            // TODO: error?
            break;
    }

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_BWP_DOWNLINKt
static int dissect_bwp_downlink(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    guint start_offset = offset;

    // Subtree.  TODO: own subtree item & ett
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_codebook_config,  tvb,
                                                         offset, 0,
                                                          "", "BWP Downlink");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_codebook_config);

    // BwpId
    gint32 bwpid;
    proto_tree_add_item_ret_int(config_tree, hf_l2server_bwpid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &bwpid);
    offset += 1;
    // Spare
    proto_tree_add_item(config_tree, hf_l2server_spare1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // Fieldmask
    guint32 field_mask;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_field_mask_2, tvb, offset, 2, ENC_LITTLE_ENDIAN, &field_mask);
    offset += 2;

    // BwpDLCommon
    if (field_mask & bb_nr5g_STRUCT_BWP_DOWNLINK_COMMON_CFG_PRESENT) {
        // TODO: bb_nr5g_BWP_DOWNLINKCOMMONt
    }

    // BwpDLDed
    if (field_mask & bb_nr5g_STRUCT_BWP_DOWNLINK_DEDICATED_CFG_PRESENT) {
        // TODO: bb_nr5g_BWP_DOWNLINKDEDICATEDt
    }

    proto_item_append_text(config_ti, " (bwpId=%d)", bwpid);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}




// bb_nr5g_CSI_REPORT_FREQ_CFGt
static int dissect_rep_freq_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_csi_report_freq_config,  tvb,
                                                         offset, 0,
                                                          "", "Report Freq Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_csi_report_freq_config);

    // CqiFmtIndicator
    proto_tree_add_item(config_tree, hf_l2server_cqi_cmd_indicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // PmiFmtIndicator
    proto_tree_add_item(config_tree, hf_l2server_pmi_cmd_indicator, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // CsiReportingBandIsValid
    proto_tree_add_item(config_tree, hf_l2server_csi_reporting_band_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // Pad
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // CsiReportingBand
    // TODO: need to infer how many bits and shift/mask to get encoded value...
    proto_tree_add_item(config_tree, hf_l2server_csi_reporting_band, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_CTRL_RES_SETt
static int dissect_control_res_set(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_control_res_set,  tvb,
                                                         offset, 0,
                                                          "", "Control Res Set");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_control_res_set);

    // CtrlResSetId
    guint32 ctrl_res_set_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_control_res_set_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &ctrl_res_set_id);
    offset += 1;
    // CtrlResSetDuration
    proto_tree_add_item(config_tree, hf_l2server_control_res_set_duration, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // PrecGranularity
    proto_tree_add_item(config_tree, hf_l2server_prec_granualarity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // CceRegMapType
    proto_tree_add_item(config_tree, hf_l2server_cce_reg_map_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // RegBundleSize
    proto_tree_add_item(config_tree, hf_l2server_reg_bundle_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // InterleaverSize
    proto_tree_add_item(config_tree, hf_l2server_interleave_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // ShiftIndex
    proto_tree_add_item(config_tree, hf_l2server_shift_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // FreqDomRes
    proto_tree_add_item(config_tree, hf_l2server_freq_dom_res, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    // PdcchDMRSScramblingId
    offset += 2;
    // PdcchDMRSScramblingIdIsValid
    offset += 1;

    // TciPresentInDci
    offset += 1;
    // NbTciStates
    offset += 1;
    // RbOffset_r16
    offset += 1;
    // TciPresentDCI_r16
    offset += 1;
    // CoresetPoolIndex_r16
    offset += 1;
    // TciStates
    offset += (bb_nr5g_MAX_NB_TCI_STATES_PDCCH);

    proto_item_append_text(config_ti, " (id=%u)", ctrl_res_set_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}


// bb_nr5g_SEARCH_SPACEt
// N.B. sertialization is just to memcpy whole struct...
static int dissect_search_space(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_search_space,  tvb,
                                                         offset, 0,
                                                          "", "Search Space");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_search_space);

    // SearchSpaceId
    guint32 search_space_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_search_space_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &search_space_id);
    offset += 1;

    // CtrlResSetId
    offset += 1;

    // MonitorSymbsInSlot
    offset += 2;

    // MonitorSlotIsValid
    offset += 1;

    // SearchSpaceTypeIsValid
    guint32 search_space_type_is_valid = tvb_get_guint8(tvb, offset);
    offset += 1;

    // MonitorSlot (union)
    offset += 2;

    // NbCandidates
    offset += sizeof(bb_nr5g_MONITOR_NBCANDIDATESt);

    // SearchSpaceType
    switch (search_space_type_is_valid) {
        case bb_nr5g_SEARCH_SPACE_TYPE_COMMON:
            //offset += sizeof(bb_nr5g_SEARCH_SPACETYPE_COMMONt);
            break;
        case bb_nr5g_SEARCH_SPACE_TYPE_DEDICATED:
            //offset += sizeof(bb_nr5g_SEARCH_SPACETYPE_DEDICATEDt);
            break;
        case bb_nr5g_SEARCH_SPACE_TYPE_DEFAULT:
            // Error/absent?
            break;
    }
    offset += MAX(sizeof(bb_nr5g_SEARCH_SPACETYPE_COMMONt),
                         sizeof(bb_nr5g_SEARCH_SPACETYPE_DEDICATEDt));

    // SearchSpaceDuration
    offset += 2;

    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_item_append_text(config_ti, " (id=%u)", search_space_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}



// bb_nr5g_CSI_REPORT_CFGt (from bb-nr5g_struct.h)
static int dissect_csi_rep_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_csi_rep_config,  tvb,
                                                         offset, 0,
                                                          "", "CSI Report Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_csi_rep_config);

    // FieldMask
    guint32 fieldmask;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                 ENC_LITTLE_ENDIAN, &fieldmask);
    offset += 4;

    // CsiRepConfigId
    guint32 csi_rep_config_id;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_csi_rep_config_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &csi_rep_config_id);
    offset += 1;

    // ResForChannelMeas
    offset += 1;
    // CsiIMResForInterference
    offset += 1;
    // NzpCsiRSResForInterference
    offset += 1;

    // Carrier (serving cell identifier)
    proto_tree_add_item(config_tree, hf_l2server_carrier, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // TimeRestForChannelMeas
    offset += 1;
    // TimeRestForInterferenceMeas
    offset += 1;
    // NrOfCQIsPerReport
    offset += 1;
    // GroupBasedBeamRepIsValid
    offset += 1;
    // GroupBasedBeamRepValue
    offset += 1;
    // CqiTable
    offset += 1;
    // SubBandSize
    offset += 1;
    // NbNonPmiPortInd
    guint32 nb_mon_pmi_port_ind;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_mon_pmi_port_ind, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_mon_pmi_port_ind);
    offset += 1;
    // ReportConfigTypeIsValid
    guint32 report_config_type_is_valid;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_report_config_type_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &report_config_type_is_valid);
    offset += 1;
    // ReportQuantityIsValid
    guint32 report_quantity_is_valid;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_report_quantity_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &report_quantity_is_valid);
    offset += 1;

    // ReportQuantity (union)
    switch (report_quantity_is_valid) {
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_NONE:
            // None
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_PMI_CQI:
            // CriRiPmiCqi
            proto_tree_add_item(config_tree, hf_l2server_cri_ri_pmi_cqi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_I1:
            // CriRiI1
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_I1_CQI:
            // CriRiI1Cqi
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_CQI:
            // CriRiCqi
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RSRP:
            // CriRsrp
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_SSBINDEX_RSRP:
            // SsbIdxRsrp
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_LII_PMI_CQI:
            // CriRiLiPmiCqi
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_CRI_SINR:
            // CriSinr_r16
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_SSB_INDEX_SINR:
            // IndexSinr_r16
            break;
        case bb_nr5g_CSI_REPORT_CFG_QUANTITY_DEFAULT:
            break;
    }
    offset += 1;

    // ReportConfigType
    guint report_config_type_offset = offset;
    switch (report_config_type_is_valid) {
        case bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODIC:
            offset += sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODICt);
            break;
        case bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCH:
            offset = dissect_semipersistent_on_pucch(config_tree, tvb, pinfo, offset);
            break;
        case bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH:
            offset += sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCHt);
            break;
        case bb_nr5g_CSI_REPORT_CFG_TYPE_APERIODIC:
            offset = dissect_aperiodic(config_tree, tvb, pinfo, offset);
            break;
        default:
            // TODO: error?
            printf("Unknown report config type (%u)\n", report_config_type_is_valid);
            break;
    }

    // Serialization skips to write next at &out->RepFreqCfg
    // Advance by larges part of (anonymous) union.
    guint report_config_type_len = MAX(sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODICt),
                                       sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCHt));
    report_config_type_len = MAX(report_config_type_len,
                                 sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCHt));
    report_config_type_len = MAX(report_config_type_len,
                                 sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_APERIODICt));
    offset = report_config_type_offset + report_config_type_len;

    // RepFreqCfg (bb_nr5g_CSI_REPORT_FREQ_CFGt)
    offset = dissect_rep_freq_config(config_tree, tvb, pinfo, offset);

    // CodebookCfg (bb_nr5g_CODEBOOK_CFGt, variable size...)
    offset = dissect_codebook_config(config_tree, tvb, pinfo, offset);

    // SemiPersistentOnPUSCH_v1530
    if (fieldmask & bb_nr5g_STRUCT_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1530_PRESENT) {
        offset += sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1530t);
    }

    // SemiPersistentOnPUSCH_v1610
    if (fieldmask & bb_nr5g_STRUCT_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610_PRESENT) {
        offset += sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610t);
    }

    // Aperiodic_v1610
    if (fieldmask & bb_nr5g_STRUCT_CSI_REPORT_CFG_TYPE_APERIODIC_v1610_PRESENT) {
        // TODO: wrong type at bb-nr5g_struct.h:2696 ?
        offset += sizeof(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610t);
    }

    // CodebookType2Cfg_r16
    if (fieldmask & bb_nr5g_STRUCT_CODEBOOK_CFG_TYPE2_R16_PRESENT) {
        offset += sizeof(bb_nr5g_CODEBOOK_TYPE2_CFG_R16t);
    }

    // NonPmiPortInd
    offset += (nb_mon_pmi_port_ind * sizeof(bb_nr5g_PORT_INDEX_FOR8RANKSt));

    proto_item_append_text(config_ti, " (CsiRepConfigId=%u)", csi_rep_config_id);
    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}



// bb_nr5g_CSI_MEAS_CFGt from bb-nr5g_struct.h
static int dissect_csi_meas_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                   guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_csi_meas_config,  tvb,
                                                         offset, 0,
                                                          "", "CSI Meas Config");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_csi_meas_config);

    // Counts

    // NbNzpCsiRsResToAdd
    guint32 nb_nzp_csi_rs_res_to_add;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_nzp_csi_rs_res_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_nzp_csi_rs_res_to_add);
    offset += 1;
    // NbNzpCsiRsResToDel
    guint32 nb_nzp_csi_rs_res_to_del;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_nzp_csi_rs_res_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_nzp_csi_rs_res_to_del);
    offset += 1;

    // NbNzpCsiRsResSetToAdd
    guint32 nb_nzp_csi_rs_res_set_to_add;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_nzp_csi_rs_res_set_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_nzp_csi_rs_res_set_to_add);
    offset += 1;
    // NbNzpCsiRsResSetToDel
    guint32 nb_nzp_csi_rs_res_set_to_del;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_nzp_csi_rs_res_set_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_nzp_csi_rs_res_set_to_del);
    offset += 1;

    // NbCsiImResToAdd
    guint nb_csi_im_res_to_add;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_im_res_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_im_res_to_add);
    offset += 1;
    // NbCsiImResToDel
    guint nb_csi_im_res_to_del;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_im_res_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_im_res_to_del);
    offset += 1;

    // NbCsiImResSetToAdd
    guint32 nb_csi_im_res_set_to_add;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_im_res_set_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_im_res_set_to_add);
    offset += 1;
    // NbCsiImResSetToDel
    guint32 nb_csi_im_res_set_to_del;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_im_res_set_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_im_res_set_to_del);
    offset += 1;

    // NbCsiSsbResSetToAdd
    guint32 nb_csi_ssb_res_set_to_add;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_ssb_res_set_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_ssb_res_set_to_add);
    offset += 1;
    // NbCsiSsbResSetToDel
    guint32 nb_csi_ssb_res_set_to_del;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_ssb_res_set_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_ssb_res_set_to_del);
    offset += 1;

    // NbCsiResCfgToAdd
    guint32 nb_csi_res_cfg_to_add;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_res_cfg_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_res_cfg_to_add);
    offset += 1;
    // NbCsiResCfgToDel
    guint32 nb_csi_res_cfg_to_del;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_res_cfg_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_res_cfg_to_del);
    offset += 1;

    // NbCsiRepCfgToAdd
    guint32 nb_csi_rep_cfg_to_add;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_rep_cfg_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_rep_cfg_to_add);
    offset += 1;
    // NbCsiRepCfgToDel
    guint32 nb_csi_rep_cfg_to_del;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_csi_rep_cfg_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_csi_rep_cfg_to_del);
    offset += 1;

    // NbAperTriggerStateList
    guint32 nb_aper_trigger_state_list;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_aper_trigger_state_list, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_aper_trigger_state_list);
    offset += 1;
    // NbSPOnPuschTriggerStateList
    guint32 nb_sp_on_pusch_trigger_state_list;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_nb_sp_on_pusch_trigger_state, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_sp_on_pusch_trigger_state_list);
    offset += 1;
    // ReportTriggerSize
    proto_tree_add_item(config_tree, hf_l2server_report_trigger_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // ReportTriggerSizeDCI02_r16
    proto_tree_add_item(config_tree, hf_l2server_report_trigger_size_dci02_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // Pad[2]
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    //========================================================================================
    // Added items

    // NzpCsiRsResToAdd
    for (guint n=0; n < nb_nzp_csi_rs_res_to_add; n++) {
        offset = dissect_nzp_csi_rs_res_config(config_tree, tvb, pinfo, offset);
    }
    // NzpCsiRsResSetToAdd
    for (guint n=0; n < nb_nzp_csi_rs_res_set_to_add; n++) {
        offset = dissect_nzp_csi_rs_res_set_config(config_tree, tvb, pinfo, offset);
    }

    // CsiImResToAdd
    for (guint n=0; n < nb_csi_im_res_to_add; n++) {
        offset = dissect_csi_im_res_config(config_tree, tvb, pinfo, offset);
    }

    // CsiImResSetToAdd
    for (guint n=0; n < nb_csi_ssb_res_set_to_add; n++) {
        offset = dissect_csi_im_res_set_config(config_tree, tvb, pinfo, offset);
    }

    // CsiSsbResSetToAdd
    for (guint n=0; n < nb_csi_ssb_res_set_to_add; n++) {
        offset = dissect_csi_ssb_res_set_config(config_tree, tvb, pinfo, offset);
    }

    // CsiResCfgToAdd
    for (guint n=0; n < nb_csi_res_cfg_to_add; n++) {
        offset = dissect_csi_res_config(config_tree, tvb, pinfo, offset);
    }

    // CsiRepCfgToAdd
    for (guint n=0; n < nb_csi_rep_cfg_to_add; n++) {
        offset = dissect_csi_rep_config(config_tree, tvb, pinfo, offset);
    }

    // AperTriggerStateList
    for (guint n=0; n < nb_aper_trigger_state_list; n++) {
        // TODO: not fixed sized...
        offset += (nb_aper_trigger_state_list * sizeof(bb_nr5g_CSI_APERIODIC_TRIGGER_STATE_CFGt));
    }

    // TODO:
    // SPOnPuschTriggerStateList (fixed size)
    offset += (nb_sp_on_pusch_trigger_state_list * sizeof(bb_nr5g_CSI_SEMIPERSISTENT_ONPUSCH_TRIGGER_STATE_CFGt));
    //-----------------------------------------------------------------------------------------


    //-----------------------------------------------------------------------------------------
    // Deleted items

    // NzpCsiRsResToDel
    for (guint n=0; n < nb_nzp_csi_rs_res_to_del; n++) {
        proto_tree_add_item(config_tree, hf_l2server_nzp_csi_rs_res_to_del, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // NzpCsiRsResSetToDel
    for (guint n=0; n < nb_nzp_csi_rs_res_set_to_del; n++) {
        proto_tree_add_item(config_tree, hf_l2server_nzp_csi_rs_res_set_to_del, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // CsiImResToDel
    for (guint n=0; n < nb_csi_im_res_to_del; n++) {
        proto_tree_add_item(config_tree, hf_l2server_csi_im_res_to_del, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // CsiImResSetToDel
    for (guint n=0; n < nb_csi_im_res_set_to_del; n++) {
        proto_tree_add_item(config_tree, hf_l2server_csi_im_res_set_to_del, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // CsiSsbResSetToDel
    for (guint n=0; n < nb_csi_ssb_res_set_to_del; n++) {
        proto_tree_add_item(config_tree, hf_l2server_csi_ssb_res_set_to_del, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // CsiResCfgToDel
    for (guint n=0; n < nb_csi_res_cfg_to_del; n++) {
        proto_tree_add_item(config_tree, hf_l2server_csi_res_cfg_to_del, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // CsiRepCfgToDel
    for (guint n=0; n < nb_csi_rep_cfg_to_del; n++) {
        proto_tree_add_item(config_tree, hf_l2server_csi_rep_cfg_to_del, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    //-----------------------------------------------------------------------------------------

    proto_item_set_len(config_ti, offset-start_offset);
    return offset;
}

// bb_nr5g_SERV_CELL_CONFIGt (from bb-nr5g_struct.h)
static int dissect_sp_cell_cfg_ded(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                  guint offset)
{
    guint start_spcell_cfg_ded_offset = offset;

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
    // TODO:
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

    // DlCellCfgDed (bb_nr5g_DOWNLINK_DEDICATED_CONFIGt from bb-nr5g_struct.h)
    if (dl_ded_present) {
        guint start_offset = offset;
        proto_item *ded_ti = proto_tree_add_string_format(config_tree, hf_l2server_sp_cell_cfg_dl, tvb,
                                                              offset, 0,
                                                              "", "DL Config");
        proto_tree *ded_tree = proto_item_add_subtree(ded_ti, ett_l2server_sp_cell_cfg_dl);

        // FieldMask
        guint32 field_mask;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_field_mask_4, tvb, offset, 4, ENC_LITTLE_ENDIAN, &field_mask);
        proto_tree_add_item(ded_tree, hf_l2server_initial_dl_bwp_present, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ded_tree, hf_l2server_pdsch_present, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ded_tree, hf_l2server_pdcch_present, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ded_tree, hf_l2server_csi_meas_config_present, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        // FirstActiveDlBwp
        proto_tree_add_item(ded_tree, hf_l2server_first_active_dl_bwp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // DefaultDlBwp
        proto_tree_add_item(ded_tree, hf_l2server_default_dl_bwpid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        // NbDlBwpIdToDel
        guint32 nbDlBwpIdToDel;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_nbdlbwpidtodel, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nbDlBwpIdToDel);
        offset += 1;
        // NbDlBwpIdToAdd
        guint32 nbDlBwpIdToAdd;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_nbdlbwpidtoadd, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nbDlBwpIdToAdd);
        offset += 1;
        // NbDlBwpScsSpecCarrier
        guint32 nbDlBwpScsSpecCarrier;
        proto_tree_add_item_ret_uint(ded_tree, hf_l2server_nb_dl_bwp_scs_spec_carrier, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nbDlBwpScsSpecCarrier);
        offset += 1;

        // NbRateMatchPatternDedToAdd
        gint32 nbRateMatchPatternDedToAdd;
        proto_tree_add_item_ret_int(ded_tree, hf_l2server_nb_rate_match_pattern_to_add_mod, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nbRateMatchPatternDedToAdd);
        offset += 1;
        // NbRateMatchPatternDedToDel
        gint32 nbRateMatchPatternDedToDel;
        proto_tree_add_item_ret_int(ded_tree, hf_l2server_nb_rate_match_pattern_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nbRateMatchPatternDedToDel);
        offset += 1;

        // Pad
        proto_tree_add_item(ded_tree, hf_l2server_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        // DlBwpIdToDel
        for (guint n=0; n < bb_nr5g_MAX_NB_BWPS; n++) {
            proto_item *del_ti = proto_tree_add_item(ded_tree, hf_l2server_dl_bwp_id_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if (n >= nbDlBwpIdToDel) {
                proto_item_append_text(del_ti, " (not in use)");
            }
            offset++;
        }

        // Optional fields.

        // InitialDlBwp
        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_INITIAL_DL_BWP_PRESENT) {
            offset = dissect_bwp_dl_dedicated(ded_tree, tvb, pinfo, offset, "Initial DL BWP");
        }
        // PdschServingCellCfg
        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDSCH_PRESENT) {
            offset = dissect_pdsch_dedicated(ded_tree, tvb, pinfo, offset);
        }
        // PdcchServingCellCfg
        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDCCH_PRESENT) {
            offset = dissect_pdcch_dedicated(ded_tree, tvb, pinfo, offset);

        }
        // CsiMeasCfg
        if (field_mask & bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_CSI_MEAS_CFG_PRESENT) {
            // TODO: sad hack to try to get back in line!
            offset += 42;

            offset = dissect_csi_meas_config(ded_tree, tvb, pinfo, offset);
        }

        // TODO: still quite a lot to do here...

        // DlBwpIdToAdd. TODO: not fixed size!!!!!
        for (guint n=0; n < nbDlBwpIdToAdd; n++) {
            // TODO: bb_nr5g_BWP_DOWNLINKt
            offset = dissect_bwp_downlink(ded_tree, tvb, pinfo, offset);
        }

        // DlChannelBwPerScs (fixed size)
        offset += (nbDlBwpScsSpecCarrier * sizeof(bb_nr5g_SCS_SPEC_CARRIERt));
        // RateMatchPatternDedToAdd (fixed size)
        offset += (nbRateMatchPatternDedToAdd * sizeof(bb_nr5g_RATE_MATCH_PATTERNt));
        // RateMatchPatternDedToDel
        offset += (nbRateMatchPatternDedToDel * sizeof(uint32_t));

        proto_item_set_len(ded_ti, offset-start_offset);
    }

    // N.B. Can't start UL config yet as offset after DL won't be correct yet!!!!!!

    // UlCellCfgDed (bb_nr5g_UPLINK_DEDICATED_CONFIGt from bb-nr5g_struct.h)
    if (false && ul_ded_present) {
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
        proto_tree_add_item(ded_tree, hf_l2server_first_active_ul_bwp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
        proto_tree_add_item(ded_tree, hf_l2server_pad, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
        // UlBwpIdToDel
        offset += (bb_nr5g_MAX_NB_BWPS * 1);

        // InitialUlBwp
        if (field_mask & bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_INITIAL_UL_BWP_PRESENT) {
            // TODO: bb_nr5g_BWP_UPLINKDEDICATEDt
            // A lot of FieldMask bits and other types inside here...
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

    proto_item_set_len(config_ti, offset-start_spcell_cfg_ded_offset);

    return offset;
}

// bb_nr5g_SERV_CELL_CONFIG_COMMONt (from bb-nr5g_struct.h)
static int dissect_sp_cell_cfg_common(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset)
{
    guint start_offset = offset;

    // Subtree.
    proto_item *config_ti = proto_tree_add_string_format(tree, hf_l2server_sp_cell_cfg_common, tvb,
                                                         offset, 0,
                                                          "", "SP Cell Cfg Common");
    proto_tree *config_tree = proto_item_add_subtree(config_ti, ett_l2server_sp_cell_cfg_common);

    // FieldMask
    guint32 fieldmask;
    proto_tree_add_item_ret_uint(config_tree, hf_l2server_field_mask_4, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fieldmask);
    offset += 4;
    // ServCellIdx
    proto_tree_add_item(config_tree, hf_l2server_serv_cell_idx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // SsbPeriodicityServCell
    proto_tree_add_item(config_tree, hf_l2server_ssb_periodicity_serv_cell, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // DmrsTypeAPos
    proto_tree_add_item(config_tree, hf_l2server_dmrs_type_a_pos, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // SubCarSpacing
    proto_tree_add_item(config_tree, hf_l2server_sub_car_spacing, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // SsbPosInBurstIsValid
    gint32 ssb_in_burst_type;
    proto_tree_add_item_ret_int(config_tree, hf_l2server_ssb_pos_in_burst_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &ssb_in_burst_type);
    offset += 1;
    // NTimingAdvanceOffset
    proto_tree_add_item(config_tree, hf_l2server_n_timing_advance_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // Pad
    proto_tree_add_item(config_tree, hf_l2server_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // SsbPosInBurst (union)
    switch (ssb_in_burst_type) {
        case bb_nr5g_SSB_POS_IN_BURST_SHORT:
            offset += 7;
            proto_tree_add_item(config_tree, hf_l2server_ssb_pos_in_burst_short, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case bb_nr5g_SSB_POS_IN_BURST_MEDIUM:
            offset += 7;
            proto_tree_add_item(config_tree, hf_l2server_ssb_pos_in_burst_medium, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case bb_nr5g_SSB_POS_IN_BURST_LONG:
            proto_tree_add_item(config_tree, hf_l2server_ssb_pos_in_burst_long, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
    }

    // PBCHBlockPower
    proto_tree_add_item(config_tree, hf_l2server_pbch_block_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // NbRateMatchPatternToAddMod
    proto_tree_add_item(config_tree, hf_l2server_nb_rate_match_pattern_to_add_mod, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // NbRateMatchPatternToDel
    proto_tree_add_item(config_tree, hf_l2server_nb_rate_match_pattern_to_del, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // TODO: are these present flags are always present anyway???

    // FreqInfoDL
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_FREQINFO_DL_COMMON_PRESENT) {
        guint32 freq_info_dl_start = offset;

        // Subtree.
        proto_item *freq_ti = proto_tree_add_string_format(config_tree, hf_l2server_freq_info_dl, tvb,
                                                           offset, 0,
                                                           "", "Freq Info DL ");
        proto_tree *freq_tree = proto_item_add_subtree(freq_ti, ett_l2server_freq_info_dl);

        // AbsFreqSSB
        proto_tree_add_item(freq_tree, hf_l2server_abs_freq_ssb, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        // AbsFreqPointA
        proto_tree_add_item(freq_tree, hf_l2server_abs_freq_point_a, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        // SsbSubcarrierOffset
        proto_tree_add_item(freq_tree, hf_l2server_ssb_subcarrier_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // NbFreqBandList
        guint32 nb_freq_band_list;
        proto_tree_add_item_ret_uint(freq_tree, hf_l2server_nb_freq_band_list, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_freq_band_list);
        offset += 1;
        // NbScsSpecCarrier
        proto_tree_add_item(freq_tree, hf_l2server_nb_scs_spec_carrier, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // Spare
        proto_tree_add_item(freq_tree, hf_l2server_spare1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // FreqBandList
        for (guint32 n=0; n < bb_nr5g_MAX_NB_MULTIBANDS; n++) {
            proto_item *ti = proto_tree_add_item(freq_tree, hf_l2server_freq_band_list, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            if (n >= nb_freq_band_list) {
                proto_item_append_text(ti, " (not set)");
            }
            offset += 2;
        }

        // ScsSpecCarrier
        offset += (sizeof(bb_nr5g_SCS_SPEC_CARRIERt) * bb_nr5g_MAX_SCS);

        proto_item_set_len(freq_ti, offset-freq_info_dl_start);
    }

    // InitDLBWP (bb_nr5g_BWP_DOWNLINKCOMMONt)
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_BWP_DL_COMMON_PRESENT) {
        // Subtree.
        proto_item *bwp_dl_common_ti = proto_tree_add_string_format(config_tree, hf_l2server_bwp_dl_common, tvb,
                                                                    offset, sizeof(bb_nr5g_BWP_DOWNLINKCOMMONt),
                                                                    "", "BWP DL Common");
        proto_tree *bwp_dl_common_tree = proto_item_add_subtree(bwp_dl_common_ti, ett_l2server_bwp_dl_common);
        printf("tree at %p\n", bwp_dl_common_tree);

        // FieldMask
        guint32 field_mask_4;
        proto_tree_add_item_ret_uint(bwp_dl_common_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                     ENC_LITTLE_ENDIAN, &field_mask_4);
        offset += 4;

        // GenBwp (bb_nr5g_BWPt, fixed size)
        offset += sizeof(bb_nr5g_BWPt);

        // PdcchConfCommon (bb_nr5g_PDCCH_CONF_COMMONt)
        if (field_mask_4 & bb_nr5g_STRUCT_BWP_DOWNLINK_COMMON_PDCCH_CFG_PRESENT) {
            gint pdcch_offset = offset;

            // Subtree.
            proto_item *pdcch_ti = proto_tree_add_string_format(bwp_dl_common_tree, hf_l2server_ul_bwp_common_pdcch, tvb,
                                                                offset, 1, "", "PDCCH ");
            proto_tree *pdcch_tree = proto_item_add_subtree(pdcch_ti, ett_l2server_ul_bwp_common_pdcch);

            // SearchSpaceSIB1
            proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_search_space_sib1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // SearchSpaceSIB
            proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_search_space_sib, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // PagSearchSpace
            proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_pag_search_space, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // RaSearchSpace
            proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_ra_search_space, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // RaCtrlResSet
            proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_ra_ctrl_res_set, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // NbCommonCtrlResSets
            guint32 nb_common_ctrl_res_sets;
            proto_tree_add_item_ret_uint(pdcch_tree, hf_l2server_ul_bwp_common_nb_common_ctrl_res_sets, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_common_ctrl_res_sets);
            offset += 1;
            // NbCommonSearchSpaces
            guint32 nb_common_search_spaces;
            proto_tree_add_item_ret_uint(pdcch_tree, hf_l2server_ul_bwp_common_nb_common_search_spaces, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_common_search_spaces);
            offset += 1;
            // ControlResourceSetZero
            proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_control_resource_set_zero, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // SearchSpaceZero
            proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_search_space_zero, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // FirstPdcchMonitOccOfPOIsValid
            guint32 first_pdcch_moni_occ_of_po_valid;
            proto_tree_add_item_ret_uint(pdcch_tree, hf_l2server_ul_bwp_common_first_pdcch_moni_occ_of_po_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &first_pdcch_moni_occ_of_po_valid);
            offset += 1;
            // NbFirstPdcchMonitOccOfPO
            guint32 nb_first_pdcch_moni_occ_of_po;
            proto_tree_add_item_ret_uint(pdcch_tree, hf_l2server_ul_bwp_common_nb_first_pdcch_monit_occ_of_po, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_first_pdcch_moni_occ_of_po);
            offset += 1;
            // NbCommonSearchSpacesExt
            guint32 nb_common_search_spaces_ext;
            proto_tree_add_item_ret_uint(pdcch_tree, hf_l2server_ul_bwp_common_nb_common_search_spaces_ext, tvb, offset, 1, ENC_LITTLE_ENDIAN, &nb_common_search_spaces_ext);
            offset += 1;

            // CommonCtrlResSets
            for (guint32 ccrs=0; ccrs < nb_common_ctrl_res_sets; ccrs++) {
                offset = dissect_control_res_set(pdcch_tree, tvb, pinfo, offset);
            }

            // CommonSearchSpaces
            for (guint32 ccs=0; ccs < nb_common_search_spaces; ccs++) {
                // bb_nr5g_SEARCH_SPACEt
                offset = dissect_search_space(pdcch_tree, tvb, pinfo, offset);
            }

            // FirstPdcchMonitOccOfPO
            for (guint32 mon_occ=0; mon_occ < nb_first_pdcch_moni_occ_of_po; mon_occ++) {
                proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_first_pdcch_moni_occ_of_po, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            // CommonSearchSpacesExt_r16
            for (guint32 ss_ext=0; ss_ext < nb_common_search_spaces_ext; ss_ext++) {
                proto_tree_add_item(pdcch_tree, hf_l2server_ul_bwp_common_first_pdcch_moni_occ_of_po, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                // TODO: not fixed size
                offset += sizeof(bb_nr5g_SEARCH_SPACE_EXTt);
            }

            proto_item_set_len(pdcch_ti, offset-pdcch_offset);
        }

        // TODO: undo sad hack!
        offset += (15*16) + 4;

        // PdschConfCommon (bb_nr5g_PDSCH_CONF_COMMONt) (apparently present regardless!)
        if (field_mask_4 & bb_nr5g_STRUCT_BWP_DOWNLINK_COMMON_PDSCH_CFG_PRESENT) {
            gint pdsch_offset = offset;

            // Subtree.
            proto_item *pdsch_ti = proto_tree_add_string_format(bwp_dl_common_tree, hf_l2server_ul_bwp_common_pdsch, tvb,
                                                                offset, 1, "", "PDSCH ");
            proto_tree *pdsch_tree = proto_item_add_subtree(pdsch_ti, ett_l2server_ul_bwp_common_pdsch);

            // NbPdschAlloc
            guint32 nb_pdsch_alloc = tvb_get_guint8(tvb, offset);
            offset += 1;

            // Spare[3]
            proto_tree_add_item(pdsch_tree, hf_l2server_spare, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            // PdschAlloc
            offset += (nb_pdsch_alloc * sizeof(bb_nr5g_PDSCH_TIMEDOMAINRESALLOCt));

            proto_item_set_len(pdsch_ti, offset-pdsch_offset);
        }

    }

    // FreqInfoUL (bb_nr5g_FREQINFO_ULt). Just memcpy'd by serialization.
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_FREQINFO_UL_COMMON_PRESENT) {
        gint pdsch_offset = offset;

        proto_item *freq_info_ul_common_ti = proto_tree_add_string_format(config_tree, hf_l2server_freq_info_ul_common, tvb,
                                                                         offset, sizeof(bb_nr5g_FREQINFO_ULt),
                                                                         "", "Freq Info UL Common");
        proto_tree *freq_info_ul_common_tree = proto_item_add_subtree(freq_info_ul_common_ti, ett_l2server_freq_info_ul_common);

        // AbsFreqPointA
        offset += 4;
        // AddSpectrumEmission
        offset += 1;
        // FreqShift7p5khz
        offset += 1;
        // PMax
        offset += 1;
        // NbFreqBandList
        offset += 1;
        // NbScsSpecCarrier
        offset += 1;
        // Spare[3]
        proto_tree_add_item(freq_info_ul_common_tree, hf_l2server_spare, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
        // FreqBandList
        offset += (bb_nr5g_MAX_NB_MULTIBANDS * 2);
        // ScsSpecCarrier
        offset += (bb_nr5g_MAX_SCS * sizeof(bb_nr5g_SCS_SPEC_CARRIERt));

        proto_item_set_len(freq_info_ul_common_ti, offset-pdsch_offset);
    }

    // InitULBWP
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_BWP_UL_COMMON_PRESENT) {
        proto_item *initial_ul_bwp_ti = proto_tree_add_string_format(config_tree, hf_l2server_initial_ul_bwp, tvb,
                                                                     offset, sizeof(bb_nr5g_BWP_UPLINKCOMMONt),
                                                                     "", "Initial UL BWP");
        proto_tree *intitial_ul_bwp_tree = proto_item_add_subtree(initial_ul_bwp_ti, ett_l2server_initial_ul_bwp);
        printf("tree at %p\n", intitial_ul_bwp_tree);

        // TODO:
        offset += sizeof(bb_nr5g_BWP_UPLINKCOMMONt);
    }

    // FreqInfoSUL
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_FREQINFO_SUL_COMMON_PRESENT) {
        proto_item *freq_info_sul_common_ti = proto_tree_add_string_format(config_tree, hf_l2server_freq_info_sul_common, tvb,
                                                                           offset, sizeof(bb_nr5g_FREQINFO_ULt),
                                                                           "", "Freq Info SUL Common");
        proto_tree *freq_info_sul_common_tree = proto_item_add_subtree(freq_info_sul_common_ti, ett_l2server_freq_info_sul_common);
        printf("tree at %p\n", freq_info_sul_common_tree);

        // TODO:
        offset += sizeof(bb_nr5g_FREQINFO_ULt);
    }

    // InitSULBWP
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_BWP_SUL_COMMON_PRESENT) {
        proto_item *bwp_sul_common_ti = proto_tree_add_string_format(config_tree, hf_l2server_bwp_sul_common, tvb,
                                                                           offset, sizeof(bb_nr5g_BWP_UPLINKCOMMONt),
                                                                           "", "Init BWP SUL Common");
        proto_tree *bwp_sul_common_tree = proto_item_add_subtree(bwp_sul_common_ti, ett_l2server_bwp_sul_common);
        printf("tree at %p\n", bwp_sul_common_tree);

        // TODO:
        offset += sizeof(bb_nr5g_BWP_UPLINKCOMMONt);
    }

    // TddDlUlConfCommon
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_TDD_COMMON_PRESENT) {
        proto_item *tdd_ti = proto_tree_add_string_format(config_tree, hf_l2server_tdd_common, tvb,
                                                          offset, sizeof(bb_nr5g_TDD_UL_DL_CONFIG_COMMONt),
                                                          "", "TDD DL UL Config Common");
        proto_tree *tdd_tree = proto_item_add_subtree(tdd_ti, ett_l2server_tdd_common);
        printf("tree at %p\n", tdd_tree);

        // TODO:
        offset += sizeof(bb_nr5g_TDD_UL_DL_CONFIG_COMMONt);
    }

    // RateMatchPatternToDel
    // RateMatchPatternToAddMod

    // LteCrsToMatchAround
    if (fieldmask & bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_COMMON_TOMATCHAROUND_PRESENT) {
        // TODO
    }
    // HighSpeedConfig_r16
    if (fieldmask & bb_nr5g_STRUCT_HIGH_SPEED_CONFIG_R16_PRESENT) {
        // TODO
    }

    proto_item_set_len(config_ti, offset-start_offset);

    return offset;
}

static guint dissect_tx_lch_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                 guint offset)
{
    guint start_offset = offset;

    // Subtree.
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

    // Subtree
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

    // Subtree
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


// Type is nr5g_rlcmac_Cmac_CONFIG_CMD_t from nr5g-rlcmac_Cmac.h
static void dissect_rlcmac_cmac_config_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset, guint len _U_)
{
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

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
    proto_tree_add_item(params_tree, hf_l2server_beamid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
            offset = dissect_rlcmac_cmac_ra_info_empty(params_tree, tvb, pinfo, offset, len, TRUE);
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
        // TODO:
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
    proto_tree_add_item(tree, hf_l2server_spare2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // Spare[3]
    proto_tree_add_item(tree, hf_l2server_spare, tvb, offset, 3*4, ENC_LITTLE_ENDIAN);
    offset += (3*4);

    // L1CellDedicatedConfig_Len (apparently not set in rrcCOM.c)
    int l1cell_dedicated_config_len;
    proto_tree_add_item_ret_int(tree, hf_l2server_l1cell_dedicated_config_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &l1cell_dedicated_config_len);
    offset += 4;

    //---------------------------------------------------------------
    // L2CellDedicatedConfig (nr5g_rlcmac_Cmac_CELL_DEDICATED_CONFIGt from nr5g-rlcmac_Cmac-bb.h)
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
    guint32 nbSCellCfgAdd;
    proto_tree_add_item_ret_uint(l2_dedicated_config_tree, hf_l2server_nb_scell_cfg_add, tvb, offset, 1,
                                 ENC_LITTLE_ENDIAN, &nbSCellCfgAdd);
    offset += 1;

    // NbSCellCgDel
    guint32 nbSCellCfgDel;
    proto_tree_add_item_ret_uint(l2_dedicated_config_tree, hf_l2server_nb_scell_cfg_del, tvb, offset, 1,
                                 ENC_LITTLE_ENDIAN, &nbSCellCfgDel);
    offset += 1;

    // PhyCellConfig (CsRNTI)
    proto_tree_add_item(l2_dedicated_config_tree, hf_l2server_cs_rnti, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // SpCellCfgDed (nr5g_rlcmac_Cmac_SERV_CELL_CONFIGt from nr5g-rlcmac_Cmac-bb.h)
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

        // FieldMask
        guint32 fieldmask;
        proto_tree_add_item_ret_uint(spcell_config_ded_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                     ENC_LITTLE_ENDIAN, &fieldmask);
        offset += 4;
        // ServCellIdx
        proto_tree_add_item(spcell_config_ded_tree, hf_l2server_serv_cell_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        // DefaultDlBwpId
        proto_tree_add_item(spcell_config_ded_tree, hf_l2server_default_dl_bwpid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // SupplUlRel
        proto_tree_add_item(spcell_config_ded_tree, hf_l2server_supp_ul_rel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        // Spare
        proto_tree_add_item(spcell_config_ded_tree, hf_l2server_spare2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        // UlCellCfgDed (nr5g_rlcmac_Cmac_UPLINK_DEDICATED_CONFIGt from nr5g-rlcmac_Cmac-bb.h)
        if (fieldmask & nr5g_rlcmac_Cmac_STRUCT_SERV_CELL_CONFIG_UPLINK_PRESENT) {

            // Subtree.
            proto_item *ul_ded_config_ti = proto_tree_add_string_format(spcell_config_ded_tree, hf_l2server_ul_cell_cfg_ded, tvb,
                                                                        offset, 0,
                                                                  "", "UL Cell Cfg Dedicated");
            proto_tree *ul_ded_config_tree = proto_item_add_subtree(ul_ded_config_ti, ett_l2server_ul_ded_config);

            // Len
            guint32 ul_len;
            proto_tree_add_item_ret_uint(ul_ded_config_tree, hf_l2server_ul_cell_cfg_ded_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ul_len);
            offset += 4;
            // FieldMask
            guint ul_fieldmask;
            proto_tree_add_item_ret_uint(ul_ded_config_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                         ENC_LITTLE_ENDIAN, &ul_fieldmask);
            offset += 4;

            // FirstActiveUlBwp
            proto_tree_add_item(ul_ded_config_tree, hf_l2server_first_active_ul_bwp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            // Spare
            offset += 1;

            // TODO:

            // NbUlBwpIdToDel
            offset += 1;

            // NbUlBwpIdToAdd
            guint32 num_bwpid_to_add;
            proto_tree_add_item_ret_uint(ul_ded_config_tree, hf_l2server_num_ul_bwpid_to_add, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_bwpid_to_add);
            offset += 1;

            // UlBwpIdToDel[]
            offset += (1 * bb_nr5g_MAX_NB_BWPS);

            // InitialUlBwp (nr5g_rlcmac_Cmac_BWP_UPLINKDEDICATEDt)
            if (ul_fieldmask & nr5g_rlcmac_Cmac_STRUCT_UPLINK_DEDICATED_CONFIG_INITIAL_UL_BWP_PRESENT) {

                // Subtree.
                proto_item *initial_ul_bwp_ti = proto_tree_add_string_format(ul_ded_config_tree, hf_l2server_initial_ul_bwp, tvb,
                                                                             offset, 0,
                                                                             "", "Initial UL BWP");
                proto_tree *initial_ul_bwp_tree = proto_item_add_subtree(initial_ul_bwp_ti, ett_l2server_initial_ul_bwp);


                // Len
                guint32 initial_ul_bwp_len;
                proto_tree_add_item_ret_uint(initial_ul_bwp_tree, hf_l2server_initial_ul_bwp_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &initial_ul_bwp_len);
                offset += 4;

                // FieldMask
                guint initial_ul_bwp_fieldmask;
                proto_tree_add_item_ret_uint(initial_ul_bwp_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                             ENC_LITTLE_ENDIAN, &initial_ul_bwp_fieldmask);
                offset += 4;

                // N.B. So far, no entries set here...
                if (initial_ul_bwp_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_PUCCH_CFG_PRESENT) {
                }

                if (initial_ul_bwp_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_PUSCH_CFG_PRESENT) {
                }

                if (initial_ul_bwp_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_SRS_CFG_PRESENT) {
                }

                if (initial_ul_bwp_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_CONFIGURED_GRANT_PRESENT) {
                }

                if (initial_ul_bwp_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_BEAM_RECOVERY_CFG_PRESENT) {
                }

                proto_item_set_len(initial_ul_bwp_ti, initial_ul_bwp_len);
            }

            // PuschServingCellCfg
            if (ul_fieldmask & nr5g_rlcmac_Cmac_STRUCT_UPLINK_DEDICATED_CONFIG_PUSCH_PRESENT) {
                // TODO
            }


            // UlBwpIdToAdd (entries are nr5g_rlcmac_Cmac_BWP_UPLINKt from nr5g-rlcmac_Cmac-bb.h)
            for (guint32 n=0; n < num_bwpid_to_add; n++) {
                // Subtree.
                proto_item *ul_bwp_ti = proto_tree_add_string_format(ul_ded_config_tree, hf_l2server_ul_bwp, tvb,
                                                                             offset, 0,
                                                                             "", "UL BWP");
                proto_tree *ul_bwp_tree = proto_item_add_subtree(ul_bwp_ti, ett_l2server_ul_bwp);

                // Len
                int bwp_uplink_len;
                proto_tree_add_item_ret_uint(ul_bwp_tree, hf_l2server_ul_bwp_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &bwp_uplink_len);
                offset += 4;

                // FieldMask
                guint ul_bwp_fieldmask;
                proto_tree_add_item_ret_uint(ul_bwp_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                             ENC_LITTLE_ENDIAN, &ul_bwp_fieldmask);
                offset += 4;

                // BwpId
                proto_tree_add_item(ul_bwp_tree, hf_l2server_bwpid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                // BwpULCommon (nr5g_rlcmac_Cmac_BWP_UPLINKCOMMONt from nr5g-rlcmac_Cmac-bb.h)
                if (ul_bwp_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_COMMON_CFG_PRESENT) {

                    // Subtree.
                    proto_item *common_ti = proto_tree_add_string_format(ul_bwp_tree, hf_l2server_ul_bwp_common, tvb,
                                                                         offset, 1, "", "Common ");
                    proto_tree *common_tree = proto_item_add_subtree(common_ti, ett_l2server_ul_bwp_common);

                    // Len
                    offset += 4;

                    // FieldMask
                    guint32 common_fieldmask;
                    proto_tree_add_item_ret_uint(common_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                                 ENC_LITTLE_ENDIAN, &common_fieldmask);
                    offset += 4;

                    // GenBwp (bb_nr5g_BWPt)
                    offset += 4;

                    // RachCfgCommon (bb_nr5g_RACH_CONF_COMMONt)
                    if (common_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_COMMON_RACH_CFG_PRESENT) {

                        // Subtree.
                        proto_item *rach_ti = proto_tree_add_string_format(common_tree, hf_l2server_rach_common, tvb,
                                                                             offset, 1, "", "RACH Common ");
                        proto_tree *rach_tree = proto_item_add_subtree(rach_ti, ett_l2server_rach_common);

                        // FieldMask
                        guint32 rach_fieldmask;
                        proto_tree_add_item_ret_uint(rach_tree, hf_l2server_field_mask_4, tvb, offset, 4,
                                                     ENC_LITTLE_ENDIAN, &rach_fieldmask);
                        offset += 4;

                        //--------------------------------
                        // RachConfGeneric

                        // Subtree.
                        proto_item *generic_ti = proto_tree_add_string_format(rach_tree, hf_l2server_rach_generic, tvb,
                                                                             offset, 1, "", "RACH Generic ");
                        proto_tree *generic_tree = proto_item_add_subtree(generic_ti, ett_l2server_rach_generic);

                        // PrachConfigIndex
                        proto_tree_add_item(generic_tree, hf_l2server_prach_configindex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                        // Msg1FDM
                        proto_tree_add_item(generic_tree, hf_l2server_msg1_fdm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // Msg1FrequencyStart
                        proto_tree_add_item(generic_tree, hf_l2server_msg1_frequency_start, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                        // ZeroCorrZone
                        proto_tree_add_item(generic_tree, hf_l2server_zero_corr_zone, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // PreambleRecTargetPwr
                        proto_tree_add_item(generic_tree, hf_l2server_preamble_rec_target_pwr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;

                        proto_item_set_len(generic_ti, sizeof(bb_nr5g_RACH_CONF_GENERICt));
                        //--------------------------------

                        // NbOfRaPreambles
                        proto_tree_add_item(rach_tree, hf_l2server_totalnumberofra_preambles, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // Msg1SubCarrSpacing
                        proto_tree_add_item(rach_tree, hf_l2server_msg1_subcarrier_spacing, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // RestSetConf
                        proto_tree_add_item(rach_tree, hf_l2server_rest_set_conf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // Msg3TranfPrecoding
                        proto_tree_add_item(rach_tree, hf_l2server_msg3_tranform_precoding, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // RsrpThresholdSsb
                        proto_tree_add_item(rach_tree, hf_l2server_rsrp_threshold_ssb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;

                        // TODO: add fields for these!

                        // RsrpThresholdSsbSul
                        proto_tree_add_item(rach_tree, hf_l2server_rsrp_threshold_ssb_sul, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // PrachRootSeqIndexIsValid
                        proto_tree_add_item(rach_tree, hf_l2server_prach_root_seq_index_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // SsbPerRachIsValid
                        proto_tree_add_item(rach_tree, hf_l2server_ssb_per_rach_is_valid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // PrachRootSeqIndex
                        proto_tree_add_item(rach_tree, hf_l2server_prach_root_seq_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                        // SsbPerRach
                        proto_tree_add_item(rach_tree, hf_l2server_ssb_per_rach, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // GroupBconfigure
                        // TODO:
                        offset += 3;
                        // Ra_ContentionResolutionTimer
                        proto_tree_add_item(rach_tree, hf_l2server_ra_contention_resolution_timer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                        // Pad
                        proto_tree_add_item(rach_tree, hf_l2server_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;

                        // RaPrioritizationForAccessIdentity_r16 (bb_nr5g_RA_PRIO_FOR_ACCESS_ID_R16t)
                        if (rach_fieldmask & bb_nr5g_STRUCT_RA_PRIO_FOR_ACCESS_IDENTITY_PRESENT) {
                            offset += sizeof(bb_nr5g_RA_PRIO_FOR_ACCESS_ID_R16t);
                        }
                    }

                    // PuschCfgCommon (nr5g_rlcmac_Cmac_PUSCH_CONF_COMMONt)
                    if (common_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_COMMON_PUSCH_CFG_PRESENT) {
                        // TODO (variable-length)
                        gint pusch_start_offset = offset;

                        // Len
                        guint32 pusch_len = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
                        offset += 4;
                        // Spare
                        // NbPuschTimeDomResAlloc
                        // PuschTimeDomResAlloc

                        offset = pusch_start_offset + pusch_len;
                    }
                }

                // BwpULDed
                if (ul_bwp_fieldmask & nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DEDICATED_CFG_PRESENT) {
                    // TODO:
                }

                proto_item_set_len(ul_bwp_ti, bwp_uplink_len);
                offset += bwp_uplink_len;
            }
            proto_item_set_len(ul_ded_config_ti, ul_len);
        }

        // SulCellCfgDed
        if (fieldmask & nr5g_rlcmac_Cmac_STRUCT_SERV_CELL_CONFIG_SUP_UPLINK_PRESENT) {
            // TODONT
        }

        // CsiMeasCfg
        if (fieldmask & nr5g_rlcmac_Cmac_STRUCT_CSI_MEAS_CFG_PRESENT) {
            // TODO:
        }

        proto_item_set_len(spcell_config_ded_ti, ded_len);
        offset = ded_start_offset + ded_len;
    }

    // MAC_CellGroupConfig (nr5g_rlcmac_Cmac_MAC_CELL_GROUP_CONFIGt)
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
        proto_tree_add_item(mac_cell_group_tree, hf_l2server_lch_basedprioritization_r16, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        offset += 1;
        // Spare[3]
        proto_tree_add_item(mac_cell_group_tree, hf_l2server_spare, tvb, offset, 3, ENC_LITTLE_ENDIAN);
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
    // L1CellDedicatedConfig (bb_nr5g_CELL_DEDICATED_CONFIGt from bb-nr5g_struct.h)
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

        // SetupReconf
        proto_tree_add_item(l1_dedicated_config_tree, hf_l2server_setup_reconf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        // PhyCellCnf (bb_nr5g_PH_CELL_GROUP_CONFIGt from bb-nr5g_struct.h)
        offset = dissect_ph_cell_config(l1_dedicated_config_tree, tvb, pinfo, offset);

        if (ded_present) {
            // SpCellCfgDed. N.B. offset returned here won't be right yet..
            offset = dissect_sp_cell_cfg_ded(l1_dedicated_config_tree, tvb, pinfo, offset);
        }

        if (common_present) {
            // SpCellCfgCommon
            offset = dissect_sp_cell_cfg_common(l1_dedicated_config_tree, tvb, pinfo, offset);
        }

        // SCellCfgAdd
        for (guint32 n=0; n<nbSCellCfgAdd; n++) {
            // TODO: dissect bb_nr5g_SCELL_CONFIGt
            // Type depends upon FieldMask present flags, etc..
        }

        // SCellCfgDel
        for (guint32 n=0; n<nbSCellCfgDel; n++) {
            // TODO: dissect uint32_t
            offset += 4;
        }

        // Skip to pass this.
        offset = dedicated_start + l1cell_dedicated_config_len;
    }
}

// I don't actually see a type for this message!!!!
static void dissect_rlcmac_cmac_config_ack(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset, guint len _U_)
{
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

    // UEId
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    //offset += 4;

    // TODO: another 8 bytes.
}


//  "To Debug Rach Access" - we don't seem to be sending it.
static void dissect_cmac_rach_cfg_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset, guint len _U_)
{
    /* Nr5gId (UEId + CellId + BeamIdx) */
    guint32 ueid, cellid;
    offset = dissect_nr5gid(tree, tvb, pinfo, offset, &ueid, &cellid);

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
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

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
    // Add config filter
    proto_item *config_ti = proto_tree_add_item(tree, hf_l2server_config, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(config_ti);

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

/* nr5g_l2_Srv_CELL_PPU_LIST_ACKt */
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
    guint32 num_nr_pro_pdu;
    proto_tree_add_item_ret_uint(tree, hf_l2server_numnrpropdu, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_nr_pro_pdu);
    offset += 1;
    // CellIdNrList[].
    for (guint32 n=0; n < num_lte_pro_pdu; n++) {
        proto_tree_add_item(tree, hf_l2server_cellidlteitem, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    // CellIdNrList[].
    for (guint32 n=0; n < num_nr_pro_pdu; n++) {
        proto_tree_add_item(tree, hf_l2server_cellidnritem, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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

    // Verbosity
    offset += 4;
    // L2_nr5g_RlcMac_Verbosity
    proto_tree_add_item(tree, hf_l2server_rlcmac_verbosity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // L2_nr5g_pdcp_Verbosity
    offset += 4;

    // BeamChangeTimer
    offset += 2;
    // FieldTestMode
    offset += 1;

    // DlHarqMode
    proto_tree_add_item(tree, hf_l2server_dl_harq_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // MeasMode
    offset += 1;
    // UlFsAdvance
    proto_tree_add_item(tree, hf_l2server_ul_fs_advance, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // DeltaNumLdpcIteration
    offset += 1;
    // DlSoftCombining
    offset += 1;
    // MaxRach
    proto_tree_add_item(tree, hf_l2server_max_rach, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // SpareC
    offset += 3;
    // Spare
    offset += (19*4);

    // NumUpStkPpu
    guint numUpStkPpu;
    proto_tree_add_item_ret_uint(tree, hf_l2server_num_up_stk_ppu, tvb, offset, 1, ENC_LITTLE_ENDIAN, &numUpStkPpu);
    offset += 1;
    // NumDwnStkPpu
    guint numDwnStkPpu;
    proto_tree_add_item_ret_uint(tree, hf_l2server_num_dwn_stk_ppu, tvb, offset, 1, ENC_LITTLE_ENDIAN, &numDwnStkPpu);
    offset += 1;
    // NumLteProPpu
    offset += 1;
    // NumNrProPpu
    guint numNrProPpu;
    proto_tree_add_item_ret_uint(tree, hf_l2server_num_nr_pro_ppu, tvb, offset, 1, ENC_LITTLE_ENDIAN, &numNrProPpu);
    offset += 1;

    // NumLteCell
    offset += 1;
    // NumNrCell
    guint32 numNrCell;
    proto_tree_add_item_ret_uint(tree, hf_l2server_num_nr_cell, tvb, offset, 1, ENC_LITTLE_ENDIAN, &numNrCell);
    offset += 1;

    //--------------------------------------------
    // Variable-sized array items.

    // numUpStkPpu
    for (guint n=0; n < numUpStkPpu; n++) {
        proto_tree_add_item(tree, hf_l2server_up_stk_ppu, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // numDwnStkPpu
    for (guint n=0; n < numDwnStkPpu; n++) {
        proto_tree_add_item(tree, hf_l2server_dwn_stk_ppu, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    // NumNrProPpu
    for (guint n=0; n < numNrProPpu; n++) {
        proto_tree_add_item(tree, hf_l2server_nr_pro_ppu, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }


    // NrCellIdList
    for (guint n=0; n < numNrCell; n++) {
        proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
}



static void dissect_rlcmac_error_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
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


static void dissect_cmac_cell_status_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                         guint offset, guint len _U_)
{
    /* Spare */
    proto_tree_add_item(tree, hf_l2server_spare4, tvb, offset, 4, ENC_NA);
    offset += 4;

    /* cellid */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Cell Status. */
    guint32 status;
    proto_tree_add_item_ret_uint(tree, hf_l2server_cmac_cell_status, tvb, offset, 1, ENC_LITTLE_ENDIAN, &status);
    offset += 1;

    col_set_str(pinfo->cinfo, COL_INFO, "CMAC Cell Status Ind - ");
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(status, cmac_cell_status_vals, "Unknown"));
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
static void dissect_sib_filter_act_act_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset, guint len _U_)
{
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* SibFilterFlag */
    proto_tree_add_item(tree, hf_l2server_sibfilterflag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
}

static void dissect_sib_filter_act_act_nak(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                           guint offset, guint len _U_)
{
    /* CellId */
    proto_tree_add_item(tree, hf_l2server_cellid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* TODO: Err */
    offset += 2;
}

/* nr5g_l2_Srv_REEST_PREPAREt from nr5g-l2_Srv.h */
static void dissect_reest_prepare_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Num PdcpAction_t (to up 32) */
    guint32 num_pdcp_actions;
    proto_tree_add_item_ret_uint(tree, hf_l2server_num_pdcp_actions, tvb, offset, 4, ENC_LITTLE_ENDIAN, &num_pdcp_actions);
    offset += 4;

    for (guint n=0; n < num_pdcp_actions; n++) {
        // Entry is of type nr5g_pdcp_Com_Action_t

        // RbType
        offset += 1;
        // Rbid
        offset += 1;
        // Action
        offset += 1;

        //offset += sizeof(nr5g_pdcp_Com_Action_t);
    }
}

static void dissect_rrc_state_cfg_cmd(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_,
                                      guint offset, guint len _U_)
{
    /* UEId */
    proto_tree_add_item(tree, hf_l2server_ueid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* State */
    proto_tree_add_item(tree, hf_l2server_rrc_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}


/************************************************************************************/

/* SRV Error */
static TYPE_FUN srv_error_type_funs[] =
{
        { 0x0402,                            "UNKNOWN_ERROR_IND",               dissect_sapi_type_dummy },
        { 0x00,                               NULL,                             NULL }
};

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

        // N.B. we send fix bytes ("buffer from log shared by Rocco")
        { lte_l2_Srv_GETINFO_CMD,            "lte_l2_Srv_GETINFO_CMD",       dissect_sapi_type_dummy },
        { lte_l2_Srv_GETINFO_ACK,            "lte_l2_Srv_GETINFO_ACK",       dissect_sapi_type_dummy },
        { lte_l2_Srv_GETINFO_NAK,            "lte_l2_Srv_GETINFO_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_CELL_CONFIG_CMD,       "nr5g_l2_Srv_CELL_CONFIG_CMD",       dissect_cell_config_cmd },
        { nr5g_l2_Srv_CELL_CONFIG_ACK,       "nr5g_l2_Srv_CELL_CONFIG_ACK",       dissect_cell_config_ack },
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
        { nr5g_l2_Srv_CREATE_UE_NAK,            "nr5g_l2_Srv_CREATE_UE_NAK",       dissect_create_ue_nak },

        { lte_l2_Srv_DELETE_UE_CMD,            "nr5g_l2_Srv_DELETE_UE_CMD",       dissect_delete_ue_cmd },
        { lte_l2_Srv_DELETE_UE_ACK,            "nr5g_l2_Srv_DELETE_UE_ACK",       dissect_delete_ue_ack },
        { lte_l2_Srv_DELETE_UE_NAK,            "nr5g_l2_Srv_DELETE_UE_NAK",       dissect_delete_ue_nak },

        { nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD,     "nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD",       dissect_rcp_ue_set_group_cmd },
        { nr5g_l2_Srv_RCP_UE_SET_GROUP_ACK,     "nr5g_l2_Srv_RCP_UE_SET_GROUP_ACK",       dissect_rcp_ue_set_group_ack },
        { nr5g_l2_Srv_RCP_UE_SET_GROUP_NAK,     "nr5g_l2_Srv_RCP_UE_SET_GROUP_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD,     "nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD",       dissect_rcp_set_ue_index_cmd },
        { nr5g_l2_Srv_RCP_UE_SET_INDEX_ACK,     "nr5g_l2_Srv_RCP_UE_SET_INDEX_ACK",       dissect_rcp_set_ue_index_ack },
        { nr5g_l2_Srv_RCP_UE_SET_INDEX_NAK,     "nr5g_l2_Srv_RCP_UE_SET_INDEX_NAK",       dissect_sapi_type_dummy },

        { nr5g_l2_Srv_REEST_PREPARE_CMD,        "nr5g_l2_Srv_REEST_PREPARE_CMD",          dissect_reest_prepare_cmd },
        { nr5g_l2_Srv_REEST_PREPARE_ACK,        "nr5g_l2_Srv_REEST_PREPARE_ACL",          dissect_sapi_type_dummy },

        { nr5g_l2_Srv_HANDOVER_CMD,     "nr5g_l2_Srv_HANDOVER_CMD",       dissect_handover_cmd },
        /* TODO: what types are these? */
        { nr5g_l2_Srv_HANDOVER_ACK,     "nr5g_l2_Srv_HANDOVER_ACK",       dissect_handover_ack },
        { nr5g_l2_Srv_HANDOVER_NAK,     "nr5g_l2_Srv_HANDOVER_NAK",       dissect_handover_ack },


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
    // TODO: these Type values are probably not right...
    { nr5g_rlcmac_Cmac_STAT_UE_HI_IND,    "lte_l2_Sap_NR_RLCMAC_ERROR",     dissect_sapi_type_dummy},
    { nr5g_rlcmac_Cmac_STAT_UE_LO_IND,    "lte_l2_Sap_NR_RLCMAC_ERROR",     dissect_rlcmac_error_ind},
    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_ERROR_TYPE_VALS      array_length(nr_rlcmac_error_type_funs)
static value_string  nr_rlcmac_error_type_vals[MAX_NR_RLCMAC_ERROR_TYPE_VALS];






/* NR RLCMAC CMAC */
static TYPE_FUN nr_rlcmac_cmac_type_funs[] =
{
    { nr5g_rlcmac_Cmac_DBEAM_IND,    "nr5g_rlcmac_Cmac_DBEAM_IND",       dissect_dbeam_ind },

    { nr5g_rlcmac_Cmac_CONFIG_CMD,     "nr5g_rlcmac_Cmac_CONFIG_CMD",       dissect_rlcmac_cmac_config_cmd },
    { nr5g_rlcmac_Cmac_CONFIG_ACK,     "nr5g_rlcmac_Cmac_CONFIG_ACK",       dissect_rlcmac_cmac_config_ack },
    { nr5g_rlcmac_Cmac_CONFIG_NAK,     "nr5g_rlcmac_Cmac_CONFIG_NAK",       dissect_rlcmac_cmac_config_ack },
    { nr5g_rlcmac_Cmac_SEG_CONFIG_REQ, "nr5g_rlcmac_Cmac_SEG_CONFIG_REQ",       dissect_sapi_type_dummy /* TODO */},

    { nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD, "nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD",       dissect_rrc_state_cfg_cmd },
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
    { nr5g_rlcmac_Cmac_CELL_STATUS_IND, "nr5g_rlcmac_Cmac_CELL_STATUS_IND",       dissect_cmac_cell_status_ind },
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
    { nr5g_rlcmac_Crlc_CONFIG_NAK,         "nr5g_rlcmac_Crlc_CONFIG_NAK",       dissect_crlc_config_ack },

    { 0x00,                               NULL,                             NULL }
};
#define MAX_NR_RLCMAC_CRLC_TYPE_VALS      array_length(nr_rlcmac_crlc_type_funs)
static value_string  nr_rlcmac_crlc_type_vals[MAX_NR_RLCMAC_CRLC_TYPE_VALS];


/* LTE PDCP CTRL */
static TYPE_FUN lte_pdcp_ctrl_type_funs[] =
{
    { nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD,           "nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD",       dissect_sib_filter_act_act_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK,           "nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK",       dissect_sib_filter_act_act_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK,           "nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK",       dissect_sib_filter_act_act_nak },
    { nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD,         "nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD",     dissect_sib_filter_act_act_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK,         "nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK",     dissect_sib_filter_act_act_cmd },
    { nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK,         "nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK",     dissect_sib_filter_act_act_nak },

    { 0x00,                               NULL,                             NULL }
};
#define MAX_LTE_PDCP_CTRL_TYPE_VALS      array_length(lte_pdcp_ctrl_type_funs)
static value_string  lte_pdcp_ctrl_type_vals[MAX_LTE_PDCP_CTRL_TYPE_VALS];




static SAPI_FUN sapi_fun_vals[] = {
    /* Server */
    { lte_l2_Sap_SRV_ERROR,         "SRV ERROR", srv_error_type_funs },
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

    /* Create a data source just for L2 payload.  This makes it easier to spot offsets inside message */
    /* TODO: there must be a more elegant way to do this? */
    tvbuff_t *l2_tvb = tvb_new_child_real_data(tvb, tvb_get_ptr(tvb, 0, tvb_reported_length(tvb)),
                                               tvb_reported_length(tvb), tvb_reported_length(tvb));
    add_new_data_source(pinfo, l2_tvb, "L2 Message");

    /* Protocol column */
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_INFO);

    /* Add divider if not first PDU in this frame */
    gboolean *already_set = (gboolean*)p_get_proto_data(wmem_file_scope(), pinfo, proto_l2server, 0);
    if (already_set && *already_set) {
         col_append_str(pinfo->cinfo, COL_PROTOCOL, "|");
         col_append_str(pinfo->cinfo, COL_INFO, "  ||  ");
    }

    col_append_str(pinfo->cinfo, COL_PROTOCOL, "L2Server");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_l2server, l2_tvb, offset, -1, ENC_NA);
    l2server_tree = proto_item_add_subtree(root_ti, ett_l2server);

    /* Header subtree */
    proto_item *header_ti = proto_tree_add_string_format(l2server_tree, hf_l2server_header, l2_tvb, offset, 8, "", "Header  ");
    proto_tree *header_tree = proto_item_add_subtree(header_ti, ett_l2server_header);

    /* SAPI */
    guint32 sapi;
    proto_item *sapi_ti = proto_tree_add_item_ret_uint(header_tree, hf_l2server_sapi, l2_tvb, offset, 2, ENC_LITTLE_ENDIAN, &sapi);
    offset += 2;
    /* Type */
    guint32 type;
    proto_item *type_ti = proto_tree_add_item_ret_uint(header_tree, hf_l2server_type, l2_tvb, offset, 2, ENC_LITTLE_ENDIAN, &type);
    offset += 2;
    /* Len */
    guint32 len;
    proto_tree_add_item_ret_uint(header_tree, hf_l2server_len, l2_tvb, offset, 4, ENC_LITTLE_ENDIAN, &len);
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
        return tvb_captured_length(l2_tvb);
    }
    else {
        /* Lookup dissector function from type (for this SAPI) */
        type2fun = get_type_fun(type, sapi2fun->sapi_funs);
        if (type2fun == NULL) {
            expert_add_info_format(pinfo, type_ti, &ei_l2server_sapi_unknown,
                                   "L2Server Type (%u) not recognised for SAPI %u", type, sapi);
            return tvb_captured_length(l2_tvb);
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
                (*type2fun->prim_fun)(l2server_tree, l2_tvb, pinfo, 8, len);
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

      { &hf_l2server_nr5gid,
        { "Nr5gId", "l2server.nr5gid", FT_STRING, BASE_NONE,
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
        { "BRSRP", "l2server.brsrp", FT_UINT32, BASE_HEX,
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
        { "NoData", "l2server.no-data", FT_BOOLEAN, 1,
          TFS(&nodata_data_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_msg3_data,
        { "NoData", "l2server.msg3-data", FT_STRING, BASE_NONE,
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
          VALS(scg_type_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_drb_continue_rohc,
        { "drb-ContinueROHC", "l2server.drb-continue-rohc", FT_BOOLEAN, 1,
          TFS(&continue_rohc_vls), 0x0, NULL, HFILL }},
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
        { "RSRP ThresholdSSB", "l2server.rsrp-threshold-ssb", FT_INT32, BASE_DEC,
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
      { &hf_l2server_ra_ssb_occasion_mask_index,
         { "RA SSB Occasion Mask Index", "l2server.ra-ssb-occasion-mask-index", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_preamble_tx_max,
         { "Preamble Tx Max", "l2server.preamble-tx-max", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_totalnumberofra_preambles,
        { "totalNumberOfRA-Preambles", "l2server.totalnumberofra-preambles", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ssb_perrach_occasion,
        { "ssb perRACH Occasion", "l2server.ssb-perrach-occasion", FT_INT8, BASE_DEC,
          VALS(ssb_perrach_occasion_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_cb_preamblesperssb,
        { "CB PreamblesPerSSB", "l2server.cb-preambles-per-ssb", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_msg3sizegroupa,
        { "Msg3 Size Group A", "l2server.msg3-size-groupa", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_numberofra_preamblesgroupa,
        { "NumberofRA Preambles GroupA", "l2server.numberofra-preambles-groupa", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_delta_preamble_msg3,
        { "Delta Preamble Msg3", "l2server.delta-preamble-msg3", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_message_power_offset_groupb,
        { "Message Power Offset GroupB", "l2server.message-power-offset-groupb", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_responsewindow,
        { "RA ResponseWindow", "l2server.ra-response-window", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ra_contentionresolutiontimer,
        { "RA ContentionResolutionTimer", "l2server.ra-contention-resolution-timer", FT_INT32, BASE_DEC,
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

      { &hf_l2server_config,
        { "Config", "l2server.config", FT_NONE, BASE_NONE,
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
      { &hf_l2server_spare,
        { "Spare", "l2server.spare", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pad,
        { "Pad", "l2server.pad", FT_BYTES, BASE_NONE,
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
      { &hf_l2server_cellidnritem,
        { "CellIdNrItem", "l2server.cellidnritem", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nb_scell_cfg_add,
        { "NbSCellCfgAdd", "l2server.number-scell-cfg-add", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_scell_cfg_del,
        { "NbSCellCfgDel", "l2server.number-scell-cfg-del", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ph_cell_config,
        { "PH Cell Config", "l2server.ph-cell-config", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ph_cell_dcp_config_present,
        { "DCP Config Present", "l2server.field-mask.dcp-config-present", FT_BOOLEAN, 8,
          NULL, bb_nr5g_STRUCT_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16_PRESENT, NULL, HFILL }},
      { &hf_l2server_ph_pdcch_blind_detection_present,
        { "PDCCH Blind Detection Present", "l2server.field-mask.pdcch-blind-detection-present", FT_BOOLEAN, 8,
          NULL, bb_nr5g_STRUCT_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16_PRESENT, NULL, HFILL }},
      { &hf_l2server_harq_ack_spatial_bundling_pucch,
        { "HARQ ACK Spacial Bundling PUCCH", "l2server.harq-ack-spatial-bundling-pucch", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_harq_ack_spatial_bundling_pusch,
        { "HARQ ACK Spacial Bundling PUSCH", "l2server.harq-ack-spatial-bundling-pusch", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pmax_nr,
        { "pMax NR", "l2server.pmax-nr", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pdsch_harq_ack_codebook,
        { "PDSCH HARQ ACK Codebook", "l2server.pdsch-harq-ack-codebook", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_mcs_crnti_valid,
        { "MCS CRNTI Valid", "l2server.mcs-crnti-valid", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_mcs_crnti,
        { "MCS CRNTI", "l2server.mcs-crnti", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pue_fr1,
        { "PUE FR1", "l2server.pue-fr1", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_tpc_srs_rnti,
        { "TPC SRS RNTI", "l2server.tpc-srs-rnti", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_tpc_pucch_rnti,
        { "TPC PUCCH RNTI", "l2server.tpc-pucch-rnti", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_tpc_pusch_rnti,
        { "TPC PUSCH RNTI", "l2server.tpc-pusch-rnti", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_sp_csi_rnti,
        { "SP CSI RNTI", "l2server.sp-csi-rnti", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_cs_rnti,
        { "CS RNTI", "l2server.cs-rnti", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pdcch_blind_detection,
        { "PDCCH Blind Detection", "l2server.pdcch-blind-detection", FT_INT8, BASE_DEC,
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
        { "BwpInactivityTimer", "l2server.bwp-inactivity-timer", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_tag_id,
        { "TagId", "l2server.tag-id", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_scell_deact_timer,
        { "SCell Deact Timer", "l2server.scell-deact-timer", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pathloss_ref_linking,
        { "Pathloss Ref Linking", "l2server.pathloss-ref-linking", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_serv_cell_mo,
        { "Serv Cell MO", "l2server.serv-cell-mo", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_default_dl_bwpid,
        { "Default DL Bwpid", "l2server.default-dl-bwpid", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_supp_ul_rel,
        { "Supp UL Rel", "l2server.supp-ul-rel", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ca_slot_offset_is_valid,
        { "CA Slot Offset Is Valid", "l2server.ca-slot-offset-is-valid", FT_INT8, BASE_DEC,
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
        { "CsiRsValidWithDCI-r16", "l2server.csi-rs-valid-with-dci-r16", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_crs_rate_match_per_coreset_poolidx_r16,
        { "CrsRateMatchPerCORESETPoolIdx-r16", "l2server.crs-rate-match-per-coreset-poolidx-r16", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_first_active_ul_bwp_pcell,
        { "First Active UL BWP pCell", "l2server.first-active-ul-bwp-pcell", FT_INT8, BASE_DEC,
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
        { "Priority", "l2server.priority", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_prioritized_bit_rate,
        { "Prioritized bit rate", "l2server.prioritized-bit-rate", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_bucket_size_duration,
        { "Bucket Size Duration", "l2server.bucket-size-duration", FT_INT32, BASE_DEC,
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
        { "Scheduling Request ID", "l2server.scheduling-request-id", FT_INT32, BASE_DEC,
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

      { &hf_l2server_cmac_cell_status,
        { "CMAC Cell Status", "l2server.cmac-cell-status", FT_UINT8, BASE_DEC,
          VALS(cmac_cell_status_vals), 0x0, NULL, HFILL }},


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
          VALS(sib_folder_flag_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_num_pdcp_actions,
        { "Number of PDCP Actions", "l2server.num-pdcp-actions", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ta,
        { "TA", "l2server.ta", FT_INT8, BASE_DEC,
          NULL, 0x0, "Timing Advance (-1 for none)", HFILL }},
      { &hf_l2server_ra_info_valid,
        { "RA Info Valid", "l2server.ra-info-valid", FT_BOOLEAN, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rach_probe_req,
        { "RACH Probe Req", "l2server.rach-probe-req", FT_BOOLEAN, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rrc_state,
        { "State", "l2server.rrc-state", FT_UINT8, BASE_DEC,
          VALS(rrc_state_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_cell_config_cellcfg,
        { "CellCfg", "l2server.cell-config.cellcfg", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_aggr_cell_cfg_common,
        { "NbAggrCellCfgCommon", "l2server.number-of-nb-aggr-cell-cfg-common", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_dlfreq_0,
        { "DL Freq[0]", "l2server.dl-freq-0", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_dlfreq_1,
        { "DL Freq[1]", "l2server.dl-freq-1", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_dl_earfcn_0,
        { "DL Earfcn[0]", "l2server.dl-earfcn-0", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_dl_earfcn_1,
        { "DL Earfcn[1]", "l2server.dl-earfcn-1", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ulfreq_0,
        { "UL Freq[0]", "l2server.ul-freq-0", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ulfreq_1,
        { "UL Freq[1]", "l2server.ul-freq-1", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_earfcn_0,
        { "UL Earfcn[0]", "l2server.ul-earfcn-0", FT_INT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_earfcn_1,
        { "UL Earfcn[1]", "l2server.ul-earfcn-1", FT_INT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ssb_arfcn,
        { "SSB Arfcn", "l2server.ssb-arfcn", FT_INT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_num_dbeam,
        { "Num Dbeam", "l2server.num-dbeam", FT_INT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_cell_cfg_ded,
        { "UL Cell Cfg Dedicated", "l2server.ul-cell-cfg-ded", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_cell_cfg_ded_len,
        { "Len", "l2server.ul-cell-cfg-ded.len", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_first_active_ul_bwp,
        { "First active UL BWP", "l2server.first-active-ul-bwp", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_num_ul_bwpid_to_add,
        { "Number of UL BWPIds to add", "l2server.num-ul-bwpids-to-add", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_initial_ul_bwp,
        { "Initial Ul BWP", "l2server.initial-ul-bwp", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_initial_ul_bwp_len,
        { "Len", "l2server.initial-ul-bwp.len", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_bwp,
        { "UL BWP", "l2server.ul-bwp", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_len,
        { "Len", "l2server.ul-bwp.len", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_bwp_common,
        { "UL BWP Common", "l2server.ul-bwp-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_bwp_common_pdcch,
        { "UL BWP Common PDCCH", "l2server.ul-bwp-common-pdcch", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_bwp_common_search_space_sib1,
        { "Search Space SIB1", "l2server.search-space-sib1", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_search_space_sib,
        { "Search Space SIB", "l2server.search-space-sib", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_pag_search_space,
        { "Page Search Space", "l2server.pag-search-space", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_ra_search_space,
        { "RA Search Space", "l2server.ra-search-space", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_ra_ctrl_res_set,
        { "RA Ctrl Res Set", "l2server.ra-ctrl-res-set", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_nb_common_ctrl_res_sets,
        { "Nb Common Ctrl Res Sets", "l2server.nb-common-ctrl-res-set", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_nb_common_search_spaces,
        { "Nb Common Search Spaces", "l2server.nb-common-search-spaces", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_control_resource_set_zero,
        { "Control Resource Set Zero", "l2server.control-resource-set-zero", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_search_space_zero,
        { "Search space zero", "l2server.search-space-zero", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_first_pdcch_moni_occ_of_po_valid,
        { "First PDCCH Monitor Occ of Po Valid", "l2server.first-pdcch-monit-of-po-valid", FT_UINT8, BASE_DEC,
           VALS(pdcch_moni_occ_of_po_valid_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_nb_first_pdcch_monit_occ_of_po,
        { "Nb First PDCCH Monitor Occ of Po", "l2server.nb-first-pdcch-monit-of-po", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_bwp_common_nb_common_search_spaces_ext,
        { "Nb Common Search Spaces Ext", "l2server.nb-common-search-spaces-ext", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_bwp_common_first_pdcch_moni_occ_of_po,
        { "First PDCCH Moni Occ of Po", "l2server.first-pdcch-moni-occ-of-po", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_bwp_common_pdsch,
        { "UL BWP Common PDSCH", "l2server.ul-bwp-common-pdsch", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rach_common,
        { "RACH Common", "l2server.rach-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_rach_generic,
        { "RACH Generic", "l2server.rach-generic", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_msg1_fdm,
        { "Msg1 FDM", "l2server.msg1-fdm", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_msg1_frequency_start,
        { "Msg1 Frequency Start", "l2server.msg1-frequency-start", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_zero_corr_zone,
        { "Zero Corr Zone", "l2server.zero-corr-zone", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_preamble_rec_target_pwr,
        { "Preamble Rec Target Pwr", "l2server.preamble-rec-target-pwr", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_msg1_subcarrier_spacing,
        { "Msg1 Subcarrier Spacing", "l2server.msg-subcarrier-spacing", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rest_set_conf,
        { "Rest Set Conf", "l2server.rest-set-conf", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_msg3_tranform_precoding,
        { "Msg3 Transform Precoding", "l2server.msg-transform-precoding", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rsrp_threshold_ssb,
        { "RSRP Threshold SSB", "l2server.rsrp-threshold-ssb", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_rsrp_threshold_ssb_sul,
        { "RSRP Threshold SSB SUL", "l2server.rsrp-threshold-ssb-sul", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_prach_root_seq_index_is_valid,
        { "PRACHSeqRootIndexIsValid", "l2server.prach-root-seq-index-is-valid", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ssb_per_rach_is_valid,
        { "SSBPerRACH", "l2server.ssb-per-rach", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_prach_root_seq_index,
        { "PRACHSeqRootIndex", "l2server.prach-root-seq-index", FT_INT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ssb_per_rach,
        { "SSBPerRACH", "l2server.ssb-per-rach", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      // TODO: hf_l2server_group_b_configured
      { &hf_l2server_ra_contention_resolution_timer,
        { "RA-ContentionResolutionTimer", "l2server.ca-contention-resolution-timer", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_freq_info_dl,
        { "Freq Info DL", "l2server.freq-info-dl", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_abs_freq_ssb,
        { "Abs Freq SSB", "l2server.abs-freq-ssb", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_abs_freq_point_a,
        { "Abs Freq Point A", "l2server.abs-freq-point-a", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ssb_subcarrier_offset,
        { "SSB Subcarrier Offset", "l2server.ssb-subcarrier-offset", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_freq_band_list,
        { "Nb Freq Band List", "l2server.nb-freq-band-list", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_scs_spec_carrier,
        { "Nb SCS Spec Carrier", "l2server.nb-scs-spec-carrier", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_freq_band_list,
        { "Freq Band List", "l2server.freq-band-list", FT_INT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ssb_periodicity_serv_cell,
        { "SSB Periodicity Serv Cell", "l2server.ssb-periodicity-serv-cell", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_dmrs_type_a_pos,
        { "DMRS TypeA Pos", "l2server.dmrs-typea-pos", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_sub_car_spacing,
        { "Sub Car Spacing", "l2server.sub-car-spacing", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ssb_pos_in_burst_is_valid,
        { "SSB Pos In Burst is valid", "l2server.ssb-pos-in-burst-is-valid", FT_INT8, BASE_DEC,
           VALS(ssb_pos_in_burst_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_n_timing_advance_offset,
        { "N Timing Advance Offset", "l2server.n-timing-advance-offset", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ssb_pos_in_burst_short,
        { "SSB Pos in burst (Short)", "l2server.ssb-pos-in-burst-short", FT_UINT8, BASE_HEX,
           NULL, 0x0f, NULL, HFILL }},
      { &hf_l2server_ssb_pos_in_burst_medium,
        { "SSB Pos in burst (Medium)", "l2server.ssb-pos-in-burst-medium", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ssb_pos_in_burst_long,
        { "SSB Pos in burst (Long)", "l2server.ssb-pos-in-burst-long", FT_UINT64, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_pbch_block_power,
        { "PBCH Block Power", "l2server.pbch-block-power", FT_INT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nb_rate_match_pattern_to_add_mod,
        { "Nb Rate Match Pattern To Add/Mod", "l2server.nb-rate-match-pattern-to-add-mod", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_rate_match_pattern_to_del,
        { "Nb Rate Match Pattern To Del", "l2server.nb-rate-match-pattern-to-del", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_bwp_dl_common,
        { "BWP DL Common", "l2server.bwp-dl-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_freq_info_ul_common,
        { "FreqInfo UL Common", "l2server.freqinfo-ul-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_bwp_ul_common,
        { "BWP UL Common", "l2server.bwp-ul-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_freq_info_sul_common,
        { "FreqInfo SUL Common", "l2server.freqinfo-sul-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_bwp_sul_common,
        { "BWP SUL Common", "l2server.bwp-sul-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_tdd_common,
        { "TDD Common", "l2server.tdd-common", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_beamid,
        { "BeamId", "l2server.beamid", FT_INT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},



      { &hf_l2server_rlcmac_verbosity,
        { "RLCMAC Verbosity", "l2server.rlcmac-verbosity", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_dl_harq_mode,
        { "DL HARQ Mode", "l2server.dl-harq-mode", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_fs_advance,
        { "UL FS Advance", "l2server.ul-fs-advance", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_max_rach,
        { "Max RACH", "l2server.max-rach", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_num_nr_cell,
        { "Num Nr Cells", "l2server.num-nr-cells", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_num_up_stk_ppu,
        { "Num Up Stk PPUs", "l2server.num-up-stk-ppu", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_num_dwn_stk_ppu,
        { "Num Dwn Stk PPUs", "l2server.num-dwn-stk-ppu", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_num_nr_pro_ppu,
        { "Num Nr Pro PPUs", "l2server.num-nr-pro-ppu", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_up_stk_ppu,
        { "Up Stk PPU", "l2server.up-stk-ppu", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_dwn_stk_ppu,
        { "Dwn Stk PPU", "l2server.dwn-stk-ppu", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nr_pro_ppu,
        { "NR Pro PPU", "l2server.nr-pro-ppu", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_setup_reconf,
        { "Setup/Reconf", "l2server.setup-reconf", FT_UINT8, BASE_DEC,
           VALS(setup_reconf_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_mac_config,
        { "MAC Config", "l2server.mac-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_lch_basedprioritization_r16,
        { "LCH-based Prioritization R16", "l2server.lch-based-prioritization-r16", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_first_active_dl_bwp,
        { "First active DL BWP", "l2server.first-active-dl-bwp", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_dl_bwp_scs_spec_carrier,
        { "Nb DL BWP Scs Spec Carriers", "l2server.nb-bwp-scs-spec-carrier", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_dl_bwp_id_to_del,
        { "DL BwpId to Delete", "l2server.dl-bwpid-to-del", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},


      { &hf_l2server_initial_dl_bwp_present,
        { "Initial DL BWP Present", "l2server.initial-dl-bwp-present", FT_BOOLEAN, 32,
           NULL, bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_INITIAL_DL_BWP_PRESENT, NULL, HFILL }},
      { &hf_l2server_pdsch_present,
        { "PDSCH Present", "l2server.pdsch-present", FT_BOOLEAN, 32,
           NULL, bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDSCH_PRESENT, NULL, HFILL }},
      { &hf_l2server_pdcch_present,
        { "PDCCH Present", "l2server.pdcch-present", FT_BOOLEAN, 32,
           NULL, bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDCCH_PRESENT, NULL, HFILL }},
      { &hf_l2server_csi_meas_config_present,
        { "CSI Meas Config Present", "l2server.csi-meas-config-present", FT_BOOLEAN, 32,
           NULL, bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_CSI_MEAS_CFG_PRESENT, NULL, HFILL }},

      { &hf_l2server_bwp_dl_dedicated,
        { "BWP DL Dedicated", "l2server.bwp-dl-dedicated", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nb_sps_conf_to_add_r16,
        { "Nb SPS Conf to add (r16)", "l2server.nb-sps-conf-to-add-r16", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_config_deactivation_state_r16,
        { "Nb Config Deactivation State r16", "l2server.nb-config-deactivation-state-r16", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_pdsch_serving_cell,
        { "PDSCH ServingCell", "l2server.pdsch-serving-cell", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_xoverhead,
        { "XOverhead", "l2server.xoverhead", FT_UINT8, BASE_DEC,
           VALS(xoverhead_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_nb_harq_processes_for_pdsch,
        { "Nb HARQ Processes for PDSCH", "l2server.nb-harq-processes-for-pdsch", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nb_code_block_group_transmission_r16,
        { "Nb code block group transmission r16", "l2server.nb-code-block-group-transmission-r16", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},


      { &hf_l2server_pdcch_serving_cell,
        { "PDCCH ServingCell", "l2server.pdcch-serving-cell", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_csi_meas_config,
        { "CSI Meas Config", "l2server.csi-meas-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nb_nzp_csi_rs_res_to_add,
        { "Nb NZP CSI RS Res To Add", "l2server.nb-nzp-csi-rs-res-to-add", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_nzp_csi_rs_res_to_del,
        { "Nb NZP CSI RS Res To Del", "l2server.nb-nzp-csi-rs-res-to-del", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_nzp_csi_rs_res_set_to_add,
        { "Nb NZP CSI RS Res Set To Add", "l2server.nb-nzp-rs-csi-rs-res-set-to-add", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_nzp_csi_rs_res_set_to_del,
        { "Nb NZP CSI RS Res Set To Del", "l2server.nb-nzp-rs-csi-rs-res-set-to-del", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_im_res_to_add,
        { "Nb CSI Im Res To Add", "l2server.nb-csi-im-res-to-add", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_im_res_to_del,
        { "Nb CSI Im Res To Del", "l2server.nb-csi-im-res-to-del", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_im_res_set_to_add,
        { "Nb CSI Im Res Set To Add", "l2server.nb-csi-im-res-set-to-add", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_im_res_set_to_del,
        { "Nb CSI Im Res Set To Del", "l2server.nb-csi-im-res-set-to-del", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_ssb_res_set_to_add,
        { "Nb CSI SSB Res Set To Add", "l2server.nb-csi-ssb-res-set-to-add", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_ssb_res_set_to_del,
        { "Nb CSI SSB Res Set To Del", "l2server.nb-csi-ssb-res-set-to-del", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_res_cfg_to_add,
        { "Nb CSI Res Cfg To Add", "l2server.nb-csi-res-cfg-to-add", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_res_cfg_to_del,
        { "Nb CSI Res Cfg To Del", "l2server.nb-csi-res-cfg-to-del", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_rep_cfg_to_add,
        { "Nb CSI Rep Cfg To Add", "l2server.nb-csi-rep-cfg-to-add", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_csi_rep_cfg_to_del,
        { "Nb CSI Rep Cfg To Del", "l2server.nb-csi-rep-cfg-to-del", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_aper_trigger_state_list,
        { "Nb Aper Trigger State List", "l2server.nb-aper-trigger-state-list", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_sp_on_pusch_trigger_state,
        { "Nb SP On PUSCH Trigger State", "l2server.nb-sp-on-pusch-trigger-state", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_report_trigger_size,
        { "Report Trigger Size", "l2server.report-trigger-size", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_report_trigger_size_dci02_r16,
        { "Report Trigger Size DCI02-r16", "l2server.report-trigger-size-dci02-r16", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nzp_csi_rs_res_config,
        { "NZP CSO RS Res Config", "l2server.nzp-csi-rs-res-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_resource_id,
        { "Resource Id", "l2server.resource-id", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_power_control_offset,
        { "Power Control Offset", "l2server.power-control-offset", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_power_control_offset_ss,
        { "Power Control Offset SS", "l2server.power-control-offset-SS", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_qcl_info_periodic_csi_rs,
        { "QCL Info Periodic CSI RS", "l2server.qcl-info-periodic-csi-rs", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_scramblingid,
        { "ScramblingId", "l2server.scrambling-id", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nzp_csi_rs_res_set_config,
        { "NZP CSO RS Res Set Config", "l2server.nzp-csi-rs-res-set-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_resource_set_id,
        { "Resource Set Id", "l2server.resource-set-id", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_repetition,
        { "Repetition", "l2server.repetition", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_aper_trigger_offset,
        { "Aper Trigger Offset", "l2server.aper-trigger-offset", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_trs_info,
        { "TRS Info", "l2server.trs-info", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_aper_trigger_offset_r16,
        { "Aper Trigger Offset r16", "l2server.aper-trigger-offset-r16", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nb_nzp_csi_rs_res_lis,
        { "Nb NZP CSI RS Res Lis", "l2server.nb-nzp-csi-rs-res-lis", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nzp_csi_rs_res_list,
        { "Nb NZP CSI RS Res List", "l2server.nb-nzp-csi-rs-res-list", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_csi_im_res_config,
        { "CSI IM Res Config", "l2server.csi-im-res-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_csi_im_res_set_config,
        { "CSI IM Res Set Config", "l2server.csi-im-res-set-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_res_set_id,
        { "Res Set Id", "l2server.res-set-id", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_im_res_list,
        { "CSI IM Res List", "l2server.csi-im-res-list", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_csi_ssb_res_set_config,
        { "CSI SSB Res Set Config", "l2server.csi-ssb-res-set-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_ssb_res_list,
        { "CSI SSB Res List", "l2server.csi-ssb-res-list", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_csi_res_config,
        { "CSI Res Config", "l2server.csi-res-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_res_id,
        { "CSI Res Id", "l2server.csi-res-id", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_res_type,
        { "CSI Res Type", "l2server.csi-res-type", FT_UINT8, BASE_DEC,
           VALS(csi_res_type_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_csi_rs_res_set_list_is_valid,
        { "CSI Res Type", "l2server.csi-res-type", FT_UINT8, BASE_DEC,
           VALS(csi_rs_res_set_list_is_valid_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_csi_rep_config,
        { "CSI Report Config", "l2server.csi-rep-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_carrier,
        { "Carrier", "l2server.carrier", FT_INT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_rep_config_id,
        { "CSI Report Config Id", "l2server.csi-rep-config-id", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_mon_pmi_port_ind,
        { "Nb Mon PMI Port Ind", "l2server.nb-mon-pmi-port-ind", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_report_config_type_is_valid,
        { "Report Config Type Is Valid", "l2server.report-config-type-is-valid", FT_UINT8, BASE_DEC,
           VALS(report_config_type_is_valid_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_report_quantity_is_valid,
        { "Report Quantity Is Valid", "l2server.report-quantity-is-valid", FT_UINT8, BASE_DEC,
           VALS(report_quantity_is_valid_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_cri_ri_pmi_cqi,
        { "CRI CI PCI CQI", "l2server.cri-ri-pmi-cqi", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_semipersistent_on_pucch,
        { "Semi-persistent on PUCCH", "l2server.semi-persistent", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_codebook_config,
        { "Codebook Config", "l2server.codebook-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_codebook_type_is_valid,
        { "Codebook Type Is Valid", "l2server.codebook-type-is-valid", FT_UINT8, BASE_DEC,
           VALS(codebook_type_is_valid_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_codebook_config_type1,
        { "Codebook Config Type1", "l2server.codebook-config-type1", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_codebook_subtype1_is_valid,
        { "Codebook Type1 Is Valid", "l2server.codebook-subtype1-is-valid", FT_UINT8, BASE_DEC,
           VALS(subtype1_is_valid_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_codebook_config_type1_single_panel,
        { "Single Panel", "l2server.codebook-config-type1-single-panel", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_of_ant_ports_is_valid,
        { "Nb Of Ant Posts Is Valid", "l2server.nb-of-ant-ports-is-valid", FT_UINT8, BASE_DEC,
           VALS(nb_of_ant_ports_is_valid_vals), 0x0, NULL, HFILL }},

      { &hf_l2server_aperiodic,
        { "APeriodic", "l2server.aperiodic", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_rep_slow_offset_list,
        { "Nb Rep Slow Offset List", "l2server.nb-rep-slow-offset-list", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nb_rep_slow_offset,
        { "Nb Rep Slow Offset", "l2server.nb-rep-slow-offset", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_csi_report_freq_config,
        { "Report Freq Config", "l2server.report-freq-config", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_cqi_cmd_indicator,
        { "CQI Cmd Indicator", "l2server.qci-cmd-indicator", FT_UINT8, BASE_DEC,
           VALS(cqi_fmt_indicator_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_pmi_cmd_indicator,
        { "PMI Cmd Indicator", "l2server.pmi-cmd-indicator", FT_UINT8, BASE_DEC,
           VALS(pmi_fmt_indicator_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_csi_reporting_band_is_valid,
        { "CSI Reporting Band is valid", "l2server.csi-reporting-band-is-valid", FT_UINT8, BASE_DEC,
           VALS(csi_reporting_band_id_valid_vals), 0x0, NULL, HFILL }},
      { &hf_l2server_csi_reporting_band,
        { "CSI Reporting Band", "l2server.csi-reporting-band", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_ul_am_cnf_frame,
        { "CNF Frame", "l2server.ul-am-cnf-frame", FT_FRAMENUM, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_ul_am_req_frame,
        { "REQ Frame", "l2server.ul-am-req-frame", FT_FRAMENUM, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_nzp_csi_rs_res_to_del,
        { "NZP CSI RS Resource to delete", "l2server.nzp-csi-rs-res-to-del", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_nzp_csi_rs_res_set_to_del,
        { "NZP CSI RS Resource Set to delete", "l2server.nzp-csi-rs-res-set-to-del", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_im_res_to_del,
        { "CSI IM Resource to delete", "l2server.csi-im-res-to-del", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_im_res_set_to_del,
        { "CSI IM Resource Set to delete", "l2server.csi-im-res-set-to-del", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_ssb_res_set_to_del,
        { "CSI SSB Resource Set to delete", "l2server.csi-ssb-res-set-to-del", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_res_cfg_to_del,
        { "CSI Res Config to delete", "l2server.csi-res-cfg-to-del", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_csi_rep_cfg_to_del,
        { "CSI Rep Config to delete", "l2server.csi-rep-cfg-to-del", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_control_res_set,
        { "Control Res Set", "l2server.control-res-set", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_control_res_set_id,
        { "Control Res Set Id", "l2server.control-res-set-id", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_control_res_set_duration,
        { "Control Res Set Duration", "l2server.control-res-set-duration", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_prec_granualarity,
        { "Prec Granularity", "l2server.prec-granularity", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_cce_reg_map_type,
        { "CCE Reg Map Type", "l2server.cce-reg-map-type", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_reg_bundle_size,
        { "Reg Bundle Size", "l2server.reg-bundle-size", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_interleave_size,
        { "Interleave Size", "l2server.interleave-size", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_shift_index,
        { "Shift Index", "l2server.shift-index", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_freq_dom_res,
        { "Freq Dom Res", "l2server.freq-dom-res", FT_UINT64, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_search_space,
        { "Search Space", "l2server.search-space", FT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
      { &hf_l2server_search_space_id,
        { "Search Space Id", "l2server.search-space-id", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},

      { &hf_l2server_n1n2,
        { "NIN2", "l2server.n1n2", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_l2server,
        &ett_l2server_header,
        &ett_l2server_nr5gid,
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
        &ett_l2server_sp_cell_cfg_lte_crs_pattern_list2,
        &ett_l2server_cell_config_cellcfg,
        &ett_l2server_ul_ded_config,
        &ett_l2server_initial_ul_bwp,
        &ett_l2server_ul_bwp,
        &ett_l2server_ul_bwp_common,
        &ett_l2server_ul_bwp_common_pdcch,
        &ett_l2server_ul_bwp_common_pdsch,
        &ett_l2server_rach_common,
        &ett_l2server_rach_generic,
        &ett_l2server_freq_info_dl,
        &ett_l2server_bwp_dl_common,
        &ett_l2server_freq_info_ul_common,
        &ett_l2server_bwp_ul_common,
        &ett_l2server_freq_info_sul_common,
        &ett_l2server_bwp_sul_common,
        &ett_l2server_tdd_common,
        &ett_l2server_mac_config,
        &ett_l2server_bwp_dl_dedicated,
        &ett_l2server_pdsch_serving_cell,
        &ett_l2server_pdcch_serving_cell,
        &ett_l2server_csi_meas_config,
        &ett_l2server_nzp_csi_rs_res_config,
        &ett_l2server_nzp_csi_rs_res_set_config,
        &ett_l2server_csi_im_res_config,
        &ett_l2server_csi_im_res_set_config,
        &ett_l2server_csi_ssb_res_set_config,
        &ett_l2server_csi_res_config,
        &ett_l2server_csi_rep_config,
        &ett_l2server_semipersistent_on_pucch,
        &ett_l2server_codebook_config,
        &ett_l2server_codebook_config_type1,
        &ett_l2server_codebook_config_type1_single_panel,
        &ett_l2server_aperiodic,
        &ett_l2server_csi_report_freq_config,
        &ett_l2server_control_res_set,
        &ett_l2server_search_space
    };

    static ei_register_info ei[] = {
        { &ei_l2server_sapi_unknown, { "l2server.sapi-unknown", PI_UNDECODED, PI_WARN, "Unknown SAPI", EXPFILL }},
        { &ei_l2server_type_unknown, { "l2server.type-unknown", PI_UNDECODED, PI_WARN, "Unknown Type for SAPI", EXPFILL }},
        { &ei_l2server_ul_no_cnf,    { "l2server.ul-no-cnf", PI_SEQUENCE, PI_WARN, "No CNF for UL AM PDU", EXPFILL }},
        { &ei_l2server_ul_no_req,    { "l2server.ul-no-req", PI_SEQUENCE, PI_WARN, "No REQ for UL AM PDU CNF", EXPFILL }},
    };

    module_t *l2server_module;
    expert_module_t* expert_l2server;

    proto_l2server = proto_register_protocol("L2Server", "L2Server", "l2server");
    proto_register_field_array(proto_l2server, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_l2server = expert_register_protocol(proto_l2server);
    expert_register_field_array(expert_l2server, ei, array_length(ei));

    l2server_message_handle = register_dissector("l2server-message", dissect_l2server_message, proto_l2server);
    l2server_handle = register_dissector("l2server", dissect_l2server, proto_l2server);

    /* Preferences */
    l2server_module = prefs_register_protocol(proto_l2server, NULL);

    prefs_register_bool_preference(l2server_module, "call_pdcp_drbs", "Call PDCP for DRBs",
        "",
        &global_call_pdcp_for_drb);

    prefs_register_bool_preference(l2server_module, "call_pdcp_srbs", "Call PDCP for SRBs",
        "",
        &global_call_pdcp_for_srb);

    prefs_register_bool_preference(l2server_module, "call_pdcp_tm", "Call PDCP for TM PDUs",
        "",
        &global_call_pdcp_for_tm);

    prefs_register_enum_preference(l2server_module, "sn_bits_for_drb",
        "PDCP SN bits for DRB PDUs",
        "",
        &global_pdcp_drb_sn_length, pdcp_drb_col_vals, FALSE);

    ul_req_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    ul_cnf_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
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
