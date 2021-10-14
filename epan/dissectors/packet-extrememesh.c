/* packet-extrememesh.c
 * Routines for Motorola Mesh ethernet header disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>

typedef enum _MeshNextProtocol
{
	MESH_NEXT_PROTOCOL_INVALID                      = -1,

	MESH_NEXT_PROTOCOL_MESH                         = 0,    // Extension
	MESH_NEXT_PROTOCOL_MCH                          = 1,    // Extension
	MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH             = 2,    // Terminating
	MESH_NEXT_PROTOCOL_PS                           = 3,    // Terminating
	MESH_NEXT_PROTOCOL_HELLO                        = 4,    // Terminating
	MESH_NEXT_PROTOCOL_LOCATION                     = 5,    // Terminating
	MESH_NEXT_PROTOCOL_SECURITY                     = 6,    // Terminating
	MESH_NEXT_PROTOCOL_SECURED_PAYLOAD              = 7,    // Extension
	MESH_NEXT_PROTOCOL_TEST                         = 8,    // Terminating
	MESH_NEXT_PROTOCOL_FRAGMENT                     = 9,    // Terminating
	MESH_NEXT_PROTOCOL_CFPU                         = 10,   // Terminating
	MESH_NEXT_PROTOCOL_EAPOM                        = 11,   // Terminating
	MESH_NEXT_PROTOCOL_NULL                         = 12,   // Terminating
	MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH_NO_ADDR     = 13,   // Terminating
	MESH_NEXT_PROTOCOL_L2_UPDATE                    = 14,   // Terminating
	MESH_NEXT_PROTOCOL_PROBE_MESSAGE                = 15,   // Terminating

	MESH_NEXT_PROTOCOL_EOL
} MeshNextProtocol;

typedef enum _MeshPathSelectionFrameType
{
	MESH_PS_FRAME_INVALID = -1,

	MESH_PS_FRAME_AREQ    =  1,    // Authorization Request
	MESH_PS_FRAME_AREP    =  2,    // Authorization Reply
	MESH_PS_FRAME_BREQ    =  3,    // Bind Request
	MESH_PS_FRAME_BREP    =  4,    // Bind Reply
	MESH_PS_FRAME_BANN    =  5,    // Bind Announcement
	MESH_PS_FRAME_BRED    =  6,    // Bind Removed
	MESH_PS_FRAME_SREQ    =  7,    // Status Request
	MESH_PS_FRAME_SREP    =  8,    // Status Reply
	MESH_PS_FRAME_PREQ    =  9,    // Path Request
	MESH_PS_FRAME_PREP    =  10,   // Path Reply
	MESH_PS_FRAME_PERR    =  11,   // Path Error
	MESH_PS_FRAME_PRST    =  12,   // Path Reset
	MESH_PS_FRAME_PREM    =  13,   // Proxy Remove
	MESH_PS_FRAME_TRACE   =  14,   // Trace Path
	MESH_PS_FRAME_PRER    =  15,   // Proxy Error

	MESH_PS_FRAME_EOL
} MeshPathSelectionFrameType;

void proto_reg_handoff_extrememesh(void);

/* Mesh pkt types */
static int proto_extreme_mesh = -1;
static int proto_extreme_mch = -1;
static int proto_extreme_ps_areq = -1;
static int proto_extreme_ps_arep = -1;
static int proto_extreme_ps_breq = -1;
static int proto_extreme_ps_brep = -1;
static int proto_extreme_ps_bann = -1;
static int proto_extreme_ps_bred = -1;
static int proto_extreme_ps_sreq = -1;
static int proto_extreme_ps_srep = -1;
static int proto_extreme_ps_preq = -1;
static int proto_extreme_ps_prep = -1;
static int proto_extreme_ps_perr = -1;
static int proto_extreme_ps_prst = -1;
static int proto_extreme_ps_prem = -1;
static int proto_extreme_ps_trace = -1;
static int proto_extreme_ps_prer = -1;
static int proto_extreme_hello = -1;
static int proto_extreme_security = -1;
static int proto_extreme_cfpu = -1;
static int proto_extreme_eapom = -1;
static int proto_extreme_l2upd = -1;
static int proto_extreme_probe = -1;


/*MESH fields*/
static int hf_extreme_mesh_version = -1;
static int hf_extreme_mesh_nextproto = -1;

/*MCH fields*/
static int hf_extreme_mch_version = -1;
static int hf_extreme_mch_next_proto = -1;
static int hf_extreme_mch_lq = -1;
static int hf_extreme_mch_htl = -1;
static int hf_extreme_mch_priority = -1;
static int hf_extreme_mch_usr_pri_flags = -1;
static int hf_extreme_mch_usr_pri_flags_user_priority = -1;
static int hf_extreme_mch_usr_pri_flags_reserved = -1;
static int hf_extreme_mch_usr_pri_flags_from_wan = -1;
static int hf_extreme_mch_usr_pri_flags_to_wan = -1;
static int hf_extreme_mch_usr_pri_flags_forward = -1;
static int hf_extreme_mch_sequence = -1;
static int hf_extreme_mch_dest = -1;
static int hf_extreme_mch_src = -1;

/*ENCAP_ETH fields*/
/*Hello fields*/
static int hf_extreme_hello_services = -1;
static int hf_extreme_hello_HTR = -1;
static int hf_extreme_hello_MTR = -1;
static int hf_extreme_hello_root_id = -1;
static int hf_extreme_hello_next_hop_id = -1;

/*Security fields*/
static int hf_extreme_security_version = -1;
static int hf_extreme_security_nextproto = -1;
static int hf_extreme_security_flags = -1;
static int hf_extreme_security_packet_num = -1;
static int hf_extreme_security_mic = -1;

/*Cfpu fields*/
static int hf_extreme_cfpu_version = -1;
static int hf_extreme_cfpu_window = -1;
static int hf_extreme_cfpu_cycle = -1;

/*EAPOM fields*/
static int hf_extreme_eapom_version = -1;
static int hf_extreme_eapom_header_type = -1;
static int hf_extreme_eapom_supplicant_addr = -1;
static int hf_extreme_eapom_meshid_len = -1;
static int hf_extreme_eapom_meshid = -1;
static int hf_extreme_eapom_body_len = -1;

/*Mesh L2 Update fields*/
static int hf_extreme_l2upd_proxy_owner = -1;
static int hf_extreme_l2upd_ballast = -1;

/*Probe fields*/
static int hf_extreme_probe_version = -1;
static int hf_extreme_probe_op_code = -1;
static int hf_extreme_probe_flags = -1;
static int hf_extreme_probe_flags_reserved = -1;
static int hf_extreme_probe_flags_reply = -1;
static int hf_extreme_probe_priority = -1;
static int hf_extreme_probe_job_id = -1;
static int hf_extreme_probe_sequence = -1;
static int hf_extreme_probe_ballast_len = -1;
static int hf_extreme_probe_ballast = -1;

/*Path Selection fields*/
/*PS AREQ fields*/
static int hf_extreme_ps_areq_version = -1;
static int hf_extreme_ps_areq_frame_type = -1;
static int hf_extreme_ps_areq_mpr_addr = -1;
static int hf_extreme_ps_areq_orig_addr = -1;
static int hf_extreme_ps_areq_opt_tot_len = -1;
static int hf_extreme_ps_areq_option = -1;
static int hf_extreme_ps_areq_option_len = -1;
static int hf_extreme_ps_areq_old_mpr = -1;
static int hf_extreme_ps_areq_proxies = -1;

/*PS AREP fields*/
static int hf_extreme_ps_arep_version = -1;
static int hf_extreme_ps_arep_frame_type = -1;
static int hf_extreme_ps_arep_mpr_addr = -1;
static int hf_extreme_ps_arep_orig_addr = -1;
static int hf_extreme_ps_arep_opt_tot_len = -1;
static int hf_extreme_ps_arep_option = -1;
static int hf_extreme_ps_arep_option_len = -1;
static int hf_extreme_ps_arep_result = -1;
static int hf_extreme_ps_arep_timeout = -1;

/*PS BREQ fields*/
static int hf_extreme_ps_breq_version = -1;
static int hf_extreme_ps_breq_frame_type = -1;
static int hf_extreme_ps_breq_mpr_addr = -1;
static int hf_extreme_ps_breq_orig_addr = -1;
static int hf_extreme_ps_breq_opt_tot_len = -1;
static int hf_extreme_ps_breq_option = -1;
static int hf_extreme_ps_breq_option_len = -1;
static int hf_extreme_ps_breq_proxy_addr = -1;
static int hf_extreme_ps_breq_old_mpr = -1;
static int hf_extreme_ps_breq_orig_pri = -1;
static int hf_extreme_ps_breq_proxy_pri = -1;
static int hf_extreme_ps_breq_vlan_id = -1;
static int hf_extreme_ps_breq_proxy_vlan_id = -1;
static int hf_extreme_ps_breq_seq = -1;

/*PS BREP fields*/
static int hf_extreme_ps_brep_version = -1;
static int hf_extreme_ps_brep_frame_type = -1;
static int hf_extreme_ps_brep_mpr_addr = -1;
static int hf_extreme_ps_brep_orig_addr = -1;
static int hf_extreme_ps_brep_opt_tot_len = -1;
static int hf_extreme_ps_brep_option = -1;
static int hf_extreme_ps_brep_option_len = -1;
static int hf_extreme_ps_brep_seq = -1;

/*PS BANN fields*/
static int hf_extreme_ps_bann_version = -1;
static int hf_extreme_ps_bann_frame_type = -1;
static int hf_extreme_ps_bann_mpr_addr = -1;
static int hf_extreme_ps_bann_orig_addr = -1;
static int hf_extreme_ps_bann_opt_tot_len = -1;
static int hf_extreme_ps_bann_option = -1;
static int hf_extreme_ps_bann_option_len = -1;
static int hf_extreme_ps_bann_proxy_addr = -1;
static int hf_extreme_ps_bann_old_root = -1;
static int hf_extreme_ps_bann_vlan_id = -1;
static int hf_extreme_ps_bann_seq = -1;

/*PS BRED fields*/
static int hf_extreme_ps_bred_version = -1;
static int hf_extreme_ps_bred_frame_type = -1;
static int hf_extreme_ps_bred_mpr_addr = -1;
static int hf_extreme_ps_bred_orig_addr = -1;
static int hf_extreme_ps_bred_opt_tot_len = -1;
static int hf_extreme_ps_bred_option = -1;
static int hf_extreme_ps_bred_option_len = -1;
static int hf_extreme_ps_bred_seq = -1;

/*PS SREQ fields*/
static int hf_extreme_ps_sreq_version = -1;
static int hf_extreme_ps_sreq_frame_type = -1;
static int hf_extreme_ps_sreq_reserved = -1;
static int hf_extreme_ps_sreq_orig_addr = -1;
static int hf_extreme_ps_sreq_term_addr = -1;
static int hf_extreme_ps_sreq_opt_tot_len = -1;
static int hf_extreme_ps_sreq_option = -1;
static int hf_extreme_ps_sreq_option_len = -1;
static int hf_extreme_ps_sreq_vlan_id = -1;

/*PS SREP fields*/
static int hf_extreme_ps_srep_version = -1;
static int hf_extreme_ps_srep_frame_type = -1;
static int hf_extreme_ps_srep_flags = -1;
static int hf_extreme_ps_srep_flags_reserved = -1;
static int hf_extreme_ps_srep_flags_status = -1;
static int hf_extreme_ps_srep_hop_count = -1;
static int hf_extreme_ps_srep_orig_addr = -1;
static int hf_extreme_ps_srep_dest_addr = -1;
static int hf_extreme_ps_srep_term_addr = -1;
static int hf_extreme_ps_srep_opt_tot_len = -1;
static int hf_extreme_ps_srep_option = -1;
static int hf_extreme_ps_srep_option_len = -1;
static int hf_extreme_ps_srep_vlan_id = -1;

/*PS PREQ fields*/
static int hf_extreme_ps_preq_version = -1;
static int hf_extreme_ps_preq_frame_type = -1;
static int hf_extreme_ps_preq_flags = -1;
static int hf_extreme_ps_preq_flags_broadcast = -1;
static int hf_extreme_ps_preq_flags_periodic = -1;
static int hf_extreme_ps_preq_flags_state = -1;
static int hf_extreme_ps_preq_flags_reserved = -1;
static int hf_extreme_ps_preq_flags_gratuitous = -1;
static int hf_extreme_ps_preq_flags_destination = -1;
static int hf_extreme_ps_preq_flags_unknown = -1;
static int hf_extreme_ps_preq_hop_count = -1;
static int hf_extreme_ps_preq_ttl = -1;
static int hf_extreme_ps_preq_path_metrics = -1;
static int hf_extreme_ps_preq_services = -1;
static int hf_extreme_ps_preq_services_reserved = -1;
static int hf_extreme_ps_preq_services_mobile = -1;
static int hf_extreme_ps_preq_services_path_pref = -1;
static int hf_extreme_ps_preq_services_geo = -1;
static int hf_extreme_ps_preq_services_proxy = -1;
static int hf_extreme_ps_preq_services_root = -1;
static int hf_extreme_ps_preq_reserved = -1;
static int hf_extreme_ps_preq_id = -1;
static int hf_extreme_ps_preq_term_addr = -1;
static int hf_extreme_ps_preq_dest_addr = -1;
static int hf_extreme_ps_preq_dest_seq = -1;
static int hf_extreme_ps_preq_orig_addr = -1;
static int hf_extreme_ps_preq_orig_seq = -1;
static int hf_extreme_ps_preq_opt_tot_len = -1;
static int hf_extreme_ps_preq_option = -1;
static int hf_extreme_ps_preq_option_len = -1;
static int hf_extreme_ps_preq_mcast_sub = -1;
static int hf_extreme_ps_preq_vlan_id = -1;
static int hf_extreme_ps_preq_mint_id = -1;

/*PS PREP fields*/
static int hf_extreme_ps_prep_version = -1;
static int hf_extreme_ps_prep_frame_type = -1;
static int hf_extreme_ps_prep_flags = -1;
static int hf_extreme_ps_prep_flags_reserved = -1;
static int hf_extreme_ps_prep_flags_new_route = -1;
static int hf_extreme_ps_prep_flags_repair = -1;
static int hf_extreme_ps_prep_flags_ack = -1;
static int hf_extreme_ps_prep_hop_count = -1;
static int hf_extreme_ps_prep_path_metrics = -1;
static int hf_extreme_ps_prep_services = -1;
static int hf_extreme_ps_prep_services_reserved = -1;
static int hf_extreme_ps_prep_services_mobile = -1;
static int hf_extreme_ps_prep_services_path_pref = -1;
static int hf_extreme_ps_prep_services_geo = -1;
static int hf_extreme_ps_prep_services_proxy = -1;
static int hf_extreme_ps_prep_services_root = -1;
static int hf_extreme_ps_prep_reserved = -1;
static int hf_extreme_ps_prep_term_addr = -1;
static int hf_extreme_ps_prep_dest_addr = -1;
static int hf_extreme_ps_prep_dest_seq = -1;
static int hf_extreme_ps_prep_orig_addr = -1;
static int hf_extreme_ps_prep_orig_seq = -1;
static int hf_extreme_ps_prep_lifetime = -1;
static int hf_extreme_ps_prep_opt_tot_len = -1;
static int hf_extreme_ps_prep_option = -1;
static int hf_extreme_ps_prep_option_len = -1;
static int hf_extreme_ps_prep_mcast_sub = -1;
static int hf_extreme_ps_prep_vlan_id = -1;
static int hf_extreme_ps_prep_mint_id = -1;

/*PS PERR fields*/
static int hf_extreme_ps_perr_version = -1;
static int hf_extreme_ps_perr_frame_type = -1;
static int hf_extreme_ps_perr_flags = -1;
static int hf_extreme_ps_perr_flags_reserved = -1;
static int hf_extreme_ps_perr_flags_warning = -1;
static int hf_extreme_ps_perr_flags_no_delete = -1;
static int hf_extreme_ps_perr_dest_count = -1;
static int hf_extreme_ps_perr_unrch_dest = -1;
static int hf_extreme_ps_perr_unrch_dest_seq = -1;

/*PS PRST fields*/
static int hf_extreme_ps_prst_version = -1;
static int hf_extreme_ps_prst_frame_type = -1;
static int hf_extreme_ps_prst_hops_to_live = -1;
static int hf_extreme_ps_prst_reserved = -1;
static int hf_extreme_ps_prst_id = -1;
static int hf_extreme_ps_prst_orig_addr = -1;
static int hf_extreme_ps_prst_dest_addr = -1;

/*PS PREM fields*/
static int hf_extreme_ps_prem_version = -1;
static int hf_extreme_ps_prem_frame_type = -1;
static int hf_extreme_ps_prem_mpr_addr = -1;
static int hf_extreme_ps_prem_orig_addr = -1;
static int hf_extreme_ps_prem_opt_tot_len = -1;
static int hf_extreme_ps_prem_option = -1;
static int hf_extreme_ps_prem_option_len = -1;
static int hf_extreme_ps_prem_proxy_addr = -1;
static int hf_extreme_ps_prem_proxy_vlan_id = -1;

/*PS TRACE fields*/
static int hf_extreme_ps_trace_version = -1;
static int hf_extreme_ps_trace_frame_type = -1;
static int hf_extreme_ps_trace_flags = -1;
static int hf_extreme_ps_trace_flags_reserved = -1;
static int hf_extreme_ps_trace_flags_reply = -1;
static int hf_extreme_ps_trace_flags_no_path = -1;
static int hf_extreme_ps_trace_dest_addr = -1;
static int hf_extreme_ps_trace_orig_addr = -1;
static int hf_extreme_ps_trace_hop_count = -1;
static int hf_extreme_ps_trace_addl_path = -1;

/*PS PRER fields*/
static int hf_extreme_ps_prer_version = -1;
static int hf_extreme_ps_prer_frame_type = -1;
static int hf_extreme_ps_prer_dest_count = -1;
static int hf_extreme_ps_prer_reserved = -1;
static int hf_extreme_ps_prer_orig_addr = -1;
static int hf_extreme_ps_prer_dest_addr = -1;
static int hf_extreme_ps_prer_unrch_addr = -1;
static int hf_extreme_ps_prer_opt_tot_len = -1;
static int hf_extreme_ps_prer_option = -1;
static int hf_extreme_ps_prer_option_len = -1;
static int hf_extreme_ps_prer_vlan_id = -1;

/*ETT for above fields...*/
static int ett_extreme_mesh = -1;

/*MCH fields*/
static int ett_extreme_mch = -1;

/*Hello fields*/
static int ett_extreme_hello = -1;

/*Security fields*/
static int ett_extreme_security = -1;

/*Cfpu fields*/
static int ett_extreme_cfpu = -1;

/*EAPOM fields*/
static int ett_extreme_eapom = -1;

/*PS fields*/
static int ett_extreme_ps = -1;

/*Ethernet without FCS Dissector handle*/
static dissector_handle_t eth_withoutfcs_handle;

static const value_string mot_mesh_packet_types[] = {
	{0, "Mesh"},
	{1, "MCH"},
	{2, "Encapsulated Ethernet"},
	{3, "PS"},
	{4, "Hello"},
	{5, "Loc"},
	{6, "Sec"},
	{7, "MSH"},
	{8, "Test"},
	{9, "Frag"},
	{10, "CFPU"},
	{11, "EAPOM"},
	{12, "NULL"},
	{13, "Encapsulated Ethernet, no address"},
	{14, "L2Up"},
	{15, "Probe"},
	{0, NULL}
};

static const value_string mot_ps_packet_types[] = {
	{0, "(Invalid)"},
	{1, "AREQ" },
	{2, "AREP" },
	{3, "BREQ" },
	{4, "BREP" },
	{5, "BANN" },
	{6, "BRED" },
	{7, "SREQ" },
	{8, "SREP" },
	{9, "PREQ" },
	{10,"PREP" },
	{11,"PERR" },
	{12,"PRST" },
	{13,"PREM" },
	{14,"TRACE"},
	{15,"PRER" }
};

static const value_string mot_ps_auth_replies[] = {
	{0, "Authorization Rejected"},
	{1, "Authorization Granted"},
	{2, "Authorization Pending"},
};

static void dissect_extreme_ps_areq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint dissect_extreme_eth_noaddr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint dissect_extreme_l2upd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint dissect_extreme_probe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint dissect_extreme_ps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_arep(struct tvbuff *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_breq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_brep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_bann(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_bred(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_sreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_srep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_preq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_prep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_perr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_prst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_prem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_extreme_ps_prer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void dissect_extreme_ps_arep(struct tvbuff *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Authorization Reply");
	proto_tree_add_item(tree, proto_extreme_ps_arep, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_arep_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_arep_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_arep_mpr_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_arep_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_arep_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_arep_option, tvb, offset, 1, FALSE);
		offset++;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			proto_tree_add_item(tree, hf_extreme_ps_arep_option_len, tvb, offset, 1, FALSE);
			offset++;
			switch(option)
			{
			case 4:
				proto_tree_add_item(tree, hf_extreme_ps_arep_result, tvb, offset, 1, FALSE);
				offset++;
				break;
			case 6:
				proto_tree_add_item(tree, hf_extreme_ps_arep_timeout, tvb, offset, 1, FALSE);
				offset++;
				break;
			default:
				/*proto_tree_add_subtree_format(tree, tvb, offset, -1, */
						/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported authorization reply option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Request

Description:

Dissects the path selection bind request.

*/
/*****************************************************************************/
static void dissect_extreme_ps_breq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 option = 0;
	guint8 option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Request");
	proto_tree_add_item(tree, proto_extreme_ps_breq, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_breq_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_breq_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_breq_mpr_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_breq_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_breq_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_breq_option, tvb, offset, 1, FALSE);
		offset++;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			proto_tree_add_item(tree, hf_extreme_ps_breq_option_len, tvb, offset, 1, FALSE);
			option_len = tvb_get_guint8(tvb, offset);
			offset++;
			switch(option)
			{
			case 1:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_breq_proxy_addr, tvb, offset, 6, FALSE);
					option_len-=6;
					offset+=6;
				}
				break;
			case 2:
				proto_tree_add_item(tree, hf_extreme_ps_breq_old_mpr, tvb, offset, 6, FALSE);
				offset+=6;
				break;
			case 5:
				break;
			case 7:
				proto_tree_add_item(tree, hf_extreme_ps_breq_orig_pri, tvb, offset, 1, FALSE);
				offset++;
				break;
			case 8:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_breq_proxy_pri, tvb, offset, 1, FALSE);
					option_len--;
					offset++;
				}
				break;
			case 10:
				proto_tree_add_item(tree, hf_extreme_ps_breq_vlan_id, tvb, offset, 2, FALSE);
				offset+=2;
				break;
			case 11:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_breq_proxy_vlan_id, tvb, offset, 2, FALSE);
					option_len-=2;
					offset+=2;
				}
				break;
			case 12:
				proto_tree_add_item(tree, hf_extreme_ps_breq_seq, tvb, offset, 4, FALSE);
				offset+=4;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported bind request option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Reply

Description:

Dissects the path selection bind reply.

*/
/*****************************************************************************/
static void dissect_extreme_ps_brep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Reply");
	proto_tree_add_item(tree, proto_extreme_ps_brep, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_brep_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_brep_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_brep_mpr_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_brep_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_brep_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_brep_option, tvb, offset, 1, FALSE);
		offset++;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			switch(option)
			{
			case 12:
				proto_tree_add_item(tree, hf_extreme_ps_brep_option_len, tvb, offset, 1, FALSE);
				offset++;
				proto_tree_add_item(tree, hf_extreme_ps_brep_seq, tvb, offset, 4, FALSE);
				offset+=4;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported bind reply option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Announcement

Description:

Dissects the path selection bind announcement (BANN) packet.

*/
/*****************************************************************************/
static void dissect_extreme_ps_bann(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 option = 0;
	guint8 option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Announcement");
	proto_tree_add_item(tree, proto_extreme_ps_bann, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_bann_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_bann_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_bann_mpr_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_bann_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_bann_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_bann_option, tvb, offset, 1, FALSE);
		offset++;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			option_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_extreme_ps_bann_option_len, tvb, offset, 1, FALSE);
			offset++;
			switch(option)
			{
			case 1:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_bann_proxy_addr, tvb, offset, 6, FALSE);
					option_len-=6;
					offset+=6;
				}
				break;
			case 2:
				proto_tree_add_item(tree, hf_extreme_ps_bann_old_root, tvb, offset, 6, FALSE);
				offset+=6;
				break;

			case 10:
				proto_tree_add_item(tree, hf_extreme_ps_bann_vlan_id, tvb, offset, 2, FALSE);
				offset+=2;
				break;
			case 12:
				proto_tree_add_item(tree, hf_extreme_ps_bann_seq, tvb, offset, 4, FALSE);
				offset+=4;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported bind announcement option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Removed

Description:

Dissects the path selection bind removed packet.

*/
/*****************************************************************************/
static void dissect_extreme_ps_bred(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Removed");
	proto_tree_add_item(tree, proto_extreme_ps_bred, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_bred_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_bred_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_bred_mpr_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_bred_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_bred_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_bred_option, tvb, offset, 1, FALSE);
		offset++;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			proto_tree_add_item(tree, hf_extreme_ps_bred_option_len, tvb, offset, 1, FALSE);
			offset++;
			switch(option)
			{
			case 12:
				proto_tree_add_item(tree, hf_extreme_ps_bred_seq, tvb, offset, 4, FALSE);
				offset+=4;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported bind removed option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Status Request

Description:

Dissects the path selection status request.

*/
/*****************************************************************************/
static void dissect_extreme_ps_sreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint16 option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Status Request");
	proto_tree_add_item(tree, proto_extreme_ps_sreq, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_sreq_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_sreq_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_sreq_reserved, tvb, offset, 2, FALSE);
	offset+=2;
	proto_tree_add_item(tree, hf_extreme_ps_sreq_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_sreq_term_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_sreq_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_sreq_option, tvb, offset, 2, FALSE);
		offset+=2;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			proto_tree_add_item(tree, hf_extreme_ps_sreq_option_len, tvb, offset, 2, FALSE);
			offset+=2;
			switch(option)
			{
			case 10:
				proto_tree_add_item(tree, hf_extreme_ps_sreq_vlan_id, tvb, offset, 2, FALSE);
				offset+=2;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported status request option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Status Reply

Description:

Dissects the path selection status reply.

*/
/*****************************************************************************/
static void dissect_extreme_ps_srep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint16 option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Status Reply");
	proto_tree_add_item(tree, proto_extreme_ps_srep, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_srep_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_srep_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_srep_flags, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_srep_flags_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_srep_flags_status, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_srep_hop_count, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_srep_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_srep_dest_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_srep_term_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_srep_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_srep_option, tvb, offset, 2, FALSE);
		offset+=2;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			proto_tree_add_item(tree, hf_extreme_ps_srep_option_len, tvb, offset, 2, FALSE);
			offset+=2;
			switch(option)
			{
			case 10:
				proto_tree_add_item(tree, hf_extreme_ps_srep_vlan_id, tvb, offset, 2, FALSE);
				offset+=2;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported status reply option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Request

Description:

Dissects the path selection path request.

*/
/*****************************************************************************/
static void dissect_extreme_ps_preq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint16 option = 0;
	guint16 option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Request");
	proto_tree_add_item(tree, proto_extreme_ps_preq, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_preq_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags_broadcast, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags_periodic, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags_state, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags_gratuitous, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags_destination, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_flags_unknown, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_preq_hop_count, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_preq_ttl, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_preq_path_metrics, tvb, offset, 2, FALSE);
	offset+=2;
	proto_tree_add_item(tree, hf_extreme_ps_preq_services, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_services_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_services_mobile, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_services_path_pref, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_services_geo, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_services_proxy, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_preq_services_root, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_preq_reserved, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_preq_id, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_preq_term_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_preq_dest_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_preq_dest_seq, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_preq_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_preq_orig_seq, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_preq_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_preq_option, tvb, offset, 2, FALSE);
		offset+=2;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			option_len = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(tree, hf_extreme_ps_preq_option_len, tvb, offset, 2, FALSE);
			offset+=2;
			switch(option)
			{
			case 1:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_preq_mcast_sub, tvb, offset, 6, FALSE);
					option_len-=6;
					offset+=6;
				}
				break;
			case 10:
				proto_tree_add_item(tree, hf_extreme_ps_preq_vlan_id, tvb, offset, 2, FALSE);
				offset+=2;
				break;
			case 14:
				proto_tree_add_item(tree, hf_extreme_ps_preq_mint_id, tvb, offset, 4, FALSE);
				offset+=4;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported path request option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Reply

Description:

Dissects the path selection path reply.

*/
/*****************************************************************************/
static void dissect_extreme_ps_prep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint16 option = 0;
	guint16 option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Reply");
	proto_tree_add_item(tree, proto_extreme_ps_prep, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prep_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prep_flags, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_flags_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_flags_new_route, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_flags_repair, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_flags_ack, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prep_hop_count, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prep_path_metrics, tvb, offset, 2, FALSE);
	offset+=2;
	proto_tree_add_item(tree, hf_extreme_ps_prep_services, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_services_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_services_mobile, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_services_path_pref, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_services_geo, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_services_proxy, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prep_services_root, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prep_reserved, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prep_term_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prep_dest_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prep_dest_seq, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_prep_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prep_orig_seq, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_prep_lifetime, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_prep_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_prep_option, tvb, offset, 2, FALSE);
		offset+=2;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			option_len = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(tree, hf_extreme_ps_prep_option_len, tvb, offset, 2, FALSE);
			offset+=2;
			switch(option)
			{
			case 1:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_prep_mcast_sub, tvb, offset, 6, FALSE);
					option_len-=6;
					offset+=6;
				}
				break;
			case 10:
				proto_tree_add_item(tree, hf_extreme_ps_prep_vlan_id, tvb, offset, 2, FALSE);
				offset+=2;
				break;
			case 14:
				proto_tree_add_item(tree, hf_extreme_ps_prep_mint_id, tvb, offset, 4, FALSE);
				offset+=4;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported path reply option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Error

Description:

Dissects the path selection path error (PERR) packet.

*/
/*****************************************************************************/
static void dissect_extreme_ps_perr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 dst_cnt = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Error");
	dst_cnt = tvb_get_guint8(tvb, 3);
	proto_tree_add_item(tree, proto_extreme_ps_perr, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_perr_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_perr_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_perr_flags, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_perr_flags_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_perr_flags_warning, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_perr_flags_no_delete, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_perr_dest_count, tvb, offset, 1, FALSE);
	offset++;
	while (dst_cnt-- > 0)
	{
		proto_tree_add_item(tree, hf_extreme_ps_perr_unrch_dest, tvb, offset, 6, FALSE);
		offset+=6;
		proto_tree_add_item(tree, hf_extreme_ps_perr_unrch_dest_seq, tvb, offset, 4, FALSE);
		offset+=4;
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Reset

Description:

Dissects the path selection path reset (PRST).

*/
/*****************************************************************************/
static void dissect_extreme_ps_prst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Reset");
	proto_tree_add_item(tree, proto_extreme_ps_prst, tvb, offset,
						-1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prst_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prst_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prst_hops_to_live, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prst_reserved, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prst_id, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_ps_prst_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prst_dest_addr, tvb, offset, 6, FALSE);
}

/*****************************************************************************/
/*

Dissect Path Selection Proxy Remove

Description:

Dissects the path selection proxy remove (PREM) packet.

*/
/*****************************************************************************/
static void dissect_extreme_ps_prem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 option = 0;
	guint8 option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Proxy Remove");
	proto_tree_add_item(tree, proto_extreme_ps_prem, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prem_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prem_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prem_mpr_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prem_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prem_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_prem_option, tvb, offset, 1, FALSE);
		offset++;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			option_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_extreme_ps_prem_option_len, tvb, offset, 1, FALSE);
			offset++;
			switch(option)
			{
			case 1:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_prem_proxy_addr, tvb, offset, 6, FALSE);
					option_len-=6;
					offset+=6;
				}
				break;
			case 11:
				while(option_len > 0)
				{
					proto_tree_add_item(tree, hf_extreme_ps_prem_proxy_vlan_id, tvb, offset, 2, FALSE);
					option_len-=2;
					offset+=2;
				}
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported proxy remove option (%d)", option);*/
				return;
			}
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Trace Path

Description:

Dissects the path selection trace path (TRACE) packet.

*/
/*****************************************************************************/
static void dissect_extreme_ps_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 hop_cnt = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Trace Path");
	hop_cnt = tvb_get_guint8(tvb, 15);
	proto_tree_add_item(tree, proto_extreme_ps_trace, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_trace_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_trace_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_trace_flags, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_trace_flags_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_trace_flags_reply, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_trace_flags_no_path, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_trace_dest_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_trace_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_trace_hop_count, tvb, offset, 1, FALSE);
	offset++;
	while(hop_cnt-- > 0)
	{
		proto_tree_add_item(tree, hf_extreme_ps_trace_addl_path, tvb, offset, 6, FALSE);
		offset+=6;
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Proxy Error

Description:

Dissects the path selection proxy error.

*/
/*****************************************************************************/
static void dissect_extreme_ps_prer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint16 option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Proxy Error");
	proto_tree_add_item(tree, proto_extreme_ps_prer, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_prer_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prer_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prer_dest_count, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prer_reserved, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_prer_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prer_dest_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prer_unrch_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_prer_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_prer_option, tvb, offset, 2, FALSE);
		offset+=2;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			proto_tree_add_item(tree, hf_extreme_ps_prer_option_len, tvb, offset, 2, FALSE);
			offset+=2;
			switch(option)
			{
			case 11:
				proto_tree_add_item(tree, hf_extreme_ps_prer_vlan_id, tvb, offset, 2, FALSE);
				offset+=2;
				break;
			default:
				/*proto_tree_add_text(tree, tvb, offset, -1, */
				/*"Unsupported status reply option (%d)", option);*/
				return;
			}
		}
	}
}



static gint dissect_extreme_ps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint frame_type_offset = 1;
	gint frame_type = MESH_PS_FRAME_INVALID;

	if(!tvb)
	{
		return MESH_NEXT_PROTOCOL_INVALID;
	}
	frame_type = tvb_get_guint8(tvb, frame_type_offset);
	switch(frame_type)
	{
	case MESH_PS_FRAME_AREQ:
		dissect_extreme_ps_areq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_AREP:
		dissect_extreme_ps_arep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BREQ:
		dissect_extreme_ps_breq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BREP:
		dissect_extreme_ps_brep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BANN:
		dissect_extreme_ps_bann(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BRED:
		dissect_extreme_ps_bred(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_SREQ:
		dissect_extreme_ps_sreq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_SREP:
		dissect_extreme_ps_srep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PREQ:
		dissect_extreme_ps_preq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PREP:
		dissect_extreme_ps_prep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PERR:
		dissect_extreme_ps_perr(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PRST:
		dissect_extreme_ps_prst(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PREM:
		dissect_extreme_ps_prem(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_TRACE:
		dissect_extreme_ps_trace(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PRER:
		dissect_extreme_ps_prer(tvb, pinfo, tree);
		break;
	default:
		/*proto_tree_add_text(tree, tvb, 0, -1, */
		/*"Undefined path selection frame type (%d)", frame_type);*/
		break;
	}
	return MESH_NEXT_PROTOCOL_INVALID;
}


static gint dissect_extreme_mch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *meshTree = tree;
	gint offset = 0;
	gint next_proto;
	tvbuff_t *nextTvb;

	if(!tvb)
	{
		return MESH_NEXT_PROTOCOL_INVALID;
	}
	proto_tree_add_item(meshTree, proto_extreme_mch, tvb, offset, -1, FALSE);
	proto_tree_add_item(meshTree, hf_extreme_mch_version, tvb, offset, 1, FALSE);
	offset++;
	next_proto = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(meshTree, hf_extreme_mch_next_proto, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(meshTree, hf_extreme_mch_lq, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(meshTree, hf_extreme_mch_htl, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(meshTree, hf_extreme_mch_priority, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(meshTree, hf_extreme_mch_usr_pri_flags, tvb, offset, 1, FALSE);
	proto_tree_add_item(meshTree, hf_extreme_mch_usr_pri_flags_user_priority, tvb, offset, 1, FALSE);
	proto_tree_add_item(meshTree, hf_extreme_mch_usr_pri_flags_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(meshTree, hf_extreme_mch_usr_pri_flags_from_wan, tvb, offset, 1, FALSE);
	proto_tree_add_item(meshTree, hf_extreme_mch_usr_pri_flags_to_wan, tvb, offset, 1, FALSE);
	proto_tree_add_item(meshTree, hf_extreme_mch_usr_pri_flags_forward, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(meshTree, hf_extreme_mch_sequence, tvb, offset, 2, FALSE);
	offset+=2;
	proto_tree_add_item(meshTree, hf_extreme_mch_dest, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(meshTree, hf_extreme_mch_src, tvb, offset, 6, FALSE);
	offset+=6;

	nextTvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);

	while(next_proto != (gint)MESH_NEXT_PROTOCOL_INVALID)
	{
		switch(next_proto)
		{
		case MESH_NEXT_PROTOCOL_NULL: // Obsolete
		case MESH_NEXT_PROTOCOL_TEST: // Multi-service Enterprise Access (MEA)
									  // Platform only
		case MESH_NEXT_PROTOCOL_FRAGMENT: // MEA only
		case MESH_NEXT_PROTOCOL_LOCATION: // MEA only
		case MESH_NEXT_PROTOCOL_INVALID:
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		case MESH_NEXT_PROTOCOL_MESH:
			// Should never encounter this inside of a MESH packet
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		case MESH_NEXT_PROTOCOL_MCH:
			next_proto = dissect_extreme_mch(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH:
			if (eth_withoutfcs_handle)
			{
				call_dissector(eth_withoutfcs_handle, nextTvb, pinfo, meshTree);
			}
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		case MESH_NEXT_PROTOCOL_PS:
			next_proto = dissect_extreme_ps(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_HELLO:
		case MESH_NEXT_PROTOCOL_SECURITY: // MEA only
		case MESH_NEXT_PROTOCOL_SECURED_PAYLOAD: // MEA only
		case MESH_NEXT_PROTOCOL_CFPU: // Quattro only
		case MESH_NEXT_PROTOCOL_EAPOM:
		case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH_NO_ADDR:
			next_proto = dissect_extreme_eth_noaddr(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_L2_UPDATE:
			next_proto = dissect_extreme_l2upd(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_PROBE_MESSAGE:
			next_proto = dissect_extreme_probe(nextTvb, pinfo, meshTree);
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"dissect_extreme_mch: Unsupported protocol (%d)", next_proto);*/
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		}
	}
	return next_proto;
}

static int dissect_extrememesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	gint offset = 0;
	/*guint8 packet_type = 0;*/
	tvbuff_t *next_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCX");
	proto_item *ti = NULL;
	proto_tree *meshTree = NULL;
	gint next_proto = MESH_NEXT_PROTOCOL_INVALID;

	ti = proto_tree_add_item(tree, proto_extreme_mesh, tvb, offset, -1, FALSE);
	meshTree = proto_item_add_subtree(ti, ett_extreme_mesh);
	proto_tree_add_item(meshTree, hf_extreme_mesh_version, tvb, offset, 1, FALSE);
	offset++;
	next_proto = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(meshTree, hf_extreme_mesh_nextproto, tvb, offset, 1, FALSE);
	offset++;

	next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);

	while(next_proto != (gint)MESH_NEXT_PROTOCOL_INVALID)
	{
		switch(next_proto)
		{
			case MESH_NEXT_PROTOCOL_NULL: // Obsolete
			case MESH_NEXT_PROTOCOL_TEST: // Multi-service Enterprise Access
									  // (MEA) Platform only
			case MESH_NEXT_PROTOCOL_FRAGMENT: // MEA only
			case MESH_NEXT_PROTOCOL_LOCATION: // MEA only
			case MESH_NEXT_PROTOCOL_INVALID:
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			case MESH_NEXT_PROTOCOL_MESH:
				// Should never encounter this inside of a MESH packet
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			case MESH_NEXT_PROTOCOL_MCH:
				next_proto = dissect_extreme_mch(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH:
				if (eth_withoutfcs_handle)
				{
					call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, meshTree);
				}
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			case MESH_NEXT_PROTOCOL_PS:
				next_proto = dissect_extreme_ps(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_HELLO:
			case MESH_NEXT_PROTOCOL_SECURITY: // MEA only
			case MESH_NEXT_PROTOCOL_SECURED_PAYLOAD: // MEA only
			case MESH_NEXT_PROTOCOL_CFPU: // Quattro only
			case MESH_NEXT_PROTOCOL_EAPOM:
			case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH_NO_ADDR:
				next_proto = dissect_extreme_eth_noaddr(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_L2_UPDATE:
				next_proto = dissect_extreme_l2upd(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_PROBE_MESSAGE:
				next_proto = dissect_extreme_probe(next_tvb, pinfo, meshTree);
				break;
			default:
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			}
		}
		return 0;
}

static void dissect_extreme_ps_areq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 option = 0;

	/*if((pinfo != NULL) && check_col(pinfo->cinfo,COL_INFO))*/
	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Authorization Request");
	proto_tree_add_item(tree, proto_extreme_ps_areq, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_ps_areq_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_areq_frame_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_ps_areq_mpr_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_areq_orig_addr, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_ps_areq_opt_tot_len, tvb, offset, 2, FALSE);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		option = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_extreme_ps_areq_option, tvb, offset, 1, FALSE);
		offset++;
		if(option != 0) // Option 0 is a single padding byte, no length byte
		{
			proto_tree_add_item(tree, hf_extreme_ps_areq_option_len, tvb, offset, 1, FALSE);
			offset++;
			switch(option)
			{
			case 2:
				proto_tree_add_item(tree, hf_extreme_ps_areq_old_mpr, tvb, offset, 6, FALSE);
				offset+=6;
				break;
			case 3:
				proto_tree_add_item(tree, hf_extreme_ps_areq_proxies, tvb, offset, 1, FALSE);
				offset++;
				break;
			default:
				return;
			}
		}
	}
}

static gint dissect_extreme_eth_noaddr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *nextTvb;
	guchar *ethBuffer;
	gint bufferLen;
	//These are encapsulated ethernet frames that have had their
	//src and dest stripped off

	//Get the length of the current buffer
	guint tvbLen = tvb_captured_length(tvb);
	//Add space for the src/dst
	bufferLen = tvbLen + 12;
	//Allocate a new ethernet buffer
	ethBuffer = (guchar*)g_malloc(bufferLen);

	//Copy in the src/dst
	memcpy(ethBuffer, pinfo->dst.data, 6);
	memcpy(ethBuffer + 6, pinfo->src.data, 6);

	//Copy in the rest of the packet
	tvb_memcpy(tvb, ethBuffer + 12, 0, tvbLen);
	nextTvb = tvb_new_real_data(ethBuffer, bufferLen, bufferLen);
	tvb_set_free_cb(nextTvb, g_free);
	tvb_set_child_real_data_tvbuff(tvb, nextTvb);
	add_new_data_source(pinfo, nextTvb, "Encapsulated Ethernet, no addr");

	if (eth_withoutfcs_handle)
	{
		call_dissector(eth_withoutfcs_handle, nextTvb, pinfo, tree);
	}

	//This is a terminal type
	return MESH_NEXT_PROTOCOL_INVALID;
}

static gint dissect_extreme_l2upd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;

	if(!tvb)
	{
		return MESH_NEXT_PROTOCOL_INVALID;
	}

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh L2 Update");
	proto_tree_add_item(tree, proto_extreme_l2upd, tvb, offset, -1, FALSE);
	proto_tree_add_item(tree, hf_extreme_l2upd_proxy_owner, tvb, offset, 6, FALSE);
	offset+=6;
	proto_tree_add_item(tree, hf_extreme_l2upd_ballast, tvb, offset, tvb_captured_length(tvb)-6, FALSE);

	return MESH_NEXT_PROTOCOL_INVALID;
}

static gint dissect_extreme_probe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint16 ballast_len;

	if(!tvb)
	{
		return MESH_NEXT_PROTOCOL_INVALID;
	}

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Probe Message");
	ballast_len = tvb_get_ntohs(tvb, 10);
	proto_tree_add_item(tree, proto_extreme_probe, tvb, offset, 12+ballast_len, FALSE);
	proto_tree_add_item(tree, hf_extreme_probe_version, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_probe_op_code, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_probe_flags, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_probe_flags_reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_extreme_probe_flags_reply, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_probe_priority, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_extreme_probe_job_id, tvb, offset, 2, FALSE);
	offset+=2;
	proto_tree_add_item(tree, hf_extreme_probe_sequence, tvb, offset, 4, FALSE);
	offset+=4;
	proto_tree_add_item(tree, hf_extreme_probe_ballast_len, tvb, offset, 2, FALSE);
	offset+=2;
	proto_tree_add_item(tree, hf_extreme_probe_ballast, tvb, offset, ballast_len, FALSE);

	return MESH_NEXT_PROTOCOL_INVALID;
}


void proto_register_extrememesh(void)
{
	/*register the fields for the various structs*/
	/* extreme mesh */
	static hf_register_info hf_extreme_mesh[] = {
	{ &hf_extreme_mesh_version, {
		"Version", "extrememesh.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mesh_nextproto, {
		"Next protocol", "extrememesh.nextproto", FT_UINT8, BASE_DEC,
		VALS(mot_mesh_packet_types), 0x0, NULL, HFILL }}
	};

	/* extreme mesh control header */
	static hf_register_info hf_extreme_mch[] = {
	{ &hf_extreme_mch_version, {
		"Version", "extrememch.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_next_proto, {
		"Next protocol", "extrememch.nextproto", FT_UINT8, BASE_DEC,
		VALS(mot_mesh_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_lq, {
		"Link Quality Metric", "extrememch.lq", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_htl, {
		"Hop To Live counter", "extrememch.htl", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_priority, {
		"Packet Priority", "extrememch.priority", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_usr_pri_flags, {
		"Priority/Flags", "extrememch.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_usr_pri_flags_user_priority, {
		"User Priority", "extrememch.flags.user_priority", FT_UINT8, BASE_DEC,
		NULL, 0xF0, NULL, HFILL }},
	{ &hf_extreme_mch_usr_pri_flags_reserved, {
		"Reserved", "extrememch.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0x08, NULL, HFILL }},
	{ &hf_extreme_mch_usr_pri_flags_from_wan, {
		"From WAN", "extrememch.flags.from_wan", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extreme_mch_usr_pri_flags_to_wan, {
		"To WAN", "extrememch.flags.to_wan", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extreme_mch_usr_pri_flags_forward, {
		"Forward Flag", "extrememch.flags.forward", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_mch_sequence, {
		"Sequence", "extrememch.sequence", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_dest, {
		"Dst", "extrememch.dst", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_mch_src, {
		"Src", "extrememch.src", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme hello */
	static hf_register_info hf_extreme_hello[] = {
	{ &hf_extreme_hello_services, {
		"Services", "extremehello.services", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_hello_HTR, {
		"Hops to root", "extremehello.hr", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extreme_hello_MTR, {
		"Metric to root", "extremehello.mtr", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_hello_root_id, {
		"Root", "extremehello.rootid", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extreme_hello_next_hop_id, {
		"Next Hop", "extremehello.nhid", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};

	/* extreme security */
	static hf_register_info hf_extreme_security[] = {
	{ &hf_extreme_security_version, {
		"Version", "extremesecurity.version", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_security_nextproto, {
		"Next proto", "extremesecurity.nextproto", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extreme_security_flags, {
		"Flags", "extremesecurity.flags", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_security_packet_num, {
		"Packet Number", "extremesecurity.pktnum", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extreme_security_mic, {
		"MIC", "extremesecurity.mic", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};

	/* extreme contention free period (CFP) update */
	static hf_register_info hf_extreme_cfpu[] = {
	{ &hf_extreme_cfpu_version, {
		"Version", "hf_extreme_cfpu.version", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_cfpu_window, {
		"Window", "hf_extreme_cfpu.window", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extreme_cfpu_cycle, {
		"Cycle", "hf_extreme_cfpu.cycle", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};

	/* extreme EAP over mesh */
	static hf_register_info hf_extreme_eapom[] = {
	{ &hf_extreme_eapom_version, {
		"Services", "extremehello.services", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_eapom_header_type, {
		"Hops to root", "extremehello.hr", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extreme_eapom_supplicant_addr, {
		"Metric to root", "extremehello.mtr", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_eapom_meshid_len, {
		"Root", "extremehello.rootid", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extreme_eapom_meshid, {
		"Next Hop", "extremehello.nhid", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extreme_eapom_body_len, {
		"Next Hop", "extremehello.nhid", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};

	/* extreme mesh path selection authorization request */
	static hf_register_info hf_extreme_ps_areq[] = {
	{ &hf_extreme_ps_areq_version, {
		"Version", "extreme.ps.areq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_frame_type, {
		"Frame Type", "extreme.ps.areq.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_mpr_addr, {
		"MPR Addr", "extreme.ps.areq.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_orig_addr, {
		"Orig Addr", "extreme.ps.areq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_opt_tot_len, {
		"Options Total Length", "extreme.ps.areq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_option, {
		"Option", "extreme.ps.areq.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_option_len, {
		"Length", "extreme.ps.areq.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_old_mpr, {
		"Old MPR Addr", "extreme.ps.areq.old_mpr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_areq_proxies, {
		"Number of Proxies", "extreme.ps.areq.proxies", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection authorization reply */
	static hf_register_info hf_extreme_ps_arep[] = {
	{ &hf_extreme_ps_arep_version, {
		"Version", "extreme.ps.arep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_frame_type, {
		"Frame Type", "extreme.ps.arep.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_mpr_addr, {
		"MPR Addr", "extreme.ps.arep.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_orig_addr, {
		"Orig Addr", "extreme.ps.arep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_opt_tot_len, {
		"Options Total Length", "extreme.ps.arep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_option, {
		"Option", "extreme.ps.arep.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_option_len, {
		"Length", "extreme.ps.arep.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_result, {
		"Result", "extreme.ps.arep.result", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_auth_replies), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_arep_timeout, {
		"Timeout", "extreme.ps.arep.timeout", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection bind request */
	static hf_register_info hf_extreme_ps_breq[] = {
	{ &hf_extreme_ps_breq_version, {
		"Version", "extreme.ps.breq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_frame_type, {
		"Frame Type", "extreme.ps.breq.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_mpr_addr, {
		"MPR Addr", "extreme.ps.breq.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_orig_addr, {
		"Orig Addr", "extreme.ps.breq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_opt_tot_len, {
		"Options Total Length", "extreme.ps.breq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_option, {
		"Option", "extreme.ps.breq.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_option_len, {
		"Length", "extreme.ps.breq.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_proxy_addr, {
		"Proxy Address", "extreme.ps.breq.proxy_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_old_mpr, {
		"Old MPR Addr", "extreme.ps.breq.old_mpr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_orig_pri, {
		"Orig Priority", "extreme.ps.breq.orig_pri", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_proxy_pri, {
		"Proxy Priority", "extreme.ps.breq.proxy_pri", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_vlan_id, {
		"VLAN ID", "extreme.ps.breq.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_proxy_vlan_id, {
		"Proxy VLAN ID", "extreme.ps.breq.proxy_vlan_id", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_breq_seq, {
		"Sequence", "extreme.ps.breq.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection bind reply */
	static hf_register_info hf_extreme_ps_brep[] = {
	{ &hf_extreme_ps_brep_version, {
		"Version", "extreme.ps.brep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_brep_frame_type, {
		"Frame Type", "extreme.ps.brep.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_brep_mpr_addr, {
		"MPR Addr", "extreme.ps.brep.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_brep_orig_addr, {
		"Orig Addr", "extreme.ps.brep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_brep_opt_tot_len, {
		"Options Total Length", "extreme.ps.brep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_brep_option, {
		"Option", "extreme.ps.brep.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_brep_option_len, {
		"Length", "extreme.ps.brep.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_brep_seq, {
		"Sequence", "extreme.ps.brep.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection bind announcement */
	static hf_register_info hf_extreme_ps_bann[] = {
	{ &hf_extreme_ps_bann_version, {
		"Version", "extreme.ps.bann.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_frame_type, {
		"Frame Type", "extreme.ps.bann.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_mpr_addr, {
		"MPR Addr", "extreme.ps.bann.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_orig_addr, {
		"Orig Addr", "extreme.ps.bann.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_opt_tot_len, {
		"Options Total Length", "extreme.ps.bann.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_option, {
		"Option", "extreme.ps.bann.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_option_len, {
		"Length", "extreme.ps.bann.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_proxy_addr, {
		"Proxy Addr", "extreme.ps.bann.proxy_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_old_root, {
		"Old Root", "extreme.ps.bann.old_root", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_vlan_id, {
		"Old Root Addr", "extreme.ps.bann.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bann_seq, {
		"Sequence", "extreme.ps.bann.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection bind removed */
	static hf_register_info hf_extreme_ps_bred[] = {
	{ &hf_extreme_ps_bred_version, {
		"Version", "extreme.ps.bred.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bred_frame_type, {
		"Frame Type", "extreme.ps.bred.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bred_mpr_addr, {
		"MPR Addr", "extreme.ps.bred.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bred_orig_addr, {
		"Orig Addr", "extreme.ps.bred.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bred_opt_tot_len, {
		"Options Total Length", "extreme.ps.bred.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bred_option, {
		"Option", "extreme.ps.bred.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bred_option_len, {
		"Length", "extreme.ps.bred.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_bred_seq, {
		"Sequence", "extreme.ps.bred.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection status request */
	static hf_register_info hf_extreme_ps_sreq[] = {
	{ &hf_extreme_ps_sreq_version, {
		"Version", "extreme.ps.sreq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_frame_type, {
		"Frame Type", "extreme.ps.sreq.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_reserved, {
		"Reserved", "extreme.ps.sreq.reserved", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_orig_addr, {
		"Orig Addr", "extreme.ps.sreq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_term_addr, {
		"Term", "extreme.ps.sreq.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_opt_tot_len, {
		"Options Total Length", "extreme.ps.sreq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_option, {
		"Option", "extreme.ps.sreq.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_option_len, {
		"Length", "extreme.ps.sreq.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_sreq_vlan_id, {
		"VLAN ID", "extreme.ps.sreq.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection status reply */
	static hf_register_info hf_extreme_ps_srep[] = {
	{ &hf_extreme_ps_srep_version, {
		"Version", "extreme.ps.srep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_frame_type, {
		"Frame Type", "extreme.ps.srep.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_flags, {
		"Flags", "extreme.ps.srep.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_flags_reserved, {
		"Reserved", "extreme.ps.srep.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFE, NULL, HFILL }},
	{ &hf_extreme_ps_srep_flags_status, {
		"Status Bit", "extreme.ps.srep.flags.status", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_ps_srep_hop_count, {
		"Hop Count", "extreme.ps.srep.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_orig_addr, {
		"Orig Addr", "extreme.ps.srep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_dest_addr, {
		"Dest Addr", "extreme.ps.srep.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_term_addr, {
		"Term Addr", "extreme.ps.srep.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_opt_tot_len, {
		"Options Total Length", "extreme.ps.srep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_option, {
		"Option", "extreme.ps.srep.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_option_len, {
		"Length", "extreme.ps.srep.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_srep_vlan_id, {
		"VLAN ID", "extreme.ps.srep.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection path request */
	static hf_register_info hf_extreme_ps_preq[] = {
	{ &hf_extreme_ps_preq_version, {
		"Version", "extreme.ps.preq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_frame_type, {
		"Frame Type", "extreme.ps.preq.type", FT_UINT8, BASE_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags, {
		"Flags", "extreme.ps.preq.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags_broadcast, {
		"Broadcast", "extreme.ps.preq.flags.broadcast", FT_UINT8, BASE_DEC,
		NULL, 0x80, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags_periodic, {
		"Periodic", "extreme.ps.preq.flags.periodic", FT_UINT8, BASE_DEC,
		NULL, 0x40, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags_state, {
		"State of the source node", "extreme.ps.preq.flags.state", FT_UINT8,
		BASE_DEC, NULL, 0x20, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags_reserved, {
		"Reserved", "extreme.ps.preq.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0x18, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags_gratuitous, {
		"Gratuitous PREP Flag", "extreme.ps.preq.flags.gtratuitous",
		FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags_destination, {
		"Destination only flag", "extreme.ps.preq.flags.destination",
		FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }},
	{ &hf_extreme_ps_preq_flags_unknown, {
		"Unknown sequence number", "extreme.ps.preq.flags.unknown", FT_UINT8,
		BASE_DEC, NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_ps_preq_hop_count, {
		"Hop Count", "extreme.ps.preq.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_ttl, {
		"TTL", "extreme.ps.preq.ttl", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_path_metrics, {
		"Path Metrics", "extreme.ps.preq.metrics", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_services, {
		"Services", "extreme.ps.preq.services", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_services_reserved, {
		"Reserved", "extreme.ps.preq.services.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xC0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_services_mobile, {
		"Mobile", "extreme.ps.preq.services.mobile", FT_UINT8, BASE_DEC,
		NULL, 0x20, NULL, HFILL }},
	{ &hf_extreme_ps_preq_services_path_pref, {
		"Path Preference", "extreme.ps.preq.services.path_pref", FT_UINT8,
		BASE_DEC, NULL, 0x18, NULL, HFILL }},
	{ &hf_extreme_ps_preq_services_geo, {
		"Geo", "extreme.ps.preq.services.geo", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extreme_ps_preq_services_proxy, {
		"Proxy", "extreme.ps.preq.services.proxy", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extreme_ps_preq_services_root, {
		"Root", "extreme.ps.preq.services.root", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_ps_preq_reserved, {
		"Reserved", "extreme.ps.preq.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_id, {
		"PREQ ID", "extreme.ps.preq.id", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_term_addr, {
		"Term Addr", "extreme.ps.preq.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_dest_addr, {
		"Dest Addr", "extreme.ps.preq.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_dest_seq, {
		"Dest Seq", "extreme.ps.preq.dest_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_orig_addr, {
		"Orig Addr", "extreme.ps.preq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_orig_seq, {
		"Orig Seq", "extreme.ps.preq.orig_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_opt_tot_len, {
		"Options Total Length", "extreme.ps.preq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_option, {
		"Option", "extreme.ps.preq.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_option_len, {
		"Length", "extreme.ps.preq.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_mcast_sub, {
		"MCAST Sub", "extreme.ps.preq.mcast_sub", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_vlan_id, {
		"VLAN ID", "extreme.ps.preq.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_preq_mint_id, {
		"Mint ID", "extreme.ps.preq.mint_id", FT_UINT32, BASE_HEX,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection path reply */
	static hf_register_info hf_extreme_ps_prep[] = {
	{ &hf_extreme_ps_prep_version, {
		"Version", "extreme.ps.prep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_frame_type, {
		"Frame Type", "extreme.ps.prep.type", FT_UINT8, BASE_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_flags, {
		"Flags", "extreme.ps.prep.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_flags_reserved, {
		"Reserved", "extreme.ps.prep.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xF8, NULL, HFILL }},
	{ &hf_extreme_ps_prep_flags_new_route, {
		"New Route", "extreme.ps.prep.flags.new_route", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extreme_ps_prep_flags_repair, {
		"Repair Flag", "extreme.ps.prep.flags.repair", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extreme_ps_prep_flags_ack, {
		"Acknowledgement Required", "extreme.ps.prep.flags.ack", FT_UINT8,
		BASE_DEC, NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_ps_prep_hop_count, {
		"Hop Count", "extreme.ps.prep.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_path_metrics, {
		"Path Metrics", "extreme.ps.prep.metrics", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_services, {
		"Services", "extreme.ps.prep.services", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_services_reserved, {
		"Reserved", "extreme.ps.prep.services.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xC0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_services_mobile, {
		"Mobile", "extreme.ps.prep.services.mobile", FT_UINT8, BASE_DEC,
		NULL, 0x20, NULL, HFILL }},
	{ &hf_extreme_ps_prep_services_path_pref, {
		"Path Preference", "extreme.ps.prep.services.path_pref", FT_UINT8,
		BASE_DEC, NULL, 0x18, NULL, HFILL }},
	{ &hf_extreme_ps_prep_services_geo, {
		"Geo", "extreme.ps.prep.services.geo", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extreme_ps_prep_services_proxy, {
		"Proxy", "extreme.ps.prep.services.proxy", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extreme_ps_prep_services_root, {
		"Root", "extreme.ps.prep.services.root", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_ps_prep_reserved, {
		"Reserved", "extreme.ps.prep.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_term_addr, {
		"Term Addr", "extreme.ps.prep.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_dest_addr, {
		"Dest Addr", "extreme.ps.prep.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_dest_seq, {
		"Dest Seq", "extreme.ps.prep.dest_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_orig_addr, {
		"Orig Addr", "extreme.ps.prep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_orig_seq, {
		"Orig Seq", "extreme.ps.prep.orig_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_lifetime, {
		"Lifetime", "extreme.ps.prep.lifetime", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_opt_tot_len, {
		"Options Total Length", "extreme.ps.prep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_option, {
		"Option", "extreme.ps.prep.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_option_len, {
		"Length", "extreme.ps.prep.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_mcast_sub, {
		"MCAST Sub", "extreme.ps.prep.mcast_sub", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_vlan_id, {
		"VLAN ID", "extreme.ps.prep.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prep_mint_id, {
		"Mint ID", "extreme.ps.prep.mint_id", FT_UINT32, BASE_HEX,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection path error */
	static hf_register_info hf_extreme_ps_perr[] = {
	{ &hf_extreme_ps_perr_version, {
		"Version", "extreme.ps.perr.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_perr_frame_type, {
		"Frame Type", "extreme.ps.perr.type", FT_UINT8, BASE_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_perr_flags, {
		"Flags", "extreme.ps.perr.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_perr_flags_reserved, {
		"Reserved", "extreme.ps.perr.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFC, NULL, HFILL }},
	{ &hf_extreme_ps_perr_flags_warning, {
		"Warning", "extreme.ps.perr.flags.warning", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extreme_ps_perr_flags_no_delete, {
		"No Delete", "extreme.ps.perr.flags.no_delete", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_ps_perr_dest_count, {
		"Dest Count", "extreme.ps.perr.dest_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_perr_unrch_dest, {
		"Unrch Dest", "extreme.ps.perr.unrch_dest", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_perr_unrch_dest_seq, {
		"Unrch Dest Seq", "extreme.ps.perr.unrch_dest_seq", FT_UINT32,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	};

	/* extreme mesh path selection path reset */
	static hf_register_info hf_extreme_ps_prst[] = {
	{ &hf_extreme_ps_prst_version, {
		"Version", "extreme.ps.prst.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prst_frame_type, {
		"Frame Type", "extreme.ps.prst.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prst_hops_to_live, {
		"Hops To Live", "extreme.ps.prst.hops_to_live", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prst_reserved, {
		"Reserved", "extreme.ps.prst.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prst_id, {
		"PRST ID", "extreme.ps.prst.id", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prst_orig_addr, {
		"Orig Addr", "extreme.ps.prst.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prst_dest_addr, {
		"Dest Addr", "extreme.ps.prst.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	};

	/* extreme mesh path selection proxy remove */
	static hf_register_info hf_extreme_ps_prem[] = {
	{ &hf_extreme_ps_prem_version, {
		"Version", "extreme.ps.prem.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_frame_type, {
		"Frame Type", "extreme.ps.prem.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_mpr_addr, {
		"MPR Addr", "extreme.ps.prem.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_orig_addr, {
		"Orig Addr", "extreme.ps.prem.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_opt_tot_len, {
		"Options Total Length", "extreme.ps.prem.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_option, {
		"Option", "extreme.ps.prem.option", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_option_len, {
		"Length", "extreme.ps.prem.option_len", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_proxy_addr, {
		"Proxy Addr", "extreme.ps.prem.proxy_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prem_proxy_vlan_id, {
		"VLAN ID", "extreme.ps.prem.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh path selection trace path */
	static hf_register_info hf_extreme_ps_trace[] = {
	{ &hf_extreme_ps_trace_version, {
		"Version", "extreme.ps.trace.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_trace_frame_type, {
		"Frame Type", "extreme.ps.trace.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_trace_flags, {
		"Flags", "extreme.ps.trace.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_trace_flags_reserved, {
		"Reserved", "extreme.ps.trace.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFC, NULL, HFILL }},
	{ &hf_extreme_ps_trace_flags_reply, {
		"Reply Flag", "extreme.ps.trace.flags.reply", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extreme_ps_trace_flags_no_path, {
		"No Path Flag", "extreme.ps.trace.flags.no_path", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_ps_trace_dest_addr, {
		"Dest Addr", "extreme.ps.trace.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_trace_orig_addr, {
		"Orig Addr", "extreme.ps.trace.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_trace_hop_count, {
		"Hop Count", "extreme.ps.trace.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_trace_addl_path, {
		"Addl Path", "extreme.ps.trace.addl_path", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	};

	/* extreme mesh path selection proxy error */
	static hf_register_info hf_extreme_ps_prer[] = {
	{ &hf_extreme_ps_prer_version, {
		"Version", "extreme.ps.prer.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_frame_type, {
		"Frame Type", "extreme.ps.prer.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_dest_count, {
		"Dest Count", "extreme.ps.prer.dest_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_reserved, {
		"Reserved", "extreme.ps.prer.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_orig_addr, {
		"Orig Addr", "extreme.ps.prer.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_dest_addr, {
		"Dest Addr", "extreme.ps.prer.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_unrch_addr, {
		"Unrch Proxy", "extreme.ps.prer.unrch_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_opt_tot_len, {
		"Options Total Length", "extreme.ps.prer.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_option, {
		"Option", "extreme.ps.prer.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_option_len, {
		"Length", "extreme.ps.prer.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_ps_prer_vlan_id, {
		"VLAN ID", "extreme.ps.prer.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh L2 update */
	static hf_register_info hf_extreme_l2upd[] = {
	{ &hf_extreme_l2upd_proxy_owner, {
		"Proxy Owner Addr", "extreme.l2upd.proxy_owner", FT_ETHER,
		BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_l2upd_ballast, {
		"Ballast", "extreme.l2upd.ballast", FT_BYTES, BASE_NONE,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extreme mesh probe message */
	static hf_register_info hf_extreme_probe[] = {
	{ &hf_extreme_probe_version, {
		"Version", "extreme.probe.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_probe_op_code, {
		"Op-code", "extreme.probe.op_code", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_probe_flags, {
		"Flags", "extreme.probe.flags", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_probe_flags_reserved, {
		"Reserved", "extreme.probe.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFE, NULL, HFILL }},
   { &hf_extreme_probe_flags_reply, {
		"Reply", "extreme.probe.flags.reply", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extreme_probe_priority, {
		"Priority", "extreme.probe.priority", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_probe_job_id, {
		"Job ID", "extreme.probe.job_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_probe_sequence, {
		"Sequence Number", "extreme.probe.sequence", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_probe_ballast_len, {
		"Ballast Length", "extreme.probe.ballast_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extreme_probe_ballast, {
		"Ballast", "extreme.probe.ballast", FT_BYTES, BASE_NONE,
		NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_extreme_mesh,
		&ett_extreme_mch,
		&ett_extreme_hello,
		&ett_extreme_security,
		&ett_extreme_cfpu,
		&ett_extreme_eapom,
		&ett_extreme_ps
	};

	/* registration */
	/* extreme mesh */
	proto_extreme_mesh = proto_register_protocol("Extreme Mesh", "EXTREME MESH", "extreme_mesh");
	proto_register_field_array(proto_extreme_mesh, hf_extreme_mesh, array_length(hf_extreme_mesh));
	proto_register_subtree_array(ett, array_length(ett));

	/* extreme mesh control header */
	proto_extreme_mch = proto_register_protocol("Extreme Mesh Control Header", "EXTREME MCH", "extreme_mch");
	proto_register_field_array(proto_extreme_mch, hf_extreme_mch, array_length(hf_extreme_mch));


	/* extreme hello */
	proto_extreme_hello = proto_register_protocol("Extreme Hello", "EXTREME HELLO", "extreme_hello");
	proto_register_field_array(proto_extreme_hello, hf_extreme_hello, array_length(hf_extreme_hello));

	/* extreme security */
	proto_extreme_security = proto_register_protocol("Extreme Security", "EXTREME SECURITY", "extreme_security");
	proto_register_field_array(proto_extreme_security, hf_extreme_security, array_length(hf_extreme_security));

	/* extreme contention free period (CFP) update */
	proto_extreme_cfpu = proto_register_protocol("Extreme Cfpu", "EXTREME CFPU", "extreme_cfpu");
	proto_register_field_array(proto_extreme_cfpu, hf_extreme_cfpu, array_length(hf_extreme_cfpu));

	/* extreme EAP over mesh */
	proto_extreme_eapom = proto_register_protocol("Extreme EAPOM", "EXTREME EAPOM", "extreme_eapom");
	proto_register_field_array(proto_extreme_eapom, hf_extreme_eapom, array_length(hf_extreme_eapom));

	/* extreme mesh L2 update */
	proto_extreme_l2upd = proto_register_protocol("Extreme Mesh L2 Update", "EXTREME L2UPD", "extreme_l2upd");
	proto_register_field_array(proto_extreme_l2upd, hf_extreme_l2upd, array_length(hf_extreme_l2upd));
	/* extreme mesh probe message */
	proto_extreme_probe = proto_register_protocol("Extreme Mesh Probe Message", "EXTREME PROBE", "extreme_probe");
	proto_register_field_array(proto_extreme_probe, hf_extreme_probe, array_length(hf_extreme_probe));

	/* extreme mesh path selection authorization request */
	proto_extreme_ps_areq = proto_register_protocol("Extreme Mesh Path Selection Authorization Request", "EXTREME PS AREQ", "extreme_ps_areq");
	proto_register_field_array(proto_extreme_ps_areq, hf_extreme_ps_areq, array_length(hf_extreme_ps_areq));

	/* extreme mesh path selection authorization reply */
	proto_extreme_ps_arep = proto_register_protocol("Extreme Mesh Path Selection Authorization Reply", "EXTREME PS AREP", "extreme_ps_arep");
	proto_register_field_array(proto_extreme_ps_arep, hf_extreme_ps_arep, array_length(hf_extreme_ps_arep));

	/* extreme mesh path selection bind request */
	proto_extreme_ps_breq = proto_register_protocol("Extreme Mesh Path Selection Bind Request", "EXTREME PS BREQ", "extreme_ps_breq");
	proto_register_field_array(proto_extreme_ps_breq, hf_extreme_ps_breq, array_length(hf_extreme_ps_breq));

	/* extreme mesh path selection bind reply */
	proto_extreme_ps_brep = proto_register_protocol("Extreme Mesh Path Selection Bind Reply", "EXTREME PS BREP", "extreme_ps_brep");
	proto_register_field_array(proto_extreme_ps_brep, hf_extreme_ps_brep, array_length(hf_extreme_ps_brep));

	/* extreme mesh path selection bind announcement */
	proto_extreme_ps_bann = proto_register_protocol("Extreme Mesh Path Selection Bind Announcement", "EXTREME PS BANN", "extreme_ps_bann");
	proto_register_field_array(proto_extreme_ps_bann, hf_extreme_ps_bann, array_length(hf_extreme_ps_bann));

	/* extreme mesh path selection bind removed */
	proto_extreme_ps_bred = proto_register_protocol("Extreme Mesh Path Selection Bind Removed", "EXTREME PS BRED", "extreme_ps_bred");
	proto_register_field_array(proto_extreme_ps_bred, hf_extreme_ps_bred, array_length(hf_extreme_ps_bred));

	/* extreme mesh path selection status request */
	proto_extreme_ps_sreq = proto_register_protocol("Extreme Mesh Path Selection Status Request", "EXTREME PS SREQ", "extreme_ps_sreq");
	proto_register_field_array(proto_extreme_ps_sreq, hf_extreme_ps_sreq, array_length(hf_extreme_ps_sreq));

	/* extreme mesh path selection status reply */
	proto_extreme_ps_srep = proto_register_protocol("Extreme Mesh Path Selection Status Reply", "EXTREME PS SREP", "extreme_ps_srep");
	proto_register_field_array(proto_extreme_ps_srep, hf_extreme_ps_srep, array_length(hf_extreme_ps_srep));

	/* extreme mesh path selection path request */
	proto_extreme_ps_preq = proto_register_protocol("Extreme Mesh Path Selection Path Request", "EXTREME PS PREQ", "extreme_ps_preq");
	proto_register_field_array(proto_extreme_ps_preq, hf_extreme_ps_preq, array_length(hf_extreme_ps_preq));

	/* extreme mesh path selection path reply */
	proto_extreme_ps_prep = proto_register_protocol("Extreme Mesh Path Selection Path Reply", "EXTREME PS PREP", "extreme_ps_prep");
	proto_register_field_array(proto_extreme_ps_prep, hf_extreme_ps_prep, array_length(hf_extreme_ps_prep));

	/* extreme mesh path selection path error */
	proto_extreme_ps_perr = proto_register_protocol("Extreme Mesh Path Selection Path Error", "EXTREME PS PERR", "extreme_ps_perr");
	proto_register_field_array(proto_extreme_ps_perr, hf_extreme_ps_perr, array_length(hf_extreme_ps_perr));

	/* extreme mesh path selection path reset */
	proto_extreme_ps_prst = proto_register_protocol("Extreme Mesh Path Selection Path Reset", "EXTREME PS PRST", "extreme_ps_prst");
	proto_register_field_array(proto_extreme_ps_prst, hf_extreme_ps_prst, array_length(hf_extreme_ps_prst));

	/* extreme mesh path selection proxy remove */
	proto_extreme_ps_prem = proto_register_protocol("Extreme Mesh Path Selection Proxy Remove", "EXTREME PS PREM", "extreme_ps_prem");
	proto_register_field_array(proto_extreme_ps_prem, hf_extreme_ps_prem, array_length(hf_extreme_ps_prem));

	/* extreme mesh path selection trace path */
	proto_extreme_ps_trace = proto_register_protocol("Extreme Mesh Path Selection Trace Path", "EXTREME PS TRACE", "extreme_ps_trace");
	proto_register_field_array(proto_extreme_ps_trace, hf_extreme_ps_trace, array_length(hf_extreme_ps_trace));

	/* extreme mesh path selection proxy error */
	proto_extreme_ps_prer = proto_register_protocol("Extreme Mesh Path Selection Proxy Error", "EXTREME PS PRER", "extreme_ps_prer");
	proto_register_field_array(proto_extreme_ps_prer, hf_extreme_ps_prer, array_length(hf_extreme_ps_prer));
}

/*****************************************************************************/
/*

Register Extreme Mesh Handoff

Description:

Initializes the dissector by creating a handle and adding it to the
dissector table.

*/
/*****************************************************************************/
void proto_reg_handoff_extrememesh(void)
{
	static dissector_handle_t extrememesh_handle;

	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

	extrememesh_handle = create_dissector_handle(dissect_extrememesh, proto_extreme_mesh);
	dissector_add_uint("ethertype", ETHERTYPE_IEEE_EXTREME_MESH, extrememesh_handle);
}
