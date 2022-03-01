/* packet-axe-rpc.c
 * Martin Mathieson
 * RPC programs used in AXE
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>

#include "config.h"
#include <epan/packet.h>

#include "packet-rpc.h"


static dissector_handle_t axe_rpc_handle;

static dissector_handle_t json_dissector_handle;

/*******************************/
/* axe-rpc fields             */
static int proto_axe_rpc           = -1;

static int hf_axe_rpc_port_v1      = -1;

static int hf_axe_rpc_chassis_v1   = -1;
static int hf_axe_rpc_chassis_v2   = -1;

static int hf_axe_rpc_schema = -1;
static int hf_axe_rpc_version_list = -1;
static int hf_axe_rpc_version = -1;
static int hf_axe_rpc_entity_type = -1;
static int hf_axe_rpc_entity_name = -1;
static int hf_axe_rpc_revision_num = -1;
static int hf_axe_rpc_date = -1;
static int hf_axe_rpc_build_string = -1;

static int hf_axe_rpc_messageid = -1;
static int hf_axe_rpc_timestamp = -1;
static int hf_axe_rpc_messagecode = -1;
static int hf_axe_rpc_instance = -1;
static int hf_axe_rpc_debug = -1;

// blobrecv2 (CommandMessage)

// message header fields.
static int hf_axe_rpc_message_header = -1;

static int hf_axe_rpc_commandmessage_id = -1;
static int hf_axe_rpc_commandmessage_len = -1;
static int hf_axe_rpc_commandmessage_time = -1;
static int hf_axe_rpc_commandmessage_code = -1;

static int hf_axe_rpc_commandmessage_component = -1;


static int hf_axe_rpc_portresource_count = -1;
static int hf_axe_rpc_portresource_address = -1;
static int hf_axe_rpc_portresource_port = -1;
static int hf_axe_rpc_portresource_data = -1;

static int hf_axe_rpc_stack_id = -1;

static int hf_axe_rpc_status  = -1;

static int hf_axe_rpc_mgmt  = -1;
static int hf_axe_rpc_chassis_hostname  = -1;
static int hf_axe_rpc_chassis_description  = -1;
static int hf_axe_rpc_chassis_pcb_rev  = -1;

static int hf_axe_rpc_chassis_address  = -1;
static int hf_axe_rpc_chassis_gid  = -1;
static int hf_axe_rpc_chassis_uid  = -1;
static int hf_axe_rpc_chassis_fpga_id  = -1;
static int hf_axe_rpc_chassis_cpld_id  = -1;
static int hf_axe_rpc_chassis_port_status  = -1;
static int hf_axe_rpc_chassis_uptime  = -1;
static int hf_axe_rpc_chassis_swreg  = -1;
static int hf_axe_rpc_chassis_reserved  = -1;

static int hf_axe_rpc_chassis_ports_len = -1;
static int hf_axe_rpc_chassis_port = -1;
static int hf_axe_rpc_chassis_pdi1_id = -1;
static int hf_axe_rpc_chassis_pdi2_id = -1;
static int hf_axe_rpc_chassis_pdi3_id = -1;
static int hf_axe_rpc_chassis_pdi4_id = -1;
static int hf_axe_rpc_chassis_pdi5_id = -1;
static int hf_axe_rpc_chassis_pdi6_id = -1;
static int hf_axe_rpc_chassis_pdi7_id = -1;
static int hf_axe_rpc_chassis_pdi8_id = -1;
static int hf_axe_rpc_chassis_status_a = -1;
static int hf_axe_rpc_chassis_status_b = -1;
static int hf_axe_rpc_chassis_status_c = -1;
static int hf_axe_rpc_chassis_status_d = -1;

static int hf_axe_rpc_chassis_dhcp_config = -1;
static int hf_axe_rpc_chassis_build_date = -1;
static int hf_axe_rpc_chassis_min_build = -1;
static int hf_axe_rpc_chassis_current_ip_address = -1;
static int hf_axe_rpc_chassis_current_netmask = -1;
static int hf_axe_rpc_chassis_current_gateway = -1;
static int hf_axe_rpc_chassis_static_ip_address = -1;
static int hf_axe_rpc_chassis_static_netmask = -1;
static int hf_axe_rpc_chassis_static_gateway = -1;



static int hf_axe_rpc_chassis_card_pcb_rev = -1;
static int hf_axe_rpc_chassis_port_pcb_rev = -1;
static int hf_axe_rpc_model_name  = -1;
static int hf_axe_rpc_firmware_rev = -1;
static int hf_axe_rpc_recovery_rev = -1;
static int hf_axe_rpc_schema_min  = -1;
static int hf_axe_rpc_schema_max  = -1;

static int hf_axe_rpc_chassis_services_len = -1;
static int hf_axe_rpc_chassis_service = -1;

static int hf_axe_rpc_chassis_service_type = -1;
static int hf_axe_rpc_chassis_service_ip_slot = -1;

static int hf_axe_rpc_chassis_service_part_code = -1;
static int hf_axe_rpc_chassis_service_part_code_version = -1;
static int hf_axe_rpc_chassis_service_part_code_tag = -1;
static int hf_axe_rpc_chassis_service_part_code_phy_type = -1;
static int hf_axe_rpc_chassis_service_part_code_phy_elems = -1;
static int hf_axe_rpc_chassis_service_part_code_phy_caps = -1;
static int hf_axe_rpc_chassis_service_part_code_series = -1;
static int hf_axe_rpc_chassis_service_part_code_gen_caps = -1;
static int hf_axe_rpc_chassis_service_part_code_wifi_regions = -1;
static int hf_axe_rpc_chassis_service_part_code_reserved = -1;



static int hf_axe_rpc_chassis_service_port_set_info = -1;

static int hf_axe_rpc_chassis_rpc_info_len = -1;
static int hf_axe_rpc_chassis_rpc = -1;
static int hf_axe_rpc_chassis_rpc_prognum = -1;
static int hf_axe_rpc_chassis_rpc_progver = -1;
static int hf_axe_rpc_chassis_rpc_service_num = -1;



/* Subtrees. */
static int ett_axe_rpc = -1;
static int ett_axe_rpc_mgmt = -1;
static int ett_axe_rpc_port = -1;
static int ett_axe_rpc_service = -1;
static int ett_axe_rpc_rpc = -1;
static int ett_axe_rpc_version = -1;
static int ett_axe_rpc_message_header = -1;
static int ett_axe_rpc_part_code = -1;


/* Forward declarations we need below */
void proto_register_axe_rpc(void);
void proto_reg_handoff_axe_rpc(void);
static gint dissect_axe_rpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static const value_string entity_type_vals[] = {
    { 0,		     "TGA Board" },
    { 1,		     "PP FPGA" },
    { 2,		     "CP FPGA" },
    { 3,		     "CPLD" },
    { 4,		     "Port Server" },
    { 5,		     "TGA Driver" },
    { 6,		     "Log Driver" },
    { 7,		     "Ministacks" },
    { 8,		     "Recovery Server" },
    { 10,		     "WPA Supplicant" },
    { 11,		     "Recovery Level" },
    { 12,		     "Loader Version"  },
    { 0, NULL }
};

// See #defines in ./fw-axe/shared/include/wtrpc/message.h
// TODO: loads missed out - only adding on demand..
static const value_string messagecode_vals[] = {
    { 0x0001,            "PORT_SETUP" },
    { 0x0002,            "MII_MESSAGE"},
    { 0x0003,            "MII_READBACK"},
    { 0x0004,            "PATTERN_SETUP"},
    { 0x0005,            "PATTERN_READBACK"},
    { 0x0006,            "PORT_BSSID"},
    { 0x0007,            "PORT_BSS_CLEAR"},
    { 0x000F,            "PORT_BUSY"},
    { 0x0010,            "PORT_INIT"},
    { 0x0011,            "PORT_SCAN"},
    { 0x0014,            "PORT_RADIO_EN"},
    { 0x0015,            "PORT_RADIO_DIS" },
    { 0x0016,            "PORT_LINK_UP" },
    { 0x0017,            "PORT_LINK_DOWN" },
    { 0x0018,            "PORT_TCP_ENABLE" },
    { 0x0020,            "PORT_LATENCY_DELAY" },
    { 0x0021,            "PORT_LATENCY_DELAY_RDBK" },
    { 0x0023,            "PORT_GET_LINK_RDBK" },
    { 0x0034,            "PORT_IP6_INFO_READBACK" },
    { 0x008A,            "READ RESOURCE (REG)" },
    { 0x008B,            "WRITE RESOURCE (REG)" },
    { 0x00F0,            "PORT_RESERVE" },
    { 0x00F1,            "PORT_RELEASE" },
    { 0x00F2,            "PORT_RESERVE_QUERY" },
    { 0x00F3,            "PORT_ALIAS" },
    { 0x00F6,            "PORT_QUERY_FPGA_INFO_MESSAGE" },
    { 0x0301,            "ACTIVE_COUNT_MESSAGE" },

    // Same as above, but reply versions.
    { 0x8001,            "PORT_SETUP REPLY" },
    { 0x8002,            "MII_MESSAGE REPLY"},
    { 0x8003,            "MII_READBACK REPLY"},
    { 0x8004,            "PATTERN_SETUP REPLY"},
    { 0x8005,            "PATTERN_READBACK REPLY"},
    { 0x8006,            "PORT_BSSID REPLY"},
    { 0x8007,            "PORT_BSS_CLEAR REPLY"},
    { 0x800F,            "PORT_BUSY REPLY"},
    { 0x8010,            "PORT_INIT REPLY"},
    { 0x8011,            "PORT_SCAN REPLY"},
    { 0x8014,            "PORT_RADIO_EN REPLY"},
    { 0x8015,            "PORT_RADIO_DIS REPLY" },
    { 0x8016,            "PORT_LINK_UP REPLY" },
    { 0x8017,            "PORT_LINK_DOWN REPLY" },
    { 0x8018,            "PORT_TCP_ENABLE REPLY" },
    { 0x8020,            "PORT_LATENCY_DELAY REPLY" },
    { 0x8021,            "PORT_LATENCY_DELAY_RDBK REPLY" },
    { 0x8023,            "PORT_GET_LINK_RDBK REPLY" },
    { 0x8034,            "PORT_IP6_INFO_READBACK REPLY" },
    { 0x808A,            "READ RESOURCE (REG) REPLY" },
    { 0x808B,            "WRITE RESOURCE (REG) REPLY" },
    { 0x80F0,            "PORT_RESERVE REPLY" },
    { 0x80F1,            "PORT_RELEASE REPLY" },
    { 0x80F2,            "PORT_RESERVE_QUERY REPLY" },
    { 0x80F3,            "PORT_ALIAS REPLY" },
    { 0x80F6,            "PORT_QUERY_FPGA_INFO_MESSAGE REPLY" },
    { 0x8301,            "ACTIVE_COUNT_MESSAGE REPLY" },

    // TODO: add others (to both).
    { 0, NULL }
};

// N.B. These fields are taken from fw-axe/shared/include/vw/part_code.h
static const value_string part_code_version_vals[] = {
    { 0,            "Unused" },
    { 1,            "Same layout as v2, indicates series 1 card" },
    { 2,            "Current layout, indicates series 2 or later card" },
    { 0, NULL }
};

static const value_string part_code_tag_vals[] = {
    { 0x8,            "Generated by fallback mechanism in web interface" },
    { 0x9,            "Generated by fallback mechanism on ports" },
    { 0xa,            "Standard manufacturing mark" },
    { 0xb,            "Reserved for manufacturing" },
    { 0xc,            "Reserved for manufacturing" },
    { 0xd,            "Reserved for manufacturing" },
    { 0xe,            "Engineering marked card" },
    { 0xf,            "Faulty hardware, may perform in limited capacity" },
    { 0, NULL }
};

static const value_string part_code_phy_type_vals[] = {
    { 0,            "None" },
    { 1,            "Ethernet" },
    { 2,            "Wireless ABG" },
    { 3,            "Wireless N" },
    { 4,            "Wireless AC" },
    { 5,            "Wireless Double wide AC" },
    { 6,            "Wireless Double wide AX" },
    { 0, NULL }
};

static const value_string part_code_phy_caps_vals[] = {
    { 0x08,         "Two radios with same phy_type and phy_elems" },
    { 0x04,         "Waveanalyze capable (WZ)" },
    { 0x02,         "Wavegen capable (WG)" },
    { 0x01,         "High power range" },
    { 0, NULL }
};

static const value_string part_code_series_vals[] = {
    { 3,            "First card to use series field (IPv6 capable hw series 2 card)" },
    { 4,            "HW series 3 cards" },
    { 5,            "Was skipped for unknown reasons" },
    { 6,            "HW series 6 cards with 11AC SISO load" },
    { 7,            "HW series 6 cards with 11AC MIMO load (mixture of beam forming and no beam forming)" },
    { 8,            "HW series 6 cards with 11AC MIMO load and NO beam forming capability" },
    { 9,            "DWAC hardware platform cards (RFX5, WBX5 and WBL5, WBI5, AXM)" },
    { 10,           "AXE hardware platform" },
    { 0, NULL }
};

static const value_string part_code_gen_caps_vals[] = {
    { 0x08,         "IPv6 enabled (series 3 or later only)" },
    { 0x04,         "Require License. License(s) are needed for some feature" },
    { 0x02,         "AP port (series 4 or later only)" },
    { 0x01,         "Reserved" },
    { 0, NULL }
};

static const value_string part_code_wifi_regions_vals[] = {
    { 0,            "Default region (compatibility region)" },
    { 1,            "United Stated/Canada" },
    { 2,            "Europe Union/Japan/Turkey/South Africa" },
    { 3,            "China" },
    { 4,            "Australia" },
    { 5,            "Korea" },
    { 6,            "Israel" },
    { 7,            "Singapore/India" },
    { 8,            "Brazil" },
    { 0, NULL }
};




// Stack IDs are defined in ./shared/include/vw/stack_id.h
/******************************************************************************
 * STACK TYPES
 *
 * THESE SHOULD ALWAYS BE EVEN (except for the roaming variant, which should
 * occupy the next higher index - e.g., STACK_WPAS + STACK_WPAS_ROAM). Also,
 * valid stack types must be >= 10.
 *
 * See the various definitions of wtrpc_stack_service() to understand the basis
 * of this arcana.
 *
 * NOTE: a 16-bit stack ID is formed from an 8-bit stack type (in the LSbyte) and
 * an 8-bit stack index (in the MSbyte) */
#define STACK_WPAS          10
#define STACK_WPAS_ROAM     11
#define STACK_L7APP         12
#define STACK_L7APP_ROAM    13
#define STACK_WEBAUTH       14
#define STACK_FORWARD       16
#define STACK_AGENT         18
#define STACK_AGENT_ROAM    19
#define STACK_BROKER        20
#define STACK_WAD           22
#define STACK_FNE_WBM       25
#define STACK_WLAND         26
#define STACK_WLAND_ROAM    27
#define STACK_ED            28
#define STACK_WTCARD        29
#define STACK_TEMPD                     30
/* MUST be the last definition */
#define STACK_MAX_COUNT     31

static const value_string stackid_vals[] = {
    { STACK_WPAS,            "WPAS" },
    { STACK_WPAS_ROAM,       "WAPS ROAM"},
    { STACK_L7APP,           "L7APP"},
    { STACK_L7APP_ROAM,      "L7APP RAOM"},
    { STACK_WEBAUTH,         "WEBAUTH"},
    { STACK_FORWARD,         "FORWARD"},
    { STACK_AGENT,           "AGENT"},
    { STACK_AGENT_ROAM,      "AGENT ROAM"},
    { STACK_BROKER,          "BROKER"},
    { STACK_WAD,             "WAD"},
    { STACK_WLAND,           "WLAND"},
    { STACK_WLAND_ROAM,      "WLAND ROAM"},
    { STACK_ED,              "ED"},
    { STACK_TEMPD,           "TEMPD"},
    { 0, NULL }
};

// This is enum dhcp_config from port_if.x
static const value_string dhcp_config_vals[] = {
    { 0,            "Static IP" },
    { 1,            "Hybrid DHCP" },
    { 2,            "Hybrid DHCP USB PPP Windows" },
    { 3,            "Hybrid DHCP USB PPP Linux" },
    { 4,            "Static IP USB PPP Windows" },
    { 5,            "Static IP USB PPP Linux" },
    { 0, NULL }
};




static int dissect_1_in_4(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_item, int chars, char *string)
{
    //printf("%u: dissect_1_in_4(offset=%d) chars=%d\n", pinfo->num, offset, chars);
    tvbuff_t *string_tvb = tvb_new_subset_length_caplen(tvb, offset, chars*4, chars*4);

    static char buffer[128];
    guint chars_written = 0;
    for (int n=0; n < tvb_captured_length_remaining(string_tvb, n); n+=4) {
        char byte = (char)tvb_get_guint8(string_tvb, n+3);
        buffer[chars_written++] = byte;
        if (!byte) {
            //printf("Getting out of string at n=%d\n", n+3);
            break;
        }
    }
    if (string) {
        g_strlcpy(string, buffer, 128);
    }

    // TODO: terminate if reached end eithout seeing NULL char?
    proto_tree_add_string(tree, hf_item, tvb, offset, chars*4, buffer);

    return tvb_captured_length(tvb);
}

/* Actually an array of chars... */
static int dissect_char_array(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int hf_item, int offset, int chars, char *string)
{
    dissect_1_in_4(tvb, offset, pinfo, tree, hf_item, chars, string);
    return chars*4;
}


static int dissect_ip_address(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, int hf_item, int offset, guint32 *ip)
{
    //printf("%u: dissect_ip_address(offset=%d) chars=%d\n", pinfo->num, offset, chars);
    tvbuff_t *ip_tvb = tvb_new_subset_length_caplen(tvb, offset, 4*4, 4*4);

    // Extract the 4 octets.
    guint8 octets[4];
    for (int n=0; tvb_captured_length_remaining(ip_tvb, n) >= 4; n+=4) {
        guint8 byte = tvb_get_guint8(ip_tvb, n+3);
        octets[(n+1)/4] = byte;
        // TODO: needed?
        if (n == 12) {
            break;
        }
    }

    // N.B. Extra temp used to avoid type-punning error.
    guint32 *ptr = (guint32*)&octets;
    guint32 temp_ip = *ptr;

    // Add item.
    proto_tree_add_ipv4(tree, hf_item, tvb, offset, 4*4, temp_ip);
    // Set output param.
    *ip = temp_ip;

    return tvb_captured_length(ip_tvb);
}


/* See struct MessageHeader in fw-axe/shared/include/wtrpc/message.h */
static int dissect_message_header(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint32 *code)
{
    /* TODO: do in subheader with msgcode string in parent? */
    int start_offset = offset;

	/* Create subtree */
	proto_item *mh_ti = proto_tree_add_string_format(tree, hf_axe_rpc_message_header,
							  tvb, offset, 0, "", "Message Header");
	proto_tree *mh_tree = proto_item_add_subtree(mh_ti, ett_axe_rpc_message_header);

    /* id */
    proto_tree_add_item(mh_tree, hf_axe_rpc_commandmessage_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* len */
    guint32 len;
    proto_tree_add_item_ret_uint(mh_tree, hf_axe_rpc_commandmessage_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
    offset += 2;
    /* time */
    proto_tree_add_item(mh_tree, hf_axe_rpc_commandmessage_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // TODO: ????
    offset += 4;

    /* code */
    proto_tree_add_item_ret_uint(mh_tree, hf_axe_rpc_commandmessage_code, tvb, offset, 2, ENC_BIG_ENDIAN, code);
    offset += 2;
    /* schema */
    proto_tree_add_item(mh_tree, hf_axe_rpc_schema, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    // Skip reserved.
    offset += 4;

    proto_item_append_text(mh_ti, " (%s len=%u)", val_to_str_const(*code, messagecode_vals, "Unknown"), len);
    proto_item_set_len(mh_ti, offset-start_offset);

    return offset;
}


/*********************************************/
/* Dissection of specific messages types     */

static int dissect_port_v1_hello(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint offset = 0;

    // Schema
    guint schema = tvb_get_ntohl(tvb, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_axe_rpc_schema, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (schema=%u)", schema);

    return tvb_reported_length(tvb);
}

static int dissect_port_v1_blobrecv_call(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint offset = 0;

    /* MessageHeader */
    guint32 messagecode;
    offset = dissect_message_header(tvb, offset, pinfo, tree, &messagecode);

    // TODO:

    return offset;
}

// TODO: rename, as also used for blobsend.
static int dissect_port_v1_blobrecv2_call(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* d _U_)
{
    gint offset = 0;

    // Status
    offset = dissect_rpc_uint32(tvb, tree, hf_axe_rpc_status, offset);

    // TODO: blob is a CommandMessage. If so, 32-bit component should follow..
    //

    /* MessageHeader */
    guint32 messagecode;
    offset = dissect_message_header(tvb, offset, pinfo, tree, &messagecode);

    guint32 count, addr, port, data;

    switch (messagecode) {
        case 0x008A: // PORT_READ_RESOURCE_MESSAGE
            // Register read.  Type is PortResourceAccessMsg
            // TODO: response has data part filled in...

            // resourceType (4 bytes)
            offset += 4;
            // flags (4 bytes)
            offset += 4;
            // address

            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_address, tvb, offset, 4, ENC_BIG_ENDIAN, &addr);
            offset += 4;

            // count
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_count, tvb, offset, 4, ENC_BIG_ENDIAN, &count);
            offset += 4;
            // port
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_port, tvb, offset, 4, ENC_BIG_ENDIAN, &port);
            offset += 4;

            // future, data
            break;

        case 0x008B: // PORT_WRITE_RESOURCE_MESSAGE
            // Register write. Type is PortResourceSetAccessMsg
            // resourceType (4 bytes)
    //	    offset += 4;
            // flags (4 bytes)
    //	    offset += 4;

            // count
            //proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_count, tvb, offset, 4, ENC_BIG_ENDIAN, &count);
            //offset += 4;
            // port
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_port, tvb, offset, 4, ENC_BIG_ENDIAN, &port);
            offset += 4;

            offset += 4;

            // address (first of 64).  Assuming count is 1...
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_address, tvb, offset, 4, ENC_BIG_ENDIAN, &addr);
            offset += 4;

            // data (first of 64). Assuming count is 1...
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_data, tvb, offset, 4, ENC_BIG_ENDIAN, &data);

            // future
            break;

        case 0x00F2:  // PORT_RESERVE_QUERY
            proto_tree_add_item(tree, hf_axe_rpc_commandmessage_component, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            break;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str_const(messagecode, messagecode_vals, "Unknown"));

    return offset;
}

static int dissect_port_v1_blobrecv2_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* d _U_)
{
    gint offset = 0;

    //printf("%u: dissect_port_v1_blobrecv2_response()\n", pinfo->num);

    // Status
    offset = dissect_rpc_uint32(tvb, tree, hf_axe_rpc_status, offset);

    /* MessageHeader */
    guint32 messagecode;
    offset = dissect_message_header(tvb, offset, pinfo, tree, &messagecode);

    guint32 count, addr, port, data;

    switch (messagecode) {
        case 0x808A: // PORT_READ_RESOURCE_MESSAGE
            // Register read.  Type is PortResourceAccessMsg
            // TODO: response has data part filled in...

            // resourceType (4 bytes)
            offset += 4;
            // flags (4 bytes)
            offset += 4;
            // address

            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_address, tvb, offset, 4, ENC_BIG_ENDIAN, &addr);
            offset += 4;

            // count
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_count, tvb, offset, 4, ENC_BIG_ENDIAN, &count);
            offset += 4;
            // port
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_port, tvb, offset, 4, ENC_BIG_ENDIAN, &port);
            offset += 4;

            // future
            offset += 28;

            // data (first of 64). Assuming count is 1...
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_data, tvb, offset, 4, ENC_BIG_ENDIAN, &data);
            break;

        case 0x808B: // PORT_WRITE_RESOURCE_MESSAGE
            // Register write. Type is PortResourceSetAccessMsg
            // resourceType (4 bytes)
    //	    offset += 4;
            // flags (4 bytes)
    //	    offset += 4;

            // count
            //proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_count, tvb, offset, 4, ENC_BIG_ENDIAN, &count);
            //offset += 4;
            // port
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_port, tvb, offset, 4, ENC_BIG_ENDIAN, &port);
            offset += 4;

            offset += 4;

            // address (first of 64).  Assuming count is 1...
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_address, tvb, offset, 4, ENC_BIG_ENDIAN, &addr);
            offset += 4;

            // data (first of 64). Assuming count is 1...
            proto_tree_add_item_ret_uint(tree, hf_axe_rpc_portresource_data, tvb, offset, 4, ENC_BIG_ENDIAN, &data);

            // future
            break;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str_const(messagecode, messagecode_vals, "Unknown"));

    return offset;
}

static int dissect_rpc_port_stack_configure_v1_call(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* d _U_)
{
    gint offset = 0;

    offset += 2;

    // Stack ID
    guint32 stack_id;
    proto_tree_add_item_ret_uint(tree, hf_axe_rpc_stack_id, tvb, offset, 2, ENC_BIG_ENDIAN, &stack_id);
    offset += 2;

    // TODO: Can't work out what type this is yet...

    offset += 28;

    // The rest is JSON.
    tvbuff_t            *json_tvb = tvb_new_subset_length(tvb, offset, -1);
    call_dissector(json_dissector_handle, json_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

static int dissect_rpc_port_stack_configure_v1_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* d _U_)
{
    gint offset = 0;

    // Status
    offset = dissect_rpc_uint32(tvb, tree, hf_axe_rpc_status, offset);

    return offset;
}




static int dissect_version(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint version_start = offset;
    proto_item *version_ti = proto_tree_add_string_format(tree, hf_axe_rpc_version,
							  tvb, offset, 0, "", "Version");
    proto_tree *version_tree = proto_item_add_subtree(version_ti, ett_axe_rpc_version);

    // entity type
    guint entity_type = tvb_get_ntohl(tvb, offset);
    offset = dissect_rpc_uint32(tvb, version_tree, hf_axe_rpc_entity_type, offset);

    // entity_name
    offset += dissect_char_array(tvb, version_tree, pinfo, hf_axe_rpc_entity_name, offset, 32, NULL);

    // revision_number
    guint rev_num = tvb_get_ntohl(tvb, offset);
    offset = dissect_rpc_uint32(tvb, version_tree, hf_axe_rpc_revision_num, offset);
    // date
    offset += dissect_char_array(tvb, version_tree, pinfo, hf_axe_rpc_date, offset, 32, NULL);
    // build_string
    offset += dissect_char_array(tvb, version_tree, pinfo, hf_axe_rpc_build_string, offset, 32, NULL);

    // Add summary
    proto_item_append_text(version_ti, " (%s, rev %u)",
			   val_to_str_const(entity_type, entity_type_vals, "Unknown"),
			   rev_num);

    proto_item_set_len(version_ti, offset-version_start);

    return offset;
}

static int dissect_port_v1_getversions_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint offset = 0;
    /*offset = */ dissect_rpc_array(tvb, pinfo, tree, offset, dissect_version, hf_axe_rpc_version_list);
    return tvb_reported_length(tvb);
}

static int dissect_blob_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint offset = 0;

    // Status
    dissect_rpc_uint32(tvb, tree, hf_axe_rpc_status, offset);
    offset += 4;

    return offset;
}




static int dissect_chassis_v2_query_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint offset = 0;

    // Payload is wbm2_info

    // Status.  TODO: really, its an int...
    dissect_rpc_uint32(tvb, tree, hf_axe_rpc_status, offset);
    offset += 4;

    // Mgmt.
    // Create mgmt subtree.
    proto_item *mgmt_ti = proto_tree_add_string_format(tree, hf_axe_rpc_mgmt,
												      tvb, offset, 0, "", "Mgmt");
    proto_tree *mgmt_tree = proto_item_add_subtree(mgmt_ti, ett_axe_rpc_mgmt);

    gint mgmt_start = offset;

    // Hostname
    char mgmt_hostname[33];
    offset += dissect_char_array(tvb, mgmt_tree, pinfo, hf_axe_rpc_chassis_hostname, offset, 33, mgmt_hostname);
    // Description.
    char description[65];
    offset += dissect_char_array(tvb, mgmt_tree, pinfo, hf_axe_rpc_chassis_description, offset, 65, description);

    // pcb_rev
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_pcb_rev, offset);
    // address
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_address, offset);
    // chassis_gid
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_gid, offset);
    // chassis_uid
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_uid, offset);
    // fpga_id
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_fpga_id, offset);
    // cpld_id
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_cpld_id, offset);
    // port_status
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_port_status, offset);
    // Uptime
    offset = dissect_rpc_uint64(tvb, mgmt_tree, hf_axe_rpc_chassis_uptime, offset);
    // swreg
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_chassis_swreg, offset);

    // TODO: missing out several fields.
    // fpga_status_a
    offset += 4;
    // fpga_status_b
    offset += 4;
    // clock_master
    offset += 8;
    // snap_clock_master
    offset += 8;
    // firmware_rev
    offset += dissect_char_array(tvb, mgmt_tree, pinfo, hf_axe_rpc_firmware_rev, offset, 33, NULL);
    // recovery_rev
    offset += dissect_char_array(tvb, mgmt_tree, pinfo, hf_axe_rpc_recovery_rev, offset, 33, NULL);
    // schema_min
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_schema_min, offset);
    // schema_max
    offset = dissect_rpc_uint32(tvb, mgmt_tree, hf_axe_rpc_schema_max, offset);

    // >>>>>> TODO: Why are these 2 fields not * 4 bytes ????? <<<<<<<<<<<<
    // model_name
    offset = dissect_rpc_bytes(tvb, mgmt_tree, hf_axe_rpc_model_name, offset, 32, TRUE, NULL);
    // reserved
    dissect_rpc_bytes(tvb, mgmt_tree, hf_axe_rpc_chassis_reserved, offset, 32, FALSE, NULL);
    offset += 32;

    proto_item_append_text(mgmt_ti, "  - %s (%s)", mgmt_hostname, description);
    proto_item_set_len(mgmt_ti, offset-mgmt_start);


    // Next is ports

    // ports_len
    guint32 num_ports = tvb_get_ntohl(tvb, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_axe_rpc_chassis_ports_len, offset);

    for (guint n=0; n < num_ports; n++) {
        // Dissect a wbm2_port_info
        // Create port subtree.
        gint port_start = offset;
        proto_item *port_ti = proto_tree_add_string_format(tree, hf_axe_rpc_chassis_port,
                                                          tvb, offset, 0, "", "Port");
        proto_tree *port_tree = proto_item_add_subtree(port_ti, ett_axe_rpc_port);

        // card_pcb_rev
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_card_pcb_rev, offset);
        // port_pcb_rev
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_port_pcb_rev, offset);

        // address
        guint32 addr = tvb_get_ntohl(tvb, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_address, offset);
        // PDIs
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi1_id, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi2_id, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi3_id, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi4_id, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi5_id, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi6_id, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi7_id, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_pdi8_id, offset);
        // Statuses
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_status_a, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_status_b, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_status_c, offset);
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_status_d, offset);

        // Uptime
        offset = dissect_rpc_uint64(tvb, port_tree, hf_axe_rpc_chassis_uptime, offset);
        // swreg
        offset = dissect_rpc_uint32(tvb, port_tree, hf_axe_rpc_chassis_swreg, offset);

        offset = dissect_rpc_bytes(tvb, port_tree, hf_axe_rpc_chassis_reserved, offset, 64, FALSE, NULL);

        proto_item_append_text(port_ti, " (address=0x%08x)", addr);
        proto_item_set_len(port_ti, offset-port_start);
    }

    // Services
    // num_services
    guint32 num_services = tvb_get_ntohl(tvb, offset);
    offset = dissect_rpc_uint32(tvb, tree, hf_axe_rpc_chassis_services_len, offset);

    for (guint n=0; n < num_services; n++) {
        // TODO: Dissect a wbm2_service_info
        // Create service subtree.
        gint service_start = offset;
        proto_item *service_ti = proto_tree_add_string_format(tree, hf_axe_rpc_chassis_service,
                                      tvb, offset, 0, "", "Service");
        proto_tree *service_tree = proto_item_add_subtree(service_ti, ett_axe_rpc_service);

        // hostname
        char hostname[33];
        offset += dissect_char_array(tvb, service_tree, pinfo, hf_axe_rpc_chassis_hostname, offset, 33, hostname);
        // service type
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_chassis_service_type, offset);
        // address
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_chassis_address, offset);
        // IP Slot
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_chassis_service_ip_slot, offset);
        // Schema Min
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_schema_min, offset);
        // Schema Max
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_schema_max, offset);
        // Status
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_status, offset);

        // TODO: RPC
        // rpc_info_len
        guint32 num_rpc = tvb_get_ntohl(tvb, offset);
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_chassis_rpc_info_len, offset);

        for (guint m=0; m < num_rpc; m++) {
            // TODO: Dissect a wbm2_rpc_info
            // Create rpc subtree.
            gint rpc_start = offset;
            proto_item *rpc_ti = proto_tree_add_string_format(service_tree, hf_axe_rpc_chassis_rpc,
                                                              tvb, offset, 0, "", "RPC");
            proto_tree *rpc_tree = proto_item_add_subtree(rpc_ti, ett_axe_rpc_rpc);

            // Prognum
            guint32 prognum = tvb_get_ntohl(tvb, offset);
            offset = dissect_rpc_uint32(tvb, rpc_tree, hf_axe_rpc_chassis_rpc_prognum, offset);
            // Progver
            offset = dissect_rpc_uint32(tvb, rpc_tree, hf_axe_rpc_chassis_rpc_progver, offset);
            // Service num
            guint32 service_num = tvb_get_ntohl(tvb, offset);
            offset = dissect_rpc_uint32(tvb, rpc_tree, hf_axe_rpc_chassis_rpc_service_num, offset);

            proto_item_append_text(rpc_ti, " (Prognum=%u - 0x%08x  service_num=%u)",
                                   prognum, prognum, service_num);
            proto_item_set_len(rpc_ti, offset-rpc_start);
        }

        // model_name
        offset = dissect_rpc_bytes(tvb, service_tree, hf_axe_rpc_model_name, offset, 32, TRUE, NULL);

        // part_code
        proto_item *part_code_ti = proto_tree_add_string_format(service_tree, hf_axe_rpc_chassis_service_part_code,
                                  tvb, offset, 8, "", "Part Code");
        proto_tree *part_code_tree = proto_item_add_subtree(part_code_ti, ett_axe_rpc_part_code);
        // Version
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        // Tag
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        // Phy Type
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_phy_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        // Phy Elems
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_phy_elems, tvb, offset, 1, ENC_BIG_ENDIAN);
        // Phy Caps
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_phy_caps, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        // Series
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_series, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        // Gen Caps
        guint32 gen_caps;
        proto_tree_add_item_ret_uint(part_code_tree, hf_axe_rpc_chassis_service_part_code_gen_caps, tvb, offset, 1, ENC_BIG_ENDIAN, &gen_caps);
        // WiFi Regions
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_wifi_regions, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        // Reserved
        proto_tree_add_item(part_code_tree, hf_axe_rpc_chassis_service_part_code_reserved, tvb, offset, 3, ENC_NA);
        offset += 3;
        proto_item_append_text(part_code_ti, " (%s)", val_to_str_const(gen_caps, part_code_gen_caps_vals, "Unknown"));


        // port_set_info
        offset = dissect_rpc_uint32(tvb, service_tree, hf_axe_rpc_chassis_service_port_set_info, offset);

        // reserved
        dissect_rpc_bytes(tvb, service_tree, hf_axe_rpc_chassis_reserved, offset, 20, FALSE, NULL);
        offset += 20;

        proto_item_append_text(service_ti, " (hostname=%s)", hostname);

        proto_item_set_len(service_ti, offset-service_start);
    }

    // dissect_rpc_bytes(tvb, mgmt_tree, hf_axe_rpc_chassis_reserved, offset, -1, FALSE, NULL);

    return tvb_reported_length(tvb);
}


static int dissect_chassis_v1_get_config_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint offset = 0;
    // Show details of struct controller_config (port_if.x)

    // hostname
    offset += dissect_char_array(tvb, tree, pinfo, hf_axe_rpc_chassis_hostname, offset, 32, NULL);
    // description
    offset += dissect_char_array(tvb, tree, pinfo, hf_axe_rpc_chassis_description, offset, 64, NULL);

    // (dhcp) config
    offset = dissect_rpc_uint32(tvb, tree, hf_axe_rpc_chassis_dhcp_config, offset);

    // mac_addr
    offset += 24;

    // build_date
    offset += dissect_char_array(tvb, tree, pinfo, hf_axe_rpc_chassis_build_date, offset, 32, NULL);

    // min_build
    offset += dissect_char_array(tvb, tree, pinfo, hf_axe_rpc_chassis_min_build, offset, 32, NULL);

    // current_ip_address
    guint32 ip;
    offset += dissect_ip_address(tvb, tree, pinfo, hf_axe_rpc_chassis_current_ip_address, offset, &ip);
    // current_netmask
    offset += dissect_ip_address(tvb, tree, pinfo, hf_axe_rpc_chassis_current_netmask, offset, &ip);
    // current_gateway
    offset += dissect_ip_address(tvb, tree, pinfo, hf_axe_rpc_chassis_current_gateway, offset, &ip);

    // static_ip_address
    offset += dissect_ip_address(tvb, tree, pinfo, hf_axe_rpc_chassis_static_ip_address, offset, &ip);
    // static_netmask
    offset += dissect_ip_address(tvb, tree, pinfo, hf_axe_rpc_chassis_static_netmask, offset, &ip);
    // static_gateway
    offset += dissect_ip_address(tvb, tree, pinfo, hf_axe_rpc_chassis_static_gateway, offset, &ip);

    return tvb_reported_length(tvb);
}

static int dissect_port_v1_stack_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint offset = 0;
    // This is an FneWbmMgmtMessage, which starts with MessageHeader

    offset += 2;

    // Stack ID
    guint32 stack_id;
    proto_tree_add_item_ret_uint(tree, hf_axe_rpc_stack_id, tvb, offset, 2, ENC_BIG_ENDIAN, &stack_id);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (stackId=%s)", val_to_str_const(stack_id, stackid_vals, "Unknown"));

    return tvb_reported_length(tvb);
}

static int dissect_rpc_port_stack_query_v1_call(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    gint offset = 32;
    // The rest is JSON.
    tvbuff_t            *json_tvb = tvb_new_subset_length(tvb, offset, -1);
    call_dissector(json_dissector_handle, json_tvb, pinfo, tree);

    return tvb_reported_length(tvb);
}





/*********************************************************************************/
/* Port program */

#define PORT_PROGRAM 0x20000089

/* Port version 1 */
static const vsff port1_proc[] = {
    { 0, "NULL",              dissect_rpc_void, dissect_rpc_void },

    { 1, "Hello",             dissect_port_v1_hello, dissect_port_v1_hello },
    { 3, "Reset",             dissect_rpc_void, dissect_rpc_void },
    { 4, "GetVersions",       dissect_rpc_void, dissect_port_v1_getversions_response },

    { 10, "BlobSend",         dissect_port_v1_blobrecv2_call, dissect_blob_res },
    { 11, "BlobRecv",         dissect_port_v1_blobrecv_call, dissect_blob_res },
    { 12, "BlobRecv2",        dissect_port_v1_blobrecv2_call, dissect_port_v1_blobrecv2_response },

    { 20, "GetStats",         dissect_rpc_void, dissect_rpc_void },
    { 21, "GetStats2",        dissect_rpc_void, dissect_rpc_void },
    { 23, "StatsClear",       dissect_rpc_void, dissect_rpc_void },

    { 30, "EnableLog",        dissect_rpc_void, dissect_rpc_void },
    { 31, "StopLog",          dissect_rpc_void, dissect_rpc_void },
    { 32, "ClearLog",         dissect_rpc_void, dissect_rpc_void },
    { 33, "QueryLog",         dissect_rpc_void, dissect_rpc_void },
    { 34, "GetLogBlock",      dissect_rpc_void, dissect_rpc_void },
    { 35, "GetLogPacket",     dissect_rpc_void, dissect_rpc_void },
    { 36, "EnableLog2",       dissect_rpc_void, dissect_rpc_void },
    { 37, "ClearLog2",        dissect_rpc_void, dissect_rpc_void },
    { 38, "StopLog2",         dissect_rpc_void, dissect_rpc_void },

    { 40, "StackConfigure",   dissect_rpc_port_stack_configure_v1_call, dissect_rpc_port_stack_configure_v1_res },
    { 42, "StackDestroy",     dissect_rpc_void, dissect_rpc_void },
    { 43, "StackControl",     dissect_port_v1_stack_control, dissect_rpc_void },
    { 44, "StackQuery",       dissect_rpc_port_stack_query_v1_call, dissect_rpc_void },

    { 51, "FOpen",            dissect_rpc_void, dissect_rpc_void },
    { 52, "FRead",            dissect_rpc_void, dissect_rpc_void },
    { 53, "FWrite",           dissect_rpc_void, dissect_rpc_void },
    { 54, "FClose",           dissect_rpc_void, dissect_rpc_void },

    { 60, "FirmwareUpgrade",  dissect_rpc_void, dissect_rpc_void },

    { 72, "LedQuery",         dissect_rpc_void, dissect_rpc_void },

    { 80, "WriteShmem",       dissect_rpc_void, dissect_rpc_void },

    { 0, NULL, NULL, NULL }
};

static const rpc_prog_vers_info port_vers_info[] = {
    { 1, port1_proc, &hf_axe_rpc_port_v1 },
};


/*******************************************************************************/
/* Chassis program */

#define CHASSIS_PROGRAM 0x20001089

/* Chassis version 1 */
static const vsff chassis1_proc[] = {
    { 0, "NULL",                     dissect_rpc_void, dissect_rpc_void },

    { 1,  "Query",                   dissect_rpc_void, dissect_rpc_void },
    { 10, "FlowControl",             dissect_rpc_void, dissect_rpc_void },

    { 20, "GetSlotInfo",             dissect_rpc_void, dissect_rpc_void },
    { 21, "GetControllerInfo",       dissect_rpc_void, dissect_rpc_void },
    { 22, "ResetCard",               dissect_rpc_void, dissect_rpc_void },
    { 23, "ResetChassis",            dissect_rpc_void, dissect_rpc_void },
    { 24, "GetConfig",               dissect_rpc_void, dissect_chassis_v1_get_config_response },
    { 25, "SetConfig",               dissect_rpc_void, dissect_rpc_void },
    { 26, "ValidatePassword",        dissect_rpc_void, dissect_rpc_void },

    { 27, "GetTimeConfig",           dissect_rpc_void, dissect_rpc_void },
    { 28, "SetTimeConfig",           dissect_rpc_void, dissect_rpc_void },

    { 40, "StackConfigure",          dissect_rpc_void, dissect_rpc_void },
    { 42, "StackDestroy",            dissect_rpc_void, dissect_rpc_void },
    { 43, "StackControl",            dissect_rpc_void, dissect_rpc_void },
    { 44, "StackQuery",              dissect_rpc_void, dissect_rpc_void },


    { 51, "FOpen",                   dissect_rpc_void, dissect_rpc_void },
    { 52, "FRead",                   dissect_rpc_void, dissect_rpc_void },
    { 53, "FWrite",		             dissect_rpc_void, dissect_rpc_void },
    { 54, "FClose",                  dissect_rpc_void, dissect_rpc_void },

    { 60, "StartFirmwareUpgrade",    dissect_rpc_void, dissect_rpc_void },
    { 61, "UpgradeStatus",           dissect_rpc_void, dissect_rpc_void },

    { 70, "ReserveFlowGroup",        dissect_rpc_void, dissect_rpc_void },
    { 71, "ReleaseFlowGroup",        dissect_rpc_void, dissect_rpc_void },

    { 101, "QueryService",           dissect_rpc_void, dissect_rpc_void },

    { 102, "ConfigParams",           dissect_rpc_void, dissect_rpc_void },

    { 0, NULL, NULL, NULL }
};

/* Chassis version 2 */
static const vsff chassis2_proc[] = {
    { 0,  "NULL",                    dissect_rpc_void, dissect_rpc_void },
    { 1,  "Reset",                   dissect_rpc_void, dissect_rpc_void },
    { 2,  "Upgrade",                 dissect_rpc_void, dissect_rpc_void },
    { 3,  "UpgradeStatus",           dissect_rpc_void, dissect_rpc_void },
    { 4,  "PortRegister",            dissect_rpc_void, dissect_rpc_void },
    { 5,  "Query",                   dissect_rpc_void, dissect_chassis_v2_query_response },
    { 6,  "Flowcontrol",             dissect_rpc_void, dissect_rpc_void },
    { 7,  "GetConfig",               dissect_rpc_void, dissect_rpc_void },
    { 8,  "SetConfig",               dissect_rpc_void, dissect_rpc_void },
    { 9,  "GetTimeConfig",           dissect_rpc_void, dissect_rpc_void },
    { 10, "SetTimeConfig",           dissect_rpc_void, dissect_rpc_void },
    { 11, "ValidatePassword",        dissect_rpc_void, dissect_rpc_void },

    { 12, "FOpen",                   dissect_rpc_void, dissect_rpc_void },
    { 13, "FRead",                   dissect_rpc_void, dissect_rpc_void },
    { 14, "FWrite",                  dissect_rpc_void, dissect_rpc_void },
    { 15, "FClose",                  dissect_rpc_void, dissect_rpc_void },

    { 16, "StackConfigure",          dissect_rpc_void, dissect_rpc_void },
    { 17, "StackQuery",              dissect_rpc_void, dissect_rpc_void },
    { 18, "StackDestroy",            dissect_rpc_void, dissect_rpc_void },
    { 19, "StackControl",            dissect_rpc_void, dissect_rpc_void },

    { 20, "ConfigParams",            dissect_rpc_void, dissect_rpc_void },

    { 0, NULL, NULL, NULL }
};



static const rpc_prog_vers_info chassis_vers_info[] = {
    { 1, chassis1_proc, &hf_axe_rpc_chassis_v1 },
    { 2, chassis2_proc, &hf_axe_rpc_chassis_v2 },
};




// Main dissection function.
// TODO: does this even get called?

static gint
dissect_axe_rpc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    //int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AXE-RPC");
    col_clear(pinfo->cinfo, COL_INFO);

    //proto_item *root_ti = proto_tree_add_item(tree, proto_axe_rpc, tvb, 0, -1, ENC_NA);
    //proto_tree *axe_rpc_tree = proto_item_add_subtree(root_ti, ett_axe_rpc);

    return tvb_captured_length(tvb);
}


/* Register axe_rpc */
void
proto_register_axe_rpc(void)
{
    static hf_register_info hf[] =
    {
        { &hf_axe_rpc_port_v1, {
            "V1 Port", "axe-rpc.port_v1", FT_UINT32, BASE_DEC, NULL /*VALS(mount1_proc_vals)*/, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_v1, {
            "V1 Chassis", "axe-rpc.chassis_v1", FT_UINT32, BASE_DEC, NULL /*VALS(mount1_proc_vals)*/, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_v2, {
            "V2 Chassis", "axe-rpc.chassis_v2", FT_UINT32, BASE_DEC, NULL /*VALS(mount1_proc_vals)*/, 0, NULL, HFILL }},

		{ &hf_axe_rpc_schema, {
			"Schema", "axe-rpc.schema", FT_INT32, BASE_DEC, NULL, 0, "Should be 124!", HFILL }},
		{ &hf_axe_rpc_entity_type, {
			"Entity Type", "axe-rpc.entity-type", FT_INT32, BASE_DEC, VALS(entity_type_vals), 0, NULL, HFILL }},
		{ &hf_axe_rpc_entity_name, {
			"Entity Name", "axe-rpc.entity-name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_revision_num, {
			"Revision Num", "axe-rpc.revision-num", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_date, {
			"Date", "axe-rpc.date", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_build_string, {
			"Build String", "axe-rpc.build-string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_axe_rpc_version_list, {
			"Versions", "axe-rpc.versions", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_axe_rpc_version, {
			"Version", "axe-rpc.version", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},


		{ &hf_axe_rpc_message_header, {
			"Message Header", "axe-rpc.message-header", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_axe_rpc_messageid, {
			"MessageId", "axe-rpc.messageid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_timestamp, {
			"Timestamp", "axe-rpc.timestamp", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_messagecode, {
			"MessageCode", "axe-rpc.messagecode", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_instance, {
			"Instance", "axe-rpc.instance", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_debug, {
			"Debug", "axe-rpc.debug", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		// blobrecv2 (CommandMessage)
		{ &hf_axe_rpc_commandmessage_id, {
			"Id", "axe-rpc.commandmessage.id", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_commandmessage_len, {
			"Len", "axe-rpc.commandmessage.len", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_commandmessage_time, {
			"Time", "axe-rpc.commandmessage.time", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_commandmessage_code, {
			"Code", "axe-rpc.commandmessage.code", FT_UINT16, BASE_HEX, VALS(messagecode_vals), 0, NULL, HFILL }},

		{ &hf_axe_rpc_commandmessage_component, {
			"Code", "axe-rpc.commandmessage.component", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},



		{ &hf_axe_rpc_portresource_count, {
			"Count", "axe-rpc.portresource.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_portresource_address, {
			"Address", "axe-rpc.portresource.address", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_portresource_port, {
			"Port", "axe-rpc.portresource.port", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_axe_rpc_portresource_data, {
			"Data", "axe-rpc.portresource.data", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_axe_rpc_status, {
			"Status", "axe-rpc.status", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_axe_rpc_stack_id, {
			"Stack ID", "axe-rpc.stack-id", FT_UINT16, BASE_DEC, VALS(stackid_vals), 0, NULL, HFILL }},

        // Management fields.
        { &hf_axe_rpc_mgmt, {
            "Management", "axe-rpc.mgmt", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_hostname, {
            "Hostname", "axe-rpc.hostname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_description, {
            "Description", "axe-rpc.description", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pcb_rev, {
            "PCB Rev", "axe-rpc.pcb-rev", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_address, {
            "Address", "axe-rpc.address", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_gid, {
            "Chassid GID", "axe-rpc.chassis-gid", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_uid, {
            "Chassis UID", "axe-rpc.chassis-uid", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_fpga_id, {
            "FPGA Id", "axe-rpc.fpga-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_cpld_id, {
            "CPLD Id", "axe-rpc.cpld-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_port_status, {
            "Port Status", "axe-rpc.port-status", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_uptime, {
            "Up-Time", "axe-rpc.uptime", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_swreg, {
            "SWReg", "axe-rpc.swreg", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_reserved, {
            "Reserved", "axe-rpc.reserved", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_ports_len, {
            "Ports Len", "axe-rpc.ports-len", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        // Port fields.
        { &hf_axe_rpc_chassis_port, {
            "Port", "axe-rpc.port", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_card_pcb_rev, {
            "Card PCB Rev", "axe-rpc.card-pcb-rev", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_port_pcb_rev, {
            "Port PCB Rev", "axe-rpc.port-pcb-rev", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_pdi1_id, {
            "PDI1 Id", "axe-rpc.pdi1-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pdi2_id, {
            "PDI2 Id", "axe-rpc.pdi2-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pdi3_id, {
            "PDI3 Id", "axe-rpc.pdi3-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pdi4_id, {
            "PDI4 Id", "axe-rpc.pdi4-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pdi5_id, {
            "PDI5 Id", "axe-rpc.pdi5-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pdi6_id, {
            "PDI6 Id", "axe-rpc.pdi6-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pdi7_id, {
            "PDI7 Id", "axe-rpc.pdi7-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_pdi8_id, {
            "PDI8 Id", "axe-rpc.pdi8-id", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_status_a, {
            "Status A", "axe-rpc.status-a", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_status_b, {
            "Status B", "axe-rpc.status-b", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_status_c, {
            "Status C", "axe-rpc.status-c", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_status_d, {
            "Status D", "axe-rpc.status-d", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        // TODO: vals()
        { &hf_axe_rpc_chassis_dhcp_config, {
            "DHCP Config", "axe-rpc.dhcp-config", FT_INT32, BASE_DEC, VALS(dhcp_config_vals), 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_build_date, {
            "Build Date", "axe-rpc.build-date", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_min_build, {
            "Min Build", "axe-rpc.min-build", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_current_ip_address, {
            "Current IP Address", "axe-rpc.current-ip-address", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_current_netmask, {
            "Current Netmask", "axe-rpc.current-netmask", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_current_gateway, {
            "Current Gateway", "axe-rpc.current-gateway", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_static_ip_address, {
            "Static IP Address", "axe-rpc.static-ip-address", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_static_netmask, {
            "Static Netmask", "axe-rpc.static-netmask", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_static_gateway, {
            "Static Gateway", "axe-rpc.static-gateway", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_model_name, {
            "Model Name", "axe-rpc.model-name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_firmware_rev, {
            "Firmware Rev", "axe-rpc.firmware-rev", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_recovery_rev, {
            "Recovery Rev", "axe-rpc.recovery-rev", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_schema_min, {
            "Schema Min", "axe-rpc.schema-min", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_schema_max, {
            "Schema Max", "axe-rpc.schema-max", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_services_len, {
            "Services Len", "axe-rpc.services-len", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        // Service fields.
        { &hf_axe_rpc_chassis_service, {
            "Service", "axe-rpc.service", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        // TODO: VALS()
        { &hf_axe_rpc_chassis_service_type, {
            "Type", "axe-rpc.service-type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_service_ip_slot, {
            "IP Slot", "axe-rpc.service-ip-slot", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_service_part_code, {
            "Part Code", "axe-rpc.service.part-code", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_version, {
            "Version", "axe-rpc.service.part-code.version", FT_UINT8, BASE_HEX, VALS(part_code_version_vals), 0xf0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_tag, {
            "Tag", "axe-rpc.service.part-code.tag", FT_UINT8, BASE_HEX, VALS(part_code_tag_vals), 0x0f, NULL, HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_phy_type, {
            "Phy Type", "axe-rpc.service.part-code.phy-type", FT_UINT8, BASE_HEX, VALS(part_code_phy_type_vals), 0x0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_phy_elems, {
            "Phy Elems", "axe-rpc.service.part-code.phy-elems", FT_UINT8, BASE_DEC, NULL, 0xf0, "Number of phy elements in port (e.g. mimo)", HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_phy_caps, {
            "Phy Caps", "axe-rpc.service.part-code.phy-elems", FT_UINT8, BASE_DEC, VALS(part_code_phy_caps_vals), 0x0f, "Phy compatibility flags", HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_series, {
            "Series", "axe-rpc.service.part-code.series", FT_UINT8, BASE_DEC, VALS(part_code_series_vals), 0x0, "General indication of software platform level", HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_gen_caps, {
            "Gen Caps", "axe-rpc.service.part-code.gen-caps", FT_UINT8, BASE_DEC, VALS(part_code_gen_caps_vals), 0xf0, "General capabilities", HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_wifi_regions, {
            "Wifi Regions", "axe-rpc.service.part-code.wifi-regions", FT_UINT8, BASE_DEC, VALS(part_code_wifi_regions_vals), 0x0f, "WiFi region/country bits - only valid for WiFi cards", HFILL }},
        { &hf_axe_rpc_chassis_service_part_code_reserved, {
            "Reserved", "axe-rpc.service.part-code.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_axe_rpc_chassis_service_port_set_info, {
            "Port Set Info", "axe-rpc.service-port-set-info", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},


        { &hf_axe_rpc_chassis_rpc_info_len, {
            "RPC Info Len", "axe-rpc.rpc-info-len", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        // RPC fields.
        { &hf_axe_rpc_chassis_rpc, {
            "RPC", "axe-rpc.rpc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_rpc_prognum, {
            "Prognum", "axe-rpc.rpc.rpc-prognum", FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_rpc_progver, {
            "Progver", "axe-rpc.rpc.rpc-progver", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_axe_rpc_chassis_rpc_service_num, {
            "Service Num", "axe-rpc.rpc.rpc-service-num", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

    };

    static gint *ett[] =
    {
        &ett_axe_rpc,
        &ett_axe_rpc_mgmt,
        &ett_axe_rpc_port,
        &ett_axe_rpc_service,
        &ett_axe_rpc_rpc,
        &ett_axe_rpc_version,
        &ett_axe_rpc_message_header,
        &ett_axe_rpc_part_code
    };

    proto_axe_rpc = proto_register_protocol("AXE RPC", "AXE-RPC", "axe-rpc");

    proto_register_field_array(proto_axe_rpc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    axe_rpc_handle = register_dissector("axe-rpc", dissect_axe_rpc, proto_axe_rpc);
}

void proto_reg_handoff_axe_rpc(void)
{
    /* Register the programs as RPC */
    rpc_init_prog(proto_axe_rpc, PORT_PROGRAM,    ett_axe_rpc, G_N_ELEMENTS(port_vers_info),    port_vers_info);
    rpc_init_prog(proto_axe_rpc, CHASSIS_PROGRAM, ett_axe_rpc, G_N_ELEMENTS(chassis_vers_info), chassis_vers_info);
    /* TODO: others? */

    json_dissector_handle = find_dissector("json");
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
