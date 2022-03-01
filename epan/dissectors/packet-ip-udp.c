/* packet-ip-udp.c
 *
 * Handy for when user-plane (purely IP) frames are sent over UDP.
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

#include <epan/conversation.h>
#include <epan/prefs.h>

void proto_register_ip_udp(void);
void proto_reg_handoff_ip_udp (void);

static int proto_ip_udp = -1;


/* Subtrees */
static gint ett_ip_udp = -1;

static dissector_handle_t ip_udp_handle;


/* User definable values */
static range_t *global_ip_udp_port_range = NULL;



/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

static gboolean global_eth_payload = FALSE;

static dissector_handle_t ip_handle;
static dissector_handle_t eth_handle;


/******************************/
/* Main dissection function.  */
static int
dissect_ip_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint offset = 0;

    /* Must be at least 20 bytes */
    if (tvb_reported_length(tvb) < 20) {
        return 0;
    }

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IP-UDP|");
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);

    /* Protocol root */
    proto_tree_add_item(tree, proto_ip_udp, tvb, offset, -1, ENC_NA);

    /* Call IP dissector */
    tvbuff_t *ip_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector_only((global_eth_payload) ? eth_handle : ip_handle,
                        ip_tvb, pinfo, tree, NULL);

    /* Claim all of the bytes */
    return tvb_captured_length(tvb);
}


void
proto_register_ip_udp(void)
{
    //static hf_register_info hf[] = {
    //};

    static gint *ett[] = {
        &ett_ip_udp
    };

    module_t *ip_udp_module;

    proto_ip_udp = proto_register_protocol("IP-UDP", "IP-UDP", "ip-udp");
    //proto_register_field_array(proto_ip_udp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ip_udp_handle = register_dissector("ip-udp", dissect_ip_udp, proto_ip_udp);

    /* Preferences */
    ip_udp_module = prefs_register_protocol(proto_ip_udp, NULL);

    prefs_register_bool_preference(ip_udp_module, "is_eth",
                                   "Frame contains ethernet",
                                   "",
                                   &global_eth_payload);
}

static void
apply_ip_udp_prefs(void)
{
    global_ip_udp_port_range = prefs_get_range_value("ip-udp", "udp.port");
}

void
proto_reg_handoff_ip_udp(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", ip_udp_handle);
    apply_ip_udp_prefs();

    ip_handle = find_dissector("ip");
    eth_handle = find_dissector("eth_withoutfcs");
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
