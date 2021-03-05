/* packet-wsdiscovery.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"
#include <epan/packet.h>

#define WS_DISCOVERY_PORT 3702

static int proto_wsdiscovery = -1;
static dissector_handle_t xml_dissector_handle;
static gint ett_wsdiscovery = -1;


static gint* ett[] = {
    &ett_wsdiscovery,
};

static int
dissect_wsdiscovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_item* protoitem = NULL;
    proto_tree* discovery_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WS-Discovery");

    /* Set the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "WS-Discovery");

    /* Create Tree Note for WS-Discovery */
    protoitem = proto_tree_add_protocol_format(tree, proto_wsdiscovery, tvb, 0, -1, "WS-Discovery");
    discovery_tree = proto_item_add_subtree(protoitem, ett_wsdiscovery);

    /* Call 'xml' dissector */
    {
        tvbuff_t* data_tvb;
        guint datasize = tvb_captured_length(tvb);
        const guint8* databuf = tvb_get_ptr(tvb, 0, datasize);
        data_tvb = tvb_new_child_real_data(tvb, databuf, datasize, datasize);
        return call_dissector(xml_dissector_handle, data_tvb, pinfo, discovery_tree);
    }
}

void
proto_register_wsdiscovery(void)
{
    proto_wsdiscovery = proto_register_protocol (
        "Web Services Dynamic Discovery",  /* name        */
        "WS-Discovery",                    /* short_name  */
        "wsdiscovery"                      /* filter_name */
    );

    /* Add data partition for expand/unexpand 'wsdiscovery' tree */
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_wsdiscovery(void)
{
    static dissector_handle_t wsdiscovery_handle;

    wsdiscovery_handle = create_dissector_handle(dissect_wsdiscovery, proto_wsdiscovery);
    dissector_add_uint("udp.port", WS_DISCOVERY_PORT, wsdiscovery_handle);

    xml_dissector_handle = find_dissector("xml");
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
