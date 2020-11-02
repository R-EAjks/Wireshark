/* packet-vrt.h
 * Shared data structure definitions for VRT dissector
 * Copyright 2020 The MITRE Corporation: original extension
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_VRT_CIF_H__
#define __PACKET_VRT_CIF_H__

typedef enum {
    vrt_type_sig = 0,        /* Signal data packet (without Stream Id) */
    vrt_type_sig_sid = 1,    /* Signal data packet with Stream Id */
    vrt_type_edat = 2,       /* Extension data packet (without Stream Id) */
    vrt_type_edat_sid = 3,   /* Extension data packet with Stream Id */
    vrt_type_ctx = 4,        /* Context packet */
    vrt_type_ectx = 5,       /* Extension context packet */
    vrt_type_cmd = 6,        /* Command packet */
    vrt_type_ecmd = 7        /* Extension command packet */
} vrt_packet_type_t;

typedef struct {
    vrt_packet_type_t type;
    guint32           cam;
    gboolean          is_ack;
    gboolean          has_cid;
    guint32           oui;
    guint16           info_class_code;
    guint16           packet_class_code;
} vrt_packet_description_t;

#endif

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

