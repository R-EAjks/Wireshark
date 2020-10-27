/* packet-g3.h
 *
 * Dissector for ITU-T Rec. G.9903 (G3-PLC) CENELEC, FCC and ARIB
 * By Klaus Hueske <Klaus.Hueske@renesas.com>
 * Copyright 2020 Renesas Electronics Europe GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Do not remove this file since it is referenced and needed by a
 * proprietary plugin that uses some of the constants defined in
 * the file.
 *
 */
#ifndef __PACKET_G3_H__
#define __PACKET_G3_H__

#define G3_BANDPLAN_CENELEC_A_B 0
#define G3_BANDPLAN_FCC_ARIB    1
#define G3_BANDPLAN_CENELEC_A   2
#define G3_BANDPLAN_CENELEC_B   3
#define G3_BANDPLAN_FCC         4
#define G3_BANDPLAN_ARIB        5

typedef struct
{
    guint8 g3_bandplan;
    gboolean g3_standard_is_G3Base;
} g3_hints_t;

#endif /* __PACKET_G3_H__ */

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
