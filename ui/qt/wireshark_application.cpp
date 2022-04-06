/* wireshark_application.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wireshark_application.h"

#include "extcap.h"

#include "ui/iface_lists.h"
#include "ui/ws_ui_util.h"

WiresharkApplication *wsApp = NULL;

WiresharkApplication::WiresharkApplication(int &argc,  char **argv) :
    MainApplication(argc, argv)
{
    wsApp = this;
    setApplicationName("Wireshark");
    setDesktopFileName(QStringLiteral("org.wireshark.Wireshark"));
}

WiresharkApplication::~WiresharkApplication()
{
    wsApp = NULL;
}

void WiresharkApplication::refreshLocalInterfaces()
{
    extcap_clear_interfaces();

#ifdef HAVE_LIBPCAP
    /*
     * Reload the local interface list.
     */
    scan_local_interfaces(false, main_window_update);

    /*
     * Now emit a signal to indicate that the list changed, so that all
     * places displaying the list will get updated.
     *
     * XXX - only if it *did* change.
     */
    emit localInterfaceListChanged();
#endif
}
