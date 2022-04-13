/* logwolf_application.cpp
 *
 * Logwolf - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logwolf_application.h"

#include "extcap.h"

#include "ui/iface_lists.h"
#include "ui/ws_ui_util.h"

LogwolfApplication *lwApp = NULL;

LogwolfApplication::LogwolfApplication(int &argc, char **argv) :
    MainApplication(argc, argv)
{
    lwApp = this;
    setApplicationName("Logwolf");
    setDesktopFileName(QStringLiteral("org.wireshark.Logwolf"));
}

LogwolfApplication::~LogwolfApplication()
{
    lwApp = NULL;
}

void LogwolfApplication::refreshLocalInterfaces()
{
    extcap_clear_interfaces();

#ifdef HAVE_LIBPCAP
    /*
     * Reload the local interface list.
     */
    scan_local_interfaces(true, main_window_update);

    /*
     * Now emit a signal to indicate that the list changed, so that all
     * places displaying the list will get updated.
     *
     * XXX - only if it *did* change.
     */
    emit localInterfaceListChanged();
#endif
}
