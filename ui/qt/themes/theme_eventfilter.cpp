/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/themes/theme_eventfilter.h>

#ifdef Q_OS_WINDOWS
#include <Windows.h>
#endif

ThemeEventFilter::ThemeEventFilter(QObject* parent) : QObject(parent) {}

bool ThemeEventFilter::nativeEventFilter(const QByteArray& eventType, void* message, long*)
{
#ifdef Q_OS_LINUX
    if (eventType == "xcb_generic_event_t") {

    }
#endif
#ifdef Q_OS_MAC
    if (eventType == "mac_generic_NSEvent") {

    }
#endif
#ifdef Q_OS_WINDOWS
#if(_WIN32_WINNT >= 0x0501)
    LRESULT code = WM_STYLECHANGED;
    /* Windows 10 in later versions explicitely informs of the color scheme change */
#if(_WIN32_WINNT >= 0x0600)
    code = WM_DWMCOLORIZATIONCOLORCHANGED;
#endif 
    if (eventType == "windows_generic_MSG") {
        MSG* msg = (MSG*)message;
        if (msg->message == code)
            themeChanged();
    }
#endif
#endif

    return false;
};
