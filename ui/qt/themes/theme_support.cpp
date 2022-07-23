/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "theme_support.h"

#include "wireshark_application.h"

#include <ui/qt/themes/theme_eventfilter.h>
#include <ui/qt/themes/theme_proxy.h>

#include <QAbstractEventDispatcher>
#include <QSettings>

#ifdef Q_OS_MAC
#include <ui/macosx/cocoa_bridge.h>
#endif

#ifdef Q_OS_WINDOWS
#include <QOperatingSystemVersion>
#endif

ThemeSupport::ThemeSupport()
{
    _startupStyle = wsApp->style()->objectName();

    ThemeEventFilter* tef = new ThemeEventFilter(this);
    connect(tef, &ThemeEventFilter::themeChanged, this, &ThemeSupport::handlePaletteChange);
    QAbstractEventDispatcher::instance()->installNativeEventFilter(tef);
}

void ThemeSupport::setTheme(ThemeSupport::AvailableThemes newTheme)
{
    if (newTheme != _currentTheme)
    {
        _currentTheme = newTheme;

        handlePaletteChange();
    }
}

ThemeSupport::AvailableThemes ThemeSupport::theme()
{
    return _currentTheme;
}

bool ThemeSupport::darkThemeAvailable() const
{
    bool result = false;

#ifdef Q_OS_MAC
    result = CocoaBridge::DarkThemeAvailable();
#else
#ifdef Q_OS_WINDOWS
    /* dark mode supported Windows 10 1809 10.0.17763 onward
     * https://stackoverflow.com/questions/53501268/win10-dark-theme-how-to-use-in-winapi
     */
    if (( QOperatingSystemVersion::current().majorVersion() > 10 ) ||
        ( QOperatingSystemVersion::current().majorVersion() == 10 && (QOperatingSystemVersion::current().microVersion() >= 17763)))
        result = true;
#endif
#endif

    return result;
}

bool ThemeSupport::eventFilter(QObject *obj, QEvent *event)
{
    /* Only interested in palette changes for the main application.
     * This won't trigger when the color changes on Windows (for that the nativeeventfilter is required)
     * But it will trigger on MacOSx
     */
    if (qobject_cast<MainApplication *>(obj) && event->type() == QEvent::ApplicationPaletteChange)
    {
        handlePaletteChange();
        return true;
    }

    return QObject::eventFilter(obj, event);
}

void ThemeSupport::handlePaletteChange()
{
    bool changeTheme = false;
    bool isDark = false;

    if (_currentTheme == ThemeSupport::System)
    {
        static int lastVal = -1;

#ifdef Q_OS_WINDOWS
        QSettings themes("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", QSettings::NativeFormat);
        int val = themes.value("AppsUseLightTheme").toInt();
        if (val != lastVal) {
            isDark = (val == 0);
            lastVal = val;
            changeTheme = true;
        }
#else
#endif
    }
    else
    {
        isDark = _currentTheme == ThemeSupport::DarkTheme;
        changeTheme = true;
    }

    if (changeTheme)
    {
        if (isDark)
            wsApp->setStyle(new ThemeProxyStyle(ThemeProxyStyle::DarkThemeStyle));
        else
            wsApp->setStyle(new ThemeProxyStyle(ThemeProxyStyle::LightThemeStyle));
    }
}

bool ThemeSupport::darkThemeActive() const
{
    if (_currentTheme == ThemeSupport::System)
    {
#ifdef Q_OS_WINDOWS
        QSettings themes("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", QSettings::NativeFormat);
        int val = themes.value("AppsUseLightTheme").toInt();
        return (val == 0);
#endif
#ifdef Q_OS_MAC
        if (CocoaBridge::DarkThemeAvailable())
            return CocoaBridge::IsInDarkTheme();
#endif
    }

    return (_currentTheme == ThemeSupport::DarkTheme);
}
