/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_SUPPORT_H
#define THEME_SUPPORT_H

#include <config.h>

#include <QObject>
#include <QStyle>

class ThemeSupport : public QObject
{
    Q_OBJECT
public:
    explicit ThemeSupport();

    enum AvailableThemes
    {
        System      = 0, //< use the theme set by the system
        LightTheme  = 1, //< force a light theme
        DarkTheme   = 2  //< force a dark theme
    };

    void setTheme(AvailableThemes newTheme);
    AvailableThemes theme();

    bool darkThemeAvailable() const;
    bool darkThemeActive() const;

signals:
    void themeHasChanged();

protected:
    virtual bool eventFilter(QObject* obj, QEvent* event);

private:
    AvailableThemes _currentTheme;
    QString _startupStyle;

private slots:
    void handlePaletteChange();
};

#endif // THEME_SUPPORT_H
