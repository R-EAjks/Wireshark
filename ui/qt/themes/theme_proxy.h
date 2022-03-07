/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_PROXY_H
#define THEME_PROXY_H

#include <QProxyStyle>
#include <QStyle>
#include <QPalette>
#include <QApplication>

class ThemeProxyStyle : public QProxyStyle {
  Q_OBJECT

public:
    enum ProxyThemeStyles{
        DarkThemeStyle,
        LightThemeStyle
    };

    ThemeProxyStyle(ProxyThemeStyles setStyle);
    ThemeProxyStyle();
    explicit ThemeProxyStyle(QStyle *style);

    QStyle* baseStyle() const;

    void polish(QPalette &palette) override;
    void polish(QApplication *app) override;

private:
    ProxyThemeStyles selStyle;
};

#endif // THEME_PROXY_H
