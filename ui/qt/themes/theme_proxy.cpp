/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/themes/theme_proxy.h>

#include <QFile>
#include <QTextStream>
#include <QPalette>
#include <QStyleFactory>

ThemeProxyStyle::ThemeProxyStyle(): 
    QProxyStyle(baseStyle()) 
{
    selStyle = ThemeProxyStyle::LightThemeStyle;
}

ThemeProxyStyle::ThemeProxyStyle(QStyle *style): 
    QProxyStyle(style) 
{
    selStyle = ThemeProxyStyle::LightThemeStyle;
}

ThemeProxyStyle::ThemeProxyStyle(ProxyThemeStyles setStyle):
    QProxyStyle(baseStyle())
{
    selStyle = setStyle;
}

QStyle* ThemeProxyStyle::baseStyle() const { 
    return QStyleFactory::create(QString("fusion")); 
}

void ThemeProxyStyle::polish(QPalette &palette) {
    // modify palette to dark
    if (selStyle == ThemeProxyStyle::DarkThemeStyle)
    {
        palette.setColor(QPalette::Window, QColor(53, 53, 53));
        palette.setColor(QPalette::WindowText, Qt::white);
        palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor(127, 127, 127));
        palette.setColor(QPalette::Base, QColor(42, 42, 42));
        palette.setColor(QPalette::AlternateBase, QColor(66, 66, 66));
        palette.setColor(QPalette::ToolTipBase, Qt::white);
        palette.setColor(QPalette::ToolTipText, QColor(53, 53, 53));
        palette.setColor(QPalette::Text, Qt::white);
        palette.setColor(QPalette::Disabled, QPalette::Text, QColor(127, 127, 127));
        palette.setColor(QPalette::Dark, QColor(35, 35, 35));
        palette.setColor(QPalette::Shadow, QColor(20, 20, 20));
        palette.setColor(QPalette::Button, QColor(53, 53, 53));
        palette.setColor(QPalette::ButtonText, Qt::white);
        palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(127, 127, 127));
        palette.setColor(QPalette::BrightText, Qt::red);
        palette.setColor(QPalette::Link, QColor(42, 130, 218));
        palette.setColor(QPalette::Highlight, QColor(42, 130, 218));
        palette.setColor(QPalette::Disabled, QPalette::Highlight, QColor(80, 80, 80));
        palette.setColor(QPalette::HighlightedText, Qt::white);
        palette.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor(127, 127, 127));
    }
}

void ThemeProxyStyle::polish(QApplication *app) {
    if (!app) 
        return;

    if (selStyle == ThemeProxyStyle::DarkThemeStyle)
    {
        QString styleSheet = ":darkstyle/darkstyle.qss";

        QFile styleSheetFile(styleSheet);
        if (styleSheetFile.open(QFile::ReadOnly | QFile::Text)) 
        {
            QTextStream ts(&styleSheetFile);
            app->setStyleSheet(ts.readAll());
        }
    }
    else
        app->setStyleSheet("");
}
