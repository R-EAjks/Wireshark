/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_EVENTFILTER_H
#define THEME_EVENTFILTER_H

#include <config.h>

#include <QObject>
#include <QStyle>
#include <QAbstractNativeEventFilter>

class ThemeEventFilter : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT
public:
    explicit ThemeEventFilter(QObject* parent = 0);

    virtual bool nativeEventFilter(const QByteArray& eventType, void* message, long*);

signals:
    void themeChanged();
};

#endif // THEME_EVENTFILTER_H