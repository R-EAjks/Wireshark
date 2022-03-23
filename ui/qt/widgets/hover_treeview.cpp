/* hover_treeview.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "hover_treeview.h"

#include <QEvent>
#include <QHoverEvent>

HoverTreeView::HoverTreeView(QWidget *parent) :
    QTreeView(parent)
{}

void HoverTreeView::setHoverIndex(const QPersistentModelIndex &hover)
{
    if ( hoverIndex == hover )
        return;

    if (selectionBehavior() != QAbstractItemView::SelectRows) {
        update(hoverIndex); //update the old one
        update(hover); //update the new one
    } else {
        QRect oldHoverRect = visualRect(hoverIndex);
        QRect newHoverRect = visualRect(hover);
        viewport()->update(QRect(0, newHoverRect.y(), viewport()->width(), newHoverRect.height()));
        viewport()->update(QRect(0, oldHoverRect.y(), viewport()->width(), oldHoverRect.height()));
    }
    hoverIndex = hover;
}

QModelIndex HoverTreeView::currentHoveredIndex() const
{
    return hoverIndex;
}

bool HoverTreeView::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::HoverEnter:
    case QEvent::HoverMove: {
        QPoint viewPortPos = viewport()->mapFromGlobal(mapToGlobal(static_cast<QHoverEvent*>(event)->pos()));
        setHoverIndex(indexAt(viewPortPos));
        break; }
    default:
        break;
    }
    return QTreeView::event(event);
}

bool HoverTreeView::viewportEvent(QEvent *event)
{
    switch (event->type()) {
    case QEvent::HoverEnter:
    case QEvent::HoverMove:
        setHoverIndex(indexAt(static_cast<QHoverEvent*>(event)->pos()));
        break;
    case QEvent::HoverLeave:
    case QEvent::Leave:
        setHoverIndex(QModelIndex());
        break;
    default:
        break;
    }
    return QTreeView::viewportEvent(event);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
