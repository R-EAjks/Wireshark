/* hover_treeview.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HOVERTREEVIEW_H
#define HOVERTREEVIEW_H

#include <QTreeView>

class HoverTreeView : public QTreeView
{
    Q_OBJECT

public:
    HoverTreeView(QWidget *parent = Q_NULLPTR);

    virtual QModelIndex currentHoveredIndex() const;

Q_SIGNALS:
    void hoveredIndexChanged();

protected:
    virtual bool event(QEvent *event) override;
    virtual bool viewportEvent(QEvent *event) override;
    virtual void setHoverIndex(const QPersistentModelIndex &);

private:
    QModelIndex hoverIndex;
};

#endif // HOVERTREEVIEW_H

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
