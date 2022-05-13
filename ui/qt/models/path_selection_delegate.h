/** @file
 *
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PATH_SELECTION_DELEGATE_H_
#define PATH_SELECTION_DELEGATE_H_

#include <QStyledItemDelegate>

class PathSelectionDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    PathSelectionDelegate(QObject *parent = 0);

protected:
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &idx) const;
    void updateEditorGeometry (QWidget * editor, const QStyleOptionViewItem & option, const QModelIndex & idx) const;
    void setEditorData(QWidget *editor, const QModelIndex &idx) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &idx) const;

protected slots:
    void pathHasChanged(QString newPath);

};

#endif /* PATH_SELECTION_DELEGATE_H_ */
