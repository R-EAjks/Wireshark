/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: 0BSD
 */

#ifndef FIELD_VALUES_DIALOG_H
#define FIELD_VALUES_DIALOG_H

#include <config.h>
#include <glib.h>

#include <QTreeWidgetItem>
#include <QMenu>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "file.h"
#include "wireshark_dialog.h"

namespace Ui {
class FieldValuesDialog;
}

class FieldValuesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit FieldValuesDialog(QWidget &parent, CaptureFile &cf);
    ~FieldValuesDialog();

private slots:
    void on_buttonBox_rejected();

    void updateWidgets();
    void updateHintLabel();

    void filterLineEditChanged(const QString &text);

    void tableContextMenu(const QPoint &pos);
    void on_actionMark_Unmark_Cell_triggered();
    void on_actionMark_Unmark_Row_triggered();
    void on_actionCopy_Cell_triggered();
    void on_actionCopy_Rows_triggered();
    void on_actionCopy_All_triggered();
    void on_actionSave_as_image_triggered();

protected:
    void keyPressEvent(QKeyEvent *event);

private:
    Ui::FieldValuesDialog  *ui;

    QMenu                   context_menu_;
    const field_info       *finfo_;
    QString                 hint_label_;
    const static int cell_width = -13;
};

class FvTreeWidgetItem : public QTreeWidgetItem
{
public:
    FvTreeWidgetItem(QTreeWidget* parent);

    bool operator<(const QTreeWidgetItem &other) const;

private:
    QTreeWidget* treeWidget;
};


#endif // FIELD_VALUES_DIALOG_H
