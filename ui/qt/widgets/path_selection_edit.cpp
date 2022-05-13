/* path_chooser_delegate.cpp
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "epan/prefs.h"
#include "ui/last_open_dir.h"

#include <ui/qt/widgets/path_selection_edit.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QHBoxLayout>
#include <QPushButton>
#include <QWidget>
#include <QLineEdit>

PathSelectionEdit::PathSelectionEdit(QString title, QString path, bool selectFile, QWidget *parent) : 
    _title(title),
    _path(path),
    _selectFile(selectFile),
    QWidget(parent)
{
    _edit = new QLineEdit(this);
    _edit->setText(_path);
    connect(_edit, &QLineEdit::textChanged, this, &PathSelectionEdit::setPath);

    _button = new QPushButton(this);
    _button->setText(tr("Browse"));
    connect(_button, &QPushButton::clicked, this, &PathSelectionEdit::browseForPath);

    setContentsMargins(0, 0, 0, 0);
    QHBoxLayout *hbox = new QHBoxLayout(this);
    hbox->setContentsMargins(0, 0, 0, 0);
    hbox->addWidget(_edit);
    hbox->addWidget(_button);
    hbox->setSizeConstraint(QLayout::SetMinimumSize);

    setLayout(hbox);

    setFocusProxy(_edit);
    setFocusPolicy(_edit->focusPolicy());

    updateWidgets();
}

PathSelectionEdit::PathSelectionEdit(QWidget *parent) : 
    PathSelectionEdit(tr("Select a path"), QString(), true, parent)
{}

void PathSelectionEdit::setPath(QString newPath)
{
    _path = newPath;
    emit pathChanged(newPath);
}

QString PathSelectionEdit::path() const
{
    return _path;
}

void PathSelectionEdit::updateWidgets()
{
    // Grow the item to match the editor. According to the QAbstractItemDelegate
    // documenation we're supposed to reimplement sizeHint but this seems to work.
    //QSize size = option.rect.size();
    //size.setHeight(qMax(option.rect.height(), hbox->sizeHint().height()));
}

void PathSelectionEdit::browseForPath()
{
    QString openDir = _path;

    if (openDir.isEmpty()) {
        if (prefs.gui_fileopen_style == FO_STYLE_LAST_OPENED) {
            openDir = QString(get_last_open_dir());
        } else if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED) {
            openDir = QString(prefs.gui_fileopen_dir);
        }
    }

    QString fileName = WiresharkFileDialog::getOpenFileName(this, _title, openDir);
    if (!fileName.isEmpty())
    {
        setPath(fileName);
    }
}