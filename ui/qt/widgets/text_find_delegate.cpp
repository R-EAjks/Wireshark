/* text_find_delegate.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Delegate for show and highlight found text in an item.
 */

#include "text_find_delegate.h"
#include <ws_attributes.h>

#include <QCheckBox>
#include <QEvent>
#include <QKeyEvent>
#include <QLabel>
#include <QLinearGradient>
#include <QLineEdit>
#include <QPainter>
#include <QPalette>
#include <QPoint>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStyleOptionViewItem>

#define TEXTSEARCHDELEGATE_CHECKBOX "TextFindDelegate::checkBox"
#define TEXTSEARCHDELEGATE_LINEEDIT "TextFindDelegate::lineEdit"

/* Attach TextFindDelegate to the view.
 * It creates Find line controls in textSearchLayout, but just in
 * case they do not exists there. It avoids duplication in multitab
 * dialogs.
 * eventSource can be NULL.
 */
TextFindDelegate *TextFindDelegate::attachToView(QObject *parent, QAbstractItemView *view, QBoxLayout *textSearchLayout, QObject *eventSource)
{
    QCheckBox *checkBox;
    QLineEdit *lineEdit;

    // Create the delegate and connect it to the view
    TextFindDelegate *textSearchDelegate = new TextFindDelegate(parent, view);
    view->setItemDelegate(textSearchDelegate);
    view->setTextElideMode(Qt::ElideNone);

    // Attach filtering model to the view
    QSortFilterProxyModel *model = new QSortFilterProxyModel(parent);
    model->setSourceModel(view->model());
    model->setFilterKeyColumn(-1);
    view->setModel(model);

    if (eventSource) {
        eventSource->installEventFilter(textSearchDelegate);
    }

    // Try to find already existing controls
    lineEdit = parent->findChild<QLineEdit *>(TEXTSEARCHDELEGATE_LINEEDIT);
    checkBox = parent->findChild<QCheckBox *>(TEXTSEARCHDELEGATE_CHECKBOX);

    if (!lineEdit) {
        // lineEdit does not exist, create it
        textSearchLayout->addWidget(new QLabel(tr("Search:"), (QWidget *)parent));
        lineEdit = new QLineEdit((QWidget *)parent);
        lineEdit->setObjectName(TEXTSEARCHDELEGATE_LINEEDIT);
        lineEdit->setToolTip(tr("Type text to highlight it in the view. Press Ctrl+F to focus the field."));
        textSearchLayout->addWidget(lineEdit);

        // checkBox does not exist, create it
        checkBox = new QCheckBox(tr("Case sensitive"), (QWidget *)parent);
        checkBox->setObjectName(TEXTSEARCHDELEGATE_CHECKBOX);
        textSearchLayout->addWidget(checkBox);

        QPushButton *pushButton = new QPushButton(tr("Clear"), (QWidget *)parent);
        textSearchLayout->addWidget(pushButton);
        connect(pushButton, SIGNAL(pressed()), lineEdit, SLOT(clear()));
    }
    textSearchDelegate->setLineEdit(lineEdit);
    textSearchDelegate->setCheckBox(checkBox);

    // Connect signals from controls to the delegate
    connect(checkBox, SIGNAL(stateChanged(int)), textSearchDelegate, SLOT(setCaseSensitivity(int)));
    connect(lineEdit, SIGNAL(textChanged(QString)), textSearchDelegate, SLOT(setSearchText(QString)));

    return textSearchDelegate;
}

void TextFindDelegate::detachFromView(QAbstractItemView *view, QObject *eventSource)
{
    TextFindDelegate *textSearchDelegate = dynamic_cast<TextFindDelegate *>(view->itemDelegate());
    if (textSearchDelegate) {
        disconnect(textSearchDelegate->getCheckBox(), SIGNAL(stateChanged(int)), textSearchDelegate, SLOT(setCaseSensitivity(int)));
        disconnect(textSearchDelegate->getLineEdit(), SIGNAL(textChanged(QString)), textSearchDelegate, SLOT(setSearchText(QString)));
        if (eventSource) {
            eventSource->removeEventFilter(textSearchDelegate);
        }
    }
}

TextFindDelegate::TextFindDelegate(QObject *parent, QAbstractItemView *view) :
    QStyledItemDelegate(parent),
    textToSearch_(""),
    caseSensitivity_(Qt::CaseInsensitive),
    view_(view)
{
}

/* Note: painter->save()/->restore() should be called outside the function */
void TextFindDelegate::paintRangeHighlight(QPainter *painter, const QStyleOptionViewItem &option, const QString text, int from, int to) const
{
    QString t;
    QRect textb;
    int textw;
    int start;
    int maxw;
    QRect highlight;

    // Calculate textwidth
    textb = option.fontMetrics.boundingRect(text);
    maxw = qMax(textb.width(), option.fontMetrics.horizontalAdvance(text));

    if (from > 0)
    {
        // Highlight should start after "from" characters
        t = text.mid(0, from);
        textb = option.fontMetrics.boundingRect(t);
        textw = qMax(textb.width(), option.fontMetrics.horizontalAdvance(t));
        start = textb.x() + textw;
    } else {
        // Hightligth should start before first character
        textb = option.fontMetrics.boundingRect(" ");
        start = textb.x();
    }

    // Calculate point after "to" character
    if (text.length() <= to)
    {
        t = text;
    } else {
        t = text.mid(0, to + 1);
    }
    textb = option.fontMetrics.boundingRect(t);
    textw = qMax(textb.width(), option.fontMetrics.horizontalAdvance(t));

    highlight = textb;
    highlight.setWidth(textw - start);
    highlight.setHeight(option.rect.height());

    // Handle allignment
    if (option.displayAlignment.testFlag(Qt::AlignRight)) {
        highlight.translate(option.rect.bottomRight());
        // TODO: Calculate left offset and replace +2 with it
        highlight.translate(-maxw + start -2 , -2);
    } else {
        //highlight = QRect(option.rect.left() + start + 2, option.rect.top(), textw - start, option.rect.height());
        highlight.translate(option.rect.bottomLeft());
        // TODO: Calculate left offset and replace +2 with it
        highlight.translate(start + 2, -2);
    }

    // Draw yellow transparent background
    QColor c = QColor(Qt::yellow);
    c.setAlpha(127);
    painter->fillRect(highlight, QBrush(c));
}

void TextFindDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    // Draw common text
    QStyledItemDelegate::paint(painter, option, index);

    if (textToSearch_.length() > 0)
    {
        QString text = index.data(Qt::DisplayRole).toString();
        int pos = 0;
        int len = textToSearch_.length();

        QStyleOptionViewItem opt = option;
        initStyleOption(&opt, index);

        painter->save();
        painter->setClipRect(opt.rect);

        while ((pos = text.indexOf(textToSearch_, pos, caseSensitivity_)) != -1) {
            paintRangeHighlight(painter, opt, text, pos, pos + len - 1);
            ++pos;
        }

        painter->restore();
    }
}

void TextFindDelegate::setSearchText(const QString text)
{
    textToSearch_ = text;
    if (view_) {
        QSortFilterProxyModel *m = dynamic_cast<QSortFilterProxyModel *>(view_->model());
        if (m) {
            // Some views replace our model so this point is not reached
            m->setFilterWildcard(text);
            m->invalidate();
        }
        view_->viewport()->update();
    }
}

void TextFindDelegate::setCaseSensitivity(int sensitive)
{
    if (sensitive) {
        caseSensitivity_ = Qt::CaseSensitive;
    } else {
        caseSensitivity_ = Qt::CaseInsensitive;
    }
    if (view_) {
        QSortFilterProxyModel *m = dynamic_cast<QSortFilterProxyModel *>(view_->model());
        if (m) {
            // Some views replace our model so this point is not reached
            m->setFilterCaseSensitivity(caseSensitivity_);
            m->invalidate();
        }
        view_->viewport()->update();
    }
}

QCheckBox *TextFindDelegate::getCheckBox()
{
    return checkBox_;
}

void TextFindDelegate::setCheckBox(QCheckBox *checkBox)
{
    checkBox_ = checkBox;
}

QLineEdit *TextFindDelegate::getLineEdit()
{
    return lineEdit_;
}

void TextFindDelegate::setLineEdit(QLineEdit *lineEdit)
{
    lineEdit_ = lineEdit;
}

bool TextFindDelegate::eventFilter(QObject *, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent &keyEvent = static_cast<QKeyEvent&>(*event);

        if ((Qt::Key_F == keyEvent.key()) &&
            (keyEvent.modifiers() == Qt::ControlModifier)
           ) {
            // Ctrl+F
            if (lineEdit_) {
                lineEdit_->setFocus();
            }

            return true;
        }
    }

    return false;
}

