/** text_find_delegate.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/** Delegate highlights found text in all cells of view.
 *
 *  String set by setSearchText() signal is searched in the view and all
 *  occurences are highlighed. setCaseSensitivity() signal enables/disables
 *  case sensitivity search. Case insensitive searc is default.
 *  Event filter can be attached to any view and it listens for Ctrl+F shortcut
 *  and focus find control.
 *
 *  Limits:
 *
 *  Highlight is drawn as 50% transparent yellow box over text. There is no
 *  better way (e.g. yellow background) without rewriting Qt code or copy code
 *  from Qt.
 *
 *  Text is searched in text as shown (DisplayRole). Therefore formatted
 *  numbers must be entered as shown (e.g. '12' is not found in 1,200, user
 *  must enter '1,2').
 *
 *  Use:
 *
 *  To attach it to view, use attachToView() function. It requires
 *  QAbstractItemView where data are searched and QBoxLayout to where find
 *  controls are added.
 *
 *  attachToView() supports multitab views and find controls are added just
 *  once. Same text is seached in every tab.
 *
 *  Example:
 *
 *  XXX_dialog.ui:
 *  Add to suitable place. Name (textSearchLayout) is example, you can use any
 *  name, but the layout box should be passed to attachToView().
 *
 *  <item>
 *    <layout class="QHBoxLayout" name="textSearchLayout"/>
 *  </item>
 *
 *  XXX_dialog.cpp, XXX_dialog constructor:
 *  ...
 *  TextFindDelegate::attachToView(this, ui->view, ui->textSearchLayout, this);
 *  ...
 *
 *  In case dialog use multiple tabs, you should attach it to every tab.
 *  Check e.g. endpoint_dialog.cpp, addTrafficTable().
 *
 */

#ifndef TEXT_FIND_DELEGATE_H
#define TEXT_FIND_DELEGATE_H

#include "config.h"

#include <QStyledItemDelegate>
#include <QAbstractItemView>
#include <QBoxLayout>
#include <QCheckBox>
#include <QLineEdit>

class TextFindDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    static TextFindDelegate *attachToView(QObject *parent, QAbstractItemView *view, QBoxLayout *textSearchLayout, QObject *eventSource);
    static void detachFromView(QAbstractItemView *view, QObject *eventSource);

    virtual void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

public slots:
    void setSearchText(const QString text);
    void setCaseSensitivity(int sensitive);

protected:
    /* Constructor is protected, it should be created with static build method only */
    TextFindDelegate(QObject *parent, QAbstractItemView *view);
    bool eventFilter(QObject *, QEvent *event) override;

private:
    QString textToSearch_;
    Qt::CaseSensitivity caseSensitivity_;
    QAbstractItemView *view_;
    QCheckBox *checkBox_;
    QLineEdit *lineEdit_;

    void paintRangeHighlight(QPainter *painter, const QStyleOptionViewItem &option, const QString text, int from, int to) const;
    QCheckBox *getCheckBox();
    void setCheckBox(QCheckBox *checkBox);
    QLineEdit *getLineEdit();
    void setLineEdit(QLineEdit *lineEdit);
};

#endif //TEXT_FIND_DELEGATE_H
