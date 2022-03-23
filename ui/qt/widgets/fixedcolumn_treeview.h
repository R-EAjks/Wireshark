/* fixedcolumn_treeview.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIXEDCOLUMN_TREEVIEW_H
#define FIXEDCOLUMN_TREEVIEW_H

#include <QTreeView>
#include <QHeaderView>
#include <QLabel>

#include "hover_treeview.h"

class FixedColumnTreeView;

/*
 * This is an INTERNAL class for the FixedColumnTreeView.
 * Not intended to being used outside of this context
 */
class FixedColumnTreeHeader: public QHeaderView
{
    Q_OBJECT
public:
    FixedColumnTreeHeader(Qt::Orientation, QWidget *parent = Q_NULLPTR);

protected:
    virtual void paintSection(QPainter *painter, const QRect &rect, int logicalIndex) const override;

private slots:
    void indicatorChanged(int logicalIndex, Qt::SortOrder order);
    void geometriesHaveChanged();
    void sectionsResized(int logicalIndex, int oldSize, int newSize);
    void sectionsMoved(int logicalIndex, int oldVisualIndex, int newVisualIndex);

    /* copied from Qt src code (QHeaderViewprivate::sectionHandleAt(int position) */
    int sectionAt(int position);

private:
    enum TreeViewState
    {
        None,
        MoveSection,
        ResizeSection
    };

    QLabel * movSecIndicator;
    TreeViewState state;
    int pressed;
    int section;
    int target;
    int firstPos;
    int lastPos;
    int indicatorOffset;
    int activePos;

    void mousePress(QMouseEvent *me);
    void mouseMove(QMouseEvent *me);
    void mouseRelease(QMouseEvent *me);

    void setupIndicator(int section, int position);
    void updateIndicator(int section, int position);

    void setActiveSection(int position);

    friend FixedColumnTreeView;
};

/*
 * This is an INTERNAL class for the FixedColumnTreeView.
 * Not intended to being used outside of this context
 */
class ViewPortTreeView : public QTreeView
{
    Q_OBJECT
public:
    ViewPortTreeView(QWidget *parent);

private:
    void forceEvent(QEvent *ev);
    void setActive(bool);

    virtual void drawRow(QPainter *painter, const QStyleOptionViewItem &options, const QModelIndex &index) const override;

    bool active_;

    friend FixedColumnTreeView;
};

/*!
  \class FixedColumnTreeView
  \brief The FixedColumnTreeView provides the possibilities to fixate columns while scrolling
  sideways.

  \ingroup Wireshark
  \ingroup Widgets

  A FixedColumnTreeView allows to fixate a part of the displayed columns on the left of the view
  and therefore having them stay in place while scrolling sideways. This is a popular UI technique
  used in various spreadsheet applications.

  In order to achieve this functionality, a second QTreeView (fixedTreeView_) is being super-
  imposed over the original QTreeView, which represents the fixed columns, while the actual columns
  are being scrolled underneath.

  Also, a second QHeaderView (fixedTreeHeader_) is being implemented, which will display the
  column headers.

  Much of the code in this class handles various glitches and UI functionalities which are presented
  because of this implementation detail. This class is implemented in such a way, that it can function
  as a replacement for any QTreeView implementation, although it is most commonly used for the
  PacketList (\c PacketList).

  \section1 Viewport vs. Display
  Important to note is the fact, that much of the manipulation taking place has to consider not only
  the position of the widget, but also it's viewport. A viewport is a widget super-imposed on an individual
  widget and actually represents the scrollable, displayed area, while the original widget is sliding,
  the viewport stays in place. A lot of the events triggered by the user, not actual are triggered for
  the widget itself, but rather the viewport and must therefore be traversed before further handling.

  \section1 VisualIndex vs. LogicalIndex
  A headerview usually has two indeces, a logical one and a visual one. The logical index is the index
  from the original model, while the visual index is it's position inside the viewport display. To ease
  implementation, throughout this class the logical index is used where applicable.

  \sa QTreeView
  \sa QHeaderView
  \sa PacketList
 */
class FixedColumnTreeView : public HoverTreeView
{
    Q_OBJECT
public:
    FixedColumnTreeView(QWidget * parent = Q_NULLPTR);

    /*
     * Returns the information if a context menu is being displayed in the treeview
     */
    bool isContextMenuActive() const;

    /*
     * Returns the information if columns are fixed or not
     */
    bool isColumnFixed() const;

    /*
     * Overwridden public methods.
     *
     * The following methods are being overwridden in functionality, to being able to
     * implement the fixate columns. They work identical to their respective QTreeView
     * methods, documentation can be found there.
     */

    void setModel(QAbstractItemModel *model) override;
    void setHeader(QHeaderView *header);
    void setFont(const QFont &font);
    void setItemDelegateForColumn(int column, QAbstractItemDelegate * delegate);
    void setColumnWidth(int column, int width);
    void setVerticalScrollBar(QScrollBar *scrollbar);
    void setTextElideMode(Qt::TextElideMode mode);

    virtual bool eventFilter(QObject *watched, QEvent *event) override;

    virtual QModelIndex indexAt(const QPoint &point) const override;

Q_SIGNALS:
    /*
     * Is being called, immediately BEFORE a context menu will be shown
     */
    void showContextMenu();
    /*
     * Is being called, immediately AFTER a context menu has been shown
     */
    void hideContextMenu();

public slots:

    /*
     * Set the number of fixed columns.
     *
     * If set to -1 (or any other negative number), all fixed columns are being resetted.
     * If set to a number >= 0, a check is being performed, if the model has enough columns
     * and if so, the column with the same visualIndex will be set as the maximum column
     * for fixation. (e.g. if set to 1 the first 2 columns in the treeview will be fixated)
     *
     * \note This is the logical index for the column! Not the visual index. If this slot
     * is being called with the index column, everything is correct and working as intended.
     * If it is being called with a section value from a HeaderView, it must be insured, that
     * the section value is indeed the logical one.
     */
    void setFixedColumn(int column);

    /*
     * Overwridden public slot
     *
     * The following method is being overwridden in functionality, to being able to
     * implement the fixate columns. It works identical to the respective QTreeView
     * slot, documentation can be found there.
     */

    void setStyleSheet(const QString &styleSheet);

protected:
    /*
     * Sets the active flag on the fixated tree view
     *
     * The treeview for the fixated columns is being implemented with the flag
     * Qt::WA_TransparentForMouseEvents. This means it will NEVER receive mouse events
     * and therefore can never have the focus. If a stylesheet is being provided, which
     * implicitly sets different styles for active and !active lines, the display would
     * show the active style on the active line of the underlying treeview and the
     * inactive style of the overlying fixated treeview. Setting explicitely the flag
     * for the fixated treeview prevents that. This also implies, that the row repainted
     * is the only affected, but this is the current implementation for Qt 5.12 LTS.
     */
    void setFixedTreeActive(bool active);

    /*
     * Override menu for the context menu
     *
     * Implementing a custom context menu is not applicable for this treeview. It would
     * impose real issues with displaying the menu, if the click would have occured over
     * the fixated columns. To being able to display a context menu, not the context menu
     * event must be overwridden, but this method, which will return the context menu
     * to be displayed.
     */
    virtual QMenu * contextMenu(QModelIndex at);

    /*
     * Handle hover events from viewport
     *
     * This handles hover events, propagated by the viewportEvent. HoverEvents are being
     * sent in the normal event handler as well, but only on Linux/Mac and not on Windows.
     * HoverEnter and HoverLeave are being handled identical to HoverMove, and there are
     * checks in place, if the hover position occurs over the viewport or not. This happens
     * when the hover reaches the border of the viewport, but still resides within the parent
     * widget. Additionally, if the new position is outside the viewport, the fixedcolumn
     * will receive a HoverLeave event to clear the display.
     */
    virtual bool hoverEvent(QHoverEvent *event);

    /*
     * Overwridden protected methods.
     *
     * The following methods are being overwridden in functionality, to being able to
     * implement the fixate columns. They work identical to their respective QTreeView
     * methods, documentation can be found there.
     */

    QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers) override;
    void scrollTo (const QModelIndex & index, ScrollHint hint = EnsureVisible) override;
    virtual void resizeEvent(QResizeEvent *event) override;
    virtual void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected) override;
    virtual void focusInEvent(QFocusEvent *event) override;
    virtual void focusOutEvent(QFocusEvent *event) override;
    virtual bool viewportEvent(QEvent *event) override;

    virtual void setHoverIndex(const QPersistentModelIndex &) override;

protected slots:
    /*
     * Slot for informing of the context menu about to be closed
     */
    virtual void contextMenuClosed();

    /*
     * Overwridden protected slot
     *
     * The following method is being overwridden in functionality, to being able to
     * implement the fixate columns. It works identical to the respective QTreeView
     * slot, documentation can be found there.
     */
    void columnResized(int column, int oldSize, int newSize);

private:
    ViewPortTreeView * fixedTreeView_;
    FixedColumnTreeHeader * fixedTreeHeader_;
    int fixedColumn_;
    bool contextMenuActive_;
    bool headerContextMenuActive_;
    bool scrollDragActive_;
    QPoint lastHover_;
    int lastHScroll_;
    int lastVScroll_;
    int hiddenSections_;

    bool isFixedColumn(int);
    void setFixedColumnsWidth(int);

    int columnWidths(QTreeView * element = Q_NULLPTR);

    void setColumnVisibility();

    bool isPositionOutsideViewport(QPoint pos);
    bool isPositionOverFixedColumn(QPoint pos);
    QPoint setToViewpointEdge(QPoint pos);

private slots:
    void updateFixedTreeView();
    void updateFixedGeometry();

    void updateSectionWidth(int logicalIndex, int oldSize, int newSize);
    void updateSectionVisualIndex(int logicalIndex, int oldVisualIndex, int newVisualIndex);
    void contextMenuEvent(QContextMenuEvent *event) final;
    void contextMenuRequested(const QPoint & pos);
};

#endif // FIXEDCOLUMN_TREEVIEW_H

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
