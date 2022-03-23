/* fixedcolumn_treeview.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "fixedcolumn_treeview.h"

#include <QHeaderView>
#include <QScrollBar>
#include <QMenu>
#include <QContextMenuEvent>
#include <QHoverEvent>
#include <QScrollBar>
#include <QApplication>
#include <QPainter>
#include <QDebug>

FixedColumnTreeHeader::FixedColumnTreeHeader(Qt::Orientation orientation, QWidget * parent) :
    QHeaderView(orientation, parent),
    movSecIndicator(Q_NULLPTR)
{
    setAcceptDrops(true);
    setSectionsMovable(true);
    setStretchLastSection(true);
    setDefaultAlignment(Qt::AlignLeft|Qt::AlignVCenter);
    setSortIndicatorShown(true);

    state = FixedColumnTreeHeader::None;
}

void FixedColumnTreeHeader::indicatorChanged(int logicalIndex, Qt::SortOrder order)
{
    setSortIndicator(logicalIndex, order);
}

void FixedColumnTreeHeader::geometriesHaveChanged()
{
    viewport()->update();
}

void FixedColumnTreeHeader::sectionsResized(int logicalIndex, int /*oldSize*/, int newSize)
{
    resizeSection(logicalIndex, newSize);
    viewport()->update();
}

void FixedColumnTreeHeader::sectionsMoved(int /*logicalIndex*/, int oldVisualIndex, int newVisualIndex)
{
    moveSection(oldVisualIndex, newVisualIndex);
    viewport()->update();
}

int FixedColumnTreeHeader::sectionAt(int position)
{
    QTreeView * pt = qobject_cast<QTreeView *>(parent());
    if ( ! pt )
        return -1;

    QHeaderView * ph = pt->header();

    int visual = ph->visualIndexAt(position);
    if (visual == -1)
        return -1;
    int log = ph->logicalIndex(visual);
    int pos = ph->sectionViewportPosition(log);
    int grip = ph->style()->pixelMetric(QStyle::PM_HeaderGripMargin, Q_NULLPTR, this);

    bool atLeft = position < pos + grip;
    bool atRight = (position > pos + ph->sectionSize(log) - grip);
    if (Qt::Horizontal && ph->isRightToLeft())
        qSwap(atLeft, atRight);

    if (atLeft) {
        //grip at the beginning of the section
        while(visual > -1) {
            int logical = ph->logicalIndex(--visual);
            if (!ph->isSectionHidden(logical))
                return logical;
        }
    } else if (atRight) {
        //grip at the end of the section
        return log;
    }
    return -1;
}

void FixedColumnTreeHeader::setActiveSection(int position)
{
    activePos = logicalIndexAt(position);
}

void FixedColumnTreeHeader::paintSection(QPainter *painter, const QRect &rect, int logicalIndex) const
{
    QTreeView * pt = qobject_cast<QTreeView *>(parent());
    if ( pt && activePos == logicalIndex )
    {
        QHeaderView * ph = pt->header();
        QPixmap pm = ph->grab(rect);

        painter->drawPixmap(rect, pm);
    }
    else
        QHeaderView::paintSection(painter, rect, logicalIndex);
}

void FixedColumnTreeHeader::setupIndicator(int section, int position)
{
    if ( ! movSecIndicator )
        movSecIndicator = new QLabel(viewport());

    QTreeView * pt = qobject_cast<QTreeView *>(parent());
    if ( ! pt )
        return;

    QHeaderView * ph = pt->header();
    int w = ph->sectionSize(section);
    int h = viewport()->height();
    int p = ph->sectionViewportPosition(section);

    const qreal pixmapDevicePixelRatio = devicePixelRatioF();
    QPixmap pm(QSize(w, h) * pixmapDevicePixelRatio);
    pm.setDevicePixelRatio(pixmapDevicePixelRatio);
    pm.fill(QColor(0, 0, 0, 45));
    QRect rect(0, 0, w, h);

    QPainter painter(&pm);
    const QVariant variant = ph->model()->headerData(section, orientation(),
                                               Qt::FontRole);
    if (variant.isValid() && variant.canConvert<QFont>()) {
        const QFont sectionFont = qvariant_cast<QFont>(variant);
        painter.setFont(sectionFont);
    } else {
        painter.setFont(font());
    }

    painter.setOpacity(0.75);
    QHeaderView::paintSection(&painter, rect, section);
    painter.end();

    movSecIndicator->setPixmap(pm);
    movSecIndicator->resize(w, h);

    indicatorOffset = position - qMax(p, 0);
}

void FixedColumnTreeHeader::updateIndicator(int section, int position)
{
    if ( ! movSecIndicator )
        return;

    if ( section == -1 || target == -1 )
    {
        movSecIndicator->hide();
        return;
    }

    if ( orientation() == Qt::Horizontal )
        movSecIndicator->move(position - indicatorOffset, 0);
    else
        movSecIndicator->move(0, position - indicatorOffset);

    movSecIndicator->show();
}

void FixedColumnTreeHeader::mousePress(QMouseEvent *me)
{
    if ( state != FixedColumnTreeHeader::None || me->button() != Qt::LeftButton )
        return;

    QTreeView * pt = qobject_cast<QTreeView *>(parent());
    if ( ! pt )
        return;

    QHeaderView * ph = pt->header();
    int pos = orientation() == Qt::Horizontal ? me->x() : me->y();
    int handle = sectionAt(pos) == -1;
    if ( handle )
    {
        pressed = ph->logicalIndexAt(pos);
        section = target = pressed;
        if ( section == -1 )
            return;

        state = FixedColumnTreeHeader::MoveSection;
        setupIndicator(section, pos);
    } else if ( ph->sectionResizeMode(handle) == Interactive )
        state = FixedColumnTreeHeader::ResizeSection;

    firstPos = lastPos = pos;
}

void FixedColumnTreeHeader::mouseMove(QMouseEvent *me)
{
    int pos = orientation() == Qt::Horizontal ? me->x() : me->y();
    if ( pos < 0 )
        return;

    if ( me->buttons() == Qt::NoButton )
    {
        state = FixedColumnTreeHeader::None;
        pressed = -1;
    }

    if ( ( state == FixedColumnTreeHeader::MoveSection ) &&
         ( qAbs(pos - firstPos) >= QApplication::startDragDistance() || ( movSecIndicator && !movSecIndicator->isHidden() ) ) )
    {
        QTreeView * pt = qobject_cast<QTreeView *>(parent());
        if ( ! pt )
            return;

        QHeaderView * ph = pt->header();

        int visual = ph->visualIndexAt(pos);
        int logical = ph->logicalIndex(visual);
        if ( visual == -1 || logical == -1 )
            return;

        int posThreshold = ph->sectionPosition(logical) - offset() + ph->sectionSize(logical) / 2;
        int moving = ph->visualIndex(section);
        if ( visual < moving )
            target = pos < posThreshold ? ph->logicalIndex(visual) : ph->logicalIndex(visual + 1);
        else if ( visual > moving )
            target = pos > posThreshold ? ph->logicalIndex(visual) : ph->logicalIndex(visual + 1);
        else
            target = section;
        updateIndicator(section, pos);
    }
    else if ( state == FixedColumnTreeHeader::ResizeSection )
    {
        lastPos = pos;
    }
}

void FixedColumnTreeHeader::mouseRelease(QMouseEvent *me)
{
    if ( state == FixedColumnTreeHeader::MoveSection )
    {
        int pos = orientation() == Qt::Horizontal ? me->x() : me->y();
        section = target = -1;
        updateIndicator(section, pos);
    }

    pressed = -1;

    state = FixedColumnTreeHeader::None;
}

ViewPortTreeView::ViewPortTreeView(QWidget *parent) :
    QTreeView(parent),
    active_(false)
{}

void ViewPortTreeView::forceEvent(QEvent *ev)
{
    viewportEvent(ev);
    update();
    viewport()->update();
}

void ViewPortTreeView::setActive(bool act)
{
    active_ = act;
    viewport()->update();
}

void ViewPortTreeView::drawRow(QPainter *painter, const QStyleOptionViewItem &options, const QModelIndex &index) const
{
    QStyleOptionViewItem opt = options;

    if ( active_ )
        opt.state |= QStyle::State_Active;

    QTreeView::drawRow(painter, opt, index);
}

FixedColumnTreeView::FixedColumnTreeView(QWidget * parent) :
    HoverTreeView(parent),
    fixedTreeView_(Q_NULLPTR),
    fixedColumn_(0),
    contextMenuActive_(false),
    headerContextMenuActive_(false),
    scrollDragActive_(false),
    lastHScroll_(-1),
    lastVScroll_(-1),
    hiddenSections_(0)
{
    fixedTreeView_ = new ViewPortTreeView(this);
    fixedTreeView_->setItemsExpandable(false);
    fixedTreeView_->setRootIsDecorated(false);
    fixedTreeView_->setUniformRowHeights(true);
    fixedTreeView_->setProperty("fixedColumn", qVariantFromValue(true));
    fixedTreeView_->setAttribute(Qt::WA_TransparentForMouseEvents);

    fixedTreeHeader_ = new FixedColumnTreeHeader(Qt::Horizontal, this);
    fixedTreeHeader_->setProperty("fixedColumn", qVariantFromValue(true));
    fixedTreeHeader_->setAttribute(Qt::WA_TransparentForMouseEvents);

    fixedTreeView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(fixedTreeView_, &HoverTreeView::customContextMenuRequested, this, &FixedColumnTreeView::contextMenuRequested);

    connect(fixedTreeView_->verticalScrollBar(), &QAbstractSlider::valueChanged,
        verticalScrollBar(), &QAbstractSlider::setValue);
    connect(verticalScrollBar(), &QAbstractSlider::valueChanged,
        fixedTreeView_->verticalScrollBar(), &QAbstractSlider::setValue);

    fixedTreeView_->header()->setSectionResizeMode(QHeaderView::Fixed);

    viewport()->stackUnder(fixedTreeView_);

    updateFixedTreeView();
}

void FixedColumnTreeView::setColumnVisibility()
{
    for ( int col = 0; col < model()->columnCount(); col++ )
    {
        fixedTreeHeader_->setSectionHidden(col, header()->isSectionHidden(col));
        fixedTreeHeader_->resizeSection(col, header()->sectionSize(col));
        fixedTreeView_->header()->setSectionHidden(col, header()->isSectionHidden(col));
        fixedTreeView_->header()->resizeSection(col, header()->sectionSize(col));
    }
}

void FixedColumnTreeView::updateFixedTreeView()
{
    if ( ! model() )
        return;

    if ( fixedColumn_ < 0 )
    {
        fixedTreeView_->hide();
        fixedTreeHeader_->hide();
        return;
    }

    fixedTreeView_->show();
    fixedTreeHeader_->show();

    fixedTreeHeader_->setStretchLastSection(header()->stretchLastSection());
    fixedTreeHeader_->setDefaultAlignment(header()->defaultAlignment());

    fixedTreeView_->setFont(font());
    fixedTreeHeader_->setFont(header()->font());

    fixedTreeView_->setSortingEnabled(isSortingEnabled());
    fixedTreeView_->setUniformRowHeights(uniformRowHeights());
    int oneEm = fontMetrics().height();
    fixedTreeView_->setMinimumSize(oneEm, oneEm);

    fixedTreeView_->setFocusPolicy(Qt::NoFocus);
    fixedTreeView_->setHeaderHidden(false);

    setColumnVisibility();

    fixedTreeView_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    fixedTreeView_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    setHorizontalScrollMode(ScrollPerPixel);
    setVerticalScrollMode(ScrollPerPixel);
    fixedTreeView_->setVerticalScrollMode(ScrollPerPixel);

    updateFixedGeometry();
}

void FixedColumnTreeView::updateFixedGeometry()
{
    if ( fixedColumn_ >= 0 && fixedTreeView_ )
    {
        int distWidth = style()->pixelMetric(QStyle::PM_HeaderMargin) / 2;
        QSize hSize = header()->size();
        fixedTreeHeader_->setGeometry ( frameWidth(), frameWidth(), columnWidths() + 1, hSize.height() );
        fixedTreeHeader_->raise();
        fixedTreeView_->setGeometry( frameWidth() - 1, frameWidth() - 1,
                                     columnWidths() + 1, viewport()->height() + header()->height() + 2 );
    }
    viewport()->update();
}

void FixedColumnTreeView::setModel(QAbstractItemModel *model_)
{
    if ( model() )
    {
        disconnect(model(), &QAbstractItemModel::modelReset, this, &FixedColumnTreeView::updateFixedTreeView);
        disconnect(model(), &QAbstractItemModel::dataChanged, this, &FixedColumnTreeView::updateFixedTreeView);
        disconnect(model(), &QAbstractItemModel::headerDataChanged, this, &FixedColumnTreeView::updateFixedTreeView);
        disconnect(model(), &QAbstractItemModel::layoutChanged, this, &FixedColumnTreeView::updateFixedTreeView);
    }

    HoverTreeView::setModel(model_);
    if ( model() )
    {
        fixedTreeView_->setModel(model());
        fixedTreeHeader_->setModel(model());

        connect(model(), &QAbstractItemModel::modelReset, this, &FixedColumnTreeView::updateFixedTreeView);
        connect(model(), &QAbstractItemModel::dataChanged, this, &FixedColumnTreeView::updateFixedTreeView);
        connect(model(), &QAbstractItemModel::headerDataChanged, this, &FixedColumnTreeView::updateFixedTreeView);
        connect(model(), &QAbstractItemModel::layoutChanged, this, &FixedColumnTreeView::updateFixedTreeView);

        updateFixedTreeView();
    }
}

void FixedColumnTreeView::setHeader(QHeaderView *header_)
{
    if ( header() )
    {
        disconnect(header(), &QHeaderView::geometriesChanged, this, &FixedColumnTreeView::updateFixedTreeView);
        disconnect(header(), &QHeaderView::sectionResized, this, &FixedColumnTreeView::updateSectionWidth);
        disconnect(header(), &QHeaderView::sectionMoved, this, &FixedColumnTreeView::updateSectionVisualIndex);
        if ( fixedTreeHeader_ )
        {
            disconnect(header(), &QHeaderView::sectionResized, fixedTreeHeader_, &FixedColumnTreeHeader::sectionsResized);
            disconnect(header(), &QHeaderView::sectionMoved, fixedTreeHeader_, &FixedColumnTreeHeader::sectionsMoved);
            disconnect(header(), &QHeaderView::sortIndicatorChanged, fixedTreeHeader_, &FixedColumnTreeHeader::indicatorChanged);
            disconnect(header(), &QHeaderView::geometriesChanged, fixedTreeHeader_, &FixedColumnTreeHeader::geometriesHaveChanged);
        }
    }

    HoverTreeView::setHeader(header_);
    if ( header_ )
    {
        hiddenSections_ = header()->hiddenSectionCount();

        connect(header(), &QHeaderView::geometriesChanged, this, &FixedColumnTreeView::updateFixedTreeView);
        connect(header(), &QHeaderView::sectionResized, this, &FixedColumnTreeView::updateSectionWidth);
        connect(header(), &QHeaderView::sectionMoved, this, &FixedColumnTreeView::updateSectionVisualIndex);

        if ( fixedTreeHeader_ )
        {
            header()->viewport()->installEventFilter(this);

            fixedTreeHeader_->setSectionsMovable(header()->sectionsMovable());
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
            fixedTreeHeader_->setFirstSectionMovable(header()->isFirstSectionMovable());
#endif

            connect(header(), &QHeaderView::sectionResized, fixedTreeHeader_, &FixedColumnTreeHeader::sectionsResized);
            connect(header(), &QHeaderView::sectionMoved, fixedTreeHeader_, &FixedColumnTreeHeader::sectionsMoved);
            connect(header(), &QHeaderView::sortIndicatorChanged, fixedTreeHeader_, &FixedColumnTreeHeader::indicatorChanged);
            connect(header(), &QHeaderView::geometriesChanged, fixedTreeHeader_, &FixedColumnTreeHeader::geometriesHaveChanged);
        }

        updateFixedTreeView();
    }
}

void FixedColumnTreeView::setFont(const QFont &font)
{
    HoverTreeView::setFont(font);
    if ( fixedTreeView_ )
        fixedTreeView_->setFont(font);
    updateFixedTreeView();
}

void FixedColumnTreeView::setItemDelegateForColumn(int column, QAbstractItemDelegate * delegate)
{
    HoverTreeView::setItemDelegateForColumn(column, delegate);
    if ( fixedTreeView_ )
        fixedTreeView_->setItemDelegateForColumn(column, delegate);
    updateFixedTreeView();
}

void FixedColumnTreeView::setFixedColumn(int column)
{
    if ( column > -1 )
    {
        int maxSize = viewport()->width();
        int totalSize = 0;
        int col = -1;

        while ( totalSize < maxSize && ++col <= column && header()->visualIndex(col) >= 0 )
            totalSize += header()->sectionSize(header()->logicalIndex(col));

        if ( totalSize > maxSize )
            return;
    }

    fixedColumn_ = header()->visualIndex(column);
    updateFixedTreeView();
}

bool FixedColumnTreeView::isColumnFixed() const
{
    return fixedColumn_ > -1 ? true : false;
}

void FixedColumnTreeView::setStyleSheet(const QString & styleSheet)
{
    if ( fixedTreeView_ )
    {
        fixedTreeView_->setStyleSheet(styleSheet);
        fixedTreeHeader_->setStyleSheet(styleSheet);
    }

    HoverTreeView::setStyleSheet(styleSheet);
    viewport()->update();
}

void FixedColumnTreeView::setTextElideMode(Qt::TextElideMode mode)
{
    if ( fixedTreeView_ )
    {
        fixedTreeView_->setTextElideMode(mode);
        fixedTreeHeader_->setTextElideMode(mode);
    }

    HoverTreeView::setTextElideMode(mode);
    viewport()->update();
}

void FixedColumnTreeView::setColumnWidth(int column, int width)
{
    HoverTreeView::setColumnWidth(column, width);

    if ( width != columnWidth(column) )
    {
        updateSectionWidth(column, columnWidth(column), width);
        updateFixedGeometry();
    }
}

void FixedColumnTreeView::setVerticalScrollBar(QScrollBar *scrollbar)
{
    if ( fixedTreeView_ )
    {
        if ( verticalScrollBar() )
        {
            disconnect(fixedTreeView_->verticalScrollBar(), &QAbstractSlider::valueChanged,
                verticalScrollBar(), &QAbstractSlider::setValue);
            disconnect(verticalScrollBar(), &QAbstractSlider::valueChanged,
                fixedTreeView_->verticalScrollBar(), &QAbstractSlider::setValue);
        }

        fixedTreeView_->setVerticalScrollBar(scrollbar);

        connect(fixedTreeView_->verticalScrollBar(), &QAbstractSlider::valueChanged,
            verticalScrollBar(), &QAbstractSlider::setValue);
        connect(verticalScrollBar(), &QAbstractSlider::valueChanged,
            fixedTreeView_->verticalScrollBar(), &QAbstractSlider::setValue);

        updateFixedGeometry();
    }
    scrollbar->installEventFilter(this);

    HoverTreeView::setVerticalScrollBar(scrollbar);
}

void FixedColumnTreeView::updateSectionWidth(int logicalIndex, int oldSize, int newSize)
{
    if (isFixedColumn(logicalIndex) && oldSize != newSize)
    {
        if ( fixedTreeView_ )
            fixedTreeView_->setColumnWidth(logicalIndex, newSize);
        updateFixedGeometry();
    }
}

void FixedColumnTreeView::updateSectionVisualIndex(int /*logicalIndex*/, int oldVisualIndex, int newVisualIndex)
{
    if ( fixedTreeView_ )
    {
        QHeaderView * fixedHeader = fixedTreeView_->header();
        for ( int sec = 0; sec < header()->count(); sec++ )
            fixedHeader->setSectionHidden(sec, header()->isSectionHidden(sec));

        fixedHeader->moveSection(oldVisualIndex, newVisualIndex);
    }
    updateFixedTreeView();
}

QMenu * FixedColumnTreeView::contextMenu(QModelIndex /*at*/)
{
    return Q_NULLPTR;
}

void FixedColumnTreeView::contextMenuEvent(QContextMenuEvent *event)
{
    contextMenuRequested(event->pos());
}

void FixedColumnTreeView::contextMenuRequested(const QPoint & pos)
{
    QModelIndex idx = indexAt(pos);

    QMenu * menu = contextMenu(idx);
    if ( menu )
    {
        contextMenuActive_ = true;
        menu->exec(mapToGlobal(pos));
    }

    contextMenuActive_ = false;
    contextMenuClosed();
}

void FixedColumnTreeView::contextMenuClosed()
{
    contextMenuActive_ = false;
}

QModelIndex FixedColumnTreeView::indexAt(const QPoint &pos) const
{
    QModelIndex idx = HoverTreeView::indexAt(pos);
    if ( const_cast<FixedColumnTreeView *>(this)->isPositionOverFixedColumn(pos) )
        idx = fixedTreeView_->indexAt(pos);

    return idx;
}

void FixedColumnTreeView::columnResized(int logicalIndex, int oldSize , int newSize)
{
    if (isFixedColumn(logicalIndex))
    {
        if ( fixedTreeView_ )
            fixedTreeView_->setColumnWidth(logicalIndex, newSize);
        updateFixedGeometry();
    }
    HoverTreeView::columnResized(logicalIndex, oldSize, newSize);
}

void FixedColumnTreeView::resizeEvent(QResizeEvent * event)
{
    HoverTreeView::resizeEvent(event);
    updateFixedGeometry();
}

int FixedColumnTreeView::columnWidths(QTreeView * element)
{
    int size = 0;
    QTreeView *workOn = element;
    if ( ! workOn )
        workOn = this;

    if ( fixedColumn_ >= 0 && workOn )
    {
        for ( int visualIndex = 0; visualIndex <= fixedColumn_; visualIndex++ )
        {
            int logicalIndex = header()->logicalIndex(visualIndex);
            size += workOn->columnWidth(logicalIndex);
        }
    }

    return size;
}

bool FixedColumnTreeView::isFixedColumn(int col)
{
    if ( model() && fixedColumn_ != -1 && fixedColumn_ >= header()->visualIndex(col) )
        return true;

    return false;
}

QModelIndex FixedColumnTreeView::moveCursor(CursorAction cursorAction,
                                          Qt::KeyboardModifiers modifiers)
{
      QModelIndex current = HoverTreeView::moveCursor(cursorAction, modifiers);

      if (fixedColumn_ >= 0 && cursorAction == MoveLeft && current.column() > fixedColumn_ && visualRect(current).topLeft().x() < columnWidths(fixedTreeView_) )
      {
            const int newValue = horizontalScrollBar()->value() + visualRect(current).topLeft().x() - columnWidths(fixedTreeView_);
            horizontalScrollBar()->setValue(newValue);
      }
      return current;
}

void FixedColumnTreeView::scrollTo (const QModelIndex & index, ScrollHint hint)
{
    if ( fixedColumn_ >= 0 && index.column() > fixedColumn_ )
        HoverTreeView::scrollTo(index, hint);
}

bool FixedColumnTreeView::isContextMenuActive() const
{
    return contextMenuActive_;
}

bool FixedColumnTreeView::isPositionOutsideViewport(QPoint pos)
{
    if ( ! scrollDragActive_ )
    {
        if ( pos.x() < 0 || pos.y() < 0 )
            return true;

        if ( pos.y() > ( viewport()->size().height() - 1 ) ||
             pos.x() > ( viewport()->width() - 1 ) )
            return true;

         if ( verticalScrollBar()->underMouse() || horizontalScrollBar()->underMouse() )
             return true;
    }

    return false;
}

bool FixedColumnTreeView::isPositionOverFixedColumn(QPoint pos)
{
    if ( pos.x() < 0 || pos.y() < 0 )
        return false;

    if ( pos.x() > columnWidths(fixedTreeView_) )
        return false;

    return true;
}

QPoint FixedColumnTreeView::setToViewpointEdge(QPoint pos)
{
    int x = pos.x();
    int y = pos.y();

    if ( x < 0 )
        x = 0;
    else if ( x > (viewport()->width() - 1) )
        x = (viewport()->width() - 1);
    if ( y < 0 )
        y = 0;
    else if ( y > (viewport()->size().height() - 1) )
        y = (viewport()->size().height() - 1);

    return QPoint(x, y);
}

bool FixedColumnTreeView::hoverEvent(QHoverEvent * he)
{
    bool hMove = false;
    bool vMove = false;
    if ( horizontalScrollBar()->value() != lastHScroll_ )
        hMove = true;
    if ( verticalScrollBar()->value() != lastVScroll_ )
        vMove = true;

    lastHScroll_ = horizontalScrollBar()->value();
    lastVScroll_ = verticalScrollBar()->value();

    if ( scrollDragActive_ && ! hMove && ! vMove )
        return false;

    if ( isPositionOutsideViewport(he->pos()) )
    {
        QHoverEvent * ev = new QHoverEvent(QEvent::HoverLeave, he->pos(), he->oldPos());
        if ( fixedTreeView_ )
            fixedTreeView_->forceEvent(ev);

        return true;
    }

    QPoint pos = he->pos();
    QPoint oldPos = he->oldPos();

    if ( fixedColumn_ > -1 && fixedTreeView_ && pos == setToViewpointEdge(pos) )
    {
        QModelIndex idx = indexAt(pos);
        idx = idx.sibling(idx.row(), fixedColumn_);
        pos = QPoint(visualRect(idx).center().x(), pos.y());
        idx = indexAt(oldPos);
        idx = idx.sibling(idx.row(), fixedColumn_);
        oldPos = QPoint(visualRect(idx).center().x(), oldPos.y());

        pos = setToViewpointEdge(pos);
        oldPos = setToViewpointEdge(oldPos);

        if ( indexAt(pos).isValid() )
        {
            QHoverEvent * ev = new QHoverEvent(he->type(), pos, oldPos);
            if ( fixedTreeView_ )
                fixedTreeView_->forceEvent(ev);

            viewport()->update();

            return true;
        }
    }

    return false;
}

void FixedColumnTreeView::setHoverIndex(const QPersistentModelIndex &idx)
{
    HoverTreeView::setHoverIndex(idx);
    if ( ! idx.isValid() )
    {
        QHoverEvent ev(QEvent::HoverLeave, QPoint(-1, -1), QPoint(-1, -1) );
        lastHover_ = QPoint(-1, -1);
        hoverEvent(&ev);
    } else {
        QModelIndex chi = currentHoveredIndex();
        QPoint centerPos = visualRect(chi).center();
        if ( ! isPositionOverFixedColumn(centerPos) )
        {
            chi = chi.sibling(chi.row(), header()->logicalIndex(0));
            centerPos = fixedTreeView_->visualRect(chi).center();
        }

        QHoverEvent ev(QEvent::HoverMove, centerPos, centerPos );
        if ( lastHover_ == centerPos )
            return;

        lastHover_ = centerPos;
        hoverEvent(&ev);
    }
}

bool FixedColumnTreeView::viewportEvent(QEvent *event)
{
    bool result = HoverTreeView::viewportEvent(event);

    switch(event->type())
    {
    case QEvent::HoverLeave: {
        lastHover_ = QPoint(-1, -1);
        break; }
    case QEvent::HoverEnter: {
        setHoverIndex(currentHoveredIndex());
        break; }
    case QEvent::Wheel: {
        QWheelEvent * we = static_cast<QWheelEvent*>(event);
#if (QT_VERSION < QT_VERSION_CHECK(5, 12, 0))
        if ( we->phase() == Qt::ScrollUpdate )
#else
        /* Scroll Momentum is updated as long as the scrolling is "rolling out" */
        if ( we->phase() == Qt::ScrollUpdate || we->phase() == Qt::ScrollMomentum )
#endif
            scrollDragActive_ = true;
        else
            scrollDragActive_ = false;
        break; }
    default:
        break;
    }

    return result;
}

void FixedColumnTreeView::focusInEvent(QFocusEvent * event)
{
    setFixedTreeActive(true);
    HoverTreeView::focusInEvent(event);
}

void FixedColumnTreeView::focusOutEvent(QFocusEvent * event)
{
    if ( ! isContextMenuActive() && ! headerContextMenuActive_ )
        setFixedTreeActive(false);
    HoverTreeView::focusOutEvent(event);
}

void FixedColumnTreeView::selectionChanged(const QItemSelection &/*selected*/, const QItemSelection &/*deselected*/)
{
    QModelIndexList list = selectedIndexes();
    QList<int> rows;
    foreach ( QModelIndex idx, list )
    {
        if ( ! rows.contains(idx.row()) )
            rows << idx.row();
    }

    if ( fixedTreeView_ && rows.count() > 0 )
    {
        if ( rows.count() == 0 )
            fixedTreeView_->selectionModel()->clearSelection();
        else
        {
            fixedTreeView_->clearSelection();
            foreach ( int row, rows )
                fixedTreeView_->selectionModel()->select(fixedTreeView_->model()->index(row, header()->logicalIndex(0)), QItemSelectionModel::Select | QItemSelectionModel::Rows);

        }
    }
    viewport()->update();
}

void FixedColumnTreeView::setFixedTreeActive(bool active)
{
    if ( fixedTreeView_ )
        fixedTreeView_->setActive(active);
    viewport()->update();
}

bool FixedColumnTreeView::eventFilter(QObject *watched, QEvent *event)
{
    if ( qobject_cast<QScrollBar *>(watched) )
    {
        switch (event->type())
        {
        case QEvent::MouseButtonPress:
            scrollDragActive_ = true;
            break;
        case QEvent::MouseButtonRelease:
            scrollDragActive_ = false;
            break;
        default:
            break;
        }

    }
    else if ( qobject_cast<QWidget*>(watched) && watched->objectName().endsWith("_viewport") )
    {
        /* Catch only events for the main header view */
        if ( qobject_cast<QHeaderView*>(watched->parent()) )
        {
            switch (event->type()) {
            case QEvent::ContextMenu: {
                headerContextMenuActive_ = true;
                break; }
            case QEvent::MouseButtonPress: {
                QMouseEvent * me = static_cast<QMouseEvent *>(event);
                fixedTreeHeader_->mousePress(me);
                break; }
            case QEvent::MouseButtonRelease: {
                QMouseEvent * me = static_cast<QMouseEvent *>(event);
                fixedTreeHeader_->mouseRelease(me);
                break; }
            case QEvent::MouseMove: {
                QMouseEvent * me = static_cast<QMouseEvent *>(event);
                fixedTreeHeader_->mouseMove(me);
                int position =  qobject_cast<QHeaderView*>(watched->parent())->visualIndexAt(me->pos().x());
                fixedTreeHeader_->setActiveSection(position);
                break; }
            case QEvent::Leave:
                fixedTreeHeader_->setActiveSection(-1);
                break;
            case QEvent::Paint: {
                /* There is no event in a headerview if sections are being hidden
                 * or unhidden. This imitates the check updates the treeview */
                if ( hiddenSections_ != header()->hiddenSectionCount() )
                {
                    hiddenSections_ = header()->hiddenSectionCount();
                    updateFixedTreeView();
                }
                break; }
            default:
                headerContextMenuActive_ = false;
                break;
            }
        }
    }

    return false;
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
