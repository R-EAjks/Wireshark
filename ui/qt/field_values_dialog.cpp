/* field_values_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: 0BSD
 */

#include "field_values_dialog.h"
#include "ui_field_values_dialog.h"
#include "ui/qt/utils/color_utils.h"

#include "main_window.h"
#include "wireshark_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include "epan/value_string.h"
#include "epan/ftypes/ftypes.h"

#include <QClipboard>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <QDebug>

FieldValuesDialog::FieldValuesDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::FieldValuesDialog),
    finfo_(cf.capFile()->finfo_selected)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 2 / 3, parent.height() * 3 / 4);

    QString field_name = QString("%1 (%2)").arg(finfo_->hfinfo->name, finfo_->hfinfo->abbrev);
    setWindowSubtitle (field_name);

    context_menu_.addActions(QList<QAction *>() << ui->actionMark_Unmark_Cell);
    context_menu_.addActions(QList<QAction *>() << ui->actionMark_Unmark_Row);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Cell);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Rows);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_All);
    context_menu_.addActions(QList<QAction *>() << ui->actionSave_as_image);

    connect(ui->fieldValueTable, SIGNAL(customContextMenuRequested(const QPoint &)),
            this, SLOT(tableContextMenu(const QPoint &)));
    connect(ui->filterLineEdit, SIGNAL(textChanged(const QString &)),
            this, SLOT(filterLineEditChanged(const QString &)));
    ui->fieldValueTable->sortByColumn(0, Qt::AscendingOrder);

    int column_value_first = 0;
    int column_value_last = 1;
    int column_description = 2;

    header_field_info *hfinfo = finfo_->hfinfo;
    const void *vf;
    const void *next_vf;
    const char *cdescription;
    uint64_t value = 0;
    uint64_t value_end = 0;
    uint64_t field_value = 0;
    bool is_first = true;
    if (hfinfo->type ==  FT_PROTOCOL || finfo_->length == 0) {
        vf = NULL;
    } else {
        vf = hfinfo->strings;
    }
    while (vf) {
        /* NOTE: "string_string" and "bytes_string" types are not interfaces
         * for wireshark fields yet (for example: range_string - it is) */
        if  (hfinfo->type ==  FT_BOOLEAN) {
            const true_false_string *tfs = static_cast<const true_false_string *>(vf);
            if (is_first == true) {
                is_first = false;
                next_vf = vf;
                cdescription = tfs->true_string;
                value = 1;
                value_end = value;
                field_value = fvalue_get_uinteger64(const_cast<fvalue_t*>(&finfo_->value));
            } else {
                next_vf = NULL;
                cdescription = tfs->false_string;
                value = 0;
                value_end = value;
                field_value = fvalue_get_uinteger64(const_cast<fvalue_t*>(&finfo_->value));
            }
        } else if (hfinfo->display & BASE_RANGE_STRING) {
            const range_string *rs = static_cast<const range_string *>(vf);
            next_vf = rs +1;
            cdescription = rs->strptr;
            value = rs->value_min;
            value_end = rs->value_max;
            field_value = fvalue_get_uinteger(const_cast<fvalue_t*>(&finfo_->value));
        } else if (hfinfo->display & BASE_EXT_STRING) {
            if (hfinfo->display & BASE_VAL64_STRING) {
                const val64_string *vs;
                if (is_first == true) {
                    is_first = false;
                    const _val64_string_ext *vse = static_cast<const _val64_string_ext *>(vf);
                    vs = const_cast<const val64_string *>(vse->_vs_p);
                } else {
                    vs = static_cast<const val64_string *>(vf);
                }

                next_vf = vs + 1;

                cdescription = vs->strptr;
                value = vs->value;
                value_end = value;
                field_value = fvalue_get_uinteger(const_cast<fvalue_t*>(&finfo_->value));
            } else {
                const value_string *vs;
                if (is_first == true) {
                    is_first = false;
                    const value_string_ext *vse = static_cast<const value_string_ext *>(vf);
                    vs = const_cast<const value_string *>(vse->_vs_p);
                } else {
                    vs = static_cast<const value_string *>(vf);
                }

                next_vf = vs + 1;

                cdescription = vs->strptr;
                value = vs->value;
                value_end = value;
                field_value = fvalue_get_uinteger(const_cast<fvalue_t*>(&finfo_->value));
            }
        } else if (hfinfo->display & BASE_VAL64_STRING) {
            const val64_string *vs = static_cast<const val64_string *>(vf);
            next_vf = vs +1;
            cdescription = vs->strptr;
            value = vs->value;
            value_end = value;
            field_value = fvalue_get_uinteger(const_cast<fvalue_t*>(&finfo_->value));
         } else if (hfinfo->display & BASE_UNIT_STRING) {
            vf = NULL;
        } else {
            const value_string *vs = static_cast<const value_string *>(vf);
            next_vf = vs +1;
            cdescription = vs->strptr;
            value = vs->value;
            value_end = value;
            field_value = fvalue_get_uinteger(const_cast<fvalue_t*>(&finfo_->value));
        }

        if (cdescription == NULL) {
            vf = NULL;
            break;
        }
        if (vf == NULL) {
            qWarning() << "Displaying field value is not supported yet for field type" << hfinfo->type << "and display type " << hfinfo->display;
            break;
        }

        int column_value_first = 0;
        int column_value_last;
        int column_description;

        if (hfinfo->display & BASE_RANGE_STRING) {
            column_value_last = 1;
            column_description = 2;
        } else {
            column_description = 1;
        }


        QString string_value = QString();
        string_value.setNum(value, 16);
        if (string_value.length() % 2)
            string_value = "0" + string_value;
        string_value = "0x" + string_value;

        QString string_end_value = QString();
        string_end_value.setNum(value_end, 16);
        if (string_end_value.length() % 2)
            string_end_value = "0" + string_end_value;
        string_end_value = "0x" + string_end_value;

        QString description = QString::fromUtf8(cdescription);
        QColor hover_color = ColorUtils::alphaBlend(palette().window(), palette().highlight(), 0.5);
        ui->fieldValueTable->setStyleSheet(QString("QTreeView::item:hover{background-color:%1; color:palette(text);}").arg(hover_color.name(QColor::HexArgb)));
        FvTreeWidgetItem *item = new FvTreeWidgetItem(ui->fieldValueTable);
        QFont font = wsApp->monospaceFont();
        item->setFont(column_value_first, font);
        item->setText(column_value_first, string_value);
        item->setTextAlignment(column_value_first, Qt::AlignRight);
        if (hfinfo->display & BASE_RANGE_STRING) {
            item->setFont(column_value_last, font);
            item->setText(column_value_last, string_end_value);
            item->setTextAlignment(column_value_last, Qt::AlignRight);
        }
        item->setText(column_description, description);
        item->setTextAlignment(column_description, Qt::AlignLeft);
        if (field_value >= value && field_value <= value_end) {
            item->setData(0, Qt::UserRole, true);
            item->setBackground(column_value_first, QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid)));
            item->setBackground(column_value_last, QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid)));
            item->setBackground(column_description, QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid)));
        }

        vf = next_vf;
    }

    int field_length = finfo_->length;
    uint64_t bitmask = hfinfo->bitmask;
    int ones;

    if (bitmask == 0) {
        ones = field_length * 8;
        bool status = false;
        bitmask = QString().rightJustified(ones, '1').toUInt(&status, 2);
    } else {
        QString bitmask_str = QString();
        uint64_t i_bitmask = 0;
        for (int i = 0; i < field_length; i += 1) {
            i_bitmask <<= 8;
            i_bitmask |= 0xFF;
        }
        bitmask = bitmask & i_bitmask;
        bitmask_str.setNum(bitmask, 2);
        ones = bitmask_str.count(QChar('1'));
    }

    if ((hfinfo->display & BASE_RANGE_STRING) || (
            ui->fieldValueTable->topLevelItemCount() == 0 && field_length > 0)) {
        QTreeWidgetItem *header = new QTreeWidgetItem();
        header->setText(0, tr("Value First"));
        header->setText(1, tr("Value Last"));
        header->setText(2, tr("Description"));
        ui->fieldValueTable->setHeaderItem(header);
    }
    if (finfo_->flags & FI_GENERATED) {
        make_description_only(tr("Wireshark Generated Field - not part of protocol"));
    } else if (hfinfo->type ==  FT_STRING) {
        make_description_only(tr("string without null terminator"));
    } else if (hfinfo->type ==  FT_STRINGZ) {
        make_description_only(tr("null terminated string"));
    } else if (hfinfo->type ==  FT_UINT_STRING) {
        make_description_only(tr("string with count being the first part of the value"));
    } else if (hfinfo->type ==  FT_STRINGZPAD) {
        make_description_only(tr("null-padded string"));
    } else if (hfinfo->type ==  FT_STRINGZTRUNC) {
        make_description_only(tr("null-truncated string"));
    } else if (hfinfo->type ==  FT_IEEE_11073_SFLOAT) {
        make_description_only(tr("IEEE 11073 SFLOAT"));
    } else if (hfinfo->type ==  FT_IEEE_11073_FLOAT) {
        make_description_only(tr("IEEE 11073 FLOAT"));
    } else if (hfinfo->type == FT_FLOAT ) {
        make_description_only(tr("float"));
    } else if (hfinfo->type ==  FT_DOUBLE) {
        make_description_only(tr("double"));
    } else if (hfinfo->type ==  FT_PROTOCOL || hfinfo->type ==  FT_BYTES) {
        make_description_only(tr("data"));
    } else if ((hfinfo->display & BASE_RANGE_STRING) == 0 &&
            ui->fieldValueTable->topLevelItemCount() == 0 &&
            field_length > 0 &&
            ones <= 64) {
        FvTreeWidgetItem *item = new FvTreeWidgetItem(ui->fieldValueTable);

        QString first;
        QString last = QString();
        QString description = tr("data");

        if (IS_FT_INT(hfinfo->type)) {
            int64_t first_value;
            int64_t last_value;

            int64_t bits = 0;
            if (hfinfo->type ==  FT_INT8) {
                bits = 8;
            } else if (hfinfo->type == FT_INT16) {
                bits = 16;
            } else if (hfinfo->type == FT_INT24) {
                bits = 24;
            } else if (hfinfo->type == FT_INT32) {
                bits = 32;
            } else if (hfinfo->type == FT_INT40) {
                bits = 40;
            } else if (hfinfo->type == FT_INT48) {
                bits = 48;
            } else if (hfinfo->type == FT_INT56) {
                bits = 56;
            } else if (hfinfo->type == FT_INT64) {
                bits = 64;
            }

            first_value = -(1 << (bits - 1));
            last_value = (1 << (bits - 1)) - 1;

            first = QString().setNum(first_value);
            last = QString().setNum(last_value);
            description = QString("type is int%1").arg(bits);
        } else {
            first = QString("0x00");
            if (IS_FT_UINT(hfinfo->type)) {
                uint64_t bits = 0;
                if (hfinfo->type ==  FT_UINT8) {
                    bits = 8;
                } else if (hfinfo->type == FT_UINT16) {
                    bits = 16;
                } else if (hfinfo->type == FT_UINT24) {
                    bits = 24;
                } else if (hfinfo->type == FT_UINT32) {
                    bits = 32;
                } else if (hfinfo->type == FT_UINT40) {
                    bits = 40;
                } else if (hfinfo->type == FT_UINT48) {
                    bits = 48;
                } else if (hfinfo->type == FT_UINT56) {
                    bits = 56;
                } else if (hfinfo->type == FT_UINT64) {
                    bits = 64;
                }
                description = QString("type is uint%1").arg(bits);
            }
        }

        uint64_t max = 1;
        uint64_t ones64 = ones;
        max <<= ones64;
        max -= 1;
        if (last.isEmpty()) {
            last = "0x" + QString().setNum(max, 16);
        }

        item->setText(column_value_first, first);
        item->setTextAlignment(column_value_first, Qt::AlignRight);
        item->setText(column_value_last, last);
        item->setTextAlignment(column_value_last, Qt::AlignRight);
        item->setText(column_description, QString(description));
        item->setTextAlignment(column_description, Qt::AlignLeft);

        item->setData(0, Qt::UserRole, true);
        item->setBackground(column_value_first, QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid)));
        item->setBackground(column_value_last, QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid)));
        item->setBackground(column_description, QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid)));
    } else if (ui->fieldValueTable->topLevelItemCount() > 0) {
        QTreeWidgetItem *header = new QTreeWidgetItem();
        header->setText(0, tr("Value"));
        header->setText(1, tr("Description"));
        ui->fieldValueTable->setHeaderItem(header);
    } else {
        make_description_only(tr("data"));
    }
    QString field_value_str = QString();
    if (vf == NULL) {
        field_value_str = fvalue_to_string_repr(NULL, &finfo_->value, FTREPR_DISPLAY, hfinfo->display);
        if (field_value_str.isEmpty()) {
            field_value_str = tr("N/A");
        }
    } else {
        field_value_str.setNum(field_value);
    }

    hint_label_ = tr("Frame %1, %2, %3 bit(s) in %4 byte(s), bitmask 0x%5. Value: %6. Items: %7", "")
                     .arg(cf.capFile()->current_frame->num)
                     .arg(field_name)
                     .arg(ones)
                     .arg(field_length)
                     .arg(bitmask, 1, 16)
                     .arg(field_value_str)
                     .arg(ui->fieldValueTable->topLevelItemCount());
    updateHintLabel();
}


FieldValuesDialog::~FieldValuesDialog()
{
    delete ui;
}


void FieldValuesDialog::make_description_only(const QString &text)
{
    QTreeWidgetItem *header = new QTreeWidgetItem();
    header->setText(0, tr("Description"));
    ui->fieldValueTable->setHeaderItem(header);

    FvTreeWidgetItem *item = new FvTreeWidgetItem(ui->fieldValueTable);
    item->setText(0, text);
}


void FieldValuesDialog::filterLineEditChanged(const QString &text)
{
    for (int i_item = 0; i_item < ui->fieldValueTable->topLevelItemCount(); ++i_item) {
        FvTreeWidgetItem *item = static_cast<FvTreeWidgetItem *>(ui->fieldValueTable->topLevelItem(i_item));
        bool show = false;
        for (int i_column = 0; i_column < item->columnCount(); i_column += 1) {
            QString value = item->text(i_column);
            show |= value.contains(text, Qt::CaseInsensitive);
        }
        item->setHidden(!show);
    }
}


void FieldValuesDialog::updateWidgets()
{
    WiresharkDialog::updateWidgets();
}


void FieldValuesDialog::updateHintLabel()
{
    QString hint = hint_label_;

    ui->hintLabel->setText(hint);
}


void FieldValuesDialog::on_buttonBox_rejected()
{
    WiresharkDialog::reject();
}


void FieldValuesDialog::keyPressEvent(QKeyEvent *event)
{
/* NOTE: Do nothing*, but in real it "takes focus" from button_box so allow user
 * to use Enter button to jump to frame from tree widget */
/* * - reimplement shortcuts from contex menu */

   if (event->modifiers() & Qt::ControlModifier && event->key()== Qt::Key_M)
        on_actionMark_Unmark_Row_triggered();
}


void FieldValuesDialog::on_actionMark_Unmark_Cell_triggered()
{
    QBrush fg;
    QBrush bg;
    QTreeWidgetItem *item = ui->fieldValueTable->currentItem();

    if (item->background(ui->fieldValueTable->currentColumn()) == QBrush(
        ColorUtils::fromColorT(&prefs.gui_marked_bg))) {
        if (item->data(0, Qt::UserRole).toBool()) {
            fg = QBrush();
            bg = QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid));
        } else {
            fg = QBrush();
            bg = QBrush();
        }
    } else {
        fg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_fg));
        bg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg));
    }

    item->setForeground(ui->fieldValueTable->currentColumn(), fg);
    item->setBackground(ui->fieldValueTable->currentColumn(), bg);
}


void FieldValuesDialog::on_actionMark_Unmark_Row_triggered()
{
    QBrush fg;
    QBrush bg;
    bool   is_marked = TRUE;
    QTreeWidgetItem *item = ui->fieldValueTable->currentItem();

    for (int i = 0; i < ui->fieldValueTable->columnCount(); i += 1) {
        if (item->background(i) != QBrush(
            ColorUtils::fromColorT(&prefs.gui_marked_bg)))
            is_marked = FALSE;
    }

    if (is_marked) {
        if (item->data(0, Qt::UserRole).toBool()) {
            fg = QBrush();
            bg = QBrush(ColorUtils::fromColorT(&prefs.gui_text_valid));
        } else {
            fg = QBrush();
            bg = QBrush();
        }
    } else {
        fg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_fg));
        bg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg));
    }

    for (int i = 0; i < ui->fieldValueTable->columnCount(); i += 1) {
        item->setForeground(i, fg);
        item->setBackground(i, bg);
    }
}


void FieldValuesDialog::on_actionCopy_Cell_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;

    copy = QString(ui->fieldValueTable->currentItem()->text(ui->fieldValueTable->currentColumn()));

    clipboard->setText(copy);
}


void FieldValuesDialog::on_actionCopy_Rows_triggered()
{
    QClipboard                         *clipboard = QApplication::clipboard();
    QString                             copy;
    QList<QTreeWidgetItem *>            items;
    QList<QTreeWidgetItem *>::iterator  i_item;

    items =  ui->fieldValueTable->selectedItems();

    for (i_item = items.begin(); i_item != items.end(); ++i_item) {
        for (int i_column = 0; i_column < (*i_item)->columnCount(); i_column += 1) {
            if (i_column > 0 && i_column < (*i_item)->columnCount())
                copy += "  ";
            copy += QString("%1").arg((*i_item)->text(i_column), cell_width);
        }
        copy += '\n';
    }
    clipboard->setText(copy);
}


void FieldValuesDialog::on_actionCopy_All_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;
    QTreeWidgetItem        *item;

    item = ui->fieldValueTable->headerItem();

    for (int i_column = 0; i_column < item->columnCount(); i_column += 1) {
        if (i_column > 0 && i_column < item->columnCount())
            copy += "  ";
        copy += QString("%1").arg(item->text(i_column), cell_width);
    }
    copy += '\n';

    for (int i_item = 0; i_item < ui->fieldValueTable->topLevelItemCount(); ++i_item) {
        item = ui->fieldValueTable->topLevelItem(i_item);

        for (int i_column = 0; i_column < item->columnCount(); i_column += 1) {
            if (i_column > 0 && i_column < item->columnCount())
                copy += "  ";
            copy += QString("%1").arg(item->text(i_column), cell_width);
        }
        copy += '\n';
    }

    clipboard->setText(copy);
}


void FieldValuesDialog::on_actionSave_as_image_triggered()
{
    QPixmap image;

    QString fileName = WiresharkFileDialog::getSaveFileName(this,
            tr("Save Table Image"),
            QString("field_values_%1_%2.png").arg(finfo_->hfinfo->name).arg(finfo_->hfinfo->abbrev),
            tr("PNG Image (*.png)"));
    if (fileName.isEmpty()) return;

    image = ui->fieldValueTable->grab();
    image.save(fileName, "PNG");
}


void FieldValuesDialog::tableContextMenu(const QPoint &pos)
{
    context_menu_.exec(ui->fieldValueTable->viewport()->mapToGlobal(pos));
}



FvTreeWidgetItem::FvTreeWidgetItem(QTreeWidget* parent) :
    QTreeWidgetItem(parent)
{
    treeWidget = parent;
}


bool FvTreeWidgetItem::operator<(const QTreeWidgetItem &other) const
{
    int column = treeWidget->sortColumn();

    QString a = text(column);
    QString b = other.text(column);

    if (column == 0) {
        a = a.mid(2);
        b = b.mid(2);
        if (a.length() < b.length()) {
            a = a.rightJustified(b.length(), '0');
        } else if (a.length() > b.length()) {
            b = b.rightJustified(a.length(), '0');
        }
    }

    return a < b;
}
