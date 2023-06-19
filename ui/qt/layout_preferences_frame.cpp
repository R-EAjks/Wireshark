/* layout_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "layout_preferences_frame.h"
#include <ui_layout_preferences_frame.h>

#include <QAbstractButton>
#include <QToolButton>
#include <QRadioButton>

#include <QDebug>
#include <epan/prefs-int.h>
#include <ui/qt/models/pref_models.h>

LayoutPreferencesFrame::LayoutPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::LayoutPreferencesFrame)
{
    ui->setupUi(this);

    pref_layout_type_ = prefFromPrefPtr(&prefs.gui_layout_type);
    pref_layout_content_1_ = prefFromPrefPtr(&prefs.gui_layout_content_1);
    pref_layout_content_2_ = prefFromPrefPtr(&prefs.gui_layout_content_2);
    pref_layout_content_3_ = prefFromPrefPtr(&prefs.gui_layout_content_3);
    pref_layout_content_4_ = prefFromPrefPtr(&prefs.gui_layout_content_4);

    QString image_pad_ss = "QToolButton { padding: 0.3em; }";
    ui->layout2Top1BotToolButton->setStyleSheet(image_pad_ss);
    ui->layout1Top2BotToolButton->setStyleSheet(image_pad_ss);
    ui->layout2Left1RightToolButton->setStyleSheet(image_pad_ss);
    ui->layout1Left2RightToolButton->setStyleSheet(image_pad_ss);
    ui->layout3VerticalToolButton->setStyleSheet(image_pad_ss);
    ui->layout3HorizontalToolButton->setStyleSheet(image_pad_ss);
    ui->layout4QuadToolButton->setStyleSheet(image_pad_ss);
    ui->layout4HorizontalToolButton->setStyleSheet(image_pad_ss);

    QStyleOption style_opt;
    QString indent_ss = QString(
             "QCheckBox, QLabel {"
             "  margin-left: %1px;"
             "}"
             ).arg(ui->packetListSeparatorCheckBox->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left());
    ui->packetListSeparatorCheckBox->setStyleSheet(indent_ss);
    ui->packetListHeaderShowColumnDefinition->setStyleSheet(indent_ss);
    ui->packetListHoverStyleCheckbox->setStyleSheet(indent_ss);
    ui->packetListAllowSorting->setStyleSheet(indent_ss);
    ui->packetListCachedRowsLabel->setStyleSheet(indent_ss);
    ui->statusBarShowSelectedPacketCheckBox->setStyleSheet(indent_ss);
    ui->statusBarShowFileLoadTimeCheckBox->setStyleSheet(indent_ss);

    pref_packet_list_separator_ = prefFromPrefPtr(&prefs.gui_packet_list_separator);
    ui->packetListSeparatorCheckBox->setChecked(prefs_get_bool_value(pref_packet_list_separator_, pref_stashed));

    pref_packet_header_column_definition_ = prefFromPrefPtr(&prefs.gui_packet_header_column_definition);
    ui->packetListHeaderShowColumnDefinition->setChecked(prefs_get_bool_value(pref_packet_header_column_definition_, pref_stashed));

    pref_packet_list_hover_style_ = prefFromPrefPtr(&prefs.gui_packet_list_hover_style);
    ui->packetListHoverStyleCheckbox->setChecked(prefs_get_bool_value(pref_packet_list_hover_style_, pref_stashed));

    pref_packet_list_sorting_ = prefFromPrefPtr(&prefs.gui_packet_list_sortable);
    ui->packetListAllowSorting->setChecked(prefs_get_bool_value(pref_packet_list_sorting_, pref_stashed));

    pref_packet_list_cached_rows_max_ = prefFromPrefPtr(&prefs.gui_packet_list_cached_rows_max);

    pref_show_selected_packet_ = prefFromPrefPtr(&prefs.gui_show_selected_packet);
    ui->statusBarShowSelectedPacketCheckBox->setChecked(prefs_get_bool_value(pref_show_selected_packet_, pref_stashed));

    pref_show_file_load_time_ = prefFromPrefPtr(&prefs.gui_show_file_load_time);
    ui->statusBarShowFileLoadTimeCheckBox->setChecked(prefs_get_bool_value(pref_show_file_load_time_, pref_stashed));
}

LayoutPreferencesFrame::~LayoutPreferencesFrame()
{
    delete ui;
}

void LayoutPreferencesFrame::showEvent(QShowEvent *)
{
    updateWidgets();
}

void LayoutPreferencesFrame::updateWidgets()
{
    switch (prefs_get_uint_value_real(pref_layout_type_, pref_stashed)) {
    case layout_type_2_top_1_bot:
        ui->layout2Top1BotToolButton->setChecked(true);
        break;
    case layout_type_1_top_2_bot:
        ui->layout1Top2BotToolButton->setChecked(true);
        break;
    case layout_type_2_left_1_right:
        ui->layout2Left1RightToolButton->setChecked(true);
        break;
    case layout_type_1_left_2_right:
        ui->layout1Left2RightToolButton->setChecked(true);
        break;
    case layout_type_3_vertical:
        ui->layout3VerticalToolButton->setChecked(true);
        break;
    case layout_type_3_horizontal:
        ui->layout3HorizontalToolButton->setChecked(true);
        break;
    case layout_type_4_quad:
        ui->layout4QuadToolButton->setChecked(true);
        break;
    case layout_type_4_horizontal:
        ui->layout4HorizontalToolButton->setChecked(true);
        break;
    }

    switch (prefs_get_enum_value(pref_layout_content_1_, pref_stashed)) {
    case layout_pane_content_plist:
        ui->pane1PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane1PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane1PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdiagram:
        ui->pane1PacketDiagramRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane1NoneRadioButton->setChecked(true);
        break;
    }

    switch (prefs_get_enum_value(pref_layout_content_2_, pref_stashed)) {
    case layout_pane_content_plist:
        ui->pane2PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane2PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane2PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdiagram:
        ui->pane2PacketDiagramRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane2NoneRadioButton->setChecked(true);
        break;
    }

    switch (prefs_get_enum_value(pref_layout_content_3_, pref_stashed)) {
    case layout_pane_content_plist:
        ui->pane3PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane3PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane3PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdiagram:
        ui->pane3PacketDiagramRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane3NoneRadioButton->setChecked(true);
        break;
    }

    switch (prefs_get_enum_value(pref_layout_content_4_, pref_stashed)) {
    case layout_pane_content_plist:
        ui->pane4PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane4PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane4PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdiagram:
        ui->pane4PacketDiagramRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane4NoneRadioButton->setChecked(true);
        break;
    }

    ui->packetListCachedRowsLineEdit->setText(QString::number(prefs_get_uint_value_real(pref_packet_list_cached_rows_max_, pref_stashed)));
}

void LayoutPreferencesFrame::on_layout2Top1BotToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_2_top_1_bot, pref_stashed);
}

void LayoutPreferencesFrame::on_layout1Top2BotToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_1_top_2_bot, pref_stashed);
}

void LayoutPreferencesFrame::on_layout1Left2RightToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_1_left_2_right, pref_stashed);
}

void LayoutPreferencesFrame::on_layout2Left1RightToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_2_left_1_right, pref_stashed);
}

void LayoutPreferencesFrame::on_layout3VerticalToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_3_vertical, pref_stashed);
}

void LayoutPreferencesFrame::on_layout3HorizontalToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_3_horizontal, pref_stashed);
}

void LayoutPreferencesFrame::on_layout4QuadToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_4_quad, pref_stashed);
}

void LayoutPreferencesFrame::on_layout4HorizontalToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_4_horizontal, pref_stashed);
}

void LayoutPreferencesFrame::on_pane1PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_plist, pref_stashed);
    if (ui->pane2PacketListRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketListRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketListRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_pdetails, pref_stashed);
    if (ui->pane2PacketDetailsRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketDetailsRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketDetailsRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_pbytes, pref_stashed);
    if (ui->pane2PacketBytesRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketBytesRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketBytesRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketDiagramRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_pdiagram, pref_stashed);
    if (ui->pane2PacketDiagramRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketDiagramRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketDiagramRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_none, pref_stashed);
}

void LayoutPreferencesFrame::on_pane2PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_plist, pref_stashed);
    if (ui->pane1PacketListRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketListRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketListRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_pdetails, pref_stashed);
    if (ui->pane1PacketDetailsRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketDetailsRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketDetailsRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_pbytes, pref_stashed);
    if (ui->pane1PacketBytesRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketBytesRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketBytesRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketDiagramRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_pdiagram, pref_stashed);
    if (ui->pane1PacketDiagramRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketDiagramRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
    if (ui->pane4PacketDiagramRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_none, pref_stashed);
}

void LayoutPreferencesFrame::on_pane3PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_plist, pref_stashed);
    if (ui->pane1PacketListRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketListRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane4PacketListRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_pdetails, pref_stashed);
    if (ui->pane1PacketDetailsRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketDetailsRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane4PacketDetailsRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_pbytes, pref_stashed);
    if (ui->pane1PacketBytesRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketBytesRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane4PacketBytesRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketDiagramRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_pdiagram, pref_stashed);
    if (ui->pane1PacketDiagramRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketDiagramRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane4PacketDiagramRadioButton->isChecked())
        ui->pane4NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_none, pref_stashed);
}

void LayoutPreferencesFrame::on_pane4PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_4_, layout_pane_content_plist, pref_stashed);
    if (ui->pane1PacketListRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketListRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketListRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane4PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_4_, layout_pane_content_pdetails, pref_stashed);
    if (ui->pane1PacketDetailsRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketDetailsRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketDetailsRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane4PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_4_, layout_pane_content_pbytes, pref_stashed);
    if (ui->pane1PacketBytesRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketBytesRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketBytesRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane4PacketDiagramRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_4_, layout_pane_content_pdiagram, pref_stashed);
    if (ui->pane1PacketDiagramRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketDiagramRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketDiagramRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane4NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_4_, layout_pane_content_none, pref_stashed);
}
void LayoutPreferencesFrame::on_restoreButtonBox_clicked(QAbstractButton *)
{
    reset_stashed_pref(pref_layout_type_);
    reset_stashed_pref(pref_layout_content_1_);
    updateWidgets();
    reset_stashed_pref(pref_layout_content_2_);
    updateWidgets();
    reset_stashed_pref(pref_layout_content_3_);
    updateWidgets();
    reset_stashed_pref(pref_layout_content_4_);
    updateWidgets();

    ui->packetListSeparatorCheckBox->setChecked(prefs_get_bool_value(pref_packet_list_separator_, pref_default));
    ui->packetListHeaderShowColumnDefinition->setChecked(prefs_get_bool_value(pref_packet_header_column_definition_, pref_default));
    ui->packetListHoverStyleCheckbox->setChecked(prefs_get_bool_value(pref_packet_list_hover_style_, pref_default));
    ui->packetListAllowSorting->setChecked(prefs_get_bool_value(pref_packet_list_sorting_, pref_default));
    ui->statusBarShowSelectedPacketCheckBox->setChecked(prefs_get_bool_value(pref_show_selected_packet_, pref_default));
    ui->statusBarShowFileLoadTimeCheckBox->setChecked(prefs_get_bool_value(pref_show_file_load_time_, pref_default));
}

void LayoutPreferencesFrame::on_packetListSeparatorCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_packet_list_separator_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_packetListHeaderShowColumnDefinition_toggled(bool checked)
{
    prefs_set_bool_value(pref_packet_header_column_definition_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_packetListHoverStyleCheckbox_toggled(bool checked)
{
    prefs_set_bool_value(pref_packet_list_hover_style_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_packetListAllowSorting_toggled(bool checked)
{
    prefs_set_bool_value(pref_packet_list_sorting_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_packetListCachedRowsLineEdit_textEdited(const QString &new_str)
{
    bool ok;
    uint new_uint = new_str.toUInt(&ok, 0);
    if (ok) {
        prefs_set_uint_value(pref_packet_list_cached_rows_max_, new_uint, pref_stashed);
    }
}

void LayoutPreferencesFrame::on_statusBarShowSelectedPacketCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_show_selected_packet_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_statusBarShowFileLoadTimeCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_show_file_load_time_, (gboolean) checked, pref_stashed);
}
