/* voip_calls_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VOIP_CALLS_DIALOG_H
#define VOIP_CALLS_DIALOG_H

#include <config.h>

#include <glib.h>

#include "cfile.h"

#include "ui/voip_calls.h"

#include <ui/qt/models/voip_calls_info_model.h>
#include <ui/qt/models/cache_proxy_model.h>
#include "ui/rtp_stream_id.h"
#include "wireshark_dialog.h"

#include <QMenu>

class QAbstractButton;

class SequenceInfo;

namespace Ui {
class VoipCallsDialog;
}

class VoipCallsDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit VoipCallsDialog(QWidget &parent, CaptureFile &cf, bool all_flows = false);
    ~VoipCallsDialog();

signals:
    void updateFilter(QString filter, bool force = false);
    void captureFileChanged(capture_file *cf);
    void goToPacket(int packet_num);
    void selectRtpStreamPassOut(rtpstream_id_t *id);
    void deselectRtpStreamPassOut(rtpstream_id_t *id);
    void openRtpStreamDialogPassOut();

public slots:
    void displayFilterSuccess(bool success);

protected:
    void contextMenuEvent(QContextMenuEvent *event);
    virtual void removeTapListeners();
    void captureFileClosing();
    void captureFileClosed();

protected slots:
    void changeEvent(QEvent* event);

private:
    Ui::VoipCallsDialog *ui;
    VoipCallsInfoModel *call_infos_model_;
    CacheProxyModel *cache_model_;
    QSortFilterProxyModel *sorted_model_;

    QWidget &parent_;
    voip_calls_tapinfo_t tapinfo_;
    SequenceInfo *sequence_info_;
    QPushButton *prepare_button_;
    QPushButton *sequence_button_;
    QPushButton *player_button_;
    QPushButton *copy_button_;
    bool voip_calls_tap_listeners_removed_;
    GQueue* shown_callsinfos_; /* queue with all shown calls (voip_calls_info_t) */

    // Tap callbacks
    static void tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data);
    static void tapDraw(void *tapinfo_ptr);
    static gint compareCallNums(gconstpointer a, gconstpointer b);

    void updateCalls();
    void prepareFilter();
    void showSequence();
    void showPlayer();
    void removeAllCalls();

    QList<QVariant> streamRowData(int row) const;

private slots:
    void selectAll();
    void selectNone();
    void copyAsCSV();
    void copyAsYAML();
    void switchTimeOfDay();
    void on_callTreeView_activated(const QModelIndex &index);
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_helpRequested();
    void updateWidgets();
    void selectRtpStreamPassIn(rtpstream_id_t *id);
    void deselectRtpStreamPassIn(rtpstream_id_t *id);
    void openRtpStreamDialogPassIn();
    void captureEvent(CaptureEvent e);
    void on_displayFilterCheckBox_toggled(bool checked);
};

#endif // VOIP_CALLS_DIALOG_H

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
