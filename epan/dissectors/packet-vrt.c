/* packet-vrt.c
 * Routines for VRT (VITA 49) packet disassembly
 * Copyright 2012 Ettus Research LLC - Nick Foster <nick@ettus.com>: original dissector
 * Copyright 2013 Alexander Chemeris <alexander.chemeris@gmail.com>: dissector improvement
 * Copyright 2013 Dario Lombardo (lomato@gmail.com): Official Wireshark port
 * Copyright 2020 The MITRE Corporation: Extended to support VITA 49.2 changes; support configurable CIF parsing
 *
 * Original dissector repository: https://github.com/bistromath/vrt-dissector
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-vrt.h"

void proto_register_vrt(void);
void proto_reg_handoff_vrt(void);

static dissector_handle_t vrt_handle;

#define VITA_49_PORT    4991

typedef int (*complex_dissector_t)(proto_tree *tree, tvbuff_t *tvb, int offset);

typedef struct {
    int tsi; /* 2-bit timestamp type */
    int tsf; /* 2-bit fractional timestamp type */
    int oui; /* 24-bit GPS/INS manufacturer OUI */
    int ts_int; /* 32-bit integer timestamp (opt.) */
    int ts_picosecond; /* 64-bit fractional timestamp (mutually exclusive with below) */
    int ts_frac_sample; /* 64-bit fractional timestamp (mutually exclusive with above) */
    int pos_x; /* 32-bit position X */
    int pos_y; /* 32-bit position Y */
    int pos_z; /* 32-bit position Z */
    int att_alpha; /* 32-bit attitude alpha */
    int att_beta; /* 32-bit attitude beta */
    int att_phi; /* 32-bit attitude phi */
    int vel_dx; /* 32-bit velocity dX */
    int vel_dy; /* 32-bit velocity dY */
    int vel_dz; /* 32-bit velocity dZ */
} ephemeris_fields;

typedef struct {
    int tsi; /* 2-bit timestamp type */
    int tsf; /* 2-bit fractional timestamp type */
    int oui; /* 24-bit GPS/INS manufacturer OUI */
    int ts_int; /* 32-bit integer timestamp (opt.) */
    int ts_picosecond; /* 64-bit fractional timestamp (mutually exclusive with below) */
    int ts_frac_sample; /* 64-bit fractional timestamp (mutually exclusive with above) */
    int lat; /* 32-bit latitude */
    int lon; /* 32-bit longitude */
    int alt; /* 32-bit altitude */
    int speed; /* 32-bit speed over ground */
    int heading; /* 32-bit heading angle */
    int track; /* 32-bit track angle */
    int mag_var; /* 32-bit magnetic variation */
} formatted_gps_ins_fields;

typedef int (*complex_dissector_t)(proto_tree *tree, tvbuff_t *tvb, int offset);

static gboolean vrt_use_ettus_uhd_header_format = FALSE;
static gboolean vrt_limit_to_49_0 = TRUE;

static int proto_vrt;

/* fields */
static int hf_vrt_header; /* 32-bit header */
static int hf_vrt_type; /* 4-bit pkt type */
static int hf_vrt_cidflag; /* 1-bit class ID flag */
static int hf_vrt_tflag; /* 1-bit trailer flag */
static int hf_vrt_tsmflag; /* 1-bit timestamp mode */
static int hf_vrt_tsi; /* 2-bit timestamp type */
static int hf_vrt_tsf; /* 2-bit fractional timestamp type */
static int hf_vrt_seq; /* 4-bit sequence number */
static int hf_vrt_len; /* 16-bit length */
static int hf_vrt_sid; /* 32-bit stream ID (opt.) */
static int hf_vrt_cid; /* 64-bit class ID (opt.) */
static int hf_vrt_cid_oui; /* 24-bit class ID OUI */
static int hf_vrt_cid_icc; /* 16-bit class ID ICC */
static int hf_vrt_cid_pcc; /* 16-bit class ID PCC */
static int hf_vrt_cif[8]; /* 32-bit CIF0-CIF7 (opt.) */
static int hf_vrt_cif0_change_flag; /* 1-bit context field change indicator */
static int hf_vrt_cif0_ref_pt_id; /* 1-bit reference point identifier */
static int hf_vrt_cif0_bandwidth; /* 1-bit bandwidth */
static int hf_vrt_cif0_if_freq; /* 1-bit IF reference frequency */
static int hf_vrt_cif0_rf_freq; /* 1-bit RF reference frequency */
static int hf_vrt_cif0_rf_freq_offset; /* 1-bit RF reference frequency offset */
static int hf_vrt_cif0_if_band_offset; /* 1-bit IF band offset */
static int hf_vrt_cif0_ref_level; /* 1-bit reference level */
static int hf_vrt_cif0_gain; /* 1-bit gain */
static int hf_vrt_cif0_over_range_count; /* 1-bit over-range count */
static int hf_vrt_cif0_sample_rate; /* 1-bit sample rate */
static int hf_vrt_cif0_timestamp_adjust; /* 1-bit timestamp adjustment */
static int hf_vrt_cif0_timestamp_cal; /* 1-bit timestamp calibration time */
static int hf_vrt_cif0_temperature; /* 1-bit temperature */
static int hf_vrt_cif0_device_id; /* 1-bit device identifier */
static int hf_vrt_cif0_state_event; /* 1-bit state/event indicators */
static int hf_vrt_cif0_signal_data_format; /* 1-bit signal data packet payload format */
static int hf_vrt_cif0_gps; /* 1-bit formatted GPS */
static int hf_vrt_cif0_ins; /* 1-bit formatted INS */
static int hf_vrt_cif0_ecef_ephemeris; /* 1-bit ECEF ephemeris */
static int hf_vrt_cif0_rel_ephemeris; /* 1-bit relative ephemeris */
static int hf_vrt_cif0_ephemeris_ref_id; /* 1-bit ephemeris ref ID */
static int hf_vrt_cif0_gps_ascii; /* 1-bit GPS ASCII */
static int hf_vrt_cif0_context_assoc_lists; /* 1-bit context association lists */
static int hf_vrt_cif0_cif7; /* 1-bit CIF7 */
static int hf_vrt_cif0_cif6; /* 1-bit CIF6 */
static int hf_vrt_cif0_cif5; /* 1-bit CIF5 */
static int hf_vrt_cif0_cif4; /* 1-bit CIF4 */
static int hf_vrt_cif0_cif3; /* 1-bit CIF3 */
static int hf_vrt_cif0_cif2; /* 1-bit CIF2 */
static int hf_vrt_cif0_cif1; /* 1-bit CIF1 */
/* TODO: complete CIF1 support (have partial CIF1 support) */
static int hf_vrt_cif1_phase_offset; /* 1-bit phase offset */
static int hf_vrt_cif1_polarization; /* 1-bit polarization */
static int hf_vrt_cif1_range; /* 1-bit range (distance) */
static int hf_vrt_cif1_aux_freq; /* 1-bit aux frequency */
static int hf_vrt_cif1_aux_bandwidth; /* 1-bit aux bandwidth */
static int hf_vrt_cif1_io32; /* 1-bit discrete I/O (32-bit) */
static int hf_vrt_cif1_io64; /* 1-bit discrete I/O (64-bit) */
static int hf_vrt_cif1_v49_spec; /* 1-bit V49 spec compliance */
static int hf_vrt_cif1_ver; /* 1-bit version and build code */
static int hf_vrt_context_ref_pt_id; /* 32-bit reference point identifier */
static int hf_vrt_context_bandwidth; /* 64-bit bandwidth */
static int hf_vrt_context_if_freq; /* 64-bit IF reference frequency */
static int hf_vrt_context_rf_freq; /* 64-bit RF reference frequency */
static int hf_vrt_context_rf_freq_offset; /* 64-bit RF frequency offset */
static int hf_vrt_context_if_band_offset; /* 64-bit IF band offset */
static int hf_vrt_context_ref_level; /* 16-bit reference level */
static int hf_vrt_context_gain_stage2; /* 16-bit gain stage 2 */
static int hf_vrt_context_gain_stage1; /* 16-bit gain stage 1 */
static int hf_vrt_context_over_range_count; /* 32-bit over-range count */
static int hf_vrt_context_sample_rate; /* 64-bit sample rate */
static int hf_vrt_context_timestamp_adjust; /* 64-bit timestamp adjustment */
static int hf_vrt_context_timestamp_cal; /* 32-bit timestamp calibration */
static int hf_vrt_context_temperature; /* 16-bit device temperature */
static int hf_vrt_context_device_id_oui; /* 24-bit device ID OUI */
static int hf_vrt_context_device_id_code; /* 16-bit device ID code */
static int hf_vrt_context_state_event_en_cal_time; /* 1-bit enable calibrated time */
static int hf_vrt_context_state_event_en_valid_data; /* 1-bit enable valid data */
static int hf_vrt_context_state_event_en_ref_lock; /* 1-bit enable reference lock */
static int hf_vrt_context_state_event_en_agc; /* 1-bit enable AGC/MGC */
static int hf_vrt_context_state_event_en_detected_sig; /* 1-bit enable detected signal */
static int hf_vrt_context_state_event_en_spectral_inv; /* 1-bit enable spectral inversion */
static int hf_vrt_context_state_event_en_over_range; /* 1-bit enable over-range */
static int hf_vrt_context_state_event_en_sample_loss; /* 1-bit enable sample loss */
static int hf_vrt_context_state_event_cal_time; /* 1-bit enable calibrated time */
static int hf_vrt_context_state_event_valid_data; /* 1-bit enable valid data */
static int hf_vrt_context_state_event_ref_lock; /* 1-bit enable reference lock */
static int hf_vrt_context_state_event_agc; /* 1-bit enable AGC/MGC */
static int hf_vrt_context_state_event_detected_sig; /* 1-bit enable detected signal */
static int hf_vrt_context_state_event_spectral_inv; /* 1-bit enable spectral inversion */
static int hf_vrt_context_state_event_over_range; /* 1-bit enable over-range */
static int hf_vrt_context_state_event_sample_loss; /* 1-bit enable sample loss */
static int hf_vrt_context_state_event_user; /* 8-bit user-defined */
static int hf_vrt_context_signal_data_format_packing; /* 1-bit signal data format packing */
static int hf_vrt_context_signal_data_format_type; /* 2-bit real/complex type */
static int hf_vrt_context_signal_data_format_item; /* 5-bit data item format */
static int hf_vrt_context_signal_data_format_repeat; /* 1-bit sample-component repeat indicator */
static int hf_vrt_context_signal_data_format_event_size; /* 3-bit event-tag size */
static int hf_vrt_context_signal_data_format_channel_size; /* 4-bit channel-tag size */
static int hf_vrt_context_signal_data_format_fraction_size; /* 4-bit data item fraction size */
static int hf_vrt_context_signal_data_format_packing_size; /* 6-bit item packing field size */
static int hf_vrt_context_signal_data_format_item_size; /* 6-bit data item size */
static int hf_vrt_context_signal_data_format_repeat_count; /* 16-bit repeat count */
static int hf_vrt_context_signal_data_format_vector_size; /* 16-bit vector size */
static formatted_gps_ins_fields hf_vrt_context_gps; /* struct for formatted GPS */
static formatted_gps_ins_fields hf_vrt_context_ins; /* struct for formatted INS */
static ephemeris_fields hf_vrt_context_ecef_ephemeris; /* struct for ECEF ephemeris */
static ephemeris_fields hf_vrt_context_rel_ephemeris; /* struct for relative ephemeris */
static int hf_vrt_context_ephemeris_ref_id; /* 32-bit ephemeris reference identifier */
static int hf_vrt_context_gps_ascii_oui; /* 24-bit GPS/INS manufacturer OUI */
static int hf_vrt_context_gps_ascii_size; /* 32-bit number of words */
static int hf_vrt_context_gps_ascii_data; /* Variable GPS ASCII data */
static int hf_vrt_context_assoc_lists_src_size; /* 32-bit source list size */
static int hf_vrt_context_assoc_lists_sys_size; /* 32-bit system list size */
static int hf_vrt_context_assoc_lists_vec_size; /* 32-bit vector-component list size */
static int hf_vrt_context_assoc_lists_a; /* 1-bit "A" bit (asynchronous-channel tag list present) */
static int hf_vrt_context_assoc_lists_asy_size; /* 32-bit asynchronous-channel list size */
static int hf_vrt_context_assoc_lists_src_data; /* Variable source context association list */
static int hf_vrt_context_assoc_lists_sys_data; /* Variable system context association list */
static int hf_vrt_context_assoc_lists_vec_data; /* Variable vector-component context association list */
static int hf_vrt_context_assoc_lists_asy_data; /* Variable asynchronous-channel context association list */
static int hf_vrt_context_assoc_lists_asy_tag_data; /* Variable asynchronous-channel tag list */
static int hf_vrt_context_phase_offset; /* 16-bit phase offset */
static int hf_vrt_context_pol_tilt; /* 16-bit polarization tilt angle */
static int hf_vrt_context_pol_ellipticity; /* 16-bit polarization ellipticity angle */
static int hf_vrt_context_range; /* 32-bit range (distance) */
static int hf_vrt_context_aux_freq; /* 64-bit aux frequency */
static int hf_vrt_context_aux_bandwidth; /* 64-bit aux bandwidth */
static int hf_vrt_context_io32; /* 32-bit discrete I/O */
static int hf_vrt_context_io64; /* 64-bit discrete I/O */
static int hf_vrt_context_v49_spec; /* 32-bit V49 spec compliance */
static int hf_vrt_context_ver_year; /* 7-bit year */
static int hf_vrt_context_ver_day; /* 9-bit day */
static int hf_vrt_context_ver_rev; /* 6-bit revision */
static int hf_vrt_context_ver_user; /* 10-bit user defined */
static int hf_vrt_ts_int; /* 32-bit integer timestamp (opt.) */
static int hf_vrt_ts_frac_picosecond; /* 64-bit fractional timestamp (opt.) */
static int hf_vrt_ts_frac_sample; /* 64-bit fractional timestamp (opt.) */
static int hf_vrt_data; /* data */
static int hf_vrt_trailer; /* 32-bit trailer (opt.) */
static int hf_vrt_trailer_enables; /* trailer indicator enables */
static int hf_vrt_trailer_ind; /* trailer indicators */
static int hf_vrt_trailer_e; /* ass con pac cnt enable */
static int hf_vrt_trailer_acpc; /* associated context packet count */
static int hf_vrt_trailer_en_caltime; /* calibrated time indicator */
static int hf_vrt_trailer_en_valid; /* valid data ind */
static int hf_vrt_trailer_en_reflock; /* reference locked ind */
static int hf_vrt_trailer_en_agc; /* AGC/MGC enabled ind */
static int hf_vrt_trailer_en_sig; /* signal detected ind */
static int hf_vrt_trailer_en_inv; /* spectral inversion ind */
static int hf_vrt_trailer_en_overrng; /* overrange indicator */
static int hf_vrt_trailer_en_sampleloss; /* sample loss indicator */
static int hf_vrt_trailer_en_user0; /* User indicator 0 */
static int hf_vrt_trailer_en_user1; /* User indicator 1 */
static int hf_vrt_trailer_en_user2; /* User indicator 2 */
static int hf_vrt_trailer_en_user3; /* User indicator 3 */
static int hf_vrt_trailer_ind_caltime; /* calibrated time indicator */
static int hf_vrt_trailer_ind_valid; /* valid data ind */
static int hf_vrt_trailer_ind_reflock; /* reference locked ind */
static int hf_vrt_trailer_ind_agc; /* AGC/MGC enabled ind */
static int hf_vrt_trailer_ind_sig; /* signal detected ind */
static int hf_vrt_trailer_ind_inv; /* spectral inversion ind */
static int hf_vrt_trailer_ind_overrng; /* overrange indicator */
static int hf_vrt_trailer_ind_sampleloss; /* sample loss indicator */
static int hf_vrt_trailer_ind_user0; /* User indicator 0 */
static int hf_vrt_trailer_ind_user1; /* User indicator 1 */
static int hf_vrt_trailer_ind_user2; /* User indicator 2 */
static int hf_vrt_trailer_ind_user3; /* User indicator 3 */

/* fixed sizes (in bytes) of context packet CIF field bits */
static int context_size_cif0[32] = { 0, 4, 4, 4, 4, 4, 4, 4, 8, 8, 4, 52, 52, 44, 44, 8,
    4, 8, 4, 4, 8, 8, 4, 4, 4, 8, 8, 8, 8, 8, 4, 0 };
static int context_size_cif1[32] = { 0, 8, 4, 4, 4, 8, 4, 0, 0, 0, 52, 0, 0, 8, 4, 8,
    4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 0, 4, 4, 4 };

/* subtree state variables */
static gint ett_vrt;
static gint ett_header;
static gint ett_trailer;
static gint ett_indicators;
static gint ett_ind_enables;
static gint ett_cid;
static gint ett_cif0;
static gint ett_cif1;
static gint ett_gain;
static gint ett_device_id;
static gint ett_state_event;
static gint ett_signal_data_format;
static gint ett_gps;
static gint ett_ins;
static gint ett_ecef_ephem;
static gint ett_rel_ephem;
static gint ett_gps_ascii;
static gint ett_assoc_lists;
static gint ett_pol;
static gint ett_ver;

/* constants (unit conversion) */
static const double FEMTOSEC_PER_SEC = 1e-15;
static const double RADIX_CELSIUS = 1.0/64.0;
static const double RADIX_DECIBEL = 1.0/128.0;
static const double RADIX_DECIBEL_MILLIWATT = 1.0/128.0;
static const double RADIX_DEGREES = 1.0/4194304.0;
static const double RADIX_HERTZ = 1.0/1048576.0;
static const double RADIX_METER = 1.0/32.0;
static const double RADIX_METER_UNSIGNED = 1.0/64.0;
static const double RADIX_METERS_PER_SECOND = 1.0/65536.0;
static const double RADIX_RADIAN_PHASE = 1.0/128.0;
static const double RADIX_RADIAN_POL = 1.0/8192.0;

/* constants (tree index) */
static const int ETT_IDX_GAIN = 8;
static const int ETT_IDX_DEVICE_ID = 9;
static const int ETT_IDX_STATE_EVENT = 10;
static const int ETT_IDX_SIGNAL_DATA_FORMAT = 11;
static const int ETT_IDX_GPS = 12;
static const int ETT_IDX_INS = 13;
static const int ETT_IDX_ECEF_EPHEM = 14;
static const int ETT_IDX_REL_EPHEM = 15;
static const int ETT_IDX_GPS_ASCII = 16;
static const int ETT_IDX_ASSOC_LISTS = 17;
static const int ETT_IDX_POL = 18;
static const int ETT_IDX_VER = 19;

static const value_string packet_types[] = {
    {vrt_type_sig,      "IF data packet without stream ID"},
    {vrt_type_sig_sid,  "IF data packet with stream ID"},
    {vrt_type_edat,     "Extension data packet without stream ID"},
    {vrt_type_edat_sid, "Extension data packet with stream ID"},
    {vrt_type_ctx,      "IF context packet"},
    {vrt_type_ectx,     "Extension context packet"},
    {vrt_type_cmd,      "Command packet"},
    {vrt_type_ecmd,     "Extension command packet"},
    {0, NULL}
};

static const value_string tsi_types[] = {
    {0x00, "No integer-seconds timestamp field included"},
    {0x01, "Coordinated Universal Time (UTC)"},
    {0x02, "GPS time"},
    {0x03, "Other"},
    {0, NULL}
};

static const value_string tsf_types[] = {
    {0x00, "No fractional-seconds timestamp field included"},
    {0x01, "Sample count timestamp"},
    {0x02, "Real time (picoseconds) timestamp"},
    {0x03, "Free running count timestamp"},
    {0, NULL}
};

static const value_string tsm_types[] = {
    {0x00, "Precise timestamp resolution"},
    {0x01, "General timestamp resolution"},
    {0, NULL}
};

static const value_string signal_type_types[] = {
    {0x00, "Signal Time Data"},
    {0x01, "Signal Spectral Data"},
    {0, NULL}
};

static const value_string cam_control_types[] = {
    {0x00, "No id"},
    {0x01, "No id (UUID)"},
    {0x02, "32-bit id"},
    {0x03, "128-bit UUID"},
    {0, NULL}
};

static const value_string cam_action_types[] = {
    {0x00, "No-action"},
    {0x01, "Dry run"},
    {0x02, "Execute"},
    {0, NULL}
};

static const value_string cam_timing_types[] = {
    {0x00, "Ignore"},
    {0x01, "Precise"},
    {0x02, "Allow late"},
    {0x03, "Allow early"},
    {0x04, "Windowed"},
    {0, NULL}
};

static const value_string frame_mode_types[] = {
    {0x00, "Full frame"},
    {0x01, "Start of frame"},
    {0x02, "Middle of frame"},
    {0x03, "End of frame"},
    {0, NULL}
};

static int * const enable_hfs[] = {
    &hf_vrt_trailer_en_user3,
    &hf_vrt_trailer_en_user2,
    &hf_vrt_trailer_en_user1,
    &hf_vrt_trailer_en_user0,
    &hf_vrt_trailer_en_sampleloss,
    &hf_vrt_trailer_en_overrng,
    &hf_vrt_trailer_en_inv,
    &hf_vrt_trailer_en_sig,
    &hf_vrt_trailer_en_agc,
    &hf_vrt_trailer_en_reflock,
    &hf_vrt_trailer_en_valid,
    &hf_vrt_trailer_en_caltime
};

static int * const ind_hfs[] = {
    &hf_vrt_trailer_ind_user3,
    &hf_vrt_trailer_ind_user2,
    &hf_vrt_trailer_ind_user1,
    &hf_vrt_trailer_ind_user0,
    &hf_vrt_trailer_ind_sampleloss,
    &hf_vrt_trailer_ind_overrng,
    &hf_vrt_trailer_ind_inv,
    &hf_vrt_trailer_ind_sig,
    &hf_vrt_trailer_ind_agc,
    &hf_vrt_trailer_ind_reflock,
    &hf_vrt_trailer_ind_valid,
    &hf_vrt_trailer_ind_caltime
};

static void dissect_header(tvbuff_t *tvb, proto_tree *tree, int type, int offset);
static void dissect_trailer(tvbuff_t *tvb, proto_tree *tree, int offset);
static void dissect_cid(tvbuff_t *tvb, proto_tree *tree, int offset, vrt_packet_description_t *descript);
static int dissect_command(tvbuff_t *tvb, proto_tree *tree, int initial_offset, vrt_packet_description_t *descript);

static int dissect_vrt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int     offset = 0;
    guint8  type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49");
    col_clear(pinfo->cinfo,COL_INFO);

    /* HACK to support UHD's weird header offset on data packets. */
    if (vrt_use_ettus_uhd_header_format && tvb_get_guint8(tvb, 0) == 0)
        offset += 4;

    /* get packet type */
    type = tvb_get_guint8(tvb, offset) >> 4;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, packet_types, "Reserved packet type (0x%02x)"));

    if (tree) { /* we're being asked for details */
        guint8  sidflag;
        guint8  cidflag;
        guint8  tflag = 0;
        guint8  ackflag = 0;
        //guint8  clflag = 0;
        guint8  tsitype;
        guint8  tsftype;
        guint16 len;
        guint16 nsamps;
        vrt_packet_description_t descript;

        proto_tree *vrt_tree;
        proto_item *ti;

        /* get SID, CID, T flags and TSI, TSF types */
        /* [TODO] Check for reserved packet type - how we handle sidflag is undefined! */
        sidflag = (((type == vrt_type_sig) || (type == vrt_type_edat)) ? 0 : 1);
        cidflag = (tvb_get_guint8(tvb, offset) >> 3) & 0x01;
        descript.type = type;
        descript.cam = 0;
        descript.has_cid = cidflag;
        /* Grab the flags we need for further decoding the packet; The actual tree is built elsewhere */
        if(vrt_limit_to_49_0) {
            if ((type == vrt_type_ctx) || (type == vrt_type_ectx)) {
                /* tsmflag is in context packets but not data packets
                tsmflag = (tvb_get_guint8(tvb, offset) >> 0) & 0x01; */
                ;
            } else {
               tflag =   (tvb_get_guint8(tvb, offset) >> 2) & 0x01;
            }
        } else {
            if ((type == vrt_type_cmd) || (type == vrt_type_ecmd)) {
                ackflag = (tvb_get_guint8(tvb, offset) >> 2) & 0x01;
                // clflag = (tvb_get_guint8(tvb, offset) >> 0) & 0x01;
            } else if ((type == vrt_type_sig) || (type == vrt_type_sig_sid)) {
                tflag = (tvb_get_guint8(tvb, offset) >> 2) & 0x01;
            } else if ((type == vrt_type_edat) || (type == vrt_type_edat_sid)) {
                tflag = (tvb_get_guint8(tvb, offset) >> 2) & 0x01;
            }
        }
        descript.is_ack = ackflag;

        tsitype = (tvb_get_guint8(tvb, offset+1) >> 6) & 0x03;
        tsftype = (tvb_get_guint8(tvb, offset+1) >> 4) & 0x03;
        len     = tvb_get_ntohs(tvb, offset+2);

        nsamps  = len - 1;  /* (Before adjusting word count for optional fields) */

        ti = proto_tree_add_item(tree, proto_vrt, tvb, offset, -1, ENC_NA);
        vrt_tree = proto_item_add_subtree(ti, ett_vrt);

        dissect_header(tvb, vrt_tree, type, offset);
        offset += 4;

        /* header's done! if SID (last bit of type), put the stream ID here */
        if (sidflag) {
            proto_tree_add_item(vrt_tree, hf_vrt_sid, tvb, offset, 4, ENC_BIG_ENDIAN);
            nsamps -= 1;
            offset += 4;
        }

        /* if there's a class ID (cidflag), put the class ID here */
        if (cidflag) {
            dissect_cid(tvb, vrt_tree, offset, &descript);
            nsamps -= 2;
            offset += 8;
        }

        /* if TSI and/or TSF, populate those here */
        if (tsitype != 0) {
            proto_tree_add_item(vrt_tree, hf_vrt_ts_int, tvb, offset, 4, ENC_BIG_ENDIAN);
            nsamps -= 1;
            offset += 4;
        }
        if (tsftype != 0) {
            if (tsftype == 1 || tsftype == 3) {
                proto_tree_add_item(vrt_tree, hf_vrt_ts_frac_sample, tvb, offset, 8, ENC_BIG_ENDIAN);
            } else if (tsftype == 2) {
                proto_tree_add_item(vrt_tree, hf_vrt_ts_frac_picosecond, tvb, offset, 8, ENC_BIG_ENDIAN);
            }
            nsamps -= 2;
            offset += 8;
        }

        /* account for the trailer before parsing the payload */
        if (tflag) {
            nsamps -= 1;
        }

        /* Parsing of the payload depend on the packet type */
        tvbuff_t *payload;
        switch(type) {
            case vrt_type_ctx: 
                payload = tvb_new_subset_length_caplen(tvb, offset, nsamps*4, nsamps*4);
                call_dissector_with_data(cif_handle, payload, pinfo, vrt_tree, (void *) &descript);
                break;
            case vrt_type_ectx:
                payload = tvb_new_subset_length_caplen(tvb, offset, nsamps*4, nsamps*4);
                call_dissector_with_data(cif_handle, payload, pinfo, vrt_tree, (void *) &descript);
                break;
            case vrt_type_cmd:
                if(vrt_limit_to_49_0) {
                    /* This is not a valid type for 49.0; just show the rest as bytes */
                    if (nsamps != 0) {
                        proto_tree_add_item(vrt_tree, hf_vrt_data, tvb, offset, nsamps*4, ENC_NA);
                    }
                } else {
                    int delta_offset = dissect_command(tvb, vrt_tree, offset, &descript);
                    nsamps -= delta_offset/4;
                    offset += delta_offset;
                    payload = tvb_new_subset_length_caplen(tvb, offset, nsamps*4, nsamps*4);
                    call_dissector_with_data(cif_handle, payload, pinfo, vrt_tree, (void *) &descript);
                }
                break;
            case vrt_type_ecmd:
                if(vrt_limit_to_49_0) {
                    /* This is not a valid type for 49.0; just show the rest as bytes */
                    if (nsamps != 0) {
                        proto_tree_add_item(vrt_tree, hf_vrt_data, tvb, offset, nsamps*4, ENC_NA);
                    }
                } else {
                    int delta_offset = dissect_command(tvb, vrt_tree, offset, &descript);
                    nsamps -= delta_offset/4;
                    offset += delta_offset;
                    payload = tvb_new_subset_length_caplen(tvb, offset, nsamps*4, nsamps*4);
                    call_dissector_with_data(cif_handle, payload, pinfo, vrt_tree, (void *) &descript);
                }
                break;
            case vrt_type_sig:
            case vrt_type_sig_sid:
                /* [TODO] Add parsing of IF Data into fields; packing fields structure is a function
                   of class id and requires additional information to parse. Use new config table or
                   perhaps add a few selectable common encodings (e.g. packed/padded N-bit integers)? 
                   But for now just dump the the raw payload*/
                if (nsamps != 0) {
                  proto_tree_add_item(vrt_tree, hf_vrt_data, tvb, offset, nsamps*4, ENC_NA);
                }
                break;
            default:
                /* no further processing for other types */
                if (nsamps != 0) {
                  proto_tree_add_item(vrt_tree, hf_vrt_data, tvb, offset, nsamps*4, ENC_NA);
                }
        }
        /* The packet type specific parsing is expected to consume all remaing data 
           (excect the optional trailer which was already accounted for above) */
        offset += nsamps * 4;
        nsamps -= nsamps;

        if (tflag) {
            dissect_trailer(tvb, vrt_tree, offset);
        }
    }
    return tvb_captured_length(tvb);
}

static void dissect_header(tvbuff_t *tvb, proto_tree *tree, int type, int offset)
{
    proto_item *hdr_item;
    proto_tree *hdr_tree;

    hdr_item = proto_tree_add_item(tree, hf_vrt_header, tvb, offset, 4, ENC_BIG_ENDIAN);

    hdr_tree = proto_item_add_subtree(hdr_item, ett_header);
    proto_tree_add_item(hdr_tree, hf_vrt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_cidflag, tvb, offset, 1, ENC_BIG_ENDIAN);

    if(vrt_limit_to_49_0) {
        if ((type == vrt_type_ctx) || (type == vrt_type_ectx)) {
            proto_tree_add_item(hdr_tree, hf_vrt_tsmflag, tvb, offset, 1, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(hdr_tree, hf_vrt_tflag, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
    } else {
        /* decode packet specific indicator bits based on packet type */
        switch(type) {
            case vrt_type_sig:
            case vrt_type_sig_sid:
                proto_tree_add_item(hdr_tree, hf_vrt_tflag, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(hdr_tree, hf_vrt_nd0flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(hdr_tree, hf_vrt_sflag, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case vrt_type_ctx:
            case vrt_type_ectx:
                proto_tree_add_item(hdr_tree, hf_vrt_nd0flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(hdr_tree, hf_vrt_tsmflag, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case vrt_type_cmd:
            case vrt_type_ecmd:
                proto_tree_add_item(hdr_tree, hf_vrt_ackflag, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(hdr_tree, hf_vrt_clflag, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            default:
                proto_tree_add_item(hdr_tree, hf_vrt_tflag, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
    }

    offset += 1;
    proto_tree_add_item(hdr_tree, hf_vrt_tsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_tsf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_vrt_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hdr_tree, hf_vrt_len, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void dissect_trailer(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_item *enable_item, *ind_item, *trailer_item;
    proto_tree *enable_tree;
    proto_tree *ind_tree;
    proto_tree *trailer_tree;
    guint16     en_bits;
    gint16      i;

    trailer_item = proto_tree_add_item(tree, hf_vrt_trailer, tvb, offset, 4, ENC_BIG_ENDIAN);
    trailer_tree = proto_item_add_subtree(trailer_item, ett_trailer);

    /* grab the indicator enables and the indicators;
       only display enables, indicators which are enabled */
    enable_item = proto_tree_add_item(trailer_tree, hf_vrt_trailer_enables, tvb, offset, 2, ENC_BIG_ENDIAN);
    ind_item = proto_tree_add_item(trailer_tree, hf_vrt_trailer_ind, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    /* grab enable bits */
    en_bits = (tvb_get_ntohs(tvb, offset) & 0xFFF0) >> 4;

    /* if there's any enables, start trees for enable bits and for indicators
       only enables and indicators which are enabled get printed. */
    if (en_bits) {
        enable_tree = proto_item_add_subtree(enable_item, ett_ind_enables);
        ind_tree = proto_item_add_subtree(ind_item, ett_indicators);
        if(vrt_limit_to_49_0) {
            for (i = 11; i >= 0; i--) {
                if (en_bits & (1<<i)) {
                    /* XXX: Display needs to be improved ... */
                    proto_tree_add_item(enable_tree, *enable_hfs[i], tvb, offset,   2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ind_tree, *ind_hfs[i],       tvb, offset+1, 2, ENC_BIG_ENDIAN);
                }
            }
        } else {
            /* In V49.2 some of the user bits are redefined so special case the end */
            if (en_bits & 0x000C) {
                proto_tree_add_item(trailer_tree, hf_vrt_trailer_ind_frame,   tvb, offset+1, 2, ENC_BIG_ENDIAN);
            }
            for (i = 11; i >= 4; i--) {
                if (en_bits & (1<<i)) {
                    /* XXX: Display needs to be improved ... */
                    proto_tree_add_item(enable_tree, *enable_hfs[i], tvb, offset,   2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(ind_tree, *ind_hfs[i],       tvb, offset+1, 2, ENC_BIG_ENDIAN);
                }
            }
            if (en_bits & 0x000C) {
                proto_tree_add_item(enable_tree, hf_vrt_trailer_en_frame,   tvb, offset, 2, ENC_BIG_ENDIAN);
            }
            if (en_bits & 0x0002) {
                proto_tree_add_item(enable_tree, *enable_hfs[1], tvb, offset,   2, ENC_BIG_ENDIAN);
                proto_tree_add_item(ind_tree, *ind_hfs[1],       tvb, offset+1, 2, ENC_BIG_ENDIAN);
            }
            if (en_bits & 0x0001) {
                proto_tree_add_item(enable_tree, *enable_hfs[0], tvb, offset,   2, ENC_BIG_ENDIAN);
                proto_tree_add_item(ind_tree, *ind_hfs[0],       tvb, offset+1, 2, ENC_BIG_ENDIAN);
            }
        }
    }
    offset += 3;
    proto_tree_add_item(trailer_tree, hf_vrt_trailer_e,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(trailer_tree, hf_vrt_trailer_acpc, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void dissect_cid(tvbuff_t *tvb, proto_tree *tree, int offset, vrt_packet_description_t *descript)
{
    proto_item *cid_item;
    proto_tree *cid_tree;
    guint32 ret;

    cid_item = proto_tree_add_item(tree, hf_vrt_cid, tvb, offset, 8, ENC_BIG_ENDIAN);
    cid_tree = proto_item_add_subtree(cid_item, ett_cid);

    proto_tree_add_item(cid_tree, hf_vrt_cid_pad, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(cid_tree, hf_vrt_cid_oui, tvb, offset, 3, ENC_BIG_ENDIAN, &ret);
    descript->oui = ret & 0x00FFFFFF;
    offset += 3;
    proto_tree_add_item_ret_uint(cid_tree, hf_vrt_cid_icc, tvb, offset, 2, ENC_BIG_ENDIAN, &ret);
    descript->info_class_code = ret & 0xFFFF;
    offset += 2;
    proto_tree_add_item_ret_uint(cid_tree, hf_vrt_cid_pcc, tvb, offset, 2, ENC_BIG_ENDIAN, &ret);
    descript->packet_class_code = ret & 0xFFFF;
}

/* return the number of bytes parsed so we can keep track of our postion */
/* using pointers for offset might be cleaner, but it does not follow the 
   model of the other dissect_xxx functions */
static int dissect_command(tvbuff_t *tvb, proto_tree *tree, int initial_offset, vrt_packet_description_t *descript)
{
    int offset = initial_offset;
    proto_item *cam_item;
    proto_tree *cam_tree;
    guint32 ee_mode;
    guint32 er_mode;

    /* Not all of these fields have meaning for all packet types, but we decode them
       all anyway. They should be 0 when not valid. */
    cam_item = proto_tree_add_item_ret_uint(tree, hf_vrt_cam, tvb, offset, 4, ENC_BIG_ENDIAN, &descript->cam);
    cam_tree = proto_item_add_subtree(cam_item, ett_cam);
    proto_tree_add_item_ret_uint(cam_tree, hf_vrt_cam_controllee, tvb, offset, 4, ENC_BIG_ENDIAN, &ee_mode);
    proto_tree_add_item_ret_uint(cam_tree, hf_vrt_cam_controller, tvb, offset, 4, ENC_BIG_ENDIAN, &er_mode);
    proto_tree_add_item(cam_tree, hf_vrt_cam_partial, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_warnings, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_errors, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_nack, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_reqv, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_reqx, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_reqs, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_reqw, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_reqer, tvb, offset, 4, ENC_BIG_ENDIAN);
    if(tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN) & (1<<15)) {   /* only display if set */
      proto_tree_add_item(cam_tree, hf_vrt_cam_requ, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(cam_tree, hf_vrt_cam_timing_control, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_ackp, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_schx, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cam_tree, hf_vrt_cam_user, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_vrt_message_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if(ee_mode == 2) {
        proto_tree_add_item(tree, hf_vrt_controllee_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else if(ee_mode == 3) {
        proto_tree_add_item(tree, hf_vrt_controllee_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
        offset += 16;
    }
    if(er_mode == 2) {
        proto_tree_add_item(tree, hf_vrt_controller_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else if(er_mode == 3) {
        proto_tree_add_item(tree, hf_vrt_controller_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
        offset += 16;
    }

    return offset - initial_offset;
}

void
proto_register_vrt(void)
{
    module_t *vrt_module;

    static hf_register_info hf[] = {
        { &hf_vrt_header,
            { "VRT header", "vrt.hdr",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_type,
            { "Packet type", "vrt.type",
            FT_UINT8, BASE_DEC,
            VALS(packet_types), 0xF0,
            NULL, HFILL }
        },
        { &hf_vrt_cidflag,
            { "Class ID included", "vrt.cidflag",
            FT_BOOLEAN, 8,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_tflag,
            { "Trailer included", "vrt.tflag",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_nd0flag,
            { "Not V49.0 Compatible", "vrt.nd0flag",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_vrt_sflag,
            { "Spectral Data mode", "vrt.qflag",
            FT_UINT8, BASE_DEC,
            VALS(signal_type_types), 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_tsmflag,
            { "Timestamp mode", "vrt.tsmflag",
            FT_UINT8, BASE_DEC,
            VALS(tsm_types), 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_ackflag,
            { "Acknowledge Packet", "vrt.ackflag",
            FT_BOOLEAN, 8,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_clflag,
            { "Cancelation Packet", "vrt.clflag",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vrt_tsi,
            { "Integer timestamp type", "vrt.tsi",
            FT_UINT8, BASE_DEC,
            VALS(tsi_types), 0xC0,
            NULL, HFILL }
        },
        { &hf_vrt_tsf,
            { "Fractional timestamp type", "vrt.tsf",
            FT_UINT8, BASE_DEC,
            VALS(tsf_types), 0x30,
            NULL, HFILL }
        },
        { &hf_vrt_seq,
            { "Sequence number", "vrt.seq",
            FT_UINT8, BASE_DEC,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_vrt_len,
            { "Length", "vrt.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_int,
            { "Integer timestamp", "vrt.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.ts_frac_sample",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.ts_frac_picosecond",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_sid,
            { "Stream ID", "vrt.sid",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid,
            { "Class ID", "vrt.cid",
            FT_UINT64, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cam,
            { "VRT Control/Acknowledge Mode", "vrt.cam",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cam_controllee,
            { "Controllee Field Format", "vrt.cam_controllee",
            FT_UINT32, BASE_DEC,
            VALS(cam_control_types), 0xC0000000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_controller,
            { "Controller Field Format", "vrt.cam_controller",
            FT_UINT32, BASE_DEC,
            VALS(cam_control_types), 0x30000000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_partial,
            { "Allow Execution of partial packet", "vrt.cam_partial",
            FT_BOOLEAN, 32,
            NULL, 0x08000000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_warnings,
            { "Allow execution with warnings", "vrt.cam_warnings",
            FT_BOOLEAN, 32,
            NULL, 0x04000000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_errors,
            { "Allow execution with errors", "vrt.cam_errors",
            FT_BOOLEAN, 32,
            NULL, 0x02000000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_action,
            { "Command Action", "vrt.cam_action",
            FT_UINT32, BASE_DEC,
            VALS(cam_action_types), 0x01800000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_nack,
            { "Response only on error/warning", "vrt.cam_nack",
            FT_BOOLEAN, 32,
            NULL, 0x00400000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_reqv,
            { "Validation Response", "vrt.cam_reqv",
            FT_BOOLEAN, 32,
            NULL, 0x00100000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_reqx,
            { "Execution Response", "vrt.cam_reqx",
            FT_BOOLEAN, 32,
            NULL, 0x00080000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_reqs,
            { "Schedule Response", "vrt.cam_reqs",
            FT_BOOLEAN, 32,
            NULL, 0x00040000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_reqw,
            { "Request additional warning description", "vrt.cam_reqw",
            FT_BOOLEAN, 32,
            NULL, 0x00020000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_reqer,
            { "Request additional error description", "vrt.cam_reqer",
            FT_BOOLEAN, 32,
            NULL, 0x00010000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_requ,
            { "Request extension packet specific response", "vrt.cam_requ",
            FT_BOOLEAN, 32,
            NULL, 0x00008000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_timing_control,
            { "Command timing control mode", "vrt.cam_timing_control",
            FT_UINT32, BASE_DEC,
            VALS(cam_timing_types), 0x00007000,
            NULL, HFILL }
        },
        { &hf_vrt_cam_ackp,
            { "Partial Action Acknowledge", "vrt.cam_ackp",
            FT_BOOLEAN, 32,
            NULL, 0x00000800,
            NULL, HFILL }
        },
        { &hf_vrt_cam_schx,
            { "Requested Action complete", "vrt.cam_schx",
            FT_BOOLEAN, 32,
            NULL, 0x00000400,
            NULL, HFILL }
        },
        { &hf_vrt_cam_user,
            { "User Control/Acknowledge Mode Flags (for Extended Command Packets)", "vrt.cam_user",
            FT_UINT32, BASE_DEC,
            NULL, 0x000000FF,
            NULL, HFILL }
        },
        { &hf_vrt_message_id,
            { "Message Id", "vrt.message_id",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_controllee_id,
            { "Controllee Id", "vrt.controllee_id",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_controller_id,
            { "Controller Id", "vrt.controller_id",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_controllee_uuid,
            { "Controllee UUID", "vrt.controllee_uuid",
            FT_GUID, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_controller_uuid,
            { "Controller UUID", "vrt.controller_uuid",
            FT_GUID, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_data,
            { "Data", "vrt.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_trailer,
            { "Trailer", "vrt.trailer",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_enables,
            { "Indicator enable bits", "vrt.enables",
            FT_UINT16, BASE_HEX,
            NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind,
            { "Indicator bits", "vrt.indicators",
            FT_UINT16, BASE_HEX,
            NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_e,
            { "Associated context packet count enabled", "vrt.e",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_acpc,
            { "Associated context packet count", "vrt.acpc",
            FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_caltime,
            { "Calibrated time indicator", "vrt.caltime",
            FT_BOOLEAN, 16,
            NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_valid,
            { "Valid signal indicator", "vrt.valid",
            FT_BOOLEAN, 16,
            NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_reflock,
            { "Reference lock indicator", "vrt.reflock",
            FT_BOOLEAN, 16,
            NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_agc,
            { "AGC/MGC indicator", "vrt.agc",
            FT_BOOLEAN, 16,
            NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_sig,
            { "Signal detected indicator", "vrt.sig",
            FT_BOOLEAN, 16,
            NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_inv,
            { "Spectral inversion indicator", "vrt.inv",
            FT_BOOLEAN, 16,
            NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_overrng,
            { "Overrange indicator", "vrt.overrng",
            FT_BOOLEAN, 16,
            NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_sampleloss,
            { "Lost sample indicator", "vrt.sampleloss",
            FT_BOOLEAN, 16,
            NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user0,
            { "User indicator 0", "vrt.user0",
            FT_BOOLEAN, 16,
            NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user1,
            { "User indicator 1", "vrt.user1",
            FT_BOOLEAN, 16,
            NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user2,
            { "User indicator 2", "vrt.user2",
            FT_BOOLEAN, 16,
            NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_user3,
            { "User indicator 3", "vrt.user3",
            FT_BOOLEAN, 16,
            NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_ind_frame,
            { "Frame Mode Indicator", "vrt.frame_mode",
            FT_UINT16, BASE_DEC,
            VALS(frame_mode_types), 0x000C,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_caltime,
            { "Calibrated time indicator enable", "vrt.caltime_en",
            FT_BOOLEAN, 16,
            NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_valid,
            { "Valid signal indicator enable", "vrt.valid_en",
            FT_BOOLEAN, 16,
            NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_reflock,
            { "Reference lock indicator enable", "vrt.reflock_en",
            FT_BOOLEAN, 16,
            NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_agc,
            { "AGC/MGC indicator enable", "vrt.agc_en",
            FT_BOOLEAN, 16,
            NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_sig,
            { "Signal detected indicator enable", "vrt.sig_en",
            FT_BOOLEAN, 16,
            NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_inv,
            { "Spectral inversion indicator enable", "vrt.inv_en",
            FT_BOOLEAN, 16,
            NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_overrng,
            { "Overrange indicator enable", "vrt.overrng_en",
            FT_BOOLEAN, 16,
            NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_sampleloss,
            { "Lost sample indicator enable", "vrt.sampleloss_en",
            FT_BOOLEAN, 16,
            NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user0,
            { "User indicator 0 enable", "vrt.user0_en",
            FT_BOOLEAN, 16,
            NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user1,
            { "User indicator 1 enable", "vrt.user1_en",
            FT_BOOLEAN, 16,
            NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user2,
            { "User indicator 2 enable", "vrt.user2_en",
            FT_BOOLEAN, 16,
            NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_user3,
            { "User indicator 3 enable", "vrt.user3_en",
            FT_BOOLEAN, 16,
            NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_vrt_trailer_en_frame,
            { "Frame mode indicator enable", "vrt.frame_mode_en",
            FT_UINT16, BASE_DEC,
            NULL, 0x00C0,
            NULL, HFILL }
        },
        { &hf_vrt_cid_pad,
            { "Class ID Pad Bit Count", "vrt.pad_count",
            FT_UINT8, BASE_DEC,
            NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_vrt_cid_oui,
            { "Class ID Organizationally Unique ID", "vrt.oui",
            FT_UINT24, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid_icc,
            { "Class ID Information Class Code", "vrt.icc",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid_pcc,
            { "Class ID Packet Class Code", "vrt.pcc",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_vrt,
        &ett_header,
        &ett_trailer,
        &ett_indicators,
        &ett_ind_enables,
        &ett_cid,
        &ett_cam
     };

    proto_vrt = proto_register_protocol ("VITA 49 radio transport protocol", "VITA 49", "vrt");

    proto_register_field_array(proto_vrt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    vrt_handle = register_dissector("vrt", dissect_vrt, proto_vrt);

    vrt_module = prefs_register_protocol(proto_vrt, NULL);
    prefs_register_bool_preference(vrt_module, "ettus_uhd_header_format",
        "Use Ettus UHD header format",
        "Activate workaround for weird Ettus UHD header offset on data packets",
        &vrt_use_ettus_uhd_header_format);
    prefs_register_bool_preference(vrt_module, "limit_to_49_0_format",
        "Limit dissection to VITA 49.0 format",
        "Use the original field defintion for fields modified in VITA 49.2",
        &vrt_limit_to_49_0);
}

void
proto_reg_handoff_vrt(void)
{
    dissector_add_uint_with_preference("udp.port", VITA_49_PORT, vrt_handle);
    cif_handle = find_dissector_add_dependency("vrt_cif", proto_vrt);

    dissector_add_string("rtp_dyn_payload_type","VITA 49", vrt_handle);
    dissector_add_uint_range_with_preference("rtp.pt", "", vrt_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
