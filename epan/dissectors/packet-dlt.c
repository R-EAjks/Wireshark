/* packet-dlt.c
 * DLT Dissector
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2013-2019 Dr. Lars Voelker, BMW
 * Copyright 2020-2023 Dr. Lars Voelker, Technica Engineering GmbH
 * Enhanced for non verbose 2023 Matthias Bilger <matthias@bilger.info>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * For further information about the "Diagnostic Log and Trace" (DLT) protocol see:
 * - GENIVI Alliance (https://covesa.global/ and https://github.com/GENIVI/)
 * - AUTOSAR (https://www.autosar.org) -> AUTOSAR_SWS_DiagnosticLogAndTrace.pdf
 */

/* This dissector currently only supports Version 1 of DLT. */

#include <config.h>
#include <limits.h>

#include <epan/packet.h>
#include "packet-tcp.h"
#include "packet-udp.h"
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/show_exception.h>
#include <epan/etypes.h>
#include <epan/tvbuff.h>

#include <epan/to_str.h>
#include <epan/uat.h>
#include <wiretap/wtap.h>

#include "packet-dlt.h"

void proto_register_dlt(void);
void proto_reg_handoff_dlt(void);

void proto_register_dlt_storage_header(void);
void proto_reg_handoff_dlt_storage_header(void);

#define PNAME                                           "DLT"
#define PSNAME                                          "Diagnostic Log and Trace (DLT)"
#define PFNAME                                          "dlt"

#define DLT_STORAGE_HEADER_NAME                         "DLT Storage Header (short)"
#define DLT_STORAGE_HEADER_NAME_LONG                    "Shortened Diagnostic Log and Trace (DLT) Storage Header"
#define DLT_STORAGE_HEADER_NAME_FILTER                  "dlt.storage"

#define DLT_MIN_SIZE_FOR_PARSING                        4

#define DLT_HDR_TYPE_EXT_HEADER                         0x01
#define DLT_HDR_TYPE_MSB_FIRST                          0x02
#define DLT_HDR_TYPE_WITH_ECU_ID                        0x04
#define DLT_HDR_TYPE_WITH_SESSION_ID                    0x08
#define DLT_HDR_TYPE_WITH_TIMESTAMP                     0x10
#define DLT_HDR_TYPE_VERSION                            0xe0
#define DLT_MSG_INFO_VERBOSE                            0x01
#define DLT_MSG_INFO_MSG_TYPE                           0x0e
#define DLT_MSG_INFO_MSG_TYPE_INFO                      0xf0
#define DLT_MSG_INFO_MSG_TYPE_INFO_COMB                 0xfe

#define DLT_MSG_VERB_PARAM_LENGTH                       0x0000000f
#define DLT_MSG_VERB_PARAM_BOOL                         0x00000010
#define DLT_MSG_VERB_PARAM_SINT                         0x00000020
#define DLT_MSG_VERB_PARAM_UINT                         0x00000040
#define DLT_MSG_VERB_PARAM_FLOA                         0x00000080

#define DLT_MSG_VERB_PARAM_ARAY                         0x00000100
#define DLT_MSG_VERB_PARAM_STRG                         0x00000200
#define DLT_MSG_VERB_PARAM_RAWD                         0x00000400
#define DLT_MSG_VERB_PARAM_VARI                         0x00000800
#define DLT_MSG_VERB_PARAM_FIXP                         0x00001000
#define DLT_MSG_VERB_PARAM_TRAI                         0x00002000
#define DLT_MSG_VERB_PARAM_STRU                         0x00004000

#define DLT_MSG_VERB_PARAM_SCOD                         0x00038000
#define DLT_MSG_VERB_PARAM_SCOD_ASCII                   0x00000000
#define DLT_MSG_VERB_PARAM_SCOD_UTF8                    0x00008000
#define DLT_MSG_VERB_PARAM_SCOD_SHIFT                   15

#define DLT_MSG_VERB_PARAM_RES                          0xfffc0000

#define DLT_SERVICE_ID_SET_LOG_LEVEL                    0x01
#define DLT_SERVICE_ID_SET_TRACE_STATUS                 0x02
#define DLT_SERVICE_ID_GET_LOG_INFO                     0x03
#define DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL            0x04
#define DLT_SERVICE_ID_STORE_CONFIGURATION              0x05
#define DLT_SERVICE_ID_RESTORE_TO_FACTORY_DEFAULT       0x06
#define DLT_SERVICE_ID_SET_COM_INTERFACE_STATUS         0x07
#define DLT_SERVICE_ID_SET_COM_INTERFACE_MAX_BANDWIDTH  0x08
#define DLT_SERVICE_ID_SET_VERBOSE_MODE                 0x09
#define DLT_SERVICE_ID_SET_MESSAGE_FILTERING            0x0a
#define DLT_SERVICE_ID_SET_TIMING_PACKETS               0x0b
#define DLT_SERVICE_ID_GET_LOCAL_TIME                   0x0c
#define DLT_SERVICE_ID_USE_ECU_ID                       0x0d
#define DLT_SERVICE_ID_USE_SESSION_ID                   0x0e
#define DLT_SERVICE_ID_USE_TIMESTAMP                    0x0f
#define DLT_SERVICE_ID_USE_EXTENDED_HEADER              0x10
#define DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL            0x11
#define DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS         0x12
#define DLT_SERVICE_ID_GET_SOFTWARE_VERSION             0x13
#define DLT_SERVICE_ID_MESSAGE_BUFFER_OVERFLOW          0x14
#define DLT_SERVICE_ID_GET_DEFAULT_TRACE_STATUS         0x15
#define DLT_SERVICE_ID_GET_COM_INTERFACE_STATUS         0x16
#define DLT_SERVICE_ID_GET_LOG_CHANNEL_NAMES            0x17
#define DLT_SERVICE_ID_GET_COM_INTERFACE_MAX_BANDWIDTH  0x18
#define DLT_SERVICE_ID_GET_VERBOSE_MODE_STATUS          0x19
#define DLT_SERVICE_ID_GET_MESSAGE_FILTERING_STATUS     0x1a
#define DLT_SERVICE_ID_GET_USE_ECUID                    0x1b
#define DLT_SERVICE_ID_GET_USE_SESSION_ID               0x1c
#define DLT_SERVICE_ID_GET_USE_TIMESTAMP                0x1d
#define DLT_SERVICE_ID_GET_USE_EXTENDED_HEADER          0x1e
#define DLT_SERVICE_ID_GET_TRACE_STATUS                 0x1f
#define DLT_SERVICE_ID_SET_LOG_CHANNEL_ASSIGNMENT       0x20
#define DLT_SERVICE_ID_SET_LOG_CHANNEL_THRESHOLD        0x21
#define DLT_SERVICE_ID_GET_LOG_CHANNEL_THRESHOLD        0x22
#define DLT_SERVICE_ID_BUFFER_OVERFLOW_NOTIFICATION     0x23
/* not found in specification but in github code */
#define DLT_USER_SERVICE_ID                             0xf00
#define DLT_SERVICE_ID_UNREGISTER_CONTEXT               0xf01
#define DLT_SERVICE_ID_CONNECTION_INFO                  0xf02
#define DLT_SERVICE_ID_TIMEZONE                         0xf03
#define DLT_SERVICE_ID_MARKER                           0xf04
#define DLT_SERVICE_ID_OFFLINE_LOGSTORAGE               0xF05
#define DLT_SERVICE_ID_PASSIVE_NODE_CONNECT             0xF06
#define DLT_SERVICE_ID_PASSIVE_NODE_CONNECTION_STATUS   0xF07
#define DLT_SERVICE_ID_SET_ALL_LOG_LEVEL                0xF08
#define DLT_SERVICE_ID_SET_ALL_TRACE_STATUS             0xF09

#define DLT_SERVICE_LOG_LEVEL_DEFAULT                   -1
#define DLT_SERVICE_LOG_LEVEL_NONE                      0
#define DLT_SERVICE_LOG_LEVEL_FATAL                     1
#define DLT_SERVICE_LOG_LEVEL_ERROR                     2
#define DLT_SERVICE_LOG_LEVEL_WARN                      3
#define DLT_SERVICE_LOG_LEVEL_INFO                      4
#define DLT_SERVICE_LOG_LEVEL_DEBUG                     5
#define DLT_SERVICE_LOG_LEVEL_VERBOSE                   6

#define DLT_SERVICE_TRACE_STATUS_DEFAULT                -1
#define DLT_SERVICE_TRACE_STATUS_OFF                    0
#define DLT_SERVICE_TRACE_STATUS_ON                     1

#define DLT_SERVICE_NEW_STATUS_OFF                      0
#define DLT_SERVICE_NEW_STATUS_ON                       1

#define DLT_SERVICE_STATUS_OK                           0x00
#define DLT_SERVICE_STATUS_NOT_SUPPORTED                0x01
#define DLT_SERVICE_STATUS_ERROR                        0x02

#define DLT_SERVICE_STATUS_LOG_LEVEL_NOT_SUPPORTED      1
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_ERROR          2
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE      6
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE_TEXT 7
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_NO_MATCH_CTX   8
#define DLT_SERVICE_STATUS_LOG_LEVEL_DLT_RESP_OVERFLOW  9

#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE              6
#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE_TEXT         7

static int proto_dlt;
static int proto_dlt_storage_header;

static dissector_handle_t dlt_handle_udp = NULL;
static dissector_handle_t dlt_handle_tcp = NULL;
static dissector_handle_t dlt_handle_storage = NULL;

/* Subdissectors */
static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

/* header fields */
static int hf_dlt_header_type;
static int hf_dlt_ht_ext_header;
static int hf_dlt_ht_msb_first;
static int hf_dlt_ht_with_ecuid;
static int hf_dlt_ht_with_sessionid;
static int hf_dlt_ht_with_timestamp;
static int hf_dlt_ht_version;

static int hf_dlt_msg_ctr;
static int hf_dlt_length;

static int hf_dlt_ecu_id;
static int hf_dlt_session_id;
static int hf_dlt_timestamp;

static int hf_dlt_ext_hdr;
static int hf_dlt_msg_info;
static int hf_dlt_mi_verbose;
static int hf_dlt_mi_msg_type;
static int hf_dlt_mi_msg_type_info;
static int hf_dlt_num_of_args;
static int hf_dlt_app_id;
static int hf_dlt_ctx_id;

static int hf_dlt_payload;
static int hf_dlt_message_id;
static int hf_dlt_payload_data;

static int hf_dlt_data_bool;
static int hf_dlt_uint8;
static int hf_dlt_uint16;
static int hf_dlt_uint32;
static int hf_dlt_uint64;
static int hf_dlt_int8;
static int hf_dlt_int16;
static int hf_dlt_int32;
static int hf_dlt_int64;
static int hf_dlt_float;
static int hf_dlt_double;
static int hf_dlt_rawd;
static int hf_dlt_string;

static int hf_dlt_non_verbose_payload;
static int hf_dlt_non_verbose_message_name;
static int hf_dlt_non_verbose_argument;
static int hf_dlt_non_verbose_base;
static int hf_dlt_non_verbose_stattic;
static int hf_dlt_non_verbose_struct;
static int hf_dlt_non_verbose_array;
static int hf_dlt_non_verbose_array_string;
static int hf_dlt_non_verbose_static;
static int hf_dlt_non_verbose_array_length_field_8bit;
static int hf_dlt_non_verbose_array_length_field_16bit;
static int hf_dlt_non_verbose_array_length_field_32bit;

static int hf_dlt_service_options;
static int hf_dlt_service_application_id;
static int hf_dlt_service_context_id;
static int hf_dlt_service_log_level;
static int hf_dlt_service_new_log_level;
static int hf_dlt_service_trace_status;
static int hf_dlt_service_new_trace_status;
static int hf_dlt_service_new_status;
static int hf_dlt_service_reserved;
static int hf_dlt_service_status;
static int hf_dlt_service_length;
static int hf_dlt_service_swVersion;
static int hf_dlt_service_status_log_info;
static int hf_dlt_service_log_levels;
static int hf_dlt_service_count;
static int hf_dlt_service_app_desc;
static int hf_dlt_service_ctx_desc;

static int hf_dlt_storage_tstamp_s;
static int hf_dlt_storage_tstamp_us;
static int hf_dlt_storage_ecu_name;
static int hf_dlt_storage_reserved;

static hf_register_info* dynamic_hf_list                               = NULL;
static guint dynamic_hf_list_size                                      = 0;
static hf_register_info* dynamic_hf_array                               = NULL;
static guint dynamic_hf_array_size                                      = 0;
static hf_register_info* dynamic_hf_struct                              = NULL;
static guint dynamic_hf_struct_size                                     = 0;

/* subtrees */
static gint ett_dlt;
static gint ett_dlt_hdr_type;
static gint ett_dlt_ext_hdr;
static gint ett_dlt_msg_info;
static gint ett_dlt_payload;
static gint ett_dlt_service_app_ids;
static gint ett_dlt_service_app_id;
static gint ett_dlt_service_ctx_id;
static gint ett_dlt_non_verbose_payload;
static gint ett_dlt_non_verbose_struct;
static gint ett_dlt_non_verbose_array;
static gint ett_dlt_non_verbose_array_dim;

static gint ett_dlt_storage;

/***************************
 ****** String Tables ******
 ***************************/

/* DLT Message Types */
static const value_string dlt_msg_type[] = {
    {DLT_MSG_TYPE_LOG_MSG,                              "DLT Log Message"},
    {DLT_MSG_TYPE_TRACE_MSG,                            "DLT Trace Message"},
    {DLT_MSG_TYPE_NETWORK_MSG,                          "DLT Network Message"},
    {DLT_MSG_TYPE_CTRL_MSG,                             "DLT Control Message"},
    {0, NULL}
};

/* DLT Message Types Infos - this is not context free and uses bits of dlt_msg_type too! */
static const value_string dlt_msg_type_info[] = {
    {DLT_MSG_TYPE_INFO_LOG_FATAL,                       "Fatal"},
    {DLT_MSG_TYPE_INFO_LOG_ERROR,                       "Error"},
    {DLT_MSG_TYPE_INFO_LOG_WARN,                        "Warn"},
    {DLT_MSG_TYPE_INFO_LOG_INFO,                        "Info"},
    {DLT_MSG_TYPE_INFO_LOG_DEBUG,                       "Debug"},
    {DLT_MSG_TYPE_INFO_LOG_VERBOSE,                     "Verbose"},
    {DLT_MSG_TYPE_INFO_TRACE_VAR,                       "Variable"},
    {DLT_MSG_TYPE_INFO_TRACE_FUNC_IN,                   "Function In"},
    {DLT_MSG_TYPE_INFO_TRACE_FUNC_OUT,                  "Function Out"},
    {DLT_MSG_TYPE_INFO_TRACE_STATE,                     "State"},
    {DLT_MSG_TYPE_INFO_TRACE_VFB,                       "VFB"},
    {DLT_MSG_TYPE_INFO_NET_IPC,                         "IPC"},
    {DLT_MSG_TYPE_INFO_NET_CAN,                         "CAN"},
    {DLT_MSG_TYPE_INFO_NET_FLEXRAY,                     "FlexRay"},
    {DLT_MSG_TYPE_INFO_NET_MOST,                        "MOST"},
    {DLT_MSG_TYPE_INFO_CTRL_REQ,                        "Request"},
    {DLT_MSG_TYPE_INFO_CTRL_RES,                        "Response"},
    {DLT_MSG_TYPE_INFO_CTRL_TIME,                       "Time"},
    {0, NULL}
};

static const value_string dlt_service[] = {
    {DLT_SERVICE_ID_SET_LOG_LEVEL,                      "Set Log Level"},
    {DLT_SERVICE_ID_SET_TRACE_STATUS,                   "Set Trace Status"},
    {DLT_SERVICE_ID_GET_LOG_INFO,                       "Get Log Info"},
    {DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL,              "Get Default Log Level"},
    {DLT_SERVICE_ID_STORE_CONFIGURATION,                "Store Configuration"},
    {DLT_SERVICE_ID_RESTORE_TO_FACTORY_DEFAULT,         "Restore Factory Default"},
    {DLT_SERVICE_ID_SET_COM_INTERFACE_STATUS,           "Set Com Interface Status (Deprecated!)"},
    {DLT_SERVICE_ID_SET_COM_INTERFACE_MAX_BANDWIDTH,    "Set Com Interface Max Bandwidth (Deprecated!)"},
    {DLT_SERVICE_ID_SET_VERBOSE_MODE,                   "Set Verbose Mode (Deprecated!)"},
    {DLT_SERVICE_ID_SET_MESSAGE_FILTERING,              "Set Message Filtering"},
    {DLT_SERVICE_ID_SET_TIMING_PACKETS,                 "Set Timing Packets (Deprecated!)"},
    {DLT_SERVICE_ID_GET_LOCAL_TIME,                     "Get Local Time (Deprecated!)"},
    {DLT_SERVICE_ID_USE_ECU_ID,                         "Use ECU ID (Deprecated!)"},
    {DLT_SERVICE_ID_USE_SESSION_ID,                     "Use Session ID (Deprecated!)"},
    {DLT_SERVICE_ID_USE_TIMESTAMP,                      "Use Timestamp (Deprecated!)"},
    {DLT_SERVICE_ID_USE_EXTENDED_HEADER,                "Use Extended Header (Deprecated!)"},
    {DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL,              "Set Default Log Level"},
    {DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS,           "Set Default Trace Status"},
    {DLT_SERVICE_ID_GET_SOFTWARE_VERSION,               "Get Software Version"},
    {DLT_SERVICE_ID_MESSAGE_BUFFER_OVERFLOW,            "Message Buffer Overflow (Deprecated!)"},
    {DLT_SERVICE_ID_GET_DEFAULT_TRACE_STATUS,           "Get Default trace Status"},
    {DLT_SERVICE_ID_GET_COM_INTERFACE_STATUS,           "Get Com Interface Status (Deprecated!)"},
    {DLT_SERVICE_ID_GET_LOG_CHANNEL_NAMES,              "Get Log Channel Names"},
    {DLT_SERVICE_ID_GET_COM_INTERFACE_MAX_BANDWIDTH,    "Get Com Interface Max Bandwidth (Deprecated!)"},
    {DLT_SERVICE_ID_GET_VERBOSE_MODE_STATUS,            "Get Verbose Mode Status (Deprecated!)"},
    {DLT_SERVICE_ID_GET_MESSAGE_FILTERING_STATUS,       "Get Message Filtering Status (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_ECUID,                      "Get Use ECUID (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_SESSION_ID,                 "Get Use Session ID (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_TIMESTAMP,                  "Get Use Timestamp (Deprecated!)"},
    {DLT_SERVICE_ID_GET_USE_EXTENDED_HEADER,            "Get Use Extended Header (Deprecated!)"},
    {DLT_SERVICE_ID_GET_TRACE_STATUS,                   "Get Trace Status"},
    {DLT_SERVICE_ID_SET_LOG_CHANNEL_ASSIGNMENT,         "Set Log Channel Assignment"},
    {DLT_SERVICE_ID_SET_LOG_CHANNEL_THRESHOLD,          "Set Log Channel Threshold"},
    {DLT_SERVICE_ID_GET_LOG_CHANNEL_THRESHOLD,          "Get log Channel Threshold"},
    {DLT_SERVICE_ID_BUFFER_OVERFLOW_NOTIFICATION,       "Buffer Overflow Notification"},
    {DLT_USER_SERVICE_ID,                               "User Service"},
    {DLT_SERVICE_ID_UNREGISTER_CONTEXT,                 "Unregister Context (undefined)"},
    {DLT_SERVICE_ID_CONNECTION_INFO,                    "Connection Info (undefined)"},
    {DLT_SERVICE_ID_TIMEZONE,                           "Timezone (undefined)"},
    {DLT_SERVICE_ID_MARKER,                             "Marker (undefined)"},
    {DLT_SERVICE_ID_OFFLINE_LOGSTORAGE,                 "Offline Log Storage (undefined)"},
    {DLT_SERVICE_ID_PASSIVE_NODE_CONNECT,               "Passive Mode Connect (undefined)"},
    {DLT_SERVICE_ID_PASSIVE_NODE_CONNECTION_STATUS,     "Passive Mode Connection Status (undefined)"},
    {DLT_SERVICE_ID_SET_ALL_LOG_LEVEL,                  "Set All Log Level (undefined)"},
    {DLT_SERVICE_ID_SET_ALL_TRACE_STATUS,               "Set All Trace Status (undefined)"},
    {0, NULL}
};

static const value_string dlt_service_log_level[] = {
    {DLT_SERVICE_LOG_LEVEL_DEFAULT,                     "Default Log Level"},
    {DLT_SERVICE_LOG_LEVEL_NONE,                        "No Messages"},
    {DLT_SERVICE_LOG_LEVEL_FATAL,                       "Fatal"},
    {DLT_SERVICE_LOG_LEVEL_ERROR,                       "Error"},
    {DLT_SERVICE_LOG_LEVEL_WARN,                        "Warn"},
    {DLT_SERVICE_LOG_LEVEL_INFO,                        "Info"},
    {DLT_SERVICE_LOG_LEVEL_DEBUG,                       "Debug"},
    {DLT_SERVICE_LOG_LEVEL_VERBOSE,                     "Verbose"},
    {0, NULL}
};

static const value_string dlt_service_trace_status[] = {
    {DLT_SERVICE_TRACE_STATUS_DEFAULT,                  "Default Trace Status"},
    {DLT_SERVICE_TRACE_STATUS_OFF,                      "Off"},
    {DLT_SERVICE_TRACE_STATUS_ON,                       "On"},
    {0, NULL}
};

static const value_string dlt_service_new_status[] = {
    {DLT_SERVICE_NEW_STATUS_OFF,                        "Off"},
    {DLT_SERVICE_NEW_STATUS_ON,                         "On"},
    {0, NULL}
};

static const value_string dlt_service_status[] = {
    {DLT_SERVICE_STATUS_OK,                             "OK"},
    {DLT_SERVICE_STATUS_NOT_SUPPORTED,                  "Not supported"},
    {DLT_SERVICE_STATUS_ERROR,                          "Error"},
    {0, NULL}
};

static const value_string dlt_service_options[] = {
    {DLT_SERVICE_OPTIONS_WITH_LOG_TRACE,                "Loglevel and Trace status"},
    {DLT_SERVICE_OPTIONS_WITH_LOG_TRACE_TEXT,           "Loglevel, Trace status, and Textual"},
    {0, NULL}
};

#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE              6
#define DLT_SERVICE_OPTIONS_WITH_LOG_TRACE_TEXT         7

/* User Configuration for dissecting non verbose dlt message payload  */
#define DATAFILE_DLT_MESSAGES  "DLT_messages"
#define DATAFILE_DLT_STRUCTS   "DLT_structs"
#define DATAFILE_DLT_ARRAYS    "DLT_arrays"
#define DATAFILE_DLT_BASETYPES "DLT_basetypes"
#define DATAFILE_DLT_STATICS   "DLT_statics"

static GHashTable *data_dlt_argument_list      = NULL;
static GHashTable *data_dlt_argument_basetypes = NULL;
static GHashTable *data_dlt_argument_arrays    = NULL;
static GHashTable *data_dlt_argument_structs   = NULL;
static GHashTable *data_dlt_argument_statics   = NULL;

#define DLT_NONE_TYPE_ID     0x0
#define DLT_BASETYPE_TYPE_ID 0x1
#define DLT_STRUCT_TYPE_ID   0x2
#define DLT_ARRAY_TYPE_ID    0x3
#define DLT_STATIC_TYPE_ID   0x4

/* User config helper macros */
#define COPY_UAT_CSTRING(old_rec, new_rec, name)  \
    do {\
        if (old_rec->name) { \
            new_rec->name = g_strdup(old_rec->name); \
        } else { \
            new_rec->name = NULL; \
        } \
    } while(0)

#define CHECK_UAT_CSTRING_NOT_EMPTY(field, fieldname)  \
    do {\
        if (field == NULL || field[0] == 0) {\
            *err = ws_strdup_printf(fieldname " cannot be empty");\
            return FALSE;\
        }\
    } while(0)
#define CHECK_UAT_DATATYPE_ID(field, identifier)  \
    do {\
        if (field > 0x0fffffffu) {\
            *err = ws_strdup_printf("DataTypes must not have the upper 4 bits set. Incorrect at at %s. value is %08x",  identifier, field);\
            return FALSE;\
        }\
    } while(0)
#define CHECK_UAT_DATATYPE(type_field, id_field, identifier)  \
    do {\
        if (make_data_type_ref(type_field, id_field) == 0) {\
            *err = ws_strdup_printf("DataTypes has an unrecognized value %s for %s", type_field, identifier);\
            return FALSE;\
        }\
        if (id_field > 0x0fffffffu) {\
            *err = ws_strdup_printf("DataTypes must not have the upper 4 bits set. Incorrect at at %s. value is %08x",  identifier, id_field);\
            return FALSE;\
        }\
    } while(0)
#define DLT_MAKE_ID(type, id) ((type & 0xF) << 28U) | (id & 0x0FFFFFFFU)
#define DLT_GET_TYPE(id) ((id & 0xF0000000U) >> 28U)

typedef struct _dlt_non_verbose_argument {
    gchar       *name;
    gint        *hf_id;
    guint32     data_type_ref;
} dlt_non_verbose_argument_t;

typedef struct _dlt_non_verbose_argument_list {
    gchar       *ecu_id;
    guint32     messageid;
    gchar       *name;
    gchar       *application_id;
    gchar       *context_id;
    guint32     num_of_items;
    dlt_non_verbose_argument_t *items;
} dlt_non_verbose_argument_list_t;

typedef struct _dlt_non_verbose_argument_list_uat {
    gchar       *ecu_id;
    guint32     messageid;
    gchar       *message_name;
    gchar       *application_id;
    gchar       *context_id;
    guint32     num_of_items;
    guint32     pos;
    gchar       *name;
    gchar       *data_type;
    guint32     data_type_ref;
} dlt_non_verbose_argument_list_uat_t;

typedef struct _dlt_non_verbose_argument_struct {
    guint32     id;
    gchar       *name;
    guint32     num_of_items;
    dlt_non_verbose_argument_t *items;
} dlt_non_verbose_argument_struct_t;

typedef struct _dlt_non_verbose_argument_struct_uat {
    guint32     id;
    gchar       *struct_name;
    guint32     num_of_items;
    guint32     pos;
    gchar       *name;
    gchar       *data_type;
    guint32     data_type_ref;
} dlt_non_verbose_argument_struct_uat_t;

typedef struct _dlt_non_verbose_argument_array_dimension {
    gchar       *name;
    gint        *hf_id;
    guint8      length;
} dlt_non_verbose_argument_array_dimension_t;

typedef struct _dlt_non_verbose_argument_array {
    guint32     id;
    gchar       *name;
    guint32     data_type_ref;
    guint32     length;
    gboolean    isstring;
    guint32     encoding;
    gboolean    dynamic_length;
    guint8      length_size;
    gboolean    ndim;
    dlt_non_verbose_argument_array_dimension_t *array_dimensions;
} dlt_non_verbose_argument_array_t;

typedef struct _dlt_non_verbose_argument_array_uat {
    guint32     id;
    gchar       *name;
    gchar       *data_type;
    guint32     data_type_ref;
    guint32     length;
    gboolean    isstring;
    gchar       *encoding;
    gboolean    dynamic_length;
    guint32     length_size;
    gboolean    ndim;
    guint32     dimension_size;
    guint32     dimension_pos;
    gchar       *dimension_name;
} dlt_non_verbose_argument_array_uat_t;

typedef struct _dlt_non_verbose_argument_static {
    guint32     id;
    gchar       *name;
} dlt_non_verbose_argument_static_t;

typedef struct _dlt_non_verbose_argument_basetype {
    guint32     id;
    gchar       *name;
    guint8      bitsize;
    gboolean    issigned;
    gboolean    isfloat;
} dlt_non_verbose_argument_basetype_t;

typedef struct _dlt_non_verbose_argument_basetype_uat {
    guint32     id;
    gchar       *name;
    guint32     bitsize;
    gboolean    issigned;
    gboolean    isfloat;
} dlt_non_verbose_argument_basetype_uat_t;

typedef dlt_non_verbose_argument_static_t dlt_non_verbose_argument_static_uat_t;

static dlt_non_verbose_argument_basetype_uat_t * dlt_non_verbose_argument_basetypes = NULL;
static guint dlt_non_verbose_argument_basetypes_num = 0;

static dlt_non_verbose_argument_static_uat_t *dlt_non_verbose_argument_statics = NULL;
static guint dlt_non_verbose_argument_statics_num = 0;

static dlt_non_verbose_argument_struct_uat_t *dlt_non_verbose_argument_structs = NULL;
static guint dlt_non_verbose_argument_structs_num = 0;

static dlt_non_verbose_argument_array_uat_t *dlt_non_verbose_argument_arrays = NULL;
static guint dlt_non_verbose_argument_arrays_num = 0;

static dlt_non_verbose_argument_list_uat_t *dlt_non_verbose_argument_lists = NULL;
static guint dlt_non_verbose_argument_lists_num = 0;

static void update_dynamic_hf_entries_dlt_argument_list(void);
static void update_dynamic_hf_entries_dlt_argument_arrays(void);
static void update_dynamic_hf_entries_dlt_argument_structs(void);

/*** DLT Messages ***/
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_lists,     ecu_id,         dlt_non_verbose_argument_list_uat_t)
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_lists,     messageid,      dlt_non_verbose_argument_list_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_lists,     message_name,   dlt_non_verbose_argument_list_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_lists,     application_id, dlt_non_verbose_argument_list_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_lists,     context_id,     dlt_non_verbose_argument_list_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_lists,     num_of_items,   dlt_non_verbose_argument_list_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_lists,     pos,            dlt_non_verbose_argument_list_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_lists,     name,           dlt_non_verbose_argument_list_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_lists,     data_type,      dlt_non_verbose_argument_list_uat_t)
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_lists,     data_type_ref,  dlt_non_verbose_argument_list_uat_t)
/*** DLT Structs ***/
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_structs,   id,             dlt_non_verbose_argument_struct_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_structs,   struct_name,    dlt_non_verbose_argument_struct_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_structs,   num_of_items,   dlt_non_verbose_argument_struct_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_structs,   pos,            dlt_non_verbose_argument_struct_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_structs,   name,           dlt_non_verbose_argument_struct_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_structs,   data_type,      dlt_non_verbose_argument_struct_uat_t)
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_structs,   data_type_ref,  dlt_non_verbose_argument_struct_uat_t)
/*** DLT Array ***/
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_arrays,    id,             dlt_non_verbose_argument_array_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_arrays,    name,           dlt_non_verbose_argument_array_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_arrays,    data_type,      dlt_non_verbose_argument_array_uat_t)
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_arrays,    data_type_ref,  dlt_non_verbose_argument_array_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_arrays,    length,         dlt_non_verbose_argument_array_uat_t)
UAT_BOOL_CB_DEF       (dlt_non_verbose_argument_arrays,    isstring,       dlt_non_verbose_argument_array_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_arrays,    encoding,       dlt_non_verbose_argument_array_uat_t)
UAT_BOOL_CB_DEF       (dlt_non_verbose_argument_arrays,    dynamic_length, dlt_non_verbose_argument_array_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_arrays,    length_size,    dlt_non_verbose_argument_array_uat_t)
UAT_BOOL_CB_DEF       (dlt_non_verbose_argument_arrays,    ndim,           dlt_non_verbose_argument_array_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_arrays,    dimension_size, dlt_non_verbose_argument_array_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_arrays,    dimension_pos,  dlt_non_verbose_argument_array_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_arrays,    dimension_name, dlt_non_verbose_argument_array_uat_t)
/*** DLT Static ***/
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_statics,   id,             dlt_non_verbose_argument_static_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_statics,   name,           dlt_non_verbose_argument_static_uat_t)
/*** DLT Basetype ***/
UAT_HEX_CB_DEF        (dlt_non_verbose_argument_basetypes, id,             dlt_non_verbose_argument_basetype_uat_t)
UAT_CSTRING_CB_DEF    (dlt_non_verbose_argument_basetypes, name,           dlt_non_verbose_argument_basetype_uat_t)
UAT_DEC_CB_DEF        (dlt_non_verbose_argument_basetypes, bitsize,        dlt_non_verbose_argument_basetype_uat_t)
UAT_BOOL_CB_DEF       (dlt_non_verbose_argument_basetypes, issigned,       dlt_non_verbose_argument_basetype_uat_t)
UAT_BOOL_CB_DEF       (dlt_non_verbose_argument_basetypes, isfloat,        dlt_non_verbose_argument_basetype_uat_t)

static guint32 make_data_type_ref(const gchar* data_type, guint32 data_type_ref){
    guint typeid = DLT_NONE_TYPE_ID;
    if(g_strcmp0(data_type, "base") == 0){
        typeid = DLT_BASETYPE_TYPE_ID;
    }else if(g_strcmp0(data_type, "struct") == 0){
        typeid = DLT_STRUCT_TYPE_ID;
    }else if(g_strcmp0(data_type, "array") == 0){
        typeid = DLT_ARRAY_TYPE_ID;
    }else if(g_strcmp0(data_type, "static") == 0){
        typeid = DLT_STATIC_TYPE_ID;
    }else{
        return 0;
    }
    return DLT_MAKE_ID(typeid, data_type_ref);
}

static void
dlt_free_key(gpointer key) {
    wmem_free(wmem_epan_scope(), key);
}

/* Argument Elements */
static void *
copy_dlt_argument_list_cb(void *n, const void *o, size_t size _U_) {
    dlt_non_verbose_argument_list_uat_t        *new_rec = (dlt_non_verbose_argument_list_uat_t *)n;
    const dlt_non_verbose_argument_list_uat_t  *old_rec = (const dlt_non_verbose_argument_list_uat_t *)o;

    COPY_UAT_CSTRING(old_rec, new_rec, ecu_id);
    COPY_UAT_CSTRING(old_rec, new_rec, message_name);
    COPY_UAT_CSTRING(old_rec, new_rec, application_id);
    COPY_UAT_CSTRING(old_rec, new_rec, context_id);
    COPY_UAT_CSTRING(old_rec, new_rec, name);
    COPY_UAT_CSTRING(old_rec, new_rec, data_type);

    new_rec->messageid     = old_rec->messageid;
    new_rec->num_of_items  = old_rec->num_of_items;
    new_rec->pos           = old_rec->pos;
    new_rec->data_type_ref = old_rec->data_type_ref;

    return new_rec;
}

static bool
update_dlt_argument_list_cb(void *r, char **err) {
    dlt_non_verbose_argument_list_uat_t *rec = (dlt_non_verbose_argument_list_uat_t *)r;

    CHECK_UAT_CSTRING_NOT_EMPTY(rec->ecu_id, "Ecu Id");
    CHECK_UAT_CSTRING_NOT_EMPTY(rec->name, "Name");

    if (rec->num_of_items > 0 && rec->pos >= rec->num_of_items) {
        *err = ws_strdup_printf("Position >= Number of Arguments");
        return FALSE;
    }

    return TRUE;
}

static void
free_dlt_argument_list_cb(void *r) {
    dlt_non_verbose_argument_list_uat_t *rec = (dlt_non_verbose_argument_list_uat_t *)r;

    if (rec->message_name) {
        g_free(rec->message_name);
        rec->message_name = NULL;
    }

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }

    if (rec->ecu_id) {
        g_free(rec->ecu_id);
        rec->ecu_id = NULL;
    }

    if (rec->application_id) {
        g_free(rec->application_id);
        rec->application_id = NULL;
    }

    if (rec->context_id) {
        g_free(rec->context_id);
        rec->context_id = NULL;
    }
}

static void
reset_dlt_argument_list_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_dlt_argument_list) {
        g_hash_table_destroy(data_dlt_argument_list);
        data_dlt_argument_list = NULL;
    }
}

static void
free_dlt_non_verbose_argument_list(gpointer data) {
    dlt_non_verbose_argument_list_t *list = (dlt_non_verbose_argument_list_t *)data;

    if (list->items != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->items));
        list->items = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_dlt_argument_list_cb(void) {
    guint i=0;
    gint64         *key = NULL;
    dlt_non_verbose_argument_list_t       *list = NULL;
    dlt_non_verbose_argument_t *item = NULL;
    reset_dlt_argument_list_cb();

    /* create new hash table */
    data_dlt_argument_list = g_hash_table_new_full(g_int64_hash, g_int64_equal, &dlt_free_key, &free_dlt_non_verbose_argument_list);
    if (data_dlt_argument_list == NULL || dlt_non_verbose_argument_lists == NULL || dlt_non_verbose_argument_lists_num == 0) {
        return;
    }

    for (i = 0; i < dlt_non_verbose_argument_lists_num; i++) {
        key = wmem_new(wmem_epan_scope(), gint64);
        *key = ((gint64)dlt_ecu_id_to_gint32(dlt_non_verbose_argument_lists[i].ecu_id)) << 32 | dlt_non_verbose_argument_lists[i].messageid;

        list = (dlt_non_verbose_argument_list_t *)g_hash_table_lookup(data_dlt_argument_list, key);
        if (list == NULL) {
            /* create new entry */
            list = wmem_new(wmem_epan_scope(), dlt_non_verbose_argument_list_t);

            list->ecu_id         = dlt_non_verbose_argument_lists[i].ecu_id;
            list->messageid      = dlt_non_verbose_argument_lists[i].messageid;
            list->name           = dlt_non_verbose_argument_lists[i].message_name;
            list->application_id = dlt_non_verbose_argument_lists[i].application_id;
            list->context_id     = dlt_non_verbose_argument_lists[i].context_id;
            list->num_of_items   = dlt_non_verbose_argument_lists[i].num_of_items;

            list->items = (dlt_non_verbose_argument_t *)wmem_alloc0_array(wmem_epan_scope(), dlt_non_verbose_argument_t, list->num_of_items);

            /* create new entry ... */
            g_hash_table_insert(data_dlt_argument_list, key, list);
        } else {
            /* don't need the key anymore, as the initial entry already exists and will be reused */
            wmem_free(wmem_epan_scope(), key);
        }

        if (dlt_non_verbose_argument_lists[i].num_of_items == list->num_of_items && dlt_non_verbose_argument_lists[i].pos < list->num_of_items) {
            item = &(list->items[dlt_non_verbose_argument_lists[i].pos]);

            /* we do not care if we overwrite param */
            item->hf_id         = NULL;
            item->name          = dlt_non_verbose_argument_lists[i].name;
            item->data_type_ref = make_data_type_ref(dlt_non_verbose_argument_lists[i].data_type, dlt_non_verbose_argument_lists[i].data_type_ref);
        }
    }
    update_dynamic_hf_entries_dlt_argument_list();
}




/* Struct Elements */
static void *
copy_dlt_argument_struct_cb(void *n, const void *o, size_t size _U_) {
    dlt_non_verbose_argument_struct_uat_t        *new_rec = (dlt_non_verbose_argument_struct_uat_t *)n;
    const dlt_non_verbose_argument_struct_uat_t  *old_rec = (const dlt_non_verbose_argument_struct_uat_t *)o;

    COPY_UAT_CSTRING(old_rec, new_rec, struct_name);
    COPY_UAT_CSTRING(old_rec, new_rec, name);
    COPY_UAT_CSTRING(old_rec, new_rec, data_type);

    new_rec->id            = old_rec->id;
    new_rec->num_of_items  = old_rec->num_of_items;
    new_rec->pos           = old_rec->pos;
    new_rec->data_type_ref = old_rec->data_type_ref;

    return new_rec;
}

static bool
update_dlt_argument_struct_cb(void *r, char **err) {
    dlt_non_verbose_argument_struct_uat_t *rec = (dlt_non_verbose_argument_struct_uat_t *)r;

    CHECK_UAT_DATATYPE_ID(rec->id, rec->name);
    CHECK_UAT_CSTRING_NOT_EMPTY(rec->struct_name, "Struct Name");
    CHECK_UAT_DATATYPE(rec->data_type, rec->data_type_ref, rec->name);
    CHECK_UAT_CSTRING_NOT_EMPTY(rec->name, "Name");

    if (rec->pos >= rec->num_of_items) {
        *err = ws_strdup_printf("Position >= Number of Arguments");
        return FALSE;
    }

    return TRUE;
}

static void
free_dlt_argument_struct_cb(void *r) {
    dlt_non_verbose_argument_struct_uat_t *rec = (dlt_non_verbose_argument_struct_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }

    if (rec->struct_name) {
        g_free(rec->struct_name);
        rec->struct_name = NULL;
    }
}

static void
reset_dlt_argument_struct_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_dlt_argument_structs) {
        g_hash_table_destroy(data_dlt_argument_structs);
        data_dlt_argument_structs = NULL;
    }
}


static void
free_dlt_non_verbose_argument_struct(gpointer data) {
    dlt_non_verbose_argument_struct_t *list = (dlt_non_verbose_argument_struct_t *)data;

    if (list->items != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->items));
        list->items = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_dlt_argument_struct_cb(void) {
    guint i=0;
    gint64         *key = NULL;
    dlt_non_verbose_argument_struct_t       *list = NULL;
    dlt_non_verbose_argument_t *item = NULL;
    reset_dlt_argument_struct_cb();

    /* create new hash table */
    data_dlt_argument_structs = g_hash_table_new_full(g_int_hash, g_int_equal, &dlt_free_key, &free_dlt_non_verbose_argument_struct);
    if (data_dlt_argument_structs == NULL || dlt_non_verbose_argument_structs == NULL || dlt_non_verbose_argument_structs_num == 0) {
        return;
    }

    for (i = 0; i < dlt_non_verbose_argument_structs_num; i++) {
        key = wmem_new(wmem_epan_scope(), gint64);
        *key = DLT_MAKE_ID(DLT_STRUCT_TYPE_ID, dlt_non_verbose_argument_structs[i].id);

        list = (dlt_non_verbose_argument_struct_t *)g_hash_table_lookup(data_dlt_argument_structs, key);
        if (list == NULL) {
            /* create new entry */
            list = wmem_new(wmem_epan_scope(), dlt_non_verbose_argument_struct_t);

            list->id           = dlt_non_verbose_argument_structs[i].id;
            list->name         = dlt_non_verbose_argument_structs[i].struct_name;
            list->num_of_items = dlt_non_verbose_argument_structs[i].num_of_items;

            list->items = (dlt_non_verbose_argument_t *)wmem_alloc0_array(wmem_epan_scope(), dlt_non_verbose_argument_t, list->num_of_items);

            /* create new entry ... */
            g_hash_table_insert(data_dlt_argument_structs, key, list);
        } else {
            /* don't need the key anymore, as the initial entry already exists and will be reused */
            wmem_free(wmem_epan_scope(), key);
        }

        if (dlt_non_verbose_argument_structs[i].num_of_items == list->num_of_items && dlt_non_verbose_argument_structs[i].pos < list->num_of_items) {
            item = &(list->items[dlt_non_verbose_argument_structs[i].pos]);

            /* we do not care if we overwrite param */
            item->hf_id         = NULL;
            item->name          = dlt_non_verbose_argument_structs[i].name;
            item->data_type_ref = make_data_type_ref(dlt_non_verbose_argument_structs[i].data_type, dlt_non_verbose_argument_structs[i].data_type_ref);
        }
    }
    update_dynamic_hf_entries_dlt_argument_structs();
}



/* Array Elements */
static void *
copy_dlt_argument_array_cb(void *n, const void *o, size_t size _U_) {
    dlt_non_verbose_argument_array_uat_t        *new_rec = (dlt_non_verbose_argument_array_uat_t *)n;
    const dlt_non_verbose_argument_array_uat_t  *old_rec = (const dlt_non_verbose_argument_array_uat_t *)o;

    COPY_UAT_CSTRING(old_rec, new_rec, name);
    COPY_UAT_CSTRING(old_rec, new_rec, encoding);
    COPY_UAT_CSTRING(old_rec, new_rec, dimension_name);
    COPY_UAT_CSTRING(old_rec, new_rec, data_type);

    new_rec->id             = old_rec->id;
    new_rec->data_type_ref  = old_rec->data_type_ref;
    new_rec->length         = old_rec->length;
    new_rec->isstring       = old_rec->isstring;
    new_rec->dynamic_length = old_rec->dynamic_length;
    new_rec->length_size    = old_rec->length_size;
    new_rec->ndim           = old_rec->ndim;
    new_rec->dimension_pos  = old_rec->dimension_pos;
    new_rec->dimension_size = old_rec->dimension_size;

    return new_rec;
}

static bool
update_dlt_argument_array_cb(void *r, char **err) {
    dlt_non_verbose_argument_array_uat_t *rec = (dlt_non_verbose_argument_array_uat_t *)r;

    CHECK_UAT_DATATYPE_ID(rec->id, rec->name);
    CHECK_UAT_DATATYPE(rec->data_type, rec->data_type_ref, rec->name);
    CHECK_UAT_CSTRING_NOT_EMPTY(rec->name, "Name");

    if (rec->dynamic_length && rec->ndim) {
        *err = ws_strdup_printf("Array cannot be multidimensional and variable length");
        return FALSE;
    }

    if (rec->dimension_pos >= rec->length) {
        *err = ws_strdup_printf("Position >= Number of Arguments");
        return FALSE;
    }

    if(rec->isstring){
        if ((g_strcmp0(rec->encoding, "utf8") == 0) || (g_strcmp0(rec->encoding, "utf16") == 0) || (g_strcmp0(rec->encoding, "ascii") == 0)) {
            *err = ws_strdup_printf("Encoding must be utf8, utf16 or ascii");
            return FALSE;
        }
    }


    return TRUE;
}

static void
free_dlt_argument_array_cb(void *r) {
    dlt_non_verbose_argument_array_uat_t *rec = (dlt_non_verbose_argument_array_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }
}

static void
reset_dlt_argument_array_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_dlt_argument_arrays) {
        g_hash_table_destroy(data_dlt_argument_arrays);
        data_dlt_argument_arrays = NULL;
    }
}

static void
free_dlt_non_verbose_argument_array(gpointer data) {
    dlt_non_verbose_argument_array_t *list = (dlt_non_verbose_argument_array_t *)data;

    if (list->array_dimensions != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->array_dimensions));
        list->array_dimensions = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_dlt_argument_array_cb(void) {
    guint i=0;
    gint64         *key = NULL;
    dlt_non_verbose_argument_array_t       *array = NULL;
    dlt_non_verbose_argument_array_dimension_t *item = NULL;
    reset_dlt_argument_array_cb();

    /* create new hash table */
    data_dlt_argument_arrays = g_hash_table_new_full(g_int_hash, g_int_equal, &dlt_free_key, &free_dlt_non_verbose_argument_array);

    if (data_dlt_argument_arrays == NULL || dlt_non_verbose_argument_arrays == NULL || dlt_non_verbose_argument_arrays_num == 0) {
        return;
    }

    for (i = 0; i < dlt_non_verbose_argument_arrays_num; i++) {
        key = wmem_new(wmem_epan_scope(), gint64);
        *key = DLT_MAKE_ID(DLT_ARRAY_TYPE_ID, dlt_non_verbose_argument_arrays[i].id);

        array = (dlt_non_verbose_argument_array_t *)g_hash_table_lookup(data_dlt_argument_arrays, key);
        if (array == NULL) {
            /* create new entry */
            array = wmem_new(wmem_epan_scope(), dlt_non_verbose_argument_array_t);

            array->id             = dlt_non_verbose_argument_arrays[i].id;
            array->name           = dlt_non_verbose_argument_arrays[i].name;
            array->data_type_ref  = make_data_type_ref(dlt_non_verbose_argument_arrays[i].data_type, dlt_non_verbose_argument_arrays[i].data_type_ref);
            array->length         = dlt_non_verbose_argument_arrays[i].length;
            array->isstring       = dlt_non_verbose_argument_arrays[i].isstring;
            array->dynamic_length = dlt_non_verbose_argument_arrays[i].dynamic_length;
            array->length_size    = dlt_non_verbose_argument_arrays[i].length_size;
            array->ndim           = dlt_non_verbose_argument_arrays[i].ndim;

            if(array->ndim){
                array->array_dimensions = (dlt_non_verbose_argument_array_dimension_t *)wmem_alloc0_array(wmem_epan_scope(), dlt_non_verbose_argument_array_dimension_t, array->length);
            }else{
                array->array_dimensions = NULL;
            }
            if (array->isstring){
                if (g_strcmp0(dlt_non_verbose_argument_arrays[i].encoding, "ascii") == 0){
                    array->encoding = ENC_ASCII;
                } else if (g_strcmp0(dlt_non_verbose_argument_arrays[i].encoding, "utf16") == 0){
                    array->encoding = ENC_UTF_16;
                }else {
                    array->encoding = ENC_UTF_8;
                }
            }else{
                    array->encoding = 0;
            }

            /* create new entry ... */
            g_hash_table_insert(data_dlt_argument_arrays, key, array);
        } else {
            /* don't need the key anymore, as the initial entry already exists and will be reused */
            wmem_free(wmem_epan_scope(), key);
        }

        if(array->ndim){
            if (dlt_non_verbose_argument_arrays[i].length == array->length && dlt_non_verbose_argument_arrays[i].dimension_pos < array->length) {
                item = &(array->array_dimensions[dlt_non_verbose_argument_arrays[i].dimension_pos]);

                /* we do not care if we overwrite param */
                item->name   = dlt_non_verbose_argument_arrays[i].dimension_name;
                item->length = dlt_non_verbose_argument_arrays[i].length_size;
                item->hf_id  = NULL;
            }
        }
    }
    update_dynamic_hf_entries_dlt_argument_arrays();
}


/* Static Elements */
static void *
copy_dlt_argument_static_cb(void *n, const void *o, size_t size _U_) {
    dlt_non_verbose_argument_static_uat_t        *new_rec = (dlt_non_verbose_argument_static_uat_t *)n;
    const dlt_non_verbose_argument_static_uat_t  *old_rec = (const dlt_non_verbose_argument_static_uat_t *)o;

    COPY_UAT_CSTRING(old_rec, new_rec, name);
    new_rec->id    = old_rec->id;

    return new_rec;
}

static bool
update_dlt_argument_static_cb(void *r, char **err) {
    dlt_non_verbose_argument_static_uat_t *rec = (dlt_non_verbose_argument_static_uat_t *)r;
    CHECK_UAT_DATATYPE_ID(rec->id, rec->name);

    CHECK_UAT_CSTRING_NOT_EMPTY(rec->name, "Name");
    return TRUE;
}

static void
free_dlt_argument_static_cb(void *r) {
    dlt_non_verbose_argument_static_uat_t *rec = (dlt_non_verbose_argument_static_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }
}

static void
reset_dlt_argument_static_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_dlt_argument_statics) {
        g_hash_table_destroy(data_dlt_argument_statics);
        data_dlt_argument_statics = NULL;
    }
}

static void
post_update_dlt_argument_static_cb(void) {
    gint64 *key = NULL;
    guint i =0;
    reset_dlt_argument_static_cb();

    /* create new hash table */
    data_dlt_argument_statics = g_hash_table_new_full(g_int_hash, g_int_equal, &dlt_free_key, NULL);
    for (i = 0; i < dlt_non_verbose_argument_statics_num; i++) {
        key = wmem_new(wmem_epan_scope(), gint64);
        *key = DLT_MAKE_ID(DLT_STATIC_TYPE_ID, dlt_non_verbose_argument_statics[i].id);
        g_hash_table_insert(data_dlt_argument_statics, key, &dlt_non_verbose_argument_statics[i]);
    }
}




static void *
copy_dlt_argument_basetype_cb(void *n, const void *o, size_t size _U_) {
    dlt_non_verbose_argument_basetype_uat_t        *new_rec = (dlt_non_verbose_argument_basetype_uat_t *)n;
    const dlt_non_verbose_argument_basetype_uat_t  *old_rec = (const dlt_non_verbose_argument_basetype_uat_t *)o;

    COPY_UAT_CSTRING(old_rec, new_rec, name);

    new_rec->id       = old_rec->id;
    new_rec->bitsize  = old_rec->bitsize;
    new_rec->issigned = old_rec->issigned;
    new_rec->isfloat = old_rec->isfloat;

    return new_rec;
}

static bool
update_dlt_argument_basetype_cb(void *r, char **err) {
    dlt_non_verbose_argument_basetype_uat_t *rec = (dlt_non_verbose_argument_basetype_uat_t *)r;

    CHECK_UAT_DATATYPE_ID(rec->id, rec->name);
    CHECK_UAT_CSTRING_NOT_EMPTY(rec->name, "Name");

    if (rec->bitsize != 8 &&  rec->bitsize != 16 && rec->bitsize != 32 && rec->bitsize != 64) {
        *err = ws_strdup_printf("Bitsize can only be 8, 16, 32 or 64 bits");
        return FALSE;
    }

    return TRUE;
}

static void
free_dlt_argument_basetype_cb(void *r) {
    dlt_non_verbose_argument_basetype_uat_t *rec = (dlt_non_verbose_argument_basetype_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }
}

static void
reset_dlt_argument_basetype_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_dlt_argument_basetypes) {
        g_hash_table_destroy(data_dlt_argument_basetypes);
        data_dlt_argument_basetypes = NULL;
    }
}

static void
post_update_dlt_argument_basetype_cb(void) {
    gint64 *key = NULL;
    guint i =0;

    reset_dlt_argument_basetype_cb();

    /* create new hash table */
    data_dlt_argument_basetypes = g_hash_table_new_full(g_int_hash, g_int_equal, &dlt_free_key, NULL);

    if (data_dlt_argument_basetypes == NULL || dlt_non_verbose_argument_basetypes == NULL || dlt_non_verbose_argument_basetypes_num == 0) {
        return;
    }

    for (i = 0; i < dlt_non_verbose_argument_basetypes_num; i++) {
        key = wmem_new(wmem_epan_scope(), gint64);
        *key = DLT_MAKE_ID(DLT_BASETYPE_TYPE_ID, dlt_non_verbose_argument_basetypes[i].id);
        g_hash_table_insert(data_dlt_argument_basetypes, key, &dlt_non_verbose_argument_basetypes[i]);
    }
}

/*************************
 ****** Expert Info ******
 *************************/

static expert_field ei_dlt_unsupported_datatype;
static expert_field ei_dlt_unsupported_length_datatype;
static expert_field ei_dlt_unsupported_string_coding;
static expert_field ei_dlt_unsupported_non_verbose_msg_type;
static expert_field ei_dlt_buffer_too_short;
static expert_field ei_dlt_parsing_error;
static expert_field ei_dlt_non_verbose_parsing_error;
static expert_field ei_dlt_non_verbose_missing_message_error;
static expert_field ei_dlt_non_verbose_datatype_unknown;
static expert_field ei_dlt_non_verbose_trucated;
static expert_field ei_dlt_non_verbose_invalid_length;

static void
expert_dlt_unsupported_parameter(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb!=NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_unsupported_datatype, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported Data Type!]");
}

static void
expert_dlt_unsupported_length_datatype(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_unsupported_length_datatype, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported Length of Datatype!]");
}

static void
expert_dlt_unsupported_string_coding(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_unsupported_string_coding, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported String Coding!]");
}

static void
expert_dlt_unsupported_non_verbose_msg_type(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_unsupported_non_verbose_msg_type, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Unsupported Non-Verbose Message Type!]");
}

static void
expert_dlt_buffer_too_short(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_buffer_too_short, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Buffer too short!]");
}

static void
expert_dlt_parsing_error(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_parsing_error, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Parsing Error!]");
}

/*
static void
expert_dlt_non_verbose_parsing_error(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_non_verbose_parsing_error, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Non-Verbose Parsing Error!]");
}
*/

static void
expert_dlt_non_verbose_message_missing(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_non_verbose_missing_message_error, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Non-Verbose Message Configuration Missing!]");
}

static void
expert_dlt_non_verbose_datatype_unknown(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_non_verbose_datatype_unknown, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Non-Verbose datatype unknown!]");
}

static void
expert_dlt_non_verbose_truncated(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_non_verbose_trucated, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Non-Verbose data truncated!]");
}


static void
expert_dlt_non_verbose_invalid_length(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, gint length) {
    if (tvb != NULL) {
        proto_tree_add_expert(tree, pinfo, &ei_dlt_non_verbose_invalid_length, tvb, offset, length);
    }
    col_append_str(pinfo->cinfo, COL_INFO, " [DLT: Non-Verbose dynamic length invalid!]");
}



/*****************************
 ****** Helper routines ******
 *****************************/

gint32
dlt_ecu_id_to_gint32(const gchar *ecu_id) {
    if (ecu_id == NULL) {
        return 0;
    }

    gint32 ret = 0;
    gint i;
    guint shift = 32;

    /* DLT allows only up to 4 ASCII chars! Unused is 0x00 */
    for (i = 0; i < (gint)strlen(ecu_id) && i < 4; i++) {
        shift -= 8;
        ret |= (gint32)ecu_id[i] << shift;
    }

    return ret;
}

/**********************************
 ****** The dissector itself ******
 **********************************/

static void
sanitize_buffer(guint8 *buf, gint length, guint32 encoding) {
    gint i = 0;

    for (i=0; i<length; i++) {
        /* UTF-8 uses the ASCII chars. So between 0x00 and 0x7f, we can treat it as ASCII. :) */
        if ((encoding==DLT_MSG_VERB_PARAM_SCOD_UTF8 || encoding==DLT_MSG_VERB_PARAM_SCOD_ASCII) && buf[i]!=0x00 && buf[i]<0x20) {
            /* write space for special chars */
            buf[i]=0x20;
        }
    }
}

static guint32
dissect_dlt_verbose_parameter_bool(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le _U_, guint32 type_info _U_, gint length) {
    guint8 value = 0;

    if (length != 1 || tvb_captured_length_remaining(tvb, offset) < length) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    value = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dlt_data_bool, tvb, offset, 1, ENC_NA);

    if (value==0x00) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " false");
    } else if (value==0x01) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " true");
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " undefined");
    }

    return length;
}

static guint32
dissect_dlt_verbose_parameter_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length) {
    gint64 value = 0;

    if (tvb_captured_length_remaining(tvb, offset) < length) {
        return 0;
    }

    if (payload_le) {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_int8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            value = (gint8)tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_int16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            value = (gint16)tvb_get_letohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_int32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            value = (gint32)tvb_get_letohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_int64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            value = (gint64)tvb_get_letoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    } else {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_int8, tvb, offset, 1, ENC_BIG_ENDIAN);
            value = (gint8)tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_int16, tvb, offset, 2, ENC_BIG_ENDIAN);
            value = (gint16)tvb_get_ntohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_int32, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = (gint32)tvb_get_ntohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_int64, tvb, offset, 8, ENC_BIG_ENDIAN);
            value = (gint64)tvb_get_ntoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %" PRId64, value);
    return length;
}

static guint32
dissect_dlt_verbose_parameter_uint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length) {
    guint64 value = 0;

    if (tvb_captured_length_remaining(tvb, offset) < length) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (payload_le) {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_uint8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            value = tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            value = tvb_get_letohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_uint32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            value = tvb_get_letohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_uint64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            value = tvb_get_letoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    } else {
        switch (length) {
        case 1:
            proto_tree_add_item(tree, hf_dlt_uint8, tvb, offset, 1, ENC_BIG_ENDIAN);
            value = tvb_get_guint8(tvb, offset);
            break;
        case 2:
            proto_tree_add_item(tree, hf_dlt_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
            value = tvb_get_ntohs(tvb, offset);
            break;
        case 4:
            proto_tree_add_item(tree, hf_dlt_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = tvb_get_ntohl(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_uint64, tvb, offset, 8, ENC_BIG_ENDIAN);
            value = tvb_get_ntoh64(tvb, offset);
            break;
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %" PRIu64, value);
    return length;
}

static guint32
dissect_dlt_verbose_parameter_float(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length) {
    gdouble value = 0.0;

    if (tvb_captured_length_remaining(tvb, offset) < length) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (payload_le) {
        switch (length) {
        case 4:
            proto_tree_add_item(tree, hf_dlt_float, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            value = (gdouble)tvb_get_letohieee_float(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_double, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            value = tvb_get_letohieee_double(tvb, offset);
            break;
        case 2:
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    } else {
        switch (length) {
        case 4:
            proto_tree_add_item(tree, hf_dlt_float, tvb, offset, 4, ENC_BIG_ENDIAN);
            value = (gdouble)tvb_get_ntohieee_float(tvb, offset);
            break;
        case 8:
            proto_tree_add_item(tree, hf_dlt_double, tvb, offset, 8, ENC_BIG_ENDIAN);
            value = tvb_get_ntohieee_double(tvb, offset);
            break;
        case 2:
        case 16:
        default:
            expert_dlt_unsupported_length_datatype(tree, pinfo, tvb, offset, length);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %f", value);
    return length;
}

static guint32
dissect_dlt_verbose_parameter_raw_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length _U_) {
    guint16     len = 0;
    guint8     *buf = NULL;
    guint32     i = 0;
    guint32     offset_orig = offset;

    if (tvb_captured_length_remaining(tvb, offset) < 2) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    if (payload_le) {
        len = tvb_get_letohs(tvb, offset);
    } else {
        len = tvb_get_ntohs(tvb, offset);
    }
    offset += 2;

    if (tvb_captured_length_remaining(tvb, offset) < len) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    proto_tree_add_item(tree, hf_dlt_rawd, tvb, offset, len, ENC_NA);

    buf = (guint8 *) tvb_memdup(pinfo->pool, tvb, offset, len);
    offset += len;

    for (i=0; i<len; i++) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%02x", buf[i]);
    }

    return offset - offset_orig;
}

static guint32
dissect_dlt_verbose_parameter_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint32 type_info _U_, gint length _U_) {
    guint16     str_len = 0;
    guint32     encoding = 0;
    guint8     *buf = NULL;
    guint32     offset_orig = offset;
    gint        tmp_length = 0;
    tvbuff_t   *subtvb = NULL;

    if (tvb_captured_length_remaining(tvb, offset) < 2) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    if (payload_le) {
        str_len = tvb_get_letohs(tvb, offset);
    } else {
        str_len = tvb_get_ntohs(tvb, offset);
    }
    offset += 2;

    if (tvb_captured_length_remaining(tvb, offset) < str_len) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, 0);
        return offset - offset_orig;
    }

    encoding = (type_info & DLT_MSG_VERB_PARAM_SCOD);

    if (encoding!=DLT_MSG_VERB_PARAM_SCOD_ASCII && encoding!=DLT_MSG_VERB_PARAM_SCOD_UTF8) {
        expert_dlt_unsupported_string_coding(tree, pinfo, tvb, offset, str_len);
        return -1;
    }

    subtvb = tvb_new_subset_length(tvb, offset, str_len);

    if (encoding == DLT_MSG_VERB_PARAM_SCOD_ASCII) {
        buf = tvb_get_stringz_enc(pinfo->pool, subtvb, 0, &tmp_length, ENC_ASCII);
    }
    else {
        buf = tvb_get_stringz_enc(pinfo->pool, subtvb, 0, &tmp_length, ENC_UTF_8);
    }

    if ( buf != NULL && tmp_length > 0) {
        sanitize_buffer(buf, tmp_length, encoding);
        proto_tree_add_item(tree, hf_dlt_string, tvb, offset, str_len, ENC_ASCII | ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", buf);
    } else {
        expert_dlt_parsing_error(tree, pinfo, tvb, offset, str_len);
    }

    offset += str_len;
    return offset - offset_orig;
}

static guint32
dissect_dlt_verbose_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le) {
    guint32     type_info = 0;
    guint8      length_field = 0;
    gint        length = 0;
    guint32     offset_orig = offset;

    /* we need at least the uint32 type info to decide on how much more bytes we need */
    if (tvb_captured_length_remaining(tvb, offset) < 4) {
        expert_dlt_parsing_error(tree, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset));
        return -1;
    }

    if (payload_le) {
        type_info = tvb_get_letohl(tvb, offset);
    } else {
        type_info = tvb_get_ntohl(tvb, offset);
    }
    offset +=4;

    length_field = type_info & DLT_MSG_VERB_PARAM_LENGTH;

    length=0;
    switch (length_field) {
    case 0x01:
        length=1;
        break;
    case 0x02:
        length=2;
        break;
    case 0x03:
        length=4;
        break;
    case 0x04:
        length=8;
        break;
    case 0x05:
        length=16;
        break;
    }

    if (length > 0 && tvb_captured_length_remaining(tvb, offset) < length) {
        return -1;
    }

    switch (type_info & (~ (DLT_MSG_VERB_PARAM_LENGTH | DLT_MSG_VERB_PARAM_SCOD))) {
    case DLT_MSG_VERB_PARAM_BOOL:
        offset += dissect_dlt_verbose_parameter_bool(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_SINT:
        offset += dissect_dlt_verbose_parameter_int(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_UINT:
        offset += dissect_dlt_verbose_parameter_uint(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_FLOA:
        offset += dissect_dlt_verbose_parameter_float(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_STRG:
        offset += dissect_dlt_verbose_parameter_string(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    case DLT_MSG_VERB_PARAM_RAWD:
        offset += dissect_dlt_verbose_parameter_raw_data(tvb, pinfo, tree, offset, payload_le, type_info, length);
        break;
    default:
        expert_dlt_unsupported_parameter(tree, pinfo, tvb, offset, 0);
    }

    if ( (offset-offset_orig) <= 4) {
        return 0;
    } else {
        return offset - offset_orig;
    }
}

static guint32
dissect_dlt_verbose_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean payload_le, guint8 num_of_args) {
    guint32     i = 0;
    guint32     offset_orig = offset;
    guint32     len_parsed = 5;

    while (len_parsed>4 && i<num_of_args) {
        len_parsed = dissect_dlt_verbose_parameter(tvb, pinfo, tree, offset, payload_le);
        offset += len_parsed;
        i++;
    }

    return offset - offset_orig;
}

static int
dissect_dlt_non_verbose_payload_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, gboolean payload_le, guint8 msg_type _U_,
                                        guint8 msg_type_info_comb, guint32 message_id) {
    proto_item     *ti = NULL;
    proto_tree     *subtree;
    proto_tree     *subtree2;
    proto_tree     *subtree3;
    int             ret = 0;
    gint            len;
    guint32         offset_orig;
    guint           tmp_length = 0;
    guint           encoding = ENC_BIG_ENDIAN;
    guint           status;
    guint           appid_count;
    guint           ctxid_count;
    guint           i;
    guint           j;

    offset_orig = offset;

    if (payload_le) {
        encoding = ENC_LITTLE_ENDIAN;
    }

    len = tvb_captured_length_remaining(tvb, offset);
    if (len == 0) {
        return 0;
    }

    if (msg_type_info_comb == DLT_MSG_TYPE_INFO_CTRL_REQ) {
        switch (message_id) {
        case DLT_SERVICE_ID_SET_LOG_LEVEL:
            proto_tree_add_item(tree, hf_dlt_service_application_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_context_id, tvb, offset + 4, 4, ENC_ASCII | ENC_NA );
            proto_tree_add_item(tree, hf_dlt_service_new_log_level, tvb, offset + 8, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 9, 4, ENC_NA);
            ret = 13;
            break;
        case DLT_SERVICE_ID_SET_TRACE_STATUS:
            proto_tree_add_item(tree, hf_dlt_service_application_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_context_id, tvb, offset + 4, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_new_trace_status, tvb, offset + 8, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 9, 4, ENC_NA);
            ret = 13;
            break;
        case DLT_SERVICE_ID_GET_LOG_INFO:
            proto_tree_add_item(tree, hf_dlt_service_options, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_application_id, tvb, offset + 1, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_context_id, tvb, offset + 5, 4, ENC_ASCII | ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 9, 4, ENC_NA);
            break;
        case DLT_SERVICE_ID_SET_MESSAGE_FILTERING:
            proto_tree_add_item(tree, hf_dlt_service_new_status, tvb, offset, 1, ENC_NA);
            ret = 1;
            break;
        case DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL:
            proto_tree_add_item(tree, hf_dlt_service_new_log_level, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 1, 4, ENC_NA);
            ret = 5;
            break;
        case DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS:
            proto_tree_add_item(tree, hf_dlt_service_new_trace_status, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset + 1, 4, ENC_NA);
            ret = 5;
            break;
        }
    } else if (msg_type_info_comb == DLT_MSG_TYPE_INFO_CTRL_RES) {
        switch (message_id) {
        case DLT_SERVICE_ID_SET_LOG_LEVEL:
        case DLT_SERVICE_ID_SET_TRACE_STATUS:
        case DLT_SERVICE_ID_STORE_CONFIGURATION:
        case DLT_SERVICE_ID_RESTORE_TO_FACTORY_DEFAULT:
        case DLT_SERVICE_ID_SET_VERBOSE_MODE:
        case DLT_SERVICE_ID_SET_MESSAGE_FILTERING:
        case DLT_SERVICE_ID_SET_TIMING_PACKETS:
        case DLT_SERVICE_ID_SET_DEFAULT_LOG_LEVEL:
        case DLT_SERVICE_ID_SET_DEFAULT_TRACE_STATUS:
        case DLT_SERVICE_ID_SET_LOG_CHANNEL_ASSIGNMENT:
            proto_tree_add_item(tree, hf_dlt_service_status, tvb, offset, 1, ENC_NA);
            ret = 1;
            break;
        case DLT_SERVICE_ID_GET_LOG_INFO:
            proto_tree_add_item_ret_uint(tree, hf_dlt_service_status_log_info, tvb, offset, 1, ENC_NA, &status);
            offset += 1;
            ti = proto_tree_add_item(tree, hf_dlt_service_log_levels, tvb, offset, len - 4, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_dlt_service_app_ids);

            proto_tree_add_item_ret_uint(subtree, hf_dlt_service_count, tvb, offset, 2, encoding, &appid_count);
            offset += 2;
            /* loop over all app id entries */
            for (i=0; i<appid_count; i++) {
                ti = proto_tree_add_item(subtree, hf_dlt_service_application_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
                offset += 4;
                subtree2 = proto_item_add_subtree(ti, ett_dlt_service_app_id);

                proto_tree_add_item_ret_uint(subtree2, hf_dlt_service_count, tvb, offset, 2, encoding, &ctxid_count);
                offset += 2;
                /* loop over all ctx id entries */
                for (j = 0; j < ctxid_count; j++) {
                    ti = proto_tree_add_item(subtree2, hf_dlt_service_context_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
                    subtree3 = proto_item_add_subtree(ti, ett_dlt_service_ctx_id);
                    offset += 4;

                    proto_tree_add_item(subtree3, hf_dlt_service_log_level, tvb, offset, 1, encoding);
                    offset += 1;
                    proto_tree_add_item(subtree3, hf_dlt_service_trace_status, tvb, offset, 1, encoding);
                    offset += 1;

                    if (status == DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE_TEXT) {
                        proto_tree_add_item_ret_uint(subtree2, hf_dlt_service_count, tvb, offset, 2, encoding, &tmp_length);
                        offset += 2;
                        proto_tree_add_item(subtree2, hf_dlt_service_ctx_desc, tvb, offset, tmp_length, ENC_ASCII | ENC_NA);
                        offset += tmp_length;
                    }
                }
                if (status == DLT_SERVICE_STATUS_LOG_LEVEL_DLT_LOG_TRACE_TEXT) {
                    proto_tree_add_item_ret_uint(subtree, hf_dlt_service_count, tvb, offset, 2, encoding, &tmp_length);
                    offset += 2;
                    proto_tree_add_item(subtree, hf_dlt_service_app_desc, tvb, offset, tmp_length, ENC_ASCII | ENC_NA);
                    offset += tmp_length;
                }
            }

            proto_tree_add_item(tree, hf_dlt_service_reserved, tvb, offset_orig + len - 4, 4, ENC_NA);
            ret = len;
            break;
        case DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL:
            proto_tree_add_item(tree, hf_dlt_service_status, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_dlt_service_log_level, tvb, offset+1, 1, ENC_NA);
            ret = 2;
            break;
        case DLT_SERVICE_ID_GET_SOFTWARE_VERSION:
            proto_tree_add_item(tree, hf_dlt_service_status, tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(tree, hf_dlt_service_length, tvb, offset + 1, 4, encoding, &tmp_length);
            if ((guint)len >= 5 + tmp_length) {
                proto_tree_add_item(tree, hf_dlt_service_swVersion, tvb, offset + 5, tmp_length, ENC_ASCII | ENC_NA);
            } else {
                expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, len);
            }
            ret = 5 + tmp_length;
            break;
        }
    }
    if (ret==0 && len>0) {
        proto_tree_add_item(tree, hf_dlt_payload_data, tvb, offset, len, encoding);
        ret = len;
    }
    return ret;
}

char*
dlt_lookup_message(guint32 messageid) {
    if (data_dlt_argument_list == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_dlt_argument_list, &messageid);
}

static gpointer
get_generic_config(GHashTable *ht, gint64 id) {
    if (ht == NULL) {
        return NULL;
    }

    return (gpointer)g_hash_table_lookup(ht, &id);
}

static dlt_non_verbose_argument_list_t*
get_message_config(const gchar* ecu_id, guint32 messageid) {
    dlt_non_verbose_argument_list_t *tmp = NULL;

    if (data_dlt_argument_list == NULL) {
        return NULL;
    }
    guint64 key = (((guint64)dlt_ecu_id_to_gint32(ecu_id)) << 32) | messageid;

    tmp = (dlt_non_verbose_argument_list_t *)get_generic_config(data_dlt_argument_list, key);

    return tmp;
}

static dlt_non_verbose_argument_basetype_t*
get_basetype_config(guint32 id) {
    if (DLT_GET_TYPE(id) != DLT_BASETYPE_TYPE_ID){
        return NULL;
    }
    if (data_dlt_argument_basetypes == NULL) {
        return NULL;
    }
    return (dlt_non_verbose_argument_basetype_t *)get_generic_config(data_dlt_argument_basetypes, (gint64)id);
}

static dlt_non_verbose_argument_struct_t*
get_struct_config(guint32 id) {
    if (DLT_GET_TYPE(id) != DLT_STRUCT_TYPE_ID){
        return NULL;
    }
    if (data_dlt_argument_structs == NULL) {
        return NULL;
    }
    return (dlt_non_verbose_argument_struct_t *)get_generic_config(data_dlt_argument_structs, (gint64)id);
}

static dlt_non_verbose_argument_static_t*
get_static_config(guint32 id) {
    if (DLT_GET_TYPE(id) != DLT_STATIC_TYPE_ID){
        return NULL;
    }
    if (data_dlt_argument_statics == NULL) {
        return NULL;
    }
    return (dlt_non_verbose_argument_static_t *)get_generic_config(data_dlt_argument_statics, (gint64)id);
}

static dlt_non_verbose_argument_array_t*
get_array_config(guint32 id) {
    if (DLT_GET_TYPE(id) != DLT_ARRAY_TYPE_ID){
        return NULL;
    }
    if (data_dlt_argument_arrays == NULL) {
        return NULL;
    }
    return (dlt_non_verbose_argument_array_t *)get_generic_config(data_dlt_argument_arrays, (gint64)id);
}


static int dissect_dlt_non_verbose_argument(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dlt_info_t *dlt_info, guint offset, gchar* name, guint32 datatype, int* hf_id);

static gint64
dissect_dlt_dynamic_length_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint offset, gint length_of_length_field) {
    proto_item *ti;
    guint32     tmp = 0;
    int hf_id = hf_dlt_non_verbose_array_length_field_8bit;
    gint remaining;
    guint8 length = 0;

    (void) subtree;
    (void) pinfo;

    remaining = tvb_captured_length_remaining(tvb, offset);
    length = length_of_length_field / 8;
    switch (length_of_length_field) {
    case 8:
        hf_id = hf_dlt_non_verbose_array_length_field_8bit;
        break;
    case 16:
        hf_id = hf_dlt_non_verbose_array_length_field_16bit;
        break;
    case 32:
        hf_id = hf_dlt_non_verbose_array_length_field_32bit;
        break;
    default:
        return -1;
    }

    if(remaining < length){
        expert_dlt_non_verbose_truncated(subtree, pinfo, tvb, offset, remaining);
        return -1;
    }
    ti = proto_tree_add_item_ret_uint(subtree, hf_id, tvb, offset, length_of_length_field / 8, ENC_BIG_ENDIAN, &tmp);
    proto_item_set_hidden(ti);

    return (gint64)tmp;
}

static int dissect_dlt_non_verbose_argument_array_element(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, dlt_info_t *dlt_info, guint offset, guint index, guint32 datatype, int* hf_id){
    dlt_non_verbose_argument_basetype_t* type;
    proto_item *ti = NULL;
    gint        param_length = -1;
    gint remaining = -1;
    int hfid = hf_dlt_non_verbose_array;
    if (hf_id !=NULL){
        hfid = *hf_id;
    }


    type = get_basetype_config(datatype);
    if (type == NULL){
        expert_dlt_non_verbose_datatype_unknown(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    param_length = (gint)((type->bitsize) / 8);
    remaining = tvb_captured_length_remaining(tvb, offset);
    if(param_length > remaining){
        expert_dlt_non_verbose_truncated(tree, pinfo, tvb, offset, remaining);
        return remaining;
    }
    ti = proto_tree_add_item(tree, hfid, tvb, offset, param_length, dlt_info->little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    proto_item_prepend_text(ti, "[%i] ", index);
    return param_length;

}

static int dissect_dlt_non_verbose_argument_array_dim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dlt_info_t *dlt_info, guint offset, dlt_non_verbose_argument_array_t* array, guint8 dimension){
    guint      i        = 0;
    gint       length   = 0;
    proto_tree *subtree = NULL;
    proto_item *ti;
    dlt_non_verbose_argument_array_dimension_t* dim = &(array->array_dimensions[dimension]);
    if (dimension == (array->length -1)){
        /* last dimension, do basetype stuff here */
       for (i = 0; i < dim->length; i++){
           length += dissect_dlt_non_verbose_argument_array_element(tvb, tree, pinfo, dlt_info, (guint)(offset+length), i, array->data_type_ref, dim->hf_id);
       }
    }else{
       for (i = 0; i < dim->length; i++){
           ti = proto_tree_add_string_format(tree, hf_dlt_non_verbose_array, tvb, (gint)(offset+length), 0, dim->name, "dim %s[%i]", dim->name, i);
           subtree = proto_item_add_subtree(ti, ett_dlt_non_verbose_array_dim);
           length += dissect_dlt_non_verbose_argument_array_dim(tvb, pinfo, subtree, dlt_info, (guint)(offset+length), array, dimension+1);
           proto_item_set_end(ti, tvb, (gint)(offset+length));
       }
    }

    return (gint)length;
}

static int dissect_dlt_non_verbose_argument_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dlt_info_t *dlt_info, guint offset, gchar* name, guint32 datatype){
    dlt_non_verbose_argument_array_t* type = NULL;
    proto_item *ti      = NULL;
    proto_tree *subtree = NULL;
    gint       length   = 0;
    guint      i        = 0;
    gint       remaining = -1;

    type = get_array_config(datatype);
    if (type == NULL){
        expert_dlt_non_verbose_datatype_unknown(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (name != NULL){
         ti = proto_tree_add_string_format(tree, hf_dlt_non_verbose_base, tvb, offset, 0, type->name, "array %s [%s] dims: %i", name, type->name, type->length);
    }else{
         ti = proto_tree_add_string_format(tree, hf_dlt_non_verbose_base, tvb, offset, 0, type->name, "array [%s] dims: %i", type->name, type->length);
    }

    subtree = proto_item_add_subtree(ti, ett_dlt_non_verbose_array);


    remaining = tvb_captured_length_remaining(tvb, offset);
    if(type->ndim){
        /* Handle multi dimensional array */
        length = dissect_dlt_non_verbose_argument_array_dim(tvb, pinfo, subtree, dlt_info, offset, type, 0);
    }else if (type->isstring){
        guint length_of_array = type->length;
        if (type->dynamic_length){
            gint64 tmp_length;
            tmp_length = dissect_dlt_dynamic_length_field(tvb, pinfo, subtree, (guint)(offset+length),  type->length_size);
            if (tmp_length < 0){
                return remaining;
            }
            length_of_array = (guint32)tmp_length;
            length += (type->length_size/8);
            remaining -= (type->length_size/8);
            if (length_of_array > type->length || length_of_array > INT_MAX){
                expert_dlt_non_verbose_invalid_length(tree, pinfo, tvb, offset, (gint)length);
                return (gint)(remaining + length);
            }
        }
        if (remaining < (gint)length_of_array){
            expert_dlt_non_verbose_truncated(tree, pinfo, tvb, offset, remaining);
            return remaining;
        }
        proto_tree_add_item(tree, hf_dlt_non_verbose_array_string, tvb, offset, length_of_array, ENC_ASCII | ENC_NA);
    }else{
        /* simple array */
        guint length_of_array = type->length;
        if (type->dynamic_length){
            gint64 tmp_length;
            tmp_length = dissect_dlt_dynamic_length_field(tvb, pinfo, subtree, (guint)(offset+length),  type->length_size);
            if (tmp_length < 0){
                return remaining;
            }
            length_of_array = (guint32)tmp_length;
            length += (type->length_size/8);
            remaining -= (type->length_size/8);
            if (length_of_array > type->length || length_of_array > INT_MAX){
                expert_dlt_non_verbose_invalid_length(tree, pinfo, tvb, offset, (gint)length);
                return remaining + length;
            }
        }
        for (i = 0; i < length_of_array && tvb_captured_length_remaining(tvb, (gint)(offset + length)) > 0; i++) {
            dlt_non_verbose_argument_array_dimension_t *item = &(type->array_dimensions[i]);
            length += dissect_dlt_non_verbose_argument(tvb, pinfo, subtree, dlt_info, (guint)(offset+length), NULL, type->data_type_ref, item->hf_id);
        }
    }

    proto_item_set_end(ti, tvb, (gint)(offset+length));
    return length;
}

static int dissect_dlt_non_verbose_argument_struct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dlt_info_t *dlt_info, guint offset, gchar* name, guint32 datatype){
    dlt_non_verbose_argument_struct_t* type;
    dlt_non_verbose_argument_t *item;
    proto_item *ti      = NULL;
    proto_tree *subtree = NULL;
    gint       length   = 0;
    guint      i        = 0;

    type = get_struct_config(datatype);
    if (type == NULL){
        expert_dlt_non_verbose_datatype_unknown(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (name != NULL){
         ti = proto_tree_add_string_format(tree, hf_dlt_non_verbose_base, tvb, offset, 0, type->name, "struct %s [%s]", name, type->name);
    }else{
         ti = proto_tree_add_string_format(tree, hf_dlt_non_verbose_base, tvb, offset, 0, type->name, "struct [%s]", type->name);
    }

    subtree = proto_item_add_subtree(ti, ett_dlt_non_verbose_struct);
    for (i = 0; i < type->num_of_items && tvb_captured_length_remaining(tvb, offset + length) > 0; i++) {
        item = &(type->items[i]);
        length += dissect_dlt_non_verbose_argument(tvb, pinfo, subtree, dlt_info, (guint)(offset+length), item->name, item->data_type_ref, item->hf_id);
    }
    proto_item_set_end(ti, tvb, (gint)(offset+length));
    return length;
}

static int dissect_dlt_non_verbose_argument_basetype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dlt_info_t *dlt_info, guint offset, guint32 datatype, int* hf_id){
    dlt_non_verbose_argument_basetype_t* type;
    gint param_length = -1;
    gint remaining = -1;

    type = get_basetype_config(datatype);
    if (type == NULL){
        expert_dlt_non_verbose_datatype_unknown(tree, pinfo, tvb, offset, 0);
        return 0;
    }
    param_length = (gint)((type->bitsize) / 8);
    remaining = tvb_captured_length_remaining(tvb, offset);
    if(param_length > remaining){
        expert_dlt_non_verbose_truncated(tree, pinfo, tvb, offset, remaining);
        return remaining;
    }
    proto_tree_add_item(tree, *hf_id, tvb, offset, param_length, dlt_info->little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    return param_length;

}

static int dissect_dlt_non_verbose_argument_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dlt_info_t *dlt_info, guint offset, guint32 datatype){
    dlt_non_verbose_argument_static_t* type;

    type = get_static_config(datatype);
    if (type == NULL){
        expert_dlt_non_verbose_datatype_unknown(tree, pinfo, tvb, offset, 0);
        return 0;
    }

    (void) dlt_info;

    proto_tree_add_string(tree, hf_dlt_non_verbose_static, tvb, offset, 0, type->name);
    return 0;
}

static int dissect_dlt_non_verbose_argument(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dlt_info_t *dlt_info, guint offset, gchar* name, guint32 datatype, int* hf_id){
    int (*fct)(tvbuff_t*, packet_info*, proto_tree*, dlt_info_t*, guint, gchar*, guint32) = NULL;

    switch(DLT_GET_TYPE(datatype)){
        case DLT_BASETYPE_TYPE_ID:
            return dissect_dlt_non_verbose_argument_basetype(tvb, pinfo, tree, dlt_info, offset, datatype, hf_id);
            break;
        case DLT_STRUCT_TYPE_ID:
            fct = dissect_dlt_non_verbose_argument_struct;
            break;
        case DLT_ARRAY_TYPE_ID:
            fct = dissect_dlt_non_verbose_argument_array;
            break;
        case DLT_STATIC_TYPE_ID:
            return dissect_dlt_non_verbose_argument_static(tvb, pinfo, tree, dlt_info, offset, datatype);
        default:
            fct = NULL;
    }
    if (fct == NULL){
        expert_dlt_non_verbose_datatype_unknown(tree, pinfo, tvb, offset, 0);
        return 0;
    }
    return fct(tvb, pinfo, tree, dlt_info, offset, name, datatype);
}

static int dissect_dlt_non_verbose(tvbuff_t *tvb, packet_info *pinfo, proto_tree *dlt_tree, proto_tree *payload_tree, dlt_info_t *dlt_info){
    dlt_non_verbose_argument_list_t* messageinfo = NULL;
    dlt_non_verbose_argument_t *item;
    gint        offset = 0;
    messageinfo = get_message_config(dlt_info->ecu_id, dlt_info->message_id);
    if (messageinfo == NULL){
        expert_dlt_non_verbose_message_missing(dlt_tree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (messageinfo->num_of_items == 0 || messageinfo->items == NULL) {
        /* no items for this message, so nothing to do */
        return 0;
    }else{
        guint32 i;
        proto_item     *ti = NULL;
        proto_tree     *non_verbose_subtree;

        proto_tree_add_item(payload_tree, hf_dlt_payload_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), dlt_info->little_endian);

        ti = proto_tree_add_item(dlt_tree, hf_dlt_non_verbose_payload, tvb, offset, -1, ENC_NA);
        non_verbose_subtree = proto_item_add_subtree(ti, ett_dlt_non_verbose_payload);

        proto_tree_add_string_format(non_verbose_subtree, hf_dlt_service_application_id, tvb, offset, 0, messageinfo->application_id, "%s", messageinfo->application_id);
        proto_tree_add_string_format(non_verbose_subtree, hf_dlt_service_context_id, tvb, offset, 0, messageinfo->context_id, "%s", messageinfo->context_id);

        col_append_fstr(pinfo->cinfo, COL_INFO, " <%s", messageinfo->ecu_id);
        if (messageinfo->application_id !=NULL){
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", messageinfo->application_id);
        }
        if (messageinfo->context_id !=NULL){
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", messageinfo->context_id);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ">");

        if (messageinfo->name != NULL){
            proto_tree_add_string_format(non_verbose_subtree, hf_dlt_non_verbose_message_name, tvb, offset, 0, messageinfo->name, "%s", messageinfo->name);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", messageinfo->name);
        }else{
            col_append_fstr(pinfo->cinfo, COL_INFO, " %08x", messageinfo->messageid);
        }

        for (i = 0; i < messageinfo->num_of_items && tvb_captured_length_remaining(tvb, offset) > 0; i++) {
            item = &(messageinfo->items[i]);
            offset += dissect_dlt_non_verbose_argument(tvb, pinfo, non_verbose_subtree, dlt_info, offset, item->name, item->data_type_ref, item->hf_id);
        }
        if (i < messageinfo-> num_of_items - 1){
            /*expert_dlt_non_verbose_parsing_error(dlt_tree, pinfo, tvb, offset, 0);*/
        }
       proto_item_set_end(ti, tvb, offset);
    }
    return offset;
}


static int
dissect_dlt_non_verbose_payload_message_handoff(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree, proto_tree *dlt_tree, proto_tree *subtree, gboolean payload_le,
                                                guint8 msg_type, guint8 msg_type_info_comb, guint32 message_id, const guint8 *ecu_id, guint32 msg_length) {

    dlt_info_t dlt_info;

    dlt_info.message_id = message_id;
    dlt_info.little_endian = payload_le;
    dlt_info.message_type = msg_type;
    dlt_info.message_type_info_comb = msg_type_info_comb;
    dlt_info.message_length = msg_length;
    dlt_info.ecu_id = (const gchar *)ecu_id;

    if(dissect_dlt_non_verbose(tvb, pinfo, dlt_tree, subtree, &dlt_info)){
        return 1;
    }

    return dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, root_tree, &heur_dtbl_entry, &dlt_info);
}

static int
dissect_dlt_non_verbose_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree, proto_tree *dlt_tree, proto_tree *payload_tree, guint32 offset, gboolean payload_le,
                                guint8 msg_type, guint8 msg_type_info_comb, const guint8 *ecu_id, guint32 length) {
    guint32        message_id = 0;
    tvbuff_t       *subtvb = NULL;
    guint32        offset_orig = offset;
    const gchar    *message_id_name = NULL;
    proto_item     *ti;

    if (payload_le) {
        ti = proto_tree_add_item(payload_tree, hf_dlt_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        message_id = tvb_get_letohl(tvb, offset);
    } else {
        ti = proto_tree_add_item(payload_tree, hf_dlt_message_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        message_id = tvb_get_ntohl(tvb, offset);
    }
    offset += 4;
    length -= 4;

    if (msg_type==DLT_MSG_TYPE_CTRL_MSG && (msg_type_info_comb==DLT_MSG_TYPE_INFO_CTRL_REQ || msg_type_info_comb==DLT_MSG_TYPE_INFO_CTRL_RES)) {
        if (tvb_captured_length_remaining(tvb, offset) == 0) {
            return offset - offset_orig;
        }

        message_id_name = try_val_to_str(message_id, dlt_service);

        if (message_id_name == NULL) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Unknown Non-Verbose Message (ID: 0x%02x)", message_id);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s (ID: 0x%02x)", message_id_name, message_id);
            proto_item_append_text(ti, " (%s)", message_id_name);
        }

        subtvb = tvb_new_subset_remaining(tvb, offset);
        dissect_dlt_non_verbose_payload_message(subtvb, pinfo, payload_tree, 0, payload_le, msg_type, msg_type_info_comb, message_id);
    } else if(msg_type == DLT_MSG_TYPE_LOG_MSG) {
        subtvb = tvb_new_subset_remaining(tvb, offset);
        if (dissect_dlt_non_verbose_payload_message_handoff(subtvb, pinfo, root_tree, dlt_tree, payload_tree, payload_le, msg_type, msg_type_info_comb, message_id, ecu_id, length) <= 0) {
            proto_tree_add_item(payload_tree, hf_dlt_payload_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), payload_le);
        }
    } else {
        expert_dlt_unsupported_non_verbose_msg_type(payload_tree, pinfo, tvb, offset, 0);
    }

    return offset - offset_orig;
}

static void
deregister_dynamic_hf_data(hf_register_info **hf_array, guint *hf_size) {
    if (*hf_array) {
        /* Unregister all fields used before */
        for (guint i = 0; i < *hf_size; i++) {
            if ((*hf_array)[i].p_id != NULL) {
                proto_deregister_field(proto_dlt, *((*hf_array)[i].p_id));
                g_free((*hf_array)[i].p_id);
                (*hf_array)[i].p_id = NULL;
            }
        }
        proto_add_deregistered_data(*hf_array);
        *hf_array = NULL;
        *hf_size = 0;
    }
}

static void
allocate_dynamic_hf_data(hf_register_info **hf_array, guint *hf_size, guint new_size) {
    *hf_array = g_new0(hf_register_info, new_size);
    *hf_size = new_size;
}

typedef struct _argument_return_attibutes_t {
    enum ftenum     type;
    int             display_base;
    gchar          *basetype_name;
} argument_return_attributes_t;

static argument_return_attributes_t
get_argument_attributes(guint32 data_type_ref) {
    argument_return_attributes_t ret;
    dlt_non_verbose_argument_basetype_t *tmp = get_basetype_config(data_type_ref);

    ret.type = FT_NONE;
    ret.display_base = BASE_NONE;
    ret.basetype_name = NULL;

    if (tmp == NULL){
        return ret;
    }
    ret.basetype_name = tmp->name;
    ret.display_base = BASE_DEC;
    if (g_strcmp0(tmp->name, "boolean") == 0) {
        ret.type = FT_BOOLEAN;
        ret.display_base = 8;
    }else if (tmp->isfloat){
        if (tmp->bitsize == 32) {
            ret.type = FT_FLOAT;
            ret.display_base = BASE_NONE;
        } else if (tmp->bitsize == 64) {
            ret.type = FT_DOUBLE;
            ret.display_base = BASE_NONE;
        }
    }else{
        if (tmp->issigned){
            if(tmp->bitsize == 8){
                ret.type = FT_UINT8;
            }else if(tmp->bitsize == 16){
                ret.type = FT_UINT16;
            }else if(tmp->bitsize == 32){
                ret.type = FT_UINT32;
            }else if(tmp->bitsize == 64){
                ret.type = FT_UINT64;
            }
        }else{
            if(tmp->bitsize == 8){
                ret.type = FT_INT8;
            }else if(tmp->bitsize == 16){
                ret.type = FT_INT16;
            }else if(tmp->bitsize == 32){
                ret.type = FT_INT32;
            }else if(tmp->bitsize == 64){
                ret.type = FT_INT64;
            }
        }
    }

    return ret;
}

static gint*
update_dynamic_hf_entry(hf_register_info *hf_array, int pos, guint data_type_ref, char *param_name) {
    argument_return_attributes_t   attribs;
    gint                       *hf_id;

    attribs = get_argument_attributes(data_type_ref);
    if (hf_array == NULL || attribs.type == FT_NONE) {
        return NULL;
    }

    hf_id = g_new(gint, 1);
    *hf_id = -1;
    hf_array[pos].p_id = hf_id;

    hf_array[pos].hfinfo.strings = NULL;
    hf_array[pos].hfinfo.bitmask = 0;
    hf_array[pos].hfinfo.blurb   = NULL;

    if (attribs.basetype_name == NULL) {
        hf_array[pos].hfinfo.name = g_strdup(param_name);
    } else {
        hf_array[pos].hfinfo.name = ws_strdup_printf("%s [%s]", param_name, attribs.basetype_name);
    }

    hf_array[pos].hfinfo.abbrev = ws_strdup_printf("dlt.non_verbose.%s", param_name);
    hf_array[pos].hfinfo.type = attribs.type;
    hf_array[pos].hfinfo.display = attribs.display_base;

    HFILL_INIT(hf_array[pos]);

    return hf_id;
}

static void
update_dynamic_argument_hf_entry(gpointer key _U_, gpointer value, gpointer data) {
    guint32                    *pos = (guint32 *)data;
    dlt_non_verbose_argument_list_t    *list = (dlt_non_verbose_argument_list_t *)value;
    guint                       i = 0;

    for (i = 0; i < list->num_of_items ; i++) {
        if (*pos >= dynamic_hf_list_size) {
            return;
        }

        dlt_non_verbose_argument_t *item = &(list->items[i]);

        item->hf_id = update_dynamic_hf_entry(dynamic_hf_list, *pos, item->data_type_ref, item->name);

        if (item->hf_id != NULL) {
            (*pos)++;
        }
    }
}

static void
update_dynamic_array_hf_entry(gpointer key _U_, gpointer value, gpointer data) {
    guint32                    *pos = (guint32 *)data;
    dlt_non_verbose_argument_array_t   *array = (dlt_non_verbose_argument_array_t *)value;
    guint                               i = 0;

    if (!array->ndim){
        return;
    }
    for (i = 0; i < array->length; i++) {
        if (*pos >= dynamic_hf_array_size) {
            return;
        }
        dlt_non_verbose_argument_array_dimension_t *item = &(array->array_dimensions[i]);

        item->hf_id = update_dynamic_hf_entry(dynamic_hf_array, *pos, array->data_type_ref, item->name);

        if (item->hf_id != NULL) {
            (*pos)++;
        }
    }
}

static void
update_dynamic_struct_hf_entry(gpointer key _U_, gpointer value, gpointer data) {
    guint32                            *pos = (guint32 *)data;
    dlt_non_verbose_argument_struct_t  *list = (dlt_non_verbose_argument_struct_t *)value;
    guint                               i = 0;

    for (i = 0; i < list->num_of_items; i++) {
        if (*pos >= dynamic_hf_struct_size) {
            return;
        }
        dlt_non_verbose_argument_t *item = &(list->items[i]);

        item->hf_id = update_dynamic_hf_entry(dynamic_hf_struct, *pos, item->data_type_ref, item->name);

        if (item->hf_id != NULL) {
            (*pos)++;
        }
    }
}

static void
update_dynamic_hf_entries_dlt_argument_list(void) {
    if (data_dlt_argument_list != NULL) {
        deregister_dynamic_hf_data(&dynamic_hf_list, &dynamic_hf_list_size);
        allocate_dynamic_hf_data(&dynamic_hf_list, &dynamic_hf_list_size, dlt_non_verbose_argument_lists_num);
        guint32 pos = 0;
        g_hash_table_foreach(data_dlt_argument_list, update_dynamic_argument_hf_entry, &pos);
        proto_register_field_array(proto_dlt, dynamic_hf_list, pos);
    }
}

static void
update_dynamic_hf_entries_dlt_argument_arrays(void) {
    if (data_dlt_argument_arrays != NULL) {
        deregister_dynamic_hf_data(&dynamic_hf_array, &dynamic_hf_array_size);
        allocate_dynamic_hf_data(&dynamic_hf_array, &dynamic_hf_array_size, dlt_non_verbose_argument_arrays_num);
        guint32 pos = 0;
        g_hash_table_foreach(data_dlt_argument_arrays, update_dynamic_array_hf_entry, &pos);
        proto_register_field_array(proto_dlt, dynamic_hf_array, pos);
    }
}

static void
update_dynamic_hf_entries_dlt_argument_structs(void) {
    if (data_dlt_argument_structs != NULL) {
        deregister_dynamic_hf_data(&dynamic_hf_struct, &dynamic_hf_struct_size);
        allocate_dynamic_hf_data(&dynamic_hf_struct, &dynamic_hf_struct_size, dlt_non_verbose_argument_structs_num);
        guint32 pos = 0;
        g_hash_table_foreach(data_dlt_argument_structs, update_dynamic_struct_hf_entry, &pos);
        proto_register_field_array(proto_dlt, dynamic_hf_struct, pos);
    }
}

static int
dissect_dlt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint32 offset_orig) {
    proto_item     *ti;
    proto_tree     *dlt_tree = NULL;
    proto_tree     *ext_hdr_tree = NULL;
    proto_tree     *subtree = NULL;
    proto_tree     *payload_tree = NULL;
    guint32         offset = offset_orig;

    guint8          header_type = 0;
    gboolean        ext_header = FALSE;
    gboolean        payload_le = FALSE;
    guint16         length = 0;
    guint16         header_length = 0;

    guint8          msg_info = 0;
    gboolean        verbose = FALSE;
    guint8          msg_type = 0;
    guint8          msg_type_info = 0;
    guint8          msg_type_info_comb = 0;

    guint8          num_of_args = 0;
    gdouble         timestamp = 0.0;

    gint            captured_length = tvb_captured_length_remaining(tvb, offset);

    const guint8   *ecu_id = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", PNAME);

    if (captured_length < DLT_MIN_SIZE_FOR_PARSING) {
        expert_dlt_buffer_too_short(tree, pinfo, tvb, offset, captured_length);
        return captured_length;
    }

    header_type = tvb_get_guint8(tvb, offset);
    ext_header = ((header_type & DLT_HDR_TYPE_EXT_HEADER) == DLT_HDR_TYPE_EXT_HEADER);
    payload_le = ((header_type & DLT_HDR_TYPE_MSB_FIRST) != DLT_HDR_TYPE_MSB_FIRST);

    ti = proto_tree_add_item(tree, proto_dlt, tvb, offset, -1, ENC_NA);
    dlt_tree = proto_item_add_subtree(ti, ett_dlt);

    ti = proto_tree_add_item(dlt_tree, hf_dlt_header_type, tvb, offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_dlt_hdr_type);

    proto_tree_add_item(subtree, hf_dlt_ht_ext_header, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_msb_first, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_with_ecuid, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_with_sessionid, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_with_timestamp, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlt_ht_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(dlt_tree, hf_dlt_msg_ctr, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(dlt_tree, hf_dlt_length, tvb, offset, 2, ENC_NA);
    offset += 2;

    if ((header_type & DLT_HDR_TYPE_WITH_ECU_ID) == DLT_HDR_TYPE_WITH_ECU_ID) {
        proto_tree_add_item_ret_string(dlt_tree, hf_dlt_ecu_id, tvb, offset, 4, ENC_ASCII | ENC_NA, pinfo->pool, &ecu_id);
        offset += 4;
    }

    if ((header_type & DLT_HDR_TYPE_WITH_SESSION_ID) == DLT_HDR_TYPE_WITH_SESSION_ID) {
        proto_tree_add_item(dlt_tree, hf_dlt_session_id, tvb, offset, 4, ENC_NA);
        offset += 4;
    }

    if ((header_type & DLT_HDR_TYPE_WITH_TIMESTAMP) == DLT_HDR_TYPE_WITH_TIMESTAMP) {
        timestamp = (tvb_get_ntohl(tvb, offset)/10000.0);
        proto_tree_add_double_format_value(dlt_tree, hf_dlt_timestamp, tvb, offset, 4, timestamp, "%.4f s", timestamp);
        offset += 4;
    }

    if ((header_type & DLT_HDR_TYPE_EXT_HEADER) == DLT_HDR_TYPE_EXT_HEADER) {
        ti = proto_tree_add_item(dlt_tree, hf_dlt_ext_hdr, tvb, offset, 10, ENC_NA);
        ext_hdr_tree = proto_item_add_subtree(ti, ett_dlt_ext_hdr);

        ti = proto_tree_add_item(ext_hdr_tree, hf_dlt_msg_info, tvb, offset, 1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_dlt_msg_info);

        proto_tree_add_item(subtree, hf_dlt_mi_verbose, tvb, offset, 1, ENC_NA);

        msg_info = tvb_get_guint8(tvb, offset);
        verbose = (msg_info & DLT_MSG_INFO_VERBOSE) == DLT_MSG_INFO_VERBOSE;
        msg_type_info_comb = msg_info & DLT_MSG_INFO_MSG_TYPE_INFO_COMB;
        msg_type = (msg_type_info_comb & DLT_MSG_INFO_MSG_TYPE) >> 1;
        msg_type_info = (msg_type_info_comb & DLT_MSG_INFO_MSG_TYPE_INFO) >> 4;

        proto_tree_add_item(subtree, hf_dlt_mi_msg_type, tvb, offset, 1, ENC_NA);
        proto_tree_add_uint_format_value(subtree, hf_dlt_mi_msg_type_info, tvb, offset, 1, msg_info, "%s (%d)",
            val_to_str_const(msg_type_info_comb, dlt_msg_type_info, "Unknown Message Type Info"), msg_type_info);
        offset += 1;

        num_of_args = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(ext_hdr_tree, hf_dlt_num_of_args, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(ext_hdr_tree, hf_dlt_app_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
        offset += 4;

        proto_tree_add_item(ext_hdr_tree, hf_dlt_ctx_id, tvb, offset, 4, ENC_ASCII | ENC_NA);
        offset += 4;
    }

    ti = proto_tree_add_item(dlt_tree, hf_dlt_payload, tvb, offset, length - offset, ENC_NA);
    payload_tree = proto_item_add_subtree(ti, ett_dlt_payload);

    header_length = offset;
    col_append_fstr(pinfo->cinfo, COL_INFO, ":");

    if (!ext_header || !verbose) {
        offset += dissect_dlt_non_verbose_payload(tvb, pinfo, tree, dlt_tree, payload_tree, offset, payload_le, msg_type, msg_type_info_comb, ecu_id, length - header_length);
    } else {
        offset += dissect_dlt_verbose_payload(tvb, pinfo, payload_tree, offset, payload_le, num_of_args);
    }

    col_set_fence(pinfo->cinfo, COL_INFO);
    return offset - offset_orig;
}

static int
dissect_dlt_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_dlt(tvb, pinfo, tree, data, 0);
}

static guint
get_dlt_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void* data _U_) {
    return tvb_get_ntohs(tvb, offset + 2);
}

static int
dissect_dlt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, DLT_MIN_SIZE_FOR_PARSING, get_dlt_message_len, dissect_dlt_msg, data);
    return tvb_reported_length(tvb);
}

static int
dissect_dlt_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return udp_dissect_pdus(tvb, pinfo, tree, DLT_MIN_SIZE_FOR_PARSING, NULL, get_dlt_message_len, dissect_dlt_msg, data);
}

static int
dissect_dlt_storage_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_tree *dlt_storage_tree;
    proto_item *ti;

    guint32     offset = 0;

    ti = proto_tree_add_item(tree, proto_dlt_storage_header, tvb, offset, 16, ENC_NA);
    dlt_storage_tree = proto_item_add_subtree(ti, ett_dlt_storage);

    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_tstamp_s, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_tstamp_us, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* setting source to ECU Name of the encapsulation header */
    set_address_tvb(&(pinfo->src), AT_STRINGZ, 4, tvb, offset);
    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_ecu_name, tvb, offset, 5, ENC_ASCII);
    offset += 5;

    proto_tree_add_item(dlt_storage_tree, hf_dlt_storage_reserved, tvb, offset, 3, ENC_NA);
    return 16 + dissect_dlt(tvb, pinfo, tree, data, 16);
}

void proto_register_dlt(void) {
    module_t        *dlt_module;
    expert_module_t    *expert_module_DLT;
    uat_t *dlt_argument_list_uat;
    uat_t *dlt_argument_struct_uat;
    uat_t *dlt_argument_array_uat;
    uat_t *dlt_argument_static_uat;
    uat_t *dlt_argument_basetype_uat;

    static hf_register_info hf_dlt[] = {
        { &hf_dlt_header_type, {
            "Header Type", "dlt.header_type",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_ht_ext_header, {
            "Extended Header", "dlt.header_type.ext_header",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_EXT_HEADER, NULL, HFILL }},
        { &hf_dlt_ht_msb_first, {
            "MSB First", "dlt.header_type.msb_first",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_MSB_FIRST, NULL, HFILL }},
        { &hf_dlt_ht_with_ecuid, {
            "With ECU ID", "dlt.header_type.with_ecu_id",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_WITH_ECU_ID, NULL, HFILL }},
        { &hf_dlt_ht_with_sessionid, {
            "With Session ID", "dlt.header_type.with_session_id",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_WITH_SESSION_ID, NULL, HFILL }},
        { &hf_dlt_ht_with_timestamp, {
            "With Timestamp", "dlt.header_type.with_timestamp",
            FT_BOOLEAN, 8, NULL, DLT_HDR_TYPE_WITH_TIMESTAMP, NULL, HFILL }},
        { &hf_dlt_ht_version, {
            "Version", "dlt.header_type.version",
            FT_UINT8, BASE_DEC, NULL, DLT_HDR_TYPE_VERSION, NULL, HFILL }},

        { &hf_dlt_msg_ctr, {
            "Message Counter", "dlt.msg_counter",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_length, {
            "Length", "dlt.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_ecu_id, {
            "ECU ID", "dlt.ecu_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_session_id, {
            "Session ID", "dlt.session_id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_timestamp, {
            "Timestamp", "dlt.timestamp",
            FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_ext_hdr, {
            "Extended Header", "dlt.ext_header",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_msg_info, {
            "Message Info", "dlt.msg_info",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_mi_verbose, {
            "Verbose", "dlt.msg_info.verbose",
            FT_BOOLEAN, 8, NULL, DLT_MSG_INFO_VERBOSE, NULL, HFILL }},
        { &hf_dlt_mi_msg_type, {
            "Message Type", "dlt.msg_info.msg_type",
            FT_UINT8, BASE_DEC, VALS(dlt_msg_type), DLT_MSG_INFO_MSG_TYPE, NULL, HFILL }},
        { &hf_dlt_mi_msg_type_info, {
            "Message Type Info", "dlt.msg_info.msg_type_info",
            FT_UINT8, BASE_DEC, NULL, DLT_MSG_INFO_MSG_TYPE_INFO, NULL, HFILL }},
        { &hf_dlt_num_of_args, {
            "Number of Arguments", "dlt.num_of_args",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_app_id, {
            "Application ID", "dlt.application_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_ctx_id, {
            "Context ID", "dlt.context_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_payload, {
            "Payload", "dlt.payload",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_message_id, {
            "Message ID", "dlt.message_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_payload_data, {
            "Payload Data", "dlt.payload.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dlt_data_bool, {
            "(bool)", "dlt.data.bool",
            FT_BOOLEAN, 1, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint8, {
            "(uint8)", "dlt.data.uint8",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint16, {
            "(uint16)", "dlt.data.uint16",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint32, {
            "(uint32)", "dlt.data.uint32",
           FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_uint64, {
            "(uint64)", "dlt.data.uint64",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int8, {
            "(int8)", "dlt.data.int8",
            FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int16, {
            "(int16)", "dlt.data.int16",
            FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int32, {
            "(int32)", "dlt.data.int32",
            FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_int64, {
            "(int64)", "dlt.data.int64",
            FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_float, {
            "(float)", "dlt.data.float",
            FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_double, {
            "(double)", "dlt.data.double",
            FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_rawd, {
            "(rawd)", "dlt.data.rawd",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_dlt_string, {
            "(string)", "dlt.data.string",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL } },


        { &hf_dlt_non_verbose_payload, {
            "Non-Verbose Payload", "dlt.non_verbose",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_message_name, {
            "Messge Name", "dlt.non_verbose.message_name",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_argument, {
            "Argument", "dlt.non_verbose.argument",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_base, {
            "(string)", "dlt.non_verbose.base",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_stattic, {
            "(base)", "dlt.non_verbose.static",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_struct, {
            "(struct)", "dlt.non_verbose.struct",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_array, {
            "(array)", "dlt.non_verbose.array",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_array_string, {
            "(string)", "dlt.non_verbose.string",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_dlt_non_verbose_static, {
            "(static)", "dlt.non_verbose.static",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_array_length_field_8bit,
            { "Length", "dlt.non_verbose.array_length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_array_length_field_16bit,
            { "Length", "dlt.non_verbose.array_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_non_verbose_array_length_field_32bit,
            { "Length", "dlt.non_verbose.array_length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },


        { &hf_dlt_service_options, {
            "Options", "dlt.service.options",
            FT_UINT8, BASE_DEC, VALS(dlt_service_options), 0x0, NULL, HFILL } },
        { &hf_dlt_service_application_id, {
            "Application ID", "dlt.service.application_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_context_id, {
            "Context ID", "dlt.service.context_id",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_log_level, {
            "Log Level", "dlt.service.log_level",
            FT_INT8, BASE_DEC, VALS(dlt_service_log_level), 0x0, NULL, HFILL } },
        { &hf_dlt_service_new_log_level, {
            "New Log Level", "dlt.service.new_log_level",
            FT_INT8, BASE_DEC, VALS(dlt_service_log_level), 0x0, NULL, HFILL } },
        { &hf_dlt_service_trace_status, {
            "Trace Status", "dlt.service.trace_status",
            FT_INT8, BASE_DEC, VALS(dlt_service_trace_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_new_trace_status, {
            "New Trace Status", "dlt.service.new_trace_status",
            FT_INT8, BASE_DEC, VALS(dlt_service_trace_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_new_status, {
            "New  Status", "dlt.service.new_status",
            FT_INT8, BASE_DEC, VALS(dlt_service_new_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_reserved, {
            "Reserved", "dlt.service.res",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_status, {
            "Status", "dlt.service.status",
            FT_UINT8, BASE_DEC, VALS(dlt_service_status), 0x0, NULL, HFILL } },
        { &hf_dlt_service_length, {
            "Length", "dlt.service.length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_swVersion, {
            "SW-Version", "dlt.service.sw_version",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_status_log_info, {
            "Status", "dlt.service.status",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_log_levels, {
            "Log Levels", "dlt.service.appid_log_levels",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_count, {
            "Count", "dlt.service.count",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_app_desc, {
            "Application Description", "dlt.service.app_description",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dlt_service_ctx_desc, {
            "Context Description", "dlt.service.ctx_description",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_dlt,
        &ett_dlt_hdr_type,
        &ett_dlt_ext_hdr,
        &ett_dlt_msg_info,
        &ett_dlt_payload,
        &ett_dlt_non_verbose_payload,
        &ett_dlt_non_verbose_struct,
        &ett_dlt_non_verbose_array,
        &ett_dlt_non_verbose_array_dim,
        &ett_dlt_service_app_ids,
        &ett_dlt_service_app_id,
        &ett_dlt_service_ctx_id,

    };

    static ei_register_info ei[] = {
        { &ei_dlt_unsupported_datatype, {
            "dlt.unsupported_datatype", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported Data Type!", EXPFILL } },
        { &ei_dlt_unsupported_length_datatype, {
            "dlt.unsupported_length_datatype", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported Length of Datatype!", EXPFILL } },
        { &ei_dlt_unsupported_string_coding, {
            "dlt.unsupported_string_coding", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported String Coding!", EXPFILL } },
        { &ei_dlt_unsupported_non_verbose_msg_type, {
            "dlt.unsupported_non_verbose_message_type", PI_MALFORMED, PI_ERROR,
            "DLT: Unsupported Non-Verbose Message Type!", EXPFILL } },
        { &ei_dlt_buffer_too_short, {
            "dlt.buffer_too_short", PI_MALFORMED, PI_ERROR,
            "DLT: Buffer too short!", EXPFILL } },
        { &ei_dlt_parsing_error, {
            "dlt.parsing_error", PI_MALFORMED, PI_ERROR,
            "DLT: Parsing Error!", EXPFILL } },
        { &ei_dlt_non_verbose_parsing_error, {
            "dlt.non_verbose.parsing_error", PI_MALFORMED, PI_ERROR,
            "DLT: Non-Verbose Parsing Error!", EXPFILL } },
        { &ei_dlt_non_verbose_missing_message_error, {
            "dlt.non_verbose.missing_message_config", PI_UNDECODED, PI_NOTE,
            "DLT: Non-Verbose Message Configuration missing!", EXPFILL } },
        { &ei_dlt_non_verbose_datatype_unknown, {
            "dlt.non_verbose.datatype_unknown", PI_UNDECODED, PI_NOTE,
            "DLT: Non-Verbose provided datatype is unknown/undefined!", EXPFILL } },
        { &ei_dlt_non_verbose_trucated, {
            "dlt.non_verbose.truncated", PI_MALFORMED, PI_WARN,
            "DLT: Non-Verbose data seems truncated, check message and config.", EXPFILL } },
        { &ei_dlt_non_verbose_invalid_length, {
            "dlt.non_verbose.invalid_length", PI_MALFORMED, PI_ERROR,
            "DLT: Non-Verbose dynamic length field exceeds maximum.", EXPFILL } },


    };

    /* UATs for user_data fields */
    static uat_field_t dlt_non_verbose_argument_list_uat_fields[] = {
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_lists,     ecu_id,         "Ecu Id",              "Ecu Id"),
        UAT_FLD_HEX        (dlt_non_verbose_argument_lists,     messageid,      "MessageId",           "Non Verbose Message Id"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_lists,     message_name,   "Name",                "Message Name"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_lists,     application_id, "Application Id",      "Application Id"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_lists,     context_id,     "Context Id",          "Context Id"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_lists,     num_of_items,   "# args",              "Number of arguments"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_lists,     pos,            "pos arg",             "Position of argument"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_lists,     name,           "Argname",             "Name of Argument"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_lists,     data_type,      "Data Type",           "Type of datatype (base, array, struct, static)"),
        UAT_FLD_HEX        (dlt_non_verbose_argument_lists,     data_type_ref,  "Datatype ID",         "ID of the Datatype"),
        UAT_END_FIELDS
    };
    static uat_field_t dlt_non_verbose_argument_struct_uat_fields[] = {
        UAT_FLD_HEX        (dlt_non_verbose_argument_structs,   id,             "Datatype ID",         "DataTypeId (28bit)"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_structs,   struct_name,    "Name",                "Name of struct"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_structs,   num_of_items,   "# items",             "Number of Items in Struct"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_structs,   pos,            "pos item",            "Position in Struct"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_structs,   name,           "Itemname",            "Name of Element"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_structs,   data_type,      "Data Type",           "Type of datatype (base, array, struct, static)"),
        UAT_FLD_HEX        (dlt_non_verbose_argument_structs,   data_type_ref,  "Element Datatype ID", "Datatype of Element"),
        UAT_END_FIELDS
    };
    static uat_field_t dlt_non_verbose_argument_array_uat_fields[] = {
        UAT_FLD_HEX        (dlt_non_verbose_argument_arrays,    id,             "Datatype ID",         "DataTypeId (28bit)"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_arrays,    name,           "Name",                "Name of Array"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_arrays,    data_type,      "Data Type",           "Type of datatype (base, array, struct, static)"),
        UAT_FLD_HEX        (dlt_non_verbose_argument_arrays,    data_type_ref,  "Datatype ID",         "Datatype of Element"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_arrays,    length,         "Length/Dimensions",   "Length/Dimension of Array (1Dimenstional: length, n-Dimenational: dimensions)"),
        UAT_FLD_BOOL       (dlt_non_verbose_argument_arrays,    isstring,       "String?",             "Is this array a string"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_arrays,    encoding,       "Encoding",            "one of: ascii, utf8, utf16"),
        UAT_FLD_BOOL       (dlt_non_verbose_argument_arrays,    dynamic_length, "Dynamic Length?",     "Is the array of dynamic length?"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_arrays,    length_size,    "Bits Lengthfiel",     "Size of the length field for dynamic length array"),
        UAT_FLD_BOOL       (dlt_non_verbose_argument_arrays,    ndim,           "N-Dimensional?",      "Is this array n dimensional"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_arrays,    dimension_size, "SubDimension Size",   "Number of sub dimensions"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_arrays,    dimension_pos,  "Dimension Position",  "Which Dimension Position is this"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_arrays,    dimension_name, "Dimension Name",      "Name for dimension"),
        UAT_END_FIELDS
    };
    static uat_field_t dlt_non_verbose_argument_static_uat_fields[] = {
        UAT_FLD_HEX        (dlt_non_verbose_argument_statics,   id,             "Datatype ID",         "DataTypeId (28bit)"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_statics,   name,           "String/Name",         "Static String"),
        UAT_END_FIELDS
    };
    static uat_field_t dlt_non_verbose_argument_basetype_uat_fields[] = {
        UAT_FLD_HEX        (dlt_non_verbose_argument_basetypes, id,             "Datatype ID",         "DataTypeId (28bit)"),
        UAT_FLD_CSTRING    (dlt_non_verbose_argument_basetypes, name,           "Name",                "Name of type"),
        UAT_FLD_DEC        (dlt_non_verbose_argument_basetypes, bitsize,        "Bitsize",             "Bitsize (8,16,32,64)"),
        UAT_FLD_BOOL       (dlt_non_verbose_argument_basetypes, issigned,       "Signed?",             "is the type signed"),
        UAT_FLD_BOOL       (dlt_non_verbose_argument_basetypes, isfloat,        "Float?",              "Type is a float"),
        UAT_END_FIELDS
    };

    /* Register the protocol name and description */
    proto_dlt = proto_register_protocol(PSNAME, PNAME, PFNAME);
    dlt_handle_tcp = register_dissector("dlt_tcp", dissect_dlt_tcp, proto_dlt);
    dlt_handle_udp = register_dissector("dlt_udp", dissect_dlt_udp, proto_dlt);
    dlt_handle_storage = register_dissector("dlt_storage", dissect_dlt_storage_header, proto_dlt_storage_header);
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_dlt, hf_dlt, array_length(hf_dlt));

    /* Register Expert Info */
    expert_module_DLT = expert_register_protocol(proto_dlt);
    expert_register_field_array(expert_module_DLT, ei, array_length(ei));

    heur_subdissector_list = register_heur_dissector_list("dlt", proto_dlt);

    /* Register preferences */
    dlt_module = prefs_register_protocol(proto_dlt, &proto_reg_handoff_dlt);

    /* UATs */
    dlt_argument_list_uat = uat_new("DLT Messages",
        sizeof(dlt_non_verbose_argument_list_uat_t), /* record size           */
        DATAFILE_DLT_MESSAGES,                       /* filename              */
        TRUE,                                        /* from profile          */
        (void **) &dlt_non_verbose_argument_lists,   /* data_ptr              */
        &dlt_non_verbose_argument_lists_num,         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                      /* but not fields        */
        NULL,                                        /* help                  */
        copy_dlt_argument_list_cb,                   /* copy callback         */
        update_dlt_argument_list_cb,                 /* update callback       */
        free_dlt_argument_list_cb,                   /* free callback         */
        post_update_dlt_argument_list_cb,                  /* post update callback  */
        reset_dlt_argument_list_cb,                     /* reset callback        */
        dlt_non_verbose_argument_list_uat_fields
    );

    prefs_register_uat_preference(dlt_module, "messages", "DLT Non Verbose Mesages",
        "A table to define DLT non verbose messages", dlt_argument_list_uat);

    dlt_argument_struct_uat = uat_new("DLT Structures",
        sizeof(dlt_non_verbose_argument_struct_uat_t), /* record size           */
        DATAFILE_DLT_STRUCTS,                       /* filename              */
        TRUE,                                        /* from profile          */
        (void **) &dlt_non_verbose_argument_structs,   /* data_ptr              */
        &dlt_non_verbose_argument_structs_num,         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                      /* but not fields        */
        NULL,                                        /* help                  */
        copy_dlt_argument_struct_cb,                   /* copy callback         */
        update_dlt_argument_struct_cb,                 /* update callback       */
        free_dlt_argument_struct_cb,                   /* free callback         */
        post_update_dlt_argument_struct_cb,                  /* post update callback  */
        reset_dlt_argument_struct_cb,                     /* reset callback        */
        dlt_non_verbose_argument_struct_uat_fields
    );

    prefs_register_uat_preference(dlt_module, "structures", "DLT Argument Structures",
        "A table to define DLT non verbose messages structs", dlt_argument_struct_uat);

    dlt_argument_array_uat = uat_new("DLT Arrays",
        sizeof(dlt_non_verbose_argument_array_uat_t), /* record size           */
        DATAFILE_DLT_ARRAYS,                       /* filename              */
        TRUE,                                        /* from profile          */
        (void **) &dlt_non_verbose_argument_arrays,   /* data_ptr              */
        &dlt_non_verbose_argument_arrays_num,         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                      /* but not fields        */
        NULL,                                        /* help                  */
        copy_dlt_argument_array_cb,                   /* copy callback         */
        update_dlt_argument_array_cb,                 /* update callback       */
        free_dlt_argument_array_cb,                   /* free callback         */
        post_update_dlt_argument_array_cb,                  /* post update callback  */
        reset_dlt_argument_array_cb,                     /* reset callback        */
        dlt_non_verbose_argument_array_uat_fields
    );

    prefs_register_uat_preference(dlt_module, "arrays", "DLT Argument Arrays",
        "A table to define DLT non verbose messages arrays", dlt_argument_array_uat);

    dlt_argument_static_uat = uat_new("DLT Static Values",
        sizeof(dlt_non_verbose_argument_static_uat_t), /* record size           */
        DATAFILE_DLT_STATICS,                       /* filename              */
        TRUE,                                        /* from profile          */
        (void **) &dlt_non_verbose_argument_statics,   /* data_ptr              */
        &dlt_non_verbose_argument_statics_num,         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                      /* but not fields        */
        NULL,                                        /* help                  */
        copy_dlt_argument_static_cb,                   /* copy callback         */
        update_dlt_argument_static_cb,                 /* update callback       */
        free_dlt_argument_static_cb,                   /* free callback         */
        post_update_dlt_argument_static_cb,                  /* post update callback  */
        reset_dlt_argument_static_cb,                     /* reset callback        */
        dlt_non_verbose_argument_static_uat_fields
    );

    prefs_register_uat_preference(dlt_module, "statics", "DLT Argument static values",
        "A table to define DLT non verbose static statics", dlt_argument_static_uat);

    dlt_argument_basetype_uat = uat_new("DLT Base Types",
        sizeof(dlt_non_verbose_argument_basetype_uat_t), /* record size           */
        DATAFILE_DLT_BASETYPES,                       /* filename              */
        TRUE,                                        /* from profile          */
        (void **) &dlt_non_verbose_argument_basetypes,   /* data_ptr              */
        &dlt_non_verbose_argument_basetypes_num,         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                      /* but not fields        */
        NULL,                                        /* help                  */
        copy_dlt_argument_basetype_cb,                   /* copy callback         */
        update_dlt_argument_basetype_cb,                 /* update callback       */
        free_dlt_argument_basetype_cb,                   /* free callback         */
        post_update_dlt_argument_basetype_cb,                  /* post update callback  */
        reset_dlt_argument_basetype_cb,                     /* reset callback        */
        dlt_non_verbose_argument_basetype_uat_fields
    );

    prefs_register_uat_preference(dlt_module, "bae_types", "DLT Argument Base Types",
        "A table to define DLT non verbose base type", dlt_argument_basetype_uat);
}

static void
clean_all_hashtables_with_empty_uat(void) {
    /* On config change, we delete all hashtables which should have 0 entries! */
    /* Usually this is already done in the post update cb of the uat.*/
    /* Unfortunately, Wireshark does not call the post_update_cb on config errors. :( */
    if (data_dlt_argument_list && dlt_non_verbose_argument_lists_num==0) {
        g_hash_table_destroy(data_dlt_argument_list);
        data_dlt_argument_list = NULL;
    }
    if (data_dlt_argument_basetypes && dlt_non_verbose_argument_basetypes_num==0) {
        g_hash_table_destroy(data_dlt_argument_basetypes);
        data_dlt_argument_basetypes = NULL;
    }
    if (data_dlt_argument_arrays && dlt_non_verbose_argument_arrays_num==0) {
        g_hash_table_destroy(data_dlt_argument_arrays);
        data_dlt_argument_arrays = NULL;
    }
    if (data_dlt_argument_structs && dlt_non_verbose_argument_structs_num == 0) {
        g_hash_table_destroy(data_dlt_argument_structs);
        data_dlt_argument_structs = NULL;
    }
    if (data_dlt_argument_statics && dlt_non_verbose_argument_statics_num==0) {
        g_hash_table_destroy(data_dlt_argument_statics);
        data_dlt_argument_statics = NULL;
    }
}

void proto_reg_handoff_dlt(void) {
    static gboolean initialized = FALSE;

    if (!initialized) {
        dissector_add_uint_with_preference("udp.port", 0, dlt_handle_udp);
        dissector_add_uint_with_preference("tcp.port", 0, dlt_handle_tcp);
        initialized = TRUE;
    } else {
        clean_all_hashtables_with_empty_uat();
    }
    update_dynamic_hf_entries_dlt_argument_list();
    update_dynamic_hf_entries_dlt_argument_arrays();
    update_dynamic_hf_entries_dlt_argument_structs();
}

void proto_register_dlt_storage_header(void) {
    static hf_register_info hfs[] = {
        { &hf_dlt_storage_tstamp_s, {
            "Timestamp s", "dlt.storage.timestamp_s",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_storage_tstamp_us, {
            "Timestamp us", "dlt.storage.timestamp_us",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_storage_ecu_name, {
            "ECU Name", "dlt.storage.ecu_name",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dlt_storage_reserved, {
            "Reserved", "dlt.storage.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_dlt_storage,
    };

    /* Register the protocol name and description */
    proto_dlt_storage_header = proto_register_protocol(DLT_STORAGE_HEADER_NAME_LONG, DLT_STORAGE_HEADER_NAME, DLT_STORAGE_HEADER_NAME_FILTER);
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_dlt, hfs, array_length(hfs));
}

void proto_reg_handoff_dlt_storage_header(void) {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_AUTOSAR_DLT, dlt_handle_storage);
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
