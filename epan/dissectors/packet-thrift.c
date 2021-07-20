/* packet-thrift.c
 * Routines for thrift protocol dissection.
 * Based on work by John Song <jsong@facebook.com> and
 * Bill Fumerola <bill@facebook.com>
 *
 * https://github.com/andrewcox/wireshark-with-thrift-plugin/blob/wireshark-1.8.6-with-thrift-plugin/plugins/thrift/packet-thrift.cpp
 *
 * Copyright 2015, Anders Broman <anders.broman[at]ericsson.com>
 * Copyright 2019-2021, Triton Circonflexe <triton[at]kumal.info>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* Ref https://thrift.apache.org/developers
 *     https://thrift.apache.org/docs/idl.html
 *     https://diwakergupta.github.io/thrift-missing-guide/
 *     https://erikvanoosten.github.io/thrift-missing-specification/
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

#include "packet-tcp.h"
#include "packet-tls.h"
#include "packet-thrift.h"

/* Line  30: Constants and early declarations. */
/* Line 180: Protocol data structure and helper functions. */
/* Line 300: Helper functions to use within custom sub-dissectors. */
/* Line 630: Generic functions to dissect TBinaryProtocol message content. */
/* Line 900: Generic functions to dissect Thrift message header. */

void proto_register_thrift(void);
void proto_reg_handoff_thrift(void);

#define THRIFT_VERSION_VALUE_MASK   0x7fff
#define THRIFT_VERSION_MASK     0xffff00f8
#define THRIFT_MESSAGE_MASK     0x00000007
#define THRIFT_VERSION_1        0x80010000

#define NOT_A_VALID_PDU (0)

#define ABORT_SUBDISSECTION_ON_ISSUE(offset) do { if (offset < 0) return offset; } while (0)

#define ABORT_ON_INCOMPLETE_PDU(len) \
    if (tvb_reported_length_remaining(tvb, *offset) < (len)) {\
        /* Do not indicate the incomplete data if we know the above dissector is able to reassemble. */\
        if (pinfo->can_desegment <= 0) \
            proto_tree_add_expert(tree, pinfo, &ei_thrift_not_enough_data, tvb, *offset, tvb_reported_length_remaining(tvb, *offset));\
        /* Do not consume more than available for the reassembly to work. */\
        thrift_opt->reassembly_offset = *offset;\
        thrift_opt->reassembly_length = len;\
        *offset = THRIFT_REQUEST_REASSEMBLY;\
        return THRIFT_REQUEST_REASSEMBLY;\
    }

static dissector_handle_t thrift_handle;
static gboolean framed_desegment = TRUE;
static guint thrift_tls_port = 0;

static gboolean show_internal_thrift_fields = FALSE;
static gboolean try_generic_if_sub_dissector_fails = FALSE;

static dissector_table_t thrift_method_name_dissector_table;

/* TBinaryProtocol elements length. */
static const int TBP_THRIFT_TYPE_LEN = 1;
static const int TBP_THRIFT_FID_LEN = 2;
static const int TBP_THRIFT_FIELD_HEADER_LEN = 3; // TBP_THRIFT_TYPE_LEN + TBP_THRIFT_FID_LEN;
static const int TBP_THRIFT_BOOL_LEN = 1;
static const int TBP_THRIFT_I8_LEN = 1;
static const int TBP_THRIFT_DOUBLE_LEN = 8;
static const int TBP_THRIFT_I16_LEN = 2;
static const int TBP_THRIFT_I32_LEN = 4;
static const int TBP_THRIFT_I64_LEN = 8;
static const int TBP_THRIFT_MTYPE_OFFSET = 3;
static const int TBP_THRIFT_MTYPE_LEN = 1;
static const int TBP_THRIFT_VERSION_LEN = 4; /* (Version + method type) is explicitly passed as an int32 in libthrift */
static const int TBP_THRIFT_LENGTH_LEN = 4;
static const int TBP_THRIFT_SEQ_ID_LEN = 4;
static const int TBP_THRIFT_STRICT_HEADER_LEN = 8; /* (Protocol id + Version + Method type) + Name length = (4) + 4. */
                                    /* Old encoding: Name length [ + name] + Message type      + Sequence Identifier   + T_STOP */
static const int TBP_THRIFT_MIN_MESSAGE_LEN = 10; // TBP_THRIFT_LENGTH_LEN + TBP_THRIFT_I8_LEN + TBP_THRIFT_SEQ_ID_LEN + TBP_THRIFT_TYPE_LEN;
static const int TBP_THRIFT_STRICT_MIN_MESSAGE_LEN = 13; // TBP_THRIFT_STRICT_HEADER_LEN       + TBP_THRIFT_SEQ_ID_LEN + TBP_THRIFT_TYPE_LEN;
static const int TBP_THRIFT_BINARY_LEN = 4; /* Length (even with empty content). */
static const int TBP_THRIFT_STRUCT_LEN = 1; /* Empty struct still contains T_STOP. */
static const int TBP_THRIFT_MAP_LEN = 6;  /* Key type + Value type + number of elements. */
static const int TBP_THRIFT_SET_LEN = 5;  /* Elements type + number of elements. */
static const int TBP_THRIFT_LIST_LEN = 5; /* Elements type + number of elements. */

static const int DISABLE_SUBTREE = -1;

static int proto_thrift = -1;
static int hf_thrift_frame_length = -1;
static int hf_thrift_protocol_id = -1;
static int hf_thrift_version = -1;
static int hf_thrift_mtype = -1;
static int hf_thrift_str_len = -1;
static int hf_thrift_method = -1;
static int hf_thrift_seq_id = -1;
static int hf_thrift_type = -1;
static int hf_thrift_key_type = -1;
static int hf_thrift_value_type = -1;
static int hf_thrift_fid = -1;
static int hf_thrift_bool = -1;
static int hf_thrift_i8 = -1;
static int hf_thrift_i16 = -1;
static int hf_thrift_i32 = -1;
static int hf_thrift_i64 = -1;
static int hf_thrift_binary = -1;
static int hf_thrift_string = -1;
static int hf_thrift_struct = -1;
static int hf_thrift_list = -1;
static int hf_thrift_set = -1;
static int hf_thrift_map = -1;
static int hf_thrift_num_list_item = -1;
static int hf_thrift_num_set_item = -1;
static int hf_thrift_num_map_item = -1;
static int hf_thrift_double = -1;
static int hf_thrift_exception = -1;
static int hf_thrift_exception_message = -1;
static int hf_thrift_exception_type = -1;

static int ett_thrift = -1;
static int ett_thrift_header = -1;
static int ett_thrift_params = -1;
static int ett_thrift_struct = -1;
static int ett_thrift_list = -1;
static int ett_thrift_set = -1;
static int ett_thrift_map = -1;
static int ett_thrift_error = -1; // ME_THRIFT_T_REPLY with field id > 0
static int ett_thrift_exception = -1; // ME_THRIFT_T_EXCEPTION

static expert_field ei_thrift_wrong_type = EI_INIT;
static expert_field ei_thrift_negative_length = EI_INIT;
static expert_field ei_thrift_wrong_proto_version = EI_INIT;
static expert_field ei_thrift_struct_fid_not_in_seq = EI_INIT;
static expert_field ei_thrift_frame_too_short = EI_INIT;
static expert_field ei_thrift_not_enough_data = EI_INIT;
static expert_field ei_thrift_frame_too_long = EI_INIT;

static const thrift_member_t thrift_exception[] = {
    { &hf_thrift_exception_message, 1, TRUE, DE_THRIFT_T_BINARY, NULL, { .encoding = ENC_UTF_8|ENC_NA } },
    { &hf_thrift_exception_type, 2, FALSE, DE_THRIFT_T_I32, TMFILL },
    { NULL, 0, FALSE, DE_THRIFT_T_STOP, TMFILL }
};

static const value_string thrift_type_vals[] = {
    { DE_THRIFT_T_STOP, "T_STOP" },
    { DE_THRIFT_T_VOID, "T_VOID" },
    { DE_THRIFT_T_BOOL, "T_BOOL" },
    { DE_THRIFT_T_I8, "T_I8" },
    { DE_THRIFT_T_DOUBLE, "T_DOUBLE" },
    { DE_THRIFT_T_I16, "T_I16" },
    { DE_THRIFT_T_I32, "T_I32" },
    { DE_THRIFT_T_I64, "T_I64" },
    { DE_THRIFT_T_BINARY, "T_BINARY" },
    { DE_THRIFT_T_STRUCT, "T_STRUCT" },
    { DE_THRIFT_T_MAP, "T_MAP" },
    { DE_THRIFT_T_SET, "T_SET" },
    { DE_THRIFT_T_LIST, "T_LIST" },
    { 0, NULL },
};

static const value_string thrift_exception_type_vals[] = {
    {  0, "Unknown (type of peer)" },
    {  1, "Unknown Method" },
    {  2, "Invalid Message Type" },
    {  3, "Wrong Method Name" },
    {  4, "Bad Sequence Id" },
    {  5, "Missing Result" },
    {  6, "Internal Error" },
    {  7, "Protocol Error (something went wrong during decoding)" },
    {  8, "Invalid Transform" },
    {  9, "Invalid Protocol" },
    { 10, "Unsupported Client Type" },
    { 0, NULL },
};

static const value_string thrift_proto_vals[] = {
    { 0x80, "Strict Binary Protocol" },
    { 0x82, "Compact Protocol" },
    { 0, NULL },
};

static const value_string thrift_mtype_vals[] = {
    { ME_THRIFT_T_CALL,      "CALL" },
    { ME_THRIFT_T_REPLY,     "REPLY" },
    { ME_THRIFT_T_EXCEPTION, "EXCEPTION" },
    { ME_THRIFT_T_ONEWAY,    "ONEWAY" },
    { 0, NULL },
};

/* Options */
#define DECODE_BINARY_AS_AUTO_UTF8      0
#define DECODE_BINARY_AS_BINARY         1
#define DECODE_BINARY_AS_ASCII          2
#define DECODE_BINARY_AS_UTF8           3
#define DECODE_BINARY_AS_UTF16BE        4
#define DECODE_BINARY_AS_UTF16LE        5
#define DECODE_BINARY_AS_UTF32BE        6
#define DECODE_BINARY_AS_UTF32LE        7

static gint32   binary_decode = DECODE_BINARY_AS_AUTO_UTF8;

static const enum_val_t binary_display_options[] = {
    { "auto", "UTF-8 if printable", DECODE_BINARY_AS_AUTO_UTF8 },
    { "hexadecimal", "Binary (hexadecimal string)", DECODE_BINARY_AS_BINARY },
    { "ascii", "ASCII String", DECODE_BINARY_AS_ASCII },
    { "utf8", "UTF-8 String", DECODE_BINARY_AS_UTF8 },
    { "utf16be", "UTF-16 Big Endian", DECODE_BINARY_AS_UTF16BE },
    { "utf16le", "UTF-16 Little Endian", DECODE_BINARY_AS_UTF16LE },
    { "utf32be", "UTF-32 Big Endian", DECODE_BINARY_AS_UTF32BE },
    { "utf32le", "UTF-32 Little Endian", DECODE_BINARY_AS_UTF32LE },
    { NULL, NULL, -1 }
};

static int dissect_thrift_type(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* pi, int type, int* offset, thrift_option_data_t *thrift_opt);

/* Check that the 4-byte value match a Thrift Strict TBinaryProtocol version
 * - 0x8001 The version itself
 * - 0x??   An undetermined byte (not used)
 * - 0x0m   The method type between 1 and 4.*/
static gboolean
is_thrift_strict_version(guint header, gboolean ignore_msg_type)
{
    int msg_type;
    if ((header & THRIFT_VERSION_MASK) == THRIFT_VERSION_1) {
        if (ignore_msg_type) {
            return TRUE;
        }
        msg_type = (header & THRIFT_MESSAGE_MASK);
        if ((ME_THRIFT_T_CALL <= msg_type) && (msg_type <= ME_THRIFT_T_ONEWAY)) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Check that the string at the designed position is valid UTF-8.
 * This allows us to fail early if the length of the string seems very long.
 * This /can/ indicate that this packet does not contain a Thrift PDU.
 *
 * This method does /NOT/ check if the data is available, the caller must check that if needed.
 * - Heuristic for method name must check for captured length.
 * - Check UTF-8 vs. binary before adding to tree must check for reported length.
 */
static int
thrift_binary_utf8_isprint(tvbuff_t* tvb, int offset, int max_len, gboolean accept_crlf)
{
    int check_len = tvb_reported_length_remaining(tvb, offset);
    int pos, remaining = 0; /* position in tvb, remaining bytes for multi-byte characters. */
    guint8 min_next = 0x80, max_next = 0xBF;
    gboolean ended = FALSE;
    int printable_len = 0; /* In case the string ends with several NUL bytes. */
    if (max_len < check_len) {
        check_len = max_len;
    }
    for (pos = offset; pos < offset + check_len; pos++) {
        guint8 current = tvb_get_guint8(tvb, pos);
        if (ended) {
            if (current != 0) {
                return -1;
            }
        } else if (remaining == 0) {
            /* We are at the beginning of a character. */
            if (current == 0) {
                ended = TRUE;
                continue; /* Avoid counting this NUL byte as printable. */
            } else if ((current & 0x80) == 0) {
                if (!g_ascii_isprint(current)) {
                    if (!accept_crlf) {
                        // New line and chariot return or not valid in the method name
                        return -1;
                    }
                    if (current != '\r' && current != '\n') {
                        // But would have been acceptable for data content
                        return -1;
                    }
                }
            } else if ((current & 0xE0) == 0xC0) {
                /* 2 bytes code 8 to 11 bits */
                if (current >= 0xC2) {
                    remaining = 1;
                    min_next = 0x80;
                } else {
                    /* Overlong encoding of ASCII for C0 and C1. */
                    return -1;
                }
            } else if ((current & 0xF0) == 0xE0) {
                /* 3 bytes code 12 to 16 bits */
                remaining = 2;
                if (current == 0xE0) {
                    min_next = 0xA0; /* 0b101x xxxx to code at least 12 bits. */
                } else {
                    if (current == 0xED) {
                        /* Reject reserved UTF-16 surrogates as specified for UTF-8. */
                        max_next = 0x9F;
                    }
                    min_next = 0x80;
                }
            } else if ((current & 0xF8) == 0xF0) {
                /* 4 bytes code 17 to 21 bits */
                remaining = 3;
                if (current == 0xF0) {
                    min_next = 0x90; /* 0b1001 xxxx to code at least 17 bits. */
                } else if (current > 0xF4) {
                    /* Invalid leading byte (above U+10FFFF). */
                    return -1;
                } else {
                    min_next = 0x80;
                }
            } else {
                /* Not the beginning of an UTF-8 character. */
                return -1;
            }
            ++printable_len;
        } else {
            if ((current < min_next) || (max_next < current)) {
                /* Not a canonical UTF-8 character continuation. */
                return -1;
            }
            min_next = 0x80;
            max_next = 0xBF;
            --remaining;
            ++printable_len;
        }
    }
    return printable_len;
}


/*
 * Helper functions to use within custom sub-dissectors.
 *
 * Currently implemented:
 * - dissect_thrift_t_stop
 * - dissect_thrift_t_bool
 * - dissect_thrift_t_i8
 * - dissect_thrift_t_i16
 * - dissect_thrift_t_i32
 * - dissect_thrift_t_i64
 * - dissect_thrift_t_string
 * - dissect_thrift_t_binary
 * - dissect_thrift_t_struct
 * - dissect_thrift_t_map
 * - dissect_thrift_t_set
 * - dissect_thrift_t_list
 *
 * Behavior:
 * 1. Read and check the type at given offset.
 * 2. If requested, add the type and field id to the tree (internal thrift fields).
 */

int
dissect_thrift_t_stop(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{
    guint32 type;
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    type = tvb_get_guint8(tvb, offset);

    if (type != DE_THRIFT_T_STOP) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
        return THRIFT_SUBDISSECTOR_ERROR;
    }
    if (show_internal_thrift_fields) {
        proto_tree_add_item_ret_uint(tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &type);
    }
    offset += TBP_THRIFT_TYPE_LEN;

    return offset;
}

int
dissect_thrift_t_field_header(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, guint8 expected_type, int field_id _U_)
{
    guint8 type;
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    // We need to check the type only first in case we face the last T_STOP of the tvb.
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    type = tvb_get_guint8(tvb, offset);

    if (type != expected_type) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
        return THRIFT_SUBDISSECTOR_ERROR;
    }

    // Once we know it's not a T_STOP
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_FIELD_HEADER_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    if (show_internal_thrift_fields) {
        proto_tree_add_item(tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
        offset += TBP_THRIFT_TYPE_LEN;

        proto_tree_add_item(tree, hf_thrift_fid, tvb, offset, TBP_THRIFT_FID_LEN, ENC_BIG_ENDIAN);
        offset += TBP_THRIFT_FID_LEN;
    } else {
        offset += TBP_THRIFT_FIELD_HEADER_LEN;
    }
    return offset;
}

int
dissect_thrift_t_bool(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_BOOL, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_BOOL_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_BOOL_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_BOOL_LEN;

    return offset;
}

int
dissect_thrift_t_i8(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_I8, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I8_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I8_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_I8_LEN;

    return offset;
}

int
dissect_thrift_t_i16(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_I16, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I16_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I16_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_FID_LEN;

    return offset;
}

int
dissect_thrift_t_i32(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_I32, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I32_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I32_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_I32_LEN;

    return offset;
}

int
dissect_thrift_t_i64(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_I64, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_I64_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_I64_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_I64_LEN;

    return offset;
}

int
dissect_thrift_t_double(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_DOUBLE, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_DOUBLE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, TBP_THRIFT_DOUBLE_LEN, ENC_BIG_ENDIAN);
    offset += TBP_THRIFT_DOUBLE_LEN;

    return offset;
}

int
dissect_thrift_t_binary(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    return dissect_thrift_t_string_enc(tvb, pinfo, tree, offset, is_field, field_id, hf_id, ENC_NA);
}

int
dissect_thrift_t_string(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id)
{
    return dissect_thrift_t_string_enc(tvb, pinfo, tree, offset, is_field, field_id, hf_id, ENC_UTF_8|ENC_NA);
}

int
dissect_thrift_t_string_enc(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, guint encoding)
{
    gint32 str_len;
    proto_item *len_item = NULL;
    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_BINARY, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_LENGTH_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    if (show_internal_thrift_fields) {
        len_item = proto_tree_add_item_ret_int(tree, hf_thrift_str_len, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &str_len);
    } else {
        str_len = tvb_get_ntohil(tvb, offset);
    }
    if (str_len < 0) {
        expert_add_info(pinfo, len_item, &ei_thrift_negative_length);
        return THRIFT_SUBDISSECTOR_ERROR;
    }
    offset += TBP_THRIFT_LENGTH_LEN;
    if (tvb_reported_length_remaining(tvb, offset) < str_len) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, str_len, encoding);
    offset = offset + str_len;

    return offset;
}

int
dissect_thrift_t_member(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, const thrift_member_t *elt)
{
    switch (elt->type) {
    case DE_THRIFT_T_STOP:
        offset = dissect_thrift_t_stop(tvb, pinfo, tree, offset);
        break;
    case DE_THRIFT_T_BOOL:
        offset = dissect_thrift_t_bool(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_DOUBLE:
        offset = dissect_thrift_t_double(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I8:
        offset = dissect_thrift_t_i8(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I16:
        offset = dissect_thrift_t_i16(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I32:
        offset = dissect_thrift_t_i32(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_I64:
        offset = dissect_thrift_t_i64(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_BINARY:
        offset = dissect_thrift_t_string(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id);
        break;
    case DE_THRIFT_T_STRUCT:
        offset = dissect_thrift_t_struct(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.members);
        break;
    case DE_THRIFT_T_MAP:
        offset = dissect_thrift_t_map(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.m.key, elt->u.m.value);
        break;
    case DE_THRIFT_T_SET:
        offset = dissect_thrift_t_set(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.element);
        break;
    case DE_THRIFT_T_LIST:
        offset = dissect_thrift_t_list(tvb, pinfo, tree, offset, is_field, elt->fid, *elt->p_hf_id, *elt->p_ett_id, elt->u.element);
        break;
    default:
        REPORT_DISSECTOR_BUG("Unexpected Thrift type dissection requested.");
        break;
    }
    return offset;
}

int
dissect_thrift_t_struct(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, gint ett_id, const thrift_member_t *seq)
{
    proto_item *ti;
    proto_tree *sub_tree;

    guint8 type;
    guint16 fid;
    gboolean enable_subtree = (ett_id != DISABLE_SUBTREE) || (hf_id != DISABLE_SUBTREE);

    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, tree, offset, DE_THRIFT_T_STRUCT, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    if (enable_subtree) {
        /* Add the struct to the tree */
        if (show_internal_thrift_fields) {
            ti = proto_tree_add_item(tree, hf_id, tvb, offset, -1, ENC_BIG_ENDIAN);
            sub_tree = proto_item_add_subtree(ti, ett_id);
        } else {
            sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_id, &ti, proto_registrar_get_nth(hf_id)->name);
        }
    } else {
        /* Sub-dissector requested that we don't use a sub_tree.
         * This is useful for ME_THRIFT_T_REPLY or unions where we always have only 1 sub-element. */
        sub_tree = tree;
    }

    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }

    while (seq->type != DE_THRIFT_T_STOP) {
        // Read the type and check for the end of the structure
        type = tvb_get_guint8(tvb, offset);
        if (type == DE_THRIFT_T_STOP) {
            if (seq->optional) {
                seq++;
                continue;
            } else {
                proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_fid_not_in_seq, tvb, offset, TBP_THRIFT_TYPE_LEN);
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }
        // We've got a field with data: check the field id against what the sub-dissector expects
        if (tvb_reported_length_remaining(tvb, offset + TBP_THRIFT_TYPE_LEN) < TBP_THRIFT_FID_LEN) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        fid = tvb_get_ntohs(tvb, offset + TBP_THRIFT_TYPE_LEN);
        if (fid != seq->fid) {
            /* Wrong field in sequence*/
            if (seq->optional) {
                /* Skip to next element*/
                seq++;
                continue;
            } else {
                proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_fid_not_in_seq, tvb, offset, TBP_THRIFT_TYPE_LEN);
                return THRIFT_SUBDISSECTOR_ERROR;
            }
        }
        offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, TRUE, seq);
        ABORT_SUBDISSECTION_ON_ISSUE(offset);
        seq++;
    }

    offset = dissect_thrift_t_stop(tvb, pinfo, sub_tree, offset);

    if (enable_subtree && offset > 0) {
        proto_item_set_end(ti, tvb, offset);
    }

    return offset;
}

int
dissect_thrift_t_linear(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, gint ett_id, const thrift_member_t *elt, const thrift_member_t *value, thrift_type_enum_t expected)
{
    proto_item *ti = NULL;
    proto_tree *sub_tree;

    guint32 elt_type, val_type;
    gint32 length;

    if (show_internal_thrift_fields) {
        ti = proto_tree_add_item(tree, hf_id, tvb, offset, -1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(ti, ett_id);
    } else {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_id, &ti, proto_registrar_get_nth(hf_id)->name);
    }

    if (is_field) {
        offset = dissect_thrift_t_field_header(tvb, pinfo, sub_tree, offset, expected, field_id);
    }
    ABORT_SUBDISSECTION_ON_ISSUE(offset);
    /* Check the type of the elements (or type of the keys in case of map). */
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    elt_type = tvb_get_guint8(tvb, offset);
    if (show_internal_thrift_fields) {
        proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
    }
    if (elt_type != elt->type) {
        proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
        return THRIFT_SUBDISSECTOR_ERROR;
    }
    offset += TBP_THRIFT_TYPE_LEN;
    /* Check the type of the values in case of map. */
    if (expected == DE_THRIFT_T_MAP) {
        if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_TYPE_LEN) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        val_type = tvb_get_guint8(tvb, offset);
        if (show_internal_thrift_fields) {
            proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
        }
        if (val_type != value->type) {
            proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, TBP_THRIFT_TYPE_LEN);
            return THRIFT_SUBDISSECTOR_ERROR;
        }
        offset += TBP_THRIFT_TYPE_LEN;
    }
    /* Check the number of entry of the container. */
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_LENGTH_LEN) {
        return THRIFT_REQUEST_REASSEMBLY;
    }
    length = tvb_get_ntohil(tvb, offset);
    if (show_internal_thrift_fields) {
        gint hf_num_item;
        switch (expected) {
            case DE_THRIFT_T_MAP:
                hf_num_item = hf_thrift_num_map_item;
                break;
            case DE_THRIFT_T_SET:
                hf_num_item = hf_thrift_num_set_item;
                break;
            case DE_THRIFT_T_LIST:
                hf_num_item = hf_thrift_num_list_item;
                break;
            default:
                return THRIFT_SUBDISSECTOR_ERROR;
        }
        ti = proto_tree_add_item_ret_int(sub_tree, hf_num_item, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &length);
    }
    offset += TBP_THRIFT_LENGTH_LEN;
    if (length < 0) {
        expert_add_info(pinfo, ti, &ei_thrift_negative_length);
        return THRIFT_SUBDISSECTOR_ERROR;
    }

    /* Read the content of the container. */
    for(int i = 0; i < length; ++i) {
        offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, FALSE, elt);
        if (expected == DE_THRIFT_T_MAP) {
            offset = dissect_thrift_t_member(tvb, pinfo, sub_tree, offset, FALSE, value);
        }
        // Avoid continuing the loop if anything went sideways.
        ABORT_SUBDISSECTION_ON_ISSUE(offset);
    }
    if (ti && offset > 0) {
        proto_item_set_end(ti, tvb, offset);
    }
    return offset;
}

int
dissect_thrift_t_set(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *elt)
{
    return dissect_thrift_t_linear(tvb, pinfo, tree, offset, is_field, field_id, hf_id, ett_id, elt, NULL, DE_THRIFT_T_SET);
}

int
dissect_thrift_t_list(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *elt)
{
    return dissect_thrift_t_linear(tvb, pinfo, tree, offset, is_field, field_id, hf_id, ett_id, elt, NULL, DE_THRIFT_T_LIST);
}

int
dissect_thrift_t_map(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *key, const thrift_member_t *value)
{
    return dissect_thrift_t_linear(tvb, pinfo, tree, offset, is_field, field_id, hf_id, ett_id, key, value, DE_THRIFT_T_MAP);
}

/*
 * Generic functions for when there is no custom sub-dissector.
 *
 * +--------------------+--------------------------+---------------------+
 * | offset   \  return | REQUEST_REASSEMBLY = -1  | Length              |
 * +--------------------+--------------------------+---------------------+
 * | REQUEST_REASSEMBLY | Reassembly required      | SHALL NEVER HAPPEN! |
 * +--------------------+--------------------------+---------------------+
 * | Length             | Error occurred at offset | Full command parsed |
 * +--------------------+--------------------------+---------------------+
 */

static int
dissect_thrift_binary(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int* offset, thrift_option_data_t *thrift_opt)
{
    gint32 str_len;
    proto_item *pi;
    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_BINARY_LEN);
    pi = proto_tree_add_item_ret_int(tree, hf_thrift_str_len, tvb, *offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &str_len);
    *offset += TBP_THRIFT_LENGTH_LEN;

    if (str_len < 0) {
        expert_add_info(pinfo, pi, &ei_thrift_negative_length);
        return THRIFT_REQUEST_REASSEMBLY;
    }
    ABORT_ON_INCOMPLETE_PDU(str_len); /* Thrift assumes there will never be string >= 2GiB */

    if (tree) {
        switch (binary_decode) {
            case DECODE_BINARY_AS_UTF32LE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UCS_4 | ENC_LITTLE_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF32BE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UCS_4 | ENC_BIG_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF16LE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF16BE:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_16 | ENC_BIG_ENDIAN);
                break;
            case DECODE_BINARY_AS_UTF8:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_8|ENC_NA);
                break;
            case DECODE_BINARY_AS_ASCII:
                proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_ASCII|ENC_NA);
                break;
            case DECODE_BINARY_AS_AUTO_UTF8:
                /* When there is no data at all, consider it a string
                 * but a buffer containing only NUL bytes is a buffer.
                 * If not entirely captured, consider it as a binary. */
                if (tvb_captured_length_remaining(tvb, *offset) >= str_len &&
                    (str_len == 0 || thrift_binary_utf8_isprint(tvb, *offset, str_len, TRUE) > 0)) {
                    proto_tree_add_item(tree, hf_thrift_string, tvb, *offset, str_len, ENC_UTF_8|ENC_NA);
                    break;
                }
                /* otherwise, continue with type BINARY */
                /* FALL THROUGH */
            case DECODE_BINARY_AS_BINARY:
            default:
                proto_tree_add_item(tree, hf_thrift_binary, tvb, *offset, str_len, ENC_NA);
        }
    }
    *offset += str_len;

    return *offset;
}

static int
dissect_thrift_list(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int* offset, thrift_option_data_t *thrift_opt)
{
    proto_tree *sub_tree;
    proto_item *ti, *type_pi;
    guint32 type;
    gint32 list_len, i;

    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_LIST_LEN);
    ti = proto_tree_add_item(tree, hf_thrift_list, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_thrift_list);

    type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, *offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &type);
    *offset += TBP_THRIFT_TYPE_LEN;
    proto_tree_add_item_ret_int(sub_tree, hf_thrift_num_list_item, tvb, *offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &list_len);
    *offset += TBP_THRIFT_LENGTH_LEN;

    for (i = 0; i < list_len; ++i) {
        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
    }
    proto_item_set_end(ti, tvb, *offset);

    return *offset;
}

static int
dissect_thrift_set(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int* offset, thrift_option_data_t *thrift_opt)
{
    proto_tree *sub_tree;
    proto_item *ti, *type_pi;
    guint32 type;
    gint32 set_len, i;

    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_SET_LEN);
    ti = proto_tree_add_item(tree, hf_thrift_set, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_thrift_set);

    type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, *offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &type);
    *offset += TBP_THRIFT_TYPE_LEN;
    proto_tree_add_item_ret_int(sub_tree, hf_thrift_num_set_item, tvb, *offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &set_len);
    *offset += TBP_THRIFT_LENGTH_LEN;

    for (i = 0; i < set_len; ++i) {
        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
    }
    proto_item_set_end(ti, tvb, *offset);

    return *offset;
}


static int
dissect_thrift_struct(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int* offset, thrift_option_data_t *thrift_opt)
{
    proto_tree *sub_tree;
    proto_item *ti, *type_pi;
    guint32 type;

    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_STRUCT_LEN);
    ti = proto_tree_add_item(tree, hf_thrift_struct, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_thrift_struct);

    while (TRUE) {
        /* Read type and field id */
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_TYPE_LEN);
        type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, *offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &type);
        *offset += TBP_THRIFT_TYPE_LEN;
        if (type == DE_THRIFT_T_STOP) {
            /* T_STOP */
            proto_item_set_end(ti, tvb, *offset);
            break;
        }
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_FID_LEN);
        proto_tree_add_item(sub_tree, hf_thrift_fid, tvb, *offset, TBP_THRIFT_FID_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_FID_LEN;
        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
    }

    return *offset;
}

static int
dissect_thrift_map(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int* offset, thrift_option_data_t *thrift_opt)
{
    proto_tree *sub_tree;
    proto_item *ti, *ktype_pi, *vtype_pi;
    guint32 ktype;
    guint32 vtype;
    gint32 map_len, i;

    ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_MAP_LEN);
    ti = proto_tree_add_item(tree, hf_thrift_map, tvb, *offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_thrift_map);

    ktype_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_key_type, tvb, *offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &ktype);
    *offset += TBP_THRIFT_TYPE_LEN;
    vtype_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_value_type, tvb, *offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &vtype);
    *offset += TBP_THRIFT_TYPE_LEN;
    proto_tree_add_item_ret_int(sub_tree, hf_thrift_num_map_item, tvb, *offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN, &map_len);
    *offset += TBP_THRIFT_LENGTH_LEN;

    for (i = 0; i < map_len; ++i) {
        if ((dissect_thrift_type(tvb, pinfo, sub_tree, ktype_pi, ktype, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) ||
            (dissect_thrift_type(tvb, pinfo, sub_tree, vtype_pi, vtype, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY)) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
    }
    proto_item_set_end(ti, tvb, *offset);

    return *offset;
}

static int
dissect_thrift_type(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* pi, int type, int* offset, thrift_option_data_t *thrift_opt)
{
    switch (type) {
    case DE_THRIFT_T_BOOL:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_BOOL_LEN);
        /* T_BOOL Boolean */
        proto_tree_add_item(tree, hf_thrift_bool, tvb, *offset, TBP_THRIFT_BOOL_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_BOOL_LEN;
        break;
    case DE_THRIFT_T_I8:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I8_LEN);
        /* T_BYTE = T_I8 8-bit signed integer */
        proto_tree_add_item(tree, hf_thrift_i8, tvb, *offset, TBP_THRIFT_I8_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I8_LEN;
        break;
    case DE_THRIFT_T_DOUBLE:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_DOUBLE_LEN);
        /* T_DOUBLE Double */
        proto_tree_add_item(tree, hf_thrift_double, tvb, *offset, TBP_THRIFT_DOUBLE_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_DOUBLE_LEN;
        break;
    case DE_THRIFT_T_I16:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I16_LEN);
        /* T_I16 16-bit signed integer */
        proto_tree_add_item(tree, hf_thrift_i16, tvb, *offset, TBP_THRIFT_I16_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I16_LEN;
        break;
    case DE_THRIFT_T_I32:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I32_LEN);
        /* T_I32 32-bit signed integer */
        proto_tree_add_item(tree, hf_thrift_i32, tvb, *offset, TBP_THRIFT_I32_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I32_LEN;
        break;
    case DE_THRIFT_T_I64:
        ABORT_ON_INCOMPLETE_PDU(TBP_THRIFT_I64_LEN);
        /* T_I64 64-bit signed integer */
        proto_tree_add_item(tree, hf_thrift_i64, tvb, *offset, TBP_THRIFT_I64_LEN, ENC_BIG_ENDIAN);
        *offset += TBP_THRIFT_I64_LEN;
        break;
    case DE_THRIFT_T_BINARY:
        /* T_BINARY Binary blob */
        if (dissect_thrift_binary(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_STRUCT:
        /* T_STRUCT Structured data */
        if (dissect_thrift_struct(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_MAP:
        /* T_MAP key->value map */
        if (dissect_thrift_map(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_SET:
        /* T_SET Set of elements (no repetition, no order) */
        if (dissect_thrift_set(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    case DE_THRIFT_T_LIST:
        /* T_LIST List of elements (possible repetition, order sensitive) */
        if (dissect_thrift_list(tvb, pinfo, tree, offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            return THRIFT_REQUEST_REASSEMBLY;
        }
        break;
    default:
        /* Bail out */
        expert_add_info(pinfo, pi, &ei_thrift_wrong_type);
        return THRIFT_REQUEST_REASSEMBLY;
    }

    return *offset;
}

/*
 * End of generic functions
 */

/*
Binary protocol Message, strict encoding, 13+ bytes:
   +--------+--------+--------+--------++--------+--------+--------+--------++--------+...+--------++--------+--------+--------+--------++...++--------+
   |1vvvvvvv|vvvvvvvv|unused  |00000mmm|| name length                       || name                || seq id                            ||   || T_STOP |
   +--------+--------+--------+--------++--------+--------+--------+--------++--------+...+--------++--------+--------+--------+--------++...++--------+

   Where:

   * 'vvvvvvvvvvvvvvv' is the version, an unsigned 15 bit number fixed to '1' (in binary: '000 0000 0000 0001'). The leading bit is 1.
   * Although for consistency with Compact protocol, we will use |pppppppp|000vvvvv| instead in the display:
   *       'pppppppp' = 0x80 for the protocol id and
   *       '000' 3 zeroed bits as mandated by the specs.
   *       'vvvvv' 5 bits for the version (see below).
   * 'unused' is an ignored byte.
   * 'mmm' is the message type, an unsigned 3 bit integer.
   *       The 5 leading bits must be '0' as some clients take the whole byte.
   *       (checked for java in 0.9.1)
   * 'name length' is the byte length of the name field, a signed 32 bit integer encoded in network (big endian) order (must be >= 0).
   * 'name' is the method name, an UTF-8 encoded string.
   * 'seq id' is the sequence id, a signed 32 bit integer encoded in network (big endian) order.

Binary protocol Message, old encoding, 9+ bytes:
   +--------+--------+--------+--------++--------+...+--------++--------++--------+--------+--------+--------++...++--------+
   | name length                       || name                ||00000mmm|| seq id                            ||   || T_STOP |
   +--------+--------+--------+--------++--------+...+--------++--------++--------+--------+--------+--------++...++--------+

   Where name length, name, mmm, seq id are the same as above.

   Because name length must be positive (therefore the first bit is always 0),
   the first bit allows the receiver to see whether the strict format or the old format is used.

Note: Double separators indicate how the Thrift parts are sent on the wire depending on the network settings.
      There are clients and server in production that do not squeeze as much data as possible in a packet
      but push each Thrift write<Type>() call directly to the wire, making it harder to detect
      as we only have 4 bytes in the first packet.

Compact protocol Message (4+ bytes): (/!\ Not handled by current implementation).
   +--------+--------+--------+...+--------+--------+...+--------+--------+...+--------+...+--------+
   |pppppppp|mmmvvvvv| seq id              | name length         | name                |   | T_STOP |
   +--------+--------+--------+...+--------+--------+...+--------+--------+...+--------+...+--------+

   Where:

   * 'pppppppp' is the protocol id, fixed to '1000 0010', 0x82.
   * 'mmm' is the message type, an unsigned 3 bit integer.
   * 'vvvvv' is the version, an unsigned 5 bit integer, fixed to '00001'.
   * 'seq id' is the sequence id, a signed 32 bit integer encoded as a varint.
   * 'name length' is the byte length of the name field, a signed 32 bit integer encoded as a varint (must be >= 0).
   * 'name' is the method name to invoke, an UTF-8 encoded string.

Framed Transport can encapsulate any protocol version:
   +--------+--------+--------+--------+--------+...+--------+--------+
   | message length                    | Any protocol message, T_STOP |
   +--------+--------+--------+--------+--------+...+--------+--------+
                                       |<------ message length ------>|

   Message types are encoded with the following values:

   * _Call_: 1
   * _Reply_: 2
   * _Exception_: 3
   * _Oneway_: 4
 */

/* Dissect a unique Thrift TBinaryProtocol PDU and return the effective length of this PDU.
 *
 * This method is called only if the preliminary verifications have been done so it will use as
 * much data as possible and will return THRIFT_REQUEST_REASSEMBLY and ask for reassembly if there is
 * not enough data.
 *
 * In case of TFramedTransport, tcp_dissect_pdus made sure that we had all necessary data so reassembly
 * will fail if the effective data is bigger than the frame which is a real error.
 *
 * Returns:
 * - THRIFT_REQUEST_REASSEMBLY = -1 if reassembly is required
 * -                              0 if an error occured
 * -                     offset > 0 to indicate the end of the PDU in case of success
 *
 * This method MUST be called with non-null thrift_opt. */
static int
dissect_thrift_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int start_offset, thrift_option_data_t *thrift_opt)
{
    proto_tree *thrift_tree, *sub_tree;
    proto_item *thrift_pi, *data_pi, *type_pi;
    int offset = start_offset;
    int header_offset = 0, data_offset = 0;
    gint32 str_len, type;
    guint8 mtype;
    guint16 version;
    gint32 seq_id, fid;
    guint8 *method_str;
    int remaining;
    tvbuff_t *msg_tvb;
    int len, tframe_length = 0;
    gboolean is_framed;

    /* Get the current state of dissection. */
    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);
    DISSECTOR_ASSERT(thrift_opt->tprotocol & PROTO_THRIFT_BINARY);

    is_framed = thrift_opt->tprotocol & PROTO_THRIFT_FRAMED;
    /* Create the item now in case of malformed buffer to use with expert_add_info() */
    thrift_pi = proto_tree_add_item(tree, proto_thrift, tvb, offset, -1, ENC_NA);
    thrift_tree = proto_item_add_subtree(thrift_pi, ett_thrift);

    if (is_framed) {
        /* Thrift documentation indicates a maximum of 16 MB frames by default.
         * Configurable since Thrift 0.14.0 so better stay on the safe side.
         * We are more tolerant with 2 GiB. */
        /* TODO: Add a dissector parameter using the same default as Thrift? */
        /* TODO: If we do, check the length in test_thrift_strict as well
         * (might be useful for compact detection). */
        tframe_length = tvb_get_ntohil(tvb, offset);
        if (tframe_length <= 0) {
            thrift_tree = proto_item_add_subtree(thrift_pi, ett_thrift_error);
            data_pi = proto_tree_add_item(thrift_tree, hf_thrift_frame_length, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            expert_add_info(pinfo, data_pi, &ei_thrift_negative_length);
            return 0;
        }
        proto_item_set_len(thrift_pi, TBP_THRIFT_LENGTH_LEN + tframe_length);
        /* Keep the same start point to avoid awkward offset calculations */
        offset += TBP_THRIFT_LENGTH_LEN;
    }

    header_offset = offset;
    remaining = tvb_reported_length_remaining(tvb, offset);
    /* We should be called only when the entire frame is ready
     * so we don't need to verify if we have enough data.
     * If not framed, anything remaining is obviously greater than 0. */
    DISSECTOR_ASSERT(remaining >= tframe_length);

    /* Decode the header depending on strict (new) or old. */
    if (thrift_opt->tprotocol & PROTO_THRIFT_STRICT) {
        if (remaining < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN) {
            proto_tree_add_expert(thrift_tree, pinfo, &ei_thrift_not_enough_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
            goto reassemble_pdu;
        }
        version = tvb_get_ntohs(tvb, offset) & THRIFT_VERSION_VALUE_MASK;
        mtype = tvb_get_guint8(tvb, offset + TBP_THRIFT_MTYPE_OFFSET) & THRIFT_MESSAGE_MASK;
        str_len = tvb_get_ntohil(tvb, offset + TBP_THRIFT_VERSION_LEN);
        if (str_len < 0) {
            expert_add_info(pinfo, thrift_pi, &ei_thrift_negative_length);
            return 0;
        }
        if (remaining < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN + str_len) {
            proto_tree_add_expert(thrift_tree, pinfo, &ei_thrift_not_enough_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
            goto reassemble_pdu;
        }
        offset += TBP_THRIFT_VERSION_LEN + TBP_THRIFT_LENGTH_LEN;
        method_str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
    } else {
        if (remaining < TBP_THRIFT_MIN_MESSAGE_LEN) {
            proto_tree_add_expert(thrift_tree, pinfo, &ei_thrift_not_enough_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
            goto reassemble_pdu;
        }
        version = 0;
        str_len = tvb_get_ntohil(tvb, offset);
        if (str_len < 0) {
            expert_add_info(pinfo, thrift_pi, &ei_thrift_negative_length);
            return 0;
        }
        if (remaining < TBP_THRIFT_MIN_MESSAGE_LEN + str_len) {
            proto_tree_add_expert(thrift_tree, pinfo, &ei_thrift_not_enough_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
            goto reassemble_pdu;
        }
        offset += TBP_THRIFT_LENGTH_LEN;
        method_str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, str_len, ENC_UTF_8|ENC_NA);
        offset += str_len;
        mtype = tvb_get_guint8(tvb, offset + TBP_THRIFT_LENGTH_LEN + str_len) & THRIFT_MESSAGE_MASK;
        offset += TBP_THRIFT_TYPE_LEN;
    }

    /* TODO: Save (non-null?) seq_id to link CALL and REPLY|EXCEPTION. */
    /* TODO: In case of non-null seq_id, indicate that it must always be saved (to track the null one as well). */
    /* TODO: Track the command name as well? Act differently for null & non-null seq_id? */
    seq_id = tvb_get_ntohil(tvb, offset);
    offset += TBP_THRIFT_SEQ_ID_LEN;

    data_offset = offset;

    /* Can be used in case of error, in particular when TFramedTransport is in use. */
    thrift_opt->reassembly_tree = thrift_tree;
    thrift_opt->reassembly_offset = start_offset;
    thrift_opt->reassembly_length = -1;
    thrift_opt->mtype = (thrift_method_type_enum_t)mtype;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s %s", val_to_str(mtype, thrift_mtype_vals, "%d"), method_str);

    if (thrift_tree) {
        offset = start_offset; /* Reset parsing position. */
        if (is_framed) {
            proto_tree_add_item(thrift_tree, hf_thrift_frame_length, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_LENGTH_LEN;
        }
        sub_tree = proto_tree_add_subtree_format(thrift_tree, tvb, header_offset, data_offset - header_offset, ett_thrift_header, NULL,
                "%s [version: %d, seqid: %d, method: %s]",
                val_to_str(mtype, thrift_mtype_vals, "%d"),
                version, seq_id, method_str);
        if (thrift_opt->tprotocol & PROTO_THRIFT_STRICT) {
            /* Strict: proto_id|version|mtype|length|name|seqid */
            proto_tree_add_item(sub_tree, hf_thrift_protocol_id, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN);
            proto_tree_add_bits_item(sub_tree, hf_thrift_version, tvb, offset * 8 + 11, 5, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_MTYPE_OFFSET;
            proto_tree_add_bits_item(sub_tree, hf_thrift_mtype, tvb, offset * 8 + 5, 3, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_MTYPE_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_str_len, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_LENGTH_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_method, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset = offset + str_len;
            proto_tree_add_item(sub_tree, hf_thrift_seq_id, tvb, offset, TBP_THRIFT_SEQ_ID_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_SEQ_ID_LEN;
        } else {
            /* Old: length|name|mtype|seqid */
            proto_tree_add_item(sub_tree, hf_thrift_str_len, tvb, offset, TBP_THRIFT_LENGTH_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_LENGTH_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_method, tvb, offset, str_len, ENC_UTF_8|ENC_NA);
            offset = offset + str_len;
            proto_tree_add_bits_item(sub_tree, hf_thrift_mtype, tvb, offset * 8 + 5, 3, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_MTYPE_LEN;
            proto_tree_add_item(sub_tree, hf_thrift_seq_id, tvb, offset, TBP_THRIFT_SEQ_ID_LEN, ENC_BIG_ENDIAN);
            offset += TBP_THRIFT_SEQ_ID_LEN;
        }
        DISSECTOR_ASSERT(offset == data_offset);
    }

    if (tvb_reported_length_remaining(tvb, data_offset) < TBP_THRIFT_TYPE_LEN) {
        proto_tree_add_expert(thrift_tree, pinfo, &ei_thrift_not_enough_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
        goto reassemble_pdu;
    }

    /* Call method dissector here using dissector_try_string() */
    msg_tvb = tvb_new_subset_remaining(tvb, data_offset);
    if (mtype != ME_THRIFT_T_EXCEPTION) {
        if (pinfo->can_desegment > 0) pinfo->can_desegment++;
        len = dissector_try_string(thrift_method_name_dissector_table, method_str, msg_tvb, pinfo, tree, thrift_opt);
        if (pinfo->can_desegment > 0) pinfo->can_desegment--;
    } else {
        /* Leverage the sub-dissector capabilities to dissect Thrift exceptions. */
        len = dissect_thrift_t_struct(msg_tvb, pinfo, thrift_tree, 0, FALSE, 0, hf_thrift_exception, ett_thrift_exception, thrift_exception);
    }
    if (len > 0) {
        /* The sub dissector dissected the tvb*/
        if (!is_framed) {
            proto_item_set_end(thrift_pi, msg_tvb, len);
        }
        return data_offset + len;
    } else if (len == THRIFT_REQUEST_REASSEMBLY) {
        /* The sub-dissector requested more bytes (len = -1) */
        goto reassemble_pdu;
    } else if (len <= THRIFT_SUBDISSECTOR_ERROR) {
        if (!try_generic_if_sub_dissector_fails) {
            return 0;
        }
        // Fallback to dissect using the generic dissector.
    }
    /* len = 0, no sub-dissector */
    sub_tree = proto_tree_add_subtree(thrift_tree, tvb, data_offset, -1, ett_thrift_params, &data_pi, "Data");
    thrift_opt->reassembly_length = TBP_THRIFT_TYPE_LEN;
    while (tvb_reported_length_remaining(tvb, offset) >= TBP_THRIFT_TYPE_LEN) {
        /*Read type and field id */
        type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, TBP_THRIFT_TYPE_LEN, ENC_BIG_ENDIAN, &type);
        offset += TBP_THRIFT_TYPE_LEN;
        if (type == DE_THRIFT_T_STOP) {
            /* The only successful exit case. */
            if (!is_framed) {
                /* In case the frame is larger than the data... */
                proto_item_set_end(thrift_pi, tvb, offset);
            }
            proto_item_set_end(data_pi, tvb, offset);
            return offset;
        }
        if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_FID_LEN) {
            thrift_opt->reassembly_offset = offset;
            thrift_opt->reassembly_length = TBP_THRIFT_FID_LEN;
            break;
        }
        proto_tree_add_item_ret_int(sub_tree, hf_thrift_fid, tvb, offset, TBP_THRIFT_FID_LEN, ENC_BIG_ENDIAN, &fid);
        offset += TBP_THRIFT_FID_LEN;
        if (thrift_opt->mtype == ME_THRIFT_T_REPLY && fid != 0) {
            /* For REPLY, in order to separate successful answers from errors (exceptions),
             * Thrift generates a struct with as much fields (all optional) as there are exceptions possible + 1.
             * At most 1 field will be filled for any reply
             * - Field id = 0: The effective type of the return value of the method (not set if void).
             * - Field id > 0: The number of the exception that was raised by the method.
             *   Note: This is different from the ME_THRIFT_T_EXCEPTION method type that is used in case the method is unknown
             *         or the PDU invalid/impossible to decode for the other endpoint.
             */
            proto_item_set_text(data_pi, "Exception: %d", fid);
        }

        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, &offset, thrift_opt) == THRIFT_REQUEST_REASSEMBLY) {
            if (offset > 0) {
                /* An error occurred at the given offset */
                if (!is_framed) {
                    /* Just set the Thrift tree to eat all available data. */
                    proto_item_set_end(thrift_pi, tvb, offset);
                }
                proto_item_set_end(data_pi, tvb, offset);
                // Consume everything
                return tvb_reported_length(tvb);
            }
            goto reassemble_pdu;
        }
        // Set it in case the loop exits
        thrift_opt->reassembly_offset = offset;
        thrift_opt->reassembly_length = TBP_THRIFT_TYPE_LEN;
    }
    proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_not_enough_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
reassemble_pdu:
    /* We did not encounter final T_STOP. */
    pinfo->desegment_offset = start_offset;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return THRIFT_REQUEST_REASSEMBLY;
}

/* For tcp_dissect_pdus. */
static guint
get_framed_thrift_pdu_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void *data _U_)
{
    return (guint)TBP_THRIFT_LENGTH_LEN + tvb_get_ntohl(tvb, offset);
}

/* Effective dissection once the exact encoding has been determined.
 * - Calls dissect_thrift_common in a loop until end of a packet matches end of Thrift PDU.
 */
static int
dissect_thrift_loop(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, thrift_option_data_t *thrift_opt)
{
    gint32 offset = 0;
    gint32 hdr_offset = 0;
    gint32 last_pdu_start_offset = 0;
    gint32 remaining = tvb_reported_length_remaining(tvb, offset);

    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);

    // loop until the end of the packet coincides with the end of a PDU.
    while (remaining > 0) {
        last_pdu_start_offset = offset;
        if (remaining < TBP_THRIFT_LENGTH_LEN) {
            goto reassemble_pdu;
        }
        if (thrift_opt->tprotocol & PROTO_THRIFT_BINARY)
        {
            /* According to Thrift documentation, old and new (strict) binary protocols
             * could coexist on a single server so we cannot assume it's still the same.
             * In particular, client could send a first request in old format to get
             * the server version and switch to strict if the server is up-to-date
             * or if it rejected explicitly the old format (there's an example for that). */
            if (tvb_get_gint8(tvb, offset + hdr_offset) < 0) {
                /* Strict header (If only the message type is incorrect, assume this is a new one. */
                if (!is_thrift_strict_version(tvb_get_ntohl(tvb, offset + hdr_offset), TRUE)) {
                    expert_add_info(pinfo, NULL, &ei_thrift_wrong_proto_version);
                    return tvb_reported_length_remaining(tvb, 0);
                }
                thrift_opt->tprotocol = (thrift_protocol_enum_t)(thrift_opt->tprotocol | PROTO_THRIFT_STRICT);
            } else {
                /* Old header. */
                thrift_opt->tprotocol = (thrift_protocol_enum_t)(thrift_opt->tprotocol & ~PROTO_THRIFT_STRICT);
            }
            offset = dissect_thrift_common(tvb, pinfo, tree, offset, thrift_opt);
        } else if (thrift_opt->tprotocol & PROTO_THRIFT_COMPACT) {
            /* TODO: Implement TCompactProtocol */
            REPORT_DISSECTOR_BUG("Dissector loop should not be called with unsupported protocol variant.");
        }

        if (offset == THRIFT_REQUEST_REASSEMBLY) {
            goto reassemble_pdu;
        } else if (offset == 0) {
            /* An error occurred, we just stop, consuming everything. */
            return tvb_reported_length_remaining(tvb, 0);
        }
        remaining = tvb_reported_length_remaining(tvb, offset);
    }
    return offset;
reassemble_pdu:
    /* We did not encounter a final T_STOP exactly at the last byte. */
    pinfo->desegment_offset = last_pdu_start_offset;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return tvb_reported_length(tvb);
}

/* Dissect a unique Thrift TBinaryProtocol PDU within a TFramedTransport and return the effective length of this PDU.
 *
 * This method is called only if the preliminary verifications have been done including length.
 * This method will throw if there is not enough data or too much data.
 *
 * This method MUST be called with non-null thrift_opt/data using thrift_option_data_t effective type. */
static int
dissect_thrift_framed(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void *data)
{
    gint32 offset = 0;
    gint32 frame_len = 0;
    gint32 reported = tvb_reported_length_remaining(tvb, offset);
    thrift_option_data_t *thrift_opt = (thrift_option_data_t *)data;

    DISSECTOR_ASSERT(thrift_opt);
    DISSECTOR_ASSERT(thrift_opt->canary == THRIFT_OPTION_DATA_CANARY);
    DISSECTOR_ASSERT(thrift_opt->tprotocol & PROTO_THRIFT_FRAMED);
    frame_len = tvb_get_ntohil(tvb, offset);
    DISSECTOR_ASSERT((frame_len + TBP_THRIFT_LENGTH_LEN) == reported);

    offset = dissect_thrift_common(tvb, pinfo, tree, offset, thrift_opt);
    if (offset == THRIFT_REQUEST_REASSEMBLY) {
        // No reassembly possible in this case
        proto_tree_add_expert(thrift_opt->reassembly_tree, pinfo, &ei_thrift_frame_too_short,
                tvb, thrift_opt->reassembly_offset, thrift_opt->reassembly_length);
        pinfo->desegment_offset = reported;
        pinfo->desegment_len = 0;
    } else if (offset > 0 && tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(thrift_opt->reassembly_tree, pinfo, &ei_thrift_frame_too_long,
                tvb, offset, tvb_reported_length_remaining(tvb, offset));
    }
    return reported;
}

/* Thrift dissection when forced by Decode As… or port selection */
static int
dissect_thrift_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void *data _U_)
{
    gint32 str_len, length = tvb_reported_length(tvb);
    thrift_option_data_t thrift_opt;
    memset(&thrift_opt, 0, sizeof(thrift_option_data_t));

    /* Starting without even the version / frame length / name length probably means a Keep-Alive at the beginning of the capture. */
    if (length < TBP_THRIFT_VERSION_LEN) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_not_enough_data, tvb, 0, length);
        /* Not a Thrift packet, maybe a keep-alive at the beginning of the capture. */
        return NOT_A_VALID_PDU;
    }
    /* Need at least the old encoding header (Name Length + Method + Sequence Id) + ending T_STOP */
    if (length < TBP_THRIFT_MIN_MESSAGE_LEN) {
        /* Note: if Nagle algorithm is not active, some systems can spit out Thrift individual elements one by one.
         * For instance on strict protocol:
         * Frame x+0: 4 bytes = version + method type (sent using writeI32)
         * Frame x+1: 4 bytes = method length
         * Frame x+2: n bytes = method name
         * Frame x+3: 4 bytes = sequence id
         * Frame x+4: 1 byte  = field type… */
        goto reassemble_pdu;
    }

    /* MSb of first byte is 1 for compact and binary strict protocols
     * and 0 for framed transport and old binary protocol. */
    if (tvb_get_gint8(tvb, 0) >= 0) {
        /* Option 1 = old binary
         * Option 2 = framed strict binary
         * Option 3 = framed old binary
         * Option 4 = framed compact or anything  not handled. */
        int remaining = tvb_reported_length_remaining(tvb, TBP_THRIFT_LENGTH_LEN); // Remaining after initial 4 bytes of "length"
        /* Old header. */
        str_len = tvb_get_ntohil(tvb, 0);

        if (remaining == 0) {
            // The endpoint probably does not have Nagle activated, wait for next packet.
            goto reassemble_pdu;
        }
        /* Checking for old binary option. */
        if (remaining < str_len) {
            /* Not enough data to check name validity.
             * Even without Nagle activated, this is /not/ plain old binary Thrift data (or method name is awfully long).
             * Non-framed old binary is not possible, consider framed data only. */
            // TODO: Display available data & error in case we can't reassemble?
            pinfo->desegment_len = str_len - remaining;
            /* Maybe we should return NOT_A_VALID_PDU instead and drop this packet but port preferences tells us this /is/ Thrift data. */
            return THRIFT_REQUEST_REASSEMBLY;
        }

        if (thrift_binary_utf8_isprint(tvb, TBP_THRIFT_LENGTH_LEN, str_len, FALSE) == str_len) {
            // UTF-8 valid data means first byte is greater than 0x20 and not between 0x80 and 0xbf (neither 0x80 nor 0x82 in particular).
            // This would indicate a method name longer than 512 MiB in Framed old binary protocol which is insane.
            // Therefore, most sane option is old binary without any framing.
            thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
            thrift_opt.tprotocol = PROTO_THRIFT_BINARY;
            /* Name length + name + method + seq_id + T_STOP */
            if (length < TBP_THRIFT_MIN_MESSAGE_LEN + str_len) {
                goto reassemble_pdu;
            }
        } else {
            // This cannot be non-framed old binary so it must be framed (and we have all of it).
            if (str_len < TBP_THRIFT_MIN_MESSAGE_LEN) {
                /* This is /not/ valid Framed data. */
                return NOT_A_VALID_PDU;
            }
            if (tvb_get_gint8(tvb, TBP_THRIFT_LENGTH_LEN) >= 0) {
                // Framed old binary format is the only matching option remaining.
                thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
                thrift_opt.tprotocol = (thrift_protocol_enum_t)(PROTO_THRIFT_FRAMED | PROTO_THRIFT_BINARY);
            } else {
                if (is_thrift_strict_version(tvb_get_ntohl(tvb, TBP_THRIFT_LENGTH_LEN), TRUE)) {
                    // Framed strict binary protocol.
                    thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
                    thrift_opt.tprotocol = (thrift_protocol_enum_t)(PROTO_THRIFT_FRAMED | PROTO_THRIFT_BINARY | PROTO_THRIFT_STRICT);
                } else {
                    // Framed compact protocol or something else entirely, bail out.
                    return NOT_A_VALID_PDU;
                }
            }
        }
    } else if (is_thrift_strict_version(tvb_get_ntohl(tvb, 0), TRUE)) {
        /* We don't need all the checks from the heuristic because the user prefs told us it /is/ Thrift data.
         * If it fails, it will probably pass through otherwise hard-to-reach code-paths so that's good for tests. */
        thrift_opt.canary = THRIFT_OPTION_DATA_CANARY;
        thrift_opt.tprotocol = (thrift_protocol_enum_t)(PROTO_THRIFT_BINARY | PROTO_THRIFT_STRICT);
    } else {
        /* Either compact protocol (0x82) or unknown. */
        /* if (tvb_get_guint8(tvb, 0) == 0x82) { thrift_opt.tprotocol = PROTO_THRIFT_COMPACT; } */
        /* else { Not a Thrift packet. } */
        return NOT_A_VALID_PDU;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "THRIFT");
    col_clear(pinfo->cinfo, COL_INFO);

    if (thrift_opt.tprotocol & PROTO_THRIFT_FRAMED) {
        tcp_dissect_pdus(tvb, pinfo, tree, framed_desegment, TBP_THRIFT_LENGTH_LEN,
                get_framed_thrift_pdu_len, dissect_thrift_framed, &thrift_opt);
        return tvb_reported_length(tvb);
    } else {
        return dissect_thrift_loop(tvb, pinfo, tree, &thrift_opt);
    }

reassemble_pdu:
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return THRIFT_REQUEST_REASSEMBLY;
}

/* Test if the captured packet matches a Thrift strict binary packet header.
 * We check for captured and not reported length because:
 * - We need to check the content to verify validity;
 * - We must not have exception in heuristic dissector.
 * Due to that, we might have false negative if the capture is too much shorten
 * but it would have been useless anyway. */
static gboolean
test_thrift_strict(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, thrift_option_data_t *thrift_opt)
{
    gint tframe_length = 0;
    int offset = 0;
    guint length = tvb_captured_length(tvb);
    gint32 str_len;

    /* Note, heuristic only detects strict binary protocol, possibly framed.
     * It could also detect compact protocol but 1 byte (0x82) is quite thin…
     * Detection of old binary protocol is tricky due to the lack of fixed data.
     * TODO: Maybe by assuming a maximum size for the method name like 16kB… or 1kB.
     *
     * In order to avoid false positive, the first packet is expected to contain:
     * 1. Possibly Frame size (4 bytes, if MSb of first byte is 0)
     * 2. Thrift "version" (4 bytes = 0x8001..0m, containing protocol id, version, and method type)
     * 3. Method length (4 bytes)
     * 4. Method name (method length bytes, verified as acceptable UTF-8),
     * 5. Sequence ID (4 bytes, content not verified),
     * 6. First field type (1 byte, content not verified). */

    /* Enough data for elements 2 to 6? */
    if (length < (guint)TBP_THRIFT_STRICT_HEADER_LEN) {
        return FALSE;
    }

    /* 1. Check if it is framed (and if the frame length is large enough for a complete message). */
    if (tvb_get_gint8(tvb, offset) >= 0) {
        // framed
        tframe_length = tvb_get_ntohil(tvb, offset);

        if (tframe_length < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN) {
            return FALSE;
        }
        offset = TBP_THRIFT_LENGTH_LEN; /* Strict header starts after frame length. */
        if (length < (guint)(offset + TBP_THRIFT_STRICT_HEADER_LEN)) {
            return FALSE;
        }
    }
    if (thrift_opt) {
        thrift_opt->canary = THRIFT_OPTION_DATA_CANARY;
        /* Set the protocol used since we now have enough information. */
        thrift_opt->tprotocol = (thrift_protocol_enum_t)(PROTO_THRIFT_BINARY | PROTO_THRIFT_STRICT);
        if (tframe_length > 0) {
            thrift_opt->tprotocol = (thrift_protocol_enum_t)(thrift_opt->tprotocol | PROTO_THRIFT_FRAMED);
        }
    } else REPORT_DISSECTOR_BUG("%s called without data structure.", G_STRFUNC);

    /* 2. Thrift version & method type (heuristic does /not/ ignore the message type). */
    if (!is_thrift_strict_version(tvb_get_ntohl(tvb, offset), FALSE)) {
        return FALSE;
    }
    offset += TBP_THRIFT_VERSION_LEN;

    /* 3. Get method name length and check against what we have. */
    str_len = tvb_get_ntohil(tvb, offset);
    if ((tframe_length > 0) && (tframe_length < TBP_THRIFT_STRICT_MIN_MESSAGE_LEN + str_len)) {
        /* The frame cannot even contain an empty Thrift message (no data, only T_STOP after the sequence id). */
        return FALSE;
    }
    offset += TBP_THRIFT_LENGTH_LEN;

    /* 4. Check method name itself. */
    if (tvb_captured_length_remaining(tvb, offset) < str_len) {
        /* Method name is no entirely captured, we cannot check it. */
        return FALSE;
    }
    if (thrift_binary_utf8_isprint(tvb, offset, str_len, FALSE) < str_len) {
        return FALSE;
    }
    offset += str_len;

    /* 5 & 6. Check that there is enough data remaining for a sequence ID and a field type (but no need for it to be captured). */
    if (tvb_reported_length_remaining(tvb, offset) < TBP_THRIFT_LENGTH_LEN + TBP_THRIFT_TYPE_LEN) {
        return FALSE;
    }

    thrift_opt->canary = THRIFT_OPTION_DATA_CANARY;
    return TRUE;
}

static gboolean
dissect_thrift_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void *data _U_)
{
    conversation_t *conversation;
    thrift_option_data_t thrift_opt;
    memset(&thrift_opt, 0, sizeof(thrift_option_data_t));

    if (!test_thrift_strict(tvb, pinfo, tree, &thrift_opt)) {
        return FALSE;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "THRIFT");
    col_clear(pinfo->cinfo, COL_INFO);

    if (thrift_opt.tprotocol & PROTO_THRIFT_FRAMED) {
        tcp_dissect_pdus(tvb, pinfo, tree, framed_desegment, TBP_THRIFT_LENGTH_LEN,
                get_framed_thrift_pdu_len, dissect_thrift_framed, &thrift_opt);
    } else {
        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, thrift_handle);

        /* TODO: use dissect_thrift_usb instead? but it does not exists (yet) and we don't know if we are in USB or not. */
        dissect_thrift_loop(tvb, pinfo, tree, &thrift_opt);
    }

    return TRUE;
}

void
proto_register_thrift(void)
{
    static hf_register_info hf[] = {
        { &hf_thrift_frame_length,
            { "Frame length", "thrift.frame_len",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_exception,
            { "Exception", "thrift.exception",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_exception_message,
            { "Exception Message", "thrift.exception.message",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_exception_type,
            { "Exception Type", "thrift.exception.type",
                FT_INT32, BASE_DEC, VALS(thrift_exception_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_protocol_id,
            { "Protocol id", "thrift.protocol_id",
                FT_UINT8, BASE_HEX, VALS(thrift_proto_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_version,
            { "Version", "thrift.version",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_mtype,
            { "Message type", "thrift.mtype",
                FT_UINT8, BASE_HEX, VALS(thrift_mtype_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_str_len,
            { "Length", "thrift.str_len",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_method,
            { "Method", "thrift.method",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_seq_id,
            { "Sequence Id", "thrift.seq_id",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_type,
            { "Type", "thrift.type",
                FT_UINT8, BASE_HEX, VALS(thrift_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_key_type,
            { "Key Type", "thrift.type",
                FT_UINT8, BASE_HEX, VALS(thrift_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_value_type,
            { "Value Type", "thrift.type",
                FT_UINT8, BASE_HEX, VALS(thrift_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_fid,
            { "Field Id", "thrift.fid",
                FT_INT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_bool,
            { "Boolean", "thrift.bool",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0, // libthrift (C++) also considers boolean value = (byte != 0x00)
                NULL, HFILL }
        },
        { &hf_thrift_i8,
            { "Integer8", "thrift.i8",
                FT_INT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_i16,
            { "Integer16", "thrift.i16",
                FT_INT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_i32,
            { "Integer32", "thrift.i32",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_i64,
            { "Integer64", "thrift.i64",
                FT_INT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_double,
            { "Double", "thrift.double",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_binary,
            { "Binary", "thrift.binary",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_string,
            { "String", "thrift.binary",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Binary field interpreted as a string.", HFILL }
        },
        { &hf_thrift_struct,
            { "Struct", "thrift.struct",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_list,
            { "List", "thrift.list",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_set,
            { "Set", "thrift.set",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_map,
            { "Map", "thrift.map",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_set_item,
            { "Number of Set Items", "thrift.num_set_item",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_list_item,
            { "Number of List Items", "thrift.num_list_item",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_thrift_num_map_item,
            { "Number of Map Items", "thrift.num_map_item",
                FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
    };


    /* setup protocol subtree arrays */
    static gint* ett[] = {
        &ett_thrift,
        &ett_thrift_header,
        &ett_thrift_params,
        &ett_thrift_struct,
        &ett_thrift_list,
        &ett_thrift_set,
        &ett_thrift_map,
        &ett_thrift_error,
        &ett_thrift_exception,
    };

    static ei_register_info ei[] = {
        { &ei_thrift_wrong_type, { "thrift.wrong_type", PI_PROTOCOL, PI_ERROR, "Type value not expected.", EXPFILL } },
        { &ei_thrift_negative_length, { "thrift.negative_length", PI_PROTOCOL, PI_ERROR, "Length greater than 2 GiB not supported.", EXPFILL } },
        { &ei_thrift_wrong_proto_version, { "thrift.wrong_proto_version", PI_MALFORMED, PI_ERROR, "Protocol version invalid or unsupported.", EXPFILL } },
        { &ei_thrift_struct_fid_not_in_seq, { "thrift.struct_fid_not_in_seq", PI_PROTOCOL, PI_ERROR, "Missing mandatory field id in struct.", EXPFILL } },
        { &ei_thrift_not_enough_data, { "thrift.not_enough_data", PI_PROTOCOL, PI_WARN, "Not enough data to decode.", EXPFILL } },
        { &ei_thrift_frame_too_short, { "thrift.frame_too_short", PI_MALFORMED, PI_ERROR, "Thrift frame shorter than data.", EXPFILL } },
        { &ei_thrift_frame_too_long, { "thrift.frame_too_long", PI_PROTOCOL, PI_WARN, "Thrift frame longer than data.", EXPFILL } },
    };


    module_t *thrift_module;
    expert_module_t* expert_thrift;


    /* Register protocol name and description */
    proto_thrift = proto_register_protocol("Thrift Protocol", "Thrift", "thrift");

    expert_thrift = expert_register_protocol(proto_thrift);

    /* register field array */
    proto_register_field_array(proto_thrift, hf, array_length(hf));

    /* register subtree array */
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_thrift, ei, array_length(ei));

    /* register dissector */
    thrift_handle = register_dissector("thrift", dissect_thrift_tcp, proto_thrift);

    thrift_module = prefs_register_protocol(proto_thrift, proto_reg_handoff_thrift);

    thrift_method_name_dissector_table = register_dissector_table("thrift.method_names", "Thrift Method names",
        proto_thrift, FT_STRING, FALSE); /* FALSE because Thrift is case-sensitive */

    prefs_register_enum_preference(thrift_module, "decode_binary",
                                   "Display binary as bytes or strings",
                                   "How the binary should be decoded",
                                   &binary_decode, binary_display_options, FALSE);

    prefs_register_uint_preference(thrift_module, "tls.port",
                                   "Thrift TLS port",
                                   "Thrift TLS port",
                                   10, &thrift_tls_port);

    prefs_register_bool_preference(thrift_module, "show_internal",
                                   "Show internal Thrift fields in the dissection tree",
                                   "Whether the Thrift dissector should display Thrift internal fields for sub-dissectors.",
                                   &show_internal_thrift_fields);

    prefs_register_bool_preference(thrift_module, "fallback_on_generic",
                                   "Fallback to generic Thrift dissector if sub-dissector fails.",
                                   "Whether the Thrift dissector should try to dissect the data if the sub-dissector failed."
                                   " This option can be useful if the data is well-formed but the sub-dissector is expecting different type/content.",
                                   &try_generic_if_sub_dissector_fails);

    prefs_register_bool_preference(thrift_module, "desegment_framed",
                                   "Reassemble Framed Thrift messages spanning multiple TCP segments",
                                   "Whether the Thrift dissector should reassemble framed messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &framed_desegment);
}

void
proto_reg_handoff_thrift(void)
{
    static guint saved_thrift_tls_port;
    static dissector_handle_t thrift_http_handle;
    static gboolean thrift_initialized = FALSE;

    thrift_http_handle = create_dissector_handle(dissect_thrift_heur, proto_thrift);

    if (!thrift_initialized) {
        thrift_initialized = TRUE;
        heur_dissector_add("tcp", dissect_thrift_heur, "Thrift over TCP", "thrift_tcp", proto_thrift, HEURISTIC_ENABLE);
        heur_dissector_add("usb.bulk", dissect_thrift_heur, "Thrift over USB", "thrift_usb_bulk", proto_thrift, HEURISTIC_ENABLE);
        dissector_add_for_decode_as_with_preference("tcp.port", thrift_handle);
        dissector_add_string("media_type", "application/x-thrift", thrift_http_handle); // Obsolete but still in use.
        dissector_add_string("media_type", "application/vnd.apache.thrift.binary", thrift_http_handle); // Officially registered.
    } else {
        ssl_dissector_delete(saved_thrift_tls_port, thrift_handle);
    }
    ssl_dissector_add(thrift_tls_port, thrift_handle);
    saved_thrift_tls_port = thrift_tls_port;
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
