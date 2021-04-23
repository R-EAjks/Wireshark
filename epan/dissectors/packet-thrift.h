/* packet-thrift.h
 *
 * Copyright 2015, Anders Broman <anders.broman[at]ericsson.com>
 * Copyright 2019-2021, Triton Circonflexe <triton[at]kumal.info>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Note: used by proprietary dissectors (too).
 */

#ifndef __PACKET_THRIFT_H__
#define __PACKET_THRIFT_H__

#include "ws_symbol_export.h"


typedef enum {
    DE_THRIFT_T_STOP = 0,
    DE_THRIFT_T_VOID, // DE_THRIFT_T_UNUSED_1?
    DE_THRIFT_T_BOOL,
    DE_THRIFT_T_I8,
    DE_THRIFT_T_DOUBLE,
    DE_THRIFT_T_UNUSED_5, // Intended for U16?
    DE_THRIFT_T_I16,
    DE_THRIFT_T_UNUSED_7, // Intended for U32?
    DE_THRIFT_T_I32,
    DE_THRIFT_T_UNUSED_9, // Intended for U64?
    DE_THRIFT_T_I64,
    DE_THRIFT_T_BINARY,
    DE_THRIFT_T_STRUCT,
    DE_THRIFT_T_MAP,
    DE_THRIFT_T_SET,
    DE_THRIFT_T_LIST,
} thrift_type_enum_t;

typedef enum {
    ME_THRIFT_T_CALL = 1,
    ME_THRIFT_T_REPLY,
    ME_THRIFT_T_EXCEPTION,
    ME_THRIFT_T_ONEWAY,
} thrift_method_type_enum_t;

/*
 * This is a list of flags even though not all combinations are available.
 * - Framed is compatible with everything;
 * - Binary can be augmented with Strict (message header is different but content is the same);
 * - Compact is incompatible with Binary & Strict as everything is coded differently.
 *
 * Valid values go from 0x02 (old binary format) to 0x09 (framed compact).
 *
 * Note: Compact is not supported yet.
 */
typedef enum {
    PROTO_THRIFT_FRAMED = 0x01,
    PROTO_THRIFT_BINARY = 0x02,
    PROTO_THRIFT_STRICT = 0x04,
    PROTO_THRIFT_COMPACT = 0x08
} thrift_protocol_enum_t;

#define THRIFT_OPTION_DATA_CANARY 0x8001da7a
#define THRIFT_REQUEST_REASSEMBLY       (-1)
#define THRIFT_SUBDISSECTOR_ERROR       (-2)

typedef struct _thrift_option_data_t {
    guint32 canary;                     /* Ensure that we don't read garbage. */
                                        /* Sub-dissectors should check against THRIFT_OPTION_DATA_CANARY. */
    thrift_method_type_enum_t mtype;    /* Method type necessary to know how to decode the message. */
    thrift_protocol_enum_t tprotocol;   /* Type and version of Thrift TProtocol. */
                                        /* Framed?((Strict? Binary)|Compact) */
    proto_tree *reassembly_tree;        /* Tree were the reassembly was requested. */
                                        /* Useful if the caller can't reassemble (Framed). */
    gint32 reassembly_offset;           /* Where the incomplete data starts. */
    gint32 reassembly_length;           /* Expected size of the data. */
} thrift_option_data_t;

#define TMFILL NULL, { .m = { NULL, NULL } }

typedef struct _thrift_member_t thrift_member_t;
struct _thrift_member_t {
    const gint *p_hf_id;             /* The hf field for the struct member*/
    const gint16 fid;                /* The Thrift field id of the stuct memeber*/
    const gboolean optional;         /* TRUE if element is optional, FALSE otherwise */
    const thrift_type_enum_t type;   /* The thrift type of the struct member */
    const gint *p_ett_id;            /* An ett field used for the subtree created if the member is a compound type. */
    union {
        const guint encoding;
        const thrift_member_t *element;
        const thrift_member_t *members;
        struct {
            const thrift_member_t *key;
            const thrift_member_t *value;
        } m;
    } u;
};

/* These functions are to be used by dissectors dissecting Thrift based protocols similar to packet-ber.c
 *
 * @param[in] tvb:      Pointer to the tvbuff_t holding the captured data.
 * @param[in] pinfo:    Pointer to the packet_info holding information about the currently dissected packet.
 * @param[in] tree:     Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * @param[in] offset:   Offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect type, id, & data.
 * @param[in] is_field: Indicate if the offset point to a field element and if field type and field id must be dissected.
 *                      Essentially for internal use in list, set, and map. Sub-dissectors should always use TRUE.
 * @param[in] field_id: Thrift field identifier? Unused at the moment.
 * @param[in] hf_id:    Header field info that describes the field to display (display name, filter name, FT_TYPE, ...).
 * @param[in] encoding: Encoding used for string display. (Only for dissect_thrift_t_string_enc)
 *
 * @return              Offset of the first non-dissected byte.
 */
WS_DLL_PUBLIC int dissect_thrift_t_stop      (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset);
WS_DLL_PUBLIC int dissect_thrift_t_bool      (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i8        (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i16       (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i32       (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i64       (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_double    (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_string    (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_string_enc(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, guint encoding);
WS_DLL_PUBLIC int dissect_thrift_t_binary    (tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id);

/** Dissect a Thrift struct
 * Dissect a Thrift struct by calling the struct member dissector in turn from the thrift_member_t array
 *
 * @param[in] tvb:      Pointer to the tvbuff_t holding the captured data.
 * @param[in] pinfo:    Pointer to the packet_info holding information about the currently dissected packet.
 * @param[in] tree:     Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * @param[in] offset:   Offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect type, id, & data.
 * @param[in] seq:      an array of thrift_member_t's containing thrift type of the struct members the hf variable to use etc.
 * @param[in] field_id: Thrift field identifier? Unused at the moment.
 * @param[in] hf_id:    A header field of FT_BYTES which will be the struct header field
 * @param[in] ett_id:   An ett field used for the subtree created to list the struct members.
 *
 * @return              Offset of the first non-dissected byte.
 */
WS_DLL_PUBLIC int dissect_thrift_t_map   (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, gint ett_id, const thrift_member_t *key, const thrift_member_t *val);
WS_DLL_PUBLIC int dissect_thrift_t_set   (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, gint ett_id, const thrift_member_t *elt);
WS_DLL_PUBLIC int dissect_thrift_t_list  (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, gint ett_id, const thrift_member_t *elt);
WS_DLL_PUBLIC int dissect_thrift_t_struct(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, gboolean is_field, int field_id _U_, gint hf_id, gint ett_id, const thrift_member_t *seq);

#endif /*__PACKET_THRIFT_H__ */
