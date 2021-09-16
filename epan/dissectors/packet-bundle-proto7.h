#ifndef WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_

/*
* SPDX-License-Identifier: GPL-2.0-or-later
*
* Reference: https://datatracker.ietf.org/doc/draft-ietf-dtn-bpbis/
*/
#include "config.h"
#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/expert.h>
#include <glib.h>

/** Bundle CRC types: Section:4.1.1 */
typedef enum {
    // no CRC is present.
    BP_CRC_NONE = 0,
    // a standard X-25 CRC-16 is present.
    BP_CRC_16 = 1,
    // a standard CRC32C (Castagnoli) CRC-32 is present.
    BP_CRC_32 = 2,
} BundleCrcType;

/** Bundle processing control flags: Section: 4.1.3*/
typedef enum {
    // bundle deletion status reports are requested.
    BP_BUNDLE_REQ_DELETION_REPORT = 0x040000,
    // bundle delivery status reports are requested.
    BP_BUNDLE_REQ_DELIVERY_REPORT = 0x020000,
    // bundle forwarding status reports are requested.
    BP_BUNDLE_REQ_FORWARDING_REPORT = 0x010000,
    // bundle reception status reports are requested.
    BP_BUNDLE_REQ_RECEPTION_REPORT = 0x004000,
    // status time is requested in all status reports.
    BP_BUNDLE_REQ_STATUS_TIME = 0x000040,
    // user application acknowledgement is requested.
    BP_BUNDLE_USER_APP_ACK = 0x000020,
    // bundle must not be fragmented.
    BP_BUNDLE_NO_FRAGMENT = 0x000004,
    // payload is an administrative record.
    BP_BUNDLE_PAYLOAD_ADMIN = 0x000002,
    // bundle is a fragment.
    BP_BUNDLE_IS_FRAGMENT = 0x000001,
} BundleProcessingFlag;

/** Block processing control flags.Section:4.1.4*/
typedef enum {
    // block must be removed from bundle if it can't be processed.
    BP_BLOCK_REMOVE_IF_NO_PROCESS = 0x10,
    // bundle must be deleted if block can't be processed.
    BP_BLOCK_DELETE_IF_NO_PROCESS = 0x04,
    // transmission of a status report is requested if block can't be processed.
    BP_BLOCK_STATUS_IF_NO_PROCESS = 0x02,
    // block must be replicated in every fragment.
    BP_BLOCK_REPLICATE_IN_FRAGMENT = 0x01,
} BlockProcessingFlag;

/** Standard block type codes.
 * Section 4.2.3 and Section 4.3. */
typedef enum {
    BP_BLOCKTYPE_INVALID = 0,
    // Payload (data)
    BP_BLOCKTYPE_PAYLOAD = 1,
    // Previous Node
    BP_BLOCKTYPE_PREV_NODE = 6,
    // Bundle Age
    BP_BLOCKTYPE_BUNDLE_AGE = 7,
    // Hop Count
    BP_BLOCKTYPE_HOP_COUNT = 10,
    // Integrity
    BP_BLOCKTYPE_INTEGRITY = 11,
    // Confidentiality
    BP_BLOCKTYPE_CONFIDENTIALITY = 12,
} BlockTypeCode;


/** Security Context Flags
 * Section 3.6 draft-ietf-dtn-bpsec-27 */
typedef enum {
    // Security Context Parameters Present
    BP_SECURITY_CONTEXT_PARAMETERS_PRESENT = 0x01
} SecurityBlockFlag;

/** SHA Variant
 * Section 3.3.1 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // HMAC 256
    BP_SHA_HMAC_256 = 5,
    // HMAC 382
    BP_SHA_HMAC_382 = 6,
    // HMAC 512
    BP_SHA_HMAC_512 = 7
} ShaVariant;

/** Integrity Scope Flags
 * Section 3.3.3 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // bundle deletion status reports are requested.
    BP_BIB_PRIMARY_BLOCK = 0x01,
    // bundle delivery status reports are requested.
    BP_BIB_TARGET_HEADER = 0x02,
    // bundle forwarding status reports are requested.
    BP_BIB_SECURITY_HEADER = 0x03,
} BibSCFlag;

/** BIB Security Context Parameters
 * Section 3.3.4 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // SHA Variant
    BP_BIB_SHA_VARIANT = 1,
    // Wrapped Key
    BP_BIB_WRAPPED_KEY = 2,
    // Integrity Scope Flags
    BP_BIB_SCOPE_FLAGS = 4
} BibSCParameters;

/** BIB Security Context Results
 * Section 3.4 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // Expected HMAC
    BP_BIB_EXPECTED_HMAC = 1
} BibSCResults;

/** AES Variant
 * Section 4.3.2 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // HMAC 256
    BP_A128GCM = 1,
    // HMAC 382
    BP_A256GCM = 3,
} AesVariant;

/** Additional Authenticated Data (AAD) Scope Flags
 * Section 4.3.4 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // bundle deletion status reports are requested.
    BP_BCB_PRIMARY_BLOCK = 0x01,
    // bundle delivery status reports are requested.
    BP_BCB_TARGET_HEADER = 0x02,
    // bundle forwarding status reports are requested.
    BP_BCB_SECURITY_HEADER = 0x03,
} BcbSCFlag;

/** BCB Security Context Parameters
 * Section 4.3.5 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // Initialization Vector
    BP_BCB_INIT_VECTOR = 1,
    // SHA Variant
    BP_BCB_SHA_VARIANT = 2,
    // Wrapped Key
    BP_BCB_WRAPPED_KEY = 3,
    // Integrity Scope Flags
    BP_BCB_SCOPE_FLAGS = 4
} BcbSCParameters;

/** BCB Security Context Results
 * Section 4.4.2 of draft-ietf-dtn-bpsec-default-sc-06 */
typedef enum {
    // Authentication Tag
    BP_BCB_AUTH_TAG = 1
} BcbSCResults;

typedef enum cbor_type {
    CBOR_TYPE_UINT = 0,
    CBOR_TYPE_NEGINT = 1,
    CBOR_TYPE_BYTESTRING = 2,
    CBOR_TYPE_STRING = 3,
    CBOR_TYPE_ARRAY = 4,
    CBOR_TYPE_MAP = 5,
    CBOR_TYPE_TAG = 6,
    CBOR_TYPE_FLOAT_CTRL = 7,
} cbor_type;

/** Administrative record type codes.
 * Section 6.1. */
typedef enum {
    // Bundle status report
    BP_ADMINTYPE_BUNDLE_STATUS = 1,
} AdminRecordTypeCode;

/** Bundle status report types.
 * These are not enumerated by the spec but are encoded separately
 * in Section 5.1 */
typedef enum {
    BP_STATUS_REPORT_RECEIVED,
    BP_STATUS_REPORT_FORWARDED,
    BP_STATUS_REPORT_DELIVERED,
    BP_STATUS_REPORT_DELETED,
} AdminBundleStatusInfoType;

typedef enum {
    CBOR_CTRL_NONE = 0,
    CBOR_CTRL_FALSE = 20,
    CBOR_CTRL_TRUE = 21,
    CBOR_CTRL_NULL = 22,
    CBOR_CTRL_UNDEF = 23
} _cbor_ctrl;

/* The basic header structure of CBOR encoding */
typedef struct {
    gint start;
    gint length;
    expert_field *error;
    guint8 type_major;
    guint8 type_minor;
    gint64 rawvalue;
} bp_cbor_head_t;

/* The basic header structure of CBOR encoding */
typedef struct {
    gint start;
    gint head_length;
    gint data_length;
    GSequence *errors;
    GSequence *tags;
    cbor_type type_major;
    guint8 type_minor;
    gint64 head_value;
} bp_cbor_chunk_t;

typedef struct {
    guint64 dtntime;
    nstime_t utctime;
} bp_dtn_time_t;

/* Creation Timestamp used to correlate bundles */
typedef struct bp_creation_ts_t{
    bp_dtn_time_t time;
    guint64 seqno;
} bp_creation_ts_t;

/* Metadata from a Node ID */
typedef struct {
    gint64 scheme;
    const char *uri;
} bp_nodeid_t;

/* Metadata extracted from the primary block */
typedef struct {
    guint64 flags;
    bp_nodeid_t *dst_nodeid;
    bp_nodeid_t *src_nodeid;
    bp_nodeid_t *rep_nodeid;
    bp_creation_ts_t ts;
    guint64 *frag_offset;
    guint64 *total_len;
    BundleCrcType crc_type;
    tvbuff_t *crc_field;
} bp_block_primary_t;

typedef struct {
    guint64 index;
    const guint64 *type_code;
    const guint64 *block_number;
    guint64 flags;
    BundleCrcType crc_type;
    tvbuff_t *crc_field;
    tvbuff_t *data;
} bp_block_canonical_t;

/* Metadata extracted per-bundle */
typedef struct {
    guint32 frame_num;
    bp_block_primary_t *primary;
    GSequence *blocks;
    GHashTable *block_types;
} bp_bundle_t;

/* Identification of an individual bundle*/
typedef struct {
    bp_nodeid_t *src;
    bp_creation_ts_t *ts;
    guint64 *frag_offset;
    guint64 *total_len;
} bp_bundle_ident_t;

/* Metadata for an entire conversation */
typedef struct {
    GHashTable *bundles;
} bp_history_t;

typedef struct {
    const bp_bundle_t *bundle;
    const bp_block_canonical_t *block;
} bp_dissector_data_t;

bp_cbor_head_t *bp_scan_cbor_head(tvbuff_t *tvb, gint start);
void bp_cbor_head_delete(gpointer ptr);
bp_cbor_chunk_t *bp_scan_cbor_chunk(tvbuff_t *tvb, gint start);
void bp_cbor_chunk_delete(gpointer ptr);
bp_creation_ts_t *bp_creation_ts_new(void);
void bp_creation_ts_delete(gpointer ptr);
bp_nodeid_t * bp_nodeid_new(void);
void bp_nodeid_delete(gpointer ptr);
bp_block_primary_t * bp_block_primary_new(void);
void bp_block_primary_delete(gpointer ptr);
bp_block_canonical_t * bp_block_canonical_new(guint64 index);
void bp_block_canonical_delete(gpointer ptr);
gint bp_block_compare_index(gconstpointer a, gconstpointer b, gpointer user_data);
gint bp_block_compare_block_number(gconstpointer a, gconstpointer b, gpointer user_data);
bp_bundle_t * bp_bundle_new(void);
void bp_bundle_delete(gpointer ptr);
bp_bundle_ident_t * bp_bundle_ident_new(bp_nodeid_t *src, bp_creation_ts_t *ts, guint64 *off, guint64 *len);
void bp_bundle_ident_delete(gpointer ptr);
gboolean bp_bundle_ident_equal(gconstpointer a, gconstpointer b);
guint bp_bundle_ident_hash(gconstpointer key);
void proto_register_bp(void);
void proto_reg_handoff_bp(void);
int dissect_bp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
void file_scope_delete (gpointer ptr);
#endif /* WIRESHARK_PLUGIN_SRC_PACKET_BPV7_H_ */

