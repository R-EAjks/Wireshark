/* packet-ansi_tcap-template.c
 * Routines for ANSI TCAP
 * Copyright 2007 Anders Broman <anders.broman@ericsson.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: T1.114
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/strutil.h>

#include "packet-ber.h"
#include "packet-tcap.h"
#include "packet-ansi_tcap.h"

#define PNAME  "ANSI Transaction Capabilities Application Part"
#define PSNAME "ANSI_TCAP"
#define PFNAME "ansi_tcap"

void proto_register_ansi_tcap(void);
void proto_reg_handoff_ansi_tcap(void);

/* Preference settings */
#define ANSI_TCAP_TID_ONLY            0
#define ANSI_TCAP_TID_AND_SOURCE      1
#define ANSI_TCAP_TID_SOURCE_AND_DEST 2
static gint ansi_tcap_response_matching_type = ANSI_TCAP_TID_ONLY;

/* Initialize the protocol and registered fields */
static int proto_ansi_tcap = -1;

#if 0
static int hf_ansi_tcapsrt_SessionId = -1;
static int hf_ansi_tcapsrt_Duplicate = -1;
static int hf_ansi_tcapsrt_BeginSession = -1;
static int hf_ansi_tcapsrt_EndSession = -1;
static int hf_ansi_tcapsrt_SessionTime = -1;
#endif
static int hf_ansi_tcap_bit_h = -1;
static int hf_ansi_tcap_op_family = -1;
static int hf_ansi_tcap_op_specifier = -1;
static int hf_ansi_tcap_parameter_acg_control_cause_indicator =-1;
static int hf_ansi_tcap_parameter_acg_duration_field =-1;
static int hf_ansi_tcap_parameter_acg_gap =-1;
static int hf_ansi_tcap_parameter_set = -1;
static int hf_ansi_tcap_parameter_digits_type_of_digits = -1;
static int hf_ansi_tcap_parameter_digits_nature_of_numbers = -1;
static int hf_ansi_tcap_parameter_digits_number_planning = -1;
static int hf_ansi_tcap_parameter_digits_encoding = -1;
static int hf_ansi_tcap_parameter_digits_number_of_digits = -1;
static int hf_ansi_tcap_parameter_digits = -1;
static int hf_ansi_tcap_service_key_identifier = -1;
static int hf_ansi_tcap_digit_identifier = -1;
static int hf_ansi_tcap_digit_length = -1;
static int hf_ansi_tcap_destination_number_value = -1;
static int hf_ansi_tcap_presentation_restirction = -1;
static int hf_ansi_tcap_encoding_scheme = -1;
static int hf_ansi_tcap_number_of_digits = -1;
static int hf_ansi_tcap_parameter_set_start = -1;
static int hf_ansi_tcap_parameter_call_forwarding_var = -1;
static int hf_ansi_tcap_parameter_call_forwarding_on_busy = -1;
static int hf_ansi_tcap_parameter_call_forwarding_dont_answer = -1;
static int hf_ansi_tcap_parameter_selective_forwarding = -1;
static int hf_ansi_tcap_parameter_dn_match = -1;
static int hf_ansi_tcap_parameter_dn_line_service = -1;
static int hf_ansi_tcap_parameter_bearer_capability_requested1 = -1;
static int hf_ansi_tcap_parameter_bearer_capability_requested2 = -1;
static int hf_ansi_tcap_parameter_bearer_capability_requested2a = -1;
static int hf_ansi_tcap_parameter_bearer_capability_requested2b = -1;
static int hf_ansi_tcap_parameter_bearer_capability_requested3 = -1;
static int hf_ansi_tcap_parameter_bearer_capability_requested3a = -1;
static int hf_ansi_tcap_parameter_business_group_length_spare = -1;
static int hf_ansi_tcap_parameter_business_group_length_AttSt = -1;
static int hf_ansi_tcap_parameter_business_group_length_BGID = -1;
static int hf_ansi_tcap_parameter_business_group_length_LP11 = -1;
static int hf_ansi_tcap_parameter_business_group_length_Party_Selector = -1;
static int hf_ansi_tcap_parameter_generic_name_type_name = -1;
static int hf_ansi_tcap_parameter_generic_name_avalibility = -1;
static int hf_ansi_tcap_parameter_generic_name_spare = -1;
static int hf_ansi_tcap_parameter_generic_name_presentation = -1;
static int hf_ansi_tcap_parameter_look_ahead_for_busy_ack_type = -1;
static int hf_ansi_tcap_parameter_look_ahead_for_busy_spare = -1;
static int hf_ansi_tcap_parameter_look_ahead_for_busy_location_field = -1;
static int hf_ansi_tcap_parameter_CIC_spare = -1;
static int hf_ansi_tcap_parameter_CIC_msb = -1;
static int hf_ansi_tcap_parameter_precedence_level_spare = -1;
static int hf_ansi_tcap_parameter_precedence_level = -1;

static guint hf_ansi_tcap_parameter_length = -1;

#include "packet-ansi_tcap-hf.c"

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
static gint ett_param = -1;
static gint ett_ansi_tcap_op_code_nat = -1;

static gint ett_otid = -1;
static gint ett_dtid = -1;
static gint ett_ansi_tcap_stat = -1;

static expert_field ei_ansi_tcap_dissector_not_implemented = EI_INIT;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static gboolean tcap_subdissector_used=FALSE;

static struct tcaphash_context_t * gp_tcap_context=NULL;

/* Note the high bit should be masked off when registering in this table (0x7fff)*/
static dissector_table_t  ansi_tcap_national_opcode_table; /* National Operation Codes */

#include "packet-ansi_tcap-ett.c"

#define MAX_SSN 254

extern gboolean gtcap_PersistentSRT;
extern guint gtcap_RepetitionTimeout;
extern guint gtcap_LostTimeout;

/* When several Tcap components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_TCAP_INSTANCE 10
int tcapsrt_global_current=0;
struct tcapsrt_info_t tcapsrt_global_info[MAX_TCAP_INSTANCE];

static dissector_table_t ber_oid_dissector_table=NULL;
static const char * cur_oid;
static const char * tcapext_oid;

static dissector_handle_t ansi_map_handle;
static dissector_handle_t ain_handle;

struct ansi_tcap_private_t ansi_tcap_private;
#define MAX_TID_STR_LEN 1024

static void ansi_tcap_ctx_init(struct ansi_tcap_private_t *a_tcap_ctx) {
  memset(a_tcap_ctx, '\0', sizeof(*a_tcap_ctx));
  a_tcap_ctx->signature = ANSI_TCAP_CTX_SIGNATURE;
  a_tcap_ctx->oid_is_present = FALSE;
  a_tcap_ctx->TransactionID_str = NULL;
}

/* Tables for register*/

static const value_string ansi_tcap_national_op_code_family_vals[] = {
  {  0x0, "All Families" },
  {  0x1, "Parameter" },
  {  0x2, "Charging" },
  {  0x3, "Provide Instructions" },
  {  0x4, "Connection Control" },
  {  0x5, "Caller Interaction" },
  {  0x6, "Send Notification" },
  {  0x7, "Network Management" },
  {  0x8, "Procedural" },
  {  0x9, "Operation Control" },
  {  0xa, "Report Event" },
  /* Spare */
  {  0x7e, "Miscellaneous" },
  {  0x7f, "Reserved" },
  { 0, NULL }
};

static const value_string ansi_tcap_national_parameter_control_cause_indication[] = {
 { 1, "Vacant Code" },
 { 2, "Out-of-Band" },
 { 3, "Database Overload" },
 { 4, "Destination Mass Calling" },
 { 5, "Operation Support System Initiated" },
 { 0, NULL },
};


static const value_string ansi_tcap_national_parameter_duration_field[] = {
 { 0x0, "Not Used" },
 { 0x1, "1 Second" },
 { 0x2, "2 Seconds" },
 { 0x3, "4 Seconds" },
 { 0x4, "8 Seconds" },
 { 0x5, "16 Seconds" },
 { 0x6, "32 Seconds" },
 { 0x7, "64 Seconds" },
 { 0x8, "128 Seconds" },
 { 0x9, "256 Seconds" },
 { 0xa, "512 Seconds" },
 { 0xb, "1024 Seconds" },
 { 0xc, "2048 Seconds" },
};

static const value_string ansi_tcap_national_parameter_gap[] = {
 { 0x0, "Remove Gap Control" },
 { 0x1, "0.00 Second" },
 { 0x2, "0.10 Seconds" },
 { 0x3, "0.25 Seconds" },
 { 0x4, "0.50 Seconds" },
 { 0x5, "1.00 Seconds" },
 { 0x6, "2.00 Seconds" },
 { 0x7, "5.00 Seconds" },
 { 0x8, "10.00 Seconds" },
 { 0x9, "15.00 Seconds" },
 { 0xa, "30.00 Seconds" },
 { 0xb, "60.00 Seconds" },
 { 0xc, "120.00 Seconds" },
 { 0xd, "300.00 Seconds" },
 { 0xe, "600.00 Seconds" },
 { 0xf, "Stop All Calls" },
};

static const value_string ansi_tcap_national_parameter_digits_type_of_digits[] = {
 { 0x00, "Not Used" },
 { 0x01, "Called Party Number" },
 { 0x02, "Calling Party Number" },
 { 0x03, "Caller Interaction" },
 { 0x04, "Routing Number" },
 { 0x05, "Billing Number" },
 { 0x06, "Destination Number" },
 { 0x07, "LATA" },
 { 0x08, "Carrier" },
 { 0x09, "Last Calling Party" },
 { 0x0a, "Last Party Called" },
 { 0x0b, "Calling Directory Number" },
 { 0x0c, "VMSR Identifier" },
 { 0x0d, "Original Called Number" },
 { 0x0e, "Redirecting Number" },
 { 0x0f, "Connected Number" },
};

static const value_string ansi_tcap_national_parameter_digits_nature_of_numbers[] = {
 { 0x0, "National" },
 { 0x1, "International" },
 { 0x2, "No Presentation Restriction" },
 { 0x3, "Presentation Restriction" },
};

static const value_string ansi_tcap_national_parameter_digits_encoding[] = {
 { 0x0, "Not Used" },
 { 0x1, "BCD" },
 { 0x2, "IA5" },
};

static const value_string ansi_tcap_national_parameter_digits_number_planning[] = {
 { 0x0, "Unkown or Not applicable" },
 { 0x1, "ISDN Numbering" },
 { 0x2, "Telephony Numbering" },
 { 0x3, "Data Numbering" },
 { 0x4, "Telex Numbering" },
 { 0x5, "Maritime Mobile Numbering" },
 { 0x6, "Land Mobile Numbering" },
 { 0x7, "Private Numbering Plan" },
};

static const value_string ansi_tcap_national_parameter_digits_number_of_digits[] = {
 { 0x0, "Digit 0 or filler" },
 { 0x1, "Digit 1" },
 { 0x2, "Digit 2" },
 { 0x3, "Digit 3" },
 { 0x4, "Digit 4" },
 { 0x5, "Digit 5" },
 { 0x6, "Digit 6" },
 { 0x7, "Digit 7" },
 { 0x8, "Digit 8" },
 { 0x9, "Digit 9" },
 { 0xa, "Spare" },
 { 0xb, "Code 11" },
 { 0xc, "Code 12" },
 { 0xd, "*" },
 { 0xe, "#" },
 { 0xf, "ST" },
};

static const value_string ansi_tcap_national_parameter_digits[] = {
 { 0x0, "Remove Gap Control" },
 { 0x1, "0.00 Second" },
 { 0x2, "0.10 Seconds" },
 { 0x3, "0.25 Seconds" },
 { 0x4, "0.50 Seconds" },
 { 0x5, "1.00 Seconds" },
};

static const value_string ansi_tcap_national_parameter_spare[] = {
 { 0, "Service Not Supported" },
 { 1, "Active" },
 { 2, "Not Active" },
 { 3, "Spare" },
};

static const value_string ansi_tcap_national_parameter_dn_match[] = {
 { 0, "spare" },
 { 1, "No Match" },
 { 2, "Match" },
 { 3, "Spare" },
};

static const value_string ansi_tcap_national_parameter_dn_service_type[] = {
 { 0, "Individual" },
 { 1, "Coin" },
 { 2, "Series Completion" },
 { 3, "Multiline Hunt" },
 { 4, "Unassigned" },
 { 5, "PBX" },
 { 6, "Multiparty (3 or more)" },
 { 7, "Choke" },
 { 8, "Nonspecific" },
 { 9, "Temporarily Out-of-Service" },
};

static const value_string ansi_tcap_national_parameter_generic_name_type_of_name[] = {
 { 0, "Spare" },
 { 1, "Calling name" },
 { 2, "Original called name" },
 { 3, "Redirected name" },
 { 4, "Redirected name" },
 { 5, "Spare" },
 { 6, "Spare" },
 { 7, "Spare" },
};

static const value_string ansi_tcap_national_parameter_generic_name_availability[] = {
 { 0, "Name available/unknown" },
 { 1, "Name not available" },
};

static const value_string ansi_tcap_national_parameter_generic_name_presentation_field[] = {
 { 0, "Presentation Allowed" },
 { 1, "Presentation Restricted" },
 { 2, "Blocking Toggle" },
 { 3, "No Indication" },
};

static const value_string ansi_tcap_national_parameter_look_ahead_for_busy_ack[] = {
 { 0, "Path Reservation Denied" },
 { 1, "Negative Acknowledgement" },
 { 2, "Positive Acknowledgement" },
 { 3, "Spare" },
};

static const value_string ansi_tcap_national_parameter_look_ahead_for_busy_location_field[] = {
 { 0, "User" },
 { 1, "Private Network Serving The Local User" },
 { 3, "Public Network Serving The Local User" },
 { 4, "Transit Network" },
 { 5, "Public Network Serving The Remote User" },
 { 6, "Private Network Serving The Remote User" },
 { 8, "Reserved" },
 { 9, "Internation Network" },
 { 0xa, "Network Beyond Interworking Point" },
};

static const value_string ansi_tcap_national_parameter_level[] = {
 { 0, "Flash Override" },
 { 1, "Flash" },
 { 3, "Immediate" },
 { 4, "Priority" },
 { 5, "Routine" },
};

/* Parameter list*/

#define TIMESTAMP                               0x17
#define ACG_INDICATORS                          0x81
#define STANDARD_ANNOUNCEMENT                   0x82
#define CUSTOMIZED_ANNOUNCEMENT                 0x83
#define DIGITS                                  0x84
#define STANDARD_USER_ERROR_CODE                0x85
#define PROBLEM_DATA                            0x86
#define SCCP_CALLING_PARTY_ADDRESS              0x87
#define TRANSACTION_ID                          0x88
#define PACKAGE_TYPE                            0x89
#define SERVICE_KEY                             0x8a
#define BUSY_IDLE_STATUS                        0x8b
#define CALL_FORWARDING_STATUS                  0x8c
#define ORIGINATING_RESTRICTIONS                0x8d
#define TERMINATING_RESTRICTIONS                0x8e
#define DN_TO_LINE_SERVICE_TYPE_MAPPING         0x8f
#define DURATION                                0x90
#define RETURNED_DATA                           0x91
#define BEARER_CAPABILITY_REQUESTED             0x92
#define BEARER_CAPABILITY_SUPPORTED             0x93
#define REFERENCE_ID                            0x94
#define BUSINESS_GROUP                          0x95
#define SIGNALLING_NETWORKS_IDENTIFIER          0x96
#define GENERIC_NAME                            0x97
#define MESSAGE_WAITING_INDICATOR_TYPE          0x98
#define LOOK_AHEAD_FOR_BUSY                     0x99
#define CIRCUIT_IDENTIFICATION_CODE             0x9a
#define PRECEDENCE_IDENTIFIER                   0x9b
#define CALL_REFERENCE_IDENTIFIER               0x9c
#define AUTHORIZATION                           0x9d
#define INTEGRITY                               0x9e
#define SEQUENCE_NUMBER                         0x9f1f
#define NUMBER_OF_MESSAGES                      0x7f20
#define DISPLAY_TEXT                            0x7f21
#define KEY_EXCHANGE                            0x7f22
#define SCCP_CALLED_PARTY_ADDRESS               0x7f23

/* Transaction tracking */
/* Transaction table */
struct ansi_tcap_invokedata_t {
    gint OperationCode;
      /*
         0 : national,
         1 : private
      */
    gint32 OperationCode_private;
    gint32 OperationCode_national;
};

static wmem_multimap_t *TransactionId_table=NULL;

// nibble swap function
unsigned char swap_nibbles(unsigned char x){
    return (x & 0x0F)<<4 | (x & 0xF0)>>4;
}

int parameter_type(proto_tree *tree, tvbuff_t *tvb, int offset_parameter_type){
/* This case stament provides all the parameter choices
 A general parameter decoding looks like: Identifier -> Length -> Value 
 There is another case statment to account for the 'F' bit */  
  switch (tvb_get_guint8(tvb, offset_parameter_type))
  {
    case TIMESTAMP:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Timestamp");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Timestamp Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      int year;
      int month;
      int day;
      int hour;
      int minute;
      int difference;
      int local_hour;
      int local_minute;
      offset_parameter_type +=1;
      year = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      month = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      day = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      hour = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      minute = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      difference = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      local_hour = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      local_minute = tvb_get_gint8(tvb, offset_parameter_type);
      proto_tree_add_text_internal(tree, tvb, 0, offset_parameter_type, "the Timestamp is %x, %x %x, %x%x, time difference of %x %x%x", 
      year, month, day, hour, minute, difference, local_hour, local_minute);
      
    break;
    case ACG_INDICATORS:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "ACG Indicators");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "ACG Indicators Parameter Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_acg_control_cause_indicator, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_acg_duration_field, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_acg_gap, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
    break;
    case STANDARD_ANNOUNCEMENT:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Standard Announcement");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Standard Announcement Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      switch (tvb_get_guint8(tvb, offset_parameter_type))
      {
      case 0:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Not Used");
        break;
      case 1:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Out-of-Band");
        break;
      case 2:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Vacant Code");
        break;
      case 3:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Disconnected Number");
        break;
      case 4:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Reorder (120 IPM)");
        break;
      case 5:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Busy (60 IPM)");
        break;
      case 6:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "No Circuit Available");
        break;
      case 7:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Reorder");
        break;
      case 8:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Audible Ring");
        break;
      
      default:
        break;
      }
    break;
    case CUSTOMIZED_ANNOUNCEMENT:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Customized Announcement Format");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Customized Announcement Format Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      int announcement_length;
      announcement_length = tvb_get_guint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Announcement Set");
      for (int i = 0; i <= announcement_length; i++)
      {
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Announcement ID %d", i);
      }
    break;
    case DIGITS:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Digits");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Digits Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_type_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_nature_of_numbers, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_number_planning, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_encoding, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_number_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      int number_of_digits;
      number_of_digits = tvb_get_guint8(tvb, offset_parameter_type);
      for (int i = 0; i <= number_of_digits; i++)
      {
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      }
    break;
    case STANDARD_USER_ERROR_CODE:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Standard User Error Code");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Standard User Error Code Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      switch (tvb_get_guint8(tvb, offset_parameter_type))
      {
      case 0:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Call Abandoned");
        break;
      case 1:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Improper Caller Response");
        break;
      default:
        break;
      }
    break;
    case SCCP_CALLING_PARTY_ADDRESS:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "SCCP Calling Party Address");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "SCCP Calling Party Address Parameter Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "SCCP Calling Party Address Parameter Value");
    break;
    case TRANSACTION_ID:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Transaction ID");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Transaction ID Parameter Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Transaction ID Parameter Value");
    break;
    case PACKAGE_TYPE:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Package Type Identifier");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Package Type Identifier Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      switch (tvb_get_guint8(tvb, offset_parameter_type))
      {
      case 0xE1:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Unidirectional");
        break;
      case 0xE2:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Query with Permission");
        break;
      case 0xE3:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Query without Permission");
        break;
      case 0xE4:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Response");
        break;
      case 0xE5:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Conversation with Permission");
        break;
      case 0xE6:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Conversation without Permission");
        break;
      case 0xE7:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Abort");
        break;
      default:
        break;
      }
    break;
    /* extra case to account for form bit (F bit)*/
    case SERVICE_KEY: case 0xaa:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Service Key Identifier");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Service key parameter length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_digit_identifier, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_digit_length, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_destination_number_value, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_presentation_restirction, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_encoding_scheme, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_number_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      int phoneNumber[5];
      for (int j = 0; j < 5; j++)
      {
        offset_parameter_type +=1;
        phoneNumber[j] = swap_nibbles(tvb_get_gint8(tvb, offset_parameter_type));
      }
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type-4, 5, "The destination phone number is %x%x%x-%x%x", 
      phoneNumber[0], phoneNumber[1], phoneNumber[2], phoneNumber[3], phoneNumber[4]);      
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_digit_identifier, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_digit_length, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_destination_number_value, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_presentation_restirction, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_encoding_scheme, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_number_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      int phoneNumberReturn[5];
      for (int k = 0; k < 5; k++)
      {
        offset_parameter_type +=1;
        phoneNumberReturn[k] = swap_nibbles(tvb_get_gint8(tvb, offset_parameter_type));
      }
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type-4, 5, "The return phone number is %x%x%x-%x%x", 
      phoneNumberReturn[0], phoneNumberReturn[1], phoneNumberReturn[2], phoneNumberReturn[3], phoneNumberReturn[4]); 

      proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "offset value is %x", offset_parameter_type);
    break;
    case BUSY_IDLE_STATUS:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Busy Idle Status");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Busy Idle Status Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 1))
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Status Identifier is BUSY");
      }else
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Status Identifier is IDLE");
  }
    break;
    case CALL_FORWARDING_STATUS:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Call Forwarding Status");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Call Forwarding Status Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_call_forwarding_var, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_call_forwarding_on_busy, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_call_forwarding_dont_answer, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_selective_forwarding, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      
    break;
    case ORIGINATING_RESTRICTIONS:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Originating Restrictions");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Originating Restrictions Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      switch (tvb_get_guint8(tvb, offset_parameter_type))
      {
      case 0:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Denied Origination");
        break;
      case 1:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Fully Restricted Origination");
        break;
      case 2:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Semi-Restricted Origination");
        break;
      case 3:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Unrestricted Origination");
        break;
      default:
        break;
      }
    break;
    case TERMINATING_RESTRICTIONS:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Terminating Restrictions");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Terminating Restrictions Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      switch (tvb_get_guint8(tvb, offset_parameter_type))
      {
      case 0:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Denied Termination");
        break;
      case 1:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Fully Restricted Termination");
        break;
      case 2:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Semi-Restricted Termination");
        break;
      case 3:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Unrestricted Termination");
        break;
      case 4:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Call Rejections Applies");
        break;
      default:
        break;
      }
    break;
    case DN_TO_LINE_SERVICE_TYPE_MAPPING:
    proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "DN To Line Service Type Mapping");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "DN To Line Service Type Mapping Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_dn_match, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_dn_line_service, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
    break;
    case DURATION:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Duration");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Duration Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      int hour_duration;
      int minute_duration;
      int seconds_duration;
      offset_parameter_type +=1;
      hour_duration = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      minute_duration = tvb_get_gint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      seconds_duration = tvb_get_gint8(tvb, offset_parameter_type);
      proto_tree_add_text_internal(tree, tvb, 0, offset_parameter_type, "the call Duration is %x:%x:%x", 
      hour_duration, minute_duration, seconds_duration);
    break;
    case RETURNED_DATA:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Returned Data");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Returned Data Parameter Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Returned Data Parameter Value");
    break;
    case BEARER_CAPABILITY_REQUESTED:
    // TODO finishing out bearer capability, look into ansi_map
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Bearer Capability Requested");
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested1, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested2, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested2a, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested2b, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested3, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested3a, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
    break;
    case BEARER_CAPABILITY_SUPPORTED:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Bearer Capability Supported");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Parameter Length");
      if ((tvb_get_guint8(tvb, offset_parameter_type) == 0x00)){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;      
      switch (tvb_get_guint8(tvb, offset_parameter_type))
      {
      case 1:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Bearer Capability is not Supported");
        break;
      case 2:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Bearer Capability is Supported");
        break;
      case 3:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Bearer Capability Not Authorized");
        break;
      case 4:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Bearer Capability Not Presently Available");
        break;
      case 5:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Bearer Capability Not Implemented");
        break;
      default:
        break;
      }
    break;
    case REFERENCE_ID:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Reference ID");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Reference ID Parameter Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Reference ID Parameter Value");
    break;
    case BUSINESS_GROUP:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Business Group");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Business Group Length");
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_AttSt, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_BGID, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_LP11, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_Party_Selector, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=3;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 3, "Business Group ID");
      offset_parameter_type +=3;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 2, "Sub-Group ID");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Line Privileges");
    break;
    case SIGNALLING_NETWORKS_IDENTIFIER:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Signalling Networks Identifier");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Signalling Networks Identifier Parameter Length");
      offset_parameter_type +=1;
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      int signalling_networks_length;
      signalling_networks_length = tvb_get_guint8(tvb, offset_parameter_type);
      for (int i = 0; i <= signalling_networks_length; i++)
      {
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Signalling Networks ID %d", i+1);
      }
    break;
    case GENERIC_NAME:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Generic Name Identifier");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Generic Name Parameter Length");
      offset_parameter_type +=1;
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      int character_number;
      character_number = tvb_get_guint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_type_name, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_avalibility, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_presentation, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      for (int i = 1; i < character_number; i++)
      {
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Character number: %d", i);
      }
    break;
    case MESSAGE_WAITING_INDICATOR_TYPE:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Message Waiting Indicator Type");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Message Waiting Indicator Type Parameter Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      int contents;
      contents = swap_nibbles(tvb_get_gint8(tvb, offset_parameter_type));
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "The contents are: %x", contents);
    break;
    case LOOK_AHEAD_FOR_BUSY:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Look Ahead For Busy");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Look Ahead For Busy Parameter Length");      
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }

      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_look_ahead_for_busy_ack_type, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_look_ahead_for_busy_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_look_ahead_for_busy_location_field, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);

    break;
    case CIRCUIT_IDENTIFICATION_CODE:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Circuit Identification Code");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Circuit Identification Parameter Length");      
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "CIC Least Significant Bits");
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_CIC_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_CIC_msb, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
    break;
    case PRECEDENCE_IDENTIFIER:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Precedence Level");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Precedence Level Parameter Length");      
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_level_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_level, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      int ni_digit12;
      int ni_digit34;
      ni_digit12 = tvb_get_guint8(tvb, offset_parameter_type);
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "the 1st and 2nd NI digits are %x", ni_digit12);
      offset_parameter_type +=1;
      ni_digit34 = tvb_get_guint8(tvb, offset_parameter_type);
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "the 1st and 2nd NI digits are %x", ni_digit34);
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 3, "MLPP Service Domain");
    break;
    case CALL_REFERENCE_IDENTIFIER:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Call Reference Identifier");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Call Reference Identifier Parameter Length");      
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 3, "Call Identify");
      offset_parameter_type +=3;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 3, "Point Code");
      offset_parameter_type +=3;
    break;
    case AUTHORIZATION:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Authorization");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Authorization Parameter Length");
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0)
      {
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Authorization Parameter Value");
    break;
    case INTEGRITY:
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Intergrity");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Intergrity Parameter Length");      
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-1, 1, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Intergrity AlgID Parameter Identifier");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Intergrity AlgID Parameter Length");
      int intergrity_AlgID;
      intergrity_AlgID = tvb_get_guint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, intergrity_AlgID, "Intergrity AlgID Parameter Value");
      offset_parameter_type +=intergrity_AlgID;
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Intergrity Value Parameter Identifier");
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Intergrity Value Parameter Length");
      int intergrity_value;
      intergrity_value = tvb_get_guint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, intergrity_value, "Intergrity Value Parameter Value");
      offset_parameter_type +=intergrity_value;
    break;
    /* 2 octet length parameters identifiers */
    case 0x9F:
      if (tvb_get_guint8(tvb, offset_parameter_type+1) == 0x1f)
      {
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 2, "Sequence Number");
      offset_parameter_type +=2;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Sequence Number Parameter Length");      
      if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type-2, 2, "This parameter is asking to be returned");
        return offset_parameter_type;
      }
      int sequence_number_length;
      sequence_number_length = tvb_get_guint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      proto_tree_add_text_internal(tree, tvb, offset_parameter_type, sequence_number_length, "Sequence Number Parameter Value");
      offset_parameter_type +=sequence_number_length;
      }
      
    break;
    case 0x7f:
      switch (tvb_get_guint8(tvb, offset_parameter_type+1))
      {
      case 0x20:
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 2, "Number of Messages");
        offset_parameter_type +=2;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Number of Messages Parameter Length");      
        if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
          proto_tree_add_text_internal(tree, tvb, offset_parameter_type-2, 2, "This parameter is asking to be returned");
          return offset_parameter_type;
        }
        int number_of_messages_length;
        number_of_messages_length = tvb_get_guint8(tvb, offset_parameter_type);
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, number_of_messages_length, "Number of Messages Parameter Value");
        offset_parameter_type +=number_of_messages_length;
        break;
      case 0x21:
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 2, "Display Text");
        offset_parameter_type +=2;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Display Text Parameter Length");      
        if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
          proto_tree_add_text_internal(tree, tvb, offset_parameter_type-2, 2, "This parameter is asking to be returned");
          return offset_parameter_type;
        }
        offset_parameter_type +=1;
        int display_text_length;
        display_text_length = tvb_get_guint8(tvb, offset_parameter_type);
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, display_text_length, "Dispay Text Parameter Value");
        offset_parameter_type +=display_text_length;
        break;

      case 0x22:
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 2, "Key Exchange");
        offset_parameter_type +=2;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Key Exchange Parameter Length");      
        if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
          proto_tree_add_text_internal(tree, tvb, offset_parameter_type-2, 2, "This parameter is asking to be returned");
          return offset_parameter_type;
        }
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Key Exchange AlgID Parameter Identifier");
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Key Exchange AlgID Parameter Length");
        int key_exchange_AlgID;
        key_exchange_AlgID = tvb_get_guint8(tvb, offset_parameter_type);
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, key_exchange_AlgID, "Key Exchange AlgID Parameter Value");
        offset_parameter_type +=key_exchange_AlgID;
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Key Exchange Value Parameter Identifier");
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "Key Exchange Value Parameter Length");
        int key_exchange_value;
        key_exchange_value = tvb_get_guint8(tvb, offset_parameter_type);
        offset_parameter_type +=1;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, key_exchange_value, "Key Exchange Value Parameter Value");
        offset_parameter_type +=key_exchange_value;
        break;

      case 0x23:
      // TODO Parameter found in T1.112
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 2, "SCCP Called Party Address");
        offset_parameter_type +=2;
        proto_tree_add_text_internal(tree, tvb, offset_parameter_type, 1, "SCCP Called Party Address Parameter Length");      
        if (tvb_get_guint8(tvb, offset_parameter_type) == 0){
          proto_tree_add_text_internal(tree, tvb, offset_parameter_type-2, 2, "This parameter is asking to be returned");
          return offset_parameter_type;
        }
        offset_parameter_type +=1;
        break;
    
      default:
        break;
      }  

    default:
    break;
  }
  return offset_parameter_type;
}

/* Store Invoke information needed for the corresponding reply */
static void
save_invoke_data(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  gchar *src, *dst;
  char *buf;

  src = address_to_str(pinfo->pool, &(pinfo->src));
  dst = address_to_str(pinfo->pool, &(pinfo->dst));

  if ((!pinfo->fd->visited)&&(ansi_tcap_private.TransactionID_str)){

          /* Only do this once XXX I hope it's the right thing to do */
          /* The hash string needs to contain src and dest to distiguish differnt flows */
          switch(ansi_tcap_response_matching_type){
                        case ANSI_TCAP_TID_ONLY:
                                buf = wmem_strdup(pinfo->pool, ansi_tcap_private.TransactionID_str);
                                break;
                        case ANSI_TCAP_TID_AND_SOURCE:
                                buf = wmem_strdup_printf(pinfo->pool, "%s%s",ansi_tcap_private.TransactionID_str,src);
                                break;
                        case ANSI_TCAP_TID_SOURCE_AND_DEST:
                        default:
                                buf = wmem_strdup_printf(pinfo->pool, "%s%s%s",ansi_tcap_private.TransactionID_str,src,dst);
                                break;
                }

          ansi_tcap_saved_invokedata = wmem_new(wmem_file_scope(), struct ansi_tcap_invokedata_t);
          ansi_tcap_saved_invokedata->OperationCode = ansi_tcap_private.d.OperationCode;
          ansi_tcap_saved_invokedata->OperationCode_national = ansi_tcap_private.d.OperationCode_national;
          ansi_tcap_saved_invokedata->OperationCode_private = ansi_tcap_private.d.OperationCode_private;

          wmem_multimap_insert32(TransactionId_table,
                        wmem_strdup(wmem_file_scope(), buf),
                        pinfo->num,
                        ansi_tcap_saved_invokedata);
          /*
          ws_warning("Tcap Invoke Hash string %s",buf);
          */
  }
}

static gboolean
find_saved_invokedata(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  gchar *src, *dst;
  char *buf;

  if (!ansi_tcap_private.TransactionID_str) {
    return FALSE;
  }

  src = address_to_str(pinfo->pool, &(pinfo->src));
  dst = address_to_str(pinfo->pool, &(pinfo->dst));

  /* The hash string needs to contain src and dest to distiguish differnt flows */
  buf = (char *)wmem_alloc(pinfo->pool, MAX_TID_STR_LEN);
  buf[0] = '\0';
  /* Reverse order to invoke */
  switch(ansi_tcap_response_matching_type){
        case ANSI_TCAP_TID_ONLY:
                snprintf(buf,MAX_TID_STR_LEN,"%s",ansi_tcap_private.TransactionID_str);
                break;
        case ANSI_TCAP_TID_AND_SOURCE:
                snprintf(buf,MAX_TID_STR_LEN,"%s%s",ansi_tcap_private.TransactionID_str,dst);
                break;
        case ANSI_TCAP_TID_SOURCE_AND_DEST:
        default:
                snprintf(buf,MAX_TID_STR_LEN,"%s%s%s",ansi_tcap_private.TransactionID_str,dst,src);
                break;
  }

  ansi_tcap_saved_invokedata = (struct ansi_tcap_invokedata_t *)wmem_multimap_lookup32_le(TransactionId_table, buf, pinfo->num);
  if(ansi_tcap_saved_invokedata){
          ansi_tcap_private.d.OperationCode                      = ansi_tcap_saved_invokedata->OperationCode;
          ansi_tcap_private.d.OperationCode_national = ansi_tcap_saved_invokedata->OperationCode_national;
          ansi_tcap_private.d.OperationCode_private  = ansi_tcap_saved_invokedata->OperationCode_private;
          return TRUE;
  }
  return FALSE;
}

/* As currently ANSI MAP is the only possible sub dissector this function
 *  must be improved to handle general cases.
 *
 *
 *
 * TODO:
 * 1)Handle national codes
 *     Design option
 *     - Create a ansi.tcap.national dissector table and have dissectors for
 *       national codes register there and let ansi tcap call them.
 * 2)Handle Private codes properly
 *     Design question
 *     Unclear how to differentiate between different private "code sets".
 *     Use SCCP SSN table as before? or a ansi.tcap.private dissector table?
 *
 */
static gboolean
find_tcap_subdissector(tvbuff_t *tvb, asn1_ctx_t *actx, proto_tree *tree){
        proto_item *item;

        /* If "DialoguePortion objectApplicationId ObjectIDApplicationContext
         * points to the subdissector this code can be used.
         *
        if(ansi_tcap_private.d.oid_is_present){
                call_ber_oid_callback(ansi_tcap_private.objectApplicationId_oid, tvb, 0, actx-pinfo, tree, NULL);
                return TRUE;
        }
        */
        if(ansi_tcap_private.d.pdu == 1){
                /* Save Invoke data for this transaction */
                save_invoke_data(actx->pinfo, tree, tvb);
        }else{
                /* Get saved data for this transaction */
                /*actx->pinfo == (*actx).pinfo*/
                if(find_saved_invokedata(actx->pinfo, tree, tvb)){
                        if(ansi_tcap_private.d.OperationCode == 0){
                                /* national */
                                item = proto_tree_add_int(tree, hf_ansi_tcap_national, tvb, 0, 0, ansi_tcap_private.d.OperationCode_national);
                        }else{
                                item = proto_tree_add_int(tree, hf_ansi_tcap_private, tvb, 0, 0, ansi_tcap_private.d.OperationCode_private);
                        }
                        proto_item_set_generated(item);
                        ansi_tcap_private.d.OperationCode_item = item;
                }
        }
        if(ansi_tcap_private.d.OperationCode == 0){
                /* national */
                proto_item          *item2=NULL;
                proto_tree          *tree2=NULL;
                guint8 family = (ansi_tcap_private.d.OperationCode_national & 0x7f00)>>8;
                guint8 specifier = (guint8)(ansi_tcap_private.d.OperationCode_national & 0xff);
                if(!dissector_try_uint(ansi_tcap_national_opcode_table, ansi_tcap_private.d.OperationCode_national, tvb, actx->pinfo, actx->subtree.top_tree)){
                        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
                                        "Dissector for ANSI TCAP NATIONAL code:0x%x(Family %u, Specifier %u) \n"
                                        "test change 1",
                                        ansi_tcap_private.d.OperationCode_national, family, specifier);
                        item2 = proto_tree_add_text_internal(tree, tvb, 0, 1, "Parameters");
                        tree2 = proto_item_add_subtree(item2, ett_tcap);
                        gint offset_parameter = 0;
                        proto_tree_add_item(tree2, hf_ansi_tcap_parameter_set_start, tvb, 0, 1, ENC_BIG_ENDIAN);
                        
                        if(((tvb_get_guint8(tvb, 0)) & 0xff) == 0xf2){                        
                          offset_parameter += 1;
                          gint parameter_length = tvb_get_guint8(tvb, offset_parameter);
                          proto_tree_add_item(tree2, hf_ansi_tcap_parameter_length, tvb, offset_parameter, 1, ENC_BIG_ENDIAN);
                          offset_parameter += 1;
                          while (offset_parameter <= parameter_length)                        
                          {
                          offset_parameter = parameter_type(tree2, tvb, offset_parameter);
                          offset_parameter +=1;
                          }
                        }else{
                            proto_tree_add_text_internal(tree2, tvb, 0, 1, "No parameters exists");
                          }

                        return FALSE;
                }
                return TRUE;
        }else if(ansi_tcap_private.d.OperationCode == 1){
                /* private */
                if((ansi_tcap_private.d.OperationCode_private & 0xff00) == 0x0900){
                    /* This is abit of a hack as it assumes the private codes with a "family" of 0x09 is ANSI MAP
                    * See TODO above.
                    * N.S0005-0 v 1.0 TCAP Formats and Procedures 5-16 Application Services
                    * 6.3.2 Component Portion
                    * The Operation Code is partitioned into an Operation Family followed by a
                    * Specifier associated with each Operation Family member. For TIA/EIA-41 the
                    * Operation Family is coded as decimal 9. Bit H of the Operation Family is always
                    * coded as 0.
                    */
                    call_dissector_with_data(ansi_map_handle, tvb, actx->pinfo, actx->subtree.top_tree, &ansi_tcap_private);

                    return TRUE;
                } else if ((ansi_tcap_private.d.OperationCode_private & 0xf000) == 0x6000) {
                    call_dissector_with_data(ain_handle, tvb, actx->pinfo, actx->subtree.top_tree, &ansi_tcap_private);
                    return TRUE;
                }
        }
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
            "Dissector for ANSI TCAP PRIVATE code:%u not implemented.\n"
            "Contact Wireshark developers if you want this supported(Spec required)",
            ansi_tcap_private.d.OperationCode_private);
        return FALSE;
}

#include "packet-ansi_tcap-fn.c"




static int
dissect_ansi_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_item          *item=NULL;
    proto_tree          *tree=NULL;
#if 0
    proto_item          *stat_item=NULL;
    proto_tree          *stat_tree=NULL;
        gint                    offset = 0;
    struct tcaphash_context_t * p_tcap_context;
    dissector_handle_t subdissector_handle;
#endif
        asn1_ctx_t asn1_ctx;

        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
        ansi_tcap_ctx_init(&ansi_tcap_private);

    asn1_ctx.subtree.top_tree = parent_tree;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANSI TCAP");

    /* create display subtree for the protocol */
    if(parent_tree){
      item = proto_tree_add_item(parent_tree, proto_ansi_tcap, tvb, 0, -1, ENC_NA);
      tree = proto_item_add_subtree(item, ett_tcap);
    }
    cur_oid = NULL;
    tcapext_oid = NULL;

    gp_tcapsrt_info=tcapsrt_razinfo();
    tcap_subdissector_used=FALSE;
    gp_tcap_context=NULL;
    dissect_ansi_tcap_PackageType(FALSE, tvb, 0, &asn1_ctx, tree, -1);

#if 0 /* Skip this part for now it will be rewritten */
    if (g_ansi_tcap_HandleSRT && !tcap_subdissector_used ) {
                if (gtcap_DisplaySRT && tree) {
                        stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_ansi_tcap_stat, &stat_item, "Stat");
                        proto_item_set_generated(stat_item);
                }
                p_tcap_context=tcapsrt_call_matching(tvb, pinfo, stat_tree, gp_tcapsrt_info);
                ansi_tcap_private.context=p_tcap_context;

                /* If the current message is TCAP only,
                 * save the Application contexte name for the next messages
                 */
                if ( p_tcap_context && cur_oid && !p_tcap_context->oid_present ) {
                        /* Save the application context and the sub dissector */
                        (void) g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
                        if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
                                p_tcap_context->subdissector_handle=subdissector_handle;
                                p_tcap_context->oid_present=TRUE;
                        }
                }
                if (g_ansi_tcap_HandleSRT && p_tcap_context && p_tcap_context->callback) {
                        /* Callback fonction for the upper layer */
                        (p_tcap_context->callback)(tvb, pinfo, stat_tree, p_tcap_context);
                }
        }
#endif
    return tvb_captured_length(tvb);
}


void
proto_reg_handoff_ansi_tcap(void)
{
    ansi_map_handle = find_dissector_add_dependency("ansi_map", proto_ansi_tcap);
    ain_handle = find_dissector_add_dependency("ain", proto_ansi_tcap);
    ber_oid_dissector_table = find_dissector_table("ber.oid");
}



void
proto_register_ansi_tcap(void)
{
    module_t    *ansi_tcap_module;


/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
#if 0
        /* Tcap Service Response Time */
        { &hf_ansi_tcapsrt_SessionId,
          { "Session Id",
            "ansi_tcap.srt.session_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcapsrt_BeginSession,
          { "Begin Session",
            "ansi_tcap.srt.begin",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "SRT Begin of Session", HFILL }
        },
        { &hf_ansi_tcapsrt_EndSession,
          { "End Session",
            "ansi_tcap.srt.end",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "SRT End of Session", HFILL }
        },
        { &hf_ansi_tcapsrt_SessionTime,
          { "Session duration",
            "ansi_tcap.srt.sessiontime",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Duration of the TCAP session", HFILL }
        },
        { &hf_ansi_tcapsrt_Duplicate,
          { "Request Duplicate",
            "ansi_tcap.srt.duplicate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#endif
        { &hf_ansi_tcap_bit_h,
          { "Require Reply", "ansi_tcap.req_rep",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_op_family,
          { "Family",
            "ansi_tcap.op_family",
            FT_UINT16, BASE_DEC, VALS(ansi_tcap_national_op_code_family_vals), 0x7f00,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_op_specifier,
          { "Specifier",
            "ansi_tcap.op_specifier",
            FT_UINT16, BASE_DEC, NULL, 0x00ff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_set,
          { "Parameters",
            "ansi_tcap.parameter_set",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_set_start,
          { "Start of Parameters",
            "ansi_tcap.parameter_set_start",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_length,
          { "The length of this Parameter set/sequence is",
            "ansi_tcap.parameter_length",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_service_key_identifier,
          { "Service key identifier",
            "ansi_tcap.hf_ansi_tcap_service_key_identifier",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_digit_identifier,
          { "Service key digit identifier",
            "ansi_tcap.hf_ansi_tcap_digit_identifier",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_digit_length,
          { "Service key digit length",
            "ansi_tcap.hf_ansi_tcap_digit_length",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_destination_number_value,
          { "Destination number value",
            "ansi_tcap.hf_ansi_tcap_destination_number_value",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_presentation_restirction,
          { "Presentation restriction indicator",
            "ansi_tcap.hf_ansi_tcap_presentation_restirction",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_encoding_scheme,
          { "Encoding scheme and number planning is",
            "ansi_tcap.hf_ansi_tcap_encoding_scheme",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_number_of_digits,
          { "Amount of digits in this phone number are",
            "ansi_tcap.hf_ansi_tcap_number_of_digits",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_call_forwarding_var,
          { "Call Forwarding Variable",
            "ansi_tcap.call_forwarding",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0xC0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_call_forwarding_on_busy,
          { "Call Forwarding On Busy",
            "ansi_tcap.call_forwarding_on_busy",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x30,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_call_forwarding_dont_answer,
          { "Call Forwarding Don't Answer",
            "ansi_tcap.call_forwarding_dont_answer",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x0C,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_selective_forwarding,
          { "Selective Forwarding",
            "ansi_tcap.selective_forwarding",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_dn_match,
          { "DN Match",
            "ansi_tcap.dn_matc",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_dn_match), 0xC0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_dn_line_service,
          { "DN Line Service",
            "ansi_tcap.dn_line_service",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_dn_service_type), 0x3F,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_spare,
          { "Spare",
            "ansi_tcap.business_group_length_spare",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_AttSt,
          { "AttSt",
            "ansi_tcap.business_group_length_AttSt",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_BGID,
          { "BGID",
            "ansi_tcap.business_group_length_BGID",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_LP11,
          { "LP11",
            "ansi_tcap.business_group_length_LP11",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_Party_Selector,
          { "Party Selector",
            "ansi_tcap.business_group_length_Party_Selector",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_type_name,
          { "Generic Name Type",
            "ansi_tcap.generic_name_type_name",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_generic_name_type_of_name), 0xD0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_avalibility,
          { "Generic Name Avalibility",
            "ansi_tcap.generic_name_avalibility",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_generic_name_availability), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_spare,
          { "Generic Name Spare",
            "ansi_tcap.generic_name_type_name_spare",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x0C,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_presentation,
          { "Generic Name Presentation",
            "ansi_tcap.generic_name_type_name_presentation",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_generic_name_presentation_field), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_look_ahead_for_busy_ack_type,
          { "Act. Type",
            "ansi_tcap.look_ahead_for_busy_ack_type",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_look_ahead_for_busy_ack), 0xC0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_look_ahead_for_busy_spare,
          { "Spare",
            "ansi_tcap.look_ahead_for_busy_spare",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x30,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_look_ahead_for_busy_location_field,
          { "Location",
            "ansi_tcap.look_ahead_for_busy_location",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_look_ahead_for_busy_location_field), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_acg_control_cause_indicator,
          { "Control Cause Indicator",
            "ansi_tcap.acg_control_cause_indicator",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_control_cause_indication), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_acg_duration_field,
          { "Duration Field",
            "ansi_tcap.acg_duration_field",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_duration_field), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_acg_gap,
          { "Gap",
            "ansi_tcap.acg_gap",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_gap), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_type_of_digits,
          { "Gap",
            "ansi_tcap.acg_gap",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_type_of_digits), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_nature_of_numbers,
          { "Gap",
            "ansi_tcap.acg_gap",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_nature_of_numbers), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_number_planning,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_number_planning), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_encoding,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_encoding), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_number_of_digits,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_number_of_digits), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits), 0xff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_CIC_spare,
          { "CIC Spare",
            "ansi_tcap.CIC_spare",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_CIC_msb,
          { "CIC Most Significant Bits",
            "ansi_tcap.CIC_msb",
            FT_UINT8, BASE_HEX, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_level_spare,
          { "Precedence Level Spare",
            "ansi_tcap.precedence_level_spare",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_level,
          { "Precedence Level",
            "ansi_tcap.precedence_level",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_level), 0x0F,
            NULL, HFILL }
        },

#include "packet-ansi_tcap-hfarr.c"
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_tcap,
        &ett_param,
        &ett_otid,
        &ett_dtid,
        &ett_ansi_tcap_stat,
        &ett_ansi_tcap_op_code_nat,
        #include "packet-ansi_tcap-ettarr.c"
    };

    static ei_register_info ei[] = {
        { &ei_ansi_tcap_dissector_not_implemented, { "ansi_tcap.dissector_not_implemented", PI_UNDECODED, PI_WARN, "Dissector not implemented", EXPFILL }},
    };

    expert_module_t* expert_ansi_tcap;

    static const enum_val_t ansi_tcap_response_matching_type_values[] = {
        {"Only Transaction ID will be used in Invoke/response matching",                        "Transaction ID only", ANSI_TCAP_TID_ONLY},
        {"Transaction ID and Source will be used in Invoke/response matching",                  "Transaction ID and Source", ANSI_TCAP_TID_AND_SOURCE},
        {"Transaction ID Source and Destination will be used in Invoke/response matching",      "Transaction ID Source and Destination", ANSI_TCAP_TID_SOURCE_AND_DEST},
        {NULL, NULL, -1}
    };

/* Register the protocol name and description */
    proto_ansi_tcap = proto_register_protocol(PNAME, PSNAME, PFNAME);
    register_dissector("ansi_tcap", dissect_ansi_tcap, proto_ansi_tcap);

   /* Note the high bit should be masked off when registering in this table (0x7fff)*/
   ansi_tcap_national_opcode_table = register_dissector_table("ansi_tcap.nat.opcode", "ANSI TCAP National Opcodes", proto_ansi_tcap, FT_UINT16, BASE_DEC);
/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_tcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ansi_tcap = expert_register_protocol(proto_ansi_tcap);
    expert_register_field_array(expert_ansi_tcap, ei, array_length(ei));

    ansi_tcap_module = prefs_register_protocol(proto_ansi_tcap, proto_reg_handoff_ansi_tcap);

    prefs_register_enum_preference(ansi_tcap_module, "transaction.matchtype",
                                   "Type of matching invoke/response",
                                   "Type of matching invoke/response, risk of mismatch if loose matching chosen",
                                   &ansi_tcap_response_matching_type, ansi_tcap_response_matching_type_values, FALSE);

    TransactionId_table = wmem_multimap_new_autoreset(wmem_epan_scope(), wmem_file_scope(), wmem_str_hash, g_str_equal);
}
