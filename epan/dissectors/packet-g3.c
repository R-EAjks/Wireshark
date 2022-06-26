/* packet-g3.c
 *
 * Dissector for ITU-T Rec. G.9903 (G3-PLC) CENELEC, FCC and ARIB
 * By Klaus Hueske <Klaus.Hueske@renesas.com>
 * Copyright 2020 Renesas Electronics Europe GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/******************************************************************************
*  Includes   <System Includes> , "Project Includes"
******************************************************************************/
#include "config.h"
#include <string.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-ieee802154.h>
#include <epan/address_types.h>
#include <epan/address.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/proto_data.h>
#include <wiretap/wtap.h>
#include <wsutil/pint.h>
#include <wsutil/crc16.h>

/* Use libgcrypt for cipher libraries. */
#include <wsutil/wsgcrypt.h>

#include "packet-g3.h"

/******************************************************************************
*  Typedef definitions
******************************************************************************/

/* Key management structures based on UAT */
typedef struct
{
    unsigned pan_id;   /* 16-bit PAN Address. Range: 0x0000 - 0xFFFF     */
    char *gmk0;        /* 16-byte Security Key 0. Allocated dynamically  */
    unsigned gmk0_len; /* Length of the GMK0 key. Should always be 16    */
    char *gmk1;        /* 16-byte Security Key 1. Allocated dynamically  */
    unsigned gmk1_len; /* Length of the GMK1 key. Should always be 16    */
} static_keys_t;

typedef struct
{
    char *eui64;        /* 8-byte EUI-64. Allocated dynamically     */
    unsigned eui64_len; /* Length of the EUI-64. Should always be 8 */
    char *psk;          /* 16-byte PSK. Allocated dynamically       */
    unsigned psk_len;   /* Length of the PSK. Should always be 16   */
} psk_t;

typedef struct
{
    guint8 id;
    guint8 key[16];
} extracted_gmk_t;

/* Frame types for acknowledgement linking */
typedef enum
{
    ACK_LINK_DATA,
    ACK_LINK_ACK,
    ACK_LINK_NACK,
} ack_link_frame_type_t;

/* Acknowledgement linking transaction structure */
typedef struct
{
    guint32 data_frame_num;         /* Data frame number */
    guint32 ack_frame_num;          /* Corresponding ack frame number */
    gboolean is_ack;                /* Type of acknowledgement */
    nstime_t data_frame_time;       /* Time when the data frame was received */
} g3_ack_link_t;

typedef struct
{
    guint8 rand_s[16];  // session ID (in message 2 & 3)
    guint8 rand_p[16];  // from message 2
    guint8 id_p[8];  // from message 2
    gboolean msg2_processed;
} eap_psk_exchange_t;

/******************************************************************************
*  Macro definitions
******************************************************************************/
#define G3_GMK_LENGTH              (16u)

#define G3_FOOTER_BASE_LENGTH      (1 + 1 + 1 + 4 + 4 + 1 + 1 + 1)
#define G3_FOOTER_CARRIER_LENGTH   (72u)

#define G3_CEN_FCH_LENGTH          (5u)
#define G3_FCC_FCH_LENGTH          (9u)

/* Masks for fields in the CENELEC FCH */
#define G3_CEN_FCH_MOD_MSK         (0xC0)
#define G3_CEN_FCH_FL_MSK          (0x3F)
#define G3_CEN_FCH_TM_MSK          (0x3F)
#define G3_CEN_FCH_PAY_MOD_SCH_MSK (0x80)
#define G3_CEN_FCH_DT_MSK          (0x70)
#define G3_CEN_FCH_FCCS_MSK        (0x0F80)
#define G3_CEN_FCH_MOD_G3BASE_MSK  (0xC080)

/* Masks for fields in the FCC FCH */
#define G3_FCC_FCH_MOD_MSK         (0xE0)
#define G3_FCC_FCH_PAY_MOD_SCH_MSK (0x10)
#define G3_FCC_FCH_DT_MSK          (0x0E)
#define G3_FCC_FCH_FL_MSK          (0x01FF)
#define G3_FCC_FCH_TM_MSK          (0x00FFFFFF)
#define G3_FCC_FCH_TWO_RS_MSK      (0x10)
#define G3_FCC_FCH_FCCS_MSK        (0x3FC0)

/* Mask for reserved fields in pre 2015 IEEE 802.15.4 aux sec header */
#define IEEE802154_AUX_KEY_RESERVED_MASK (0xE0)

#define PROTO_TAG_G3BEACON           "G3BEACON"
#define PROTO_TAG_G3COMMAND          "G3COMMAND"
#define PROTO_TAG_G3DATA             "G3DATA"

/* Masks for fields in the Tone Map Response */
#define G3_TMR_TXRES_MSK             (0x80)
#define G3_TMR_TXGAIN_MSK            (0x78)
#define G3_TMR_MOD_MSK               (0x06)
#define G3_TMR_MOD_SCH_MSK           (0x01)
#define G3_TMR_TM_MSK                (0x3F)
#define G3_TMR_TXCOEFF_NIBBLE_HI_MSK (0xF0)
#define G3_TMR_TXCOEFF_NIBBLE_LO_MSK (0x0F)

/* Masks for fields in the Tone Map Response */
#define G3_FCC_TMR_TXRES_MSK    (0x80)
#define G3_FCC_TMR_TXGAIN_MSK   (0x78)
#define G3_FCC_TMR_MOD_MSK      (0x07)
#define G3_FCC_TMR_TM_MSK       (0x00FFFFFF)
#define G3_FCC_TMR_TXCOEFF_B76  (0xC0)
#define G3_FCC_TMR_TXCOEFF_B54  (0x30)
#define G3_FCC_TMR_TXCOEFF_B32  (0x0C)
#define G3_FCC_TMR_TXCOEFF_B10  (0x03)
#define G3_FCC_TMR_MOD_SCH_MSK  (0x80)

#define R_EAP_PSK_DONE_SUCCESS_WITH_EXT    (0xA0u) //!< 0b10000000 for DONE_FAILURE and 0x00100000 for present extension
#define R_EAP_PSK_EXT_TYPE_G3              (0x02u) //!< G3 PLC configuration data

/******************************************************************************
*  Imported global variables and functions (from other files)
******************************************************************************/

/******************************************************************************
*  Exported global variables and functions (to be accessed by other files)
******************************************************************************/

/******************************************************************************
*  Private global variables
******************************************************************************/

/* Key Management */

/* The UAT table itself containing an array of static_keys_t entries */
static uat_t *static_keys_uat = NULL;

static static_keys_t *static_keys     = NULL; /* The keys */
static guint          num_static_keys = 0;    /* The number of keys */

/*
 *  Static variables that hold the last pan_id, key_index and gmk returned
 *  by the lookup_key function. This acts as the simplest cache possible but
 *  works very efficiently, avoiding in most cases a linear search over the
 *  array of static_keys.
 */
static guint8 last_key_index = 0xff; /* only 0/1 allowed -> mark as invalid */
static guint16 last_pan_id = 0;
static const guint8 *last_gmk = NULL;

/*
 *  The UAT interface works almost exclusively with callbacks and functions
 *  defined inside macros. The following functions define the update
 *  functions for each field in the static_keys structure.
 */

/* Field callbacks. */
UAT_HEX_CB_DEF(keys_uat, pan_id, static_keys_t)
UAT_BUFFER_CB_DEF(keys_uat, gmk0, static_keys_t, gmk0, gmk0_len)
UAT_BUFFER_CB_DEF(keys_uat, gmk1, static_keys_t, gmk1, gmk1_len)

/* PSK UAT table and callbacks */
static uat_t *psks_uat = NULL;
static psk_t *psks = NULL;
static guint num_psks = 0;
UAT_BUFFER_CB_DEF(psks_uat, eui64, psk_t, eui64, eui64_len)
UAT_BUFFER_CB_DEF(psks_uat, psk, psk_t, psk, psk_len)

/* Other preferences */
static gboolean extract_gmks_from_eap = TRUE;
static gboolean use_universal_psk = FALSE;
static const gchar *universal_psk_string = "ab10341145111bc3c12de8ff11142204";

/* GMK extraction */
static wmem_tree_t *extracted_gmk0s;
static wmem_tree_t *extracted_gmk1s;
static gboolean universal_psk_valid;
static guint8 universal_psk_bytes[16];

static g3_hints_t *g3_hints = NULL;
static gboolean cenelec_is_b;
static gboolean standard_is_G3Base;
static const gchar *bandplan_name[] = {
    "G3-CenelecA/B",
    "G3-FCC/ARIB",
    "G3-CenelecA",
    "G3-CenelecB",
    "G3-FCC",
    "G3-ARIB"
};

/* Wireshark entities */

/* Wireshark ID of the G3 protocol */
static int proto_g3 = -1;

/* Wireshark ID of the G3BEACON protocol */
static int proto_g3beacon = -1;

/* Wireshark ID of the G3COMMAND protocol */
static int proto_g3command = -1;

/* Wireshark ID of the G3_FCCCOMMAND protocol */
static int proto_g3_fcccommand = -1;

/* Wireshark ID of the G3DATA protocol */
static int proto_g3data = -1;

/* These are the handles needed by our subdissectors */
static dissector_handle_t g3_handle;
static dissector_handle_t g3beacon_handle;
static dissector_handle_t g3_cen_command_handle;
static dissector_handle_t g3_fcc_command_handle;
static dissector_handle_t g3data_handle;
static dissector_handle_t data_handle;
static dissector_handle_t data6lowpan_handle;

/* Fragmentation and reassembly */
static reassembly_table msg_reassembly_table;

/* Acknowledgement linking */
static wmem_tree_t *ack_links[65536];  // FCS -> tree of ack links

/* The hash map for the gmk extraction */
static wmem_map_t *eap_psk_exchange_map;

/* CENELEC FCH */
static const value_string packetmodulationtype_cen_dif[] = {
    { 0, "Robust" },
    { 1, "DBPSK"  },
    { 2, "DQPSK"  },
    { 3, "D8PSK"  },
    { 0, NULL     }
};

static const value_string packetmodulationtype_cen_coh[] = {
    { 0, "Robust" },
    { 1, "BPSK"   },
    { 2, "QPSK"   },
    { 3, "8PSK"   },
    { 0, NULL     }
};

static const value_string packetmodulationtype_cen_dif_g3base[] = {
    { 0x000, "Robust"            },
    { 0x080, "DBPSK"             },
    { 0x100, "DQPSK"             },
    { 0x180, "D8PSK"             },
    { 0x001, "Reserved by ITU-T" },
    { 0x081, "Super ROBO"        },
    { 0x101, "Reserved by ITU-T" },
    { 0x181, "Reserved by ITU-T" },
    { 0, NULL                    }
};

static const value_string packetmodulationtype_cen_coh_g3base[] = {
    { 0x000, "Robust"            },
    { 0x080, "BPSK"              },
    { 0x100, "QPSK"              },
    { 0x180, "8PSK"              },
    { 0x001, "16QAM"             },
    { 0x081, "Super ROBO"        },
    { 0x101, "64QAM"             },
    { 0x181, "256QAM"            },
    { 0, NULL                    }
};

static const value_string packetdelimitertype_cen[] = {
    { 0, "Start of frame with no response expected" },
    { 1, "Start of frame with response expected"    },
    { 2, "Reserved by ITU-T"                        },
    { 3, "Reserved by ITU-T"                        },
    { 4, "Reserved by ITU-T"                        },
    { 5, "Reserved by ITU-T"                        },
    { 6, "Reserved by ITU-T"                        },
    { 7, "Reserved by ITU-T"                        },
    { 0, NULL                                       }
};

static const value_string packetmodulationscheme_cen[] = {
    { 0, "Differential" },
    { 1, "Coherent"     },
    { 0, NULL           }
};

static const value_string packettonemaprequest_cen[] = {
    { 0, "Not requested" },
    { 1, "Requested"     },
    { 0, NULL            }
};

/* FCC FCH */
static const value_string packetmodulationtype_fcc_dif[] = {
    { 0, "Robust"            },
    { 1, "DBPSK"             },
    { 2, "DQPSK"             },
    { 3, "D8PSK"             },
    { 4, "Reserved by ITU-T" },
    { 5, "Reserved by ITU-T" },
    { 6, "Reserved by ITU-T" },
    { 7, "Reserved by ITU-T" },
    { 0, NULL                }
};

static const value_string packetmodulationtype_fcc_coh[] = {
    { 0, "Robust"            },
    { 1, "BPSK"              },
    { 2, "QPSK"              },
    { 3, "8PSK"              },
    { 4, "16QAM"             },
    { 5, "Reserved by ITU-T" },
    { 6, "Reserved by ITU-T" },
    { 7, "Reserved by ITU-T" },
    { 0, NULL                }
};

static const value_string packetmodulationtype_fcc_dif_g3base[] = {
    { 0, "Robust"            },
    { 1, "DBPSK"             },
    { 2, "DQPSK"             },
    { 3, "D8PSK"             },
    { 4, "Reserved by ITU-T" },
    { 5, "Super ROBO"        },
    { 6, "Reserved by ITU-T" },
    { 7, "Reserved by ITU-T" },
    { 0, NULL                }
};

static const value_string packetmodulationtype_fcc_coh_g3base[] = {
    { 0, "Robust"            },
    { 1, "BPSK"              },
    { 2, "QPSK"              },
    { 3, "8PSK"              },
    { 4, "16QAM"             },
    { 5, "Super ROBO"        },
    { 6, "64QAM"             },
    { 7, "256QAM"            },
    { 0, NULL                }
};

static const value_string packetmodulationscheme_fcc[] = {
    { 0, "Differential" },
    { 1, "Coherent"     },
    { 0, NULL           }
};

static const value_string packetdelimitertype_fcc[] = {
    { 0, "Start of frame with no response expected" },
    { 1, "Start of frame with response expected"    },
    { 2, "Reserved by ITU-T"                        },
    { 3, "Reserved by ITU-T"                        },
    { 4, "Reserved by ITU-T"                        },
    { 5, "Reserved by ITU-T"                        },
    { 6, "Reserved by ITU-T"                        },
    { 7, "Reserved by ITU-T"                        },
    { 0, NULL                                       }
};

static const value_string packettworsblocks_fcc[] = {
    { 0, "Transmitting two RS blocks" },
    { 1, "Transmitting one RS block"  },
    { 0, NULL                         }
};

static const value_string g3_cen_ack_dt_vals[] = {
    { 2, "Positive acknowledgement (ACK)"  },
    { 3, "Negative acknowledgement (NACK)" },
    { 0, NULL }
};

static const value_string g3_fcc_ack_dt_vals[] = {
    { 2, "Positive acknowledgement (ACK)"  },
    { 3, "Negative acknowledgement (NACK)" },
    { 0, NULL }
};

/* MAC */
static const value_string packetcontentioncontrol[] = {
    { 0, "Allowed in next contention state" },
    { 1, "Free access"                      },
    { 0, NULL                               }
};

static const value_string packetchannelaccesspriority[] = {
    { 0, "Normal" },
    { 1, "High"   },
    { 0, NULL     }
};

static const value_string packetlastsegmentflag[] = {
    { 0, "Not last segment" },
    { 1, "Last segment"     },
    { 0, NULL               }
};

static const value_string packetframetype[] = {
    { 0, "Beacon"         },
    { 1, "Data"           },
    { 2, "Acknowledgment" },
    { 3, "MAC command"    },
    { 4, "Reserved"       },
    { 5, "Reserved"       },
    { 6, "Reserved"       },
    { 7, "Reserved"       },
    { 0, NULL             }
};

static const value_string packetsecurityenabled[] = {
    { 0, "No"  },
    { 1, "Yes" },
    { 0, NULL  }
};

static const value_string packetframepending[] = {
    { 0, "No"  },
    { 1, "Yes" },
    { 0, NULL  }
};

static const value_string packetackrequest[] = {
    { 0, "No"  },
    { 1, "Yes" },
    { 0, NULL  }
};

static const value_string packetpanidcompression[] = {
    { 0, "No"  },
    { 1, "Yes" },
    { 0, NULL  }
};

static const value_string packetaddrmode[] = {
    { 0, "Pan ID and Address Field are not present" },
    { 1, "Reserved"                                 },
    { 2, "16 Bit Short Address"                     },
    { 3, "64 Bit Extended Address"                  },
    { 0, NULL  }
};

static const value_string g3_sec_level_names[] = {
    { SECURITY_LEVEL_NONE,        "No Security" },
    { SECURITY_LEVEL_MIC_32,      "32-bit Message Integrity Code" },
    { SECURITY_LEVEL_MIC_64,      "64-bit Message Integrity Code" },
    { SECURITY_LEVEL_MIC_128,     "128-bit Message Integrity Code" },
    { SECURITY_LEVEL_ENC,         "Encryption" },
    { SECURITY_LEVEL_ENC_MIC_32,  "Encryption with 32-bit Message Integrity Code" },
    { SECURITY_LEVEL_ENC_MIC_64,  "Encryption with 64-bit Message Integrity Code" },
    { SECURITY_LEVEL_ENC_MIC_128, "Encryption with 128-bit Message Integrity Code" },
    { 0, NULL }
};

static const value_string g3_key_id_mode_names[] = {
    { KEY_ID_MODE_IMPLICIT,       "Implicit Key" },
    { KEY_ID_MODE_KEY_INDEX,      "Indexed Key using the Default Key Source" },
    { KEY_ID_MODE_KEY_EXPLICIT_4, "Explicit Key with 4-octet Key Source" },
    { KEY_ID_MODE_KEY_EXPLICIT_8, "Explicit Key with 8-octet Key Source" },
    { 0, NULL }
};

static const range_string cfitype[]          = {
    { 0x00, 0x06, "Reserved by ITU-T" },
    { 0x07, 0x07, "Beacon request"    },
    { 0x08, 0x09, "Reserved by ITU-T" },
    { 0x0A, 0x0A, "Tone map response" },
    { 0x0B, 0xFF, "Reserved by ITU-T" },
    { 0, 0, NULL                      }
};

static const value_string txgainres[] = {
    { 0, "6 dB" },
    { 1, "3 dB" },
    { 0, NULL   }
};

static const value_string modtype_dif[] = {
    { 0, "Robust"            },
    { 1, "DBPSK"            },
    { 2, "DQPSK"            },
    { 3, "D8PSK"            },
    { 4, "Reserved by ITU-T" },
    { 5, "Reserved by ITU-T" },
    { 6, "Reserved by ITU-T" },
    { 7, "Reserved by ITU-T" },
    { 0, NULL                }
};

static const value_string modtype_coh[] = {
    { 0, "Robust"            },
    { 1, "BPSK"              },
    { 2, "QPSK"              },
    { 3, "8PSK"              },
    { 4, "16QAM"             },
    { 5, "Reserved by ITU-T" },
    { 6, "Reserved by ITU-T" },
    { 7, "Reserved by ITU-T" },
    { 0, NULL                }
};

static const value_string modsch[] = {
    { 0, "Differential" },
    { 1, "Coherent"     },
    { 0, NULL           }
};

static const value_string veryfirst[] = {
    { 0, "64 Bit Extended Address" },
    { 1, "16 Bit Short Address"    },
    { 0, NULL                      }
};

static const value_string cfhtype[] = {
    { 0x00, "Reserved"                              },
    { 0x01, "Mesh routing message"                  },
    { 0x02, "LoWPAN Bootstrapping Protocol message" },
    { 0x03, "Contention Free Access Command"        },
    { 0, NULL                                       }
};

static const value_string cfatype[] = {
    { 0, "Request to allow a transmission during contention free slot" },
    { 1, "Request to stop a transmission during contention free slot"  },
    { 2, "Response with SUCCESS"                                       },
    { 3, "Response with FAIL"                                          },
    { 0, NULL                                                          }
};

static const value_string messagetype[] = {
    {   0, "Route Request"             },
    {   1, "Route Reply"               },
    {   2, "Route Error"               },
    { 252, "Path Request"              },
    { 253, "Path Reply"                },
    { 254, "Reverse Link Cost Request" },
    { 255, "Reverse Link Cost Reply"   },
    { 0, NULL                          }
};

static const value_string mediatype[] = {
    { 0, "PLC" },
    { 1, "RF"  },
    { 0, NULL             }
};

static const value_string lbptype[] = {
    { 0, "Message from LBD" },
    { 1, "Message to LBD"   },
    { 0, NULL               }
};

static const value_string lbpcodeto[] = {
    { 0, "Reserved"  },
    { 1, "Accepted"  },
    { 2, "Challenge" },
    { 3, "Decline"   },
    { 4, "Kick"      },
    { 0, NULL        }
};

static const value_string lbpcodefrom[] = {
    { 0, "Reserved" },
    { 1, "Joining"  },
    { 4, "Kick"     },
    { 5, "Conflict" },
    { 0, NULL       }
};

static const value_string lbpeapcode[] = {
    { 1, "Request"  },
    { 2, "Response" },
    { 3, "Success"  },
    { 4, "Failure"  },
    { 0, NULL       }
};

static const value_string tflag[] = {
    { 0, "First Message"  },
    { 1, "Second Message" },
    { 2, "Third Message"  },
    { 3, "Fourth Message" },
    { 0, NULL             }
};

static const value_string eaptypes[] = {
    {   1, "Identity"                 },
    {   2, "Notification"             },
    {   3, "Nak"                      },
    {   4, "MD5-Challenge"            },
    {   5, "One Time Password (OTP)"  },
    {   6, "Generic Token Card (GTC)" },
    {  47, "EAP-PSk"                  },
    { 254, "Expanded Nak"             },
    { 255, "Experimental use"         },
    { 0, NULL                         }
};

static const value_string g3data_hop_phase_diff_vals[] = {
    { 0, "Not supported"              },
    { 1, "0 phase differential"       },
    { 2, "60 phase differential"      },
    { 3, "120 phase differential"     },
    { 4, "180 phase differential"     },
    { 5, "240 phase differential"     },
    { 6, "300 phase differential"     },
    { 7, "Unknown phase differential" },
    { 0, NULL                         }
};

static const value_string g3data_lbp_cfg_attr_id_vals[] = {
    { 7, "Short_Addr"       },
    { 9, "GMK"              },
    {10, "GMK-activation"   },
    {11, "GMK-removal"      },
    {12, "Parameter-result" },
    { 0, NULL }
};

static const value_string g3data_lbp_cfg_M_vals[] = {
    { 0, "Device specific information (DSI)" },
    { 1, "PAN specific information (PSI)"    },
    { 0, NULL }
};

static const value_string g3data_lbp_cfg_value_parameter_result_result_vals[] = {
    { 0, "Success"                    },
    { 1, "Missing required parameter" },
    { 2, "Invalid parameter value"    },
    { 3, "Unknown parameter ID"       },
    { 0, NULL }
};

static const value_string g3data_lbp_cfg_value_parameter_result_attr_id_vals[] = {
    { 0, "Success -> Ignored" },
    { 7, "Short_Addr"         },
    { 9, "GMK"                },
    {10, "GMK-activation"     },
    {11, "GMK-removal"        },
    {12, "Parameter-result"   },
    { 0, NULL }
};

/* The following hf_* variables are used to hold the Wireshark IDs of
 * the header fields; they are filled out when we call
 * proto_register_field_array() in proto_register_g3() */

/* Kts attempt at defining the protocol */
static gint hf_g3_macpayload = -1;

/* Frame control header CENELEC */
static gint hf_g3_cen_fch             = -1;
static gint hf_g3_cen_fch_PDC         = -1;
static gint hf_g3_cen_fch_MOD_dif     = -1;
static gint hf_g3_cen_fch_MOD_coh     = -1;
static gint hf_g3_cen_fch_MOD_dif_g3base = -1;
static gint hf_g3_cen_fch_MOD_coh_g3base = -1;
static gint hf_g3_cen_fch_FL          = -1;
static gint hf_g3_cen_fch_TM          = -1;
static gint hf_g3_cen_fch_PAY_MOD_SCH = -1;
static gint hf_g3_cen_fch_DT          = -1;
static gint hf_g3_cen_fch_FCCS        = -1;

/* Frame control header FCC */
static gint hf_g3_fcc_fch             = -1;
static gint hf_g3_fcc_fch_PDC         = -1;
static gint hf_g3_fcc_fch_MOD_dif     = -1;
static gint hf_g3_fcc_fch_MOD_coh     = -1;
static gint hf_g3_fcc_fch_MOD_dif_g3base = -1;
static gint hf_g3_fcc_fch_MOD_coh_g3base = -1;
static gint hf_g3_fcc_fch_PAY_MOD_SCH = -1;
static gint hf_g3_fcc_fch_DT          = -1;
static gint hf_g3_fcc_fch_FL          = -1;
static gint hf_g3_fcc_fch_TM          = -1;
static gint hf_g3_fcc_fch_TWO_RS      = -1;
static gint hf_g3_fcc_fch_FCCS        = -1;

static int hf_g3_cen_ack_fcs_1          = -1;
static int hf_g3_cen_ack_ssca           = -1;
static int hf_g3_cen_ack_reserved_b1    = -1;
static int hf_g3_cen_ack_fcs_2          = -1;
static int hf_g3_cen_ack_reserved_b3    = -1;
static int hf_g3_cen_ack_dt             = -1;
static int hf_g3_cen_ack_fccs           = -1;
static int hf_g3_cen_ack_ConvZeros      = -1;
static int hf_g3_cen_ack_reserved_b4    = -1;
static int hf_g3_cen_reserved           = -1;
static int hf_g3_fcc_ack_fcs_1          = -1;
static int hf_g3_fcc_ack_ssca           = -1;
static int hf_g3_fcc_ack_reserved_b1_1  = -1;
static int hf_g3_fcc_ack_dt             = -1;
static int hf_g3_fcc_ack_reserved_b1_2  = -1;
static int hf_g3_fcc_ack_reserved_b2    = -1;
static int hf_g3_fcc_ack_fcs_2          = -1;
static int hf_g3_fcc_ack_reserved_b4to6 = -1;
static int hf_g3_fcc_ack_reserved_b7    = -1;
static int hf_g3_fcc_ack_fccs           = -1;
static int hf_g3_fcc_ack_ConvZeros      = -1;
static int hf_g3_fcc_reserved           = -1;


/* Segment control */
static gint hf_g3_segmentcontrol = -1;
static gint hf_g3_sc_RES         = -1;
static gint hf_g3_sc_TMR         = -1;
static gint hf_g3_sc_CC          = -1;
static gint hf_g3_sc_CAP         = -1;
static gint hf_g3_sc_LSF         = -1;
static gint hf_g3_sc_SC          = -1;
static gint hf_g3_sc_SL          = -1;

/* Frame control field */
static gint hf_g3_framecontrol        = -1;
static gint hf_g3_fc_frametype        = -1;
static gint hf_g3_fc_security         = -1;
static gint hf_g3_fc_pending          = -1;
static gint hf_g3_fc_ack              = -1;
static gint hf_g3_fc_panidcompression = -1;
static gint hf_g3_fc_reserved         = -1;
static gint hf_g3_fc_dstaddressmode   = -1;
static gint hf_g3_fc_version          = -1;
static gint hf_g3_fc_srcaddressmode   = -1;

/* Acknowledgement linking */
static int hf_g3_ack_in    = -1;
static int hf_g3_ack_for   = -1;
static int hf_g3_nack_in   = -1;
static int hf_g3_nack_for  = -1;
static int hf_g3_ack_delay = -1;

/* Sequence number */
static gint hf_g3_seqno = -1;

/* PAN ID fields */
static gint hf_g3_dstpanid = -1;
static gint hf_g3_srcpanid = -1;

/* Address fields */
static gint hf_g3_dstaddr   = -1;
static gint hf_g3_srcaddr   = -1;
static gint hf_g3_dstaddr64 = -1;
static gint hf_g3_srcaddr64 = -1;

/* Auxiliary security header */
static gint hf_g3_auxiliary           = -1;
static gint hf_g3_aux_sec_reserved     = -1;
static gint hf_g3_key_id_mode          = -1;
static gint hf_g3_security_level       = -1;
static gint hf_g3_aux_framecounter    = -1;
static gint hf_g3_aux_keyidentifier   = -1;
static gint hf_g3_mic32               = -1;
static gint hf_g3_aux_sec_seg1        = -1;

/* Frame check sequence */
static gint hf_g3_framecheck = -1;

/* Segmentation fields */
static int hf_msg_segments                  = -1;
static int hf_msg_segment                   = -1;
static int hf_msg_segment_overlap           = -1;
static int hf_msg_segment_overlap_conflicts = -1;
static int hf_msg_segment_multiple_tails    = -1;
static int hf_msg_segment_too_long_segment = -1;
static int hf_msg_segment_error             = -1;
static int hf_msg_segment_count             = -1;
static int hf_msg_reassembled_in             = -1;
static int hf_msg_reassembled_length         = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
 * the header fields; they are filled out when calling
 * proto_register_field_array() in proto_register_g3beacon() */

/* Kts attempt at defining the protocol */
static gint hf_g3beacon        = -1;

/* Superframe specification field */
static gint hf_g3beacon_superframe            = -1;
static gint hf_g3beacon_sf_association_permit = -1;
static gint hf_g3beacon_sf_pan_coordinator    = -1;
static gint hf_g3beacon_sf_reserved           = -1;
static gint hf_g3beacon_sf_BLE                = -1;
static gint hf_g3beacon_sf_CAP_slot           = -1;
static gint hf_g3beacon_sf_order              = -1;
static gint hf_g3beacon_sf_beacon_order       = -1;

/* GTS fields */
static gint hf_g3beacon_GTS = -1;

/* GTS specification */
static gint hf_g3beacon_GTSspec                  = -1;
static gint hf_g3beacon_GTSspec_descriptor_count = -1;
static gint hf_g3beacon_GTSspec_reserved         = -1;
static gint hf_g3beacon_GTSspec_permit           = -1;

/* Pending address fields */
static gint hf_g3beacon_pendingaddress = -1;

/* Pending address specification */
static gint hf_g3beacon_pendingaddressspec  = -1;
static gint hf_g3beacon_pas_number_short    = -1;
static gint hf_g3beacon_pas_reserved_low    = -1;
static gint hf_g3beacon_pas_number_extended = -1;
static gint hf_g3beacon_pas_reserved_high   = -1;

/* Beacon payload fields */
static gint hf_g3beacon_payload = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
 * the header fields; they are filled out when calling
 * proto_register_field_array() in proto_register_g3command() */

/* Kts attempt at defining the protocol */
static gint hf_g3command = -1;

/* Command frame identifier field */
static gint hf_g3command_cfi = -1;

/* Tone map response payload */
static gint hf_g3command_payload            = -1;
static gint hf_g3command_payload_txres      = -1;
static gint hf_g3command_payload_txgain     = -1;
static gint hf_g3command_payload_mod_dif    = -1;
static gint hf_g3command_payload_mod_coh    = -1;
static gint hf_g3command_payload_mod_sch    = -1;
static gint hf_g3command_payload_tm         = -1;
static gint hf_g3command_payload_lqi        = -1;
static gint hf_g3command_payload_txcoef_tm0 = -1;
static gint hf_g3command_payload_txcoef_tm1 = -1;
static gint hf_g3command_payload_txcoef_tm2 = -1;
static gint hf_g3command_payload_txcoef_tm3 = -1;
static gint hf_g3command_payload_txcoef_tm4 = -1;
static gint hf_g3command_payload_txcoef_tm5 = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
 * the header fields; they are filled out when calling
 * proto_register_field_array() in proto_register_g3_fcccommand() */

/* Kts attempt at defining the protocol */
static gint hf_g3_fcccommand = -1;

/* Command frame identifier field */
static gint hf_g3_fcccommand_cfi = -1;

/* Tone map response payload */
static gint hf_g3_fcccommand_payload             = -1;
static gint hf_g3_fcccommand_payload_txres       = -1;
static gint hf_g3_fcccommand_payload_txgain      = -1;
static gint hf_g3_fcccommand_payload_mod_dif     = -1;
static gint hf_g3_fcccommand_payload_mod_coh     = -1;
static gint hf_g3_fcccommand_payload_tm          = -1;
static gint hf_g3_fcccommand_payload_lqi         = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm0  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm1  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm2  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm3  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm4  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm5  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm6  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm7  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm8  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm9  = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm10 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm11 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm12 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm13 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm14 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm15 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm16 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm17 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm18 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm19 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm20 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm21 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm22 = -1;
static gint hf_g3_fcccommand_payload_txcoef_tm23 = -1;
static gint hf_g3_fcccommand_payload_mod_sch     = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
 * the header fields; they are filled out when calling
 * proto_register_field_array() in proto_register_g3beacon() */

/* Kts attempt at defining the protocol */
static gint hf_g3data        = -1;

/* Command header type field */
static gint hf_g3data_lowpan_bc0htype = -1;
static gint hf_g3data_eschtype        = -1;
static gint hf_g3data_meshhtype       = -1;
static gint hf_g3data_frag1htype      = -1;
static gint hf_g3data_fragnhtype      = -1;

/* Command address fields */
static gint hf_g3data_vforigin      = -1;
static gint hf_g3data_vfdest        = -1;
static gint hf_g3data_hops          = -1;
static gint hf_g3data_originator    = -1;
static gint hf_g3data_destination   = -1;
static gint hf_g3data_originator64  = -1;
static gint hf_g3data_destination64 = -1;

/* Command fragmented fields */
static gint hf_g3data_datagram_size   = -1;
static gint hf_g3data_datagram_tag    = -1;
static gint hf_g3data_datagram_offset = -1;

/* Command bc0 fields */
static gint hf_g3data_seqnr = -1;

/* Command command ID field */
static gint hf_g3data_command_id = -1;

/* Command command payload field */
static gint hf_g3data_command_payload    = -1;
static gint hf_g3data_unidentified_bytes = -1;

/* Command cfa value field */
static gint hf_g3data_cfavalue = -1;

/* Command mesh routing message fields */
static gint hf_g3data_messagetype              = -1;
static gint hf_g3data_media_type               = -1;

static gint hf_g3data_rrep_hoplimit            = -1;
static gint hf_g3data_rrep_wlinks              = -1;
static gint hf_g3data_rrep_repair              = -1;
static gint hf_g3data_rreq_unicast             = -1;
static gint hf_g3data_rreq_reserved            = -1;
static gint hf_g3data_rrep_bit_reserved        = -1;
static gint hf_g3data_rrep_otype_low           = -1;
static gint hf_g3data_rrep_otype_high          = -1;
static gint hf_g3data_rrep_rc                  = -1;
static gint hf_g3data_rrep_preqid              = -1;
static gint hf_g3data_rrep_reserved            = -1;
static gint hf_g3data_rrep_originator          = -1;
static gint hf_g3data_rrep_destination         = -1;
static gint hf_g3data_rrep_sequence            = -1;

static gint hf_g3data_rerr_reserved            = -1;
static gint hf_g3data_rerr_errorcode           = -1;
static gint hf_g3data_rerr_address             = -1;

static gint hf_g3data_preq_originator          = -1;
static gint hf_g3data_preq_destination         = -1;
static gint hf_g3data_preq_pmt                 = -1; /* new */
static gint hf_g3data_preq_hop_fpa             = -1; /* new */
static gint hf_g3data_preq_hop_mns             = -1; /* new */
static gint hf_g3data_preq_hop_phase_diff      = -1; /* new */
static gint hf_g3data_preq_hop_mrx             = -1; /* new */
static gint hf_g3data_preq_hop_mtx             = -1; /* new */
static gint hf_g3data_preq_hop_reserved        = -1; /* new */
static gint hf_g3data_preq_hop_fplc            = -1; /* new */

static gint hf_g3data_prep_destination         = -1;
static gint hf_g3data_prep_originator          = -1;
static gint hf_g3data_prep_expected_originator = -1;

static gint hf_g3data_rlc_linkcost             = -1;

/* Command LBP message fields */
static gint hf_g3data_lbp_header       = -1;
static gint hf_g3data_lbp_data         = -1;
static gint hf_g3data_lbp_type         = -1;
static gint hf_g3data_lbp_codefrom     = -1;
static gint hf_g3data_lbp_codeto       = -1;
static gint hf_g3data_lbp_transaction  = -1;
static gint hf_g3data_lbp_address      = -1;
static gint hf_g3data_lbp_codetype     = -1;
static gint hf_g3data_lbp_len          = -1;
static gint hf_g3data_lbp_identifier   = -1;

static gint hf_g3data_eap_header       = -1;
static gint hf_g3data_eap_data         = -1;
static gint hf_g3data_eap_type         = -1;
static gint hf_g3data_eap_tflag        = -1;
static gint hf_g3data_eap_reservedflag = -1;
static gint hf_g3data_eap_rands        = -1;
static gint hf_g3data_eap_ids          = -1;
static gint hf_g3data_eap_randp        = -1;
static gint hf_g3data_eap_macp         = -1;
static gint hf_g3data_eap_idp          = -1;
static gint hf_g3data_eap_macs         = -1;
static gint hf_g3data_eap_pchannel     = -1;

static gint hf_g3data_lbp_cfg_attr_id                        = -1;
static gint hf_g3data_lbp_cfg_M                              = -1;
static gint hf_g3data_lbp_cfg_type                           = -1;
static gint hf_g3data_lbp_cfg_len                            = -1;
static gint hf_g3data_lbp_cfg_value_Short_Addr_short_addr    = -1;
static gint hf_g3data_lbp_cfg_value_GMK_key_id               = -1;
static gint hf_g3data_lbp_cfg_value_GMK_gmk                  = -1;
static gint hf_g3data_lbp_cfg_value_GMK_activation_key_id    = -1;
static gint hf_g3data_lbp_cfg_value_GMK_removal_key_id       = -1;
static gint hf_g3data_lbp_cfg_value_parameter_result_result  = -1;
static gint hf_g3data_lbp_cfg_value_parameter_result_attr_id = -1;
static gint hf_g3data_lbp_cfg_value_parameter_result_M       = -1;
static gint hf_g3data_lbp_cfg_value_parameter_result_type    = -1;

/* Channel field */
static gint hf_g3data_pchannel_nonce     = -1;
static gint hf_g3data_pchannel_tag       = -1;
static gint hf_g3data_pchannel_r         = -1;
static gint hf_g3data_pchannel_e         = -1;
static gint hf_g3data_pchannel_reserved  = -1;
static gint hf_g3data_pchannel_extension = -1;

/* NAK fields*/
static gint hf_g3data_nak_data = -1;
static gint hf_g3data_databyte = -1;
static gint hf_g3data_hopinfo  = -1;

/* IDs of the subtrees that we may be creating */
static gint ett_g3_mac        = -1;
static gint ett_g3_cen_fch    = -1;
static gint ett_g3_fcc_fch    = -1;

/* Segment control */
static gint ett_g3_segmentcontrol = -1;

/* Frame control field */
static gint ett_g3_framecontrol        = -1;

/* Auxiliary security header */
static gint ett_g3_auxiliary           = -1;

/* Fragment ids for subtrees */
static gint                 ett_msg_segment  = -1;
static gint                 ett_msg_segments = -1;

/* These are the ids of the subtrees that may be created */
static gint ett_g3beacon        = -1;

/* Superframe specification field */
static gint ett_g3beacon_superframe            = -1;

/* GTS fields */
static gint ett_g3beacon_GTS = -1;

/* GTS specification */
static gint ett_g3beacon_GTSspec                  = -1;

/* Pending address fields */
static gint ett_g3beacon_pendingaddress = -1;

/* Pending address specification */
static gint ett_g3beacon_pendingaddressspec  = -1;

/* These are the ids of the subtrees that may be created */
static gint ett_g3command = -1;

/* Tone map response payload */
static gint ett_g3command_payload            = -1;

/* These are the ids of the subtrees that may be created */
static gint ett_g3_fcccommand = -1;

/* Tone map response payload */
static gint ett_g3_fcccommand_payload             = -1;

/* These are the ids of the subtrees that may be created */
static gint ett_g3data        = -1;

/* Command header type field */
static gint ett_g3data_lowpan_bc0htype = -1;
static gint ett_g3data_eschtype        = -1;
static gint ett_g3data_meshhtype       = -1;
static gint ett_g3data_frag1htype      = -1;
static gint ett_g3data_fragnhtype      = -1;
static gint ett_g3data_lbp_header      = -1;
static gint ett_g3data_lbp_data        = -1;
static gint ett_g3data_eap_header      = -1;
static gint ett_g3data_eap_data        = -1;
static gint ett_g3data_eap_pchannel    = -1;

/* Command command payload field */
static gint ett_g3data_command_payload = -1;
static gint ett_g3data_hopinfo         = -1;
static gint ett_g3data_lbp_cfg_param   = -1;

static const fragment_items msg_frag_items = {
    /* Fragment subtrees */
    &ett_msg_segment,
    &ett_msg_segments,

    /* Fragment fields */
    &hf_msg_segments,
    &hf_msg_segment,
    &hf_msg_segment_overlap,
    &hf_msg_segment_overlap_conflicts,
    &hf_msg_segment_multiple_tails,
    &hf_msg_segment_too_long_segment,
    &hf_msg_segment_error,
    &hf_msg_segment_count,

    /* Reassembled in field */
    &hf_msg_reassembled_in,

    /* Reassembled length field */
    &hf_msg_reassembled_length,

    /* Reassembled data field */
    NULL,

    /* Tag */
    "G3 segments"
};

/* Expert fields */
static expert_field ei_g3_crc_error = EI_INIT;
static expert_field ei_g3_illegal_key_security_level = EI_INIT;
static expert_field ei_g3_illegal_key_identifier_mode = EI_INIT;
static expert_field ei_g3_illegal_key_index = EI_INIT;
static expert_field ei_g3_key_not_found = EI_INIT;
static expert_field ei_g3_decryption_failed = EI_INIT;
static expert_field ei_g3_mic_check_failed = EI_INIT;
static expert_field ei_g3_unknown_dlt = EI_INIT;
static expert_field ei_g3_fcs_error = EI_INIT;
static expert_field ei_g3_ack_link_ack_missing = EI_INIT;
static expert_field ei_g3_ack_link_data_frame_missing = EI_INIT;
static expert_field ei_g3data_illegal_value = EI_INIT;
static expert_field ei_g3data_psk_not_found = EI_INIT;

static int g3_short_address_type = -1;
static ieee802154_hints_t *ieee_hints;

/******************************************************************************
*  Private function prototypes
******************************************************************************/
static void proto_init_g3(void);

static gboolean keys_uat_update_cb(void *r, char **err);
static gboolean psks_uat_update_cb(void *r, char **err);

static int g3_short_addr_to_str(const address *addr, gchar *buf, int buf_len _U_);
static int g3_short_str_len(const address *addr _U_);
static int g3_short_len(void);

static void g3data_init(void);

static int  dissect_g3(tvbuff_t    *tvb,
                       packet_info *pinfo,
                       proto_tree  *tree,
                       void        *data);

static int dissect_g3beacon(tvbuff_t    *tvb,
                            packet_info *pinfo,
                            proto_tree  *tree,
                            void        *data);

static int dissect_g3command(tvbuff_t    *tvb,
                             packet_info *pinfo,
                             proto_tree  *tree,
                             void        *data);

static int dissect_g3_fcccommand(tvbuff_t    *tvb,
                                 packet_info *pinfo,
                                 proto_tree  *tree,
                                 void        *data);

static int dissect_g3data(tvbuff_t    *tvb,
                          packet_info *pinfo,
                          proto_tree  *tree,
                          void *data   _U_);

/******************************************************************************
*  Public function bodies
******************************************************************************/

// suppress Wmissing-prototypes for global init functions called by Wireshark
void proto_reg_handoff_g3(void);
void proto_reg_handoff_g3beacon(void);
void proto_reg_handoff_g3command(void);
void proto_reg_handoff_g3_fcccommand(void);
void proto_reg_handoff_g3data(void);

void proto_register_g3(void);
void proto_register_g3beacon(void);
void proto_register_g3command(void);
void proto_register_g3_fcccommand(void);
void proto_register_g3data(void);

void
proto_reg_handoff_g3(void)
{
    g3_handle = create_dissector_handle(dissect_g3, proto_g3);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_G3_CENELEC, g3_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_G3_FCC_ARIB, g3_handle);
    data_handle = find_dissector("data");
    data6lowpan_handle = find_dissector("6lowpan");
}

void
proto_register_g3(void)
{
    module_t *g3_module;

    /* A header field is something you can search/filter on.
     * A structure is created to register the fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}} */
    static hf_register_info hf[] = {
        { &hf_g3_cen_fch,
          { "CENELEC FCH", "g3.fch", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3_cen_fch_PDC,
          { "Phase Detection Counter", "g3.fch.PDC", FT_UINT8, BASE_DEC, NULL, 0x0,
            "G3 Phase Detection Counter", HFILL }
        },
        { &hf_g3_cen_fch_MOD_dif,
          { "Modulation Type", "g3.fch.MOD", FT_UINT8, BASE_DEC, VALS(packetmodulationtype_cen_dif), G3_CEN_FCH_MOD_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_cen_fch_MOD_coh,
          { "Modulation Type", "g3.fch.MOD", FT_UINT8, BASE_DEC, VALS(packetmodulationtype_cen_coh), G3_CEN_FCH_MOD_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_cen_fch_MOD_dif_g3base,
          { "Modulation Type", "g3.fch.MOD", FT_UINT16, BASE_HEX, VALS(packetmodulationtype_cen_dif_g3base), G3_CEN_FCH_MOD_G3BASE_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_cen_fch_MOD_coh_g3base,
          { "Modulation Type", "g3.fch.MOD", FT_UINT16, BASE_HEX, VALS(packetmodulationtype_cen_coh_g3base), G3_CEN_FCH_MOD_G3BASE_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_cen_fch_FL,
          { "Frame Length", "g3.fch.FL", FT_UINT8, BASE_DEC, NULL, G3_CEN_FCH_FL_MSK,
            "G3 Frame Length", HFILL }
        },
        { &hf_g3_cen_fch_TM,
          { "Tone Map", "g3.fch.TM", FT_UINT8, BASE_HEX, NULL, G3_CEN_FCH_TM_MSK,
            "G3 Tone Map", HFILL }
        },
        { &hf_g3_cen_fch_PAY_MOD_SCH,
          { "Packet Modulation Scheme", "g3.fch.MODSCH", FT_UINT8, BASE_DEC, VALS(packetmodulationscheme_cen), G3_CEN_FCH_PAY_MOD_SCH_MSK,
            "Packet Payload Modulation Scheme", HFILL }
        },
        { &hf_g3_cen_fch_DT,
          { "Delimiter Type", "g3.fch.DT", FT_UINT8, BASE_DEC, VALS(packetdelimitertype_cen), G3_CEN_FCH_DT_MSK,
            "Packet Delimiter Type", HFILL }
        },
        { &hf_g3_cen_fch_FCCS,
          { "Frame Control Check Sequence", "g3.fch.FCCS", FT_UINT16, BASE_HEX, NULL, G3_CEN_FCH_FCCS_MSK,
            "G3 Frame Control Check Sequence", HFILL }
        },

        /*********************************************************/

        { &hf_g3_fcc_fch,
          { "FCC FCH", "g3.fcc.fch", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3_fcc_fch_PDC,
          { "Phase Detection Counter", "g3.fch.PDC", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3_fcc_fch_MOD_dif,
          { "Modulation Type", "g3.fch.MOD", FT_UINT8, BASE_DEC, VALS(packetmodulationtype_fcc_dif), G3_FCC_FCH_MOD_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_fcc_fch_MOD_coh,
          { "Modulation Type", "g3.fch.MOD", FT_UINT8, BASE_DEC, VALS(packetmodulationtype_fcc_coh), G3_FCC_FCH_MOD_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_fcc_fch_MOD_dif_g3base,
          { "Modulation Type", "g3.fch.MOD", FT_UINT8, BASE_DEC, VALS(packetmodulationtype_fcc_dif_g3base), G3_FCC_FCH_MOD_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_fcc_fch_MOD_coh_g3base,
          { "Modulation Type", "g3.fch.MOD", FT_UINT8, BASE_DEC, VALS(packetmodulationtype_fcc_coh_g3base), G3_FCC_FCH_MOD_MSK,
            "Packet Modulation Type", HFILL }
        },
        { &hf_g3_fcc_fch_PAY_MOD_SCH,
          { "Payload Modulation Scheme", "g3.fch.MODSCH", FT_UINT8, BASE_DEC, VALS(packetmodulationscheme_fcc), G3_FCC_FCH_PAY_MOD_SCH_MSK,
            "Packet Modulation Scheme", HFILL }
        },
        { &hf_g3_fcc_fch_DT,
          { "Delimiter Type", "g3.fch.DT", FT_UINT8, BASE_DEC, VALS(packetdelimitertype_fcc), G3_FCC_FCH_DT_MSK,
            "Packet Delimiter Type", HFILL }
        },
        { &hf_g3_fcc_fch_FL,
          { "Frame Length", "g3.fch.FL", FT_UINT16, BASE_DEC, NULL, G3_FCC_FCH_FL_MSK,
            "G3 Frame Length", HFILL }
        },
        { &hf_g3_fcc_fch_TM,
          { "Tone Map", "g3.fch.TM", FT_UINT32, BASE_HEX, NULL, G3_FCC_FCH_TM_MSK,
            "G3 Tone Map", HFILL }
        },
        { &hf_g3_fcc_fch_TWO_RS,
          { "Two RS Blocks", "g3.fch.TWORS", FT_UINT8, BASE_DEC, VALS(packettworsblocks_fcc), G3_FCC_FCH_TWO_RS_MSK,
            "G3 FCC Two RS Blocks (TWORS)", HFILL }
        },
        { &hf_g3_fcc_fch_FCCS,
          { "Frame Control Check Sequence", "g3.fch.FCCS", FT_UINT16, BASE_HEX, NULL, G3_FCC_FCH_FCCS_MSK,
            "G3 Frame Control Check Sequence", HFILL }
        },

        /*********************************************************/

        { &hf_g3_cen_ack_fcs_1,
          { "MAC FCS[7:0]", "g3.cen.ack.fcs_1", FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_ssca,
          { "Further segments are expected", "g3.cen.ack.ssca", FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_reserved_b1,
          { "Reserved", "g3.cen.ack.reserved_b1", FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_fcs_2,
          { "MAC FCS[15:8]", "g3.cen.ack.fcs_2", FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_reserved_b3,
          { "Reserved", "g3.cen.ack.reserved_b3", FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_dt,
          { "Delimiter type", "g3.cen.ack.dt", FT_UINT8, BASE_DEC, VALS(g3_cen_ack_dt_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_fccs,
          { "Frame Control Check Sequence", "g3.cen.ack.fccs", FT_UINT16, BASE_HEX, NULL, 0x0f80,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_ConvZeros,
          { "ConvZeros", "g3.cen.ack.ConvZeros", FT_UINT8, BASE_DEC, NULL, 0x7e,
            NULL, HFILL }
        },
        { &hf_g3_cen_ack_reserved_b4,
          { "Reserved", "g3.cen.ack.reserved_b4", FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_g3_cen_reserved,
          { "Reserved", "g3.cen.reserved", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_fcs_1,
          { "MAC FCS[7:0]", "g3.fcc.ack.fcs_1", FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_ssca,
          { "Further segments are expected", "g3.fcc.ack.ssca", FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_reserved_b1_1,
          { "Reserved", "g3.fcc.ack.reserved_b1_1", FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_dt,
          { "Delimiter type", "g3.fcc.ack.dt", FT_UINT8, BASE_DEC, VALS(g3_fcc_ack_dt_vals), 0x0e,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_reserved_b1_2,
          { "Reserved", "g3.fcc.ack.reserved_b1_2", FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_reserved_b2,
          { "Reserved", "g3.fcc.ack.reserved_b2", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_fcs_2,
          { "MAC FCS[15:8]", "g3.fcc.ack.fcs_2", FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_reserved_b4to6,
          { "Reserved", "g3.fcc.ack.reserved_b4to6", FT_UINT32, BASE_DEC, NULL, 0x00ffffff,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_reserved_b7,
          { "Reserved", "g3.fcc.ack.reserved_b7", FT_UINT8, BASE_DEC, NULL, 0xc0,
            NULL, HFILL }
        },
        { &hf_g3_fcc_ack_fccs,
          { "Frame Control Check Sequence", "g3.fcc.ack.fccs", FT_UINT16, BASE_HEX, NULL, 0x3fc0,
            "G3 FCC Frame Control Check Sequence", HFILL }
        },
        { &hf_g3_fcc_ack_ConvZeros,
          { "ConvZeros", "g3.fcc.ack.ConvZeros", FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_g3_fcc_reserved,
          { "Reserved", "g3.fcc.reserved", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /*********************************************************/

        { &hf_g3_ack_in,
          { "Acknowledgement in frame", "g3.ack_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0,
            NULL, HFILL }
        },
        { &hf_g3_ack_for,
          { "Acknowledgement for frame", "g3.ack_for", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL }
        },
        { &hf_g3_nack_in,
          { "Negative acknowledgement in frame", "g3.nack_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0,
            NULL, HFILL }
        },
        { &hf_g3_nack_for,
          { "Negative acknowledgement for frame", "g3.nack_for", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL }
        },
        { &hf_g3_ack_delay,
          { "Delay", "g3.ack_delay", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Time between frame and acknowledgement", HFILL }
        },

        /*********************************************************/

        { &hf_msg_segments,
          { "Message segments", "g3.msg.segments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_segment,
          { "Message segment", "g3.msg.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_segment_overlap,
          { "Message segment overlap", "g3.msg.segment.overlap",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_segment_overlap_conflicts,
          { "Message segment overlapping with conflicting data",
            "g3.msg.segment.overlap.conflicts",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_segment_multiple_tails,
          { "Message has multiple tail segments",
            "g3.msg.segment.multiple_tails",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_segment_too_long_segment,
          { "Message segment too long", "g3.msg.segment.too_long_segment",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_segment_error,
          { "Message segment reassembly error", "g3.msg.segment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_segment_count,
          { "Message segment count", "g3.msg.segment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_reassembled_in,
          { "Reassembled in", "g3.msg.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_msg_reassembled_length,
          { "Reassembled length", "g3.msg.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },

        { &hf_g3_segmentcontrol,
          { "Segment Control", "g3.segmentcontrol", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3_sc_RES,
          { "Reserved", "g3.RES", FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_g3_sc_TMR,
          { "Tone Map Request", "g3.TMR", FT_UINT8, BASE_DEC, VALS(packettonemaprequest_cen), 1<<3,
            "G3 Tone Map Request", HFILL }
        },
        { &hf_g3_sc_CC,
          { "Contention Control", "g3.CC", FT_UINT8, BASE_DEC, VALS(packetcontentioncontrol), 1<<2,
            "G3 Contention Control", HFILL }
        },
        { &hf_g3_sc_CAP,
          { "Channel access priority", "g3.CAP", FT_UINT8, BASE_DEC, VALS(packetchannelaccesspriority), 1<<1,
            "G3 Channel access priority", HFILL }
        },
        { &hf_g3_sc_LSF,
          { "Last Segment Flag", "g3.LSF", FT_UINT8, BASE_DEC, VALS(packetlastsegmentflag), 1<<0,
            "G3 Last Segment Flag", HFILL }
        },
        { &hf_g3_sc_SC,
          { "Segment Count", "g3.SC", FT_UINT8, BASE_DEC, NULL, 0x0,
            "G3 Segment Count", HFILL }
        },
        { &hf_g3_sc_SL,
          { "Segment Length of MAC frame", "g3.SL", FT_UINT16, BASE_DEC, NULL, 0x0,
            "G3 Segment Length of MAC frame", HFILL }
        },

        { &hf_g3_framecontrol,
          { "Frame Control", "g3.framecontrol", FT_UINT16, BASE_HEX, NULL, 0x0,
            "G3 Frame Control", HFILL }
        },
        { &hf_g3_fc_frametype,
          { "Frame Type", "g3.frametype", FT_UINT16, BASE_DEC, VALS(packetframetype), IEEE802154_FCF_TYPE_MASK,
            "G3 Frame Type", HFILL }
        },
        { &hf_g3_fc_security,
          { "Security enabled", "g3.security", FT_UINT16, BASE_DEC, VALS(packetsecurityenabled), IEEE802154_FCF_SEC_EN,
            NULL, HFILL }
        },
        { &hf_g3_fc_pending,
          { "Frame Pending", "g3.pending", FT_UINT16, BASE_DEC, VALS(packetframepending), IEEE802154_FCF_FRAME_PND,
            NULL, HFILL }
        },
        { &hf_g3_fc_ack,
          { "Acknowledge Requested", "g3.ack", FT_UINT16, BASE_DEC, VALS(packetackrequest), IEEE802154_FCF_ACK_REQ,
            NULL, HFILL }
        },
        { &hf_g3_fc_panidcompression,
          { "Pan ID Compression", "g3.panidcompression", FT_UINT16, BASE_DEC, VALS(packetpanidcompression), IEEE802154_FCF_PAN_ID_COMPRESSION,
            NULL, HFILL }
        },
        { &hf_g3_fc_reserved,
          { "Reserved", "g3.reserved", FT_UINT16, BASE_DEC, NULL, 0x0380,
            NULL, HFILL }
        },
        { &hf_g3_fc_dstaddressmode,
          { "Destination Address Mode", "g3.dstaddressmode", FT_UINT16, BASE_DEC, VALS(packetaddrmode), IEEE802154_FCF_DADDR_MASK,
            "G3 Destination Address Mode", HFILL }
        },
        { &hf_g3_fc_version,
          { "Frame Version", "g3.version", FT_UINT16, BASE_DEC, NULL, IEEE802154_FCF_VERSION,
            "G3 Frame Version", HFILL }
        },
        { &hf_g3_fc_srcaddressmode,
          { "Source Address Mode", "g3.srcaddressmode", FT_UINT16, BASE_DEC, VALS(packetaddrmode), IEEE802154_FCF_SADDR_MASK,
            "G3 Source Address Mode", HFILL }
        },

        { &hf_g3_seqno,
          { "Sequence Number", "g3.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
            "G3 Sequence Number", HFILL }
        },

        { &hf_g3_dstpanid,
          { "Destination PAN ID", "g3.dstpanid", FT_UINT16, BASE_HEX, NULL, 0x0,
            "G3 Destination PAN ID", HFILL }
        },
        { &hf_g3_srcpanid,
          { "Source PAN ID", "g3.srcpanid", FT_UINT16, BASE_HEX, NULL, 0x0,
            "G3 Source PAN ID", HFILL }
        },
        { &hf_g3_dstaddr,
          { "Destination Address", "g3.dstaddr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "G3 Destination Address", HFILL }
        },
        { &hf_g3_srcaddr,
          { "Source Address", "g3.srcaddr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "G3 Source Address", HFILL }
        },
        { &hf_g3_dstaddr64,
          { "Destination Address", "g3.dstaddr64", FT_EUI64, BASE_NONE, NULL, 0x0,
            "G3 Destination Address", HFILL }
        },
        { &hf_g3_srcaddr64,
          { "Source Address", "g3.srcaddr64", FT_EUI64, BASE_NONE, NULL, 0x0,
            "G3 Source Address", HFILL }
        },

        { &hf_g3_auxiliary,
          { "Auxiliary Security", "g3.auxiliary", FT_NONE, BASE_NONE, NULL, 0x0,
            "G3 Auxiliary Security", HFILL }
        },

        { &hf_g3_security_level,
          { "Security Level", "g3.aux_sec.sec_level", FT_UINT8, BASE_HEX, VALS(g3_sec_level_names),
            IEEE802154_AUX_SEC_LEVEL_MASK, "The Security Level of the frame", HFILL }
        },

        { &hf_g3_key_id_mode,
          { "Key Identifier Mode", "g3.aux_sec.key_id_mode", FT_UINT8, BASE_HEX, VALS(g3_key_id_mode_names),
            IEEE802154_AUX_KEY_ID_MODE_MASK,
            "The scheme to use by the recipient to lookup the key in its key table", HFILL }
        },

        { &hf_g3_aux_sec_reserved,
          { "Reserved", "g3.aux_sec.reserved", FT_UINT8, BASE_HEX, NULL, IEEE802154_AUX_KEY_RESERVED_MASK,
            NULL, HFILL }
        },

        { &hf_g3_aux_framecounter,
          { "Frame Counter", "g3.frame_counter", FT_UINT32, BASE_DEC, NULL, 0x0,
            "G3 Frame Counter", HFILL }
        },

        { &hf_g3_aux_keyidentifier,
          { "Key Index", "g3.key_index", FT_UINT8, BASE_DEC, NULL, 0x0,
            "G3 Key Index", HFILL }
        },

        { &hf_g3_mic32,
          { "MIC-32", "g3.mic32", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3_aux_sec_seg1,
          { "Aux Sec Header From 1st Segment", "g3.aux_sec_seg1", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /*********************************************************/

        { &hf_g3_macpayload,
          { "G3 MAC Payload", "g3.macpayload", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /*********************************************************/

        { &hf_g3_framecheck,
          { "Frame Check Sequence", "g3.framecheck", FT_UINT16, BASE_HEX, NULL, 0x0,
            "G3 Frame Check Sequence", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_g3_mac,
        &ett_g3_cen_fch,
        &ett_g3_fcc_fch,
        &ett_g3_segmentcontrol,
        &ett_g3_framecontrol,
        &ett_g3_auxiliary,
        &ett_msg_segment,
        &ett_msg_segments
    };

    static ei_register_info ei[] = {
        { &ei_g3_crc_error, { "g3.crc_error", PI_PROTOCOL, PI_WARN, "CRC Error", EXPFILL }},
        { &ei_g3_illegal_key_security_level, { "g3.illegal_key_security_level", PI_PROTOCOL, PI_WARN, "Illegal Key Security Level", EXPFILL }},
        { &ei_g3_illegal_key_identifier_mode, { "g3.illegal_key_identifier_mode", PI_PROTOCOL, PI_WARN, "Illegal Key Identifier Mode", EXPFILL }},
        { &ei_g3_illegal_key_index, { "g3.illegal_key_index", PI_PROTOCOL, PI_WARN, "Illegal Key Index", EXPFILL }},
        { &ei_g3_key_not_found, { "g3.key_not_found", PI_SECURITY, PI_WARN, "Key not found", EXPFILL }},
        { &ei_g3_decryption_failed, { "g3.decryption_failed", PI_SECURITY, PI_WARN, "Decryption Failed", EXPFILL }},
        { &ei_g3_mic_check_failed, { "g3.mic_check_failed", PI_SECURITY, PI_WARN, "MIC Check Failed", EXPFILL }},
        { &ei_g3_unknown_dlt, { "g3.unknown_dlt", PI_PROTOCOL, PI_ERROR, "Unkown DLT", EXPFILL }},
        { &ei_g3_fcs_error, { "g3.fcs_error", PI_PROTOCOL, PI_WARN, "FCS Error", EXPFILL }},
        { &ei_g3_ack_link_ack_missing,{ "g3.ack_missing", PI_PROTOCOL, PI_NOTE, "Acknowledgement Missing", EXPFILL }},
        { &ei_g3_ack_link_data_frame_missing,{ "g3.data_frame_missing", PI_PROTOCOL, PI_WARN, "Data Frame Missing", EXPFILL }},
    };

    expert_module_t *expert_g3;

    /*
     *  Definition of the auxiliary structure for each field in the
     *  static_keys structure. These macros define names, tooltips
     *  and callbacks for checks, updates and serialization of each field
     *  in the structure.
     *  Used by the UI and preferences functions.
     */
    static uat_field_t keys_uat_flds[] = {
        UAT_FLD_HEX(keys_uat, pan_id, "PAN Identifier", "16-bit PAN identifier in hexadecimal."),
        UAT_FLD_BUFFER(keys_uat, gmk0, "GMK0", "16-byte Group Key number 0."),
        UAT_FLD_BUFFER(keys_uat, gmk1, "GMK1", "16-byte Group Key number 1."),
        UAT_END_FIELDS
    };

    /*
     *  Definition of the auxiliary structure for each field in the
     *  psk structure. These macros define names, tooltips
     *  and callbacks for checks, updates and serialization of each field
     *  in the structure.
     *  Used by the UI and preferences functions.
     */
    static uat_field_t psks_uat_flds[] = {
        UAT_FLD_BUFFER(psks_uat, eui64, "EUI64", "8-byte EUI-64."),
        UAT_FLD_BUFFER(psks_uat, psk,   "PSK",   "16-byte PSK."),
        UAT_END_FIELDS
    };

    /* Register a new address type for our dissector. This is
     * necessary to make the 6lowpan dissector treat this address in a
     * different way. Internally, it is just a EUI64 address build
     * according to the G3 standard.
     */
    g3_short_address_type = address_type_dissector_register("AT_G3_SHORT",
                                                            "G3 16-bit short address",
                                                            g3_short_addr_to_str, g3_short_str_len,
                                                            NULL, NULL, g3_short_len, NULL, NULL);

    /* The full and short name are used in e.g. the "Preferences" and "Enabled protocols"
     * dialogs as well as the generated field name list in the documentation.
     * The abbreviation is used as the display filter name.*/
    proto_g3 = proto_register_protocol(
                                       "G3 Protocol", /* Name */
                                       "G3",          /* Short name */
                                       "g3"           /* Abbrev */
                                       );



    /* Make sure Wireshark knows that G3 contains preferences */
    g3_module = prefs_register_protocol(proto_g3,
                                        proto_reg_handoff_g3);

    /* Create a UAT for decryption keys. */
    static_keys_uat = uat_new("Static G3 Keys",
        sizeof(static_keys_t),      /* record size */
        "g3_keys",                  /* filename */
        TRUE,                       /* from_profile */
        (void**)&static_keys,       /* data_ptr */
        &num_static_keys,           /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,     /* affects dissection of packets, but not set of named fields */
        NULL,                       /* help */
        NULL,                       /* copy callback */
        keys_uat_update_cb,         /* update callback */
        NULL,                       /* free callback */
        NULL,                       /* post update callback */
        NULL,                       /* reset callback */
        keys_uat_flds);             /* UAT field definitions */

    /* Register preferences for the static_key UAT */
    prefs_register_uat_preference(g3_module, "static_keys",
                                  "Static G3 Keys",
                                  "A table of static GMKs (GMK0 and GMK1) for each PAN ID",
                                  static_keys_uat);

    /* Create a UAT for the PSKs. */
    psks_uat = uat_new("EUI-64 --> PSK Mapping",
        sizeof(psk_t),              /* record size */
        "g3_psks",                  /* filename */
        TRUE,                       /* from_profile */
        (void**)&psks,              /* data_ptr */
        &num_psks,                  /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,     /* affects dissection of packets, but not set of named fields */
        NULL,                       /* help */
        NULL,                       /* copy callback */
        psks_uat_update_cb,         /* update callback */
        NULL,                       /* free callback */
        NULL,                       /* post update callback */
        NULL,                       /* reset callback */
        psks_uat_flds);             /* UAT field definitions */

                                    /* Register preferences for the static_key UAT */
    prefs_register_uat_preference(g3_module, "psks",
        "EUI-64 --> PSK Mapping",
        "A table of PSKs for EUIs",
        psks_uat);


    prefs_register_bool_preference(g3_module, "extract_gmks_from_eap",
        "Extract GMKs from EAP Messages",
        "Set if EAP messages should be parsed to extract GMKs (requires PSKs).",
        &extract_gmks_from_eap);

    prefs_register_bool_preference(g3_module, "use_universal_psk",
        "Use universal PSK instead of EUI-64 --> PSK Mapping",
        "Set if the following PSK should be used for all nodes.",
        &use_universal_psk);

    prefs_register_string_preference(g3_module, "universal_psk",
        "Universal PSK",
        "The Universal PSK.",
        &universal_psk_string);

    /* Register the arrays */
    proto_register_field_array(proto_g3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("g3", dissect_g3, proto_g3);

    expert_g3 = expert_register_protocol(proto_g3);
    expert_register_field_array(expert_g3, ei, array_length(ei));

    /* Register the dissector init function */
    register_init_routine(proto_init_g3);
}

void
proto_reg_handoff_g3beacon(void)
{
    g3beacon_handle = create_dissector_handle(dissect_g3beacon, proto_g3beacon);
}

void
proto_register_g3beacon(void)
{
    /* A header field is something you can search/filter on.
     * A structure is created to register the fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}} */
    static hf_register_info hf[] = {
        { &hf_g3beacon,
            { "G3 MAC Payload", "g3.beacon.data", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_g3beacon_superframe,
          { "Superframe Specification", "g3.beacon.superframe", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3beacon_sf_association_permit,
          { "Association Permit", "g3.beacon.sf_association_permit", FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3beacon_sf_pan_coordinator,
          { "PAN Coordinator", "g3.beacon.sf_pan_coordinator", FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_g3beacon_sf_reserved,
          { "Reserved", "g3.beacon.sf_reserved", FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_g3beacon_sf_BLE,
          { "Battery Life Extension", "g3.beacon.sf_BLE", FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_g3beacon_sf_CAP_slot,
          { "Final CAP Slot", "g3.beacon.sf_CAP_slot", FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_g3beacon_sf_order,
          { "Superframe Order", "g3.beacon.sf_order", FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_g3beacon_sf_beacon_order,
          { "Beacon Order", "g3.beacon.sf_beacon_order", FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },

        { &hf_g3beacon_GTS,
          { "Guaranteed Time Slot", "g3.beacon.GTS", FT_NONE, BASE_NONE, NULL, 0x0,
            "GTS", HFILL }
        },
        { &hf_g3beacon_GTSspec,
          { "GTS Specification", "g3.beacon.GTSspec", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3beacon_GTSspec_descriptor_count,
          { "GTS Descriptor Count", "g3.beacon.GTSspec_descriptor_count", FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3beacon_GTSspec_reserved,
          { "Reserved", "g3.beacon.GTSspec_reserved", FT_UINT8, BASE_DEC, NULL, 0x78,
            NULL, HFILL }
        },
        { &hf_g3beacon_GTSspec_permit,
          { "GTS Permit", "g3.beacon.GTSspec_permit", FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },

        { &hf_g3beacon_pendingaddress,
          { "Pending Address", "g3.beacon.pendingaddress", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3beacon_pendingaddressspec,
          { "Pending Address Specification", "g3.beacon.pendingaddressspec", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3beacon_pas_number_short,
          { "Number of Short Adresses Pending", "g3.beacon.pas_number_short", FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3beacon_pas_reserved_low,
          { "Reserved", "g3.beacon.pas_reserved_low", FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_g3beacon_pas_number_extended,
          { "Number of Extended Adresses Pending", "g3.beacon.pas_number_extended", FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_g3beacon_pas_reserved_high,
          { "Reserved", "g3.beacon.pas_reserved_high", FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },

        { &hf_g3beacon_payload,
          { "Beacon Payload", "g3.beacon.beacon", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };
    static gint *ett[] = {
        &ett_g3beacon,
        &ett_g3beacon_superframe,
        &ett_g3beacon_GTS,
        &ett_g3beacon_GTSspec,
        &ett_g3beacon_pendingaddress,
        &ett_g3beacon_pendingaddressspec,
    };

    /* The full and short name are used in e.g. the "Preferences" and "Enabled protocols"
       dialogs as well as the generated field name list in the documentation.
       The abbreviation is used as the display filter name.*/
    proto_g3beacon = proto_register_protocol(
                                             "G3 Beacon", //Name
                                             "G3_BEACON", //Short name
                                             "g3_beacon"  //Abbrev
                                             );

    /* Register the arrays */
    proto_register_field_array(proto_g3beacon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("g3beacon", dissect_g3beacon, proto_g3beacon);
}

void
proto_reg_handoff_g3command(void)
{
    g3_cen_command_handle = create_dissector_handle(dissect_g3command, proto_g3command);
}

void
proto_register_g3command(void)
{
    /* A header field is something you can search/filter on.
     * A structure is created to register the fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}} */
    static hf_register_info hf[] = {
        { &hf_g3command,
            { "G3 MAC Payload", "g3.command.data", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3command_payload,
          { "Command Payload", "g3.command.command", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3command_cfi,
          { "Command Frame Identifier", "g3.command.cfi", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(cfitype), 0x0,
            NULL, HFILL }
        },

        { &hf_g3command_payload_txres,
          { "Tx Gain Resolution", "g3.command.tmrpayload_txres", FT_UINT8, BASE_DEC, VALS(txgainres), G3_TMR_TXRES_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_txgain,
          { "Requested amount of gain steps", "g3.command.tmrpayload_txgain", FT_UINT8, BASE_DEC, NULL, G3_TMR_TXGAIN_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_mod_dif,
          { "Modulation type", "g3.command.tmrpayload_mod", FT_UINT8, BASE_DEC, VALS(modtype_dif), G3_TMR_MOD_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_mod_coh,
          { "Modulation type", "g3.command.tmrpayload_mod", FT_UINT8, BASE_DEC, VALS(modtype_coh), G3_TMR_MOD_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_mod_sch,
          { "Modulation scheme", "g3.command.tmrpayload_mod_sch", FT_UINT8, BASE_DEC, VALS(modsch), G3_TMR_MOD_SCH_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_tm,
          { "Tone map", "g3.command.tmrpayload_tm", FT_UINT8, BASE_HEX, NULL, G3_TMR_TM_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_lqi,
          { "Link Quality Indicator", "g3.command.tmrpayload_lqi", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3command_payload_txcoef_tm0,
          { "Requested amount of gain steps for TM[0]", "g3.command.tmrpayload_txcoef_tm0", FT_UINT8, BASE_DEC, NULL, G3_TMR_TXCOEFF_NIBBLE_HI_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_txcoef_tm1,
          { "Requested amount of gain steps for TM[1]", "g3.command.tmrpayload_txcoef_tm1", FT_UINT8, BASE_DEC, NULL, G3_TMR_TXCOEFF_NIBBLE_LO_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_txcoef_tm2,
          { "Requested amount of gain steps for TM[2]", "g3.command.tmrpayload_txcoef_tm2", FT_UINT8, BASE_DEC, NULL, G3_TMR_TXCOEFF_NIBBLE_HI_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_txcoef_tm3,
          { "Requested amount of gain steps for TM[3]", "g3.command.tmrpayload_txcoef_tm3", FT_UINT8, BASE_DEC, NULL, G3_TMR_TXCOEFF_NIBBLE_LO_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_txcoef_tm4,
          { "Requested amount of gain steps for TM[4]", "g3.command.tmrpayload_txcoef_tm4", FT_UINT8, BASE_DEC, NULL, G3_TMR_TXCOEFF_NIBBLE_HI_MSK,
            NULL, HFILL }
        },
        { &hf_g3command_payload_txcoef_tm5,
          { "Requested amount of gain steps for TM[5]", "g3.command.tmrpayload_txcoef_tm5", FT_UINT8, BASE_DEC, NULL, G3_TMR_TXCOEFF_NIBBLE_LO_MSK,
            NULL, HFILL }
        }
    };
    static gint *ett[] = {
        &ett_g3command,
        &ett_g3command_payload,
    };

    /*The full and short name are used in e.g. the "Preferences" and "Enabled protocols"
     * dialogs as well as the generated field name list in the documentation.
     * The abbreviation is used as the display filter name.*/
    proto_g3command = proto_register_protocol(
                                              "G3 Command", //Name
                                              "G3_COMMAND", //Short name
                                              "g3_command"  //Abbrev
                                              );

    /* Register the arrays */
    proto_register_field_array(proto_g3command, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("g3command", dissect_g3command, proto_g3command);
}

void
proto_reg_handoff_g3_fcccommand(void)
{
    g3_fcc_command_handle = create_dissector_handle(dissect_g3_fcccommand, proto_g3_fcccommand);
}

void
proto_register_g3_fcccommand(void)
{
    /* A header field is something you can search/filter on.
     * A structure is created to register the fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}} */
    static hf_register_info hf[] = {
        { &hf_g3_fcccommand,
            { "G3 FCC MAC Payload", "g3.fcccommand.data", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3_fcccommand_payload,
          { "Command Payload", "g3.fcccommand.command", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3_fcccommand_cfi,
          { "Command Frame Identifier", "g3.fcccommand.cfi", FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(cfitype), 0x0,
            NULL, HFILL }
        },

        { &hf_g3_fcccommand_payload_txres,
          { "Tx Gain Resolution", "g3.fcccommand.tmrpayload_txres", FT_UINT8, BASE_DEC, VALS(txgainres), G3_FCC_TMR_TXRES_MSK,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txgain,
          { "Requested amount of gain steps", "g3.fcccommand.tmrpayload_txgain", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXGAIN_MSK,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_mod_dif,
          { "Modulation type", "g3.fcccommand.tmrpayload_mod", FT_UINT8, BASE_DEC, VALS(modtype_dif), G3_FCC_TMR_MOD_MSK,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_mod_coh,
          { "Modulation type", "g3.fcccommand.tmrpayload_mod", FT_UINT8, BASE_DEC, VALS(modtype_coh), G3_FCC_TMR_MOD_MSK,
            NULL, HFILL }
        },

        { &hf_g3_fcccommand_payload_tm,
          { "Tone map", "g3.fcccommand.tmrpayload_tm", FT_UINT32, BASE_HEX, NULL, G3_FCC_TMR_TM_MSK,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_lqi,
          { "Link Quality Indicator", "g3.fcccommand.tmrpayload_lqi", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3_fcccommand_payload_txcoef_tm0,
          { "Requested amount of gain steps for TM[0]", "g3.fcccommand.tmrpayload_txcoef_tm0", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B76,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm1,
          { "Requested amount of gain steps for TM[1]", "g3.fcccommand.tmrpayload_txcoef_tm1", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B54,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm2,
          { "Requested amount of gain steps for TM[2]", "g3.fcccommand.tmrpayload_txcoef_tm2", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B32,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm3,
          { "Requested amount of gain steps for TM[3]", "g3.fcccommand.tmrpayload_txcoef_tm3", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B10,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm4,
          { "Requested amount of gain steps for TM[4]", "g3.fcccommand.tmrpayload_txcoef_tm4", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B76,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm5,
          { "Requested amount of gain steps for TM[5]", "g3.fcccommand.tmrpayload_txcoef_tm5", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B54,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm6,
          { "Requested amount of gain steps for TM[6]", "g3.fcccommand.tmrpayload_txcoef_tm6", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B32,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm7,
          { "Requested amount of gain steps for TM[7]", "g3.fcccommand.tmrpayload_txcoef_tm7", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B10,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm8,
          { "Requested amount of gain steps for TM[8]", "g3.fcccommand.tmrpayload_txcoef_tm8", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B76,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm9,
          { "Requested amount of gain steps for TM[9]", "g3.fcccommand.tmrpayload_txcoef_tm9", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B54,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm10,
          { "Requested amount of gain steps for TM[10]", "g3.fcccommand.tmrpayload_txcoef_tm10", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B32,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm11,
          { "Requested amount of gain steps for TM[11]", "g3.fcccommand.tmrpayload_txcoef_tm11", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B10,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm12,
          { "Requested amount of gain steps for TM[12]", "g3.fcccommand.tmrpayload_txcoef_tm12", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B76,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm13,
          { "Requested amount of gain steps for TM[13]", "g3.fcccommand.tmrpayload_txcoef_tm13", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B54,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm14,
          { "Requested amount of gain steps for TM[14]", "g3.fcccommand.tmrpayload_txcoef_tm14", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B32,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm15,
          { "Requested amount of gain steps for TM[15]", "g3.fcccommand.tmrpayload_txcoef_tm15", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B10,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm16,
          { "Requested amount of gain steps for TM[16]", "g3.fcccommand.tmrpayload_txcoef_tm16", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B76,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm17,
          { "Requested amount of gain steps for TM[17]", "g3.fcccommand.tmrpayload_txcoef_tm17", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B54,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm18,
          { "Requested amount of gain steps for TM[18]", "g3.fcccommand.tmrpayload_txcoef_tm18", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B32,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm19,
          { "Requested amount of gain steps for TM[19]", "g3.fcccommand.tmrpayload_txcoef_tm19", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B10,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm20,
          { "Requested amount of gain steps for TM[20]", "g3.fcccommand.tmrpayload_txcoef_tm20", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B76,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm21,
          { "Requested amount of gain steps for TM[21]", "g3.fcccommand.tmrpayload_txcoef_tm21", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B54,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm22,
          { "Requested amount of gain steps for TM[22]", "g3.fcccommand.tmrpayload_txcoef_tm22", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B32,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_txcoef_tm23,
          { "Requested amount of gain steps for TM[23]", "g3.fcccommand.tmrpayload_txcoef_tm23", FT_UINT8, BASE_DEC, NULL, G3_FCC_TMR_TXCOEFF_B10,
            NULL, HFILL }
        },
        { &hf_g3_fcccommand_payload_mod_sch,
          { "Payload modulation scheme", "g3.fcccommand.tmrpayload_mod_sch", FT_UINT8, BASE_DEC, VALS(modsch), G3_FCC_TMR_MOD_SCH_MSK,
            NULL, HFILL }
        }
    };
    static gint *ett[] = {
        &ett_g3_fcccommand,
        &ett_g3_fcccommand_payload,
    };

    /*The full and short name are used in e.g. the "Preferences" and "Enabled protocols"
     * dialogs as well as the generated field name list in the documentation.
     * The abbreviation is used as the display filter name.*/
    proto_g3_fcccommand = proto_register_protocol(
                                                  "G3 FCC Command", //Name
                                                  "G3_FCC_COMMAND", //Short name
                                                  "g3_fcc_command"  //Abbrev
                                                  );

    /* Register the arrays */
    proto_register_field_array(proto_g3_fcccommand, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("g3_fcccommand", dissect_g3_fcccommand, proto_g3_fcccommand);
}

void
proto_reg_handoff_g3data(void)
{
    g3data_handle = create_dissector_handle(dissect_g3data, proto_g3data);
}

void
proto_register_g3data(void)
{
    /* A header field is something you can search/filter on.
     * A structure is created to register the fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}} */
    static hf_register_info hf[] = {
        { &hf_g3data,
            { "G3 Adaptation Layer", "g3.data.data", FT_NONE, BASE_NONE, NULL, 0x0,
              "G3 ADP", HFILL }
        },

        { &hf_g3data_lowpan_bc0htype,
          { "Header: LOWPAN_BC0 (Broadcast)", "g3.data.bc0htype", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_eschtype,
          { "Header: ESC (Additional Dispatch byte follows)", "g3.data.eschtype", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_meshhtype,
          { "Header: MESH (Mesh Header)", "g3.data.meshhtype", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_frag1htype,
          { "Header: FRAG1 (Fragmentation Header (first))", "g3.data.frag1htype", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_fragnhtype,
          { "Header: FRAGN (Fragmentation Header (subsequent))", "g3.data.fragnhtype", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_hopinfo,
          { "Hop Information", "g3.data.hopinfo", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_vforigin,
          { "Originator Address Type", "g3.data.vforigin", FT_UINT8, BASE_DEC, VALS(veryfirst), 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_vfdest,
          { "Final Address Type", "g3.data.vfdest", FT_UINT8, BASE_DEC, VALS(veryfirst), 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_hops,
          { "Hops left", "g3.data.hops", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_originator,
          { "Originator Address", "g3.data.originator", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_destination,
          { "Final Address", "g3.data.destination", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_originator64,
          { "Originator Address", "g3.data.originator64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_destination64,
          { "Final Address", "g3.data.destination64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_datagram_size,
          { "Datagram size", "g3.data.datagram_size", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_datagram_tag,
          { "Datagram tag", "g3.data.datagram_tag", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_datagram_offset,
          { "Datagram offset", "g3.data.datagram_offset", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_seqnr,
          { "Sequence number", "g3.data.seqnr", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_command_id,
          { "Command ID", "g3.data.command_id", FT_UINT8, BASE_HEX, VALS(cfhtype), 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_command_payload,
          { "Command Payload", "g3.data.command_payload", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_unidentified_bytes,
          { "Unidentified bytes", "g3.data.unidentified_bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_cfavalue,
          { "Contention Free Access Value", "g3.data.cfavalue", FT_UINT8, BASE_DEC, VALS(cfatype), 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_messagetype,
          { "Message type", "g3.data.messagetype", FT_UINT8, BASE_DEC, VALS(messagetype), 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_rrep_hoplimit,
          { "Hop Limit", "g3.data.rrep_hoplimit", FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_wlinks,
          { "Number of weak links", "g3.data.rrep_wlinks", FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_repair,
          { "Repair type", "g3.data.rrep_repair", FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3data_rreq_unicast,
          { "Unicast RREQ", "g3.data.rreq_unicast", FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_g3data_rreq_reserved,
          { "Reserved", "g3.data.rreq_reserved", FT_UINT8, BASE_DEC, NULL, 0x30,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_bit_reserved,
          { "Reserved", "g3.data.rrep_bit_reserved", FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_otype_low,
          { "Metric Type", "g3.data.rrep_otype_low", FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_otype_high,
          { "Metric Type", "g3.data.rrep_otype_high", FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_rc,
          { "Route cost", "g3.data.rrep_rc", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_preqid,
          { "Hop Count", "g3.data.rrep_preqid", FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_reserved,
          { "Reserved", "g3.data.rrep_reserved", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_originator,
          { "Link layer Originator Address", "g3.data.rrep_originator", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_destination,
          { "Link layer Destination Address", "g3.data.rrep_destination", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_rrep_sequence,
          { "Sequence Number", "g3.data.rrep_sequence", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_rerr_reserved,
          { "Reserved", "g3.data.rerr_reserved", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_rerr_errorcode,
          { "Error Code", "g3.data.rerr_errorcode", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_rerr_address,
          { "Unreachable Link Layer Destination Address", "g3.data.rerr_address", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_preq_originator,
          { "Originator Address", "g3.data.preq_originator", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_preq_destination,
          { "Destination Address", "g3.data.preq_destination", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_preq_pmt,
          { "Path Metric Type", "g3.data.hop_pmt", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_preq_hop_fpa,
          { "Hop Address", "g3.data.hop_fpa", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_preq_hop_mns,
          { "Metric Not Supported", "g3.data.hop_mns", FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_g3data_preq_hop_phase_diff,
          { "Forward Path Phase Differential", "g3.data.hop_phase_diff", FT_UINT8, BASE_DEC, VALS(g3data_hop_phase_diff_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_g3data_preq_hop_mrx,
          { "Forward Path MRx", "g3.data.hop_mrx", FT_UINT8, BASE_DEC, VALS(mediatype), 0x08,
            NULL, HFILL }
        },
        { &hf_g3data_preq_hop_mtx,
          { "Forward Path MTx", "g3.data.hop_mtx", FT_UINT8, BASE_DEC, VALS(mediatype), 0x04,
            NULL, HFILL }
        },
        { &hf_g3data_preq_hop_reserved,
          { "Reserved", "g3.data.hop_mtx", FT_UINT8, BASE_DEC, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_g3data_preq_hop_fplc,
          { "Hop Path Link Cost", "g3.data.hop_fplc", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_prep_destination,
          { "Destination Address", "g3.data.prep_destination", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_prep_originator,
          { "Originator Address", "g3.data.prep_originator", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_prep_expected_originator,
          { "Expected Originator", "g3.data.prep_exporig", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_rlc_linkcost,
          { "Link Cost", "g3.data.rlc_linkcost", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_lbp_header,
          { "LBP Header", "g3.data.lbp_header", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_data,
          { "LBP Payload", "g3.data.lbp_data", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_eap_header,
          { "EAP Header", "g3.data.eap_header", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_eap_data,
          { "EAP Payload", "g3.data.eap_data", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_lbp_type,
          { "Message Type", "g3.data.lbp_type", FT_UINT16, BASE_DEC, VALS(lbptype), 0x8000,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_codefrom,
          { "Message from LBD", "g3.data.lbp_codefrom", FT_UINT16, BASE_DEC, VALS(lbpcodefrom), 0x7000,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_codeto,
          { "Message to LBD", "g3.data.lbp_codeto", FT_UINT16, BASE_DEC, VALS(lbpcodeto), 0x7000,
            NULL, HFILL }
        },
        { &hf_g3data_media_type,
          { "Media Type", "g3.data.media_type", FT_UINT16, BASE_DEC, VALS(mediatype), 0x0800,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_transaction,
          { "Transaction ID", "g3.data.lbp_seq", FT_UINT16, BASE_DEC, NULL, 0x07ff,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_address,
          { "Address of Bootstrapping Device", "g3.data.lbp_address", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_lbp_codetype,
          { "Code", "g3.data.lbp_codetype", FT_UINT8, BASE_DEC, VALS(lbpeapcode), 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_len,
          { "Length", "g3.data.lbp_len", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_identifier,
          { "Identifier", "g3.data.lbp_identifier", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_eap_type,
          { "Type", "g3.data.eap_type", FT_UINT8, BASE_HEX, VALS(eaptypes), 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_eap_tflag,
          { "T flag", "g3.data.eap_tflag", FT_UINT8, BASE_DEC, VALS(tflag), 0xc0,
            NULL, HFILL }
        },
        { &hf_g3data_eap_reservedflag,
          { "Reserved flags", "g3.data.eap_reservedflag", FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_g3data_eap_rands,
          { "RAND_S", "g3.data.eap_rands", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_eap_ids,
          { "ID_S", "g3.data.eap_ids", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_eap_randp,
          { "RAND_P", "g3.data.eap_randp", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_eap_macp,
          { "MAC_P (Encrypted)", "g3.data.eap_macp", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_eap_idp,
          { "ID_P", "g3.data.eap_idp", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_eap_macs,
          { "MAC_S", "g3.data.eap_macs", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_eap_pchannel,
          { "PCHANNEL", "g3.data.eap_pchannel", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_lbp_cfg_attr_id,
          { "attribute ID", "g3.data.lbp.cfg.attr_id", FT_UINT8, BASE_DEC, VALS(g3data_lbp_cfg_attr_id_vals), 0xfc,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_M,
          { "M", "g3.data.lbp.cfg.M", FT_UINT8, BASE_DEC, VALS(g3data_lbp_cfg_M_vals), 0x02,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_type,
          { "Type: Configuration Parameter", "g3.data.lbp.cfg.type", FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_len,
          { "len", "g3.data.lbp.cfg.len", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        /* g3data_lbp_cfg_param */
        { &hf_g3data_lbp_cfg_value_Short_Addr_short_addr,
          { "short addr", "g3.data.lbp.cfg.value.Short_Addr.short_addr", FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_GMK_key_id,
          { "key id", "g3.data.lbp.cfg.value.GMK.key_id", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_GMK_gmk,
          { "gmk", "g3.data.lbp.cfg.value.GMK.gmk", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_GMK_activation_key_id,
          { "key id", "g3.data.lbp.cfg.value.GMK_activation.key_id", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_GMK_removal_key_id,
          { "key id", "g3.data.lbp.cfg.value.GMK_removal.key_id", FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_parameter_result_result,
          { "result", "g3.data.lbp.cfg.value.parameter_result.result", FT_UINT8, BASE_DEC, VALS(g3data_lbp_cfg_value_parameter_result_result_vals), 0,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_parameter_result_attr_id,
          { "attribute ID", "g3.data.lbp.cfg.value.parameter_result.attr_id", FT_UINT8, BASE_DEC, VALS(g3data_lbp_cfg_value_parameter_result_attr_id_vals), 0xfc,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_parameter_result_M,
          { "M", "g3.data.lbp.cfg.value.parameter_result.M", FT_UINT8, BASE_DEC, VALS(g3data_lbp_cfg_M_vals), 0x02,
            NULL, HFILL }
        },
        { &hf_g3data_lbp_cfg_value_parameter_result_type,
          { "Configuration parameters", "g3.data.lbp.cfg.value.parameter_result.type", FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_g3data_pchannel_nonce,
          { "Nonce", "g3.data.pchannel_nonce", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_pchannel_tag,
          { "Tag", "g3.data.pchannel_tag", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_g3data_pchannel_r,
          { "Result indication flag (Encrypted)", "g3.data.pchannel_r", FT_UINT8, BASE_HEX, NULL, 0xc0,
            NULL, HFILL }
        },
        { &hf_g3data_pchannel_e,
          { "Extension flag (Encrypted)", "g3.data.pchannel_e", FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_g3data_pchannel_reserved,
          { "Reserved field (Encrypted)", "g3.data.pchannel_reserved", FT_UINT8, BASE_HEX, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_g3data_pchannel_extension,
          { "Extension field (Encrypted)", "g3.data.pchannel_extension", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_nak_data,
          { "Data", "g3.data.nak_data", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_g3data_databyte,
          { "Data", "g3.data.data_databyte", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };
    static gint *ett[] = {
        &ett_g3data,

        &ett_g3data_lowpan_bc0htype,
        &ett_g3data_eschtype,
        &ett_g3data_meshhtype,
        &ett_g3data_frag1htype,
        &ett_g3data_fragnhtype,

        &ett_g3data_lbp_header,
        &ett_g3data_lbp_data,

        &ett_g3data_eap_header,
        &ett_g3data_eap_data,
        &ett_g3data_eap_pchannel,

        &ett_g3data_lbp_cfg_param,

        &ett_g3data_command_payload,
        &ett_g3data_hopinfo
    };

    static ei_register_info ei[] = {
        { &ei_g3data_illegal_value, { "g3.data.illegal_value", PI_PROTOCOL, PI_WARN, "Illegal Value", EXPFILL } },
        { &ei_g3data_psk_not_found, { "g3.data.psk_not_found", PI_SECURITY, PI_WARN, "PSK not found", EXPFILL } },
    };

    expert_module_t *expert_g3data;

    /* The full and short name are used in e.g. the "Preferences" and "Enabled protocols"
       dialogs as well as the generated field name list in the documentation.
       The abbreviation is used as the display filter name.*/
    proto_g3data = proto_register_protocol(
                                           "G3 Data", /* name       */
                                           "G3_DATA", /* short name */
                                           "g3_data"  /* abbrev     */
                                           );
    register_init_routine(&g3data_init);

    /* Register the arrays */
    proto_register_field_array(proto_g3data, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("g3data", dissect_g3data, proto_g3data);

    expert_g3data = expert_register_protocol(proto_g3data);
    expert_register_field_array(expert_g3data, ei, array_length(ei));
}

/******************************************************************************
*  Private function bodies for CRC-5 and CRC-8 FCCS calculation
******************************************************************************/

//******************************************************************************
//
// CRC()  - Computes a USB CRC value given an input value.
//          Ported from the Perl routine from the USB white paper entitled
//          "CYCLIC REDUNDANCY CHECKS IN USB"
//          www.usb.org/developers/whitepapers/crcdes.pdf
//
//          Ported by Ron Hemphill 01/20/06.
//
//  dwinput:    The input value.
//  iBitcnt:    The number of bits represented in dwInput.
//
//  Returns:    The computed CRC value.
//
//******************************************************************************
static guint32
calc_crcusb(guint32 dwInput, guint32 crc, int iBitcnt, guint32 poly, guint8 crcBitSize)
{
    static const guint8 INT_SIZE = 32;
    guint32 udata = (dwInput << (INT_SIZE - iBitcnt));

    poly = (poly << (INT_SIZE - crcBitSize));
    crc = (crc << (INT_SIZE - crcBitSize));

    if ((iBitcnt < 1) || (iBitcnt > INT_SIZE)) {    // Validate iBitcnt
        return 0xffffffff;
    }


    while (iBitcnt--) {
        if ((udata ^ crc) & (0x1 << (INT_SIZE - 1))) { // first bit
            crc <<= 1;        //biggest is XXXXX00000000.....
            crc ^= poly;      //biggest is XXXXX00000000.....
        } else {
            crc <<= 1;
        }
        udata <<= 1;
    }

    // Shift back into position
    crc >>= (INT_SIZE - crcBitSize);

    return crc;
}

/******************************************************************************
*  End of private function bodies for CRC-5 and CRC-8 FCCS calculation
******************************************************************************/

/******************************************************************************
*  Private function bodies
******************************************************************************/
static void
proto_init_g3(void)
{
    reassembly_table_init(&msg_reassembly_table,
                          &addresses_reassembly_table_functions);
    last_key_index = 0xff;
    extracted_gmk0s = wmem_tree_new(wmem_file_scope());
    extracted_gmk1s = wmem_tree_new(wmem_file_scope());

    memset(ack_links, 0, sizeof (ack_links));

    /* Get the universal PSK. */
    universal_psk_valid = FALSE;
    if (use_universal_psk) {
        GByteArray *bytes = g_byte_array_new();
        gboolean res = hex_str_to_bytes(universal_psk_string, bytes, FALSE);
        universal_psk_valid = (res && bytes->len >= 16);
        if (universal_psk_valid) {
            memcpy(universal_psk_bytes, bytes->data, 16);
        }
        g_byte_array_free(bytes, TRUE);
    }

    cenelec_is_b = FALSE;
    standard_is_G3Base = FALSE;
}

/*!
 *  \fn static guint16 calc_tvb_fcs(tvbuff_t* tvb, gint offset, int length)
 *  \brief Calclate the FCS CRC-16 over the selected portion of the tvb
 *  \param tvb The tvb
 *  \param offset The start offset for the CRC calculation
 *  \param length The number of bytes to consider for the CRC calculation
 *  \return the FCS CRC-16
 */
static guint16
calc_tvb_fcs(tvbuff_t *tvb, gint offset, int length)
{
    static const guint16 FCS_CRC16_SEED = 0;
    const guint8 *data = tvb_get_ptr(tvb, offset, length);

    return crc16_x25_ccitt_seed(data, length, FCS_CRC16_SEED);
}

/*!
 *  \fn static guint16 calc_tvb_fccs_cena(tvbuff_t* tvb, gint offset)
 *  \brief Calculate the CENELEC-A FCCS CRC-5 over the selected portion of the tvb
 *  \param tvb The tvb
 *  \param offset The start offset for the CRC calculation
 *  \return the FCCS CRC-5
 */
static guint8
calc_tvb_fccs_cena(tvbuff_t *tvb, gint offset)
{
    guint32 data = tvb_get_guint8(tvb, offset + 0) << 24 | tvb_get_guint8(tvb, offset + 1) << 16 |
                   tvb_get_guint8(tvb, offset + 2) << 8 | tvb_get_guint8(tvb, offset + 3) << 0;

    return (guint8) (calc_crcusb(data >> 4, 0x1f, 28, 0x05, 5) ^ 0x1f);
}

/*!
 *  \fn static guint16 calc_tvb_fccs_fcc(tvbuff_t* tvb, gint offset)
 *  \brief Calculate the FCC FCCS CRC-8 over the selected portion of the tvb
 *  \param tvb The tvb
 *  \param offset The start offset for the CRC calculation
 *  \return the FCCS CRC-8
 */
static guint8
calc_tvb_fccs_fcc(tvbuff_t *tvb, gint offset)
{
    guint8 crc = 0xff;
    guint8 i;
    for (i=0; i<58/8; i++)
        crc = (guint8) calc_crcusb(tvb_get_guint8(tvb, offset+i), crc, 8, 0x07, 8);
    crc = (guint8) calc_crcusb(tvb_get_guint8(tvb, offset+58/8) >> (8-58%8), crc, 58%8, 0x07, 8);
    return (guint8) (crc^0xff);
}

/*!
 *  \fn static void ack_link_register_frame(tvbuff_t *tvb, packet_info* pinfo, proto_tree* subtree, guint16 fcs, ack_link_frame_type_t frame_type)
 *  \brief Register a frame for acknowledgement linking using the Frame Check Sum.
 *  \param tvb The current TV buffer.
 *  \param pinfo The Wireshark packet information.
 *  \param subtree The tree to append this info to.
 *  \param fcs The Frame Check Sequence used as ack link identifier.
 *  \param frame_type Type of frame to register.
 */
static void
ack_link_register_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, guint16 fcs,
                        ack_link_frame_type_t frame_type)
{
    g3_ack_link_t *ack_link = NULL;

    if (!PINFO_FD_VISITED(pinfo)) {
        if (ack_links[fcs] == NULL) {
            ack_links[fcs] = wmem_tree_new(wmem_file_scope());
        }

        if (frame_type == ACK_LINK_DATA) {
            ack_link = wmem_new(wmem_file_scope(), g3_ack_link_t);
            ack_link->data_frame_num = pinfo->num;
            ack_link->ack_frame_num = 0;
            ack_link->data_frame_time = pinfo->fd->abs_ts;
            wmem_tree_insert32(ack_links[fcs], pinfo->num, (void *) ack_link);
        } else {
            ack_link = (g3_ack_link_t *) wmem_tree_lookup32_le(ack_links[fcs], pinfo->num);

            // In case of a FCS collision: don't overwrite an earlier ack if it's there
            if (ack_link && ack_link->ack_frame_num == 0) {
                ack_link->ack_frame_num = pinfo->num;
                ack_link->is_ack = frame_type == ACK_LINK_ACK ? TRUE : FALSE;
            } else {
                ack_link = NULL;
            }
        }
    } else {
        if (ack_links[fcs] != NULL) {
            ack_link = (g3_ack_link_t *) wmem_tree_lookup32_le(ack_links[fcs], pinfo->num);
        }
    }

    /* Add result to the tree */
    if (frame_type == ACK_LINK_DATA) {
        if (ack_link && ack_link->ack_frame_num) {
            proto_item *it = proto_tree_add_uint(subtree,
                                                 ack_link->is_ack ? hf_g3_ack_in : hf_g3_nack_in,
                                                 tvb,
                                                 0,
                                                 0,
                                                 ack_link->ack_frame_num);
            PROTO_ITEM_SET_GENERATED(it);
        } else {
            proto_item *it = proto_tree_get_parent(subtree);
            expert_add_info(pinfo, it, &ei_g3_ack_link_ack_missing);
        }
    } else {
        if (ack_link) {
            proto_item *it = proto_tree_add_uint(subtree,
                                                 ack_link->is_ack == ACK_LINK_ACK ? hf_g3_ack_for : hf_g3_nack_for,
                                                 tvb,
                                                 0,
                                                 0,
                                                 ack_link->data_frame_num);
            PROTO_ITEM_SET_GENERATED(it);

            nstime_t ns;
            nstime_delta(&ns, &pinfo->fd->abs_ts, &ack_link->data_frame_time);
            it = proto_tree_add_time(subtree, hf_g3_ack_delay, tvb, 0, 0, &ns);
            PROTO_ITEM_SET_GENERATED(it);
        } else {
            proto_item *it = proto_tree_get_parent(subtree);
            expert_add_info(pinfo, it, &ei_g3_ack_link_data_frame_missing);
            return;
        }
    }
}

/*!
 *  \fn static const guint8* lookup_key(guint16 pan_id, guint8 key_index)
 *  \brief Look up key for specfied pan_id and index in preferences UAT
 *  \param[in] pan_id 16-bit value of the PAN ID of the searched key
 *  \param[in] key_index Can be 0 or 1 to select GMK0 or GMK1 respectively
 *  \param[in] frame_num Number of the frame (used for extracted GMKs)
 *  \return The key (16 bytes) or NULL if not found; the key must not be deallocated
 *  \details This function returns a pointer to the appropriate entry in the
 *  static UAT static_keys table. The return value is NULL if the security key
 *  for the given PAN is not found. Otherwise, it returns a pointer to a 16-byte
 *  array containing the key. Do not delete or deallocate this pointer since this is the one stored in the
 *  UAT table and is managed by the UAT functions.
 */
static const guint8 *
lookup_key(guint16 pan_id, guint8 key_index, guint32 frame_num)
{
    guint i;
    guint8 *lookup_result = NULL;

    /* Check that the key_index is correct. Can only be 0 or 1 */
    if (key_index > 1) {
        return lookup_result;
    }

    if (extract_gmks_from_eap) {
        const guint8 *key = (const guint8 *) wmem_tree_lookup32_le(
            key_index == 0 ? extracted_gmk0s : extracted_gmk1s, frame_num);
        if (key != NULL) {
            return key;
        }
    } else {
        /* Check the cache. If the value is already there, return it */
        if ((last_gmk != NULL) && (last_pan_id == pan_id) && (last_key_index == key_index)) {
            return last_gmk;
        }
    }

    /* Check each entry linearly for the right pan_id */
    for (i = 0; i < num_static_keys; i++) {
        if (static_keys[i].pan_id == pan_id) {
            if (key_index == 0) {
                lookup_result = (guint8 *) static_keys[i].gmk0;
            } else {
                lookup_result = (guint8 *) static_keys[i].gmk1;
            }

            /* Update the cache */
            last_pan_id = pan_id;
            last_key_index = key_index;
            last_gmk = lookup_result;

            break;
        }
    }
    return lookup_result;
}

/*!
 *  \fn static gboolean keys_uat_update_cb(void *r, char **err)
 *  \brief Callback function to sanity check a UAT entry for a PAN ID/GMK0/GMK1 row
 *  \param r Pointer to the row information (static_keys_t)
 *  \param[out] err Output string set in error case
 *  \return TRUE if everything is fine or FALSE in case of an error
 *  \details Callback function associated with the static_key structure to perform a
 *  check of each field whenever an entry has been modified. This can happen either
 *  through user interaction in the GUI of wireshark or through the uat_load function
 *  that reads a stored table from a given file.
 */
static gboolean
keys_uat_update_cb(void *r, char **err)
{
    static_keys_t *map = (static_keys_t *) r;

    /* Ensure a valid PAN identifier. */
    if (map->pan_id > 0xFFFF) {
        *err = g_strdup("Invalid PAN identifier. Must be 16 bits (0x0000-0xFFFF).");
        return FALSE;
    }

    /* Ensure a valid key length */
    if ((map->gmk0_len != G3_GMK_LENGTH) || (map->gmk1_len != G3_GMK_LENGTH)) {
        *err = g_strdup("Invalid Key length. Must be 16 bytes.");
        return FALSE;
    }

    return TRUE;
} /* keys_uat_update_cb */

/*!
 *  \fn static gboolean psks_uat_update_cb(void *r, char **err)
 *  \brief Callback function to sanity check a PSK entry
 *  \param r Pointer to the row information (static_keys_t)
 *  \param[out] err Output string set in error case
 *  \return TRUE if everything is fine or FALSE in case of an error
 *  \details Callback function associated with the static_key structure to perform a
 *  check of each field whenever an entry has been modified. This can happen either
 *  through user interaction in the GUI of wireshark or through the uat_load function
 *  that reads a stored table from a given file.
 */
static gboolean
psks_uat_update_cb(void *r, char **err)
{
    psk_t *map = (psk_t *) r;

    /* Ensure a valid key length */
    if (map->eui64_len != 8) {
        *err = g_strdup("Invalid EUI-64 length. Must be 8 bytes.");
        return FALSE;
    }

    /* Ensure a valid key length */
    if (map->psk_len != 16) {
        *err = g_strdup("Invalid PSK length. Must be 16 bytes.");
        return FALSE;
    }

    return TRUE;
} /* psks_uat_update_cb */

/*!
 *  \fn static void add_extracted_gmk(guint32 frame_num, guint8 id, const guint8* key)
 *  \brief Add extracted GMK
 *  \param frame_num The number of the frame from which the GMK is extracted
 *  \param id The GMK ID
 *  \param gmk The GMK
 */
static void
add_extracted_gmk(guint32 frame_num, guint8 id, const guint8 *gmk)
{
    guint8 *key = wmem_alloc_array(wmem_file_scope(), guint8, 16);

    memcpy(key, gmk, 16);

    if (key) {
        wmem_tree_insert32(id == 0 ? extracted_gmk0s : extracted_gmk1s, frame_num, key);
    }
}

/*!
 *  \fn static const guint8* lookup_psk(const guint8* eui64)
 *  \brief Lookup PSK based on EUI-64
 *  \param eui64 Pointer to the EUI-64
 *  \return Pointer to the PSK or NULL if not found
 */
static const guint8 *
lookup_psk(const guint8 *eui64)
{
    guint i;

    if (use_universal_psk) {
        return universal_psk_valid ? universal_psk_bytes : NULL;
    }
    for (i = 0; i < num_psks; i++) {
        if (memcmp(eui64, psks[i].eui64, 8) == 0) {
            return (const guint8 *) psks[i].psk;
        }
    }
    return NULL;
}

/*!
 *  \fn static void create_enc_iv(const ieee802154_packet *packet, guint8 *iv)
 *  \brief Fill the initialization vector for decryption.
 *  \details See IEEE 802.15.4-2006 B.4.1.3 and G3 Table 9-22 for details.
 *  \param packet The IEEE 802.15.4 packet information.
 *  \param iv The output buffer for the initialization vector (must be at least 16 bytes).
 */
static void
create_enc_iv(const ieee802154_packet *packet, guint8 *iv)
{
    guint i = 0;

    /* Flags: Reserved || Reserved || 0 || L'  with L'=L-1 and L=2 -> 1 (IEEE 802.15.4-2006 B.4.1.3) */
    iv[i++] = (0x2 - 1);

    /* CCM* nonce (G3 Table 9-22) */
    gboolean addr_is_long_mode = FALSE;
    if (standard_is_G3Base) {
        if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
            addr_is_long_mode = TRUE;
        }
    }
    if (addr_is_long_mode == TRUE) {
        iv[i++] = (guint8) (packet->src64 >> 56);
        iv[i++] = (guint8) (packet->src64 >> 48);
        iv[i++] = (guint8) (packet->src64 >> 40);
        iv[i++] = (guint8) (packet->src64 >> 32);
        iv[i++] = (guint8) (packet->src64 >> 24);
        iv[i++] = (guint8) (packet->src64 >> 16);
        iv[i++] = (guint8) (packet->src64 >> 8);
        iv[i++] = (guint8) (packet->src64 >> 0);
    } else {
        iv[i++] = (guint8) (packet->src_pan >> 8);
        iv[i++] = (guint8) (packet->src_pan >> 0);
        iv[i++] = (guint8) (packet->src16 >> 8);
        iv[i++] = (guint8) (packet->src16 >> 0);
        iv[i++] = (guint8) (packet->src_pan >> 8);
        iv[i++] = (guint8) (packet->src_pan >> 0);
        iv[i++] = (guint8) (packet->src16 >> 8);
        iv[i++] = (guint8) (packet->src16 >> 0);
    }
    iv[i++] = (guint8) (packet->frame_counter >> 24);
    iv[i++] = (guint8) (packet->frame_counter >> 16);
    iv[i++] = (guint8) (packet->frame_counter >> 8);
    iv[i++] = (guint8) (packet->frame_counter >> 0);
    iv[i++] = packet->security_level; // security level

    /* counter bytes (IEEE 802.15.4-2006 B.4.1.3) start with 0 */
    iv[i++] = 0x0;
    iv[i] = 0x0;
}

/*!
 *  \fn static void create_mic_iv(const ieee802154_packet *packet, guint8 *iv, guint16 data_len, guint8 mic_len)
 *  \brief Fill the initialization vector for MIC computation.
 *  \details See IEEE 802.15.4-2006 B.4.1.2 and G3 Table 9-22 for details.
 *  \param packet The IEEE 802.15.4 packet information.
 *  \param iv The output buffer for the initialization vector (must be at least 16 bytes).
 *  \param data_len The length of the data.
 *  \param mic_len The length of the MIC.
 */
static void
create_mic_iv(const ieee802154_packet *packet, guint8 *iv, guint16 data_len, guint8 mic_len)
{
    create_enc_iv(packet, iv);

    /* Flags: Reserved || Adata || M' || L' with Adata=1, M'=(M - 2)/2,  L'=L-1 (IEEE 802.15.4-2006 B.4.1.2) */
    iv[0] = (guint8) (1 << 6 | ((mic_len - 2) / 2) << 3 | 1);

    /* plain text length */
    iv[14] = (guint8) (data_len >> 8);
    iv[15] = (guint8) (data_len >> 0);
}

/*!
 *  \fn static guint dissect_g3_cen_fch(tvbuff_t *tvb, guint offset, proto_tree *tree, gboolean* out_continue)
 *  \brief Parse and display the G3 CENELEC FCH header
 *  \param tvb The current tvb.
 *  \param offset The offset of the header in the tvb.
 *  \param pinfo The Wireshark packet information.
 *  \param tree The display tree.
 *  \param[out] out_continue is set to FALSE if ACK/NACK or illegal values are encountered (unchanged otherwise)
 *  \return The length of this header
 */
static guint
dissect_g3_cen_fch(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree,
                   gboolean *out_continue)
{
    proto_item *fccs_item = NULL;
    proto_item *g3_fch_subitem;
    proto_tree *g3_fch_subtree;
    guint8 dt = (guint8) ((tvb_get_guint8(tvb, offset + 3) >> 4) & (0x07));

    if (dt > 1) {
        *out_continue = FALSE;
    }

    g3_fch_subitem =
        proto_tree_add_item(tree, hf_g3_cen_fch, tvb, offset, G3_CEN_FCH_LENGTH, ENC_NA);
    g3_fch_subtree = proto_item_add_subtree(g3_fch_subitem, ett_g3_cen_fch);

    if (dt < 2) {
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_PDC, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (tvb_get_guint8(tvb, offset + 3) & G3_CEN_FCH_PAY_MOD_SCH_MSK) {
            if (standard_is_G3Base) {
                proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_MOD_coh_g3base, tvb, (offset + 1),
                                    2, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_MOD_coh, tvb, (offset + 1), 1,
                                    ENC_BIG_ENDIAN);
            }
        } else {
            if (standard_is_G3Base) {
                proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_MOD_dif_g3base, tvb, (offset + 1),
                                    2, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_MOD_dif, tvb, (offset + 1), 1,
                                    ENC_BIG_ENDIAN);
            }
        }
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_FL, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_TM, tvb, (offset + 2), 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_PAY_MOD_SCH, tvb, (offset + 3), 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_DT, tvb, (offset + 3), 1, ENC_BIG_ENDIAN);
        fccs_item = proto_tree_add_item(g3_fch_subtree, hf_g3_cen_fch_FCCS, tvb, (offset + 3), 2,
                                        ENC_BIG_ENDIAN);
    } else if (dt < 4) {
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_fcs_1, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_ssca, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_reserved_b1, tvb, offset + 1, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_fcs_2, tvb, offset + 2, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_reserved_b3, tvb, offset + 3, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_dt, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        fccs_item = proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_fccs, tvb, offset + 3, 2,
                                        ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_ConvZeros, tvb, offset + 4, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_cen_ack_reserved_b4, tvb, offset + 4, 1,
                            ENC_BIG_ENDIAN);

        // Extract reference FCS for acknowledgement linking
        guint16 fcs = tvb_get_guint8(tvb, offset) | (tvb_get_guint8(tvb, offset + 2) << 8);

        if (dt == 2) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Acknowledgement");
            ack_link_register_frame(tvb, pinfo, tree, fcs, ACK_LINK_ACK);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "NACK");
            ack_link_register_frame(tvb, pinfo, tree, fcs, ACK_LINK_NACK);
        }

        proto_tree_add_item(tree, hf_g3_cen_reserved, tvb, offset + 5, 3, ENC_NA);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown delimiter type %u. Stopping dissection.",
                        dt);
    }

    if (dt < 4) {
        guint8 calc_crc = calc_tvb_fccs_cena(tvb, offset);

        /* G3 Spec:
           "where the FCCS field is packed as follows: bit 3 to bit 0 of Byte 3 are packed with FCCS bit 3 to bit 0,
           respectively, and bit 7 of Byte 4 is packed with FCCS bit 4 (MSB)"
        */
        guint8 msg_crc = (guint8) ((tvb_get_guint8(tvb, offset+3) & 0x0f) | ((tvb_get_guint8(tvb, offset+4) & 0x80) >> 3));
        if (calc_crc != msg_crc)
        {
            expert_add_info_format(pinfo, fccs_item, &ei_g3_crc_error, "CRC error: expected 0x%02x, is 0x%02x", calc_crc, msg_crc);
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "CRC Error");
        }
    }
    return G3_CEN_FCH_LENGTH;
}

/*!
 *  \fn static guint dissect_g3_fcc_fch(tvbuff_t *tvb, guint offset, proto_tree *tree, gboolean* out_continue)
 *  \brief Parse and display the G3 FCC FCH header
 *  \param tvb The current tvb.
 *  \param offset The offset of the header in the tvb.
 *  \param pinfo The Wireshark packet information.
 *  \param tree The display tree.
 *  \param[out] out_continue is set to FALSE if ACK/NACK or illegal values are encountered (unchanged otherwise)
 *  \return The length of this header
 */
static guint
dissect_g3_fcc_fch(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree,
                   gboolean *out_continue)
{
    proto_item *fccs_item = NULL;
    proto_item *g3_fch_subitem;
    proto_tree *g3_fch_subtree;
    guint8 dt = (guint8) ((tvb_get_guint8(tvb, offset + 1) >> 1) & (0x07));

    if (dt > 1) {
        *out_continue = FALSE;
    }

    g3_fch_subitem =
        proto_tree_add_item(tree, hf_g3_fcc_fch, tvb, offset, G3_FCC_FCH_LENGTH, ENC_NA);
    g3_fch_subtree = proto_item_add_subtree(g3_fch_subitem, ett_g3_fcc_fch);

    if (dt < 2) {
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_PDC, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (tvb_get_guint8(tvb, offset + 1) & G3_FCC_FCH_PAY_MOD_SCH_MSK) {
            if (standard_is_G3Base) {
                proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_MOD_coh_g3base, tvb, (offset + 1),
                                    1, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_MOD_coh, tvb, (offset + 1), 1,
                                    ENC_BIG_ENDIAN);
            }
        } else {
            if (standard_is_G3Base) {
                proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_MOD_dif_g3base, tvb, (offset + 1),
                                    1, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_MOD_dif, tvb, (offset + 1), 1,
                                    ENC_BIG_ENDIAN);
            }
        }
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_PAY_MOD_SCH, tvb, (offset + 1), 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_DT, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_FL, tvb, (offset + 1), 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_TM, tvb, (offset + 3), 3,
                            ENC_LITTLE_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_TWO_RS, tvb, (offset + 6), 1,
                            ENC_BIG_ENDIAN);
        fccs_item = proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_fch_FCCS, tvb, (offset + 7), 2,
                                        ENC_BIG_ENDIAN);
    } else if (dt < 4) {
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_fcs_1, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_ssca, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_reserved_b1_1, tvb, offset + 1, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_dt, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_reserved_b1_2, tvb, offset + 1, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_reserved_b2, tvb, offset + 2, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_fcs_2, tvb, offset + 3, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_reserved_b4to6, tvb, offset + 4, 3,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_reserved_b7, tvb, offset + 7, 1,
                            ENC_BIG_ENDIAN);
        fccs_item = proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_fccs, tvb, offset + 7, 2,
                                        ENC_BIG_ENDIAN);
        proto_tree_add_item(g3_fch_subtree, hf_g3_fcc_ack_ConvZeros, tvb, offset + 8, 1,
                            ENC_BIG_ENDIAN);

        // Extract reference FCS for acknowledgement linking
        guint16 fcs = tvb_get_guint8(tvb, offset) | (tvb_get_guint8(tvb, offset + 3) << 8);

        if (dt == 2) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Acknowledgement");
            ack_link_register_frame(tvb, pinfo, tree, fcs, ACK_LINK_ACK);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "NACK");
            ack_link_register_frame(tvb, pinfo, tree, fcs, ACK_LINK_NACK);
        }

        proto_tree_add_item(tree, hf_g3_fcc_reserved, tvb, offset + 9, 3, ENC_NA);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown delimiter type %u. Stopping dissection.",
                        dt);
    }

    if (dt < 4) {
        guint8 calc_crc = calc_tvb_fccs_fcc(tvb, offset);
        guint8 msg_crc =
            (tvb_get_guint8(tvb, offset + 7) << 2) | (tvb_get_guint8(tvb, offset + 8) >> 6);
        if (calc_crc != msg_crc) {
            expert_add_info_format(pinfo, fccs_item, &ei_g3_crc_error,
                                   "CRC error: expected 0x%02x, is 0x%02x", calc_crc, msg_crc);
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "CRC Error");
        }
    }

    return G3_FCC_FCH_LENGTH;
}

/*!
 *  \fn static guint parse_dst_addr(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
 *  \brief Parse the destination address and PAN ID.
 *  \param tvb The current tvb.
 *  \param offset The offset of the header in the tvb.
 *  \param pinfo The Wireshark packet information.
 *  \param tree The display tree.
 *  \param packet The IEEE 802.15.4 packet information that is both used and filled.
 *  \return The length of this part.
 */
static guint
parse_dst_addr(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree,
               ieee802154_packet *packet)
{
    guint original_offset = offset;

    /* Add the destination pan ID item */
    packet->dst_pan = tvb_get_guint8(tvb, offset) | (tvb_get_guint8(tvb, offset + 1) << 8);
    proto_tree_add_uint(tree, hf_g3_dstpanid, tvb, offset, 2, packet->dst_pan);
    offset += 2;

    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        guint8 *ep_short_addr = wmem_alloc_array(pinfo->pool, guint8, g3_short_len());
        packet->dst16 = tvb_get_letohs(tvb, offset);

        ep_short_addr[0] = (guint8) ((packet->dst_pan >> 8) & 0xff);
        ep_short_addr[1] = (guint8) ((packet->dst_pan >> 0) & 0xff);
        ep_short_addr[2] = (guint8) ((packet->dst16 >> 8) & 0xff);
        ep_short_addr[3] = (guint8) ((packet->dst16 >> 0) & 0xff);

        set_address(&pinfo->dl_dst, g3_short_address_type, 4, ep_short_addr);
        set_address(&pinfo->dst, g3_short_address_type, 4, ep_short_addr);

        /* Provide address hints to higher layers that need it. */
        if (ieee_hints) {
            ieee_hints->dst16 = packet->dst16;
            ieee_hints->src_pan = packet->dst_pan;
        }

        /* Add the short 16 bit destination address item */
        proto_tree_add_uint(tree, hf_g3_dstaddr, tvb, offset, 2, packet->dst16);

        /* Fill in the destination column */
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%04X", packet->dst16);
        col_add_fstr(pinfo->cinfo, COL_DEF_DL_DST, "0x%04X", packet->dst16);

        offset += 2;
    } else if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64 nbo_addr;
        guint8 *ep_addr;

        /* Get the address. */
        packet->dst64 = tvb_get_letoh64(tvb, offset);

        /* Copy and convert the address to network byte order. */
        nbo_addr = pntoh64(&(packet->dst64));  // not sure about alignment issues -> be conservative
        ep_addr = (guint8 *) wmem_memdup(pinfo->pool, &nbo_addr, sizeof (nbo_addr));  // must not be on stack for use in set_address

        set_address(&pinfo->dl_dst, AT_EUI64, 8, ep_addr);
        set_address(&pinfo->dst, AT_EUI64, 8, ep_addr);

        /* Add the extended 64 bit destination address item */
        proto_tree_add_eui64_format_value(tree, hf_g3_dstaddr64, tvb, offset, 8, packet->dst64,
                                          "0x%" G_GINT64_MODIFIER "x", packet->dst64);

        /* Fill in the destination column */
        col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%" G_GINT64_MODIFIER "x", packet->dst64);
        col_add_fstr(pinfo->cinfo, COL_DEF_DL_DST, "0x%" G_GINT64_MODIFIER "x", packet->dst64);

        offset += 8;
    }

    return offset - original_offset;
}

/*!
 *  \fn static guint parse_src_addr(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
 *  \brief Parse the source address and PAN ID.
 *  \param tvb The current tvb.
 *  \param offset The offset of the header in the tvb.
 *  \param pinfo The Wireshark packet information.
 *  \param tree The display tree.
 *  \param packet The IEEE 802.15.4 packet information that is both used and filled.
 *  \return The length of this part.
 */
static guint
parse_src_addr(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree,
               ieee802154_packet *packet)
{
    guint original_offset = offset;

    if (packet->pan_id_compression == 0) {
        /* Add the source pan ID item */
        packet->src_pan = tvb_get_guint8(tvb, offset) | (tvb_get_guint8(tvb, offset + 1) << 8);
        proto_tree_add_uint(tree, hf_g3_srcpanid, tvb, offset, 2, packet->src_pan);
        offset += 2;
    } else {
        packet->src_pan = packet->dst_pan;
    }
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        guint8 *ep_short_addr = wmem_alloc_array(pinfo->pool, guint8, g3_short_len());
        packet->src16 = tvb_get_letohs(tvb, offset);

        ep_short_addr[0] = (guint8) ((packet->src_pan >> 8) & 0xff);
        ep_short_addr[1] = (guint8) ((packet->src_pan >> 0) & 0xff);
        ep_short_addr[2] = (guint8) ((packet->src16 >> 8) & 0xff);
        ep_short_addr[3] = (guint8) ((packet->src16 >> 0) & 0xff);

        set_address(&pinfo->dl_src, g3_short_address_type, g3_short_len(), ep_short_addr);
        set_address(&pinfo->src, g3_short_address_type, g3_short_len(), ep_short_addr);

        /* Provide address hints to higher layers that need it. */
        if (ieee_hints) {
            ieee_hints->src16 = packet->src16;
            ieee_hints->src_pan = packet->src_pan;
        }

        /* Add the short 16 bit source address item */
        proto_tree_add_uint(tree, hf_g3_srcaddr, tvb, offset, 2, packet->src16);

        /* Fill in the destination column */
        col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%04X", packet->src16);
        col_add_fstr(pinfo->cinfo, COL_DEF_DL_SRC, "0x%04X", packet->src16);

        offset += 2;
    } else if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        guint64 nbo_addr;
        guint8 *ep_addr;

        /* Get the address. */
        packet->src64 = tvb_get_letoh64(tvb, offset);

        /* Copy and convert the address to network byte order. */
        nbo_addr = pntoh64(&(packet->src64));  // not sure about alignment issues -> be conservative
        ep_addr = (guint8 *) wmem_memdup(pinfo->pool, &nbo_addr, sizeof (nbo_addr));  // must not be on stack for use in set_address

        set_address(&pinfo->dl_src, AT_EUI64, 8, ep_addr);
        set_address(&pinfo->src, AT_EUI64, 8, ep_addr);

        /* Add the extended 64 bit source address item */
        proto_tree_add_eui64_format_value(tree, hf_g3_srcaddr64, tvb, offset, 8, packet->src64,
                                          "0x%" G_GINT64_MODIFIER "x", packet->src64);

        /* Fill in the source column */
        col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%" G_GINT64_MODIFIER "x", packet->src64);
        col_add_fstr(pinfo->cinfo, COL_DEF_DL_SRC, "0x%" G_GINT64_MODIFIER "x", packet->src64);

        offset += 8;
    }

    return offset - original_offset;
}

/*!
 *  \fn static guint dissect_aux_sec_header(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree,
 *                                          ieee802154_packet *packet)
 *  \brief Parse the auxiliary security header, fill packet info, and build the tree
 *  \param tvb The current tvb.
 *  \param offset The offset of the header in the tvb.
 *  \param pinfo The Wireshark packet information.
 *  \param tree The display tree.
 *  \param packet The IEEE 802.15.4 packet information that is filled.
 *  \param[out] out_valid Is set to FALSE if illegal values are encountered (unchanged otherwise)
 *  \return The length of this header
 */
static guint
dissect_aux_sec_header(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree,
                       ieee802154_packet *packet, gboolean *out_valid)
{
    proto_item *g3_subitem;
    proto_tree *g3_auxsec_tree;

    static const guint8 AUX_KEY_ID_LEN[] = {0, 1, 5, 9};  // IEEE 802.15.4-2006, Table 96
    guint8 key_id_len;

    /* Parse security level and key ID mode */
    guint security_control = tvb_get_guint8(tvb, offset);
    packet->security_level = (ieee802154_security_level) (security_control & IEEE802154_AUX_SEC_LEVEL_MASK);
    packet->key_id_mode = (ieee802154_key_id_mode) ((security_control & IEEE802154_AUX_KEY_ID_MODE_MASK) >> IEEE802154_AUX_KEY_ID_MODE_SHIFT);
    packet->frame_counter = tvb_get_letohl(tvb, offset + 1);
    key_id_len = AUX_KEY_ID_LEN[packet->key_id_mode];
    packet->key_index = tvb_get_guint8(tvb, offset + 5);

    /* Add the auxiliary security item */
    g3_subitem = proto_tree_add_item(tree, hf_g3_auxiliary, tvb, offset, 5 + key_id_len, ENC_NA);
    g3_auxsec_tree = proto_item_add_subtree(g3_subitem, ett_g3_auxiliary);

    proto_tree_add_uint(g3_auxsec_tree, hf_g3_security_level, tvb, offset, 1,
                        security_control & IEEE802154_AUX_SEC_LEVEL_MASK);
    proto_tree_add_uint(g3_auxsec_tree, hf_g3_key_id_mode, tvb, offset, 1,
                        security_control & IEEE802154_AUX_KEY_ID_MODE_MASK);
    proto_tree_add_uint(g3_auxsec_tree, hf_g3_aux_sec_reserved, tvb, offset, 1,
                        security_control & IEEE802154_AUX_KEY_RESERVED_MASK);
    proto_tree_add_uint(g3_auxsec_tree, hf_g3_aux_framecounter, tvb, offset + 1, 4,
                        packet->frame_counter);
    proto_tree_add_uint(g3_auxsec_tree, hf_g3_aux_keyidentifier, tvb, offset + 5, key_id_len,
                        packet->key_index);
    if (packet->security_level != SECURITY_LEVEL_ENC_MIC_32) {
        expert_add_info_format(pinfo, g3_subitem, &ei_g3_illegal_key_security_level,
                               "Illegal key security level (only 0x05 (ENC-MIC-32) allowed)");
        *out_valid = FALSE;
    }
    if (packet->key_id_mode != KEY_ID_MODE_KEY_INDEX) {
        expert_add_info_format(pinfo, g3_subitem, &ei_g3_illegal_key_identifier_mode,
                               "Illegal key identifier mode (only 0x01 allowed)");
        *out_valid = FALSE;
    } else if (packet->key_index > 1) {
        expert_add_info_format(pinfo, g3_subitem, &ei_g3_illegal_key_index,
                               "Illegal key index (only 0x00-0x01 allowed)");
        *out_valid = FALSE;
    }
    return 5 + key_id_len;
}

/*!
 *  \fn static tvbuff_t* decrypt(packet_info *pinfo, proto_tree *tree, const ieee802154_packet *packet,
 *                               tvbuff_t *mhr_tvb, guint mhr_offset, guint16 mhr_len,
 *                               tvbuff_t *payload_tvb, guint payload_offset)
 *  \brief Decrypt a (possibly re-assembled) payload and verify the MIC.
 *  \details Since the auxiliary security header is only present in the first segment but reassembly occurs in the last
 *  and the MIC computation requires both, this function takes two tvbs as input and uses the payload_offset parameter
 *  (indicating both the start of the encrypted payload and the size of the AUXSEC header if present in the payload tvb)
 *  to use the correct information.
 *  \param tree The display tree.
 *  \param pinfo The Wireshark packet information.
 *  \param packet The IEEE 802.15.4 packet information that must contain the security information.
 *  \param mhr_tvb The tvb containing the MAC header.
 *  \param mhr_offset The offset of the frame control header in the tvb.
 *  \param mhr_len The length of the header for MIC computation (FC + potentially AUXSEC).
 *  \param payload_tvb The tvb containing: possibly the AUXSEC header | encrypted payload | MIC-32.
 *  \param payload_offset The offset of the payload (if > 0; the size of the AUXSEC header in the payload_tvb).
 *  \return The the new decrypted tvb or NULL if decryption failed (e.g., due to missing library) or MIC check failed.
 */
static tvbuff_t *
decrypt(packet_info *pinfo, proto_tree *tree, const ieee802154_packet *packet,
        tvbuff_t *mhr_tvb, guint mhr_offset, guint mhr_len,
        tvbuff_t *payload_tvb, guint payload_offset)
{
    proto_item *subitem;
    guint mic_len = (guint) IEEE802154_MIC_LENGTH(packet->security_level);
    guint data_len = tvb_reported_length_remaining(payload_tvb, payload_offset) - mic_len;
    guint8 *plaintext;
    guint8 iv[16];
    guint8 rx_mic[16];
    guint8 dec_mic[16];
    gboolean mic_ok = TRUE;
    gboolean enc_ok = TRUE;
    tvbuff_t *new_tvb = NULL;
    const guint8 *key = lookup_key(packet->src_pan, packet->key_index, pinfo->num);

    if (key != NULL) {
        create_enc_iv(packet, iv);
        tvb_memcpy(payload_tvb, rx_mic, payload_offset + data_len, mic_len);
        plaintext = (guint8 *) tvb_memdup(pinfo->pool, payload_tvb, payload_offset, data_len);

        /* Perform CTR-mode transformation. */
        enc_ok = ccm_ctr_encrypt(key, iv, rx_mic, plaintext, data_len);
        if (enc_ok) {
            /* Check MIC */
            guint8 *adata = (guint8 *) wmem_alloc(pinfo->pool, mhr_len + payload_offset);

            tvb_memcpy(mhr_tvb, adata, mhr_offset, mhr_len);
            if (payload_offset > 0) {
                tvb_memcpy(payload_tvb, adata + mhr_len, 0, payload_offset);
            }

            create_mic_iv(packet, iv, (guint16) data_len, (guint8) mic_len);
            mic_ok = ccm_cbc_mac(key, iv, adata, mhr_len + payload_offset, plaintext, data_len,
                                 dec_mic);
            mic_ok = mic_ok && memcmp(rx_mic, dec_mic, mic_len) == 0;

            if (mic_ok) {
                /* Create a tvbuff for the plaintext. */
                new_tvb = tvb_new_child_real_data(payload_tvb, plaintext, data_len, data_len);
                add_new_data_source(pinfo, new_tvb, "Decrypted G3 payload");
            } else {
                wmem_free(pinfo->pool, plaintext);
            }
        }
    }

    if (payload_offset > 0) {
        /* mark the auxiliary header in the reassembled message */
        proto_tree_add_item(tree, hf_g3_aux_sec_seg1, payload_tvb, 0, payload_offset, ENC_NA);
    }

    subitem = proto_tree_add_item(tree, hf_g3_mic32, payload_tvb, payload_offset + data_len,
                                  mic_len, ENC_BIG_ENDIAN);
    if (key == NULL) {
        expert_add_info_format(pinfo, subitem, &ei_g3_key_not_found,
                               "Key not found for PAN ID 0x%04x, GMK%d (keys can be added in G3 preferences)",
                               packet->src_pan, packet->key_index);
    } else if (enc_ok == FALSE) {
        expert_add_info_format(pinfo, subitem, &ei_g3_decryption_failed, "Decryption failed");
    } else if (mic_ok == FALSE) {
        expert_add_info_format(pinfo, subitem, &ei_g3_mic_check_failed, "MIC check failed");
    }

    return new_tvb;
}

static int
g3_short_addr_to_str(const address *addr, gchar *buf, int buf_len _U_)
{
    const guint8 *g3_short_addr = (const guint8 *) (addr->data);

    guint8 g3_eui64_addr[8];

    guint8 converted_bytes = 1; /* NULL character at the end of the string */

    DISSECTOR_ASSERT(buf_len >= EUI64_STR_LEN);

    /* Convert a short address to in interface identifier (RFC4944 Section 6 and RFC2464 Section 4) */
    g3_eui64_addr[0] = (guint8) (g3_short_addr[0] & 0xFD); /* Clear the U/L bit */
    g3_eui64_addr[1] = (guint8) g3_short_addr[1];
    g3_eui64_addr[2] = 0x00;
    g3_eui64_addr[3] = 0xff;
    g3_eui64_addr[4] = 0xfe;
    g3_eui64_addr[5] = 0x00;
    g3_eui64_addr[6] = (guint8) g3_short_addr[2];
    g3_eui64_addr[7] = (guint8) g3_short_addr[3];

    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", g3_eui64_addr[0],
               g3_eui64_addr[1], g3_eui64_addr[2], g3_eui64_addr[3], g3_eui64_addr[4],
               g3_eui64_addr[5], g3_eui64_addr[6], g3_eui64_addr[7]);

    converted_bytes = EUI64_STR_LEN;

    return converted_bytes;
}

static int
g3_short_str_len(const address *addr _U_)
{
    return EUI64_STR_LEN;
}

static int
g3_short_len(void)
{
    return 4;
}

/*!
 *  \fn static gboolean rand_p_equal(gconstpointer v1, gconstpointer v2)
 *  \brief Compare two rand_s values (used for hashing)
 *  \param v1 Pointer to a rand_s (uint8_t[16]).
 *  \param v2 Pointer to a rand_s (uint8_t[16]).
 *  \return TRUE if the two keys match.
 */
static gboolean
rand_s_equal(gconstpointer v1, gconstpointer v2)
{
    return memcmp(v1, v2, 16) == 0;
}

/*!
 *  \fn static guint rand_s_hash(gconstpointer v)
 *  \brief Create hash value for a rand_s (uint8_t[16])
 *  \param v Pointer to a rand_s (uint8_t[16]).
 *  \return a hash value corresponding to the key.
 */
static guint
rand_s_hash(gconstpointer v)
{
    const guint8 *p = (const guint8 *) v;

    // rand_s should be random -> the first 4 bytes should already be pretty unique
    return p[0] | ((guint32) p[1] << 8) | ((guint32) p[2] << 16) | ((guint32) p[3] << 24);
}

/*!
 *  \fn static void g3data_init(void)
 *  \brief Init callback
 */
static void
g3data_init(void)
{
    eap_psk_exchange_map = wmem_map_new(wmem_file_scope(), rand_s_hash, rand_s_equal);
}

/*!
 *  \fn static gboolean decrypt_eap_psk_ext(const guint8* psk, const guint8* rand_p, guint32 nonce, guint8* data, size_t data_size)
 *  \brief Decrypt EAP-PSK extension
 *  \param psk Pointer to the PSK (uint8_t[16]).
 *  \param rand_p Pointer to the rand_p (uint8_t[16]).
 *  \param nonce Nonce
 *  \param data Encrypted content (is decrypted in-place)
 *  \return TRUE on success.
 */
static gboolean
decrypt_eap_psk_ext(const guint8 *psk, const guint8 *rand_p, guint32 nonce, guint8 *data,
                    size_t data_size)
{
    // Tested with these values from G3-PLC - WS3 - 6LoWPAN layer - Interoperability Test Suite v0.12.1
    // Ext. Mac: 1122334455667788
    // PSK: AB 10 34 11 45 11 1B C3 C1 2D E8 FF 11 14 22 04
    // GMK: AF 4D 6D CC F1 4D E7 C1 C4 23 5E 6F EF 6C 15 1F
    // KDK: 97 40 52 63 D1 4C D0 99 0C C6 52 B9 77 45 F2 DB
    // TEK: 45 CA 5C A2 60 B9 DD 87 6A 42 58 74 E6 B5 7F 05
    // NMC: 19 B4 03 FB 75 E3 67 1C 1F F1 DE AA 2B EC E4 CB
    // Dec: A0 02 1D 02 00 ED 27 11 00 AF 4D 6D CC F1 4D E7 C1 C4 23 5E 6F EF 6C 15 1F 2B 01 00

    guint8 kdk[16] = { 0 };
    guint8 tek[16];
    guint8 nonce_buf[16 + 16] = { 0 };
    guint8 nonce_mac[16];
    size_t nonce_mac_size = sizeof(nonce_mac);
    gcry_cipher_hd_t cipher_hd = NULL;
    gcry_mac_hd_t mac_hd = NULL;

    nonce_buf[16 + 12 + 0] = nonce >> 24;
    nonce_buf[16 + 12 + 1] = nonce >> 16;
    nonce_buf[16 + 12 + 2] = nonce >> 8;
    nonce_buf[16 + 12 + 3] = nonce >> 0;

    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0))
        goto fail;

    /* Set the PSK as key. */
    if (gcry_cipher_setkey(cipher_hd, psk, 16))
        goto fail;

    /* Encrypt 0*16. */
    if (gcry_cipher_encrypt(cipher_hd, kdk, 16, NULL, 0))
        goto fail;
    kdk[15] ^= 2;
    if (gcry_cipher_encrypt(cipher_hd, kdk, 16, NULL, 0))
        goto fail;

    /* Set the KDK as key. */
    if (gcry_cipher_setkey(cipher_hd, kdk, 16))
        goto fail;
    memcpy(tek, rand_p, 16);
    if (gcry_cipher_encrypt(cipher_hd, tek, 16, NULL, 0))
        goto fail;
    tek[15] ^= 1;
    if (gcry_cipher_encrypt(cipher_hd, tek, 16, NULL, 0))
        goto fail;

    gcry_cipher_close(cipher_hd);
    cipher_hd = NULL;


    if (gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL))
        goto fail;
    if (gcry_mac_setkey(mac_hd, tek, 16))
        goto fail;
    if (gcry_mac_write(mac_hd, nonce_buf, sizeof (nonce_buf)))
        goto fail;
    if (gcry_mac_read(mac_hd, nonce_mac, &nonce_mac_size))
        goto fail;
    gcry_mac_close(mac_hd);
    mac_hd = NULL;

    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0))
        goto fail;
    if (gcry_cipher_setkey(cipher_hd, tek, 16))
        goto fail;
    if (gcry_cipher_setctr(cipher_hd, nonce_mac, sizeof (nonce_mac)))
        goto fail;
    if (gcry_cipher_decrypt(cipher_hd, data, data_size, NULL, 0))
        goto fail;
    gcry_cipher_close(cipher_hd);
    cipher_hd = NULL;

    return TRUE;

fail:
    if (cipher_hd)
        gcry_cipher_close(cipher_hd);
    if (mac_hd)
        gcry_mac_close(mac_hd);
    return FALSE;
}

/*!
 *  \fn static gint dissect_g3data_lbp_cfg(tvbuff_t* tvb, gint offset, packet_info* pinfo, proto_tree* tree)
 *  \brief Dissect a LBP configuration parameter
 *  \param tvb The current tvb.
 *  \param offset The offset of the header in the tvb.
 *  \param tree The display tree.
 *  \return The new offset after parsing the header.
 */
static gint
dissect_g3data_lbp_cfg(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    guint8 attr_id = (tvb_get_guint8(tvb, offset + 0) & 0xfc) >> 2;
    guint8 len = tvb_get_guint8(tvb, offset + 1);

    proto_item *subitem = proto_tree_add_uint_format(tree, hf_g3data_lbp_cfg_attr_id, tvb, offset,
                                                     len + 2,
                                                     attr_id, "LBP Configuration Parameter: %s", val_to_str_const(
                                                         attr_id, g3data_lbp_cfg_attr_id_vals,
                                                         "UNKNOWN"));
    proto_tree *subtree = proto_item_add_subtree(subitem, ett_g3data_lbp_cfg_param);

    proto_tree_add_item(subtree, hf_g3data_lbp_cfg_attr_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_g3data_lbp_cfg_M, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_g3data_lbp_cfg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_g3data_lbp_cfg_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

    offset += 2;

    /* g3data.lbp.cfg.value */
    switch (attr_id) {
        case 7:     /* Short_Addr */
            if (len == 2) {
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_Short_Addr_short_addr, tvb, offset,
                                2, ENC_BIG_ENDIAN);
            } else {
                expert_add_info_format(pinfo, subitem, &ei_g3data_illegal_value,
                                       "Illegal value: 'len' != 2");
            }
            break;
        case 9:     /* GMK */
            if (len == 17) {
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_GMK_key_id, tvb, offset, 1,
                                    ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_GMK_gmk, tvb, offset + 1, 16,
                                    ENC_NA);
            } else {
                expert_add_info_format(pinfo, subitem, &ei_g3data_illegal_value,
                                       "Illegal value: 'len' != 17");
            }
            break;
        case 10:     /* GMK_activation */
            if (len == 1) {
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_GMK_activation_key_id, tvb, offset,
                                    1, ENC_BIG_ENDIAN);
            } else {
                expert_add_info_format(pinfo, subitem, &ei_g3data_illegal_value,
                                       "Illegal value: 'len' != 1");
            }
            break;
        case 11:     /* GMK_removal */
            if (len == 1) {
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_GMK_removal_key_id, tvb, offset, 1,
                                    ENC_BIG_ENDIAN);
            } else {
                expert_add_info_format(pinfo, subitem, &ei_g3data_illegal_value,
                                       "Illegal value: 'len' != 1");
            }
            break;
        case 12:     /* parameter_result */
            if (len == 2) {
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_parameter_result_result, tvb,
                                    offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_parameter_result_attr_id, tvb,
                                    offset + 1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_parameter_result_M, tvb,
                                    offset + 1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_g3data_lbp_cfg_value_parameter_result_type, tvb,
                                    offset + 1, 1, ENC_BIG_ENDIAN);
            } else {
                expert_add_info_format(pinfo, subitem, &ei_g3data_illegal_value,
                                       "Illegal value: 'len' != 2");
            }
            break;
        default:
            expert_add_info_format(pinfo, subitem, &ei_g3data_illegal_value,
                                   "Illegal value (Unknown g3data.lbp.cfg.attr_id)");
    }

    return offset + len;
}

static guint16
dissect_g3_escframe(tvbuff_t    *tvb,
                    packet_info *pinfo,
                    guint16      offset,
                    proto_tree  *g3data_tree)
{
    guint8     value                           = 0;
    guint      length                          = 0;
    guint16    value16                         = 0;
    guint8     lbp_type                        = 0;
    guint8     l_bit                           = 0;
    guint8     eap_type                        = 0;
    guint8     message_code                    = 0;
    guint16    value_length                    = 0;
    gboolean   is_rreq                         = FALSE;

    proto_item*g3data_subitem                  = NULL;
    proto_item*g3data_hopinfoitem              = NULL;
    proto_tree*g3data_payload_subtree          = NULL;
    proto_tree*g3data_payload_subsubtree       = NULL;
    proto_tree*g3data_payload_subsubsubtree    = NULL;
    proto_tree*g3data_payload_subsubsubsubtree = NULL;
    proto_tree*g3data_hopinfotree              = NULL;

    /* Skip header item */
    offset += 1;

    /* Add the command ID item */
    value = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(g3data_tree, hf_g3data_command_id, tvb, offset, 1, ENC_NA);

    offset += 1;

    if (value == 0x01) { //Mesh routing message
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Mesh routing message");
    } else if (value == 0x02) { //LoWPAN Bootstrapping Protocol message
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "LBP message");
    } else if (value == 0x03) { //Contention Free Access Command
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Contention Free Access Command");
    }

    length = tvb_reported_length(tvb) - offset;

    if (value == 0x01) { //Mesh routing message
        /* Add the command payload item */
        g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_command_payload, tvb,
                                             offset, length, ENC_NA);
        g3data_payload_subtree = proto_item_add_subtree(g3data_subitem, ett_g3data_command_payload);

        value = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(g3data_payload_subtree, hf_g3data_messagetype, tvb, offset, 1, ENC_NA);

        offset += 1;

        if ((value == 0) || (value == 1)) { //rreq or rrep
            if (value == 0) {
                is_rreq = TRUE;
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Route Request");
            } else {
                is_rreq = FALSE;
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Route Reply");
            }

            /* Add the short 16 bit destination address item */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rrep_destination,
                                             tvb, offset, 2, value16, "0x%04X", value16);
            offset += 2;

            /* Add the short 16 bit originator address item */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rrep_originator, tvb,
                                             offset, 2, value16, "0x%04X", value16);
            offset += 2;

            /* Add the 16 bit sequence number */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rrep_sequence, tvb,
                                             offset, 2, value16, "0x%04X", value16);
            offset += 2;

            /* Get 4 bits flags and 4 bits metric type */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_repair, tvb, offset, 1, ENC_NA);
            if (is_rreq == TRUE) {
                /* Only add Unicast RREQ to route request packets */
                proto_tree_add_item(g3data_payload_subtree, hf_g3data_rreq_unicast, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(g3data_payload_subtree, hf_g3data_rreq_reserved, tvb, offset, 1, ENC_NA);
            } else {
                /* Route reply packets have a reserved bit */
                proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_bit_reserved, tvb, offset, 1, ENC_NA);
            }
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_otype_low, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Add the 16 bit route cost */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rrep_rc, tvb, offset,
                                             2, value16, "0x%04X", value16);
            offset += 2;

            /* Get hop limit and count */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_hoplimit, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_preqid, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Get weak link count and reserved */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_wlinks, tvb, offset, 1, ENC_NA);
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_rrep_reserved, tvb, offset, 1, (value & 0x0f));
            offset += 1;
        } else if (value == 2) { //rerr
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Route Error");

            /* Add the short 16 bit destination address */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rrep_destination,
                                             tvb, offset, 2, value16, "0x%04X", value16);
            offset += 2;

            /* Add the short 16 bit originator address */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rrep_originator, tvb,
                                             offset, 2, value16, "0x%04X", value16);
            offset += 2;

            /* Get 8 bit error code */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rerr_errorcode, tvb,
                                             offset, 1, value, "0x%02X", value);
            offset += 1;

            /* Add the short 16 bit unreachable address */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_rerr_address, tvb,
                                             offset, 2, value16, "0x%04X", value16);
            offset += 2;

            /* Get hop limit and reserved */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_hoplimit, tvb, offset, 1, ENC_NA);
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_rerr_reserved, tvb, offset, 1, (value & 0x0f));
            offset += 1;
        } else if (value == 252) { //preq
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Path Request");

            /* Add the short 16 bit destination address */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_preq_destination,
                                             tvb, offset, 2, value16, "0x%04X", value16);
            offset += 2;
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_preq_originator, tvb,
                                             offset, 2, value16, "0x%04X", value16);
            offset += 2;
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_preq_pmt, tvb, offset, 1,
                                ((value & 0xf0) >> 4));
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_rrep_reserved, tvb, offset, 4, 0);
            offset += 4;

            /* Browse through individual elements */
            while (offset < tvb_reported_length(tvb)) {
                g3data_hopinfoitem = proto_tree_add_item(g3data_payload_subtree, hf_g3data_hopinfo,
                                                         tvb, offset, tvb_reported_length(
                                                             tvb) - offset, ENC_NA);
                g3data_hopinfotree = proto_item_add_subtree(g3data_hopinfoitem, ett_g3data_hopinfo);

                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_fpa, tvb, offset, 2, ENC_NA);
                offset += 2;
                value = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_mns, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_phase_diff, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_mrx, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_mtx, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_reserved, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_fplc, tvb, offset, 1, ENC_NA);
                offset++;
            }
        } else if (value == 253) { //prep
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Path Reply");

            /* Add the short 16 bit destination address */
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_prep_destination,
                                             tvb, offset, 2, value16, "0x%04X", value16);
            offset += 2;
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree,
                                             hf_g3data_prep_expected_originator, tvb, offset, 2,
                                             value16, "0x%04X", value16);
            offset += 2;
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_preq_pmt, tvb, offset, 1,
                                ((value & 0xF0) >> 4));
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_rrep_reserved, tvb, offset, 2, 0);
            offset += 2;
            value16 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format_value(g3data_payload_subtree, hf_g3data_prep_originator, tvb,
                                             offset, 2, value16, "0x%04X", value16);
            offset += 2;

            /* Browse through individual elements */
            while (offset < tvb_reported_length(tvb)) {
                g3data_hopinfoitem = proto_tree_add_item(g3data_payload_subtree, hf_g3data_hopinfo,
                                                         tvb, offset, 4, ENC_NA);
                g3data_hopinfotree = proto_item_add_subtree(g3data_hopinfoitem, ett_g3data_hopinfo);

                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_fpa, tvb, offset, 2, ENC_NA);
                offset += 2;
                value = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_mns, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_phase_diff, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_mrx, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_mtx, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_reserved, tvb, offset, 1, ENC_NA);
                offset++;
                proto_tree_add_item(g3data_hopinfotree, hf_g3data_preq_hop_fplc, tvb, offset, 1, ENC_NA);
                offset++;
            }
        } else if (value == 254) { //rlcreq
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Reverse Link Cost Request");

            /* Add destination and originator */
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_preq_destination, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_preq_originator, tvb, offset, 2, ENC_NA);
            offset += 2;

            /* Get metric type and reserved field */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_otype_high, tvb, offset, 1, ENC_NA);
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_rrep_reserved, tvb, offset, 1, (value & 0x0f));
            offset += 1;
        } else if (value == 255) { //rlcrep
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Reverse Link Cost Reply");

            /* Add destination and originator */
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_preq_destination, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_preq_originator, tvb, offset, 2, ENC_NA);
            offset += 2;

            /* Get metric type and reserved field */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(g3data_payload_subtree, hf_g3data_rrep_otype_high, tvb, offset, 1, ENC_NA);
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_rrep_reserved, tvb, offset, 1, (value & 0x0f));
            offset += 1;

            /* Add link cost field */
            value   = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(g3data_payload_subtree, hf_g3data_rlc_linkcost, tvb, offset, 1, value);
            offset += 1;
        }
    } else if (value == 0x02) { //LoWPAN Bootstrapping Protocol message
        /* Add the command payload item */
        g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_command_payload, tvb,
                                             offset, length, ENC_NA);
        g3data_payload_subtree = proto_item_add_subtree(g3data_subitem, ett_g3data_command_payload);

        /* Add LBP header item and tree */
        g3data_subitem = proto_tree_add_item(g3data_payload_subtree, hf_g3data_lbp_header, tvb,
                                             offset, 10, ENC_NA);
        g3data_payload_subsubtree = proto_item_add_subtree(g3data_subitem, ett_g3data_lbp_header);

        value = tvb_get_guint8(tvb, offset);
        lbp_type = (value >> 7);

        proto_tree_add_item(g3data_payload_subsubtree, hf_g3data_lbp_type, tvb, offset, 2,
                            ENC_BIG_ENDIAN);
        if (lbp_type == 0) {
            proto_tree_add_item(g3data_payload_subsubtree, hf_g3data_lbp_codefrom, tvb, offset, 2,
                                ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(g3data_payload_subsubtree, hf_g3data_lbp_codeto, tvb, offset, 2,
                                ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(g3data_payload_subsubtree, hf_g3data_media_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(g3data_payload_subsubtree, hf_g3data_lbp_transaction, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Add the extended 64 bit destination address item */
        proto_tree_add_item(g3data_payload_subsubtree, hf_g3data_lbp_address, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        /* Add LBP data item and tree */
        length = tvb_reported_length(tvb) - offset;

        if (length != 0) {
            g3data_subitem = proto_tree_add_item(g3data_payload_subtree, hf_g3data_lbp_data, tvb,
                                                 offset, length, ENC_NA);
        }

        g3data_payload_subsubtree = proto_item_add_subtree(g3data_subitem, ett_g3data_lbp_data);

        if (length != 0) {
            value = tvb_get_guint8(tvb, offset);
            l_bit = (value & 0x01);

            if (l_bit == 1) { //Configuration parameters
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Configuration parameters");

                do
                {
                    offset = dissect_g3data_lbp_cfg(tvb, offset, pinfo, g3data_payload_subsubtree);
                }
                while (tvb_reported_length(tvb) > offset);
            } else { //EAP Messages
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "EAP");

                /* Add EAP header item and tree */
                g3data_subitem = proto_tree_add_item(g3data_payload_subsubtree,
                                                     hf_g3data_eap_header, tvb, offset, 4, ENC_NA);
                g3data_payload_subsubsubtree = proto_item_add_subtree(g3data_subitem,
                                                                      ett_g3data_eap_header);

                proto_tree_add_uint(g3data_payload_subsubsubtree, hf_g3data_lbp_codetype, tvb,
                                    offset, 1, (value >> 2));
                offset += 1;

                proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_lbp_identifier, tvb,
                                    offset, 1, ENC_NA);
                offset += 1;

                value_length =
                    ((tvb_get_guint8(tvb, offset) << 8) | tvb_get_guint8(tvb, offset + 1)) - 4;
                proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_lbp_len, tvb, offset, 2,
                                    ENC_NA);
                offset += 2;

                if (value_length != 0) {
                    /* Add EAP data item and tree */
                    g3data_subitem = proto_tree_add_item(g3data_payload_subsubtree,
                                                         hf_g3data_eap_data, tvb, offset,
                                                         value_length, ENC_NA);
                    g3data_payload_subsubsubtree = proto_item_add_subtree(g3data_subitem,
                                                                          ett_g3data_eap_data);

                    eap_type = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_type, tvb,
                                        offset, 1, ENC_NA);
                    offset += 1;

                    if (eap_type == 47) { //eap-psk
                        eap_psk_exchange_t *eap_psk_exchange = NULL;
                        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "PSK");
                        value = tvb_get_guint8(tvb, offset);
                        message_code = (value >> 6);
                        proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_tflag, tvb,
                                            offset, 1, ENC_NA);
                        proto_tree_add_item(g3data_payload_subsubsubtree,
                                            hf_g3data_eap_reservedflag, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        if (extract_gmks_from_eap && (message_code == 1 || message_code == 2)) {
                            guint8 rand_s[16];
                            tvb_memcpy(tvb, rand_s, offset, 16);
                            eap_psk_exchange = (eap_psk_exchange_t *) wmem_map_lookup(
                                eap_psk_exchange_map, rand_s);
                            if (eap_psk_exchange == NULL) {
                                eap_psk_exchange = wmem_new(wmem_file_scope(), eap_psk_exchange_t);
                                eap_psk_exchange->msg2_processed = FALSE;
                                memcpy(eap_psk_exchange->rand_s, rand_s, 16);
                                wmem_map_insert(eap_psk_exchange_map, eap_psk_exchange->rand_s,
                                                eap_psk_exchange);
                            }
                        }

                        proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_rands, tvb,
                                            offset, 16, ENC_NA);
                        offset += 16;

                        if (message_code == 0) { //Message 1
                            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Message 1");
                            value_length -= 18;
                            proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_ids,
                                                tvb, offset, value_length, ENC_NA);
                        } else if (message_code == 1) { //Message 2
                            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Message 2");
                            if (extract_gmks_from_eap && !eap_psk_exchange->msg2_processed) {
                                tvb_memcpy(tvb, eap_psk_exchange->rand_p, offset, 16);
                                tvb_memcpy(tvb, eap_psk_exchange->id_p, offset + 16 + 16, 8);
                                eap_psk_exchange->msg2_processed = TRUE;
                            }
                            proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_randp,
                                                tvb, offset, 16, ENC_NA);
                            offset += 16;

                            proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_macp,
                                                tvb, offset, 16, ENC_NA);
                            offset += 16;

                            value_length -= 50;
                            proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_idp,
                                                tvb, offset, value_length, ENC_NA);
                        } else if (message_code == 2) { //Message 3
                            guint32 nonce;
                            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Message 3");
                            proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_eap_macs,
                                                tvb, offset, 16, ENC_NA);
                            offset += 16;

                            value_length -= 34;
                            g3data_subitem = proto_tree_add_item(g3data_payload_subsubsubtree,
                                                                 hf_g3data_eap_pchannel, tvb,
                                                                 offset, value_length, ENC_NA);
                            g3data_payload_subsubsubsubtree = proto_item_add_subtree(g3data_subitem,
                                                                                     ett_g3data_eap_pchannel);

                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_nonce, tvb, offset, 4, ENC_NA);
                            nonce = tvb_get_ntohl(tvb, offset);
                            offset += 4;

                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_tag, tvb, offset, 16, ENC_NA);
                            offset += 16;

                            value = tvb_get_guint8(tvb, offset);
                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_r, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_e, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_reserved, tvb, offset, 1,
                                                ENC_NA);
                            offset += 1;

                            value_length -= 21;

                            if (value_length != 0) {
                                proto_item *pchext = proto_tree_add_item(
                                    g3data_payload_subsubsubsubtree, hf_g3data_pchannel_extension,
                                    tvb, offset, value_length, ENC_NA);
                                if (extract_gmks_from_eap && eap_psk_exchange->msg2_processed) {
                                    guint ext_size = value_length + 1;
                                    guint8 *ext = (guint8 *) tvb_memdup(
                                        pinfo->pool, tvb, offset - 1, ext_size);
                                    const guint8 *psk = lookup_psk(eap_psk_exchange->id_p);
                                    if (psk &&
                                        decrypt_eap_psk_ext(psk, eap_psk_exchange->rand_p, nonce,
                                                            ext,
                                                            ext_size)
                                        && ext[0] == R_EAP_PSK_DONE_SUCCESS_WITH_EXT &&
                                        ext[1] == R_EAP_PSK_EXT_TYPE_G3) {
                                        // no caching (1) to display decrypted values and (2) to handle interop testsuite which reuses RAND_S
                                        tvbuff_t *tvb_ext = tvb_new_child_real_data(tvb, ext,
                                                                                    ext_size,
                                                                                    ext_size);

                                        // parse 9.4.4.2.1.3 Configuration parameters
                                        guint ext_offset = 2;
                                        while (ext_offset + 1 < ext_size &&
                                               ext_offset + ext[ext_offset + 1] <= ext_size) {
                                            if (ext[ext_offset] == 0x27) {
                                                add_extracted_gmk(pinfo->num, ext[ext_offset + 2],
                                                                  ext + ext_offset + 3);
                                                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                                                                   "GMK Extracted");
                                            }
                                            ext_offset += 2 + ext[ext_offset + 1];
                                        }
                                        ext_offset = 2;
                                        add_new_data_source(pinfo, tvb_ext,
                                                            "Decrypted EAP-PSK Extension");
                                        while (ext_offset < ext_size) {
                                            ext_offset = dissect_g3data_lbp_cfg(tvb_ext, ext_offset,
                                                                                pinfo,
                                                                                g3data_payload_subsubsubsubtree);
                                        }
                                    } else if (psk == NULL) {
                                        expert_add_info_format(pinfo, pchext,
                                                               &ei_g3data_psk_not_found,
                                                               "PSK not found for %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x (can be added in G3 preferences)",
                                                               eap_psk_exchange->id_p[0],
                                                               eap_psk_exchange->id_p[1],
                                                               eap_psk_exchange->id_p[2],
                                                               eap_psk_exchange->id_p[3],
                                                               eap_psk_exchange->id_p[4],
                                                               eap_psk_exchange->id_p[5],
                                                               eap_psk_exchange->id_p[6],
                                                               eap_psk_exchange->id_p[7]
                                                               );
                                    }
                                }
                            }
                        } else if (message_code == 3) { //Message 4
                            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Message 4");
                            value_length -= 18;
                            g3data_subitem = proto_tree_add_item(g3data_payload_subsubsubtree,
                                                                 hf_g3data_eap_pchannel, tvb,
                                                                 offset, value_length, ENC_NA);
                            g3data_payload_subsubsubsubtree = proto_item_add_subtree(g3data_subitem,
                                                                                     ett_g3data_eap_pchannel);

                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_nonce, tvb, offset, 4, ENC_NA);
                            offset += 4;

                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_tag, tvb, offset, 16, ENC_NA);
                            offset += 16;

                            value = tvb_get_guint8(tvb, offset);
                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_r, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_e, tvb, offset, 1, ENC_NA);
                            proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                hf_g3data_pchannel_reserved, tvb, offset, 1,
                                                ENC_NA);
                            offset += 1;

                            value_length -= 21;

                            if (value_length != 0) {
                                proto_tree_add_item(g3data_payload_subsubsubsubtree,
                                                    hf_g3data_pchannel_extension, tvb, offset,
                                                    value_length, ENC_NA);
                            }
                        }

                        offset += value_length;
                    } else {
                        value_length -= 1;
                        proto_tree_add_item(g3data_payload_subsubsubtree, hf_g3data_nak_data, tvb,
                                            offset, value_length, ENC_NA);
                    }
                }
            }
        }
    } else if (value == 0x03) { //Contention Free Access Command
        /* Add the command payload item */
        g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_command_payload, tvb,
                                             offset, length, ENC_NA);
        g3data_payload_subtree = proto_item_add_subtree(g3data_subitem, ett_g3data_command_payload);

        proto_tree_add_item(g3data_payload_subtree, hf_g3data_cfavalue, tvb, offset, length, ENC_NA);

        offset += length;
    } else {
        if (length != 0) {
            /* Add the command payload item */
            g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_command_payload,
                                                 tvb, offset, length, ENC_NA);
            g3data_payload_subtree = proto_item_add_subtree(g3data_subitem,
                                                            ett_g3data_command_payload);

            proto_tree_add_item(g3data_payload_subtree, hf_g3data_unidentified_bytes, tvb, offset,
                                length, ENC_NA);

            offset += length;
        }
    }

    return offset;
}

static guint16
dissect_g3_lowpan_bc0frame(tvbuff_t    *tvb,
                           packet_info *pinfo,
                           guint16      offset,
                           proto_tree  *g3data_tree)
{
    proto_item *g3data_subitem = NULL;
    proto_tree *g3data_payload_tree = NULL;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Broadcast header");

    /* Add header item */
    g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_lowpan_bc0htype, tvb, offset, 2,
                                         ENC_NA);
    g3data_payload_tree = proto_item_add_subtree(g3data_subitem, ett_g3data_lowpan_bc0htype);

    offset += 1;

    /* Add datagram tag item */
    proto_tree_add_item(g3data_payload_tree, hf_g3data_seqnr, tvb, offset, 1, ENC_NA);

    offset += 1;

    return offset;
}

static guint16
dissect_g3_meshframe(tvbuff_t    *tvb,
                     packet_info *pinfo,
                     guint16      offset,
                     proto_tree  *g3data_tree)
{
    guint16 offset_value = 0;
    guint8 value = 0;
    guint8 value1 = 0;
    guint8 value2 = 0;
    guint8 value3 = 0;
    guint8 value4 = 0;
    guint8 value5 = 0;
    guint8 value6 = 0;
    guint8 value7 = 0;
    guint8 value8 = 0;
    guint16 value16 = 0;
    guint64 value64 = 0;

    proto_item *g3data_subitem = NULL;
    proto_tree *g3data_payload_tree = NULL;

    /* Store the start offset value */
    offset_value = offset;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Mesh header");

    /* Add header item */
    g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_meshhtype, tvb, offset, 5, ENC_NA);
    g3data_payload_tree = proto_item_add_subtree(g3data_subitem, ett_g3data_meshhtype);

    /* Parse the header fields and add values */
    value = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(g3data_payload_tree, hf_g3data_vforigin, tvb, offset, 1,
                        ((value >> 5) & 0x01));
    proto_tree_add_uint(g3data_payload_tree, hf_g3data_vfdest, tvb, offset, 1,
                        ((value >> 4) & 0x01));
    offset += 1;

    if ((value & 0x0f) != 0x0f) {
        proto_tree_add_uint(g3data_payload_tree, hf_g3data_hops, tvb, offset, 1, (value & 0x0f));
    } else {
        value = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(g3data_payload_tree, hf_g3data_hops, tvb, offset, 1, value);
        offset += 1;
    }

    if (((value >> 5) & 0x01) == 1) {
        /* Add the short 16 bit originator address item */
        value16 = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint_format_value(g3data_payload_tree, hf_g3data_originator, tvb, offset, 2,
                                         value16, "0x%04X", value16);

        offset += 2;
    } else {
        /* Add the extended 64 bit originator address item */
        value1 = tvb_get_guint8(tvb, offset);
        value2 = tvb_get_guint8(tvb, offset + 1);
        value3 = tvb_get_guint8(tvb, offset + 2);
        value4 = tvb_get_guint8(tvb, offset + 3);
        value5 = tvb_get_guint8(tvb, offset + 4);
        value6 = tvb_get_guint8(tvb, offset + 5);
        value7 = tvb_get_guint8(tvb, offset + 6);
        value8 = tvb_get_guint8(tvb, offset + 7);
        proto_tree_add_eui64_format_value(g3data_payload_tree, hf_g3data_originator64, tvb, offset,
                                          8, value64,
                                          "0x%02X%02X%02X%02X%02X%02X%02X%02X", value1, value2,
                                          value3, value4, value5, value6, value7, value8);

        offset += 8;
    }

    if (((value >> 4) & 0x01) == 1) {
        /* Add the short 16 bit destination address item */
        value16 = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint_format_value(g3data_payload_tree, hf_g3data_destination, tvb, offset, 2,
                                         value16, "0x%04X", value16);

        offset += 2;
    } else {
        /* Add the extended 64 bit destination address item */
        value1 = tvb_get_guint8(tvb, offset);
        value2 = tvb_get_guint8(tvb, offset + 1);
        value3 = tvb_get_guint8(tvb, offset + 2);
        value4 = tvb_get_guint8(tvb, offset + 3);
        value5 = tvb_get_guint8(tvb, offset + 4);
        value6 = tvb_get_guint8(tvb, offset + 5);
        value7 = tvb_get_guint8(tvb, offset + 6);
        value8 = tvb_get_guint8(tvb, offset + 7);
        proto_tree_add_eui64_format_value(g3data_payload_tree, hf_g3data_destination64, tvb, offset,
                                          8, value64,
                                          "0x%02X%02X%02X%02X%02X%02X%02X%02X", value1, value2,
                                          value3, value4, value5, value6, value7, value8);

        offset += 8;
    }

    /* Change the highlight length of the header item to the real length */
    proto_item_set_len(g3data_subitem, (offset - offset_value));

    return offset;
}

static guint16
dissect_g3_frag1frame(tvbuff_t    *tvb,
                      packet_info *pinfo,
                      guint16      offset,
                      proto_tree  *g3data_tree)
{
    guint8 value = 0;
    guint8 value2 = 0;

    proto_item *g3data_subitem = NULL;
    proto_tree *g3data_payload_tree = NULL;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Frag1 header");

    /* Add header item */
    g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_frag1htype, tvb, offset, 4, ENC_NA);
    g3data_payload_tree = proto_item_add_subtree(g3data_subitem, ett_g3data_frag1htype);

    /* Parse the header fields and add values */
    value = tvb_get_guint8(tvb, offset);
    value2 = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_uint(g3data_payload_tree, hf_g3data_datagram_size, tvb, offset, 2,
                        (((value & 0x07) << 8) | value2));

    offset += 2;

    /* Add datagram tag item */
    proto_tree_add_item(g3data_payload_tree, hf_g3data_datagram_tag, tvb, offset, 2, ENC_NA);

    offset += 2;

    return offset;
}

static guint16
dissect_g3_fragnframe(tvbuff_t    *tvb,
                      packet_info *pinfo,
                      guint16      offset,
                      proto_tree  *g3data_tree)
{
    guint16 offset_value = 0;
    guint8 value = 0;
    guint8 value2 = 0;
    guint16 length = 0;

    proto_item *g3data_subitem = NULL;
    proto_tree *g3data_payload_tree = NULL;

    /* Store the start offset value */
    offset_value = offset;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Fragn header");

    /* Add header item */
    g3data_subitem = proto_tree_add_item(g3data_tree, hf_g3data_fragnhtype, tvb, offset, 5, ENC_NA);
    g3data_payload_tree = proto_item_add_subtree(g3data_subitem, ett_g3data_fragnhtype);

    /* Parse the header fields and add values */
    value = tvb_get_guint8(tvb, offset);
    value2 = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_uint(g3data_payload_tree, hf_g3data_datagram_size, tvb, offset, 2,
                        (((value & 0x07) << 8) | value2));

    offset += 2;

    /* Add datagram tag item */
    proto_tree_add_item(g3data_payload_tree, hf_g3data_datagram_tag, tvb, offset, 2, ENC_NA);

    offset += 2;

    /* Add datagram offset item */
    proto_tree_add_item(g3data_payload_tree, hf_g3data_datagram_offset, tvb, offset, 1, ENC_NA);

    offset += 1;

    length = tvb_reported_length(tvb) - offset;
    proto_tree_add_item(g3data_payload_tree, hf_g3data_databyte, tvb, offset, length, ENC_NA);
    offset += length;

    /* Change the highlight length of the header item to the real length */
    proto_item_set_len(g3data_subitem, (offset - offset_value));

    return offset;
}

static int
dissect_g3data(tvbuff_t    *tvb,
               packet_info *pinfo,
               proto_tree  *tree,
               void        *data)
{
    guint16 offset = 0;
    guint8 dispatch = 0;
    guint length = tvb_reported_length(tvb);

    proto_item *g3data_item = NULL;
    proto_tree *g3data_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "G3 Adaptation Layer");

    dispatch = tvb_get_guint8(tvb, offset);

    /* 2 passes: pass 1 - skip known headers */
    if ((dispatch & 0xc0) == 0x80) { // Mesh Header
        offset = dissect_g3_meshframe(tvb, pinfo, offset, NULL);
        if ((length - offset) != 0) {
            dispatch = tvb_get_guint8(tvb, offset);
        }
    }
    if (dispatch == 0x50) { // LOWPAN_BC0 broadcast
        offset = dissect_g3_lowpan_bc0frame(tvb, pinfo, offset, NULL);
        if ((length - offset) != 0) {
            dispatch = tvb_get_guint8(tvb, offset);
        }
    }
    if ((dispatch & 0xf8) == 0xc0) { // Fragmentation Header (first)
        offset = dissect_g3_frag1frame(tvb, pinfo, offset, NULL);
        if ((length - offset) != 0) {
            dispatch = tvb_get_guint8(tvb, offset);
        }
    }

    if ((dispatch & 0xf8) == 0xe0) { // Fragmentation Header (subsequent)
        offset = dissect_g3_fragnframe(tvb, pinfo, offset, NULL);
        if ((length - offset) != 0) {
            dispatch = tvb_get_guint8(tvb, offset);
        }
    }


    /* decision time */
    if (dispatch != 0x40) { // everything but 'additional dispatch byte follows'
        /* send everything to 6LoWPAN dissector (handles also NALP) */
        call_dissector_with_data(data6lowpan_handle, tvb, pinfo, tree, data);
    } else {
        /* second pass with display */
        offset = 0;
        dispatch = tvb_get_guint8(tvb, offset);
        g3data_item = proto_tree_add_item(tree, hf_g3data, tvb, offset+1, length-1, ENC_NA);
        g3data_tree = proto_item_add_subtree(g3data_item, ett_g3data);

        if ((dispatch & 0xc0) == 0x80) { // Mesh Header
            offset = dissect_g3_meshframe(tvb, pinfo, offset, g3data_tree);
            if ((length - offset) != 0) {
                dispatch = tvb_get_guint8(tvb, offset);
            }
        }
        if (dispatch == 0x50) { // LOWPAN_BC0 broadcast
            offset = dissect_g3_lowpan_bc0frame(tvb, pinfo, offset, g3data_tree);
            if ((length - offset) != 0) {
                dispatch = tvb_get_guint8(tvb, offset);
            }
        }
        if ((dispatch & 0xf8) == 0xc0) { // Fragmentation Header (first)
            offset = dissect_g3_frag1frame(tvb, pinfo, offset, g3data_tree);
            if ((length - offset) != 0) {
                dispatch = tvb_get_guint8(tvb, offset);
            }
        }

        if ((dispatch & 0xf8) == 0xe0) { // Fragmentation Header (subsequent)
            offset = dissect_g3_fragnframe(tvb, pinfo, offset, g3data_tree);
        }

        offset = dissect_g3_escframe(tvb, pinfo, offset, g3data_tree); // Additional Dispatch byte follows

        if ((length - offset) != 0) { // Reserved
            /* Parse the fields and add values */
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "[Byte(s) left]");
        }
    }

    return length;
}

static int
dissect_g3beacon(tvbuff_t    *tvb,
                 packet_info *pinfo,
                 proto_tree  *tree,
                 void *data   _U_)
{
    guint16 offset = 0;
    guint length = 0;

    proto_item*g3beacon_item         = NULL;
    proto_tree*g3beacon_tree         = NULL;
    proto_item*g3beacon_subitem      = NULL;
    proto_tree*g3beacon_payload_tree = NULL;
    proto_tree*g3beacon_GTS_tree     = NULL;
    proto_tree*g3beacon_pa_tree      = NULL;

    g3beacon_item = proto_tree_add_item(tree, hf_g3beacon, tvb, offset, 5, ENC_NA);
    g3beacon_tree = proto_item_add_subtree(g3beacon_item, ett_g3beacon);

    /* Add the superframe item */
    g3beacon_subitem = proto_tree_add_item(g3beacon_tree, hf_g3beacon_superframe, tvb, offset, 2,
                                           ENC_NA);
    g3beacon_payload_tree = proto_item_add_subtree(g3beacon_subitem, ett_g3beacon_superframe);

    /* Parse the superframe fields and add values */
    proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_sf_order, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_sf_beacon_order, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_sf_association_permit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_sf_pan_coordinator, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_sf_reserved, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_sf_BLE, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_sf_CAP_slot, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Add the GTS item */
    g3beacon_subitem = proto_tree_add_item(g3beacon_tree, hf_g3beacon_GTS, tvb, offset, 1, ENC_NA);
    g3beacon_payload_tree = proto_item_add_subtree(g3beacon_subitem, ett_g3beacon_GTS);

    /* Add the GTS spec item */
    g3beacon_subitem = proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_GTSspec, tvb, offset,
                                           1, ENC_NA);
    g3beacon_GTS_tree = proto_item_add_subtree(g3beacon_subitem, ett_g3beacon_GTSspec);

    /* Parse the GTS spec fields and add values */
    proto_tree_add_item(g3beacon_GTS_tree, hf_g3beacon_GTSspec_descriptor_count, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_GTS_tree, hf_g3beacon_GTSspec_reserved, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_GTS_tree, hf_g3beacon_GTSspec_permit, tvb, offset, 1, ENC_NA);

    offset += 1;

    /* Add the pendingaddress item */
    g3beacon_subitem = proto_tree_add_item(g3beacon_tree, hf_g3beacon_pendingaddress, tvb, offset,
                                           1, ENC_NA);
    g3beacon_payload_tree = proto_item_add_subtree(g3beacon_subitem, ett_g3beacon_pendingaddress);

    /* Add the pendingaddress spec item */
    g3beacon_subitem = proto_tree_add_item(g3beacon_payload_tree, hf_g3beacon_pendingaddressspec,
                                           tvb, offset, 1, ENC_NA);
    g3beacon_pa_tree = proto_item_add_subtree(g3beacon_subitem, ett_g3beacon_pendingaddressspec);

    /* Parse the pendingaddress spec fields and add values */
    proto_tree_add_item(g3beacon_pa_tree, hf_g3beacon_pas_number_short, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_pa_tree, hf_g3beacon_pas_reserved_low, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_pa_tree, hf_g3beacon_pas_number_extended, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(g3beacon_pa_tree, hf_g3beacon_pas_reserved_high, tvb, offset, 1, ENC_NA);

    offset += 1;

    /* Add the beacon payload item */
    length = tvb_reported_length(tvb) - offset;
    proto_tree_add_item(g3beacon_tree, hf_g3beacon_payload, tvb, offset, length, ENC_NA);

    if (length != 0) {
        /* Parse the fields and add values */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "[Bytes left]");
    }

    return tvb_captured_length(tvb);
}

static int
dissect_g3command(tvbuff_t    *tvb,
                  packet_info *pinfo,
                  proto_tree  *tree,
                  void *data   _U_)
{
    guint16 offset = 0;
    guint8 value = 0;
    guint length = 0;

    proto_item *g3command_item = NULL;
    proto_tree *g3command_tree = NULL;
    proto_item *g3command_subitem = NULL;
    proto_tree *g3command_subtree = NULL;

    length = tvb_reported_length(tvb);
    g3command_item = proto_tree_add_item(tree, hf_g3command, tvb, offset, length, ENC_NA);
    g3command_tree = proto_item_add_subtree(g3command_item, ett_g3command);

    /* Add the command frame identifier item and add the value */
    value = tvb_get_guint8(tvb, 0);
    proto_tree_add_item(g3command_tree, hf_g3command_cfi, tvb, offset, 1, ENC_NA);

    offset += 1;

    if (value == 0x07) { //Beacon request payload
        /* Update the info column */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Beacon Request");
    } else if (value == 0x0A) { //Tone map response payload
        /* Update the info column */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Tone Map Response");

        /* Add the Tone Map Response payload item */
        g3command_subitem = proto_tree_add_item(g3command_tree, hf_g3command_payload, tvb, offset,
                                                7, ENC_NA);
        g3command_subtree = proto_item_add_subtree(g3command_subitem, ett_g3command_payload);

        /* Add the TXRES item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txres, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Add the TXGAIN item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txgain, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Add the MOD item */
        if (tvb_get_guint8(tvb, offset) & G3_TMR_MOD_SCH_MSK) {
            proto_tree_add_item(g3command_subtree, hf_g3command_payload_mod_coh, tvb, offset, 1,
                                ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(g3command_subtree, hf_g3command_payload_mod_dif, tvb, offset, 1,
                                ENC_BIG_ENDIAN);
        }

        /* Add the MOD SCH item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_mod_sch, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Add the TM item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_tm, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
        /* Add the LQI item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_lqi, tvb, (offset + 2), 1, ENC_BIG_ENDIAN);
        /* Add the TXCOEF_TM0 item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txcoef_tm0, tvb, (offset + 3), 1, ENC_BIG_ENDIAN);
        /* Add the TXCOEF_TM1 item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txcoef_tm1, tvb, (offset + 3), 1, ENC_BIG_ENDIAN);
        /* Add the TXCOEF_TM2 item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txcoef_tm2, tvb, (offset + 4), 1, ENC_BIG_ENDIAN);
        /* Add the TXCOEF_TM3 item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txcoef_tm3, tvb, (offset + 4), 1, ENC_BIG_ENDIAN);
        /* Add the TXCOEF_TM4 item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txcoef_tm4, tvb, (offset + 5), 1, ENC_BIG_ENDIAN);
        /* Add the TXCOEF_TM5 item */
        proto_tree_add_item(g3command_subtree, hf_g3command_payload_txcoef_tm5, tvb, (offset + 5),
                            1, ENC_BIG_ENDIAN);
    } else {   //Unidentified payload
        /* Update the info column */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Unidentified Command");

        /* Add the command payload item */
        length = tvb_reported_length(tvb) - offset;

        if (length != 0) {
            proto_tree_add_item(g3command_tree, hf_g3command_payload, tvb, offset, length, ENC_NA);

            /* Parse the fields and add values */
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "[Bytes left]");
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_g3_fcccommand(tvbuff_t    *tvb,
                      packet_info *pinfo,
                      proto_tree  *tree,
                      void *data   _U_)
{
    guint16 offset = 0;
    guint8 value = 0;
    guint length = 0;

    proto_item *g3_fcccommand_item = NULL;
    proto_tree *g3_fcccommand_tree = NULL;
    proto_item *g3_fcccommand_subitem = NULL;
    proto_tree *g3_fcccommand_subtree = NULL;

    length = tvb_reported_length(tvb);
    g3_fcccommand_item = proto_tree_add_item(tree, hf_g3_fcccommand, tvb, offset, length, ENC_NA);
    g3_fcccommand_tree = proto_item_add_subtree(g3_fcccommand_item, ett_g3_fcccommand);

    /* Add the command frame identifier item and add the value */
    value = tvb_get_guint8(tvb, 0);
    proto_tree_add_item(g3_fcccommand_tree, hf_g3_fcccommand_cfi, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    if (value == 0x07) { //Beacon request payload
        /* Update the info column */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Beacon Request");
    } else if (value == 0x0A) { //Tone map response payload
        /* Update the info column */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Tone Map Response");

        /* Add the Tone Map Response payload item */
        g3_fcccommand_subitem = proto_tree_add_item(g3_fcccommand_tree, hf_g3_fcccommand_payload,
                                                    tvb, offset, 12, ENC_NA);
        g3_fcccommand_subtree = proto_item_add_subtree(g3_fcccommand_subitem,
                                                       ett_g3_fcccommand_payload);

        /* Add the TXRES item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txres, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* Add the TXGAIN item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txgain, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* Add the MOD item */
        if (tvb_get_guint8(tvb, offset + 11) & G3_FCC_TMR_MOD_SCH_MSK) {
            proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_mod_coh, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_mod_dif, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
        }

        /* Add the TM item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_tm, tvb, (offset + 1),
                            3, ENC_LITTLE_ENDIAN);

        /* Add the LQI item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_lqi, tvb, (offset + 4),
                            1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM0 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm0, tvb,
                            (offset + 5), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM1 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm1, tvb,
                            (offset + 5), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM2 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm2, tvb,
                            (offset + 5), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM3 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm3, tvb,
                            (offset + 5), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM4 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm4, tvb,
                            (offset + 6), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM5 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm5, tvb,
                            (offset + 6), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM6 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm6, tvb,
                            (offset + 6), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM7 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm7, tvb,
                            (offset + 6), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM8 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm8, tvb,
                            (offset + 7), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM9 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm9, tvb,
                            (offset + 7), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM10 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm10, tvb,
                            (offset + 7), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM11 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm11, tvb,
                            (offset + 7), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM12 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm12, tvb,
                            (offset + 8), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM13 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm13, tvb,
                            (offset + 8), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM14 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm14, tvb,
                            (offset + 8), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM15 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm15, tvb,
                            (offset + 8), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM16 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm16, tvb,
                            (offset + 9), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM17 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm17, tvb,
                            (offset + 9), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM18 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm18, tvb,
                            (offset + 9), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM19 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm19, tvb,
                            (offset + 9), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM20 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm20, tvb,
                            (offset + 10), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM21 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm21, tvb,
                            (offset + 10), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM22 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm22, tvb,
                            (offset + 10), 1, ENC_BIG_ENDIAN);

        /* Add the TXCOEF_TM23 item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_txcoef_tm23, tvb,
                            (offset + 10), 1, ENC_BIG_ENDIAN);

        /* Add the MOD SCH item */
        proto_tree_add_item(g3_fcccommand_subtree, hf_g3_fcccommand_payload_mod_sch, tvb,
                            (offset + 11), 1, ENC_BIG_ENDIAN);
    } else {   //Unidentified payload
        /* Update the info column */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Unidentified Command");

        /* Add the command payload item */
        length = tvb_reported_length(tvb) - offset;

        if (length != 0) {
            proto_tree_add_item(g3_fcccommand_tree, hf_g3_fcccommand_payload, tvb, offset, length,
                                ENC_NA);

            /* Parse the fields and add values */
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "[Bytes left]");
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_g3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree* g3_tree         = NULL;
    proto_item* g3_item         = NULL;
    proto_item* subitem         = NULL;
    proto_tree* subtree         = NULL;

    guint       offset          = 0;
    guint       mhr_offset      = 0;
    gboolean    valid           = TRUE;
    tvbuff_t*   payload_tvb     = NULL;

    /* Segmentation (fragmentation) variables */
    fragment_head* frag_msg     = NULL;
    guint16  segment_length     = 0;
    guint8   segment_count      = 0;
    gboolean is_last_segment    = FALSE;

    guint    aux_sec_header_len = 0;
    guint8 packet_encap         = 0;

    ieee802154_packet* packet   = (ieee802154_packet *)wmem_alloc(pinfo->pool, sizeof(ieee802154_packet));

    /* Clear out the addressing strings. */
    set_address(&pinfo->dst, AT_NONE, 0, NULL);
    set_address(&pinfo->src, AT_NONE, 0, NULL);
    set_address(&pinfo->dl_dst, AT_NONE, 0, NULL);
    set_address(&pinfo->dl_src, AT_NONE, 0, NULL);
    set_address(&pinfo->net_dst, AT_NONE, 0, NULL);
    set_address(&pinfo->net_src, AT_NONE, 0, NULL);

    /* Allocate frame data with hints for upper layers */
    if (!pinfo->fd->visited) {
        ieee_hints = wmem_new0(wmem_file_scope(), ieee802154_hints_t);
        p_add_proto_data(wmem_file_scope(), pinfo,
                         proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0, ieee_hints);
    } else {
        ieee_hints = (ieee802154_hints_t *) p_get_proto_data(
            wmem_file_scope(), pinfo, proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN), 0);
    }

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    g3_hints = (g3_hints_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_get_id_by_filter_name(
                                                   "g3"), 0);

    if (g3_hints) {
        packet_encap = g3_hints->g3_bandplan;
        cenelec_is_b = (packet_encap == G3_BANDPLAN_CENELEC_B) ? TRUE : FALSE;
        standard_is_G3Base = g3_hints->g3_standard_is_G3Base;
    } else {
        packet_encap = (pinfo->rec->rec_header.packet_header.pkt_encap - WTAP_ENCAP_G3_CENELEC);
    }

    /* Add the G3 FCH */
    switch (packet_encap)
    {
        case G3_BANDPLAN_CENELEC_A_B:
        case G3_BANDPLAN_CENELEC_A:
        case G3_BANDPLAN_CENELEC_B:
            g3_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_g3_mac, &g3_item, bandplan_name[packet_encap]);
            offset += dissect_g3_cen_fch(tvb, offset, pinfo, g3_tree, &valid);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, bandplan_name[packet_encap]);
            break;
        case G3_BANDPLAN_FCC_ARIB:
        case G3_BANDPLAN_FCC:
        case G3_BANDPLAN_ARIB:
            g3_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_g3_mac, &g3_item, bandplan_name[packet_encap]);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, bandplan_name[packet_encap]);
            offset += dissect_g3_fcc_fch(tvb, offset, pinfo, g3_tree, &valid);
            break;
        default:
            expert_add_info_format(pinfo, g3_item, &ei_g3_unknown_dlt,
                                   "Unknown DLT: supports %d (CENELEC), %d (FCC/ARIB)",
                                   WTAP_ENCAP_G3_CENELEC+102, WTAP_ENCAP_G3_FCC_ARIB+102);
            return tvb_captured_length(tvb);
    }

    /* Ack/Nack -> return directly */
    if (!valid) {
        return tvb_captured_length(tvb);
    }

    /* Add the segment control item */
    if (valid) {
        guint8 sc = tvb_get_guint8(tvb, offset);
        guint8 value = tvb_get_guint8(tvb, offset + 1);
        guint8 value2 = tvb_get_guint8(tvb, offset + 2);

        segment_count = (guint8) ((value & 0xfc) >> 2);
        segment_length = (guint16) (((value & 0x03) << 8) | value2);

        if ((sc & 0x01) == 1) {
            is_last_segment = TRUE;
        }

        subitem = proto_tree_add_item(g3_tree, hf_g3_segmentcontrol, tvb, offset, 3, ENC_NA);
        subtree = proto_item_add_subtree(subitem, ett_g3_segmentcontrol);

        proto_tree_add_uint(subtree, hf_g3_sc_RES, tvb, offset, 1, sc);
        proto_tree_add_uint(subtree, hf_g3_sc_TMR, tvb, offset, 1, sc);
        proto_tree_add_uint(subtree, hf_g3_sc_CC, tvb, offset, 1, sc);
        proto_tree_add_uint(subtree, hf_g3_sc_CAP, tvb, offset, 1, sc);
        proto_tree_add_uint(subtree, hf_g3_sc_LSF, tvb, offset, 1, sc);

        proto_tree_add_uint(subtree, hf_g3_sc_SC, tvb, offset + 1, 1, segment_count);
        proto_tree_add_uint(subtree, hf_g3_sc_SL, tvb, offset + 1, 2, segment_length);

        offset += 3;
    }

    mhr_offset = offset;  // save offset for encryption

    /* Add the IEEE 802.15.4 frame control item */
    if (valid) {
        /* Parse the frame control fields and add values
         * Get the FCF field.*/
        guint16 fcf = tvb_get_letohs(tvb, offset);

        /* Parse FCF Flags. */
        packet->frame_type = fcf & IEEE802154_FCF_TYPE_MASK;
        packet->security_enable = (fcf & IEEE802154_FCF_SEC_EN) >> 3;
        packet->frame_pending = (fcf & IEEE802154_FCF_FRAME_PND) >> 4;
        packet->ack_request = (fcf & IEEE802154_FCF_ACK_REQ) >> 5;
        packet->pan_id_compression = (fcf & IEEE802154_FCF_PAN_ID_COMPRESSION) >> 6;
        packet->version = (fcf & IEEE802154_FCF_VERSION) >> 12;
        packet->dst_addr_mode = (fcf & IEEE802154_FCF_DADDR_MASK) >> 10;
        packet->src_addr_mode = (fcf & IEEE802154_FCF_SADDR_MASK) >> 14;

        subitem =
            proto_tree_add_item(g3_tree, hf_g3_framecontrol, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        subtree = proto_item_add_subtree(subitem, ett_g3_framecontrol);

        proto_tree_add_uint(subtree, hf_g3_fc_srcaddressmode, tvb, offset + 1, 1, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_version, tvb, offset + 1, 1, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_dstaddressmode, tvb, offset + 1, 1, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_reserved, tvb, offset, 2, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_panidcompression, tvb, offset, 1, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_ack, tvb, offset, 1, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_pending, tvb, offset, 1, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_security, tvb, offset, 1, fcf);
        proto_tree_add_uint(subtree, hf_g3_fc_frametype, tvb, offset, 1, fcf);

        /* Update info column */
        {
            static const char *frame_type_cinfos[] = {"Beacon frame", "Data frame", "Acknowledge frame",
                                                      "MAC command frame", "Other frame"};
            unsigned fi = (unsigned) packet->frame_type;
            if (fi >= array_length(frame_type_cinfos)) {
                fi = array_length(frame_type_cinfos) - 1;
            }
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, frame_type_cinfos[fi]);
        }

        /* Add the sequence number item */
        packet->seqno = tvb_get_guint8(tvb, offset + 2);
        proto_tree_add_item(g3_tree, hf_g3_seqno, tvb, offset + 2, 1, ENC_NA);

        offset += 3;

        if ((packet->dst_addr_mode != 0x00) && (packet->dst_addr_mode != 0x01)) {
            offset += parse_dst_addr(tvb, offset, pinfo, g3_tree, packet);
        }

        if ((packet->src_addr_mode != 0x00) && (packet->src_addr_mode != 0x01)) {
            offset += parse_src_addr(tvb, offset, pinfo, g3_tree, packet);
        }
    }

    /* In G3, auxiliary security header is present only in the first segment */
    if (valid && packet->security_enable && (segment_count == 0)) {
        aux_sec_header_len = dissect_aux_sec_header(tvb, offset, pinfo, g3_tree, packet, &valid);
        offset += aux_sec_header_len;
    }

    /* Check if segment length is OK */
    if (segment_length > tvb_captured_length_remaining(tvb, offset) - 2) { // -FCS
        valid = FALSE;
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                            "Bogus segment length %u. Stopping dissection.", segment_length);
    }


    if (valid && !(is_last_segment && segment_count == 0)) {
        /* Fragmented */
        gboolean save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;

        /* Reassembly happens in last segment but decryption requires aux sec header that is only in first segment.
         * --> also save aux_sec header*/
        frag_msg = fragment_add_seq_check(&msg_reassembly_table,
                                          tvb,
                                          offset - aux_sec_header_len,
                                          pinfo,
                                          packet->seqno,                        // ID for fragments belonging together
                                          NULL,
                                          segment_count,                        // Fragment sequence number
                                          segment_length + aux_sec_header_len,  // Fragment length
                                          !is_last_segment);                    // More fragments?

        payload_tvb = process_reassembled_data(tvb,
                                               offset,
                                               pinfo,
                                               "Reassembled G3 segments",
                                               frag_msg,
                                               &msg_frag_items,
                                               NULL,
                                               g3_tree);

        pinfo->fragmented = save_fragmented;

        if (frag_msg != NULL && is_last_segment) {
            /* Reassembled */
            col_add_fstr(pinfo->cinfo, COL_INFO, "(Reassembled G3 segments)");
        } else {
            /* Not last packet of reassembled Short Message */
            col_add_fstr(pinfo->cinfo, COL_INFO, "(G3 segment id %u index %u length %u)",
                         packet->seqno, segment_count,
                         segment_length);
            valid = FALSE;
        }
    }

    /* Create payload tvb if no segmentation of reassembly incomplete */
    if (valid && payload_tvb == NULL) {
        payload_tvb = tvb_new_subset_length(tvb, offset, segment_length);
    }

    if (valid && packet->security_enable) {
        guint payload_offset = 0;
        tvbuff_t *dec_tvb;
        if (frag_msg != NULL) {
            gboolean ignore;

            /* Fill in required packet values and use offset in payload for aux sec header */
            payload_offset = dissect_aux_sec_header(payload_tvb, 0, pinfo, NULL, packet, &ignore);
        }
        dec_tvb = decrypt(pinfo, g3_tree, packet, tvb, mhr_offset, offset - mhr_offset, payload_tvb,
                          payload_offset);
        if (dec_tvb != NULL) {
            payload_tvb = dec_tvb;
        } else {
            valid = FALSE;
        }
    }

    /* Set the complete g3 header item length */
    proto_item_set_len(g3_item, offset);

    /* Add the FCS */
    {
        proto_item *fcs_item = proto_tree_add_item(g3_tree, hf_g3_framecheck, tvb, tvb_captured_length(tvb) - 2, 2, ENC_LITTLE_ENDIAN);
        guint16 calc_fcs = calc_tvb_fcs(tvb, mhr_offset - 3, tvb_captured_length_remaining(tvb, mhr_offset - 3) - 2);
        guint16 fcs = tvb_get_letohs(tvb, -2);
        if (fcs != calc_fcs) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "FCS error");
            expert_add_info_format(pinfo, fcs_item, &ei_g3_fcs_error, "FCS error, expected 0x%04x",
                                   calc_fcs);
        } else {
            if (packet->ack_request) {
                ack_link_register_frame(tvb, pinfo, g3_tree, fcs, ACK_LINK_DATA);
            }
        }
    }

    if (!valid || segment_length == 0) { // corrupt, not able to decrypt, or not ready due to segmentation. Or empty.
        proto_tree_add_item(tree, hf_g3_macpayload, tvb, offset, segment_length, ENC_NA);
    }
    else
    {
        switch (packet->frame_type)
        {
            case 0:
                call_dissector(g3beacon_handle, payload_tvb, pinfo, tree);
                break;
            case 1:
                call_dissector_with_data(data6lowpan_handle, payload_tvb, pinfo, tree, packet);
                break;
            case 3:
                if (packet_encap == G3_BANDPLAN_CENELEC_A_B ||
                    packet_encap == G3_BANDPLAN_CENELEC_A ||
                    packet_encap == G3_BANDPLAN_CENELEC_B) {
                    call_dissector(g3_cen_command_handle, payload_tvb, pinfo, tree);
                } else {
                    call_dissector(g3_fcc_command_handle, payload_tvb, pinfo, tree);
                }
                break;
            default:
                proto_tree_add_item(tree, hf_g3_macpayload, tvb, offset, segment_length, ENC_NA);
                if (packet->frame_type == 2) {
                    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "[Acknowledgement]");
                } else {
                    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "[Frame type error]");
                }
        }
    }

    /* Check for padding bytes (segment_length too big has already been checked) */
    if (valid) {
        gint bytes_left = (tvb_reported_length(tvb) - offset - 2) - segment_length;
        if (bytes_left != 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", [%u byte(s) left]", bytes_left);
        }
    }

    return tvb_captured_length(tvb);
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
