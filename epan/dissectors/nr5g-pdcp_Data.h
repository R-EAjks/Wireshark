#ifndef nr5g_pdcp_Data_DEFINED
#define nr5g_pdcp_Data_DEFINED

//#include "lsu.h"
#include "nr5g.h"
#include "nr5g-pdcp_Com.h"

#define nr5g_pdcp_Data_VERSION   "0.2.0"

/*
 * This interface conforms to the rules specified in `lsu.h'.
 * This interface is aligned with NR specification TS 38.323
 */

#pragma pack(1)

/*------------------------------------------------------------------*
 |  PRIMITIVES OPCODES                                              |
 *------------------------------------------------------------------*/


/*
 * AUX SAP
 */
/* Request for a Random Access (USER side only) */
#define nr5g_pdcp_Data_RA_REQ       0x02

/* Confirm success or failure of a Random Access (USER side only) */
#define nr5g_pdcp_Data_RA_CNF       0x202

/* Indicate a successful Random Access */
#define nr5g_pdcp_Data_RA_IND       0x402

/* Integrity verification on a message delivered with
 * nr5g_pdcp_Data_DATA_1_IND        (USER side only)
 */
#define nr5g_pdcp_Data_INT_CKH_REQ   0x03
#define nr5g_pdcp_Data_INT_CKH_CNF   0x203

/* Define action on messages received after delivering
 * nr5g_pdcp_Data_DATA_1_IND (they are buffered by PDCP until
 * security activation)            (USER side only)
 */
#define nr5g_pdcp_Data_RX_BUF_REQ    0x04

/*
 * DATA SAP
 */
#define nr5g_pdcp_Data_DATA_REQ     0x01
#define nr5g_pdcp_Data_DATA_1_REQ    0x04    /* RRC messages not ciphered
                                               or not integrity protected
                                               after security activation */
#define nr5g_pdcp_Data_DATA_CNF     0x201
#define nr5g_pdcp_Data_DATA_IND     0x401
#define nr5g_pdcp_Data_DATA_1_IND    0x404   /* Integrity protected message
                                               when security is not active
                                               (USER side only) */
#define nr5g_pdcp_Data_DISC_REQ     0x02

/* Indicate Max. num. of retransmission reached from Lower Layer */
#define nr5g_pdcp_Data_MAX_RETX_IND 0x403


/* Deciphered NAS logging feature */
#define  nr5g_pdcp_Data_DECIPH_NAS  0x10
#define  nr5g_pdcp_Data_LOG_INFO_IND    0x11

/*------------------------------------------------------------------*
 |  CODES USED IN PRIMITIVES                                        |
 *------------------------------------------------------------------*/

typedef enum {
    nr5g_pdcp_Data_RxBufAct_Discard
} nr5g_pdcp_Data_RxBufAct_e;
typedef uchar nr5g_pdcp_Data_RxBufAct_v;


/*------------------------------------------------------------------*
 |  LAYOUT OF PRIMITIVES                                            |
 *------------------------------------------------------------------*/

/*
 * nr5g_pdcp_Data_RA_REQ
 */
typedef struct {
    nr5g_Id_t       Nr5gId;     /* NR5G Id */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    nr5g_LchType_v  Lch;        /* Logical Channel Type */
    int             MaxUpPwr;   /* Maximum uplink power (in dBm) */
    int             BRSRP;      /* Simulated BRSRP [dBm, 0x7FFFFFFF for none] */
    int             UeCategory; /* UE category */
    
    uint            Flags;
#define nr5g_pdcp_Data_FLAG_RA_TEST_01  (0x01) /* Enable RA test mode type 1 (see NOTE (1))  */
#define nr5g_pdcp_Data_FLAG_NO_UL_HARQ  (0x02) /* Disable UL HARQ (see NOTE (2)) */
    uchar                   NrCellGrId;    /* Nr Ceel Group Id (0 or 1) Default 0*/
    uchar                   SpareC[3];
    uint            Spare[2];   /* Must be set to zero */
    uchar           Rt_Preamble;    /* RA test mode preamble. Valid in RA_TEST_* mode only.
                                       [0 - 63, -1 for none] */
    uint            Rt_RaRnti;      /* RA test mode RA-RNTI. Valid in RA_TEST_* mode only. 
                                       [-1 for none] */
    uchar           UlSubCarrSpacing;  /* Subcarrier spacing
                                          [Enum kHz15, kHz30, kHz60, kHz120, kHz240, 0xFF for none] */

    uchar           DiscardRarNum;      /* 0x00 -> Do not discard any RAR (default) */
                                        /* 0x.. -> Number of RARs to discard before accepting a new one */
                                        /* 0xFF -> Discard all RARs */
    uchar           NoData;     /* If set, Data is not present/valid */
    uchar           Data[1];    /* Data to be transmitted in RA procedure (Msg3) */
} nr5g_pdcp_Data_RA_REQ_t;

/*
 * (1) RA test mode type 1.
 *     If enabled, preamble during RA is not performed.
 *     RAR/msg2 triggers directly the RA.
 *     Some parameters can be optionally set to control the RA (Rt_* parameters).
 *     If Rt_Preamble is set, the UE will consider it as if the preamble was performed (e.g. RAR 
 *     must contais that preamble).
 *     If Rt_Preamble is not set, any preamble will be considered valid.
 *     The same is valid for Rt_RaRnti.
 *
 * (2) Disable UL HARQ
 *     If set, UL HARQ is disabled. 
 *     NDI in UL DCI are ignored and UL DCI are used for new data Tx only.
 */

/*
 * nr5g_pdcp_Data_RA_CNF
 */
typedef struct {
    nr5g_Id_t        Nr5gId;      /* NR5G Id */
    short           Res;        /* Result code (see TODO) */
    nr5g_RA_RES_v   RaRes;      /* RA Result code */
    uint            C_RNTI;     /* Assigned C-RNTI */
    uint            numberOfPreamblesSent;  /* number of RACH preambles that were transmitted. Corresponds to parameter PREAMBLE_TRANSMISSION_COUNTER in TS 36.321 */
    uchar           contentionDetected;     /* If set contention was detected for at least one of the transmitted preambles */
} nr5g_pdcp_Data_RA_CNF_t;

/*
 * nr5g_pdcp_Data_RA_IND
 */
typedef struct {
    nr5g_Id_t        Nr5gId;      /* NR5G Id */
    short           Res;        /* Result code (see TODO) */
    uint            C_RNTI;     /* Assigned C-RNTI */
    uchar           CrId[1];    /* Contention Resolution Id */
} nr5g_pdcp_Data_RA_IND_t;

/*
 * nr5g_pdcp_Data_INT_CKH_REQ
 */
typedef struct {
    nr5g_Id_t        Nr5gId;      /* NR5G Id */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    uint            Ref;        /* Value in nr5g_pdcp_Data_DATA_1_IND */
    nr5g_NIA_v       IntAlg;
    uchar           K_RRCint[16];
    uchar           Data[1];    /* Message to be integrity-checked
                                   received in nr5g_pdcp_Data_DATA_1_IND */
} nr5g_pdcp_Data_INT_CKH_REQ_t;

/*
 * nr5g_pdcp_Data_INT_CKH_CNF
 */
typedef struct {
    nr5g_Id_t        Nr5gId;      /* NR5G Id */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    uint            Ref;        /* Value in nr5g_pdcp_Data_INT_CKH_REQ */
    short           Res;        /* Result code (see TODO) */
} nr5g_pdcp_Data_INT_CKH_CNF_t;

/*
 * nr5g_pdcp_Data_RX_BUF_REQ
 */
typedef struct {
    nr5g_Id_t        Nr5gId;      /* NR5G Id */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    nr5g_pdcp_Data_RxBufAct_v Action;
} nr5g_pdcp_Data_RX_BUF_REQt;


/*
 * nr5g_pdcp_Data_DATA_REQ
 */
typedef struct {
    nr5g_Id_t       Nr5gId;     /* NR5G Id */
    uint            LogRef;     /* Reference for deciphered NAS logging */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    nr5g_LchType_v  Lch;        /* Logical Channel Type */
    uchar           MUI;        /* User Information */
    uchar           Data[1];    /* Data (see Note 1) */
} nr5g_pdcp_Data_DATA_REQ_t;
/*
 * Maximum data size (bytes) is nr5g_pdcp_Com_MAX_DATA_SIZE
 */

/*
 * nr5g_pdcp_Data_DATA_1_REQ
 */
typedef struct {
    nr5g_Id_t        Nr5gId;      /* NR5G Id */
    uint            LogRef;     /* Reference for deciphered NAS logging */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    nr5g_LchType_v   Lch;        /* Logical Channel Type */
    uchar           MUI;        /* User Information */
    uchar           Integr;     /* If !=0, 'Data' must be integrity protected */
    uchar           Cipher;     /* If !=0, 'Data' must be ciphered */
    uchar           Data[1];    /* Data (see Note 1) */
} nr5g_pdcp_Data_DATA_1_REQ_t;
/*
 * Maximum data size (bytes) is nr5g_pdcp_Com_MAX_DATA_SIZE
 */

/*
 * nr5g_pdcp_Data_DATA_IND
 */
typedef struct {
    nr5g_Id_t       Nr5gId;     /* NR5G Id */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    nr5g_LchType_v  Lch;        /* Logical Channel Type */
    ushort          Esbf;       /* Extended L1 SFN/SBF number (1) */
    uint            LogRef;     /* Reference for deciphered NAS logging */
    uchar           Data[1];    /* Data */
} nr5g_pdcp_Data_DATA_IND_t;

/*
 * nr5g_pdcp_Data_DATA_1_IND
 */
typedef struct {
    nr5g_Id_t        Nr5gId;      /* NR5G Id */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    nr5g_LchType_v   Lch;        /* Logical Channel Type */
    ushort          Esbf;       /* Extended L1 SFN/SBF number (1) */
    uint            Ref;        /* Value for the 'Ref' field in
                                   nr5g_pdcp_Data_INT_CKH_REQ/CNF */
    uint            LogRef;     /* Reference for deciphered NAS logging */
    uchar           Data[1];    /* Data */
} nr5g_pdcp_Data_DATA_1_IND_t;

/*
 * (1) Used the convention of consider an extended subframe number, as
 *       Esbf = SFN*10 + SBF
 *     so,
 *     System Frame Number (SFN) is equal to:
 *       [Esbf/10]
 *     Subfame number (SBF) is equal to:
 *       [Esbf%10]
 *     
 *     Value range:  0 - 10239.
 *
 *     Value -1U (0xFFFF) means 'not apply or not reported'.
 */


/*
 * nr5g_pdcp_Data_DISC_REQ
 * nr5g_pdcp_Data_DATA_CNF
 */
typedef struct {

    nr5g_Id_t       Nr5gId;     /* NR5G Id */
    nr5g_RbType_v   RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
    nr5g_LchType_v  Lch;        /* Logical Channel Type */
    uchar           MUI;        /* User Information */

} nr5g_pdcp_Data_MUI_t;

/*
 * nr5g_pdcp_Data_MAX_RETX_IND
 */
typedef struct {
    nr5g_Id_t       Nr5gId;     /* NR5G Id */
    nr5g_RbType_v   RbType;     /* Radio Bearer Type */
    uchar           RbId;       /* Rb id */
} nr5g_pdcp_Data_MAX_RETX_t;

/*
 * nr5g_pdcp_Data_DECIPH_NAS
 */
typedef struct
{
    nr5g_Id_t Nr5gId; /* NR5G Id */
    uint LogRef; /* Logging Reference (if -1, it does not apply) */
    nr5g_RbType_v RbType; /* Radio Bearer Type */
    uchar RbId; /* Radio Bearer Identifier */
    uchar Dir; /* Logging Direction (0 -> DL, 1 -> UL) */
    uchar Spare;
    uchar Data[1]; /* Start of deciphered NAS data */
} nr5g_pdcp_Data_DECIPH_NAS_t;

/*
 * nr5g_pdcp_Data_LOG_INFO
 */
typedef struct
{
    nr5g_Id_t Nr5gId; /* NR5G Id */
    uint  FilterPass; /* Logging flags: see lsuMonSdrNr5gPass* defines in lsumon-nr5gsdr.h */
} nr5g_pdcp_Data_LOG_INFO_t;

/*------------------------------------------------------------------*
 |  SUMMARY OF PRIMITIVES                                           |
 *------------------------------------------------------------------*/

typedef union {
    nr5g_pdcp_Data_RA_REQ_t     RaReq;
    nr5g_pdcp_Data_RA_CNF_t     RaCnf;
    nr5g_pdcp_Data_RA_IND_t     RaInd;
    nr5g_pdcp_Data_INT_CKH_REQ_t IntChkReq;
    nr5g_pdcp_Data_INT_CKH_CNF_t IntChkCnf;
    nr5g_pdcp_Data_RX_BUF_REQt   RxBufReq;

    nr5g_pdcp_Data_DATA_REQ_t   DataReq;
    nr5g_pdcp_Data_DATA_1_REQ_t  Data1Req;
    nr5g_pdcp_Data_MUI_t            DiscReq;
    nr5g_pdcp_Data_MUI_t            DataCnf;
    nr5g_pdcp_Data_DATA_IND_t   DataInd;
    nr5g_pdcp_Data_DATA_1_IND_t  Data1Ind;
    nr5g_pdcp_Data_MAX_RETX_t   MaxRetxInd;

    nr5g_pdcp_Data_DECIPH_NAS_t DeciphNas;
    nr5g_pdcp_Data_LOG_INFO_t   LogInfoInd;

} nr5g_pdcp_Data_PRIMt;


#pragma pack()
#endif
