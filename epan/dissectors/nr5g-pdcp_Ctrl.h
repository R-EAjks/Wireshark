#ifndef nr5g_pdcp_Ctrl_DEFINED
#define nr5g_pdcp_Ctrl_DEFINED

#ifndef tmLTEUU 
#include "lsu.h"
#endif
#include "nr5g.h"

#define nr5g_pdcp_Ctrl_VERSION   "1.8.0"

/*
 * This interface conforms to the rules specified in `lsu.h'.
 */

#pragma pack(1)

/*------------------------------------------------------------------*
 |  PRIMITIVES OPCODES                                              |
 *------------------------------------------------------------------*/

/*
 * CPDCP SAP
 */

/*
 * Initialize a PDCP-Entity */
#define nr5g_pdcp_Ctrl_CONFIG_CMD            0x01
#define nr5g_pdcp_Ctrl_CONFIG_ACK            (0x100 + nr5g_pdcp_Ctrl_CONFIG_CMD)
#define nr5g_pdcp_Ctrl_CONFIG_NAK            (0x200 + nr5g_pdcp_Ctrl_CONFIG_CMD)

/*
 * Initialize a PDCP-Entity starting from a given state */
#define nr5g_pdcp_Ctrl_CONFIG_STATE_CMD     0x07
#define nr5g_pdcp_Ctrl_CONFIG_STATE_ACK     (0x100 + nr5g_pdcp_Ctrl_CONFIG_STATE_CMD)
#define nr5g_pdcp_Ctrl_CONFIG_STATE_NAK     (0x200 + nr5g_pdcp_Ctrl_CONFIG_STATE_CMD)

/*
 * Release a prev. opened PDCP-Entity */
#define nr5g_pdcp_Ctrl_RELEASE_CMD           0x02
#define nr5g_pdcp_Ctrl_RELEASE_ACK           (0x100 + nr5g_pdcp_Ctrl_RELEASE_CMD)
#define nr5g_pdcp_Ctrl_RELEASE_NAK           (0x200 + nr5g_pdcp_Ctrl_RELEASE_CMD)

/*
 * Set security parameters for an UE
 */
#define nr5g_pdcp_Ctrl_SET_SEC_UE_CMD    0x03
#define nr5g_pdcp_Ctrl_SET_SEC_UE_ACK    (0x100 + nr5g_pdcp_Ctrl_SET_SEC_UE_CMD)
#define nr5g_pdcp_Ctrl_SET_SEC_UE_NAK    (0x200 + nr5g_pdcp_Ctrl_SET_SEC_UE_CMD)

/*
 * Activate SIB filtering for a cell
 */
#define nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD    0x05
#define nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK    (0x100 + nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD)
#define nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK    (0x200 + nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD)

/*
 * Deactivate SIB filtering for a cell
 */
#define nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD    0x06
#define nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK    (0x100 + nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD)
#define nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK    (0x200 + nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD)

/*
 * Initialize a PDCP-SDAP-Entity Mapping */
#define nr5g_pdcp_Ctrl_SDAP_CONFIG_CMD            0x08
#define nr5g_pdcp_Ctrl_SDAP_CONFIG_ACK            (0x100 + nr5g_pdcp_Ctrl_SDAP_CONFIG_CMD)
#define nr5g_pdcp_Ctrl_SDAP_CONFIG_NAK            (0x200 + nr5g_pdcp_Ctrl_SDAP_CONFIG_CMD)

/*
 * Initialize a PDCP-SDAP-Entity Qfi List */
#define nr5g_pdcp_Ctrl_QFI_CONFIG_CMD            0x09
#define nr5g_pdcp_Ctrl_QFI_CONFIG_ACK            (0x100 + nr5g_pdcp_Ctrl_QFI_CONFIG_CMD)
#define nr5g_pdcp_Ctrl_QFI_CONFIG_NAK            (0x200 + nr5g_pdcp_Ctrl_QFI_CONFIG_CMD)

/*
 * Configuration for nodeB security testing for U-plane data */
#define nr5g_pdcp_Ctrl_NB_SEC_UPLANE_CFG         0x0A
#define nr5g_pdcp_Ctrl_NB_SEC_UPLANE_CFG_ACK     (0x100 + nr5g_pdcp_Ctrl_NB_SEC_UPLANE_CFG)
#define nr5g_pdcp_Ctrl_NB_SEC_UPLANE_CFG_NAK     (0x200 + nr5g_pdcp_Ctrl_NB_SEC_UPLANE_CFG)

/*
 * UE test loop mode A: start data loopback
 */
#define nr5g_pdcp_Ctrl_UE_LOOP_A_START_CMD      0x0B
#define nr5g_pdcp_Ctrl_UE_LOOP_A_START_ACK      (0x100 + nr5g_pdcp_Ctrl_UE_LOOP_A_START_CMD)
#define nr5g_pdcp_Ctrl_UE_LOOP_A_START_NAK      (0x200 + nr5g_pdcp_Ctrl_UE_LOOP_A_START_CMD)

/*
 * UE test loop: stop data loopback
 */
#define nr5g_pdcp_Ctrl_UE_LOOP_STOP_CMD         0x0C
#define nr5g_pdcp_Ctrl_UE_LOOP_STOP_ACK         (0x100 + nr5g_pdcp_Ctrl_UE_LOOP_STOP_CMD)
#define nr5g_pdcp_Ctrl_UE_LOOP_STOP_NAK         (0x200 + nr5g_pdcp_Ctrl_UE_LOOP_STOP_CMD)


/*
 * STAT SAP
 */
#define  nr5g_pdcp_Ctrl_STAT_UE_REQ         0x01
#define  nr5g_pdcp_Ctrl_STAT_UE_IND        (0x400 + nr5g_pdcp_Ctrl_STAT_UE_REQ)

/*
 * ERR SAP
 */
#define nr5g_pdcp_Ctrl_ERROR_IND         0x401
#define nr5g_pdcp_Ctrl_REJECT_IND        0x402
#define nr5g_pdcp_Ctrl_NC_ERROR_IND      0x403 /* Non Critical Error */
#define nr5g_pdpc_Ctrl_INT_FAIL_IND      0x404 /* Integrity check failure */

/*------------------------------------------------------------------*
 |  CODES USED IN PRIMITIVES                                        |
 *------------------------------------------------------------------*/

typedef enum {
    nr5g_pdcp_Ctrl_UM = nr5g_UM,
    nr5g_pdcp_Ctrl_AM = nr5g_AM,
} nr5g_pdcp_Ctrl_RlcMode_e;
typedef uchar nr5g_pdcp_Ctrl_RlcMode_v;

typedef enum {
    nr5g_pdcp_Ctrl_SnSize_12 = 12,
    nr5g_pdcp_Ctrl_SnSize_18 = 18,

} nr5g_pdcp_Ctrl_SnSize_e;
typedef uchar nr5g_pdcp_Ctrl_SnSize_v;

typedef enum {
    nr5g_pdcp_Ctrl_SecOpt_UseNow,
    nr5g_pdcp_Ctrl_SecOpt_WaitReest
} nr5g_pdcp_Ctrl_SecOpt_e;
typedef uchar nr5g_pdcp_Ctrl_SecOpt_v;

typedef enum {
    nr5g_pdcp_Ctrl_DataFlowType_Nsapi,        /* The upper layer data flow is bearer oriented (e.g. EPS bearer case) */
    nr5g_pdcp_Ctrl_DtaFlowType_PDU_SessionID, /* The upper layer data flow is QoS oriented (e.g. PDU_Session/QFI case) */
} nr5g_pdcp_Ctrl_DataFlowType_e;
typedef uchar nr5g_pdcp_Ctrl_DataFlowType_v;

typedef enum {
    nr5g_pdcp_Ctrl_RohcUsed = 0,        /* Rohc is used */
    nr5g_pdcp_Ctrl_RohcNotUsed = 1,     /* Rohc is not used */
    nr5g_pdcp_Ctrl_RohcNoChange = 2    /* Rohc continue to use prev cfg */
} nr5g_pdcp_Ctrl_RohcCfgType_e;
typedef uchar nr5g_pdcp_Ctrl_RohcCfgType_v;

typedef enum {
    nr5g_pdcp_Ctrl_UpType_Ip,        /* The upper layer data flow is bearer oriented (e.g. EPS bearer case) */
    nr5g_pdcp_Ctrl_UpType_Eth, /* The upper layer data flow is QoS oriented (e.g. PDU_Session/QFI case) */
} nr5g_pdcp_Ctrl_UpType_e;
typedef uchar nr5g_pdcp_Ctrl_UpType_v;

/*------------------------------------------------------------------*
 |  STRUCTURES USED IN PRIMITIVES                                   |
 *------------------------------------------------------------------*/

typedef struct {
    uint                    discardTimer;           /* NYI */
    nr5g_pdcp_Ctrl_SnSize_v snSizeTx;               /* snSizeUl, UM and AM Mode */
    nr5g_pdcp_Ctrl_SnSize_v snSizeRx;               /* snSizeDl, UM and AM Mode */

    struct headerCompression_s{
        nr5g_pdcp_Ctrl_RohcCfgType_v    NotUsed; /* See nr5g_pdcp_Ctrl_RohcCfgType_e */
        rohcCFG_PARt    CfgPar; /* Configuration of ROHC Compressor/Decompressor */
    } headerCompression;

    uchar                   integrityProtection;    /* [BOOL] */
    uchar                   statusReportRequired;   /* [BOOL] valid for AM Mode only */
    struct {
        uchar   Enabled;    /* [BOOL] */
        uint    pp_cellGroup;   /* primaryPath cellGroup */
        uchar   pp_LchId;       /* primaryPath logicalChannel */
        uint    tx_DataSplitThreshold; /* ul-DataSplitThreshold [bytes, -1U means infinity
                                                                        -2U means none] */
        uchar tx_Duplication;   /* ul-Duplication, [BOOL] */
    } moreThanOneRLC; /* only one secondary cell group supported */

    uint    t_Reordering; /* t-Reordering [ms, -1U means not configured] */
    uchar   outOfOrderDelivery; /* [BOOL] */
    uchar   cipheringDisabled; /* [BOOL] If TRUE ciphering is disabled for this RB */

    uint security_config_idx; /* Indicate the security config. to be used (Prop., see nr5g_pdcp_Ctrl_SET_SEC_UE_CMD). */

    struct {
        uchar   splitSecondaryPath;     /* LCID of the split secondary RLC entity as specified in TS 38.323, -1U means not configured */
        uchar   duplicationState;       /* 3 [BOOL] uplink PDCP duplication state for the associated RLC entities,
                                           ascending order of logical channel ID of all RLC entities other than the primary RLC entity (order of MCG and SCG). -1U means not configured */
    } moreThanTwoRLC_DRB;               /* r16: SRBs (absent), DRBs (present if PDCP entity for a radio bearer with more than two associated logical channels) */

} nr5g_pdcp_Ctrl_PdcpInfo_t;

/*
 * ER field value
 */
typedef enum {

    nr5g_pdcp_Ctrl_ER_VOID       = 0, /* No Action */
    nr5g_pdcp_Ctrl_ER_ESTABLISH,      /* Establish new entity */
    nr5g_pdcp_Ctrl_ER_RECONFIGURE,    /* Reconfigure the entity */
    nr5g_pdcp_Ctrl_ER_RE_ESTABLISH,   /* Re-establish the entity */
    nr5g_pdcp_Ctrl_ER_SUSPEND,        /* apply PDCP suspend on the entity */

} nr5g_pdcp_Ctrl_ER_v;
typedef uchar nr5g_pdcp_Ctrl_ER_t;

typedef struct {
    uchar     QFI;          /* values: 0...63 */
    ushort    PrevNsapi;    /* Nsapi of the PDP Context previosly linked to the upper layer data flow.
                               -1 means "not apply". */
} nr5g_pdcp_Ctrl_QfiCfg_t;

typedef struct {
    uint        StartAfter;         /* Start corruptin/replaying after ... */
    uint        NumOfConsecutive;   /* Number of consecutive PDU to be corrupted/replayed */
    uint        RetransmitAfter;    /* Retransmit PDU after ... */
    uint        Spare[4];           /* */
} nr5g_NbSec_Uplane_Config_t;

/*------------------------------------------------------------------*
 |  LAYOUT OF PRIMITIVES                                            |
 *------------------------------------------------------------------*/

/*
 * ACK
 */
typedef struct {
    uint        UeId;       /* UE Id */
    uchar       RbId;       /* Rb id */
    nr5g_RbType_v RbType;   /* Radio Bearer Type */
} nr5g_pdcp_Ctrl_ACK_t;

/*
 * NAK
 */
typedef struct {
    uint        UeId;       /* UE Id */
    uchar       RbId;       /* Rb id */
    nr5g_RbType_v RbType;   /* Radio Bearer Type */
    short       Err;        /* Error code */
} nr5g_pdcp_Ctrl_NAK_t;

/*
 * nr5g_pdcp_Ctrl_CONFIG_CMD
 */
typedef struct {
    uint                            UeId;       /* UE Id */
    uchar                           RbId;       /* Rb id (1)(2) */
    
    nr5g_pdcp_Ctrl_ER_t             ER;

    nr5g_RbType_v                   RbType;     /* Radio Bearer Type of the mapped RB */
    nr5g_pdcp_Ctrl_DataFlowType_v   DataFlowType; /* Select Nsapi or PDU_SessionID in following union */
    union {
        ushort                      Nsapi;         /* Nsapi of the related PDP Context */
        ushort                      PDU_SessionID; /* Configured PDU Session ID */
    } u;
    ushort                          PrevNsapi;     /* Nsapi of the PDP Context previosly linked to the upper layer data flow.
                                                      -1 means "not apply". */
    nr5g_pdcp_Ctrl_RlcMode_v        RlcMode;    /* RLC Mode of the mapped RB */
    nr5g_pdcp_Ctrl_PdcpInfo_t       PdcpInfo;

} nr5g_pdcp_Ctrl_CONFIG_t;

/*
 * nr5g_pdcp_Ctrl_SDAP_CONFIG_CMD
 */
typedef struct {
    uint                            UeId;       /* UE Id */
    ushort                          PDU_SessionID; /* PDU_SessionID */
    uchar                           RbId;       /* Rb id */
    nr5g_RbType_v                   RbType;     /* Radio Bearer Type of the mapped RB */
    nr5g_pdcp_Ctrl_UpType_v         UpType;     /* PDCP Upper level traffic type (only in case of DataFlowType = nr5g_pdcp_Ctrl_DtaFlowType_PDU_SessionID) */
    /* 38.331: "SDAP-Config" information element */
    nr5g_SdapHeader_v               SdapHeaderDl;
    nr5g_SdapHeader_v               SdapHeaderUl;
    nr5g_DefaultDRB_v               DefaultDRB;
    uchar                           NumOfQFIToAdd;
    nr5g_pdcp_Ctrl_QfiCfg_t         QFIToAdd[nr5g_maxNrofQFIs];
    uchar                           NumOfQFIToRelease;
    uchar                           QFIToRelease[nr5g_maxNrofQFIs]; /* values: 0...63 */
} nr5g_pdcp_Ctrl_SDAP_CONFIG_t;

/*
 * nr5g_pdcp_Ctrl_QFI_CONFIG_CMD
 */
typedef struct {
    uint                            UeId;       /* UE Id */
    ushort                          PDU_SessionID; /* PDU_SessionID */
    /* 24.501: "QoS flow descriptions" information element */
    uchar                           NumOfNasQFI;
    nr5g_pdcp_Ctrl_QfiCfg_t         NasQFI[nr5g_maxNrofQFIs];       /* values: 0...63 */
} nr5g_pdcp_Ctrl_QFI_CONFIG_t;

/*
 * nr5g_pdcp_Ctrl_CONFIG_STATE_CMD
 */
typedef struct {
    uint                            UeId;       /* UE Id */
    uchar                           RbId;       /* Rb id (1)(2) */
    
    nr5g_RbType_v                   RbType;     /* Radio Bearer Type of the mapped RB */
    uchar                           Nsapi;      /* Nsapi of the related PDP Context */
    nr5g_pdcp_Ctrl_RlcMode_v        RlcMode;    /* RLC Mode of the mapped RB */
    nr5g_pdcp_Ctrl_PdcpInfo_t       PdcpInfo;

    /* State variables of PDCP. see 3GPP 38.323 par. 7.1 */
    uint                            Next_TX_SN;
    uint                            TX_HFN;
    uint                            Next_RX_SN;
    uint                            RX_HFN;
//  uint                            Last_Submitted_RX_SN;
    
} nr5g_pdcp_Ctrl_CONFIG_STATE_t;

/*
 * NOTES
 *
 * (1) The value of 'RbId'.
 *
 * (2) The maximum allowed value for 'RbId' is nr5g_MaxNrOfRB.
 *
 * (3) The effective srb-Identity or drb-Identity of the RB.
 */

/*
 * nr5g_pdcp_Ctrl_RELEASE_CMD
 */
typedef struct {
    uint        UeId;       /* UE Id (1) */
    uchar       RbId;       /* Rb id */
    nr5g_RbType_v RbType;    /* Radio Bearer Type */
    
} nr5g_pdcp_Ctrl_RELEASE_t;

typedef struct {
    nr5g_NIA_v      IntAlg;
    uchar           K_RRCint[16];
    uchar           K_UPint[16];

    nr5g_NEA_v      EncAlg;
    uchar           K_RRCenc[16];
    uchar           K_UPenc [16];
} nr5g_pdcp_Ctrl_Sec_t;

/*
 * nr5g_pdcp_Ctrl_SET_SEC_UE_CMD
 */
typedef struct {
    uint            UeId;           /* Ue Identification */

    nr5g_pdcp_Ctrl_SecOpt_v Options;

    uchar SecMask;  /* Bitmask of valid 'Sec' (security config.). LSB is mapped to Sec[0] and so on. */
#define nr5g_pdcp_Ctrl_NUM_SEC  (2)
    nr5g_pdcp_Ctrl_Sec_t Sec[nr5g_pdcp_Ctrl_NUM_SEC]; /* First element is the security config. with security_config_idx = 0, second is security_config_idx = 1 and so on */

} nr5g_pdcp_Ctrl_SET_SEC_UE_CMDt;

/*
 * nr5g_pdcp_Ctrl_SET_SEC_UE_ACK
 */
typedef struct {
    uint            UeId;           /* Ue Identification */
} nr5g_pdcp_Ctrl_SET_SEC_UE_ACKt;

/*
 * nr5g_pdcp_Ctrl_SET_SEC_UE_NAK
 */
typedef struct {
    uint            UeId;           /* Ue Identification */
    short           Err;            /* Error code */
} nr5g_pdcp_Ctrl_SET_SEC_UE_NAKt;


/* nr5g_pdcp_Ctrl_UE_LOOP_A_START_CMD */
typedef struct {
    uint            UeId;           /* Ue Identifier */
    uint            NumLBsetup;     /* Number of elements in LB setup list */
    struct {
        ushort          UlPdcpSduSz;    /* UL PDCP SDU size in bytes */
        ushort          Nsapi;
    }               LBsetup[1];     /* LB setup list */
} nr5g_pdcp_Ctrl_UE_LOOP_A_START_CMDt;


/* nr5g_pdcp_Ctrl_UE_LOOP_STOP_CMD */
typedef struct {
    uint            UeId;           /* Ue Identifier */
} nr5g_pdcp_Ctrl_UE_LOOP_STOP_CMDt;

/* nr5g_pdcp_Ctrl_UE_LOOP_A_START_ACK
 * nr5g_pdcp_Ctrl_UE_LOOP_STOP_ACK
 */
typedef struct {
    uint            UeId;           /* Ue Identifier */
} nr5g_pdcp_Ctrl_UE_LOOP_ACKt;

/* nr5g_pdcp_Ctrl_UE_LOOP_A_START_NAK
 * nr5g_pdcp_Ctrl_UE_LOOP_STOP_NAK
 */
typedef struct {
    uint            UeId;           /* Ue Identifier */
    short           Err;            /* Error code */
} nr5g_pdcp_Ctrl_UE_LOOP_NAKt;


/*
 * nr5g_pdcp_Ctrl_ERROR_IND
 */
typedef struct {
    short   Err;        /* Error code */
    char    Desc[1];    /* Error description (var len ASCIIZ string) */
} nr5g_pdcp_Ctrl_ERROR_t;


/*
 * nr5g_pdcp_Ctrl_REJECT_IND
 */
typedef struct {
    short   Err;        /* Cause of rejection */
    short   Spare;      /* zero */
    /*
     * The full rejected message (including its header) is placed here */
} nr5g_pdcp_Ctrl_REJECT_t;


/*
 * nr5g_pdpc_Ctrl_INT_FAIL_IND
 */
typedef struct {
    uint    UeId;           /* UE Identifier */
    uchar   RbId;           /* Rb id */
    nr5g_RbType_v RbType;    /* Radio Bearer Type */
} nr5g_pdpc_Ctrl_INT_FAIL_t;


/*
 * nr5g_pdcp_Ctrl_STAT_UE_CMD
 */
typedef struct
{
    uint    UeId;           /* UE Identifier */
} nr5g_pdcp_Ctrl_STAT_UE_REQt;

typedef struct
{
    uchar         RbId;           /* Rb id */
    nr5g_RbType_v RbType;         /* Radio Bearer Type */
    nr5g_pdcp_Com_StatElem_t    Elem;  /* Radio Bearer specific statistics */
} nr5g_pdcp_Ctrl_RbStat_t;

#define nr5g_pdcp_Ctrl_NUM_RB_STAT (10)
/*
 * nr5g_pdcp_Ctrl_STAT_UE_IND
 */
typedef struct
{
    uint    UeId;           /* UE Identifier */
    
    uint    DeltaTs;        /* Interval between current and previous stat report */

    uint    NumRb;
    nr5g_pdcp_Ctrl_RbStat_t RbStat[nr5g_pdcp_Ctrl_NUM_RB_STAT]; /* Radio Bearers stat. */
} nr5g_pdcp_Ctrl_STAT_UE_INDt;


/*
 * nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD
 * nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD
 */
typedef struct {
    uint            CellId;         /* Cell Identification */
    uint            SibFilterFlag;  /* 0 -> Legacy */
    uchar           Inst;           /* TSTM Inst */
} nr5g_pdcp_Ctrl_SIB_FILTER_CMDt;

/*
 * nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK
 * nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK
 */
typedef struct {
    uint            CellId;         /* Cell Identification */
    uint            SibFilterFlag;  /* 0 -> Legacy */
    uchar           Inst;           /* TSTM Inst */
} nr5g_pdcp_Ctrl_SIB_FILTER_ACKt;

/*
 * nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK
 * nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK
 */
typedef struct {
    uint            CellId;     /* Cell Identification */
    short           Err;        /* Error code */
    uchar           Inst;       /* TSTM Inst */
} nr5g_pdcp_Ctrl_SIB_FILTER_NAKt;

/*
 * nr5g_pdcp_Ctrl_NB_SEC_UPLANE_CFG
 */
typedef struct {
    uint        UeId;       /* UE Id (1) */
    uchar       RbId;       /* Rb id */
    nr5g_RbType_v RbType;    /* Radio Bearer Type */
    uchar       CorruptionEnabled;
    nr5g_NbSec_Uplane_Config_t   CorruptionCfg;
    uchar       ReplayEnabled;
    nr5g_NbSec_Uplane_Config_t   ReplayCfg;

} nr5g_pdcp_Ctrl_NB_SEC_UPLANE_t;

/*------------------------------------------------------------------*
 |  SUMMARY OF PRIMITIVES                                           |
 *------------------------------------------------------------------*/

typedef union {

    nr5g_pdcp_Ctrl_ERROR_t         ErrorInd;
    nr5g_pdcp_Ctrl_REJECT_t        RejectInd;
    nr5g_pdpc_Ctrl_INT_FAIL_t      IntFailInd;

    nr5g_pdcp_Ctrl_ACK_t           Ack;
    nr5g_pdcp_Ctrl_NAK_t           Nak;

    nr5g_pdcp_Ctrl_CONFIG_t        ConfigCmd;
    nr5g_pdcp_Ctrl_SDAP_CONFIG_t   SdapConfigCmd;
    nr5g_pdcp_Ctrl_QFI_CONFIG_t    QfiConfigCmd;

    nr5g_pdcp_Ctrl_CONFIG_STATE_t  ConfigStateCmd;

    nr5g_pdcp_Ctrl_RELEASE_t       ReleaseCmd;

    nr5g_pdcp_Ctrl_SET_SEC_UE_CMDt SetSecUeCmd;
    nr5g_pdcp_Ctrl_SET_SEC_UE_ACKt SetSecUeAck;
    nr5g_pdcp_Ctrl_SET_SEC_UE_NAKt SetSecUeNak;

    nr5g_pdcp_Ctrl_STAT_UE_REQt    StatUeReq;
    nr5g_pdcp_Ctrl_STAT_UE_INDt    StatUeInd;

    nr5g_pdcp_Ctrl_SIB_FILTER_CMDt SibFilterCmd;
    nr5g_pdcp_Ctrl_SIB_FILTER_ACKt SibFilterAck;
    nr5g_pdcp_Ctrl_SIB_FILTER_NAKt SibFilterNak;

    nr5g_pdcp_Ctrl_NB_SEC_UPLANE_t NbSecUplane;

    nr5g_pdcp_Ctrl_UE_LOOP_A_START_CMDt UeLoopAStartCmd;
    nr5g_pdcp_Ctrl_UE_LOOP_STOP_CMDt    UeLoopStopCmd;
    nr5g_pdcp_Ctrl_UE_LOOP_ACKt         UeLoopAck;
    nr5g_pdcp_Ctrl_UE_LOOP_NAKt         UeLoopNak;

} nr5g_pdcp_Ctrl_PRIMt;


#pragma pack()
#endif
