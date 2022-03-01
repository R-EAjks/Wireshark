#ifndef lte_rlcmac_Cmac_DEFINED
#define lte_rlcmac_Cmac_DEFINED

#include "lte.h"
#include "sdrLteStruct.h"
#include "sdrdrv-lte-def.h"
#include "lte-rlcmac_Com.h"

#define lte_rlcmac_Cmac_VERSION   "2.32.1"

/*
 * References used in this interface:
 *
 * [MAC] 3GPP TS 36.321 V8.4.0 (LTE MAC protocol).
 * [RRC] 3GPP TS 36.331 V8.4.0 (LTE RRC protocol).
 * [PHY Pro] 3GPP TS 36.213 V8.5.0 (LTE physical layer procedures).
 *
 * This references can be used to indicate where a specific parameter is defined, with the exact name in that reference. For example:
 *
 * uchar MaxHarqTx;  [RRC]: maxHARQ-Tx
 *
 * means that the parameter 'MaxHarqTx' can be found in [RRC] (the RRC spec.) called 'maxHARQ-Tx'.
 * If not otherwise stated, the values and range in [RRC] must be considered valid.
 */

#pragma pack(1)

/*
 * CMAC SAP
 */

#define lte_rlcmac_Cmac_LAA_CONFIG_CMD  0x64
#define lte_rlcmac_Cmac_LAA_CONFIG_ACK  (0x100 + lte_rlcmac_Cmac_LAA_CONFIG_CMD)
#define lte_rlcmac_Cmac_LAA_CONFIG_NAK  (0x200 + lte_rlcmac_Cmac_LAA_CONFIG_CMD)

#define lte_rlcmac_Cmac_CONFIG_CMD      0x02
#define lte_rlcmac_Cmac_CONFIG_ACK      (0x100 + lte_rlcmac_Cmac_CONFIG_CMD)
#define lte_rlcmac_Cmac_CONFIG_NAK      (0x200 + lte_rlcmac_Cmac_CONFIG_CMD)

/* This primitive is used to request for setup, release and configuration
 * of transport channels in MAC debug mode.
 * The UE use directly a pre-assigned C-RNTI (Static C-RNTI).
 * RA info not used.
 * Uplink SPS is considered not active. */

#define lte_rlcmac_Cmac_DEB_CONFIG_CMD      0x50
#define lte_rlcmac_Cmac_DEB_CONFIG_ACK      (0x100 + lte_rlcmac_Cmac_DEB_CONFIG_CMD)
#define lte_rlcmac_Cmac_DEB_CONFIG_NAK      (0x200 + lte_rlcmac_Cmac_DEB_CONFIG_CMD)

#define lte_rlcmac_Cmac_DEB_RACH_ACC_CMD      0x51
#define lte_rlcmac_Cmac_DEB_RACH_ACC_ACK      (0x100 + lte_rlcmac_Cmac_DEB_RACH_ACC_CMD)
#define lte_rlcmac_Cmac_DEB_RACH_ACC_NAK      (0x200 + lte_rlcmac_Cmac_DEB_RACH_ACC_CMD)

#define lte_rlcmac_Cmac_RRC_STATE_CFG_CMD   0x03
#define lte_rlcmac_Cmac_RRC_STATE_CFG_ACK  (0x100 + lte_rlcmac_Cmac_RRC_STATE_CFG_CMD)
#define lte_rlcmac_Cmac_RRC_STATE_CFG_NAK  (0x200 + lte_rlcmac_Cmac_RRC_STATE_CFG_CMD)

#define lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD   0x09
#define lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_ACK  (0x100 + lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD)
#define lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_NAK  (0x200 + lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD)

#define lte_rlcmac_Cmac_RESET_CMD   0x05
#define lte_rlcmac_Cmac_RESET_ACK  (0x100 + lte_rlcmac_Cmac_RESET_CMD)
#define lte_rlcmac_Cmac_RESET_NAK  (0x200 + lte_rlcmac_Cmac_RESET_CMD)

#define lte_rlcmac_Cmac_RELEASE_CMD   0xA1
#define lte_rlcmac_Cmac_RELEASE_ACK  (0x100 + lte_rlcmac_Cmac_RELEASE_CMD)
#define lte_rlcmac_Cmac_RELEASE_NAK  (0x200 + lte_rlcmac_Cmac_RELEASE_CMD)

#define lte_rlcmac_Cmac_STATUS_REQ           0x07
#define lte_rlcmac_Cmac_STATUS_IND           0x404
#define lte_rlcmac_Cmac_CELL_STATUS_IND      0x405
#define lte_rlcmac_Cmac_DCI62_DII_IND        0x406
#define lte_rlcmac_Cmac_STATUS_CNF           0x407
#define lte_rlcmac_Cmac_DCIN2_DII_IND        0x408

#define lte_rlcmac_Cmac_MEAS_SET_CMD    0x06
#define lte_rlcmac_Cmac_MEAS_SET_ACK    (0x100 + lte_rlcmac_Cmac_MEAS_SET_CMD)
#define lte_rlcmac_Cmac_MEAS_SET_NAK    (0x200 + lte_rlcmac_Cmac_MEAS_SET_CMD)

#define lte_rlcmac_Cmac_ERRPROF_START_CMD  0x08
#define lte_rlcmac_Cmac_ERRPROF_START_ACK  (0x100 + lte_rlcmac_Cmac_ERRPROF_START_CMD)
#define lte_rlcmac_Cmac_ERRPROF_START_NAK  (0x200 + lte_rlcmac_Cmac_ERRPROF_START_CMD)

#define lte_rlcmac_Cmac_FAST_FADING_CMD   0x04
#define lte_rlcmac_Cmac_FAST_FADING_ACK  (0x100 + lte_rlcmac_Cmac_FAST_FADING_CMD)
#define lte_rlcmac_Cmac_FAST_FADING_NAK  (0x200 + lte_rlcmac_Cmac_FAST_FADING_CMD)

#define lte_rlcmac_Cmac_CELL_STATUS_REQ   0xA0
#define lte_rlcmac_Cmac_CELL_STATUS_ACK  (0x100 + lte_rlcmac_Cmac_CELL_STATUS_REQ)
#define lte_rlcmac_Cmac_CELL_STATUS_NAK  (0x200 + lte_rlcmac_Cmac_CELL_STATUS_REQ)

/*
 * STAT SAP
 */
#define  lte_rlcmac_Cmac_STAT_CELL_CMD       0x01
#define  lte_rlcmac_Cmac_STAT_CELL_ACK      (0x100 + lte_rlcmac_Cmac_STAT_CELL_CMD)
#define  lte_rlcmac_Cmac_STAT_CELL_NAK      (0x200 + lte_rlcmac_Cmac_STAT_CELL_CMD)

#define  lte_rlcmac_Cmac_STAT_UE_CMD         0x02
#define  lte_rlcmac_Cmac_STAT_UE_ACK        (0x100 + lte_rlcmac_Cmac_STAT_UE_CMD)
#define  lte_rlcmac_Cmac_STAT_UE_NAK        (0x200 + lte_rlcmac_Cmac_STAT_UE_CMD)

#define  lte_rlcmac_Cmac_STAT_MBMS_CMD       0x03
#define  lte_rlcmac_Cmac_STAT_MBMS_ACK      (0x100 + lte_rlcmac_Cmac_STAT_MBMS_CMD)
#define  lte_rlcmac_Cmac_STAT_MBMS_NAK      (0x200 + lte_rlcmac_Cmac_STAT_MBMS_CMD)

#define  lte_rlcmac_Cmac_STAT_NET_MBMS_CMD   0x04
#define  lte_rlcmac_Cmac_STAT_NET_MBMS_ACK   (0x100 + lte_rlcmac_Cmac_STAT_NET_MBMS_CMD)
#define  lte_rlcmac_Cmac_STAT_NET_MBMS_NAK   (0x200 + lte_rlcmac_Cmac_STAT_NET_MBMS_CMD)

/*
 * TEST SAP
 */
#define  lte_rlcmac_Cmac_TEST_JITTER_REQ     0x01
#define  lte_rlcmac_Cmac_TEST_JITTER_IND     (0x400 + lte_rlcmac_Cmac_TEST_JITTER_REQ)

#define lte_rlcmac_Cmac_TEST_DEBUG_CFG_CMD       0x02
#define lte_rlcmac_Cmac_TEST_DEBUG_CFG_ACK       (0x100 + lte_rlcmac_Cmac_TEST_DEBUG_CFG_CMD)
#define lte_rlcmac_Cmac_TEST_DEBUG_CFG_NAK       (0x200 + lte_rlcmac_Cmac_TEST_DEBUG_CFG_CMD)



/*
 * SCHED SAP
 */
#define  lte_rlcmac_Cmac_SCHED_CFG_CMD      0x01
#define  lte_rlcmac_Cmac_SCHED_CFG_ACK      (0x100 + lte_rlcmac_Cmac_SCHED_CFG_CMD)
#define  lte_rlcmac_Cmac_SCHED_CFG_NAK      (0x200 + lte_rlcmac_Cmac_SCHED_CFG_CMD)

#define  lte_rlcmac_Cmac_SCHED_CLOSE_CMD    0x02
#define  lte_rlcmac_Cmac_SCHED_CLOSE_ACK    (0x100 + lte_rlcmac_Cmac_SCHED_CLOSE_CMD)
#define  lte_rlcmac_Cmac_SCHED_CLOSE_NAK    (0x200 + lte_rlcmac_Cmac_SCHED_CLOSE_CMD)

#define  lte_rlcmac_Cmac_SCHED_INFO_CMD     0x03
#define  lte_rlcmac_Cmac_SCHED_INFO_ACK     (0x100 + lte_rlcmac_Cmac_SCHED_INFO_CMD)
#define  lte_rlcmac_Cmac_SCHED_INFO_NAK     (0x200 + lte_rlcmac_Cmac_SCHED_INFO_CMD)

/*
 * MBMS SAP
 */
#define lte_rlcmac_Cmac_MBMS_MCCH_ACQUISITION_CMD   0x01
#define lte_rlcmac_Cmac_MBMS_MCCH_ACQUISITION_ACK   (0x100 + lte_rlcmac_Cmac_MBMS_MCCH_ACQUISITION_CMD)
#define lte_rlcmac_Cmac_MBMS_MCCH_ACQUISITION_NAK   (0x200 + lte_rlcmac_Cmac_MBMS_MCCH_ACQUISITION_CMD)

#define lte_rlcmac_Cmac_MBMS_AREA_CONFIG_CMD        0x02
#define lte_rlcmac_Cmac_MBMS_AREA_CONFIG_ACK        (0x100 + lte_rlcmac_Cmac_MBMS_AREA_CONFIG_CMD)
#define lte_rlcmac_Cmac_MBMS_AREA_CONFIG_NAK        (0x200 + lte_rlcmac_Cmac_MBMS_AREA_CONFIG_CMD)

#define lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_CMD     0x03
#define lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_ACK     (0x100 + lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_CMD)
#define lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_NAK     (0x200 + lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_CMD)

/*------------------------------------------------------------------*
 |  STRUCTURES USED IN PRIMITIVES                                   |
 *------------------------------------------------------------------*/

/*
 * PHYSICAL CHANNELS CONFIGURATION
 */
typedef sdrLte_Sib lte_rlcmac_Cmac_Sib;
typedef sdrLte_SibBR lte_rlcmac_Cmac_SibBR;
typedef sdrLte_SibNB lte_rlcmac_Cmac_SibNB;
typedef sdrLte_MbsfnSubframeConfig lte_rlcmac_Cmac_MbsfnSubframeConfig;
typedef sdrLte_SibData lte_rlcmac_Cmac_SibData;
typedef sdrLte_Tdd lte_rlcmac_Cmac_Tdd;
typedef sdrLte_DedPhyChannelCfg lte_rlcmac_Cmac_DedPhyChannelCfg;
typedef sdrLte_DedPhyChannelCfgNB lte_rlcmac_Cmac_DedPhyChannelCfgNB;
typedef sdrLte_PrachBR lte_rlcmac_Cmac_PrachBR;
typedef sdrLte_RntiLaaCfg lte_rlcmac_Cmac_RntiLaaCfg;

typedef struct
    {
    ushort        UlBandwidth;    // Uplink transmission bandwidth configuration (NRB)
                                  // [6, 15, 25, 50, 75, 100]
    uint          UlEarfcn;       // Uplink Radio Frequency Channel Number
                                  
    uchar         AddEmission;    // Additional spectrum emission defined in [36.101]
                                  // (0, 31)
    sdrLte_SibData SibData;

    } lte_rlcmac_Cmac_PhChannelsCfg;

typedef struct
    {
    uchar               UlBandwidth;    // Uplink transmission bandwidth configuration (NRB)
                                        // [6, 15, 25, 50, 75, 100]
                                        // 0xFF in case of cell PRECONFIG
    uchar               Valid;          // 0 -> message not valid (cell PRECONFIG and CONFIG for cell BR have to be
                                        // considered as not valid)
                                        // 1 -> default value (message valid)
                                        // This field has been added to maintain the consistency between a legacy cell and a BR one
    uint                UlEarfcn;       // Uplink Radio Frequency Channel Number

    uchar               AddEmission;    // Additional spectrum emission defined in [36.101]
                                        // (0, 31)
    sdrLte_SibData      SibData;
    sdrLte_SibDataBR    SibDataBR;

    } lte_rlcmac_Cmac_PhChannelsCfgBR;

typedef struct
    {
    uchar               UlBandwidth;    // Uplink transmission bandwidth configuration (NRB)
                                        // [6, 15, 25, 50, 75, 100]
                                        // 0xFF in case of cell PRECONFIG
    uchar               Valid;          // 0 -> message not valid ( cell PRECONFIG and CONFIG for cell NB-IoT have to be
                                        // considered as not valid ) 
                                        // 1 -> default value ( message valid )
                                        // This field has been added to mantain the consistency between a legacy cell and a NB-IoT one 
    uint                UlEarfcn;       // Uplink Radio Frequency Channel Number

    uchar                AddEmission;    // Additional spectrum emission defined in [36.101]
                                        // (0, 31)
    sdrLte_SibDataNB     SibDataNB;     // Physical channel configuration according to SIB-NB content

    } lte_rlcmac_Cmac_PhChannelsCfgNB;


/*
*  RB INFORMATION ELEMENT
*/
typedef struct {

    uchar   LchId;
    uchar   LchGroupId;         /* -1 for none */
    uchar   LchPrio;
    uint    PrioBitRate;        /* [kBytes/sec, -1 for "infinity"] */
    uint    BucketSizeDuration; /* [ms] */
    uchar   SR_Mask;            /* set means 'setup' */
    uchar   logicalChannelSR_Prohibit_r12;  /* TRUE means enabled */
    uint    bitRateQueryProhibitTimer;  /* [ms, -1 means "not configured"] */
} lte_rlcmac_Cmac_TxLchInfo_t;

typedef struct {

    uchar   LchId;

} lte_rlcmac_Cmac_RxLchInfo_t;

typedef struct {

    lte_rlcmac_Cmac_TxLchInfo_t  TxLchInfo;

    lte_rlcmac_Cmac_RxLchInfo_t  RxLchInfo;

} lte_rlcmac_Cmac_RbMappingInfo_t;


typedef struct {

    lte_RbType_v                      RbType;
    uchar                             RbId;
    lte_rlcmac_Cmac_RbMappingInfo_t   RbMappingInfo;

//  uchar                             TrchMaxNumULTx; /* TODO non dovrebbe servire */

} lte_rlcmac_Cmac_RbCfg_t;


typedef struct {

    lte_RbType_v           RbType;
    uchar                  RbId;

} lte_rlcmac_Cmac_RbRel_t;


typedef struct {

    /* RB to be added or re-configured */
    uchar                        NumOfRbCfg;
    lte_rlcmac_Cmac_RbCfg_t      RbCfg[1];

    /* RB to be released */
    uchar                        NumOfRbRel;
    lte_rlcmac_Cmac_RbRel_t      RbRel[1];
    
} lte_rlcmac_Cmac_RbInfoElem_t;


typedef struct {
    int     DeltaPreambleMsg3;      /* [dBm] */
    uchar   Num_Preambles;          /* Must be != 0. Used to determine the total number of 
                                    RA preambles that UE can select. */
    uchar   Size_PreamblesGroupA;   /* (MESSAGE_SIZE_GROUP_A) Size of the group A of RA preambles.
                                    Group B is constituted by the 
                                    remaining RA preambles out of the 
                                    "Number of RA preambles". */
    uchar   MessageSizeGroupA;      /*  */
    int     MessagePowerOffsetGroupB;   /* [dBm, 0x80000000 means "-infinity"] */
    int     PowerRampingStep;       /* [dB] */
    int     PreambleInitialReceivedTargetPower; /* [dBm] */
    uint    PreambleTransMax;       /* Max number of RACH preamble trasmissions */
    uchar   RA_ResponseWindowSize;  /* Random Access response window [ms] */
    uint    ContentionResolutionTimer;  /* [ms] */

    uint    MaxMsg3_HARQ_Tx;
    
    uint    Prach_ConfigurationIndex;
    
    uint    TimeAlignmentTimerCommon; /* [RRC]: timeAlignmentTimerCommon, [MAC]: "Time Alignment Timer" 
                                         [ms, -1 means infinity] */
    
    
    /* uchar                            NumSC = 0; Valid only zero */
    lte_rlcmac_Cmac_DedPhyChannelCfg DefPhRntiCfg;  /* Default configuration for T-RNTI's */
    
} lte_rlcmac_Cmac_RA_Info_t;

typedef struct {
    uchar   prach_ConfigIndex; /* Set of PRACH resources in the Serving Cell */

    struct {
        uchar   firstPreamble;
        uchar   lastPreamble;
    } PreambleMappingInfo; /* the groups of Random Access Preambles and the set of available Random Access Preambles in each group. */

    uint maxNumPreambleAttemptCE; /* maximum number of preamble transmission */
    uint RA_ResponseWindowSize; /* RA response window size (SpCell only) */
    uint ContentionResolutionTimer; /* the Contention Resolution Timer (SpCell only) */

    struct {
        uchar n;
        uchar elem[2];
    } mpdcch_NarrowbandsToMonitor; /* Narrowbands to monitor */ // TODO capire se serve anche a L1

} lte_rlcmac_Cmac_RA_Info_CE_t;

typedef struct {
    struct {
        uchar n;
        uchar elem[sdrLteMAXCE_LEVEL-1];
    } RSRP_ThresholdsPrachInfoList; /* the criteria to select PRACH resources */

    int     powerRampingStep;                   /* [dB] */
    int     preambleInitialReceivedTargetPower; /* [dBm] */
    uint preambleTransMax_CE; /* the maximum number of preamble transmission */

    lte_rlcmac_Cmac_RA_Info_CE_t RA_Info_CE[sdrLteMAXCE_LEVEL]; /* Valid elements are first (RSRP_ThresholdsPrachInfoList.n + 1) 
                                                                    First elem. is for CE level 0, second for CE level 1 and so on. */

} lte_rlcmac_Cmac_RA_Info_BR_t;

typedef enum {
    
    lte_rlcmac_Cmac_SCMSG3_RangeStart_zero = 0,
    lte_rlcmac_Cmac_SCMSG3_RangeStart_oneThird = 1,
    lte_rlcmac_Cmac_SCMSG3_RangeStart_twoThird = 2,
    lte_rlcmac_Cmac_SCMSG3_RangeStart_one = 3,
    
} lte_rlcmac_Cmac_SCMSG3_RangeStart_e;
typedef uchar lte_rlcmac_Cmac_SCMSG3_RangeStart_v;

typedef struct {
    /* These values are the same among anchor and non-anchor carriers */
    uint ContentionResolutionTimer; /* Timer for contention resolution (SpCell only) */
    uint RA_ResponseWindowSize; /* Duration of the RA response window (SpCell only) */

    /* These values should be carrier specific, but if not explicitly specified they must be taken from anchor carrier */
    uint maxNumPreambleAttemptCE; /* Maximum number of preamble transmission attempts per NPRACH resource */
    uint numRepetitionsPerPreambleAttempt; /* Number of NPRACH repetitions per attempt for each NPRACH resource */

    /* These values are carrier specific */
    uint nprach_SubcarrierOffset; /* Frequency location of the NPRACH resource. In number of sub-carriers, offset from sub-carrier 0 */
    uint nprach_NumSubcarriers; /* Number of sub-carriers in a NPRACH resource */
    lte_rlcmac_Cmac_SCMSG3_RangeStart_v nprach_SubcarrierMSG3_RangeStart;
    uint nprach_NumCBRA_StartSubcarriers; /* The number of start subcarriers for contention based random access (0xffffffff means not supported) */
    uint nprach_Periodicity; /* Periodicity of a NPRACH resource */
    uint nprach_StartTime; /* Start time of the NPRACH resource in one period */

} lte_rlcmac_Cmac_NPrach_ParametersList_t;

typedef struct {
    
    struct {
        uchar n;
        uchar elem[sdrLteMAXNPRACH_RES-1];
    } RSRP_ThresholdsPrachInfoList; /* the criteria to select PRACH resources */

    int     powerRampingStep;                   /* [dB] */
    int     preambleInitialReceivedTargetPower; /* [dBm] */
    uint    preambleTransMax_CE;                /* the maximum number of preamble transmission */
    uint    TimeAlignmentTimerCommon; /* [RRC]: timeAlignmentTimerCommon, [MAC]: "Time Alignment Timer"
                                         [ms, -1 means infinity] */

    uint NumNonAnchorCarriers; /* Number of non-anchor carriers. It determines the actual size of NumNonAnchorResources and NPrach_Parameters */
    /* Number of resources for each non-anchor carrier. Must have the same order as NPrach_Parameters */
    uint NumNonAnchorResources[sdrLteMAX_NONANCHORCARRIERS_NB];
    /* Valid elements are first (RSRP_ThresholdsPrachInfoList.n + 1) of sdrLteMAXNPRACH_RES for anchor carrier (-> always index 0)
     * for non-anchor carrier valid elements come from NumNonAnchorResources array.
     * Must have same order as Nprach_Parameters from sdrLte_ULNonAnchorConfigCommonNB -> sdrLte_SibDataNB_02 structure of SDR interface */
    lte_rlcmac_Cmac_NPrach_ParametersList_t NPrach_Parameters[1 + sdrLteMAX_NONANCHORCARRIERS_NB][sdrLteMAXNPRACH_RES];
    /* NPRACH selection probability for each NPRACH resource on the anchor carrier
     * px0, px2, px3, px4, px5, px6, px7, px8, px9, px10, px11, px12, px13, px14, px15, px16 */
    uint NPrach_ProbabilityAnchor[sdrLteMAXNPRACH_RES];

    lte_rlcmac_Cmac_DedPhyChannelCfgNB DefPhRntiCfg; /* Default configuration for T-RNTI's */

} lte_rlcmac_Cmac_RA_Info_NB_t;

typedef struct {

    uchar           active;                     /* SPS UL Flag: 1 -> SPS UL active, 0 -> SPS UL not active */
    uint            SpsRnti;                    /* [RRC]: semiPersistSchedC-RNTI, [-1 for none] */
    ushort          semiPersistSchedIntervalUL; /* [RRC]: semiPersistSchedIntervalUL
                                                    [10, 20, 32, 40, 64, 80, 128, 160, 320, 640] */
    uchar           implicitReleaseAfter;       /* [RRC]: implicitReleaseAfter [2, 3] */
    uchar           twoIntervalsConfig;         /* [RRC]: twoIntervalsConfig [0, 1] */
} lte_rlcmac_Cmac_SpsCfgUl_t;

typedef struct {

    uint onDurationTimer;
    uint drxInactivityTimer;
    uint drxRetransmissionTimer;
    uint longDRXCycle;
    uint drxStartOffset;
    uint drxShortCycleTimer;
    uint shortDRXCycle;

} lte_rlcmac_Cmac_DrxConfig_t;


typedef struct {

    uchar  skipUlTxDynamic;  /* Boolean: 0 False or not present - 1 True */
    uchar  skipUlTxSPS;      /* Boolean: 0 False or not present - 1 True */

} lte_rlcmac_Cmac_SkipUlTx_t;

typedef struct {
    uint            TimeAlignmentTimer;             /* [RRC]: TimeAlignmentTimer, [MAC]: "Time Alignment Timer" 
                                                       [ms, -1 means infinity] */
    uchar           MaxHarqTx;                      /* [RRC]: maxHARQ-Tx, [MAC]: "Maximum number of HARQ transmissions" */
    uint            PeriodicBsrTimer;               /* [ms] */
    uint            RetxBsrTimer;                   /* [ms] */
    uint            PeriodicPowHeadTimer;           /* [ms, -1 means PH not configured
                                                            -2 means infinity] */
    uint            ProhibitPowHeadTimer;           /* [ms] */
    uint            logicalChannelSR_ProhibitTimer_r12; /* [ms] */

    uchar           wb_cqi_cw1;                     /* Wide-band CQI for CW1 
                                                       (always 4 bit for each codeword) */
    uint            sb_cqi_cw1;                     /* Subband differential CQI for CW1 
                                                       (2N bits for reporting mode 3.0 and 3.1 (max 26 bit)) */
    uchar           wb_cqi_cw2;                     /* Wide-band CQI for CW2 
                                                       (always 4 bit for each codeword) */
    uint            sb_cqi_cw2;                     /* Subband differential CQI for CW2
                                                       (2N bits for reporting mode 3.0 and 3.1 (max 26 bit)) */
    uint            pmi;                            /* Precoding matrix indication
                                                       N or 2N bits for reporting mode 1.2 (max 26 bit) */
    uchar           ri;                             /* Simulated Rank Indicator 
                                                       (0 = Rank 1, 1 = Rank 2) */
    uint            R;                              /* Position of the M selected subbands 
                                                       L bits for reporting mode 2.0 and 2.2*/
    int             NormPowHeadr;                   /* Simulated Normalized Power Headroom [dB, 0x7FFFFFFF for none] */
    uint            Pathloss;                       /* Simulated Pathloss */
    lte_rlcmac_Cmac_SpsCfgUl_t SpsCfgUl;            /* [RRC]: sps-Configuration (UL only) */
    
    /* Physical channel elements */
    uchar                               DedPhyChannelType;   /* Indicate what DedPhyChannelCfg is valid
                                                             0 = DedPhyChannelCfg is valid
                                                             1 = DedPhyChannelCfgNB is valid */
    lte_rlcmac_Cmac_DedPhyChannelCfg    DedPhyChannelCfg;    /* Dedicated physical channel configuration */
    lte_rlcmac_Cmac_DedPhyChannelCfgNB  DedPhyChannelCfgNB;  /* Dedicated physical channel configuration for NB-IoT */
    uchar           TtiBundling;                           /* TTI bundling flag (0 = not active, 1 = active) */
    uchar  HoFlag;                      /* Handover flag ( 0 = normal config, 
                                                           1 = prim. is used to configure an HO,
                                                           2 = prim. is used to configure an X2 target HO ) */
   
    lte_rlcmac_Cmac_DrxConfig_t drxConfig;

    lte_rlcmac_Cmac_SkipUlTx_t  skipUlTx;

    uchar extendedPHRFlags; /* Bitmask for extended PHR configuration */
    #define lte_rlcmac_Cmac_EPHR_extendedPHR         0x01   /* extendedPHR enabled */
    #define lte_rlcmac_Cmac_EPHR_extendedPHR2        0x02   /* extendedPHR2 enabled */
    #define lte_rlcmac_Cmac_EPHR_dualConnectivityPHR 0x04   /* dualConnectivityPHR enabled */    

    uchar extendedBSRFlag;      /* 1: use extended-BSR */

    uchar raiActivation;        /* Activation of release assistance indication: booleam MISSING_IE: 0*/

    uchar dataInactivityTimer;   /* Data Innactivity timer in sec (0: Release -  -1 Missing IE)*/

} lte_rlcmac_Cmac_TrchParm_t;

typedef enum {
    
    lte_rlcmac_Cmac_Rrc_State_IDLE = 1,
    lte_rlcmac_Cmac_Rrc_State_SIG_SEGV = 2,
    
} lte_rlcmac_Cmac_Rrc_State_e;
typedef uchar lte_rlcmac_Cmac_Rrc_State_v;

typedef enum {
    
    lte_rlcmac_Cmac_Action_RELEASE_ALL_RLC = 1,
    
} lte_rlcmac_Cmac_Action_e;
typedef uchar lte_rlcmac_Cmac_Action_v;

typedef enum {
    
    lte_rlcmac_Cmac_STATUS_NONE = 0,
    lte_rlcmac_Cmac_STATUS_RA_RECOVER_FROM_PROBLEM = 1, /* (1) */
    lte_rlcmac_Cmac_STATUS_PUCCH_SRS_RELEASE = 2,       /* (2) */
    lte_rlcmac_Cmac_STATUS_RNTI_DUP_RELEASE = 3,        /* (3) */
    lte_rlcmac_Cmac_STATUS_CELL_OUT_OF_SYNC = 4,        /* (4) */
    lte_rlcmac_Cmac_STATUS_CELL_SYNC = 5,               /* (5) */
    lte_rlcmac_Cmac_STATUS_CELL_IN_SERVICE = 7,         /* (8) */
    lte_rlcmac_Cmac_STATUS_CELL_START_UP_FAIL = 8,         /* (8) */
    lte_rlcmac_Cmac_STATUS_UE_DATA_IN_TMR_EXP = 9,         /* (9) (only for lte_rlcmac_Cmac_STATUS_IND_t)*/
    
} lte_rlcmac_Cmac_STATUS_e;
typedef uchar lte_rlcmac_Cmac_STATUS_v;
/*
 * (1) Indicate a Random Access recover from a problem.
 * (2) Indicate a PUCCH/SRS release.
 * (3) Indicate a RNTI Duplication triggering release. (Prop.)
 * (4) The cell is not synchronized
 * (5) The cell is synchronized
 * (8) Cell is in service
 * (9) Cell startup failure (start up has failed: Rach probe or cfg problem)
 */


/*------------------------------------------------------------------*
 |  LAYOUT OF PRIMITIVES                                            |
 *------------------------------------------------------------------*/

/*
 * ACK
 */
typedef struct {

    uint     UeId;
    uint     CellId;

} lte_rlcmac_Cmac_ACK_t;

/*
  NAK
 */

typedef struct {

    uint     UeId;
    uint     CellId;
    short    Err;           /* Error code */

} lte_rlcmac_Cmac_NAK_t;

typedef struct {
    uint CellId;
    uint SCellIndex; /* [1 - 7] */
} lte_rlcmac_Cmac_AddModCellIds_t;

typedef struct {
    uint SCellIndex; /* [1 - 7] */
} lte_rlcmac_Cmac_RelCellIds_t;

typedef struct {
    /* SCells to be added or modified. */
    uchar                           NumOfSCellAddMod;
    lte_rlcmac_Cmac_AddModCellIds_t AddModCellIds[1];

    /* SCells to be released. */
    uchar                           NumOfSCellRel;
    lte_rlcmac_Cmac_RelCellIds_t    RelCellIds[1];
} lte_rlcmac_Cmac_SCellLists_t;

typedef struct {
    /* RA information elements */
    uchar   DedicatedPreamble;          /* Dedicated preamble [1 - 64, -1 for none] (DedicatedPreamble and DedicatedPreambleNB must be mutually exclusive) */
    uchar   DedicatedPrachMaskIndex;    /* PRACH Mask Index [0 - 15, -1 for none] */
    uint    EndTime_DedicatedPreamble;  /* End time dedicated preamble [ms, 0 for none] */
    uint    DedicatedPreambleNB;        /* NB-IOT Dedicated preamble, -1 for none (DedicatedPreamble and DedicatedPreambleNB must be mutually exclusive) */

    uint validPrachBRInfo; /* 1 -> PRACH configuration Common is present (Only for Cat-m Users), 0 -> Otherwise */
    lte_rlcmac_Cmac_PrachBR PrachBRInfo; /* PRACH configuration Common */

    /* RB information elements */
    lte_rlcmac_Cmac_RbInfoElem_t    RbIE;

    /* TRCH information elements */
    lte_rlcmac_Cmac_TrchParm_t TrchParm;

    uint sCellDeactivationTimer;           /* [rf] */
    lte_rlcmac_Cmac_SCellLists_t sCellLists;

} lte_rlcmac_Cmac_CfgParams_t;

/*
lte_rlcmac_Cmac_CONFIG_REQ:
This primitive is used to request for setup, release and configuration
of transport channels.
*/
typedef struct {

    uint   UeId;
    lte_rlcmac_Cmac_CfgParams_t Params;

} lte_rlcmac_Cmac_CONFIG_CMD_t;


/* this primitive is used to activate the UE in debug mode.
 * the UE can use directly a pre-assigned C-RNTI (Static C-RNTI). */
typedef struct {

    uint   UeId;
    
    /* RA information elements */
//  uchar   DedicatedPreamble;          /* Dedicated preamble [1 - 64, -1 for none] */
//  uchar   DedicatedPrachMaskIndex;    /* PRACH Mask Index [0 - 15, -1 for none] */
//  uint    EndTime_DedicatedPreamble;  /* End time dedicated preamble [ms, 0 for none] */
    
    uint   Crnti;                       /* Static C-RNTI */
    
    /* RB information elements */
    lte_rlcmac_Cmac_RbInfoElem_t    RbIE;

    /* TRCH information elements */
    uint            TimeAlignmentTimer;             /* [RRC]: TimeAlignmentTimer, [MAC]: "Time Alignment Timer" */
    uchar           MaxHarqTx;                      /* [RRC]: maxHARQ-Tx, [MAC]: "Maximum number of HARQ transmissions" */
    uint            PeriodicBsrTimer;               /* [ms] */
    uint            RetxBsrTimer;                   /* [ms] */
    uint            PeriodicPowHeadTimer;           /* [ms, -1 means PH not configured] TODO */
    uint            ProhibitPowHeadTimer;           /* [ms] */
    uint            logicalChannelSR_ProhibitTimer_r12; /* [ms] */
    
    uchar           wb_cqi_cw1;                     /* Wide-band CQI for CW1 
                                                       (always 4 bit for each codeword) */
    uint            sb_cqi_cw1;                     /* Subband differential CQI for CW1 
                                                       (2N bits for reporting mode 3.0 and 3.1 (max 26 bit)) */
    uchar           wb_cqi_cw2;                     /* Wide-band CQI for CW2 
                                                       (always 4 bit for each codeword) */
    uint            sb_cqi_cw2;                     /* Subband differential CQI for CW2
                                                       (2N bits for reporting mode 3.0 and 3.1 (max 26 bit)) */
    uint            pmi;                            /* Precoding matrix indication
                                                       N or 2N bits for reporting mode 1.2 (max 26 bit) */
    uchar           ri;                             /* Simulated Rank Indicator 
                                                       (0 = Rank 1, 1 = Rank 2) */
    uint            R;                              /* Position of the M selected subbands 
                                                       L bits for reporting mode 2.0 and 2.2*/
    
    int             NormPowHeadr;                   /* Simulated Normalized Power Headroom [dB, 0x7FFFFFFF for none] */
    uint            Pathloss;                       /* Simulated Pathloss */
//  lte_rlcmac_Cmac_SpsCfg_t SpsCfg;                /* [RRC]: sps-Configuration */
    
    /* Physical channel elements */
    /* uchar                            NumSC = 0; Valid only zero */
    lte_rlcmac_Cmac_DedPhyChannelCfg    DedPhyChannelCfg;  /* Dedicated physical channel configuration */
    uchar           TtiBundling;                    /* TTI bundling flag (0 = not active, 1 = active) */

    lte_rlcmac_Cmac_DrxConfig_t drxConfig;

} lte_rlcmac_Cmac_DEB_CONFIG_CMD_t;

typedef struct {

    uint            UeId;
    uint            TestType;       /* see lte_tm_rlcmac_Cmac_RACH_TYPE_..*/
    uchar           RbId;       /* Rb id  (1)*/
    lte_LchType_v   Lch;        /* Logical Channel Type: lte_CCCH, lte_DCCH (1)*/
        int     MaxUpPwr;       /* Maximum uplink power (in dBm) (1)*/
    int     RSRP;       /* Simulated RSRP [dBm, 0x7FFFFFFF for none] (1)*/
    int     UeCategory;     /* UE category (1)*/
    uchar       Data[1];    /* Data to be transmitted in RA procedure (MAC SDU Msg3) (1)*/

} lte_rlcmac_Cmac_DEB_RACH_ACC_CMD_t;


#define lte_rlcmac_Cmac_RACH_TYPE_PREAMBLE      1  /* Only premable*/
#define lte_rlcmac_Cmac_RACH_TYPE_MSG3_NO_CONT      2  /* Msg3 without waiting for Msg 4*/
#define lte_rlcmac_Cmac_RACH_TYPE_MSG3_CONT             3  /* Do contention resolution */

/*
 *  Notes:
 *
 *  1 Not used in case of TestMode = lte_rlcmac_Cmac_RACH_TYPE_PREAMBLE
 */

#if 0
RELATED TO CIPHERING
/*
 * lte_rlcmac_Cmac_RRC_START_CFG_REQ
 * lte_rlcmac_Cmac_RRC_START_IND
 */
typedef struct {
    NYI
} lte_rlcmac_Cmac_START_CFG_t;
#endif

/*
 * lte_rlcmac_Cmac_RRC_STATE_CFG_CMD
 */
typedef struct {

    uint                          UeId;

    lte_rlcmac_Cmac_Rrc_State_v   State;

} lte_rlcmac_Cmac_RRC_STATE_CFG_CMD_t;

/*
 * lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD
 */
typedef struct {

    uint                          Spare;      /* must be set to -1 */
    uint                          CellId;

    lte_rlcmac_Cmac_Rrc_State_v   State;

} lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD_t;

/*
 * lte_rlcmac_Cmac_RESET_CMD
 */
typedef struct {

    uint                       UeId;

} lte_rlcmac_Cmac_RESET_CMD_t;

/*
 * lte_rlcmac_Cmac_RELEASE_CMD
 */
typedef struct {

    uint                         UeId;
    lte_rlcmac_Cmac_Action_v     Action;
    uint                         Spare[4];


} lte_rlcmac_Cmac_RELEASE_CMD_t;

/*
 * lte_rlcmac_Cmac_STATUS_REQ
 */
typedef struct {

    uint                        UeId;

} lte_rlcmac_Cmac_STATUS_REQ_t;

/*
 * lte_rlcmac_Cmac_STATUS_CNF
 */
typedef struct {

    uint                        UeId;
    short                       Res;  /* Result code (see TODO) */

    /* Status info */
    lte_rlcmac_Cmac_STATUS_v    Status;
    uint                        numberOfPreamblesSent;  /* number of RACH preambles that were transmitted. Corresponds to parameter PREAMBLE_TRANSMISSION_COUNTER in TS 36.321 */
    uchar                       contentionDetected;     /* If set contention was detected for at least one of the transmitted preambles */
    uchar                       maxTxPowerReached;      /* If set the maximum power level was used for the last transmitted preamble */

} lte_rlcmac_Cmac_STATUS_CNF_t;

/*
 * lte_rlcmac_Cmac_STATUS_IND
 */
typedef struct {

    uint                        UeId;

    /* Status info */
    lte_rlcmac_Cmac_STATUS_v    Status;

} lte_rlcmac_Cmac_STATUS_IND_t;


/*
 * lte_rlcmac_Cmac_CELL_STATUS_IND
 */
typedef struct {

    uint                        Spare;
    uint                        CellId;
    uint                        PhyCellId;
    uint                        DlEarfcn;

    /* Status info */
    lte_rlcmac_Cmac_STATUS_v    Status;

    uchar                       Master;         /* Master Cell 0: Slave -- 1: Master*/
    uchar                       CellCfgMsk;     /* Cell configuration mask [see note 0]*/

} lte_rlcmac_Cmac_CELL_STATUS_IND_t;

/*
 *     Note 0 - bit 0 If 1 cell is a legacy LTE cell
 *              bit 1 If 1 cell is a CAT-M cell
 *              bit 2 If 1 cell is a NB cell
 */



/*
lte_rlcmac_Cmac_MEAS_SET_CMD
This primitive is used by client to set measurement values
at MAC and physical level.
*/
typedef struct {
    uint    UeId;
    uchar   wb_cqi_cw1;                     /* Wide-band CQI for CW1 
                                               (always 4 bit for each codeword) (1) */
    uint    sb_cqi_cw1;                     /* Subband differential CQI for CW1 
                                               (2N bits for reporting mode 3.0 and 3.1 (max 26 bit)) (1) */
    uchar   wb_cqi_cw2;                     /* Wide-band CQI for CW2 
                                               (always 4 bit for each codeword) (1) */
    uint    sb_cqi_cw2;                     /* Subband differential CQI for CW2
                                               (2N bits for reporting mode 3.0 and 3.1 (max 26 bit)) (1) */
    uint    pmi;                            /* Precoding matrix indication
                                               N or 2N bits for reporting mode 1.2 (max 26 bit) (1) */
    uchar   ri;                             /* Simulated Rank Indicator 
                                               (0 = Rank 1, 1 = Rank 2) (1) */
    uint    R;                              /* Position of the M selected subbands 
                                               L bits for reporting mode 2.0 and 2.2 (1) */
    int     NormPowHeadr;                   /* Simulated Normalized Power Headroom [dB, 0x7FFFFFFF for none] (2) */
    uint    Pathloss;                       /* Simulated Pathloss [dB, -1 for none] */
} lte_rlcmac_Cmac_MEAS_SET_CMD_t;
/*
 * (1) valid if 'ri != -1'
 * 
 * (2) 'PowHeadr' is reported by MAC in the specific MAC Control PDU.
 * 
 */

#if 0
/*
CMAC_MEASUREMENT_Ind:
This primitive is used to notify RRC of the measurement result
*/
typedef struct {
    NYI
} lte_rlcmac_Cmac_MEASUREMENT_IND_t;
#endif


#if 0
NYI, see if needed
/*
 * lte_rlcmac_Cmac_RESUME_REQ
 */
typedef struct {

    /*
    The parameter UeId contains the descriptors 
    used to identify one MAC entity 
    */
    uint          UeId;

} lte_rlcmac_Cmac_RESUME_t;
#endif

/*
 * lte_rlcmac_Cmac_STAT_CELL_CMD
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
} lte_rlcmac_Cmac_STAT_CELL_CMDt;

/*
 * lte_rlcmac_Cmac_STAT_CELL_ACK
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    lte_rlcmac_Com_Cell_Stat_t Stat1; /* Cell specific statistic (part 1) */

    sdrdrv_ltedef_FddCellStat_t Stat2; /* Cell specific statistic (part 2) */
    
} lte_rlcmac_Cmac_STAT_CELL_ACKt;

/*
 * lte_rlcmac_Cmac_STAT_MBMS_CMD
 */
typedef struct
{
    uint        AreaIdx;
    uint        CellId;
} lte_rlcmac_Cmac_STAT_MBMS_CMDt;

/*
 * lte_rlcmac_Cmac_STAT_MBMS_ACK
 */
typedef struct
{
    uint        AreaIdx;
    uint        CellId;

    lte_rlcmac_Com_Mbms_Stat_t Stat; /* MBMS Rx statistics */
} lte_rlcmac_Cmac_STAT_MBMS_ACKt;

/*
 * lte_rlcmac_Cmac_STAT_NET_MBMS_CMD
 */
typedef struct
{
    uint        AreaIdx;
    uint        CellId;
} lte_rlcmac_Cmac_STAT_NET_MBMS_CMDt;

/*
 * lte_rlcmac_Cmac_STAT_NET_MBMS_ACK
 */
typedef struct
{
    uint        AreaIdx;
    uint        CellId;

    lte_rlcmac_Com_Net_Mbms_Stat_t Stat; /* MBMS Tx (NET) statistics */
} lte_rlcmac_Cmac_STAT_NET_MBMS_ACKt;

/*
 * lte_rlcmac_Cmac_STAT_MBMS_NACK
 */
typedef struct
{
    uint        AreaIdx;
    uint        CellId;
    short       Err;   /* Error code */

} lte_rlcmac_Cmac_STAT_MBMS_NACKt;

/*
 * lte_rlcmac_Cmac_STAT_UE_CMD
 */
typedef struct
{
    uint    UeId;           /* UE Identifier */
    
} lte_rlcmac_Cmac_STAT_UE_CMDt;

/*
 * lte_rlcmac_Cmac_STAT_UE_ACK
 */
typedef struct
{
    uint    UeId;           /* UE Identifier */
    uint    CellId;         /* Cell Identifier */
    uchar   SCellIdx;       /* Secondary Cell Identifier */
    uchar   IsLast;         /* Last statistics flag:
                               0 -> other statistics will follow (current is not the last one), 1 -> last statistic, 2 -> statistic procedure aborted */
    uchar   Spare[2];
    
    lte_rlcmac_Com_Stat_t     Stat1;  /* Ue specific statistics (part 1) */
    
    sdrdrv_ltedef_FddUeStat_t Stat2;  /* Ue specific statistics (part 2) */
    
} lte_rlcmac_Cmac_STAT_UE_ACKt;

typedef struct
{
    uint    UeId;           /* UE Identifier */
    
} lte_rlcmac_Cmac_ERRPROF_START_CMD_t;

/*
 * lte_rlcmac_Cmac_FAST_FADING_CMD
 */
typedef struct {

    lte_Id_t   id;          /* User/Cell Identifier */
    char       FadingSim[]; /* ASCIIZ fading simulation file name */

} lte_rlcmac_Cmac_FAST_FADING_CMD_t;

/*
 * lte_rlcmac_Cmac_TEST_JITTER_REQ
 * lte_rlcmac_Cmac_TEST_JITTER_IND
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    uchar       Pattern[8]; /* Can be filled with any value */
    uint        Ui;         /* User information */
    uint        Ts0;        /* Tx req TS on client */
    uint        Ts1;        /* Rx req TS on server */
    uint        Ts2;        /* Tx req TS on server */
    uint        Ts3;        /* Rx req TS on process */
    uint        Ts4;        /* Tx ind TS on process */
    uint        Ts5;        /* Rx ind TS on server */
    uint        Ts6;        /* Tx ind TS on server */
    
} lte_rlcmac_Cmac_TEST_JITTERt;

/*
 * lte_rlcmac_Cmac_TEST_DEBUG_CFG_CMD
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;

    uchar       Param[]; /* Debug Cfg parameters */
} lte_rlcmac_Cmac_TEST_DEBUG_CFG_CMD_t;

/*
 * lte_rlcmac_Cmac_SCHED_CFG_CMD
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    uint        SlotSize;   /* number of frames considered as a slot */
    ushort      NumSlot;    /* Number of requested Slots [2] */
    
} lte_rlcmac_Cmac_SCHED_CFG_CMDt;

/*
 * lte_rlcmac_Cmac_SCHED_CFG_ACK
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    uint        ExtSfn;   /* Current Extended Subframe Number */
    
} lte_rlcmac_Cmac_SCHED_CFG_ACKt;


/*
 * lte_rlcmac_Cmac_SCHED_CLOSE_CMD
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
} lte_rlcmac_Cmac_SCHED_CLOSE_CMDt;


/*
 * lte_rlcmac_Cmac_SCHED_INFO_CMD
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
} lte_rlcmac_Cmac_SCHED_INFO_CMDt;

/*
 * lte_rlcmac_Cmac_SCHED_INFO_ACK
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    uint        ExSbf;       /* Extended Subframe Number [3] */
    ushort      NumSlot;     /* Number of slot in a NBR list */
    ushort      NumUlRnti;   /* Number on RNTI in RNTI list */
    uchar       NumUlMcs;    /* Number on MCS in MCS list */
    ushort      NumDl0Rnti;  /* Number on RNTI in RNTI list */
    uchar       NumDl0Mcs;   /* Number on MCS in MCS list */
    ushort      NumDl1Rnti;  /* Number on RNTI in RNTI list */
    uchar       NumDl1Mcs;   /* Number on MCS in MCS list */
    
    /*
    ### UL RNTI list ###
    ushort      Rnti_0;
    ushort      Nrbr_0[NumSlot]; # NRB list for Rnti_0
    
    ushort      Rnti_1;
    ushort        Nrbr_1[NumSlot]; # NRB list for Rnti_1
    
    ...
    
    ushort      Rnti_N; // N = NumRnti
    ushort      Nrbr_N[NumSlot]; # NRB list for Rnti_N
    
    ### UL MCS list ###
    uchar       Mcs_0;
    ushort      Nrbm_0[NumSlot]; # NRB list for Mcs_0
    
    uchar       Mcs_1;
    ushort      Nrbm_1[NumSlot]; # NRB list for Mcs_1
    
    ...
    
    uchar       Mcs_M; // M = NumMcs
    ushort      Nrbm_N[NumSlot]; # NRB list for Mcs_M
    
    ### DL RNTI list for codeword 0 ###
    [same as UL RNTI list]
    
    ### DL MCS list for codeword 0 ###
    [same as UL MCS list]
    
    ### DL RNTI list for codeword 1 ###
    [same as UL RNTI list]
    
    ### DL MCS list for codeword 1 ###
    [same as UL MCS list]
     */
    
} lte_rlcmac_Cmac_SCHED_INFO_ACKt;
/*
 * NOTES:
 * 
 * [1] The Len field of the primitive is the total length considering all lists inside the message.
 * [2] The slot is the SBF interval for which number of RB is reported.
 * [3] Extended Subframe Number is equal to: 
 *      SFN*10+SBF, where
 *     SFN : is the System Frame Number
 *     SBF : is the Subframe Number
 */

/* The IE MBMS-NotificationConfig specifies the MBMS notification related configuration parameters, that are
 * applicable to all MBSFN areas
 */
typedef struct NotificationConfig_t {
    uchar NotificationRepetitionCoeff; /* Actual change notification repetition period common for all MCCHs that are
                                        *  configured = shortest modification period / notificationRepetitionCoeff. The
                                        *  "shortest modification period" corresponds with the lowest value of
                                        *  mcch-ModificationPeriod of all MCCHs that are configured. [0 -> n2, 1 -> n4]
                                        */
    uchar NotificationOffset;          /* Indicates, together with the notificationRepetitionCoeff, the radio frames in
                                        * which the MCCH information change notification is scheduled i.e. the MCCH
                                        * information change notification is scheduled in radio frames for which:
                                        * SFN mod(notification repetition period) = notificationOffset. [0-10]
                                        */
    uchar NotificationSFIndex;         /* Indicates the subframe used to transmit MCCH change notifications on PDCCH.
                                        * Different from FDD to TDD
                                        */
    uchar Spare;
} lte_rlcmac_Cmac_NotificationConfig;

/* The IE MCCH-Config contains the information required to configure
 * the MCCH associated with an MBSFN area
 */
typedef struct McchConfig_t {
    uchar McchRepetitionPeriod;    /* Defines the interval between transmissions of MCCH information, in radio frames.
                                    * [0 -> rf32, 1 -> rf64, 2 -> rf128, 3 -> rf256]
                                    */
    uchar McchOffset;              /* Indicates, together with the mcch-RepetitionPeriod, the radio frames in which MCCH
                                    * is scheduled i.e. MCCH is scheduled in radio frames for which:
                                    * SFN mod(mcch-RepetitionPeriod) = (mcch-Offset). [0-10]
                                    */
    uchar McchModificationPeriod;  /* Defines periodically appearing boundaries, i.e. radio frames for which
                                    * SFN mod(mcch-ModificationPeriod) = 0. [0 -> rf512, 1 -> rf1024]
                                    */
    uchar SfAllocInfo;             /* Indicates the subframes of the radio frames indicated by the mcch-RepetitionPeriod
                                    * and the mcch-Offset, that may carry MCCH. Value “1” indicates that the corresponding
                                    * subframe is allocated. Different from FDD to TDD
                                    */
    uchar SignallingMCS;           /* Indicates the Modulation and Coding Scheme (MCS) applicable for the subframes indicated
                                    * by the field sf-AllocInfo and for each (P)MCH that is configured for this MBSFN area,
                                    * for the first subframe allocated to the (P)MCH within each MCH scheduling period.
                                    * [0 -> n2, 1 -> n7, 2 -> n13, 3 -> n19]
                                    */
    uchar Spare[3];
} lte_rlcmac_Cmac_McchCfg;

/* The IE MBSFN-AreaInfoList contains the information required to acquire
 * the MBMS control information associated with one or more MBSFN areas
 */
typedef struct MBSFN_AreaInfo_t {
    uchar MbsfnAreaId;           /* Indicates the MBSFN area ID. [0-255] */
    uchar NonMBSFNregionLength;  /* Indicates how many symbols from the beginning of the subframe constitute
                                  * the non-MBSFN region. This value applies in all subframes of the MBSFN area
                                  * used for PMCH transmissions as indicated in the MSI. [0 -> 1 symbol, 1 -> 2 symbols]
                                  */
    uchar NotificationIndicator; /* Indicates which PDCCH bit is used to notify the UE about change of the MCCH applicable
                                  * for this MBSFN area. Value 0 corresponds with the least significant bit. [0-7]
                                  */
    uchar RbId;                  /* MCCH RbId in range: 33-40 => area 0 -> rbId 33, ..., area 7 -> rbId 40 */
    lte_rlcmac_Cmac_McchCfg McchConfig;
    /* lte_rlcmac_Crlc_RxUmParm_t: Start */
    uint  TimerReordering;
    uchar SnLength;
    /* lte_rlcmac_Crlc_RxUmParm_t: End */
    uchar AreaIdx;               /* 0, ..., 7 */
    uchar AcquisitionFlag;       /* If set to 1 then Area Info must be always acquired */
    uchar Spare;
} lte_rlcmac_Cmac_AreaInfo;

/* lte_rlcmac_Cmac_MBMS_MCCH_ACQUISITION_CMD:
 * MBMS control information provided on the BCCH can be taken from SIB13
 * It contains the information required to acquire the MBMS control
 * information associated with one or more MBSFN areas
 */
typedef struct lte_rlcmac_Cmac_MBMS_MCCH_ACQUISITION_t {
    uint Spare; /* must be set to -1 */
    uint CellId;

    /* IE MBMS-NotificationConfig */
    lte_rlcmac_Cmac_NotificationConfig NotificationConfig;

    /* IE MBSFN-AreaInfoList */
    uchar Spare1[3];
    char NumOfAreaInfo; /* MBSFN-AreaInfoList is a sequence of MBSFN-AreaInfo. [1-maxMBSFN-Area(8)] */
    lte_rlcmac_Cmac_AreaInfo AreaInfoList[0];
} lte_rlcmac_Cmac_MbmsMcchAcquisition;

typedef struct MBMS_SessionInfo_t {
    uchar LogicalChannelIdentity; /* [0-28] */

    uchar Spare[3];
} lte_rlcmac_Cmac_SessionInfo;

typedef struct PMCH_Config_t {
    ushort SfAllocEnd;          /* Indicates the last subframe allocated to this (P)MCH within a period identified by field
                                 * commonSF-AllocPeriod. [0-1535]
                                 */
    uchar DataMCS;              /* Defines the Modulation and Coding Scheme (MCS) applicable for the subframes of this
                                 * (P)MCH as indicated by the field commonSF-Alloc. [0-28]
                                 */
    uchar MchSchedulingPeriod;  /* Indicates the MCH scheduling period i.e. the periodicity used for providing MCH scheduling
                                 * information at lower layers (MAC) applicable for an MCH. The mch-SchedulingPeriod starts in
                                 * the radio frames for which: SFN mod(mch-SchedulingPeriod) = 0. E-UTRAN configures
                                 * mch-SchedulingPeriod of the (P)MCH listed first in PMCH-InfoList to be smaller than or equal
                                 * to mcch-RepetitionPeriod.
                                 * [0 -> rf8, 1 -> rf16, 2 -> rf32, 3 -> rf64, 4 -> rf128, 5 -> rf256, 6 -> rf1024]
                                 */
} lte_rlcmac_Cmac_PmchConfig;

/* The IE PMCH-InfoList specifies configuration of all PMCHs of an MBSFN area. The information provided for an
 * individual PMCH includes the configuration parameters of the sessions that are carried by the concerned PMCH */
typedef struct PMCH_Info_t {
    /* IE MBSFN-PMCHConfig */
    lte_rlcmac_Cmac_PmchConfig PmchConfig;
    uchar PmchIdx; /* 0, ..., 14 */

    /* IE MBMS-SessionInfoList */
    uchar Spare[2];
    char NumOfSessionInfo; /* MBMS-SessionInfoList is a sequence of MBMS_SessionInfo [0-maxSessionPerPMCH(29)] */
    lte_rlcmac_Cmac_SessionInfo SessionInfoList[0];
} lte_rlcmac_Cmac_PmchInfo;

/* lte_rlcmac_Cmac_MBMS_AREA_CONFIG_CMD:
 * The MBSFNAreaConfiguration message contains the MBMS control information applicable
 * for an MBSFN area. E-UTRAN configures an MCCH for each MBSFN area i.e. the MCCH identifies
 * the MBSFN area.
 * Signalling radio bearer: N/A
 * RLC-SAP: UM
 * Logical channel: MCCH
 * Direction: E-UTRAN to UE
 */
typedef struct lte_rlcmac_Cmac_MBMS_AREA_CONFIG_CMD_t {
    uint Spare; /* must be set to -1 */
    uint CellId;

    /* IE MBSFN-CommonSFAllocPattern */
    uchar AreaIdx;              /* 0, ..., 7 */
    uchar CommonSFAllocPeriod;  /* Indicates the period during which resources corresponding with field commonSF-Alloc
                                 * are divided between the (P)MCH that are configured for this MBSFN area. The subframe
                                 * allocation patterns, as defined by commonSF-Alloc, repeat continuously during this period.
                                 * [0 -> rf4, 1 -> rf8, 2 -> rf16, 3 -> rf32, 4 -> rf64, 5 -> rf128, 6 -> rf256] */
    char NumOfPmchInfo; /* PMCH-InfoList is a sequence of PMCH-Info. [0-maxPMCH-PerMBSFN(15)] */
    char NumOfCommonSFAlloc;
    sdrLte_MbsfnSubframeConfig CommonSFAlloc[0]; /* CommonSF_AllocPatternList is a sequence of MBSFN_SubframeConfig. [1-maxMBSFN-Allocations(8)] */

    /* IE MBSFN-PMCHInfoList */
    lte_rlcmac_Cmac_PmchInfo PmchInfoList[0];
} lte_rlcmac_Cmac_MbmsAreaConfig;

typedef struct lte_rlcmac_Cmac_MrbCfg_t {
    uchar areaIdx; /* 0 - 7 */
    uchar pmchIdx; /* 0 - 14 */
    uchar lcid; /* 0 - 28 */
    uchar rbId; /* 41 - 63 */
    /* lte_rlcmac_Crlc_RxUmParm_t */
    uint  TimerReordering;
    uchar SnLength;
    uchar Spare[3];
} lte_rlcmac_Cmac_MrbCfg_t;

typedef struct lte_rlcmac_Cmac_MrbRel_t {
    uchar areaIdx; /* 0 - 7 */
    uchar pmchIdx; /* 0 - 14 */
    uchar lcid; /* 0 - 28 */
    uchar rbId; /* 41 - 63 */
} lte_rlcmac_Cmac_MrbRel_t;

/* lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_CMD: */
typedef struct lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_CMD_t {
    uint spare;      /* must be set to -1 */
    uint cellId;

    uchar                       numOfRbCfg;
    uchar                       numOfRbRel;
    uchar                       spare1[2];
    /* MRB to be added or re-configured */
    lte_rlcmac_Cmac_MrbCfg_t    rbCfg[0]; // Up to lte_MaxNrOfRB_T_MRB

    /* MRB to be released */
    lte_rlcmac_Cmac_MrbRel_t    rbRel[0]; // Up to lte_MaxNrOfRB_T_MRB

} lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_CMD_t;

typedef struct lte_rlcmac_Cmac_MBMS_MRB_ACK_Info_t {
    uchar RbId;
    uchar Error;
    ushort Spare;
} lte_rlcmac_Cmac_MBMS_MRB_ACK_Info_t;

/*
 * lte_rlcmac_Cmac_MBMS_MRB_CMD_ACK
 */
typedef struct
{
    uint CellId;
    ushort Spare;
    uchar NumCfgInfo;
    uchar NumRelInfo;
    lte_rlcmac_Cmac_MBMS_MRB_ACK_Info_t CfgInfo[0];
    lte_rlcmac_Cmac_MBMS_MRB_ACK_Info_t RelInfo[0];

} lte_rlcmac_Cmac_MBMS_MRB_CMD_ACKt;

/*
 * lte_rlcmac_Cmac_MBMS_CMD_ACK
 */
typedef struct
{
    uint AreaIdx;
    uint CellId;

} lte_rlcmac_Cmac_MBMS_CMD_ACKt;

/*
 * lte_rlcmac_Cmac_MBMS_CMD_ACK
 */
typedef struct
{
    uint AreaIdx;
    uint CellId;
    short Err; /* Error code */

} lte_rlcmac_Cmac_MBMS_CMD_NACKt;

/*
 * lte_rlcmac_Cmac_DCI62_DII_IND/lte_rlcmac_Cmac_DCIN2_DII_IND
 */
typedef struct {

    uint CellId;
    ushort Esbf;
    uchar Dii; /* Direct Indication information */
    uchar Spare;

} lte_rlcmac_Cmac_DCI62_DII_IND_t;

typedef lte_rlcmac_Cmac_DCI62_DII_IND_t lte_rlcmac_Cmac_DCI_DII_IND_t;

typedef struct {

    uint CellId;
    uint NumRnti;
    lte_rlcmac_Cmac_RntiLaaCfg LaaCfg[1];

} lte_rlcmac_Cmac_PhLaaCfg_t;

/*
 * lte_rlcmac_Cmac_CELL_STATUS_REQ
 */
typedef struct {

    uint Spare; /* must be set to -1 */
    uint CellId;

} lte_rlcmac_Cmac_CELL_STATUS_REQ_t;

/*
 * lte_rlcmac_Cmac_CELL_STATUS_ACK
 */
typedef struct {

    uint Spare; /* must be set to -1 */
    uint CellId;
    uint SyncFlag; /* 0 -> out if SYNC, 1 -> SYNC */

} lte_rlcmac_Cmac_CELL_STATUS_ACK_t;

/*------------------------------------------------------------------*
 |  SUMMARY OF PRIMITIVES                                           |
 *------------------------------------------------------------------*/

typedef union {
    lte_rlcmac_Cmac_ACK_t                        Ack;
    lte_rlcmac_Cmac_NAK_t                        Nak;

    lte_rlcmac_Cmac_CONFIG_CMD_t                 ConfigCmd;
    lte_rlcmac_Cmac_RRC_STATE_CFG_CMD_t          RrcStateCfgCmd;
    lte_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD_t     CellRrcStateCfgCmd;
    lte_rlcmac_Cmac_RESET_CMD_t                  ResetCmd;
    lte_rlcmac_Cmac_RELEASE_CMD_t                ReleaseCmd;
    lte_rlcmac_Cmac_STATUS_REQ_t                 StatusReq;
    lte_rlcmac_Cmac_STATUS_CNF_t                 StatusCnf;
    lte_rlcmac_Cmac_STATUS_IND_t                 StatusInd;
    lte_rlcmac_Cmac_CELL_STATUS_IND_t            CellStatusInd;
    lte_rlcmac_Cmac_CELL_STATUS_REQ_t            CellStatusReq;
    lte_rlcmac_Cmac_CELL_STATUS_ACK_t            CellStatusAck;
    lte_rlcmac_Cmac_MEAS_SET_CMD_t               MeasSetReq;

    lte_rlcmac_Cmac_DEB_CONFIG_CMD_t             DebConfigCmd;
    lte_rlcmac_Cmac_DEB_RACH_ACC_CMD_t           DebRachAccCmd;

    lte_rlcmac_Cmac_STAT_CELL_CMDt               StatCellCmd;
    lte_rlcmac_Cmac_STAT_CELL_ACKt               StatCellAck;

    lte_rlcmac_Cmac_STAT_UE_CMDt                 StatUeCmd;
    lte_rlcmac_Cmac_STAT_UE_ACKt                 StatUeAck;

    lte_rlcmac_Cmac_ERRPROF_START_CMD_t          ErrprofStartCmd;

    lte_rlcmac_Cmac_TEST_JITTERt                 Jitter;
    lte_rlcmac_Cmac_TEST_DEBUG_CFG_CMD_t         DebugCfgCmd;

    lte_rlcmac_Cmac_SCHED_CFG_CMDt               SchedCfgCmd;
    lte_rlcmac_Cmac_SCHED_CFG_ACKt               SchedCfgAck;
    lte_rlcmac_Cmac_SCHED_CLOSE_CMDt             SchedCloseCmd;
    lte_rlcmac_Cmac_SCHED_INFO_CMDt              SchedInfoCmd;
    lte_rlcmac_Cmac_SCHED_INFO_ACKt              SchedInfoAck;

    /* MBMS */
    /* A limited amount of MBMS control information is also provided on the BCCH
     * The BCCH carries the information needed to acquire the MCCH(s)
     */
    lte_rlcmac_Cmac_MbmsMcchAcquisition MbmsMcchAcquisitionCmd;

    /* Most of the MBMS control information is provided on the MCCH
     * The MCCH carries the MBSFNAreaConfiguration message, which indicates the MBMS
     * sessions that are ongoing as well as the (corresponding) radio resource configuration.
     * The MCCH may also carry the MBMSCountingRequest message
     */
    lte_rlcmac_Cmac_MbmsAreaConfig MbmsAreaConfigCmd;

    /* The MRBs that correspond to (up to) 8 MCCHs in the range RbId 33-40
     * Configuration of MTCH MRBs
     */
    lte_rlcmac_Cmac_MBMS_SESSION_CONFIG_CMD_t MbmsSessionConfigCmd;
    lte_rlcmac_Cmac_MBMS_MRB_CMD_ACKt MbmsMrbCmdAck;
    lte_rlcmac_Cmac_MBMS_CMD_ACKt MbmsCmdAck;
    lte_rlcmac_Cmac_MBMS_CMD_NACKt MbmsCmdNack;

    /* MBMS specific statistics */
    lte_rlcmac_Cmac_STAT_MBMS_CMDt StatMbmsCmd;
    lte_rlcmac_Cmac_STAT_MBMS_ACKt StatMbmsAck;
    lte_rlcmac_Cmac_STAT_NET_MBMS_CMDt StatNetMbmsCmd;
    lte_rlcmac_Cmac_STAT_NET_MBMS_ACKt StatNetMbmsAck;
    lte_rlcmac_Cmac_STAT_MBMS_NACKt StatMbmsNack;

    /* RCP fading */
    lte_rlcmac_Cmac_FAST_FADING_CMD_t FastFadingCmd;

    /* LTE-M/NB-IOT */
    lte_rlcmac_Cmac_DCI_DII_IND_t DciDiiInd;

    /* LAA */
    lte_rlcmac_Cmac_PhLaaCfg_t LaaConfigCmd;

} lte_rlcmac_Cmac_PRIMt;

#pragma    pack()
#endif
