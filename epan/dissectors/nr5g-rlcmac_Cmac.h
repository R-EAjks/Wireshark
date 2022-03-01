#ifndef nr5g_rlcmac_Cmac_DEFINED
#define nr5g_rlcmac_Cmac_DEFINED

#include "nr5g.h"
#include "nr5g-rlcmac_Com.h"
#include "nr5g-rlcmac_Cmac-bb.h"

#define nr5g_rlcmac_Cmac_VERSION   "0.21.0"

/*
 * This interface conforms to the rules specified in `lsu.h'.
 */

#pragma pack(1)

/*------------------------------------------------------------------*
 |  PRIMITIVES OPCODES                                              |
 *------------------------------------------------------------------*/

/*
 * CMAC SAP
 */

#define nr5g_rlcmac_Cmac_CONFIG_CMD      0x01
#define nr5g_rlcmac_Cmac_CONFIG_ACK      (0x100 + nr5g_rlcmac_Cmac_CONFIG_CMD)
#define nr5g_rlcmac_Cmac_CONFIG_NAK      (0x200 + nr5g_rlcmac_Cmac_CONFIG_CMD)
#define nr5g_rlcmac_Cmac_SEG_CONFIG_REQ  0x13

#define nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD   0x02
#define nr5g_rlcmac_Cmac_RRC_STATE_CFG_ACK  (0x100 + nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD)
#define nr5g_rlcmac_Cmac_RRC_STATE_CFG_NAK  (0x200 + nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD)

#define nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD   0x03
#define nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_ACK  (0x100 + nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD)
#define nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_NAK  (0x200 + nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD)

#define nr5g_rlcmac_Cmac_RESET_CMD   0x04
#define nr5g_rlcmac_Cmac_RESET_ACK  (0x100 + nr5g_rlcmac_Cmac_RESET_CMD)
#define nr5g_rlcmac_Cmac_RESET_NAK  (0x200 + nr5g_rlcmac_Cmac_RESET_CMD)

#define nr5g_rlcmac_Cmac_RELEASE_CMD   0x09
#define nr5g_rlcmac_Cmac_RELEASE_ACK  (0x100 + nr5g_rlcmac_Cmac_RELEASE_CMD)
#define nr5g_rlcmac_Cmac_RELEASE_NAK  (0x200 + nr5g_rlcmac_Cmac_RELEASE_CMD)

#define nr5g_rlcmac_Cmac_STATUS_REQ           0x05
#define nr5g_rlcmac_Cmac_STATUS_IND           0x405
#define nr5g_rlcmac_Cmac_CELL_STATUS_REQ      0x12
#define nr5g_rlcmac_Cmac_CELL_STATUS_CNF      0x312
#define nr5g_rlcmac_Cmac_CELL_STATUS_IND      0x406
#define nr5g_rlcmac_Cmac_STATUS_CNF           0x407
#define nr5g_rlcmac_Cmac_DBEAM_IND            0x408
#define nr5g_rlcmac_Cmac_DCI_IND              0x409

#define nr5g_rlcmac_Cmac_MEAS_SET_REQ    0x06

/* To Debug Rach Access */
#define nr5g_rlcmac_Cmac_RACH_CFG_CMD       0x10
#define nr5g_rlcmac_Cmac_RACH_CFG_ACK       (0x100 + nr5g_rlcmac_Cmac_RACH_CFG_CMD)
#define nr5g_rlcmac_Cmac_RACH_CFG_NAK       (0x200 + nr5g_rlcmac_Cmac_RACH_CFG_CMD)

#define nr5g_rlcmac_Cmac_RACH_ACC_CMD       0x11
#define nr5g_rlcmac_Cmac_RACH_ACC_ACK       (0x100 + nr5g_rlcmac_Cmac_RACH_ACC_CMD)
#define nr5g_rlcmac_Cmac_RACH_ACC_NAK       (0x200 + nr5g_rlcmac_Cmac_RACH_ACC_CMD)

#define nr5g_rlcmac_Cmac_RACH_ACC_IND       0x12

/*
 * L1_TEST SAP
 */
#define nr5g_rlcmac_Cmac_L1T_START_TEST_CMD       0x01
#define nr5g_rlcmac_Cmac_L1T_START_TEST_ACK      (0x100 + nr5g_rlcmac_Cmac_L1T_START_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1T_START_TEST_NAK      (0x200 + nr5g_rlcmac_Cmac_L1T_START_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD       0x02
#define nr5g_rlcmac_Cmac_L1T_STOP_TEST_ACK      (0x100 + nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1T_STOP_TEST_NAK      (0x200 + nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1T_LOG_IND            (0x103)

#define nr5g_rlcmac_Cmac_L1L2T_START_TEST_CMD       0x04
#define nr5g_rlcmac_Cmac_L1L2T_START_TEST_ACK      (0x100 + nr5g_rlcmac_Cmac_L1L2T_START_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_START_TEST_NAK      (0x200 + nr5g_rlcmac_Cmac_L1L2T_START_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_CMD       0x05
#define nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_ACK      (0x100 + nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_NAK      (0x200 + nr5g_rlcmac_Cmac_L1L2T_STOP_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD       0x06
#define nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_ACK       (0x100 + nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD)
#define nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_NAK       (0x200 + nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD)

#define nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD       0x07
#define nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_ACK      (0x100 + nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_NAK      (0x200 + nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD       0x08
#define nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_ACK      (0x100 + nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_NAK      (0x200 + nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_CMD  0x09
#define nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_ACK (0x100 + nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_NAK (0x200 + nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_CMD        0x10
#define nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_ACK       (0x100 + nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_NAK       (0x200 + nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_CMD)

#define nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_CMD       0x11
#define nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_ACK       (0x100 + nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_NAK       (0x200 + nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_CMD)

#define nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_CMD           0x12
#define nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_ACK           (0x100 + nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_CMD)
#define nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_NAK           (0x200 + nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_CMD)

#define nr5g_rlcmac_Cmac_L1T_BINDUMP_CMD       0x14
#define nr5g_rlcmac_Cmac_L1T_BINDUMP_ACK       (0x100 + nr5g_rlcmac_Cmac_L1T_BINDUMP_CMD)
#define nr5g_rlcmac_Cmac_L1T_BINDUMP_NAK       (0x200 + nr5g_rlcmac_Cmac_L1T_BINDUMP_CMD)

#define nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_CMD  0x15
#define nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_ACK (0x100 + nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_CMD)
#define nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_NAK (0x200 + nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_CMD)

/*
 * STAT SAP
 */
#define  nr5g_rlcmac_Cmac_STAT_CELL_REQ       0x01
#define  nr5g_rlcmac_Cmac_STAT_DBEAM_IND  0x401


#define  nr5g_rlcmac_Cmac_STAT_UE_REQ         0x02
#define  nr5g_rlcmac_Cmac_STAT_UE_HI_IND     0x402
#define  nr5g_rlcmac_Cmac_STAT_UE_LO_IND     0x403


/*------------------------------------------------------------------*
 |  STRUCTURES USED IN PRIMITIVES                                   |
 *------------------------------------------------------------------*/

typedef struct {
    uint16_t    CellId;  /* cell number */
    uint16_t    DbeamId; /* digital beam number */
} nr5g_rlcmac_Cmac_BB_INSTt;

/*
 * PHYSICAL CHANNELS CONFIGURATION
 */
typedef bb_nr5g_CELL_GROUP_CONFIGt nr5g_rlcmac_Cmac_CellCfg_t;

/*
*  RB INFORMATION ELEMENT
*/
typedef struct {

    uchar   logicalChannelIdentity;
    uchar   logicalChannelGroup;        /* -1 for none */
    uchar   priority;
    uint    prioritisedBitRate;            /* [kBytes/sec, -1 for "infinity"] */
    uint    bucketSizeDuration;            /* [ms] */
    uint    allowedServingCells;
    uint    allowedSCS_List;
    uchar    maxPUSCH_Duration;
    uchar    configuredGrantType1Allowed;/* [BOOLEAN] If TRUE LCID can be Txd on configuredGrantType1 */
    uchar   logicalChannelSR_Mask;        /* TRUE means enabled */
    uchar   logicalChannelSR_DelayTimerConfigured;  /* TRUE means enabled */
    uchar    requestDuplicatesFromPDCP;    /* E/// only. If set to TRUE, this logical channel is configured for data duplication. */
    uint    schedulingRequestID;        /* mapped SchedulingRequestId */
    uint    bitRateQueryProhibitTimer;    /* [ms, -1 means "not configured"] */
    uchar    allowedPHY_PriorityIndex;    /* [0: p0, 1: p1, -1: "not present"] */
} nr5g_rlcmac_Cmac_TxLchInfo_t;

typedef struct {

    uchar   logicalChannelIdentity;

} nr5g_rlcmac_Cmac_RxLchInfo_t;

typedef struct {

    nr5g_rlcmac_Cmac_TxLchInfo_t  TxLchInfo;

    nr5g_rlcmac_Cmac_RxLchInfo_t  RxLchInfo;

} nr5g_rlcmac_Cmac_RbMappingInfo_t;


typedef struct {

    nr5g_RbType_v                      RbType;
    uchar                              RbId;
    uchar                              reestablishRLC; /* indicates that RLC should be re-established. */
    nr5g_rlcmac_Cmac_RbMappingInfo_t   RbMappingInfo;

} nr5g_rlcmac_Cmac_RbCfg_t;


typedef struct {

    nr5g_RbType_v           RbType;
    uchar                  RbId;

} nr5g_rlcmac_Cmac_RbRel_t;


typedef struct {

    /* RB to be added or re-configured */
    uchar                        NumOfRbCfg;
    nr5g_rlcmac_Cmac_RbCfg_t      RbCfg[nr5g_MaxNrOfRB];

    /* RB to be released */
    uchar                        NumOfRbRel;
    nr5g_rlcmac_Cmac_RbRel_t      RbRel[nr5g_MaxNrOfRB];
    
} nr5g_rlcmac_Cmac_RbInfoElem_t;


typedef enum {
    nr5g_lc_Cmac_oneEighth = 0,
    nr5g_lc_Cmac_oneFourth = 1,
    nr5g_lc_Cmac_oneHalf = 2,
    nr5g_lc_Cmac_one = 3,
    nr5g_lc_Cmac_two = 4,
    nr5g_lc_Cmac_four = 5,
    nr5g_lc_Cmac_eight = 6,
    nr5g_lc_Cmac_sixteen = 7,
} nr5g_rlcmac_Cmac_ssb_perRACH_Occasion_e;
typedef uchar nr5g_rlcmac_Cmac_ssb_perRACH_Occasion_v;


typedef struct {
    uint    BwpId;

    uint    prach_ConfigIndex; /* RRC: prach_ConfigurationIndex. [0 - 255] */

    int     preambleReceivedTargetPower; /* initial preamble power [dBm] */

    uint rsrp_ThresholdSSB; /*  [unit 0 - 140] TODO */
    uint csirs_Threshold; /* not present in RRC TODO */
    uint sul_RSRP_Threshold; /* RRC: rsrp-ThresholdSSB-SUL. [0 - 140] TODO */

    uchar   ra_PreambleIndex;          /* Dedicated preamble [0 - 63, -1 for none] */

    int     preamblePowerRampingStep; /* RRC: powerRampingStep. power-ramping factor [dB] */

    uint    ra_ssb_OccasionMaskIndex; /*  TODO */
    uint    preambleTxMax;       /* RRC: preambleTransMax. Max number of preamble trasmission */

    uchar    totalNumberOfRA_Preambles; /* {not present in MAC, present in RRC} [1 - 63] TODO */
    nr5g_rlcmac_Cmac_ssb_perRACH_Occasion_v    ssb_perRACH_Occasion;    /* SSB per RACH occasion. First part of ssb-perRACH-OccasionAndCB-PreamblesPerSSB */
    uchar    CB_PreamblesPerSSB; /* Number of CB preambles per SSB. Second part of ssb-perRACH-OccasionAndCB-PreamblesPerSSB */

    struct {
        uint    ra_Msg3SizeGroupA;            /* [bytes, -1 means Group B not present] */
        uchar    numberofRA_PreamblesGroupA;    /* [1 - 64] */
        uchar    deltaPreambleMsg3;            /* as in TS 38.213 */
        int        messagePowerOffsetGroupB; /* [dB, 0x8000.. means minusinfinity] */
    } groupBconfigured;

    /* {set of Random Access Preambles for SI request: missing in specs} TODO */
    /* {set of Random Access Preambles for beam failure recovery request} TODO */
    

    uint    ra_ResponseWindow; /* time window to monitor RA response(s) [sl] */
   
    uint    ra_ContentionResolutionTimer;  /* [sf] */
    
//    nr5g_rlcmac_Cmac_RntiCfg RntiCfg;  /* Default configuration for T-RNTI's (variable length) */
} nr5g_rlcmac_Cmac_RA_Info_t;


typedef struct {
    uint    periodicBSR_Timer;          /* [sf, -1 means infinity] */
    uint    retxBSR_Timer;              /* [sf] */
    uint    logicalChannelSR_DelayTimer; /* E/// not present [sf, -2 means none] */
} nr5g_rlcmac_Cmac_BSR_Configuration_t;

typedef struct {
    uchar   srConfigIndex;   //SchedulingRequestId
    uchar   srProhibitTimer; //sr-ProhibitTimer in ms 0: not present
        uchar   srTransMax;      //sr-TransMax
} schedulingRequestToAdd;

#define nr5g_rlcmac_Cmac_SR_MAX  8

typedef struct {
    uchar                        NSrToAdd;  //NUm of Sr to Add 0..8
    schedulingRequestToAdd       SrToAdd[nr5g_rlcmac_Cmac_SR_MAX];
    uchar                        NSrToDel;  //NUm of Sr to Del 0..8
    uchar                        SrToDel[nr5g_rlcmac_Cmac_SR_MAX]; //SchedulingRequestId
} nr5g_rlcmac_Cmac_SR_Configuration_t;

typedef struct {
    uint    tag_Id;
    uint    timeAlignmentTimer; /* [ms, -1 means infinity] */
} nr5g_rlcmac_Cmac_TAG_Configuration_t;

typedef struct {
    uint    phr_PeriodicTimer; /* [sf, 0 means PHR disabled, -1 means infinity] */
    uint    phr_ProhibitTimer; /* [sf] */

    int        phr_Tx_PowerFactorChange;    /* [dB, 0x7FF.. means infinity] */
    uint    multiplePHR                ;    /* [BOOLEAN] */
    uint    phr_Type2SpCell            ;    /* [BOOLEAN] */
    uint    phr_Type2OtherCell        ;    /* [BOOLEAN] */
    uint    phr_ModeOtherCG            ;    /* [0 -> real, 1 -> virtual] */

    uint    Spare                    ;
} nr5g_rlcmac_Cmac_PHR_Config_t;

typedef struct {
    nr5g_rlcmac_Cmac_BSR_Configuration_t    bsr_Config;
    nr5g_rlcmac_Cmac_TAG_Configuration_t    tag_Config; /* E/// not present */
    nr5g_rlcmac_Cmac_PHR_Config_t            phr_Config;
    nr5g_rlcmac_Cmac_SR_Configuration_t    Sr_Config;

    uchar    skipUplinkTxDynamic;
    uint    sCellDeactivationTimer;    /* E/// not present [ms], -1 means none */

    uchar  HoFlag;                      /* Handover flag ( 0 = normal config,
                                                           1 = prim. is used to configure an HO */
   
} nr5g_rlcmac_Cmac_MAC_CellGroupConfig_t;


typedef struct {
    uchar SCellIndex; /* [0 - 31] */

    int PCMAXc;
    int PCMAXc_SUL; /* -1 means no SUL carrier */
#if 0
    TODO
    /* MAC parameters */
    SPS_Config_t sps_Config;
     STAG_Id_t stag_Id;
    HARQ_RTT_Timers_t harq_RTT_Timers;
    SPSULtransmissionWithoutGrant_Config_t ulTransmissionWithoutGrantsps_Config;
    uint    sCellDeactivationTimer;    /* E/// only [ms], -1 means none in 3GPP is one for the CG and not per ServCell */

#endif

} nr5g_rlcmac_Cmac_ServCellConfig_t;


typedef enum {
    
    nr5g_rlcmac_Cmac_Rrc_State_IDLE = 1,
    nr5g_rlcmac_Cmac_Rrc_State_MAC_RESET = 2,
    
} nr5g_rlcmac_Cmac_Rrc_State_e;
typedef uchar nr5g_rlcmac_Cmac_Rrc_State_v;

typedef enum {
    
    nr5g_rlcmac_Cmac_Action_RELEASE_ALL_RLC = 1,
    
} nr5g_rlcmac_Cmac_Action_e;
typedef uchar nr5g_rlcmac_Cmac_Action_v;


typedef enum {
    
    nr5g_rlcmac_Cmac_STATUS_NONE = 0,
    nr5g_rlcmac_Cmac_STATUS_RA_RECOVER_FROM_PROBLEM = 1, /* (1) */
    nr5g_rlcmac_Cmac_STATUS_PUCCH_SRS_RELEASE = 2,       /* (2) */
    nr5g_rlcmac_Cmac_STATUS_RNTI_DUP_RELEASE = 3,        /* (3) */
    nr5g_rlcmac_Cmac_STATUS_LOWER_LAYER_NAK = 4,         /* (4) */
    nr5g_rlcmac_Cmac_STATUS_RLF_HARQ_CSI_OFF = 5,        /* (5) */
    nr5g_rlcmac_Cmac_STATUS_RL_SYNC_ON = 6,              /* (6) */

} nr5g_rlcmac_Cmac_STATUS_e;
typedef uchar nr5g_rlcmac_Cmac_STATUS_v;

typedef enum {

    nr5g_rlcmac_Cmac_CELL_STATUS_NONE = 0,
    nr5g_rlcmac_Cmac_CELL_STATUS_IN_SERVICE = 1,              /* (1) */
    nr5g_rlcmac_Cmac_CELL_STATUS_RACH_PROBE_FAILURE = 2,        /* (2) */

} nr5g_rlcmac_Cmac_CELL_STATUS_e;
typedef uchar nr5g_rlcmac_Cmac_CELL_STATUS_v;

/* These values are mapped on bb-nr5g.h */
typedef enum {

    nr5g_rlcmac_Cmac_STATUS_DBEAM_BOOTING_UP = 0,
    nr5g_rlcmac_Cmac_STATUS_DBEAM_SYNC = 1,
    nr5g_rlcmac_Cmac_STATUS_DBEAM_NO_SIGNAL = 2,
    nr5g_rlcmac_Cmac_STATUS_DBEAM_SYNC_NOT_FOUND = 3,
    nr5g_rlcmac_Cmac_STATUS_DBEAM_UNSTABLE_CLOCK = 4,
    nr5g_rlcmac_Cmac_STATUS_DBEAM_SYNC_UNLOCKED = 5,

} nr5g_rlcmac_Cmac_DBEAM_STATUS_e;
typedef uchar nr5g_rlcmac_Cmac_DBEAM_STATUS_v;


/*
 * (1) Indicate a Random Access recover from a problem.
 * (2) Indicate a PUCCH/SRS release.
 * (3) Indicate a RNTI Duplication triggering release. (Prop.)
 * (4) The cell is not synchronized
 * (5) The cell synchronized
 */


typedef struct {
    uint    BeamId;                      /* Beam Identifier */
    uint    SsbIndex;                    /* SS block index */
    int     Snr;   /* Signal to noise ration in dB. */
    int     Rsrp;  /* PSS rx power in dB. The value is multiplied for 10.0 . */
    int     Rsrq;  /* Reference Signal Received Quality in dB The value is multiplied for 10.0 */

} nr5g_rlcmac_Cmac_BEAM_STATUS_t;



/*------------------------------------------------------------------*
 |  LAYOUT OF PRIMITIVES                                            |
 *------------------------------------------------------------------*/

/*
 * ACK
 */
typedef struct {

    uint UeId;
    nr5g_rlcmac_Cmac_BB_INSTt     BbInst;
    uint32_t                      TestHdl;       /* Test handler */

} nr5g_rlcmac_Cmac_ACK_t;


/*
  NAK
 */
typedef struct {

    uint UeId;
    nr5g_rlcmac_Cmac_BB_INSTt     BbInst;
    uint32_t                      TestHdl;       /* Test handler */
    int16_t    Err;           /* Error code */

} nr5g_rlcmac_Cmac_NAK_t;


typedef struct {
    uchar    SCellIndex; /* [0 - 31] */
    uchar    LsuCellId;
    int      PCMAXc;
    int      PCMAXc_SUL; /* -1 means no SUL carrier */
    //TODO
} nr5g_rlcmac_Cmac_SCellConfig_t;

typedef struct {
    uchar SCellIndex; /* [0 - 31] */
} nr5g_rlcmac_Cmac_RelCellIds_t;

#define nr5g_rlcmac_Com_MaxNumSCells 7

typedef struct {
    /* SCells to be added or modified. */
    uchar                              NumOfSCellAdd;
    nr5g_rlcmac_Cmac_SCellConfig_t     SCellConfig[nr5g_rlcmac_Com_MaxNumSCells];

    /* SCells to be released. */
    uchar                           NumOfSCellRel;
    nr5g_rlcmac_Cmac_RelCellIds_t   SCellRel[nr5g_rlcmac_Com_MaxNumSCells];
} nr5g_rlcmac_Cmac_SCellList_t;

typedef struct {
    nr5g_rlcmac_Cmac_ServCellConfig_t   spCellConfig;
} nr5g_rlcmac_Cmac_SpCellConfig_t;

typedef struct {

    uint    Beam_id;                       /* Beam Index (-1 means not applicable) */
    uint    Crnti;                         /* <Static C-RNTI> in L2 TESTMODE or -1 in normal behaviour */

    /* RA information elements */
    uint    BwpMask;                                            /* Validity mask of RA_Info[] array. */
    nr5g_rlcmac_Cmac_RA_Info_t    RA_Info[bb_nr5g_MAX_NB_BWPS+1]; /* First element for Initial BWP. other elements for additional BWP. Array Index correspond to BWP-Id */
    
    /* RB information elements */
    nr5g_rlcmac_Cmac_RbInfoElem_t    RbIE;

    /* Parameters applicable for the entire cell group: */
    nr5g_rlcmac_Cmac_MAC_CellGroupConfig_t mac_CellGroupConfig; /* not (yet) present in E/// */

    nr5g_rlcmac_Cmac_SpCellConfig_t    spCellConfig; /* E///: pCellConfig */
    nr5g_rlcmac_Cmac_SCellList_t    sCellList;

} nr5g_rlcmac_Cmac_CfgParams_t;

#define nr5g_rlcmac_Cmac_MAC_SEG_SIZE    (20000) /* unit: bytes */
/*
nr5g_rlcmac_Cmac_CONFIG_CMD:
This primitive is used to request for setup, release and configuration
of transport channels.
*/
typedef struct {

    uint   UeId;

    nr5g_rlcmac_Cmac_CfgParams_t Params;

#define nr5g_rlcmac_Cmac_L2_TEST_MODE_NO 0 /* no test mode */
#define nr5g_rlcmac_Cmac_L2_TEST_MODE_01 1 /* L2 test mode: UL and DL are active, RA not expected */
#define nr5g_rlcmac_Cmac_L2_TEST_MODE_02 2 /* L2 test mode: RA without contention */
    uchar L2TestMode;
    uint  RL_Failure_Timer; /* Started when Radio Link Failure detected (RLF_HARQ_OFF,RLF_CSI_OFF set 1) */
                            /* Stopped if no more Radio Link Failure. At expiration: nr5g_rlcmac_Cmac_STATUS_IND(nr5g_rlcmac_Cmac_STATUS_RLF_HARQ_CSI_OFF) to TSTM */
                            /* Values: 0 (no timer, default) or <milliseconds value> */
    uint  RL_SyncOn_Timer;  /* Started when Radio Link SyncOn detected (RLF_HARQ_OFF,RLF_CSI_OFF set 0) */
                            /* Stopped if Radio Link Failure. At expiration: nr5g_rlcmac_Cmac_STATUS_IND(nr5g_rlcmac_Cmac_STATUS_RL_SYNC_ON) to TSTM */
                            /* Values: 0 (no timer, default) or <milliseconds value> */
    uchar SegCnt;      /* Segment counter (1) */

    uint enablePmiReporting; /* 0: disabled, 1:enabled */

    uchar RA_InfoIsForSUL;   /* Flag to control RA_Info (dedicated). 0: RA_Info (dedicated) is for NUL, 1: RA_Info (dedicated) is for SUL */
    uchar Spare1[2];   /* For future extension, set to 0 */
    uint  Spare[3];    /* For future extension, set to 0 */

    uint L1CellDedicatedConfig_Len; /* byte length of L1CellDedicatedConfig[] */
    /* L1 for L2 parameters (variable length) */
    nr5g_rlcmac_Cmac_CELL_DEDICATED_CONFIGt L2CellDedicatedConfig;

    /* L1 parameters */
    uchar L1CellDedicatedConfig[]; /* contains bb_nr5g_CELL_DEDICATED_CONFIGt (variable length) according to bb-nr5g_struct.h interface. */
} nr5g_rlcmac_Cmac_CONFIG_CMD_t;

/*
nr5g_rlcmac_Cmac_SEG_CONFIG_REQ:
This primitive is used to request a segment of CONFIG_CMD
of transport channels.
*/
typedef struct {

    uint   UeId;

    uchar  SegCnt;     /* Segment counter (1) */
    uchar  Spare[31];  /* For future extension, set to 0 */
    uchar  Data[];     /* contains a segment of CONFIG_CMD. */
} nr5g_rlcmac_Cmac_SEG_CONFIG_REQ_t;

/* 
 *  Notes:
 *
 * 1) Segment counter: count remaining segments of the CONFIG_CMD.
 *
 *    CONFIG_CMD can be segmented in one initial CONFIG_CMD and one or more SEG_CONFIG_REQ.
 *    Segments are concatenated in reversed order of SegCnt.
 *    SegCnt=0 means no remaining segment (i.e. current segment is the last segment)
 *    SegCnt=1 means one remaining segment, and so on.
 *    SegCnt can be considered as an inverse sequence counter for segments, i.e. considering 
 *    N as the total number of segments, we have 1 x CONFIG_CMD + (N-1) x SEG_CONFIG_REQ with:
 *    segment #0 (initial CONFIG_CMD): SegCnt = N-1
 *    segment #1 (first SEG_CONFIG_REQ): SegCnt = N-2
 *    ...
 *    segment #(N-2): SegCnt = 1
 *    segment #(N-1) (last segment): SegCnt = 0
 * */

/*
 * nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD
 */
typedef struct {

    uint                          UeId;

    nr5g_rlcmac_Cmac_Rrc_State_v   State;

} nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD_t;

/*
 * nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD
 */
typedef struct {

    uint                          Spare;      /* must be set to -1 */
    uint                          CellId;

    nr5g_rlcmac_Cmac_Rrc_State_v   State;

} nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD_t;

/*
 * nr5g_rlcmac_Cmac_RESET_CMD
 */
typedef struct {

    uint                       UeId;

} nr5g_rlcmac_Cmac_RESET_CMD_t;

/*
 * nr5g_rlcmac_Cmac_RELEASE_CMD
 */
typedef struct {

    uint                         UeId;
    nr5g_rlcmac_Cmac_Action_v    Action;
    uint                         Spare[4];


} nr5g_rlcmac_Cmac_RELEASE_CMD_t;

/*
 * nr5g_rlcmac_Cmac_STATUS_REQ
 */
typedef struct {

    uint                        UeId;

} nr5g_rlcmac_Cmac_STATUS_REQ_t;

/*
 * nr5g_rlcmac_Cmac_STATUS_CNF
 */
typedef struct {

    uint                        UeId;
    short                       Res;  /* Result code (see TODO) */

    /* Status info */
    nr5g_rlcmac_Cmac_STATUS_v    Status;
    uint                        numberOfPreamblesSent;    /* number of RACH preambles that were transmitted. Corresponds to parameter PREAMBLE_TRANSMISSION_COUNTER in TS 36.321 */
    uchar                       contentionDetected;        /* If set contention was detected for at least one of the transmitted preambles */
    uchar                       maxTxPowerReached;        /* If set the maximum power level was used for the last transmitted preamble */

} nr5g_rlcmac_Cmac_STATUS_CNF_t;

/*
 * nr5g_rlcmac_Cmac_STATUS_IND
 */
typedef struct {

    uint                        UeId;

    /* Status info */
    nr5g_rlcmac_Cmac_STATUS_v    Status;

} nr5g_rlcmac_Cmac_STATUS_IND_t;


/*
 * nr5g_rlcmac_Cmac_CELL_STATUS_IND
 */
typedef struct {

    uint                        Spare;
    uint                        CellId;

    /* Status info */
    nr5g_rlcmac_Cmac_CELL_STATUS_v    Status;

} nr5g_rlcmac_Cmac_CELL_STATUS_IND_t;


/*
 * nr5g_rlcmac_Cmac_CELL_STATUS_REQ
 */
typedef struct {

    uint                        Spare;      /* must be set to -1 */
    uint                        CellId;
} nr5g_rlcmac_Cmac_CELL_STATUS_REQ_t;


/*
 * nr5g_rlcmac_Cmac_CELL_STATUS_CNF
 */
typedef struct {

    uint                        Spare;
    uint                        CellId;

    /* Status info */
    nr5g_rlcmac_Cmac_CELL_STATUS_v Status;
    ushort                         phy_cell_id; /* Physical Cell Identifier [-1 mean not available] */
    uint                         SsbArfcn;     /* ARFCN of cell */

    uint                           NumBeam;
    nr5g_rlcmac_Cmac_BEAM_STATUS_t Beam[];

} nr5g_rlcmac_Cmac_CELL_STATUS_t;


/*
 * nr5g_rlcmac_Cmac_RACH_CFG_CMD
 */
typedef struct {
    nr5g_Id_t    Nr5gId;        /* NR5G Id */
    nr5g_rlcmac_Cmac_RA_Info_t    RA_Info;
} nr5g_rlcmac_Cmac_RACH_CFG_CMDt;


/*
 * nr5g_rlcmac_Cmac_RACH_ACC_CMD
 * To test a RACH access in case of HARQ or MAC MODE TestMode
 */
typedef struct {
    nr5g_Id_t        Nr5gId;        /* NR5G Id */
    uint            TestType;       /* see nr5g_tm_rlcmac_Cmac_RACH_TYPE_..*/
    nr5g_RbType_v   RbType;         /* Radio Bearer Type */
    uchar            RbId;         /* Rb id  (1)*/
    nr5g_LchType_v    Lch;         /* Logical Channel Type: nr5g_CCCH, nr5g_DCCH (1)*/
    int                MaxUpPwr;       /* Maximum uplink power (in dBm) (1)*/
    int                RSRP;        /* Simulated RSRP [dBm, 0x7FFFFFFF for none] (1)*/
    int                UeCategory;     /* UE category (1)*/
    uint             Spare[2];       /* For future extension, set to 0 */

    uchar            Data[1];    /* Data to be transmitted in RA procedure (MAC SDU Msg3) (1)*/
} nr5g_rlcmac_Cmac_RACH_ACC_CMDt;

#define nr5g_rlcmac_Cmac_RACH_TYPE_PREAMBLE         1  /* Only premable*/
#define nr5g_rlcmac_Cmac_RACH_TYPE_MSG3_NO_CONT     2  /* Msg3 without waiting for Msg 4*/
#define nr5g_rlcmac_Cmac_RACH_TYPE_MSG3_CONT             3  /* Do contention resolution */

/*
 *  Notes:
 *
 *  1 Not used in case of TestMode = nr5g_tm_rlcmac_Cmac_RACH_TYPE_PREAMBLE
 */


/*
 * nr5g_rlcmac_Cmac_RACH_ACC_INDt
 */

typedef struct {
    nr5g_Id_t        Nr5gId;        /* NR5G Id; CellId is valid */
    short            Res;        /* Result code (see TODO) */
    uint            Crnti;        /* Assigned C-RNTI */
    uchar            CrId[1];    /* Contention Resolution Id */
} nr5g_rlcmac_Cmac_RACH_ACC_INDt;



/*
 * nr5g_rlcmac_Cmac_DBEAM_IND_t
 */
typedef struct {

    uint                        Spare;
    uint                        CellId;

    uint                        DbeamId;

    /* Current Status info */
    nr5g_rlcmac_Cmac_DBEAM_STATUS_v    Status;

    uint                        NumBeam;
//    bb_nr5g_BEAM_STATUS         Beam[];

} nr5g_rlcmac_Cmac_DBEAM_IND_t;


/*
 * nr5g_rlcmac_Cmac_DCI_IND
 */
typedef struct {
    uchar                       Format;  //Set it to 0
    uchar                       ShortMsg;
} nr5g_rlcmac_Cmac_DCI1_0t;

typedef union {
    nr5g_rlcmac_Cmac_DCI1_0t   Dci0;
} nr5g_rlcmac_Cmac_DCI_t;

typedef struct {

    uint                        Spare;
    uint                        CellId;

    uint                        DbeamId;

    nr5g_rlcmac_Cmac_DCI_t      Dci;

} nr5g_rlcmac_Cmac_DCI_IND_t;

/*
 * nr5g_rlcmac_Cmac_L1T_START_TEST_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt   BbInst;
    uint32_t                    TestHdl;       /* Test handler (1) */
    uint8_t                     Param[]; /* Test parameters (2) */

} nr5g_rlcmac_Cmac_L1T_START_TEST_CMD_t;

/*
 * nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;
    uint32_t                    TestHdl;       /* Test handler (1) */

} nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD_t;

/*
 * nr5g_rlcmac_Cmac_L1T_LOG_IND
 */
typedef struct {

    uint UeId;
    nr5g_rlcmac_Cmac_BB_INSTt   BbInst;
    uint8_t                     LogStr[]; /* Test parameters (2) */

} nr5g_rlcmac_Cmac_L1T_LOG_IND_t;

/*
 * (1) A numeric handler used to match start and stop commands
 * (2) For each test type the L1 needs a different set of parameters
 *     They are specified in bb-l1test.h  
 */

/*
 * nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;
    uint8_t                      Param[]; /* Debug Cfg parameters */

} nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD_t;

/*
 * nr5g_rlcmac_Cmac_L1T_BINDUMP_CMD
 */
typedef struct {
    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;
    uint8_t                      Param[]; /* Debug Cfg parameters */

} nr5g_rlcmac_Cmac_L1T_BINDUMP_CMD_t;

/*
 * nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_CMD: L2 configuration for triggering L1 bindump
 */
typedef struct {
    nr5g_rlcmac_Cmac_BB_INSTt   BbInst;
    uint						Len;
    char                        Param[]; /* Debug Cfg parameters */
} nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_CMD_t;

/*
 * nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;

    uint            TestHnd;
    uint            Rnti;

    uchar           PucchTest;     /* If 1 PUCCH configuration is valid */

    /* PDCCH configuration */
    uchar           NumCce;        /* Aggregation level in number of CCEs (1, 2, 4, 8, 16) */
    uchar           Symb;          /* Symbol inside the slot the PDCCH is expected on (0..13) */
    uchar           Dcilen;        /* DCI length in bits including the CRC */
    uchar           HarqProc;      /* HARQ PROCESS field offset in bits inside the DCI */
    uchar           Ndi;           /* NDI field offset in bits inside the DCI */
    uchar           Rv;            /* RV field offset in bits inside the DCI */
        uchar           PdcchDuration;    /* PDCCH duration in number of symbols (1, 2, 3) */
        ushort          DmrsScramblingId; /* PDCCH DMRS scrambling id (0xffff means the ue specific DMRS id isn't configured)*/

    /* PUSCH configuration */
    uchar           DciTriggered;  /* 1 means the actual PUSCH transmission is triggered by a grant,
                                            0 means the PUSCH is transmitted in every slot with RV=0 */
    uchar           K2;            /* K2 parameter for downlink/uplink timing */
    uchar           TrfPre;        /* Transform precoding (0 = disabled, 1 = enabled) */

    /* Grant parameters */
    uchar             DmrsSym;       /* DMRS symbol (0..13) */
    uchar           PuschMap;      /* PUSCH mapping type (0 = A, 1 = B) */
    uchar           StartSymb;     /* Starting symbol */
    uchar           NumSymb;       /* Number of symbols */
    ushort          StartRB;       /* Starting RB (0..272) */
    ushort          NumRB;         /* Number of PRBs (1..273) */
    uchar           McsTab;        /* MCS table (0, 1) */
    uchar           Mcs;           /* MCS value */
    uchar           NDmrsAddPos;   /* Number of additional DMRS symbols 0..2 */
    uchar           PtrsOn;        /* PTRS ON-OFF flag */
    uchar           kPTRS;         /* PTRS frequency density */
    uchar           lPTRS;         /* PTRS time density */
    uchar           NumLayers;     /* Number of layers (1, 2) */
    uchar           AntPorts;      /* Antenna ports (bit0 = port 0, bit1 = port 1) */
    uint            ScramblerId;   /* ScramblerId (0xffffffff means PCI is used) */
    uint            DmrsSeqId;     /* DMRS sequence id (0xffffffff means PCI is used) */
    uchar           Pmi;           /* Precoding matrix index (0,1) */

    /* UCI configurations */
    uchar           UciOn;         /* UCI multiplexing flag */
    uchar           CsiPart1Len;   /* CSI part 1 information bit payload */
    uchar           CsiPart2Len;   /* CSI part 2 information bit payload */

    /* PUCCH part */
    ulong           SlotsMap1;     /* bitmap (one bit per slot 0-63) */
    ulong           SlotsMap2;     /* bitmap (one bit per slot 64-79) */
    ushort          PucchFormat;   /* PUCCH format (1,2,3,4) */
    uint            NumBit;        /* Number of bits */
    ulong           inputDataSeq0; /* Input pattern 1st part*/
    ulong           inputDataSeq1; /* Input pattern 2nd part*/
    ushort          StartRB2ndHop; /* starting RB for mapping this PUCCH tx (2nd hop) */
    ushort          FreqHop;       /* Intra slot frequency hopping (0=disabled, 1=enabled) */
    ushort          GroupHop;      /* Group hopping (0=neither, 1=enabled, 2=disabled) */
    ushort          HopId;         /* Hopping id */
    ushort          Cs;            /* Initial cyclic shift */
    ushort          OccIdx;        /* Time domain OCC index */
    ushort          OccLen;        /* Time domain OCC length */
    ushort          addDmrsF3F4;  /* Additional DMRS for PUCCH format 3/4 (0=no additional DMRS, 1=otherwise) */

    /* Radio condition */
     uint            Ta;             /* Timing advance (TS) */
        int             Power;          /* TX Power per resource element in dB */
    int             Awgn;           /* AWGN power in dBm (0x7FFFFF means disabled) */
    uint            FadingProfile;

} nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD_t;


/*
 * nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;
    uint            TestHnd;

} nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD_t;


/*
 * nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;

    uint            TestHnd;
    uint            Rnti;

    /* PRACH Config */
    ulong             SlotsMap1;     /* bitmap (one bit per slot 0-63) */
    ulong             SlotsMap2;     /* bitmap (one bit per slot 64-79) */
    ulong             AwgnSlotsMap1;             /* bitmap (one bit per slot 0-63) slots with only awgn*/
    ulong             AwgnSlotsMap2;             /* bitmap (one bit per slot 64-79) slots with only awgn*/
    uint32_t          PrachFormat;               /* ENUM (0,1,2,3,A0,A1,A2,A3,B1,B2,B3,B4,C0,C2) */
    uint16_t          StartRB;                   /* Starting RB (0..272) */
    uint16_t          NumRB;                     /* Number of PRBs (1..273) */
    uint16_t          StartSymb;                 /* Starting symbol (0..13) */
    uint16_t          SymbMask;                  /* Preamble Starting symbols (0..13). Bitmap identifying preamble starting symbols in a slot*/
    uint32_t          RootSequenceIdx;           /* Root sequence index (0..837) */
    uint32_t          ZeroCorrelationZone;       /* Zero correlation zone (0..15) */
    uint32_t          PInd;                      /* Preamble index (1..56) */
    uint32_t          NumTxInLoop;               /* Number of transmission in one loop */
    uint32_t          NumLoop;                   /* Number of loops (0xffffffff means infinite loop) */
    uint32_t          DeltaTimeOff;              /* Addition timing offset for each transmission in the loop */


    /* Radio condition */
     uint            Ta;             /* Timing advance (TS) */
    int             Power;          /* TX Power per resource element in dB */
    int             Awgn;           /* AWGN power in dBm (0x7FFFFF means disabled) */
    uint            FadingProfile;

} nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_CMD_t;

/*
 * nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;
    uint            TestHnd;

} nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_CMD_t;


/*
 * nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;
    uint        TestHnd;
    uint        NumTxInLoop;               /* Number of transmission in one loop*/
    uint        NumLoop;                   /* Number of loops (0xffffffff means infinite loop) */
    uint        DeltaTimeOff;              /* Addition timing offset for each transmission in the loop */

} nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_CMD_t;

/*
 * nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_CMD
 */
typedef struct {

    nr5g_rlcmac_Cmac_BB_INSTt    BbInst;
    uint        TestHnd;

} nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_CMD_t;


/*
 * STAT SAP
 */

#define nr5g_rlcmac_Cmac_STAT_NUM_RLC (10)
#define nr5g_rlcmac_Cmac_NUM_MCS      (32)
#define nr5g_rlcmac_Cmac_NUM_RV       (4)
#define nr5g_rlcmac_MAX_NUM_LAYER     (4)

/*
 * nr5g_rlcmac_Cmac_STAT_CELL_REQ
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
} nr5g_rlcmac_Cmac_STAT_CELL_REQt;

/*
 * nr5g_rlcmac_Cmac_STAT_DBEAM_IND
 */
typedef struct
{
    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    /* Digital Beam Id */
    uint                        DbeamId;

    uint    DeltaTs;        /* Interval between current and previous stat report */

    uchar   Type;           /* Set it to 0: for future extension */
    nr5g_rlcmac_Com_MacStatBasic_t    Basic;
    nr5g_rlcmac_Com_MacStatPxsch_t        Mcs[nr5g_rlcmac_Cmac_NUM_MCS];
    
    nr5g_rlcmac_Com_MacStatPdcch_t        Pdcch;

    nr5g_rlcmac_Com_BbStat_t BbStat; /* Base band specific statistic  */
} nr5g_rlcmac_Cmac_STAT_DBEAM_INDt;

/*
 * nr5g_rlcmac_Cmac_STAT_UE_CMD
 */
typedef struct
{
    uint    UeId;           /* UE Identifier */   
    uint    StatReq;        /*0: MCS stat  request - 1: RV stat request (Optional field: MOT present->MCS stat)*/
} nr5g_rlcmac_Cmac_STAT_UE_REQt;



typedef struct
{
    nr5g_RbType_v RbType;    /* Radio Bearer Type */
    uchar   RbId;           /* Rb id */
    nr5g_rlcmac_Com_RlcStatElem_t    Elem;  /* RLC specific statistics */
} nr5g_rlcmac_Cmac_RlcStat_t;

/*
 * nr5g_rlcmac_Cmac_STAT_UE_HI_IND
 */
typedef struct
{
    uint    UeId;           /* UE Identifier */
   
    uint    DeltaTs;        /* Interval between current and previous stat report */

    uchar   Type;           /* Set it to 0: for future extension */

    uint    NumRlc;
    nr5g_rlcmac_Cmac_RlcStat_t    Rlc[nr5g_rlcmac_Cmac_STAT_NUM_RLC];  /* RLC stat */

    nr5g_rlcmac_Com_MacStatBasic_t    Basic;
    nr5g_rlcmac_Com_MacStatBuff_t    Buff;
 
} nr5g_rlcmac_Cmac_STAT_UE_HI_INDt;

/*
 * nr5g_rlcmac_Cmac_STAT_UE_LO_IND
 */
typedef struct
{
    uint    UeId;           /* UE Identifier */
    uint    CellId;         /* Cell Identifier */
    uchar   SCellIdx;       /* Secondary Cell Identifier */
    uchar   IsLast;         /* Last statistics flag:
                               0 -> other statistics will follow (current is not the last one), 1 -> last statistic, 2 -> statistic procedure aborted */
    uint    DeltaTs;        /* Interval between current and previous stat report */
    
    uchar   Type;           /* Set it to 0: for future extension */
    nr5g_rlcmac_Com_MacStatPxsch_t        Mcs[nr5g_rlcmac_Cmac_NUM_MCS];
    nr5g_rlcmac_Com_MacStatPdcch_t        Pdcch;

    nr5g_rlcmac_Com_PMIt            Pmi;
    int                             Snr[nr5g_rlcmac_MAX_NUM_LAYER];   /* Per-layer SNR in dB; -1 means "not valid" */

} nr5g_rlcmac_Cmac_STAT_UE_LO_INDt;

typedef struct
{
    uint    UeId;           /* UE Identifier */
    uint    CellId;         /* Cell Identifier */
    uchar   SCellIdx;       /* Secondary Cell Identifier */
    uchar   IsLast;         /* Last statistics flag:
                               0 -> other statistics will follow (current is not the last one), 1 -> last statistic, 2 -> statistic procedure aborted */
    uint    DeltaTs;        /* Interval between current and previous stat report */
    
    uchar   Type;           /* Set it to 1: for future extension */
    uchar   UlMcs;
    uchar   DlMcs;
    nr5g_rlcmac_Com_MacStatPxsch_t        Rv[nr5g_rlcmac_Cmac_NUM_RV];
    nr5g_rlcmac_Com_MacStatPdcch_t        Pdcch;
} nr5g_rlcmac_Cmac_STAT_UE_LO_RV_INDt;

/*------------------------------------------------------------------*
 |  SUMMARY OF PRIMITIVES                                           |
 *------------------------------------------------------------------*/

typedef union {
    nr5g_rlcmac_Cmac_ACK_t                        Ack;
    nr5g_rlcmac_Cmac_NAK_t                        Nak;

    nr5g_rlcmac_Cmac_CONFIG_CMD_t                  ConfigCmd;
    nr5g_rlcmac_Cmac_SEG_CONFIG_REQ_t              SegConfigCmd;
    nr5g_rlcmac_Cmac_RRC_STATE_CFG_CMD_t           RrcStateCfgCmd;
    nr5g_rlcmac_Cmac_CELL_RRC_STATE_CFG_CMD_t      CellRrcStateCfgCmd;
    nr5g_rlcmac_Cmac_RESET_CMD_t                   ResetCmd;
    nr5g_rlcmac_Cmac_RELEASE_CMD_t                 ReleaseCmd;
    nr5g_rlcmac_Cmac_STATUS_REQ_t                  StatusReq;
    nr5g_rlcmac_Cmac_STATUS_CNF_t                  StatusCnf;
    nr5g_rlcmac_Cmac_STATUS_IND_t                  StatusInd;
    nr5g_rlcmac_Cmac_DBEAM_IND_t                   DbeamInd;
    nr5g_rlcmac_Cmac_CELL_STATUS_IND_t             CellStatusInd;
    nr5g_rlcmac_Cmac_CELL_STATUS_REQ_t             CellStatusReq;
    nr5g_rlcmac_Cmac_CELL_STATUS_t                 CellStatusCnf;

    nr5g_rlcmac_Cmac_RACH_ACC_CMDt                 RachAccCmd;
    nr5g_rlcmac_Cmac_RACH_ACC_INDt                 RachAccInd;
    
    nr5g_rlcmac_Cmac_L1T_START_TEST_CMD_t         StartTestCmd;
    nr5g_rlcmac_Cmac_L1T_STOP_TEST_CMD_t          StopTestCmd;
    nr5g_rlcmac_Cmac_L1T_LOG_IND_t                LogInd;
    nr5g_rlcmac_Cmac_L1T_DEBUG_CFG_CMD_t          DebugCfgCmd;
    nr5g_rlcmac_Cmac_L1T_BINDUMP_CMD_t            BindumpCfg;
    nr5g_rlcmac_Cmac_L1L2T_CONF_START_TEST_CMD_t  ConfStartCmd;
    nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_TEST_CMD_t   ConfStopCmd;
    nr5g_rlcmac_Cmac_L1T_L2_BINDUMP_CFG_CMD_t     L2BinDumpCfg;

    nr5g_rlcmac_Cmac_L1L2T_CONF_START_PRACH_TEST_CMD_t ConfStartPrachCmd;
    nr5g_rlcmac_Cmac_L1L2T_CONF_STOP_PRACH_TEST_CMD_t   ConfStopPrachCmd;
    nr5g_rlcmac_Cmac_L1L2T_RACH_START_LOOP_CMD_t        ConfRachStartLoop;
    nr5g_rlcmac_Cmac_L1L2T_PUCCH_START_CMD_t        ConfPucchStart;

    nr5g_rlcmac_Cmac_STAT_CELL_REQt                StatCellReq;
    nr5g_rlcmac_Cmac_STAT_DBEAM_INDt               StatDbeamInd;
    nr5g_rlcmac_Cmac_STAT_UE_REQt                  StatUeReq;
    nr5g_rlcmac_Cmac_STAT_UE_HI_INDt               StatUeHiInd;
    nr5g_rlcmac_Cmac_STAT_UE_LO_INDt               StatUeLoInd;

} nr5g_rlcmac_Cmac_PRIMu;

#pragma    pack()
#endif
