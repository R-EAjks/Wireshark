#ifndef nr5g_rlcmac_Cmac_BB_DEFINED
#define nr5g_rlcmac_Cmac_BB_DEFINED

#include "bb-nr5g_instr_macros.h"
#include "bb-nr5g_struct.h"

#pragma pack(1)


#define nr5g_rlcmac_Cmac_DRX_ON_DURATION_TIMER_SUBMILLISEC (0)
#define nr5g_rlcmac_Cmac_DRX_ON_DURATION_TIMER_MILLISEC    (1)

#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS10       (0)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS20       (1)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS32       (2)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS40       (3)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS60       (4)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS64       (5)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS70       (6)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS80       (7)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS128      (8)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS160      (9)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS256      (10)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS320      (11)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS512      (12)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS640      (13)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS1024     (14)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS1280     (15)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS2048     (16)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS2560     (17)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS5120     (18)
#define nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_MS10240    (19)

typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /*  */
    uint32_t Spare;
    uint8_t NbPuschTimeDomResAlloc;   /* Gives the number of valid elements in PuschAlloc vector:
                                         1...bb_nr5g_MAX_NB_UL_ALLOCS; Default value is 0*/
    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt), PuschTimeDomResAlloc, bb_nr5g_MAX_NB_UL_ALLOCS);
} PREFIX(nr5g_rlcmac_Cmac_PUSCH_CONF_COMMONt);

/* 38.331 SchedulingRequestResourceConfig IE: it determines physical layer resources on PUCCH where the UE may send the dedicated scheduling request*/
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /*  */
    uint32_t Spare;
    uint8_t SRResourceId;/* Range 0 ...(bb_nr5g_MAX_SR_RESOURCES-1);  */
    uint8_t SRId;/* SchedulingRequestId, Range 0 ...7;  */
    uint8_t ResourceId; /* PUCCH Resource identifier. Range 0 ...(bb_nr5g_MAX_PUCCH_RESOURCES -1); Default value is 0xFF */
    uint8_t SRPeriodAndOffSetIsValid;/* This field assumes a value defined as bb_nr5g_SR_PERIODICITYANDOFFSET_***
                                            in order to read in good way the associated parameter CsiResPeriodAndOffSet.
                                            If this field is set to default value CsiResPeriodAndOffSet is neither read or used */
    /* SR periodicity and offset in number of slots*/
    union{
        uint16_t Sym2;   /*  Range 0; Default is 0xFFFF */
        uint16_t Sym6_7; /*  Range 0; Default is 0xFFFF */
        uint16_t Slot1;  /*  Range 0; Default is 0xFFFF */
        uint16_t Slot2; /*  Range 0..1; Default is 0xFFFF */
        uint16_t Slot4; /*  Range 0..3; Default is 0xFFFF */
        uint16_t Slot5; /*  Range 0..4; Default is 0xFFFF */
        uint16_t Slot8; /*  Range 0..7; Default is 0xFFFF */
        uint16_t Slot10; /*  Range 0..9; Default is 0xFFFF */
        uint16_t Slot16; /*  Range 0..15; Default is 0xFFFF */
        uint16_t Slot20; /*  Range 0..19; Default is 0xFFFF */
        uint16_t Slot40; /*  Range 0..39; Default is 0xFFFF */
        uint16_t Slot80; /*  Range 0..79; Default is 0xFFFF */
        uint16_t Slot160; /*  Range 0..159; Default is 0xFFFF */
        uint16_t Slot320; /*  Range 0..319; Default is 0xFFFF */
        uint16_t Slot640; /*  Range 0..639; Default is 0xFFFF */
    } SRPeriodAndOffSet;
} PREFIX(nr5g_rlcmac_Cmac_SR_RESOURCE_CFGt);

typedef struct {
    uint32_t Len;    /* Effective length of this Element */
    uint32_t Spare; /* Must be set to 0 */

    uint8_t NbDl_DataToUL_ACK_r16;
    uint8_t NbDl_DataToUL_ACK_DCI_1_2_r16;
    uint8_t NbSchedulingRequestResourceToAdd;
    uint8_t Spare1; /* Must be set to 0 */
    AFIELD(int8_t, Dl_DataToUL_ACK_r16, 8);
    AFIELD(uint8_t, Dl_DataToUL_ACK_DCI_1_2_r16, 8);
    AFIELD(uint8_t, SchedulingRequestResourceToAdd, bb_nr5g_MAX_SR_RESOURCES); /* Enum[p0, p1] */
} PREFIX(nr5g_rlcmac_Cmac_PUCCH_CONF_DEDICATED_R16_IESt);

/* 38.331 PUCCH-Config: it is used to configure the UE specific PUCCH parameters applicable to a particular BWP*/
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /* Field mask according to bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_***_PRESENT */
    uint32_t FieldMask;
    uint8_t NbDlDataToUlAck;  /* Gives the number of valid elements in DlDataToUlAck vector: 1...8; Default value is 0*/
    uint8_t DlDataToUlAck[8]; /* Static list of timing for given PDSCH to the DL ACK. Range element 0...15*/
    uint8_t  NSchedReqResConfigToAdd;  /* Gives the number of valid elements in  vector SchedReqResCfg: 1...bb_nr5g_MAX_SR_RESOURCES; Default value is 0*/
#define nr5g_rlcmac_Cmac_STRUCT_PUCCH_CONF_DEDICATED_R16_IES_PRESENT 0x0020
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_PUCCH_CONF_DEDICATED_R16_IESt), PucchConfExtR16);
#define nr5g_rlcmac_Cmac_STRUCT_PUCCH_CONF_DEDICATED_SR_RES_CFG_PRESENT    0x0001
    AFIELD(PREFIX(nr5g_rlcmac_Cmac_SR_RESOURCE_CFGt), SchedReqResCfg, bb_nr5g_MAX_SR_RESOURCES); /* Dynamic list of added scheduling Request Resources*/
} PREFIX(nr5g_rlcmac_Cmac_PUCCH_CONF_DEDICATEDt);

/* 38.331 BWP-UplinkCommon IE : It is prepared to become dynamic. 
   Actually we decide to use the structure as static to semplify the handling */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t FieldMask; 
    PREFIX(bb_nr5g_BWPt)   GenBwp;
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_COMMON_RACH_CFG_PRESENT    0x0001
    PREFIX(bb_nr5g_RACH_CONF_COMMONt) RachCfgCommon;
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_COMMON_PUSCH_CFG_PRESENT   0x0002
    PREFIX(nr5g_rlcmac_Cmac_PUSCH_CONF_COMMONt) PuschCfgCommon;
} PREFIX(nr5g_rlcmac_Cmac_BWP_UPLINKCOMMONt);

/* 38.331 PUSCH-Config: it is used to configure the UE specific PUSCH parameters applicable to a particular BWP*/
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t FieldMask;
    uint8_t NbPuschAllocDed;  /* Gives the number of valid elements in PuschAllocDed vector: 1...bb_nr5g_MAX_NB_UL_ALLOCS; Default value is 0*/
    uint8_t NbPuschTimeDomainAlloListDCI01_r16; /* Default value 0, -1 meas Release (SetupRelease Need M) */
    uint8_t NbPuschTimeDomainAlloListDCI02_r16; /* Default value 0, -1 meas Release (SetupRelease Need M) */
    uint8_t NbPuschTimeDomainAllocListForMultiPUSCH_r16; /* Default value 0, -1 meas Release (SetupRelease Need M) */

    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt), PuschAllocDed, bb_nr5g_MAX_NB_UL_ALLOCS); /* Dynamic list of time domain allocations for timing of UL assignment to UL data*/
    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOC_R16t), PuschTimeDomainAlloListDCI01_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);    
    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOC_R16t), PuschTimeDomainAlloListDCI02_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);
    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOC_R16t), PuschTimeDomainAllocListForMultiPUSCH_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);
} PREFIX(nr5g_rlcmac_Cmac_PUSCH_CONF_DEDICATEDt);

/* 38.331 NR-ConfiguredGrantConfig IE: it is used to configure uplink transmission without dynamic grant */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t FieldMask; 
    uint8_t NbHarqProcesses;        /* The number of HARQ processes configured. Range 1..16 */
    uint8_t RepK;                   /* The number of repetitions of K. Enum [n1, n2, n4, n8] */
    uint8_t RepKRV;                 /* The redundancy version (RV) sequence to use if repK is set to n2, n4 or n8.
                                        Otherwise, the field is absent; Default value 0xFF; Need R */
    uint8_t Periodicity;            /* Enum [sym2, sym7, sym1x14, sym2x14, sym4x14, sym5x14, sym8x14, sym10x14, sym16x14, sym20x14,
                                        sym32x14, sym40x14, sym64x14, sym80x14, sym128x14, sym160x14, sym256x14, sym320x14, sym512x14,
                                        sym640x14, sym1024x14, sym1280x14, sym2560x14, sym5120x14, sym6, sym1x12, sym2x12, sym4x12,
                                        sym5x12, sym8x12, sym10x12, sym16x12, sym20x12, sym32x12, sym40x12, sym64x12, sym80x12, sym128x12,
                                        sym160x12, sym256x12, sym320x12, sym512x12, sym640x12, sym1280x12, sym2560x12] */
    struct {
        uint16_t TimeDomOffset;         /* Offset [slots] related to SFN=0; Range 0..5119; Default value 0xFF; Need R */
    } RrcConfUlGrant;

    uint8_t Timer;                  /* Indicates the initial value of the configured grant timer in multiples of periodicity.
                                       Range 1..64; Default value 0xFF; Need R */
    uint8_t cg_RetransmissionTimer_r16; /*  Range 1..64; Default value 0xFF */

    uint8_t CgNrofPUSCHInSlot_r16;  /* Range 1..7; Default value 0xFF */
    uint8_t CgNrofSlots_r16;        /* Range 1..40; Default value 0xFF */
    uint8_t CgUCIMultiplexing;      /* Enum [enabled];  Default value 0xFF */
    uint8_t BetaOffsetCG_UCI_r16;   /* Range 0..31; Default value 0xFF */

    uint8_t HarqProcIDOffset_r16;   /* Range 0..15; Default value 0xFF */
    uint8_t HarqProcIDOffset2_r16;  /* Range 0..15; Default value 0xFF */
    uint8_t ConfigGrantConfigIndex_r16; /* Range (0.. maxNrofConfiguredGrantConfig-r16-1=11) */
    uint8_t ConfigGrantConfigIndexMAC_r16; /* Range (0.. maxNrofConfiguredGrantConfigMAC-r16-1=31) */

    uint16_t PeriodicityExt_r16;          /* Range (1.. 5120) */
    uint8_t StartingFromRV0_r16;      /* Enum [on, off];  Default value 0xFF */
    uint8_t Phy_PriorityIndex_r16;    /* Enum [p0, p1];   Default value 0xFF */

    uint8_t AutonomousTx_r16;         /* Enum [enabled];  Default value 0xFF */
    uint8_t Spare[3]; /* Must be set to 0xFF */
} PREFIX(nr5g_rlcmac_Cmac_CONFIGURED_GRANT_CONFt);

typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t Spare;
    uint8_t ResourceSetId; /* SRS Resource Set id 0...(bb_nr5g_MAX_SRS_RESOURCE_SETS-1); Default/Invalid value is 0xFF*/
    uint8_t NbResourceIdList; /*Gives the number of valid elements in ResourceIdList vector: 1.. bb_nr5g_MAX_SRS_RESOURCE_PERSET; Default value is 0*/
    uint8_t Usage; /* Indicates if the SRS resource set is used for beam management vs. used for either codebook based or non-codebook based transmission
                     Enum [beamManagement, codebook, nonCodebook, antennaSwitching]; Default/Invalid value is 0xFF */
    uint8_t Pad[2];
    uint8_t ResourceIdList[bb_nr5g_MAX_SRS_RESOURCE_PERSET]; /*The IDs of the SRS-Reosurces used in this SRS-ResourceSet*/
    PREFIX(bb_nr5g_SRS_RESOURCETYPESETt) ResourceType;
} PREFIX(nr5g_rlcmac_Cmac_SRS_RESOURCE_SETt);

typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t Spare;
    uint8_t ResourceId; /*SRS Resource id 0...(bb_nr5g_MAX_SRS_RESOURCES-1); Default/Invalid value is 0xFF*/
    PREFIX(bb_nr5g_SRS_RESOURCETYPEt) ResourceType; /*Time domain behavior of SRS resource configuration*/
} PREFIX(nr5g_rlcmac_Cmac_SRS_RESOURCEt);

/* 38.331 SRS-Config IE: it is used to configure sounding reference signal transmissions */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t Spare;
    uint8_t NbResourceSetsToDel;  /* Gives the number of valid elements in ResourceSetsToDel vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourceSetsToAdd;  /* Gives the number of valid elements in ResourceSetsToAdd vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourcesToDel;  /* Gives the number of valid elements in ResourceSetsToDel vector: 1...bb_nr5g_MAX_SRS_RESOURCES; Default value is 0*/
    uint8_t NbResourcesToAdd;  /* Gives the number of valid elements in ResourceSetsToAdd vector: 1...bb_nr5g_MAX_SRS_RESOURCES; Default value is 0*/
    AFIELD(uint32_t, ResourceSetsToDel, bb_nr5g_MAX_SRS_RESOURCE_SETS); /* Dynamic list for deleting SRS resource sets*/
    AFIELD(PREFIX(nr5g_rlcmac_Cmac_SRS_RESOURCE_SETt), ResourceSetsToAdd, bb_nr5g_MAX_SRS_RESOURCE_SETS); /* Dynamic list for adding SRS resource sets*/
    AFIELD(uint32_t, ResourcesToDel, bb_nr5g_MAX_SRS_RESOURCES); /* Dynamic list for deleting SRS resources*/
    AFIELD(PREFIX(nr5g_rlcmac_Cmac_SRS_RESOURCEt), ResourcesToAdd, bb_nr5g_MAX_SRS_RESOURCES); /* Dynamic list for adding SRS resources*/
} PREFIX(nr5g_rlcmac_Cmac_SRS_CONF_DEDICATEDt);

/* 38.331 BWP-UplinkDedicated IE */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t FieldMask;
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_PUCCH_CFG_PRESENT   0x0001
    PREFIX(nr5g_rlcmac_Cmac_PUCCH_CONF_DEDICATEDt) PucchConfDed; 
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_PUSCH_CFG_PRESENT   0x0002
    PREFIX(nr5g_rlcmac_Cmac_PUSCH_CONF_DEDICATEDt) PuschConfDed;
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_SRS_CFG_PRESENT   0x0004
    PREFIX(nr5g_rlcmac_Cmac_SRS_CONF_DEDICATEDt)   SrsConfDed;
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_CONFIGURED_GRANT_PRESENT 0x0008
    PREFIX(nr5g_rlcmac_Cmac_CONFIGURED_GRANT_CONFt) GrantConfDed;
    /* Configuration of beam failure recovery. It can be present only for SpCell.
       If supplementaryUplink is present, the field is present 
       only in one of the uplink carriers, either UL or SUL. */
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DED_BEAM_RECOVERY_CFG_PRESENT   0x0010
    VFIELD(PREFIX(bb_nr5g_BEAM_FAIL_RECOVERY_CFGt),   BeamFailRecConfDed);
} PREFIX(nr5g_rlcmac_Cmac_BWP_UPLINKDEDICATEDt);

/* 38.331 BWP-Uplink IE */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t FieldMask;
     uint8_t BwpId;  /* BwpId is used to refer to Bandwidth Parts (BWP). The initial BWP is
                        referred to by BwpId 0.
                        The other BWPs are referred to by 1 to bb_nr5g_MAX_NB_BWPS.*/
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_COMMON_CFG_PRESENT   0x0001
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_BWP_UPLINKCOMMONt), BwpULCommon);
#define nr5g_rlcmac_Cmac_STRUCT_BWP_UPLINK_DEDICATED_CFG_PRESENT   0x0002
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_BWP_UPLINKDEDICATEDt), BwpULDed);
} PREFIX(nr5g_rlcmac_Cmac_BWP_UPLINKt);

typedef struct {
    uint8_t XOverhead; /* Accounts for overhead from CSI-RS, CORESET, etc. If the field is absent, the UE applies value xOh0.
                          Enum [xOh6, xOh12, xOh18]; Default/Invalid value is 0xFF*/
} PREFIX(nr5g_rlcmac_Cmac_PUSCH_SERVING_CELL_CFGt);

typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /* Field mask according to bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG***_PRESENT */
    uint32_t FieldMask;
    uint8_t FirstActiveUlBwp; /* If configured for an SpCell, this field contains the ID of the UL BWP to be activated upon performing the reconfiguration
                                 in which it is received. If the field is absent, the RRC reconfiguration does not impose a BWP switch.
                                 If configured for an SCell, this field contains the ID of the downlink bandwidth part to be used upon MAC-activation of an SCell.
                                 If not provided, the UE uses the default BWP.
                                 The initial bandwidth part is referred to by BwpId = 0.
                                 Range 0....(bb_nr5g_MAX_NB_BWPS-1); Default value is 0xFF*/
    uint8_t Spare;
    
    uint8_t NbUlBwpIdToDel; /* Gives the number of valid elements in UlBwpIdToDel vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t NbUlBwpIdToAdd; /* Gives the number of valid elements in UlBwpIdToAdd vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t UlBwpIdToDel[bb_nr5g_MAX_NB_BWPS]; /*Static list of additional uplink bandwidth parts to be released*/
    /* The dedicated (UE-specific) configuration for the initial uplink bandwidth-part*/
#define nr5g_rlcmac_Cmac_STRUCT_UPLINK_DEDICATED_CONFIG_INITIAL_UL_BWP_PRESENT   0x0001
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_BWP_UPLINKDEDICATEDt), InitialUlBwp);
#define nr5g_rlcmac_Cmac_STRUCT_UPLINK_DEDICATED_CONFIG_PUSCH_PRESENT   0x0002
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_PUSCH_SERVING_CELL_CFGt), PuschServingCellCfg);
    AFIELD(PREFIX(nr5g_rlcmac_Cmac_BWP_UPLINKt), UlBwpIdToAdd, bb_nr5g_MAX_NB_BWPS); /*Dynamic list of additional uplink bandwidth parts to be added/modified*/
} PREFIX(nr5g_rlcmac_Cmac_UPLINK_DEDICATED_CONFIGt); 

typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t FieldMask;
    uint8_t CsiRepCfgId; /* CSI-ReportConfigId. Range 0 ...(bb_nr5g_MAX_NB_CSI_REPORT_CFGS-1). 
                           Default/Invalid value is 0xff*/
    uint8_t ReportConfigTypeIsValid; /* This field assumes a value defined as bb_nr5g_CSI_REPORT_CFG_TYPE_***
                              in order to read in good way the associated parameter ReportConfigType.
                              If this field is set to default value ReportConfigType is neither read or used */
    union{
        PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODICt) RepCfgPer;
        PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCHt) RepCfgSemiPersOnPucch;
        PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCHt) RepCfgSemiPersOnPusch;
    } ReportConfigType;

#define nr5g_rlcmac_Cmac_STRUCT_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610_PRESENT 0x0002
    VFIELD(PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610t), SemiPersistentOnPUSCH_v1610);
#define nr5g_rlcmac_Cmac_STRUCT_CSI_REPORT_CFG_TYPE_APERIODIC_v1610_PRESENT 0x0004
    VFIELD(PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610t), Aperiodic_v1610);
} PREFIX(nr5g_rlcmac_Cmac_CSI_REPORT_CFGt);

/* 38.331 CSI-MeasConfig IE: it is used to configure CSI-RS (reference signals) belonging to the serving cell in which CSI-MeasConfig is included and channel state information reports
to be transmitted on L1 (PUCCH, PUSCH) on the serving cell in which CSI-MeasConfig is included */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    uint32_t Spare; /* Set to zero */
    uint8_t NbCsiRepCfgToDel; /* Gives the number of valid elements in CsiRepCfgToDel vector: 1...bb_nr5g_MAX_NB_CSI_REPORT_CFGS; Default value is 0*/
    uint8_t NbCsiRepCfgToAdd; /* Gives the number of valid elements in CsiRepCfgToAdd vector: 1...bb_nr5g_MAX_NB_CSI_REPORT_CFGS; Default value is 0*/
    AFIELD(uint32_t, CsiRepCfgToDel, bb_nr5g_MAX_NB_CSI_REPORT_CFGS); /*Dynamic list of CSI Report to be deleted  */
    AFIELD(PREFIX(nr5g_rlcmac_Cmac_CSI_REPORT_CFGt), CsiRepCfgToAdd, bb_nr5g_MAX_NB_CSI_REPORT_CFGS); /*Dynamic list of Configured CSI report settings to be added/modify */    
} PREFIX(nr5g_rlcmac_Cmac_CSI_MEAS_CFGt);
/* 38.331 CellGroupConfig IE: Serving cell specific MAC and PHY parameters for a SpCell */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /* Field mask according to bb_nr5g_STRUCT_SERV_CELL_CONFIG_***_PRESENT */
    uint32_t FieldMask;
    uint32_t ServCellIdx; /* default is 0xFFFFFFFF. */

    uint8_t DefaultDlBwpId; /* 1 to bb_nr5g_MAX_NB_BWPS; Default/Absent 0xFF */
    uint8_t SupplUlRel; /* Enum[true]; Default/NoAction 0xFF */
    uint8_t Spare[2]; /* Must be set to 0xFF */
#define nr5g_rlcmac_Cmac_STRUCT_SERV_CELL_CONFIG_UPLINK_PRESENT   0x0004
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_UPLINK_DEDICATED_CONFIGt), UlCellCfgDed);
#define nr5g_rlcmac_Cmac_STRUCT_SERV_CELL_CONFIG_SUP_UPLINK_PRESENT   0x0008
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_UPLINK_DEDICATED_CONFIGt), SulCellCfgDed);
#define nr5g_rlcmac_Cmac_STRUCT_CSI_MEAS_CFG_PRESENT   0x0010
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_CSI_MEAS_CFGt), CsiMeasCfg);
} PREFIX(nr5g_rlcmac_Cmac_SERV_CELL_CONFIGt);

/* 38.331 SCellConf IE: it is used to configure secondary cell for a specific UE */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /* Field mask according to bb_nr5g_STRUCT_SCELL_CONFIG_***_PRESENT */
    uint32_t FieldMask;

    /* Secondary cell dedicated parameter configuration */
    /* To semplify the handling we decide to have ServCellIdx also at this level*/
    uint16_t ServCellIdx;
    uint8_t sCellState_r16; /* ENUMERATED {activated}; Default/NoAction 0xFF */
    uint8_t Spare[1]; /* Must be set to 0xFF */

#define nr5g_rlcmac_Cmac_STRUCT_SCELL_CONFIG_DED_PRESENT   0x0001
    /* Secondary cell dedicated parameter configuration */
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_SERV_CELL_CONFIGt), SCellCfgDed);
} PREFIX(nr5g_rlcmac_Cmac_SCELL_CONFIGt);


/* 38.331 DRX-Config IE: used to configure DRX related parameters. */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /* Field mask according to bb_nr5g_STRUCT_SERV_CELL_CONFIG_***_PRESENT */
    uint32_t Spare;

    uint8_t drx_onDurationTimer_IsValid; /* This field assumes a value defined as nr5g_rlcmac_Cmac_DRX_ON_DURATION_TIMER_*** */
    union {
        uint32_t  subMilliSeconds; /* INTEGER (1..31). Value in multiples of 1/32 ms. */
        uint32_t milliSeconds;    /* Enum: [ms1, ms2, ms3, ms4, ms5, ms6, ms8, ms10, ms20, ms30, ms40, ms50, ms60, ms80, ms100, ms200, ms300, ms400, ms500, ms600, ms800, ms1000, ms1200, ms1600] */
    } drx_onDurationTimer; /* The field to be read is linked to drx_onDurationTimer_IsValid field */

    uint32_t drx_InactivityTimer; /* Enum: [ms0, ms1, ms2, ms3, ms4, ms5, ms6, ms8, ms10, ms20, ms30, ms40, ms50, ms60, ms80, ms100, ms200, ms300, ms500, ms750, ms1280, ms1920, ms2560] */

    uint8_t drx_HARQ_RTT_TimerDL; /* INTEGER (0..56). Value in number of symbols of the BWP where the transport block was received. */

    uint8_t drx_HARQ_RTT_TimerUL; /* INTEGER (0..56). Value in number of symbols of the BWP where the transport block was transmitted. */

    uint32_t drx_RetransmissionTimerDL; /* Enum: [sl0, sl1, sl2, sl4, sl6, sl8, sl16, sl24, sl33, sl40, sl64, sl80, sl96, sl112, sl128, sl160, sl320]. Value in number of slot lengths of the BWP where the transport block was received. */

    uint32_t drx_RetransmissionTimerUL; /* Enum: [sl0, sl1, sl2, sl4, sl6, sl8, sl16, sl24, sl33, sl40, sl64, sl80, sl96, sl112, sl128, sl160, sl320]. Value in number of slot lengths of the BWP where the transport block was transmitted. */

    uint8_t drx_LongCycleStartOffset_IsValid; /* This field assumes a value defined as nr5g_rlcmac_Cmac_DRX_LONG_CYCLE_***. */
    union {
        uint32_t ms10      ; /* INTEGER(0..9)    */
        uint32_t ms20      ; /* INTEGER(0..19)   */ 
        uint32_t ms32      ; /* INTEGER(0..31)   */
        uint32_t ms40      ; /* INTEGER(0..39)   */
        uint32_t ms60      ; /* INTEGER(0..59)   */
        uint32_t ms64      ; /* INTEGER(0..63)   */
        uint32_t ms70      ; /* INTEGER(0..69)   */
        uint32_t ms80      ; /* INTEGER(0..79)   */
        uint32_t ms128     ; /* INTEGER(0..127)  */
        uint32_t ms160     ; /* INTEGER(0..159)  */
        uint32_t ms256     ; /* INTEGER(0..255)  */
        uint32_t ms320     ; /* INTEGER(0..319)  */
        uint32_t ms512     ; /* INTEGER(0..511)  */
        uint32_t ms640     ; /* INTEGER(0..639)  */
        uint32_t ms1024    ; /* INTEGER(0..1023) */
        uint32_t ms1280    ; /* INTEGER(0..1279) */
        uint32_t ms2048    ; /* INTEGER(0..2047) */
        uint32_t ms2560    ; /* INTEGER(0..2559) */
        uint32_t ms5120    ; /* INTEGER(0..5119) */
        uint32_t ms10240   ; /* INTEGER(0..10239) */
    } drx_LongCycleStartOffset; /* The field to be read is linked to drx_LongCycleStartOffset_IsValid field.
                                   drx-LongCycle in ms and drx-StartOffset in multiples of 1ms. If drx-ShortCycle is configured, the value of drx-LongCycle shall be a multiple of the drx-ShortCycle value.  */

    uint32_t drx_ShortCycle;        /* Enum: [ms2, ms3, ms4, ms5, ms6, ms7, ms8, ms10, ms14, ms16, ms20, ms30, ms32, ms35, ms40, ms64, ms80, ms128, ms160, ms256, ms320, ms512, ms640]. Not present value is 0xFFFFFFFF (Need R) */

    uint32_t drx_ShortCycleTimer;   /* INTEGER(0..31). Value in multiples of drx-ShortCycle. A value of 1 corresponds to drx-ShortCycle, a value of 2 corresponds to 2 * drx-ShortCycle and so on. Not present value is 0 (Need R) */

    uint8_t drx_SlotOffset; /* INTEGER (0..31). Value in 1/32 ms. Value 0 corresponds to 0ms, value 1 corresponds to 1/32ms, value 2 corresponds to 2/32ms, and so on. */

} PREFIX(nr5g_rlcmac_Cmac_DRX_CONFIGt);


/* 38.331 MAC-CellGroupConfig IE: used to configure MAC parameters for a cell group */
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /* Field mask according to bb_nr5g_STRUCT_SERV_CELL_CONFIG_***_PRESENT */
    uint32_t FieldMask;
    uint8_t lch_BasedPrioritization_r16; /* ENUMERATED {enabled}; Default 0xFF: NotPresent/Reset (Need R) */
    /* Used to configure DRX */
    uint8_t Spare[3]; /* must be set to 0xFF */
#define nr5g_rlcmac_Cmac_STRUCT_DRX_CONFIG_PRESENT   0x0001
    VFIELD(PREFIX(nr5g_rlcmac_Cmac_DRX_CONFIGt), DrxConfig);
} PREFIX(nr5g_rlcmac_Cmac_MAC_CELL_GROUP_CONFIGt);

/* 38.331 CellGroupConfig IE: Serving cell specific MAC and PHY parameters for a SpCell and for SCell*/
typedef struct {
    uint32_t Len;   /* Effective length of this Element */
    /* Field mask according to bb_nr5g_STRUCT_SPCELL_CONFIG_***_PRESENT */
    uint16_t FieldMask;
    /*  Message static part has to be put at the beginning */
    uint8_t NbSCellCfgDel;     /* Gives the number of valid elements in SCellCfgDel vector:
                                   1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0*/
    uint8_t NbSCellCfgAdd;     /* Gives the number of valid elements in SCellCfgAdd vector:
                                   1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0*/

    /* Cell-Group specific L1 parameters */
    struct {
        uint32_t CsRNTI; /* RNTI-Value := Range (0..65535); Default/NoAction value is 0xFFFFFFFF, Release is 0xFFFFFFFE; SetupRelease Need M */
    } PhyCellConf;

    /* Primary cell dedicated parameter configuration */
#define nr5g_rlcmac_Cmac_STRUCT_SPCELL_CONFIG_DED_PRESENT   0x0001
    PREFIX(nr5g_rlcmac_Cmac_SERV_CELL_CONFIGt) SpCellCfgDed;
    /* MAC parameters applicable for the entire cell group. */
#define nr5g_rlcmac_Cmac_STRUCT_MAC_CELL_GROUP_CONFIG_PRESENT   0x0002
    PREFIX(nr5g_rlcmac_Cmac_MAC_CELL_GROUP_CONFIGt) MAC_CellGroupConfig;

    AFIELD(uint32_t, SCellCfgDel, bb_nr5g_MAX_NB_SERVING_CELLS); /*Dynamic list of serving cell id of aggregable cells to be deleted */
    /* Aggregable dedicated cell parameter configuration */
    AFIELD(PREFIX(nr5g_rlcmac_Cmac_SCELL_CONFIGt), SCellCfgAdd, bb_nr5g_MAX_NB_SERVING_CELLS); /* Dynamic list of aggregable cells to be added or to modified */
} PREFIX(nr5g_rlcmac_Cmac_CELL_DEDICATED_CONFIGt);

#pragma    pack()
#endif
