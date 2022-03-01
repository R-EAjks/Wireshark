/********************************************************************
$Source$
$Author$
$Date$
---------------------------------------------------------------------
Project :
Description :
---------------------------------------------------------------------
$Revision$
$State$
$Name$
---------------------------------------------------------------------
$Log$
*********************************************************************/

#ifndef  bb_nr5g_struct_macro_DEFINED
#define  bb_nr5g_struct_marco_DEFINED

#define bb_nr5g_INTERNAL
#include "bb-nr5g_def.h"

#pragma  pack(1)
/*
 * The current bb-nr5g Interface version
 */
#define     bb_nr5g_struct_VERSION       "1.0.1"

#define bb_nr5g_RNTI_C_RNTI     0
#define bb_nr5g_RNTI_SI_RNTI    1
#define bb_nr5g_RNTI_P_RNTI     2
#define bb_nr5g_RNTI_RA_RNTI    3
#define bb_nr5g_RNTI_INT_RNTI   4
#define bb_nr5g_RNTI_SFI_RNTI   5

/* RNTI */
typedef struct {
    uint16_t          RntiType; /* Rnti type see bb_nr5g_RNTI_*** */
    uint16_t          Rnti;     /* RNTI */
} STRUCT_NAME(tm_, bb_nr5g_RNTIt);

/**********************************************************************************************************************
 * The TDD-UL-DL-Config IEs determines the Uplink/Downlink TDD configuration. There are both, UE- and cell specific IEs.*/
/* 38.331 TDD-UL-DL-ConfigCommon */
typedef struct {
    uint8_t     RefSubCarSpacing; /* Corresponds to L1 parameter 'reference-SCS' (see 38.211, section FFS_Section)
                                     Enum kHz15, kHz30, kHz60, kHz120, kHz240; Default/Invalid value is 0xFF*/
    uint8_t     DlULTransmPeriodicity; /* Periodicity of the DL-UL pattern. 
                                       Corresponds to L1 parameter 'DL-UL-transmission-periodicity' (see 38.211, section FFS_Section)
                                       Enum ms0p5, ms0p625, ms1, ms1p25, ms2, ms2p5, ms5, ms10; Default/Invalid value is 0xFF*/
    uint16_t    NrDLSlots;       /* Number of consecutive full DL slots at the beginning of each DL-UL pattern.
                                    Corresponds to L1 parameter 'number-of-DL-slots' (see 38.211, Table 4.3.2-1)
                                    Range (0...bb_nr5g_MAX_NB_SLOTS);Default/Invalid value is 0xFFFF*/
    uint8_t     NrDLSymbols;     /* Number of consecutive DL symbols in the beginning of the slot following the last full DL slot 
                                    If the field is absent or released, there is no partial-downlink slot.
                                    Corresponds to L1 parameter 'number-of-DL-symbols-common' (see 38.211, section FFS_Section).                         
                                    Range (0...bb_nr5g_MAX_NB_SYMBS -1);Default/Invalid value is 0xFF*/
    uint8_t     NrULSymbols;     /* Number of consecutive UL symbols in the end of the slot preceding the first full UL slot 
                                    If the field is absent or released, there is no partial-uplink slot.
                                    Corresponds to L1 parameter 'number-of-UL-symbols-common' (see 38.211, section FFS_Section).                         
                                    Range (0...bb_nr5g_MAX_NB_SYMBS -1);Default/Invalid value is 0xFF*/
    uint16_t    NrULSlots;       /* Number of consecutive full UL slots at the beginning of each DL-UL pattern.
                                    Corresponds to L1 parameter 'number-of-UL-slots' (see 38.211, Table 4.3.2-1)
                                    Range (0...bb_nr5g_MAX_NB_SLOTS);Default/Invalid value is 0xFFFF*/
} STRUCT_NAME(tm_, bb_nr5g_TDD_UL_DL_CONFIG_COMMONt);

/****************************************************************************************/
/* 38.331 TDD-UL-DL-ConfigDedicated */
typedef struct {
    uint16_t    SlotIndex; /* Identifies a slot within a dl-UL-TransmissionPeriodicity. Range 0...bb_nr5g_MAX_NB_SLOTS-1 */
    uint8_t     Symbols;   /* Possible values are :
                              bb_nr5g_TDD_UL_DL_SLOT_ALLDL : indicates that all symbols in this slot are used for DL  
                              bb_nr5g_TDD_UL_DL_SLOT_ALLUL : indicates that all symbols in this slot are used for UL  
                              bb_nr5g_TDD_UL_DL_SLOT_EXPLICIT : indicates explicitly how many symbols
                              in the beginning and end of this slot are allocated to downlink and uplink, respectively. 
                              bb_nr5g_TDD_UL_DL_SLOT_DEFAULT: invalid value */
    uint8_t     DownlinkSymbols; /* Number of consecutive DL symbols in the beginning of the slot identified by SlotIndex 
                                 Default/Invalid value is 0xFF. Range 1... bb_nr5g_MAX_NB_SYMBS -1.
                                 It has meaning in case of Symbols field assumes the bb_nr5g_TDD_UL_DL_SLOT_EXPLICIT value */
    uint8_t     UplinkSymbols;  /* Number of consecutive UL symbols in the beginning of the slot identified by SlotIndex 
                                 Default/Invalid value is 0xFF. Range 1... bb_nr5g_MAX_NB_SYMBS -1.
                                 It has meaning in case of Symbols field assumes the bb_nr5g_TDD_UL_DL_SLOT_EXPLICIT value */
    uint8_t     Spare[3];
} STRUCT_NAME(tm_, bb_nr5g_TDD_UL_DL_SLOT_CONFIGt);

typedef struct {
    uint16_t nbSlotSpecCfgAddMod; /* Gives the number of valid elements in SlotSpecCfgAddMod. Range (0...bb_nr5g_MAX_NB_SLOTS - 1)*/
    uint16_t nbSlotSpecCfgDel;    /* Gives the number of valid elements in SlotSpecCfgDel. Range (0...bb_nr5g_MAX_NB_SLOTS - 1)*/
    STRUCT_NAME(tm_, bb_nr5g_TDD_UL_DL_SLOT_CONFIGt) SlotSpecCfgAddMod[bb_nr5g_MAX_NB_SLOTS]; /* The SlotSpecCfg* allows overriding UL/DL allocations provided in tdd-UL-DL-configurationCommon
                                    Dynamic list of SlotSpecCfg to be added/modified */
    uint32_t                       SlotSpecCfgDel[bb_nr5g_MAX_NB_SLOTS];    /* Dynamic list of SlotSpecCfg to be deleted */                  
} STRUCT_NAME(tm_, bb_nr5g_TDD_UL_DL_CONFIG_DEDICATEDt);

/****************************************************************************************/
/* 38.331 ControlResourceSet IE:used to configure a time/frequency control resource set (CORESET) in which 
   to search for downlink control information */
typedef struct {
    uint8_t  CtrlResSetId;       /* Corresponds to L1 parameter 'CORESET-ID;
                                    Default/Invalid value is 0xFF. Range 0... bb_nr5g_MAX_NB_CTRL_RES_SETS -1  */
    uint8_t  CtrlResSetDuration; /* Corresponds to L1 parameter 'CORESET-time-duration' (see 38.211, section 7.3.2.2FFS_Section)
                                    Default/Invalid value is 0xFF. Range 1... bb_nr5g_MAX_CORESET_DURATION  */
    uint8_t  PrecGranularity;    /* Corresponds to L1 parameter 'CORESET-precoder-granuality' (see 38.211, sections 7.3.2.2 and 7.4.1.3.2)
                                    Enum [sameAsREG-bundle, allContiguousRBs]; Default/Invalid value is 0xFF */                            
    uint8_t  CceRegMapType;      /* 0=nonInterleaved; 1=interleaved; Default/Invalid value is 0xFF*/
    uint8_t  RegBundleSize;      /* Corresponds to L1 parameter 'CORESET-REG-bundle-size' (see 38.211, section FFS_Section)
                                    Enum [n2, n3, n6]; Default/Invalid value is 0xFF */                            
    uint8_t  InterleaverSize;    /* Corresponds to L1 parameter 'CORESET-REG-bundle-size' (see 38.211, section FFS_Section)
                                    Enum [n2, n3, n6]; Default/Invalid value is 0xFF */       
    uint16_t ShiftIndex;         /* Corresponds to L1 parameter 'CORESET-shift-index' (see 38.211, section 7.3.2.2)
                                    Range 0 ....bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1; Default/Invalid value is 0xFFFF */
    uint64_t FreqDomRes;        /*  Frequency domain resources for the CORESET. BitMap: each bit corresponds a group of 6 RBs, 
                                    with grouping starting from PRB 0, which is fully contained in the bandwidth part within 
                                    which the CORESET is configured. Size is 45*/
    uint16_t PdcchDMRSScramblingId; /* Corresponds to L1 parameter 'PDCCH-DMRS-Scrambling-ID' (see 38.214, section 5.1)*/
    uint8_t TciPresentInDci;    /*  Corresponds to L1 parameter 'TCI-PresentInDCI' (see 38,213, section 5.1.5) 
                                    Enum [enable]; Default/Invalid value is 0xFF  */ 

    uint8_t NbTciStates;        /*  Gives the number of valid elements in TciStates vector: 1....bb_nr5g_MAX_NB_TCI_STATES_PDCCH */
    uint8_t TciStates[bb_nr5g_MAX_NB_TCI_STATES_PDCCH]; /* Corresponds to L1 parameter 'TCI-StatesPDCCH' (see 38.214, section FFS_Section)*/
} STRUCT_NAME(tm_, bb_nr5g_CTRL_RES_SETt);

/****************************************************************************************/
/* 38.331 SearchSpace IE:defines how/where to search for PDCCH candidates */
typedef struct {
    uint8_t AggLev1;  /* Default/Invalid value is 0xFF: Enum [n0, n1, n2, n3, n4, n5, n6, n8] */
    uint8_t AggLev2;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t AggLev4;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t AggLev8;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t AggLev16; /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t Spare[3];
} STRUCT_NAME(tm_, bb_nr5g_MONITOR_NBCANDIDATESt);

typedef struct {
    uint8_t DciFmts00And10;  /* Default/Invalid value is 0xFF: TBD */
    uint8_t DciFmts20;       /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t DciFmts21;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t DciFmts22;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t DciFmts23;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t DciFmts23MonPeriodicity; /* It is filled with valid values if DciFmts23 is different than 0xFF*/
                                    /*  Default/Invalid value is 0xFF; Enum [n1, n2, n4, n5, n6, n8, n10, n16, n20]  */
    uint8_t DciFmts23PdcchCand;     /* It is filled with valid values if DciFmts23 is different than 0xFF*/
                                    /*  Default/Invalid value is 0xFF; Enum [n1, n2]  */
    uint8_t Spare;
    STRUCT_NAME(tm_, bb_nr5g_MONITOR_NBCANDIDATESt) DciFmts20CandSFI; /* It is filled with valid values if DciFmts20 is different than 0xFF*/

} STRUCT_NAME(tm_, bb_nr5g_SEARCH_SPACETYPE_COMMONt);

typedef struct {
    uint8_t DciFmts; /* Default/Invalid value is 0xFF: Enum [formats0-0-And-1-0, formats0-1-And-1-1] */
    uint8_t Spare[3];
} STRUCT_NAME(tm_, bb_nr5g_SEARCH_SPACETYPE_DEDICATEDt);

typedef struct {
    uint8_t  SearchSpaceId;     /*  Identity of the search space
                                    Default/Invalid value is 0xFF. Range 0... bb_nr5g_MAX_NB_SEARCH_SPACES -1  */
    uint8_t  CtrlResSetId;       /* The CORESET applicable for this SearchSpace
                                    Default/Invalid value is 0xFF. Range 0... bb_nr5g_MAX_NB_CTRL_RES_SETS -1  */
    uint16_t MonitorSymbsInSlot; /* Symbols for PDCCH monitoring in the slots configured for PDCCH monitoring
                                    Bitmap size(14) (see MonitorSlot field). */

    uint8_t  MonitorSlotIsValid;   /* This field assumes a value defined as bb_nr5g_SEARCH_SPACE_MONSLOT_*** 
                                       in order to read in good way the associated parameter MonitorSlot. 
                                       If this field is set to default value MonitorSlot is neither read or used */
    uint8_t  SearchSpaceTypeIsValid;  /* This field assumes a value defined as bb_nr5g_SEARCH_SPACE_TYPE_*** 
                                       in order to read in good way the associated parameters in SearchSpaceType. 
                                       If this field is set to default value SearchSpaceType is neither read or used */
    uint8_t  Spare;
    union {
        uint8_t Sl1;  /* Default value is 0xFF */
        uint8_t Sl2;  /* Default value is 0xFF; Range 0...1 */
        uint8_t Sl4;  /* Default value is 0xFF; Range 0...3 */
        uint8_t Sl5;  /* Default value is 0xFF; Range 0...4 */
        uint8_t Sl8;  /* Default value is 0xFF; Range 0...7 */
        uint8_t Sl10; /* Default value is 0xFF; Range 0...9 */ 
        uint8_t Sl16; /* Default value is 0xFF; Range 0...15 */
        uint8_t Sl20; /* Default value is 0xFF; Range 0...19 */       
    } MonitorSlot; /* Slots for PDCCH Monitoring configured as periodicity and offset. The field to be read is linked to 
                      MonitorSlotIsValid field */
    STRUCT_NAME(tm_, bb_nr5g_MONITOR_NBCANDIDATESt)      NbCandidates;   /* Number of PDCCH candidates per aggregation level*/
    union {
    	STRUCT_NAME(tm_, bb_nr5g_SEARCH_SPACETYPE_COMMONt)    SearchSpaceTypeCommon;
    	STRUCT_NAME(tm_, bb_nr5g_SEARCH_SPACETYPE_DEDICATEDt) SearchSpaceTypeDedicated;
    } SearchSpaceType;
} STRUCT_NAME(tm_, bb_nr5g_SEARCH_SPACEt);

/****************************************************************************************/
/* 38.331 DownlinkPreemption IE: Configuration of downlink preemption indication on PDCCH. */

typedef struct {
    uint16_t ServCellIdx;  /*Serving cell identifier */
    uint8_t PositionInDCI; /* Starting position (in number of bit) of the 14 bit INT value applicable 
                            for this serving cell (servingCellId) within the DCI payload.
                            Default/Invalid value is 0xFF; Range 0....(bb_nr5g_MAX_INT_DCI_PAYLOAD_SIZE-1)*/
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_INT_CFG_PER_SERVINGCELLt);

typedef struct {
    uint8_t TimeFrequencySet; /* Set selection for DL-preemption indication. 
                                 Corresponds to L1 parameter 'int-TF-unit' 
                                 (see 38.213, section 10.1)
                                 Default/Invalid value is 0xFF. Enum [set0, set1]*/
    uint8_t DciPayloadSize;  /* Total length of the DCI payload scrambled with INT-RNTI.
                                Default/Invalid value is 0xFF; Range 0....bb_nr5g_MAX_INT_DCI_PAYLOAD_SIZE*/
    uint8_t NbIntConfPerServingCell; /*Gives the number of valid elements in IntConfPerServingCell vector: 
                                     Range:1 ..bb_nr5g_MAX_NB_SERVING_CELLS; Default/Invalid value is 0*/
    uint8_t Pad;   
    STRUCT_NAME(tm_, bb_nr5g_RNTIt) IntRnti;      /* RNTI used for indication pre-emption in DL. */
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_INT_CFG_PER_SERVINGCELLt), IntConfPerServingCell[bb_nr5g_MAX_NB_SERVING_CELLS_OBJ]);
                                /* Dynamic list: Indicates (per serving cell) the position of the 14 bit INT values inside the DCI payload.*/
} STRUCT_NAME(tm_, bb_nr5g_DOWNLINK_PREEMPTIONt);

/****************************************************************************************/
/* 38.331 SlotFormatCombinations applicable for one serving cell.*/
typedef struct {
    uint16_t SlotFormatCombinationId; /* SFI index that is assoicated with a certian slot-format-combination
                                       Range:1 ..bb_nr5g_MAX_SLOT_FMT_COMBS_PER_SET; Default/Invalid value is 0xFFFF*/
    uint16_t NbSlotFormats; /*Gives the number of valid elements in SlotFormats vector: 
                                     Range:1 ..bb_nr5g_MAX_NB_SLOT_FMTS_PER_COMB; Default/Invalid value is 0*/
    VFIELD(uint32_t, SlotFormats[bb_nr5g_MAX_NB_SLOT_FMTS_PER_COMB_OBJ]); /* Dynamic list. Element range is 0 ...255 */
} STRUCT_NAME(tm_, bb_nr5g_SLOT_FMT_COMBt);

typedef struct {
    uint16_t ServCellIdx;  /*Serving cell identifier */    
    uint8_t SubcarrierSpacing;  /* Reference subcarrier spacing for this Slot Format Combination*/
    uint8_t SubcarrierSpacing2; /* Reference subcarrier spacing for a Slot Format Combination on an FDD or SUL cell*/
    uint8_t PositionInDCI;      /* The (starting) position (bit) of the slotFormatCombinationId (SFI-Index)
                                   Range 0..bb_nr5g_MAX_SFI_DCI_PAYLOAD_SIZE;Default/Invalid value is 0xFF*/
    uint8_t Pad;
    uint16_t NbSlotFormatCombinations; /* Gives the number of valid elements in slotFormatCombinations vector: 
                                         Range:1 ..bb_nr5g_MAX_SLOT_FMT_COMBS_PER_SET; Default/Invalid value is 0*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SLOT_FMT_COMBt), slotFormatCombinations[bb_nr5g_MAX_SLOT_FMT_COMBS_PER_SET_OBJ]);/*Dynamic list*/
} STRUCT_NAME(tm_, bb_nr5g_SLOT_FMT_COMBSPERCELLt);

/* SlotFormatIndicator IE*/
typedef struct {
    uint8_t DciPayloadSize;  /* Total length of the DCI payload scrambled with SFI-RNTI.
                                Default/Invalid value is 0xFF; Range 1....bb_nr5g_MAX_SFI_DCI_PAYLOAD_SIZE*/
    uint8_t NbSlotFormatCombToAdd; /*Gives the number of valid elements in slotFormatCombToAdd vector: 
                                     Range:1 ..bb_nr5g_MAX_AGG_CELLS_PER_GROUP; Default/Invalid value is 0*/
    uint8_t NbSlotFormatCombToDel; /*Gives the number of valid elements in SlotFormatCombToDel vector: 
                                     Range:1 ..bb_nr5g_MAX_AGG_CELLS_PER_GROUP; Default/Invalid value is 0*/
    uint8_t Pad;   
    STRUCT_NAME(tm_, bb_nr5g_RNTIt) Rnti;               /* RNTI used for SFI on the given cell */
    VFIELD(uint32_t, SlotFormatCombToDel[bb_nr5g_MAX_AGG_CELLS_PER_GROUP_OBJ]); /* Dynamic list */
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SLOT_FMT_COMBSPERCELLt), slotFormatCombToAdd[bb_nr5g_MAX_AGG_CELLS_PER_GROUP_OBJ]); /* Dynamic list */
} STRUCT_NAME(tm_, bb_nr5g_SLOT_FMT_INDICATORt);

/****************************************************************************************/
/* PUSCH-TPC-CommandConfig IE */
typedef struct {
    uint8_t TpcIndex; /*An index determining the position of the first bit 
                        of TPC command inside the DCI format 2-2 
                        Range:1 ..15; Default/Invalid value is 0xFF*/
    uint8_t TcpIndexSUL;/*An index determining the position of the first bit 
                        of TPC command inside the DCI format 2-2 
                        Range:1 ..15; Default/Invalid value is 0xFF*/
    uint16_t ServCellIdx;  /*Serving cell identifier */    
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_TPC_CFGt);

/* PUCCH-TPC-CommandConfig IE */
typedef struct {
    uint8_t TpcIndexPCell; /*An index determining the position of the first bit 
                        of TPC command inside the DCI format 2-2 
                        Range:1 ..15; Default/Invalid value is 0xFF*/
    uint8_t TpcIndexSCell;/*An index determining the position of the first bit 
                        of TPC command inside the DCI format 2-2 
                        Range:1 ..15; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];     
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_TPC_CFGt);

/****************************************************************************************/
/* PTRS-DownlinkConfig IE */
typedef struct {

    uint8_t NbEpreRatioPort2; /* Gives the number of valid elements in EpreRatioPort2 vector: 
                                     Range:1 or 2; Default value is 0*/
    uint8_t NbFrequencyDensity; /* Gives the number of valid elements in FrequencyDensity vector: 
                                     Range: 2; Default value is 0*/
    uint8_t NbTimeDensity; /* Gives the number of valid elements in TimeDensity vector: 
                                     Range: 3; Default value is 0*/
    uint8_t ResElemeOffset; /* Indicates the subcarrier offset for DL PTRS.
                               Enum [offset01, offset10, offset11]; Default/Invalid value is 0xFF*/
    uint16_t FrequencyDensity[2]; /* Presence and frequency density of DL PT-RS as a function of Scheduled BW
                                     Element range 1..276. Size of the static vector is 2 */
    uint8_t TimeDensity[3];  /* Presence and frequency density of DL PT-RS as a function of Scheduled BW
                                    Element range 0..29. Size of the static vector is 2*/
    uint8_t EpreRatioPort1;    /* EPRE ratio between PTRS and PDSCH. Range:0 ...3; Default/Invalid value is 0xFF*/
    uint8_t EpreRatioPort2[2]; /* EPRE ratio between PTRS and PDSCH. Element range:0 ...3; Default/Invalid value is 0xFF. 
                                  Size of the static vector is 1 or 2*/
    uint8_t Pad[2];
} STRUCT_NAME(tm_, bb_nr5g_PTRS_DOWNLINK_CFGt);

/* DMRS-DownlinkConfig IE */
typedef struct {
    uint8_t DmrsType;   /* Selection of the DMRS type to be used for DL 
                           Enum [type2]; Default/Invalid value is 0xFF*/
    uint8_t DmrsAddPos; /* Position for additional DM-RS in DL 
                           Enum [pos0, pos1, pos3]; Default/Invalid value is 0xFF*/
    uint16_t DmrsGroup1; /* DM-RS groups that are QCL 
                            BIT STRING (SIZE (12)); Default/Invalid value is 0xFFFF*/
    uint16_t DmrsGroup2; /* DM-RS groups that are QCL 
                            BIT STRING (SIZE (12)); Default/Invalid value is 0xFFFF*/
    uint8_t MaxLength;   /* The maximum number of OFDM symbols for DL front loaded DMRS 
                            Enum [len2]; Default/Invalid value is 0xFF*/
    uint8_t IsPhaseTrackingRSValid; /* This parameter handles if the PhaseTrackingRS has to be considered as optional or not.
									   If this parameter is set to 0 -> PhaseTrackingRS field is not read because not valid 
									   If this parameter is set to 1 -> PhaseTrackingRS field is present*/
    uint32_t ScramblingID0; /* DL DMRS scrambling initalization
                               Range 0....65535 */
    uint32_t ScramblingID1; /* DL DMRS scrambling initalization
                               Range 0....65535 */
    STRUCT_NAME(tm_, bb_nr5g_PTRS_DOWNLINK_CFGt) PhaseTrackingRS;
} STRUCT_NAME(tm_, bb_nr5g_DMRS_DOWNLINK_CFGt);

/* PTRS-UplinkConfig IE */
typedef struct {
    uint8_t NbFrequencyDensity; /* Gives the number of valid elements in FrequencyDensity vector: 
                                    Range: 2; Default value is 0*/
    uint8_t NbTimeDensity; /* Gives the number of valid elements in TimeDensity vector: 
                                     Range: 3; Default value is 0*/                                     
    uint8_t MaxNbPorts;         /* Maximum number of UL PTRS ports. Enum [n1, n2]; Default/Invalid value is 0xFF*/
    uint8_t ResElemOffset; /* Indicates the subcarrier offset for UL PTRS.
                               Enum [offset01, offset10, offset11]; Default/Invalid value is 0xFF*/
    uint8_t PtrsPower; /*UL PTRS power boosting factor per PTRS port. Enum [p00, p01, p10, p11]; Default/Invalid value is 0xFF*/
    uint8_t TimeDensity[3];  /* Presence and frequency density of UL PT-RS for CP-OFDM waveform as a function of MCS
                                    Element range 0..29. Size of the static vector is 2*/
    uint16_t FrequencyDensity[2]; /* Presence and frequency density of UL PT-RS for CP-OFDM waveform as a function of scheduled BW
                                     Element range 1..276. Size of the static vector is 2 */
} STRUCT_NAME(tm_, bb_nr5g_CP_OFDM_CFGt);

typedef struct {
    uint8_t NbSampleDensity; /* Gives the number of valid elements in SampleDensity vector: 
                                    Range: 5; Default value is 0*/
    uint8_t TimeDensity; /* Time density. Enum [d2]; Default/Invalid value is 0xFF*/
    uint16_t SampleDensity[5]; /* Sample density of PT-RS
                                  Element range 1..276. Size of the static vector is 5 */
} STRUCT_NAME(tm_, bb_nr5g_DFT_S_OFDM_CFGt);

typedef struct {
    uint8_t ModeSpecParamsIsValid;/* This field assumes a value defined as bb_nr5g_PTRS_UPLINK_MODE_SPEC_PARAMS_*** 
                                       in order to read in good way the associated parameters in ModeSpecPars. 
                                       If this field is set to default value ModeSpecPars is neither read or used.
                                       In this case bb_nr5g_PTRS_UPLINK_CFGt is considered as not configured*/  
    uint8_t Pad[3];  
    union{
    	STRUCT_NAME(tm_, bb_nr5g_CP_OFDM_CFGt) CpOfdmMode;
    	STRUCT_NAME(tm_, bb_nr5g_DFT_S_OFDM_CFGt) DftsOfdmMode;
    } ModeSpecParams;  
} STRUCT_NAME(tm_, bb_nr5g_PTRS_UPLINK_CFGt);

/* DMRS-UplinkConfig IE */
typedef struct {
    uint32_t ScramblingID0; /* UL DMRS scrambling initalization for CP-OFDM
                               Range 0....65535 */
    uint32_t ScramblingID1; /* UL DMRS scrambling initalization for CP-OFDM
                               Range 0....65535 */
} STRUCT_NAME(tm_, bb_nr5g_TRANSF_PRECOD_DISABLEt);

typedef struct {
    uint16_t PuschIdentity;/* Parameter: N_ID^(PUSCH) for DFT-s-OFDM DMRS
                               Range 0....1007 */
    uint8_t DisableSeqGroupHop; /* Sequence-group hopping for PUSCH can be disabled for a certain UE despite being enabled on a cell basis 
                            Enum [disabled]; Default/Invalid value is 0xFF*/
    uint8_t SeqHopEnabled; /* Determines if sequence hopping is enabled or not 
                            Enum [enabled]; Default/Invalid value is 0xFF*/
} STRUCT_NAME(tm_, bb_nr5g_TRANSF_PRECOD_ENABLEt);

typedef struct {
    uint8_t DmrsType;   /* Selection of the DMRS type to be used for UL 
                           Enum [type2]; Default/Invalid value is 0xFF*/
    uint8_t DmrsAddPos; /* Position for additional DM-RS in UL 
                           Enum [pos0, pos1, pos3]; Default/Invalid value is 0xFF*/
    uint8_t MaxLength;   /* The maximum number of OFDM symbols for UL front loaded DMRS 
                            Enum [len2]; Default/Invalid value is 0xFF*/
    uint8_t TransfPrecodIsValid;/* This field assumes a value defined as bb_nr5g_DMRS_UPLINK_TRANSF_PRECOD_*** 
                                       in order to read in good way the associated parameters in TransfPrecod. 
                                       If this field is set to default value TransfPrecod is neither read or used */    
    union{
    	STRUCT_NAME(tm_, bb_nr5g_TRANSF_PRECOD_DISABLEt) TransfPrecodDisable;
    	STRUCT_NAME(tm_, bb_nr5g_TRANSF_PRECOD_ENABLEt) TransfPrecodEnable;
    } TransfPrecod;  
    STRUCT_NAME(tm_, bb_nr5g_PTRS_UPLINK_CFGt) PhaseTrackingRS;
} STRUCT_NAME(tm_, bb_nr5g_DMRS_UPLINK_CFGt);

/****************************************************************************************/
/* BetaOffsets IE*/
typedef struct {
    uint8_t BetaOffsetAckIdx1; /* Up to 2 bits HARQ-ACK. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 11. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetAckIdx2; /* Up to 11 bits HARQ-ACK. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 11. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetAckIdx3; /* Up to 11 bits HARQ-ACK. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 11. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetCsiPart1Idx1; /* Up to 11 bits CSI part 1 bits. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 11. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetCsiPart1Idx2; /* Up to 11 bits CSI part 1 bits. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 11. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetCsiPart2Idx1; /* Up to 11 bits CSI part 2 bits. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 11. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetCsiPart2Idx2; /* Up to 11 bits CSI part 2 bits. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 11. Range 0...31; Default value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_BETAOFFSETSt);

/* UCI-OnPUSCH IE*/
typedef struct {
    uint8_t Scaling; /* Indicates a scaling factor to limit the number of resource elements assigned to UCI on PUSCH
                        Enum [f0p5, f0p65, f0p8, f1]; Default/Invalid value is 0xFF*/
    uint8_t BetaOffsetsIsValid;/* This field assumes a value defined as bb_nr5g_UCI_ON_PUSCH_BETAOFFSETS_*** 
                                       in order to read in good way the associated parameters in BetaOffsets. 
                                       If this field is set to default value BetaOffsets is neither read or used */    
    uint8_t NbBetaOffsets; /* Gives the number of valid elements in BetaOffsets vector: 
                                    Range: 1 if BetaOffsetsIsValid=bb_nr5g_UCI_ON_PUSCH_BETAOFFSETS_SEMISTATIC or 4 if BetaOffsetsIsValid=bb_nr5g_UCI_ON_PUSCH_BETAOFFSETS_DYNAMIC; 
                                    Default value is 0*/
    uint8_t Pad;
    STRUCT_NAME(tm_, bb_nr5g_BETAOFFSETSt) BetaOffsets[4];
} STRUCT_NAME(tm_, bb_nr5g_UCI_ON_PUSCHt);

/****************************************************************************************/
/* QCLInfo IE */
typedef struct {
    uint16_t ServCellIdx;  /* The carrier which the RS is located in. Default/Invalid value is 0xFFFF. In this case the structure is considered
                              as filled with not valid values */    
    uint8_t  BwpId;        /* BwpId is used to refer to Bandwidth Parts (BWP). 
                              The initial BWP is referred to by BwpId 0. The other BWPs are referred to by BwpId 1 to bb_nr5g_MAX_NB_BWPS.
                              Default/Invalid value is 0xFF */
    uint8_t  QclType;      /* Enum [typeA, typeB, typeC, typeD]; Default/Invalid value is 0xFF*/
    uint8_t RefSigIsValid; /* This field assumes a value defined as bb_nr5g_QCL_INFO_REF_SIG_*** 
                                       in order to read in good way the associated parameters in RefSig. 
                                       If this field is set to default value RefSig is neither read or used */
    union{
        uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
        uint8_t Ssb;              /* Range 0....63; Default is 0xFF */
        uint8_t CsiRsForTracking; /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS-1); Default is 0xFF */
    } RefSig;  
    uint8_t Pad[2];
} STRUCT_NAME(tm_, bb_nr5g_QCL_INFOt);

/* TCI-State IE */
typedef struct {
    uint8_t TciStateId; /* Range 0....(bb_nr5g_MAX_NB_TCI_STATES-1); Default/Invalid is 0xFF */
    uint8_t NbPtrsPorts; /*Enum [n1, n2]; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];
    STRUCT_NAME(tm_, bb_nr5g_QCL_INFOt) QclType1;
    STRUCT_NAME(tm_, bb_nr5g_QCL_INFOt) QclType2;
} STRUCT_NAME(tm_, bb_nr5g_TCI_STATEt);

/****************************************************************************************/
/* RateMatchPattern IE*/
typedef struct {
    uint8_t  SubCarSpacing;          /* SubcarrierSpacing for this resource pattern
                                       Enum [kHz15, kHz30, kHz60, kHz120, kHz240]; Default/Invalid value is 0xFF*/
    uint8_t  Mode;                  /* Enum [dynamic, semiStatic]; Default/Invalid value is 0xFF */
    uint8_t  SymbInResBlockIsValid; /* This field assumes a value defined as bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SYMBRES_*** 
                                       in order to read in good way the associated parameter SymbInResBlock. 
                                       If this field is set to default value SymbInResBlock is neither read or used */
    uint8_t  PeriodicityAndPatternIsValid; /* This field assumes a value defined as bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_*** 
                                       in order to read in good way the associated parameter PeriodicityAndPattern. 
                                       If this field is set to default value PeriodicityAndPattern is neither read or used */
    uint32_t ResBlocks[bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SIZERES]; /* A resource block level bitmap in the frequency domain
                                                                      Bitmap Size(275) */
    uint32_t SymbInResBlock;
    uint64_t PeriodicityAndPattern; /* A time domain repetition pattern. Bitmap size to be considered as valid is
                                       defined by means of PeriodicityAndPatternIsValid field*/
 
} STRUCT_NAME(tm_, bb_nr5g_RATE_MATCH_PATTERN_BITMAPt);

typedef struct {
    uint8_t RateMatchPatternId;     /* Identifies one RateMatchMattern
                                       Default value is 0XFF; Range 0..bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS-1*/
    uint8_t RateMatchPatternType;   /* This field assumes a value defined as bb_nr5g_RATE_MATCH_PATTERN_*** in order to read
                                       in good way the associated structures. If this field is set to default value
                                       no pattern type in this bb_nr5g_RATE_MATCH_PATTERNt will be considered as valid */
    uint8_t RateMatchPatternCtrlResSet; /* This field is used as a PDSCH rate matching pattern. 
                                           Defaul value is 0xFF; it is assumed as to be valid only if RateMatchPatternType
                                           is set to bb_nr5g_RATE_MATCH_PATTERN_CTRLRESSET */
    uint8_t Spare;
    STRUCT_NAME(tm_, bb_nr5g_RATE_MATCH_PATTERN_BITMAPt)  RateMatchPatternBitmap; /* It is assumed as to be valid only if RateMatchPatternType
                                           is set to bb_nr5g_RATE_MATCH_PATTERN_BITMAP */
} STRUCT_NAME(tm_, bb_nr5g_RATE_MATCH_PATTERNt);

/****************************************************************************************/
/* PDSCH-TimeDomainResourceAllocation IE */
typedef struct {
    uint8_t K0;     /*  Corresponds to L1 parameter 'K0' (see 38.214, section FFS_Section)
                        When the field is absent the UE applies the value 0
                        Default value is 0xFF. Range 1...3  */
    uint8_t MappingType;    /* PDSCH mapping type. 
                               Corresponds to L1 parameter 'Mapping-type' (see 38.214, section FFS_Section)
                               Enum [typeA, typeB]; Default value is 0xFF*/
    uint8_t StartSymbAndLen;  /* An index into a table/equation in RAN1 specs capturing valid combinations of start symbol 
                                and length (jointly encoded).
                                Corresponds to L1 parameter 'Index-start-len' (see 38.214, section FFS_Section)
                                Bitmap of size(7); Default value is 0xFF*/
    uint8_t Spare;                   
} STRUCT_NAME(tm_, bb_nr5g_PDSCH_TIMEDOMAINRESALLOCt);

/****************************************************************************************/
/* CSI-FrequencyOccupation IE */
typedef struct {
    uint16_t StartingRB; /* PRB where this CSI resource starts in relation to PRB 0 of the associated BWP
                            Range 0...(bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1)*/
    uint16_t NrRBs;     /* Number of PRBs across which this CSI resource spans
                            Range 24...bb_nr5g_MAX_NB_PHYS_RES_BLOCKS*/
} STRUCT_NAME(tm_, bb_nr5g_CSI_FREQUENCY_OCCt);

/* CSI-RS-ResourceMapping IE */
typedef struct {
    uint8_t NbPorts; /* Number of ports: Enum [p1,p2,p4,p8,p12,p16,p24,p32]; Default value is 0xFF*/
    uint8_t FreqDomAllocIsValid; /* This field assumes a value defined as bb_nr5g_CSI_RS_RES_MAPPING_FREQ_DOMAIN_*** 
                                       in order to read in good way the associated parameter FreqDomAlloc. 
                                       If this field is set to default value FreqDomAlloc is neither read or used */
    union{
        uint8_t Row1;             /* BIT STRING (SIZE (4)); Default is 0xFF */
        uint16_t Row2;            /* BIT STRING (SIZE (12)); Default is 0xFFFF */
        uint8_t Row4;             /* BIT STRING (SIZE (3)); Default is 0xFF */
        uint8_t Other;            /* BIT STRING (SIZE (6)); Default is 0xFF */
    } FreqDomAlloc;  
    uint8_t FirstOFDMSymbolInTimeDomain; /* Time domain allocation within a physical resource block. Range 0...13; Default value is 0xFF */
    uint8_t FirstOFDMSymbolInTimeDomain2;/* Time domain allocation within a physical resource block. Range 0...13; Default value is 0xFF */
    uint8_t CdmType; /* CDM type. Enum [noCDM, fd-CDM2, cdm4-FD2-TD2, cdm8-FD2-TD4]; Default value is 0xFF */
    uint8_t DensityIsValid; /* This field assumes a value defined as bb_nr5g_CSI_RS_RES_MAPPING_DENSITY_*** 
                                       in order to read in good way the associated parameter Density. 
                                       If this field is set to default value Density is neither read or used */
    union{
        uint8_t Dot5;             /* Enum [evenPRBs, oddPRBs]; Default value is 0xFF */
        uint8_t One;              /* Default is 0xFF */
        uint8_t Three;            /* Default is 0xFF */
    } Density; 
    uint8_t Pad[3]; 
    STRUCT_NAME(tm_, bb_nr5g_CSI_FREQUENCY_OCCt) FreqBand; /* Wideband or partial band CSI-RS */
} STRUCT_NAME(tm_, bb_nr5g_CSI_RS_RES_MAPPINGt);

/* CSI-ResourcePeriodicityAndOffset IE */
typedef struct {
    uint8_t CsiResPeriodAndOffSetIsValid;/* This field assumes a value defined as bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_*** 
                                            in order to read in good way the associated parameter CsiResPeriodAndOffSet. 
                                            If this field is set to default value CsiResPeriodAndOffSet is neither read or used */
    uint8_t Pad;
    union{
        uint16_t Slot4; /*  Range 0..3; Default is 0xFFFF */
        uint16_t Slot5; /*  Range 0..4; Default is 0xFFFF */
        uint16_t Slot8; /*  Range 0..7; Default is 0xFFFF */
        uint16_t Slot10; /*  Range 0..9; Default is 0xFFFF */
        uint16_t Slot16; /*  Range 0..15; Default is 0xFFFF */
        uint16_t Slot20; /*  Range 0..19; Default is 0xFFFF */
        uint16_t Slot32; /*  Range 0..31; Default is 0xFFFF */
        uint16_t Slot40; /*  Range 0..39; Default is 0xFFFF */
        uint16_t Slot64; /*  Range 0..63; Default is 0xFFFF */
        uint16_t Slot80; /*  Range 0..79; Default is 0xFFFF */
        uint16_t Slot160; /*  Range 0..159; Default is 0xFFFF */
        uint16_t Slot320; /*  Range 0..319; Default is 0xFFFF */
        uint16_t Slot640; /*  Range 0..639; Default is 0xFFFF */
    } CsiResPeriodAndOffSet;    
} STRUCT_NAME(tm_, bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt);

/* ZP-CSI-RS-Resource IE */
typedef struct {
    uint8_t ResourceId; /* ZP CSI-RS resource set ID. Range 0.... (bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES-1) */
    uint8_t Pad[3];
    STRUCT_NAME(tm_, bb_nr5g_CSI_RS_RES_MAPPINGt) ResourceMapping; /* OFDM symbol and subcarrier occupancy of the ZP-CSI-RS resource within a slot */
    STRUCT_NAME(tm_, bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt) PeriodicityAndOffset;/*Periodicity and slot offset for periodic/semi-persistent ZP-CSI-RS*/
} STRUCT_NAME(tm_, bb_nr5g_ZP_CSI_RS_RESt);

/* ZP-CSI-RS-ResourceSet IE: it refers to a set of ZP-CSI-RS-Resources using their ZP-CSI-RS-ResourceIds.*/
typedef struct {
    uint8_t ResourceSetId; /* ZP CSI-RS resource configuration ID. Range 0.... (bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS-1) */
    uint8_t ResourceType;  /* Time domain behavior of ZP-CSI-RS resource configuration 
                              Enum [aperiodic, semiPersistent, periodic]; Default value is 0xFF */
    uint8_t Pad;
    uint8_t NbResourceSetIdList; /* Gives the number of valid elements in ResourceSetIdList vector: 1 .. bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS; 
                                    Default value is 0*/
    uint8_t ResourceSetIdList[bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS];
} STRUCT_NAME(tm_, bb_nr5g_ZP_CSI_RS_RES_SETt);

/****************************************************************************************/
/* PUCCH-Resource IE */
/* A PUCCH Format 0 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t InitCyclicShift; /* Range 0 ...11; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 1..2; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..13; Default value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT0t);

/* A PUCCH Format 1 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t InitCyclicShift; /* Range 0 ...11; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 4..14; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..10; Default value is 0xFF */
    uint8_t TimeDomainOCC;   /* Range 0..6; Default value is 0xFF */
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT1t);

/* A PUCCH Format 2 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t NrPRBs;          /* Range 1..16; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 1..2; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..13; Default value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT2t);

/* A PUCCH Format 3 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t NrPRBs;          /* Range 1..16; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 4..14; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..10; Default value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT3t);

/* A PUCCH Format 4 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t NrofSymbols;     /* Range 4..14; Default value is 0xFF */
    uint8_t OccLength;      /* Enum [n2,n4]; Default value is 0xFF */
    uint8_t OccIndex;        /* Enum [n0,n1,n2,n3]; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..10; Default value is 0xFF */
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT4t);

typedef struct {
    uint8_t ResourceId; /* Range 0 ...(bb_nr5g_MAX_PUCCH_RESOURCES -1); Default value is 0xFF */
    uint8_t IntraSlotFreqHop; /* Enum [enabled]; Default value is 0xFF */
    uint16_t StartingPRB; /* Range 0 ...(bb_nr5g_MAX_NB_PHYS_RES_BLOCKS -1); Default value is 0xFFFF */
    uint16_t SecondHopPRB; /* Index of starting PRB for second hop of PUCCH in case of FH. This value is appliable for intra-slot frequency hopping
                              Range 0 ...(bb_nr5g_MAX_NB_PHYS_RES_BLOCKS -1); Default value is 0xFFFF */
    uint8_t FormatIsValid; /* This field assumes a value defined as bb_nr5g_PUCCH_RESOURCE_FORMAT_*** 
                              in order to read in good way the associated parameter Format. 
                              If this field is set to default value Format is neither read or used */
    uint8_t Pad;                        
    union{
    	STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT0t fmt0);
    	STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT1t fmt1);
    	STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT2t fmt2);
    	STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT3t fmt3);
    	STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT4t fmt4);
    } Format;    
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_RESOURCEt);

typedef struct {
    uint8_t SpatialRelationInfoId; /* Range 0 ...(bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS -1); Default value is 0xFF */
    uint8_t PathlossRefRSId; /* Range 0 ...(bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS-1); Default/Invalid value is 0xFF */
    uint8_t ClosedLoopIdx; /* The index of the closed power control loop 
                                Enum [i0, i1]; Default/Invalid value is 0xFF */
    uint8_t P0PucchId; /*Range 1..8; Default/Invalid value is 0xFF*/
    uint8_t RefSigIsValid; /* This field assumes a value defined as bb_nr5g_SPATIAL_RELATION_INFO_REF_SIG_*** 
                                       in order to read in good way the associated parameters in RefSig. 
                                       If this field is set to default value RefSig is neither read or used */
    union{
        uint8_t Ssb;              /* Range 0....63; Default is 0xFF */
        uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
        uint8_t Srs;             /* Range 0....(bb_nr5g_MAX_SRS_RESOURCES-1); Default is 0xFF */
    } RefSig;  
    uint8_t Pad[2];
} STRUCT_NAME(tm_, bb_nr5g_SPATIAL_RELATION_INFOt);

typedef struct {
    uint8_t ResourceSetId; /* Range 0 ...(bb_nr5g_MAX_PUCCH_RESOURCE_SETS -1); Default value is 0xFF */
    uint8_t NbResources; /* Gives the number of valid elements in Resources vector: Range 8 ...bb_nr5g_MAX_PUCCH_RESOURCE_SETS; Default value is 0xFF */
    uint16_t MaxPayloadMinus1; /* Range 4...256. Default value is 0xFFFF*/
    uint8_t Resources[bb_nr5g_MAX_PUCCH_RESOURCES_PERSET]; /*PUCCH resources of format0 and format1 are only allowed in the first PUCCH reosurce set*/
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_RESOURCE_SETt);

/* PUCCH-FormatConfig IE */
typedef struct {
    uint8_t IntraSlotFreqHop; /* Enabling inter-slot frequency hopping when PUCCH Format 1, 3 or 4 is repetead over multiple slots.
                                 Enum [enabled]; Default value is 0xFF */
    uint8_t AdditionalDmrs; /* Enabling 2 DMRS symbols per hop of a PUCCH Format 3 or 4 if both hops are more than X symbols when FH is enabled (X=4).
                               Enabling 4 DMRS sybmols for a PUCCH Format 3 or 4 with more than 2X+1 symbols when FH is disabled (X=4). 
                               Enum [true]; Default/Invalid value is 0xFF*/
    uint8_t MaxCodeRate; /* Max coding rate to determine how to feedback UCI on PUCCH for format 2, 3 or 4
                                Enum [zeroDot08, zeroDot15, zeroDot25, zeroDot35, zeroDot45, zeroDot60, zeroDot80]; Default/Invalid value is 0xFF*/
    uint8_t NbSlots;  /* Number of slots with the same PUCCH F1, F3 or F4.Enum [n2,n4,n8]; Default/Invalid value is 0xFF*/
    uint8_t Pi2Pbsk;  /* Enabling pi/2 BPSK for UCI symbols instead of QPSK for PUCCH.Enum [enabled]; Default/Invalid value is 0xFF*/
    uint8_t SimultaneousHarqAckCsi; /*Enabling simultaneous transmission of CSI and HARQ-ACK feedback with or without SR with PUCCH Format 2, 3 or 4
                                      Enum [true]; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT_CFGt);

/****************************************************************************************/
/* 38.331 PUSCH-PowerControl IE: it is used to configure UE specific power control parameter for PUSCH.*/
typedef struct {
    uint8_t AlphaSetId; /* Range 0 ...(bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS-1); Default/Invalid value is 0xFF */
    int8_t P0;            /* P0 value for PUSCH with grant (except msg3) in steps of 1dB.Range -16...15 */
    uint8_t Alpha;       /* Alpha value for PUSCH with grant (except msg3)                     
                                Enum [alpha0, alpha04, alpha05, alpha06, alpha07, alpha08, alpha09, alpha1]; Default/Invalid value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_P0_PUSCH_ALPHASETt);

typedef struct {
    uint8_t PathlossRefRSId; /* Range 0 ...(bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS-1); Default/Invalid value is 0xFF */
    uint8_t Pad;
    uint8_t RefSigIsValid; /* This field assumes a value defined as bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RS_REF_SIG_*** 
                                       in order to read in good way the associated parameters in RefSig. 
                                       If this field is set to default value RefSig is neither read or used */
    union{
        uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
        uint8_t Ssb;              /* Range 0....63; Default is 0xFF */
    } RefSig; 
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RSt);

typedef struct {
    uint8_t SriPwCtrlId; /* Range 0 ...(bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING-1); Default/Invalid value is 0xFF */
    uint8_t SriPathlossRefRSId; /* Range 0 ...(bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS-1); Default/Invalid value is 0xFF */
    uint8_t SriAlphaSetId;  /* Range 0 ...(bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS-1); Default/Invalid value is 0xFF */
    uint8_t SriClosedLoopIdx; /* The index of the closed power control loop associated with this SRI-PUSCH-PowerControl
                                Enum [i0, i1]; Default/Invalid value is 0xFF */
} STRUCT_NAME(tm_, bb_nr5g_SRI_PUSCH_POWERCONTROLt);

typedef struct {
    uint8_t TpcAccumulation; /* If enabled, UE applies TPC commands via accumulation. If not enabled, UE applies the TPC command without accumulation
                                Enum [disabled]; Default value is 0xFF */
    uint8_t Msg3Alpha;       /* Dedicated alpha value for msg3 PUSCH.                     
                                Enum [alpha0, alpha04, alpha05, alpha06, alpha07, alpha08, alpha09, alpha1]; Default/Invalid value is 0xFF */
    int16_t P0NomWithoutGrant; /*P0 value for UL grant-free/SPS based PUSCH. Value in dBm.Range -202..24; Default value is 0xFFFF*/
    uint8_t TwoPuschPCAdjStates; /*Number of PUSCH power control adjustment states maintained by the UE (i.e., fc(i)).
                               Enum [twoStates]; Default/Invalid value is 0xFF */
    uint8_t DeltaMcs; /*Indicates whether to apply dela MCS. Enum [enabled]; Default/Invalid value is 0xFF */
    uint8_t NbP0AlphaSets; /* Gives the number of valid elements in P0AlphaSets vector: 1..bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS; Default value is 0*/
    uint8_t NbPathlossRefRsToAdd; /* Gives the number of valid elements in PathlossRefRsToAdd vector: 1..bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS; Default value is 0*/
    
    uint8_t NbPathlossRefRsToDel; /* Gives the number of valid elements in PathlossRefRsToDel vector: 1..bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS; Default value is 0*/
    uint8_t NbSriPuschMapToAdd; /* Gives the number of valid elements in SriPuschMapToAdd vector: 1..bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING; Default value is 0*/
    uint8_t NbSriPuschMapToDel; /* Gives the number of valid elements in SriPuschMapToAdd vector: 1..bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING; Default value is 0*/
    uint8_t Pad;

    uint8_t PathlossRefRsToDel[bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS]; /* Static list of Reference Signals to be deleted */
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_P0_PUSCH_ALPHASETt), P0AlphaSets[bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS_OBJ]); /*Dynamic list for configuration {p0-pusch,alpha} sets for PUSCH (except msg3).*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RSt), PathlossRefRsToAdd[bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS_OBJ]); /* Dynamic list of Reference Signals (e.g. a CSI-RS config or a SSblock)
                                                                    to be used for PUSCH path loss estimation to be added/modified */
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SRI_PUSCH_POWERCONTROLt), SriPuschMapToAdd[bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING_OBJ]); /* Dynamic list of SRI-PUSCH-PowerControl elements among which one is selected
                                                            by the SRI field in DCI to be added/modified*/
    VFIELD(uint32_t, SriPuschMapToDel[bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING_OBJ]); /* Dynamic list of SRI-PUSCH-PowerControl elements to be deleted */
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_POWERCONTROLt);

/* 38.331 PUCCH-PowerControl IE: it is used to configure is used to configure FFS*/
typedef struct {
    uint8_t PathlossRefRSId; /* Range 0 ...(bb_nr5g_MAX_NB_PUCH_PATHLOSS_REFERENCE_RS-1); Default/Invalid value is 0xFF */
    uint8_t Pad;
    uint8_t RefSigIsValid; /* This field assumes a value defined as bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RS_REF_SIG_*** 
                                       in order to read in good way the associated parameters in RefSig. 
                                       If this field is set to default value RefSig is neither read or used */
    union{
        uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
        uint8_t Ssb;              /* Range 0....63; Default is 0xFF */
    } RefSig; 
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RSt);

typedef struct {
    uint8_t P0Id; /*Range 1..8;Default value is 0xFF*/
    int8_t  P0Value; /* Range -16..15; */
    uint8_t Pad[2];
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_P0t);

typedef struct {
    int8_t deltaFPucchF0; /* deltaF for PUCCH format 0 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t deltaFPucchF1; /* deltaF for PUCCH format 1 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t deltaFPucchF2; /* deltaF for PUCCH format 2 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t deltaFPucchF3; /* deltaF for PUCCH format 3 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t deltaFPucchF4; /* deltaF for PUCCH format 4 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    uint8_t TwoPucchPCAdjStates; /*Number of PUCCH power control adjustment states maintained by the UE (i.e., fc(i)).
                               Enum [twoStates]; Default/Invalid value is 0xFF */
    uint8_t NbP0Set; /* Gives the number of valid elements in P0Set vector: 1..bb_nr5g_MAX_PUCCH_P0_PERSET; Default value is 0*/
    uint8_t NbPathlossRefRs; /* Gives the number of valid elements in PathlossRefRs vector: 1..bb_nr5g_MAX_NB_PUCCH_PATHLOSS_REFERENCE_RS; Default value is 0*/
    STRUCT_NAME(tm_, bb_nr5g_PUCCH_P0t) P0Set[bb_nr5g_MAX_PUCCH_P0_PERSET];
    STRUCT_NAME(tm_, bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RSt) PathlossRefRs[bb_nr5g_MAX_NB_PUCCH_PATHLOSS_REFERENCE_RS];
} STRUCT_NAME(tm_,  bb_nr5g_PUCCH_POWERCONTROLt);

/* 38.331 SchedulingRequestResourceConfig IE: it determines physical layer resources on PUCCH where the UE may send the dedicated scheduling request*/
typedef struct {
    uint8_t SRResourceId;/* Range 0 ...(bb_nr5g_MAX_SR_RESOURCES-1); Default/Invalid value is 0xFF */
    uint8_t SRId;/* Range 0 ...7; Default/Invalid value is 0xFF */
    uint8_t ResourceId; /* PUCCH Resource identifier. Range 0 ...(bb_nr5g_MAX_PUCCH_RESOURCES -1); Default value is 0xFF */
    uint8_t SRPeriodAndOffSetIsValid;/* This field assumes a value defined as bb_nr5g_SR_PERIODICITYANDOFFSET_*** 
                                            in order to read in good way the associated parameter CsiResPeriodAndOffSet. 
                                            If this field is set to default value CsiResPeriodAndOffSet is neither read or used */
    uint8_t Pad[2];
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
}STRUCT_NAME(tm_,  bb_nr5g_SR_RESOURCE_CFGt);

/* 38.331 SRS-Config IE: is used to configure sounding reference signal transmissions */
typedef struct {
    uint8_t TransmissionCombN; /* This field assumes a value defined as bb_nr5g_SRS_TRANSMISSION_COMB_*** 
                        in order to read in good way the associated parameters of the structure. 
                        If this field is set to default value no associated parameters of the structure is neither read or used */
    uint8_t CombOffset; /* if TransmissionCombN=bb_nr5g_SRS_TRANSMISSION_COMB_N2 Range 0..1 
                           if TransmissionCombN=bb_nr5g_SRS_TRANSMISSION_COMB_N4 Range 0..3 */
    uint8_t CyclicShift;/* if TransmissionCombN=bb_nr5g_SRS_TRANSMISSION_COMB_N2 Range 0..7 
                           if TransmissionCombN=bb_nr5g_SRS_TRANSMISSION_COMB_N4 Range 0..11 */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_SRS_TRANSMISSION_COMBt);

typedef struct {
    uint8_t StartPos; /* Range 0..5*/
    uint8_t NbSymbols; /* Enum [n1, n2, n4]; Default/Invalid value is 0xFF */
    uint8_t RepFactor; /* Enum [n1, n2, n4]; Default/Invalid value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCE_MAPPINGt);

typedef struct {
    uint8_t CSrs; /* Range 0..63; Default/Invalid value is 0xFF */
    uint8_t BSrs; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t BHop; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_SRS_SPATIAL_RELATION_INFOt);

typedef struct {
    uint8_t CSrs; /* Range 0..63; Default/Invalid value is 0xFF */
    uint8_t BSrs; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t BHop; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t Pad;
} STRUCT_NAME(tm_, bb_nr5g_SRS_FREQ_HOPPINGt);

/* SRS-ResourcePeriodicityAndOffset IE */
typedef struct {
    uint8_t SrsResourceType; /* This field assumes a value defined as bb_nr5g_SRS_RESOURCETYPE_*** 
                                            in order to read togheter whit bb_nr5g_SRS_PERIODICITYANDOFFSET_*** 
                                            in good way the associated parameter SrsPeriodAndOffSet. 
                                            If this field is set to default value SrsPeriodAndOffSet is neither read or used */
    uint8_t SrsPeriodAndOffSetIsValid;/* This field assumes a value defined as bb_nr5g_SRS_PERIODICITYANDOFFSET_*** 
                                            in order to read in good way the associated parameter CsiResPeriodAndOffSet. 
                                            If this field is set to default value CsiResPeriodAndOffSet is neither read or used */
    union{
        uint16_t Slot1; /*  Range 0; Default is 0xFFFF */
        uint16_t Slot2; /*  Range 0..1; Default is 0xFFFF */
        uint16_t Slot4; /*  Range 0..3; Default is 0xFFFF */
        uint16_t Slot5; /*  Range 0..4; Default is 0xFFFF */
        uint16_t Slot8; /*  Range 0..7; Default is 0xFFFF */
        uint16_t Slot10; /*  Range 0..9; Default is 0xFFFF */
        uint16_t Slot16; /*  Range 0..15; Default is 0xFFFF */
        uint16_t Slot20; /*  Range 0..19; Default is 0xFFFF */
        uint16_t Slot32; /*  Range 0..31; Default is 0xFFFF */
        uint16_t Slot40; /*  Range 0..39; Default is 0xFFFF */
        uint16_t Slot64; /*  Range 0..63; Default is 0xFFFF */
        uint16_t Slot80; /*  Range 0..79; Default is 0xFFFF */
        uint16_t Slot160; /*  Range 0..159; Default is 0xFFFF */
        uint16_t Slot320; /*  Range 0..319; Default is 0xFFFF */
        uint16_t Slot640; /*  Range 0..639; Default is 0xFFFF */
        uint16_t Slot1280; /*  Range 0..1279; Default is 0xFFFF */
        uint16_t Slot2560; /*  Range 0..2559; Default is 0xFFFF */
    } SrsPeriodAndOffSet;    
} STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCETYPEt);

typedef struct {
    uint8_t SrsResourceTypeSetIsValid; /* This field assumes a value defined as bb_nr5g_SRS_RESOURCETYPESET_*** 
                                    in good way the associated parameter SrsResourceTypeSet. 
                                    If this field is set to default value SrsResourceTypeSet is neither read or used */
    union{
        struct
        {
            uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */   
            uint8_t ResTrigger;       /* Range 0....(bb_nr5g_MAX_NB_SRS_TRIGGER_STATES-1); Default is 0xFF */ 
            uint8_t SlotOffset;       /* Range 1...8; Default is 0xFF */ 
        } Aperiodic;
        struct
        {
            uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */           
        } PeriodicOrSemiPers;        
    } SrsResourceTypeSet;    

} STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCETYPESETt);

typedef struct {
    uint8_t ResourceId; /*SRS Resource id 0...(bb_nr5g_MAX_SRS_RESOURCES-1); Default/Invalid value is 0xFF*/
    uint8_t NbPorts;    /*Enum [port1, ports2, ports4]; Default/Invalid value is 0xFF */
    uint8_t PtrsPortIndex;  /* The PTRS port index for this SRS resource for non-codebook based UL MIMO
                               Enum [n0, n1]; Default/Invalid value is 0xFF */
    uint8_t FreqDomainPos;  /* Parameter(s) defining frequency domain position and configurable shift to align SRS allocation to 4 PRB grid
                               Range 0..67; Default is 0xFFFF */
    uint16_t FreqDomainShift;/*  Range 0..268; Default is 0xFFFF */
    uint16_t SequenceId; /* Sequence ID used to initialize psedo random group and sequence hopping
                            BIT STRING (SIZE (10)); Default is 0xFFFF*/
    uint8_t GroupOrSeqHop; /*Parameter(s) for configuring group or sequence hopping
                            Enum [neither, groupHopping, sequenceHopping]; Default/Invalid value is 0xFF*/
    uint8_t RefSigIsValid; /* This field assumes a value defined as bb_nr5g_SRS_SPATIAL_RELATION_INFO_REF_SIG_*** 
                                       in order to read in good way the associated parameters in RefSig. 
                                       If this field is set to default value RefSig is neither read or used */
    union{
        uint8_t Ssb;              /* Range 0....63; Default is 0xFF */
        uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
        uint8_t Srs;             /* Range 0....(bb_nr5g_MAX_SRS_RESOURCES-1); Default is 0xFF */
    } RefSig;  
    uint8_t Pad;
    STRUCT_NAME(tm_, bb_nr5g_SRS_TRANSMISSION_COMBt) TransmissionComb; /* Comb value (2 or 4) and comb offset (0..combValue-1).*/
    STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCE_MAPPINGt) ResourceMapping; /*OFDM symbol location of the SRS resource within a slot including number of OFDM symbols*/
    STRUCT_NAME(tm_, bb_nr5g_SRS_FREQ_HOPPINGt) FreqHop; /*Includes parameters capturing SRS frequency hopping*/
    STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCETYPEt) ResourceType; /*Time domain behavior of SRS resource configuration*/
} STRUCT_NAME(tm_,  bb_nr5g_SRS_RESOURCEt);

typedef struct {
    uint8_t ResourceId; /* SRS Resource Set id 0...(bb_nr5g_MAX_SRS_RESOURCE_SETS-1); Default/Invalid value is 0xFF*/
    uint8_t Usage; /* Indicates if the SRS resource set is used for beam management vs. used for either codebook based or non-codebook based transmission
                     Enum [beamManagement, codebook, nonCodebook, antennaSwitching]; Default/Invalid value is 0xFF */
    uint8_t Alpha;   /* alpha value for SRS power control.                     
                        Enum [alpha0, alpha04, alpha05, alpha06, alpha07, alpha08, alpha09, alpha1]; Default/Invalid value is 0xFF */
    uint8_t PwCtrlAdj; /*Indicates whether hsrs,c(i) = fc(i,1) or hsrs,c(i) = fc(i,2) (if twoPUSCH-PC-AdjustmentStates are configured)
                        or serarate close loop is configured for SRS.
                        Enum [sameAsFci2, separateClosedLoop]; Default/Invalid value is 0xFF */
    uint8_t PathlossRefRSIsValid; /* This field assumes a value defined as bb_nr5g_SRS_PATHLOSS_REFERENCE_RS_*** 
                                       in order to read in good way the associated parameters in RefSig. 
                                       If this field is set to default value RefSig is neither read or used */
    union{
        uint8_t Ssb;              /* Range 0....63; Default is 0xFF */
        uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
    } PathlossRefRS;  
    int16_t P0; /*P0 value for SRS power control. Range -202...24*/
    uint8_t NbResourceIdList; /*Gives the number of valid elements in ResourceIdList vector: 1.. bb_nr5g_MAX_SRS_RESOURCE_PERSET; Default value is 0*/
    uint8_t Pad[3];
    uint8_t ResourceIdList[bb_nr5g_MAX_SRS_RESOURCE_PERSET]; /*The IDs of the SRS-Reosurces used in this SRS-ResourceSet*/
    STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCETYPESETt) ResourceType;
} STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCE_SETt);

/****************************************************************************************/
/* 38.331 PDCCH-ConfigCommon IE: it is used to configure cell specific PDCCH parameters provided in SIB as well as during 
          handover and PSCell/SCell addition */
typedef struct {
    uint8_t SearchSpaceSIB1; /* Corresponds to L1 parameter 'rmsi-SearchSpace' (see 38.213, section 10)
                                Default value is 0xFF. Range 0... bb_nr5g_MAX_NB_SEARCH_SPACES -1  */
    uint8_t SearchSpaceSIB; /*  Corresponds to L1 parameter 'osi-SearchSpace' (see 38.213, section 10)
                                Default value is 0xFF. Range 0... bb_nr5g_MAX_NB_SEARCH_SPACES -1  */
    uint8_t PagSearchSpace; /*  Corresponds to L1 parameter 'paging-SearchSpace' (see 38.213, section 10)
                                Default value is 0xFF. Range 0... bb_nr5g_MAX_NB_SEARCH_SPACES -1  */
    uint8_t RaSearchSpace;  /*  ID of the Search space for random access procedure
                                Corresponds to L1 parameter 'rach-coreset-configuration' (see 38.211?, section FFS_Section)
                                Default value is 0xFF. Range 0... bb_nr5g_MAX_NB_SEARCH_SPACES -1  */
    uint8_t RaCtrlResSet;   /*  CORESET configured for random access. When the field is absent the UE uses the CORESET 
                                according to pdcch-ConfigSIB1 which is associated with ControlResourceSetId = 0 in the 
                                CommonCtrlResSets list.
                                Corresponds to L1 parameter 'rach-coreset-configuration' (see 38.211?, section FFS_Section)
                                Default value is 0xFF. Otherwise  1 */
    uint8_t NbCommonCtrlResSets;  /*Gives the number of valid elements in CommonCtrlResSets vector: 1 or 2; Default value is 0*/
    uint8_t NbCommonSearchSpaces; /*Gives the number of valid elements in CommonSearchSpaces vector: 1 .. 4; Default value is 0*/
    uint8_t Spare;
    STRUCT_NAME(tm_, bb_nr5g_CTRL_RES_SETt) CommonCtrlResSets[bb_nr5g_COMMON_CTRL_RES_SET_SIZE];
                                                   /* A list of common control resource sets. Only CORESETs with ControlResourceSetId = 0 
                                                   or 1 are allowed. The CORESET#0 corresponds to the CORESET configured in MIB
                                                   (see pdcch-ConfigSIB1) and is used to provide that information to the UE
                                                    by dedicated signalling during handover and (P)SCell addition. 
                                                    The CORESET#1 may be configured an used for RAR (see RaCtrlResSet) */
    STRUCT_NAME(tm_, bb_nr5g_SEARCH_SPACEt) CommonSearchSpaces[bb_nr5g_COMMON_SEARCH_SPACE_SIZE];
} STRUCT_NAME(tm_, bb_nr5g_PDCCH_CONF_COMMONt);

/****************************************************************************************/

/* 38.331 PDSCH-ConfigCommon IE: is used to configure FFS */
typedef struct {
    uint8_t NbPdschAlloc;  /* Gives the number of valid elements in PdschAlloc vector: 
                              1...bb_nr5g_MAX_NB_DL_ALLOCS; Default value is 0*/
    uint8_t Spare[3];                   
    STRUCT_NAME(tm_, bb_nr5g_PDSCH_TIMEDOMAINRESALLOCt)  PdschAlloc[bb_nr5g_MAX_NB_DL_ALLOCS];
} STRUCT_NAME(tm_, bb_nr5g_PDSCH_CONF_COMMONt);

/****************************************************************************************/
/* 38.331 PDCCH-Config IE: is used to configure UE specific PDCCH parameters such as control 
          resource sets (CORESET), search spaces and additional parameters for acquiring the
          PDCCH. */
typedef struct {
     /* Field mask according to bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_***_PRESENT */
    uint8_t FieldMask;
   /* The network configures at most 3 CORESETs per BWP per cell (including the initial CORESET)*/
    uint8_t NbDedCtrlResSetsToAdd;  /*Gives the number of valid elements in DedCtrlResSetsToAdd vector: 1..3; Default value is 0*/
    uint8_t NbDedCtrlResSetsToDel;  /*Gives the number of valid elements in DedCtrlResSetsToDel vector: 1..3; Default value is 0*/
    uint8_t NbDedSearchSpacesToAdd; /*Gives the number of valid elements in DedSearchSpacesToAdd vector: 1 .. 10; Default value is 0*/
    uint8_t NbDedSearchSpacesToDel; /*Gives the number of valid elements in DedSearchSpacesToDel vector: 1 .. 10; Default value is 0*/
    uint8_t DedCtrlResSetsIdToDel[bb_nr5g_DED_CTRL_RES_SET_SIZE]; /* A static list of dedicated control resource sets identifier to delete.*/
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_DOWNLINK_PREEMPTION_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_DOWNLINK_PREEMPTIONt), DownlinkPreemption); /*Configuration of downlink preemtption indications to be monitored in this cell*/
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_SLOT_FMT_INDICATOR_PRESENT   0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SLOT_FMT_INDICATORt), SlotFormatIndicator);
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_TPC_PUSCH_PRESENT   0x0004
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUSCH_TPC_CFGt), TpcPusch); /* Enable and configure reception of group TPC commands for PUSCH*/
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_TPC_PUCCH_PRESENT   0x0008
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_TPC_CFGt), TpcPucch); /* Enable and configure reception of group TPC commands for PUCCH*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_CTRL_RES_SETt), DedCtrlResSetsToAdd[3]); /* A dynamic list of dedicated control resource sets to add.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SEARCH_SPACEt), DedSearchSpacesToAdd[10]);/* A dynamic list of dedicated search space to add.*/
    VFIELD(uint32_t, DedSearchSpacesIdToDel[10]); /* A dynamic list of dedicated search space identifier to delete.*/
} STRUCT_NAME(tm_, bb_nr5g_PDCCH_CONF_DEDICATEDt);

/****************************************************************************************/
typedef struct {
    uint8_t BundSize ;  /* Enum [n4, wideband]; Default value is 0xFF */
}STRUCT_NAME(tm_,  bb_nr5g_PDSCH_PRBBUNDLTYPESTATICt);

typedef struct {
    uint8_t BundSizeSet1;  /* Enum [n4, wideband, n2-wideband, n4-wideband]; Default value is 0xFF */
    uint8_t BundSizeSet2;  /* Enum [n4, wideband]; Default value is 0xFF */
} STRUCT_NAME(tm_, bb_nr5g_PDSCH_PRBBUNDLTYPEDYNAMICt);

/* 38.331 PDSCH-Config IE: is used to configure the UE specific PDSCH parameters.*/
typedef struct {
    uint16_t DataScrIdentity; /* Identifer used to initalite data scrambling (c_init) for both PDSCH.
                                 Range 0...1007. Default value is 0xFFFF*/
    uint8_t VrbToPrbInterl;   /* Interleaving unit configurable between 2 and 4 PRBs
                                 Enum [n2, n4]; Default value is 0xFF*/
    uint8_t ResAllocType;   /*  Configuration of resource allocation type 0 and resource allocation type 1 for non-fallback DCI 
                                Enum [resourceAllocationType0, resourceAllocationType1, dynamicSwitch]; Default value is 0xFF */
    uint8_t AggregationFactor;  /* Number of repetitions for data 
                                  Enum [n2, n4, n8]; Default value is 0xFF */
    uint8_t RbgSize;            /* Selection between config 1 and config 2 for RBG size for PDSCH 
                                  Enum [config1, config2]; Default value is 0xFF */
    uint8_t McsTable;           /* Indicates which MCS table the UE shall use for PDSCH
                                   Enum [qam64, qam256]; Default value is 0xFF */
    uint8_t MaxCwSchedByDCI;    /* Maximum number of code words that a single DCI may schedule.
                                   Enum [n1,n2]; Default value is 0xFF */
    
    uint16_t PrbBundlTypeIsValid;/* This field assumes a value defined as bb_nr5g_PDSCH_CONF_DED_BUNDLING_*** 
                                       in order to read in good way the associated parameters in SearchSpaceType. 
                                       If this field is set to default value SearchSpaceType is neither read or used */
    union {
    	STRUCT_NAME(tm_, bb_nr5g_PDSCH_PRBBUNDLTYPESTATICt) BundTypeS;
    	STRUCT_NAME(tm_, bb_nr5g_PDSCH_PRBBUNDLTYPEDYNAMICt) BundTypeD;
    } PrbBundlType; /* Indicates the PRB bundle type and bundle size(s).*/
 
    uint8_t NbTciStatesToAdd;       /* Gives the number of valid elements in TciStatesToAdd vector: 1..bb_nr5g_MAX_NB_TCI_STATES; Default value is 0*/
    uint8_t NbTciStatesToDel;       /* Gives the number of valid elements in TciStatesToDel vector: 1..bb_nr5g_MAX_NB_TCI_STATES; Default value is 0*/
    uint8_t NbPdschAllocDed;  /* Gives the number of valid elements in PdschAllocDed vector: 1...bb_nr5g_MAX_NB_DL_ALLOCS; Default value is 0*/
    uint8_t NbRateMatchPatternDedToAdd;  /* Gives the number of valid elements in RateMatchPatternDed vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    
    uint8_t NbRateMatchPatternDedToDel;  /* Gives the number of valid elements in RateMatchPatternDed vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternGroup1;  /* Gives the number of valid elements in RateMatchPatternGroup1 vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternGroup2;  /* Gives the number of valid elements in RateMatchPatternGroup2 vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbZpCsiRsResourceToAdd;/* Gives the number of valid elements in ZpCsiRsResourceToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES; Default value is 0*/

    uint8_t NbZpCsiRsResourceToDel;/* Gives the number of valid elements in ZpCsiRsResourceToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES; Default value is 0*/
    uint8_t NbAperiodicZpCsiRsResSetsToAdd;/* Gives the number of valid elements in AperiodicZpCsiRsResSetsToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/
    uint8_t NbAperiodicZpCsiRsResSetsToDel;/* Gives the number of valid elements in AperiodicZpCsiRsResSetsToDel vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/
    uint8_t NbSpZpCsiRsResSetsToAdd;/* Gives the number of valid elements in SpZpCsiRsResSetsToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/

    uint8_t NbSpZpCsiRsResSetsToDel;/* Gives the number of valid elements in SpZpCsiRsResSetsToDel vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/
    uint8_t Pad;
     /* Field mask according to bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_***_PRESENT to handle DmrsMappingTypeA and DmrsMappingTypeB*/
    uint16_t FieldMask;

    uint8_t RateMatchPatternGroup1[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS]; /* IDs of a first group of RateMatchPatterns defined in the RateMatchPatternDed.
                                                                           Range 1... bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t RateMatchPatternGroup2[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS];/*  IDs of a second group of RateMatchPatterns defined in the RateMatchPatternDed.
                                                                           Range 1... bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/    
#define bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_DMRS_TYPEA_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_DMRS_DOWNLINK_CFGt), DmrsMappingTypeA); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type A */
#define bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_DMRS_TYPEB_PRESENT   0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_DMRS_DOWNLINK_CFGt), DmrsMappingTypeB); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type B */
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_TCI_STATEt), TciStatesToAdd[bb_nr5g_MAX_NB_TCI_STATES_OBJ]);    /* Dynamic list of Transmission Configuration Indicator (TCI) states for dynamically indicating (over DCI)
                                           a transmission configuration to be added/modified.*/
    VFIELD(uint32_t, TciStatesToDel[bb_nr5g_MAX_NB_TCI_STATES_OBJ]); /* Dynamic list of Transmission Configuration Indicator (TCI) states to be deleted.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PDSCH_TIMEDOMAINRESALLOCt), PdschAllocDed[bb_nr5g_MAX_NB_DL_ALLOCS_OBJ]); /* Dynamic list of time-domain configurations for timing of DL assignment to DL data.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_RATE_MATCH_PATTERNt), RateMatchPatternDedToAdd[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS_OBJ]);  /* Dynamic list of Resources patterns which the UE should rate match PDSCH around to be added/modified.*/
    VFIELD(uint32_t, RateMatchPatternDedToDel[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS_OBJ]); /* Dynamic list of Zero-Power (ZP) CSI-RS resource identifier used for PDSCH rate-matching to be deleted.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_ZP_CSI_RS_RESt), ZpCsiRsResourceToAdd[bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES_OBJ]); /* Dynamic list of Zero-Power (ZP) CSI-RS resources used for PDSCH rate-matching to be added/modified.*/
    VFIELD(uint32_t, ZpCsiRsResourceToDel[bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES_OBJ]); /* Dynamic list of Zero-Power (ZP) CSI-RS resource identifier used for PDSCH rate-matching to be deleted.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_ZP_CSI_RS_RES_SETt), AperiodicZpCsiRsResSetsToAdd[bb_nr5g_MAX_NB_ZP_CSI_RS_SETS_OBJ]); /* Dynamic list of sets to be added/modified. Each set contains a set-ID and the IDs of one or more ZP-CSI-RS-Resources.*/
    VFIELD(uint32_t, AperiodicZpCsiRsResSetsToDel[bb_nr5g_MAX_NB_ZP_CSI_RS_SETS_OBJ]); /* Dynamic list of set identifiers to be deleted.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_ZP_CSI_RS_RES_SETt), SpZpCsiRsResSetsToAdd[bb_nr5g_MAX_NB_ZP_CSI_RS_SETS_OBJ]); /* Dynamic list of sets to be added/modified. Each set contains a set-ID and the IDs of one or more ZP-CSI-RS-Resources.*/
    VFIELD(uint32_t, SpZpCsiRsResSetsToDel[bb_nr5g_MAX_NB_ZP_CSI_RS_SETS_OBJ]); /* Dynamic list of set identifiers to be deleted.*/
} STRUCT_NAME(tm_,  bb_nr5g_PDSCH_CONF_DEDICATEDt);

/****************************************************************************************/
/* 38.331 SPS-Config IE is used to configure downlink semi-persistent transmission. TODO*/
typedef struct {
    uint8_t Periodicity; /* Periodicity for DL SPS 
                            Enum [ms10, ms20, ms32, ms40, ms64, ms80, ms128, ms160, ms320, ms640]; Default value is 0xFF*/
    uint8_t NbHarqProcesses; /* Number of configured HARQ processes for SPS DL 
                                Range 0...8; Default value is 0xFF*/
    uint8_t Pad[2];
    STRUCT_NAME(tm_, bb_nr5g_PUCCH_RESOURCEt) N1PucchAn; /*HARQ resource for PUCCH for DL SPS*/
} STRUCT_NAME(tm_,  bb_nr5g_SPS_CONF_DEDICATEDt);

/****************************************************************************************/
/* 38.331 RACH-ConfigGeneric IE: it is used to specify the cell specific random-access parameters 
    both for regular random access as well as for beam failure recovery.*/
typedef struct {
    uint8_t PrachConfigIndex; /* PRACH configuration index. Range 0...255 */
    uint8_t Msg1FDM;          /* The number of PRACH transmission occasions FDMed in one time instance
                                 Enum [one, two, four, eight]; Default value is 0xFF*/
    uint16_t Msg1FrequencyStart; /* Offset of lowest PRACH transmission occasion in frequency domain with respective to PRB 0.
                                    Default value is 0xFFFF; Range 0... bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1*/
    uint8_t  ZeroCorrZone;        /* N-CS configuration, see Table 6.3.3.1-3 in 38.211
                                     Default value is 0xFFFF; Range 0...15 */
    uint8_t  Spare;
    int16_t  PreambleRecTargetPwr; /* The target power level at the network receiver side 
                                      (see 38.213, section 7.4, 38.321, section 5.1.2, 5.1.3)
                                      Default value is -1; Range -200...-74 */
} STRUCT_NAME(tm_, bb_nr5g_RACH_CONF_GENERICt);

/* 38.331 RACH-ConfigCommon IE: it is used to specify the cell specific random-access parameters*/
typedef struct {
	STRUCT_NAME(tm_, bb_nr5g_RACH_CONF_GENERICt) RachConfGeneric;
    uint8_t NbOfRaPreambles; /* Total number of preambles used for contention based and contention free random access
                                Default value is 0xFF; Range 1...63*/
    uint8_t Msg1SubCarrSpacing; /*  Subcarrier spacing of PRACH
                                    Enum [kHz15, kHz30, kHz60, kHz120, kHz240]; Default/Invalid value is 0xFF*/
    uint8_t RestSetConf;        /* Configuration of an unrestricted set or one of two types of restricted sets, see 38.211 6.3.3.1
                                   Enum [unrestrictedSet, restrictedSetTypeA, restrictedSetTypeB]; Default/Invalid value is 0xFF*/
    uint8_t Msg3TransfPrecoding; /* Indicates to a UE whether transform precoding is enabled for Msg3 transmission.
                                    Enum [enabled]; Default/Invalid value is 0xFF*/
    uint8_t RsrpThresholdSsb;    /*  UE may select the SS block and corresponding PRACH resource 
                                    for path-loss estimation and (re)transmission based on SS blocks that satisfy the threshold (see 38.213, section REF)
                                    Default value is 0xFFFF; Range 0...124 */
    uint8_t RsrpThresholdSsbSul; /*  UE may select the SS block and corresponding PRACH resource for path-loss estimation and (re)transmission on the SUL carrier
                                    based on SS blocks that satisfy the threshold (see 38.213, section REF)
                                    Default value is 0xFFFF; Range 0...124 */
    uint8_t PrachRootSeqIndexIsValid; /* This field assumes a value defined as bb_nr5g_RACH_CONF_COMMON_ROOTSEQINDEX_*** 
                                       in order to read in good way the associated parameters in PrachRootSeqIndex. 
                                       If this field is set to default value PrachRootSeqIndex is neither read or used */
    uint8_t SsbPerRachIsValid;      /* This field assumes a value defined as bb_nr5g_RACH_CONF_COMMON_OCCASION_*** 
                                       in order to read in good way the associated parameters in SsbPerRach. 
                                       If this field is set to default value SsbPerRach is neither read or used */
    uint16_t PrachRootSeqIndex;   /* PRACH root sequence index. 
                                     Range[ 0...837] if  PrachRootSeqIndexIsValid is L839 
                                     Range[ 0...137] if  PrachRootSeqIndexIsValid is L139 */
    uint8_t Spare;
    union{
        uint8_t OneEight; /* Enum [n4,n8,n12,n16,n20,n24,n28,n32,n36,n40,n44,n48,n52,n56,n60,n64]; Default is 0xFF */
        uint8_t OneFourth;/* Enum [n4,n8,n12,n16,n20,n24,n28,n32,n36,n40,n44,n48,n52,n56,n60,n64]; Default is 0xFF */
        uint8_t OneHalf;  /* Enum [n4,n8,n12,n16,n20,n24,n28,n32,n36,n40,n44,n48,n52,n56,n60,n64]; Default is 0xFF */
        uint8_t One;      /* Enum [n4,n8,n12,n16,n20,n24,n28,n32,n36,n40,n44,n48,n52,n56,n60,n64]; Default is 0xFF */
        uint8_t Two;      /* Enum [n4,n8,n12,n16,n20,n24,n28,n32]; Default is 0xFF */
        uint8_t Four;     /* Range 1...16; Default is 0xFF */
        uint8_t Eight;    /* Range 1...8; Default is 0xFF */
        uint8_t SixTeen;  /* Range 1...4; Default is 0xFF */
    } SsbPerRach;
} STRUCT_NAME(tm_, bb_nr5g_RACH_CONF_COMMONt);

/* 38.331 PUSCH-ConfigCommon IE: it is used to configure the cell specific PUSCH parameters*/
typedef struct {
    uint8_t K2;     /*  Corresponds to L1 parameter 'K2' (see 38.214, section FFS_Section)
                        When the field is absent the UE applies the value 1 when PUSCH SCS is 15/30KHz; 
                        2 when PUSCH SCS is 60KHz and 3 when PUSCH SCS is 120KHz.
                        Default value is 0xFF. Range 0...7  */
    uint8_t MappingType;    /* PUSCH mapping type. 
                               Corresponds to L1 parameter 'Mapping-type' (see 38.214, section FFS_Section)
                               Enum [typeA, typeB]; Default value is 0xFF*/
    uint8_t StartSymbAndLen;  /* An index into a table/equation in RAN1 specs capturing valid combinations of start symbol 
                                and length (jointly encoded).
                                Corresponds to L1 parameter 'Index-start-len' (see 38.214, section FFS_Section)
                                Bitmap of size(7); Default value is 0xFF*/
    uint8_t Spare;                   
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt);

typedef struct {
    uint8_t GroupHopEnabledTransfPrecoding; /* Sequence-group hopping can be enabled or disabled 
                                               by means of this cell-specific parameter
                                               Enum [enabled]; Default value is 0xFF*/
    int8_t  Msg3DeltaPreamble; /* Power offset between msg3 and RACH preamble transmission in steps of 1dB.
                                  Range -1 .. 6 */
    int16_t P0NomWithGrant;    /* P0 value for PUSCH with grant (except msg3). Value in dBm. Only even values (step size 2) allowed.
                                  Range -202..24;*/
    uint8_t NbPuschTimeDomResAlloc;   /* Gives the number of valid elements in PuschAlloc vector: 
                                         1...bb_nr5g_MAX_NB_UL_ALLOCS; Default value is 0*/
    uint8_t Spare[3];                   
    STRUCT_NAME(tm_, bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt)  PuschTimeDomResAlloc[bb_nr5g_MAX_NB_UL_ALLOCS];
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_CONF_COMMONt);

/* 38.331 PUSCH-Config: it is used to configure the UE specific PUSCH parameters applicable to a particular BWP*/
typedef struct {
    uint16_t DataScrIdentity; /* Identifer used to initalite data scrambling (c_init) for both PUSCH.
                                 Range 0...1007. Default value is 0xFFFF*/
    uint8_t TxConfig; /*Whether UE uses codebook based or non-codebook based transmission
                            Enum [codebook, nonCodebook]; Default value is 0xFF */
    uint8_t ResAllocType;   /*  Configuration of resource allocation type 0 and resource allocation type 1 for non-fallback DCI 
                                Enum [resourceAllocationType0, resourceAllocationType1, dynamicSwitch]; Default value is 0xFF */
    uint8_t AggregationFactor;  /* Number of repetitions for data 
                                  Enum [n2, n4, n8]; Default value is 0xFF */
    uint8_t McsTable;           /* Indicates which MCS table the UE shall use for PUSCH
                                   Enum [qam256]; Default value is 0xFF */
    uint8_t McsTableTransfPrecoder; /* Indicates which MCS table the UE shall use for PUSCH with transform precoding
                                   Enum [qam256]; Default value is 0xFF */
    uint8_t TransfPrecoder; /* The UE specific selection of transformer precoder for PUSCH.
                                   Enum [enabled, disabled]; Default value is 0xFF */
    uint8_t CodebookSubset;     /* Subset of PMIs addressed by TPMI, where PMIs are those supported by UEs with maximum coherence capabilities 
                                  Enum [fullyAndPartialAndNonCoherent, partialAndNonCoherent, nonCoherent]; Default value is 0xFF */
    uint8_t MaxRank; /* Subset of PMIs addressed by TRIs from 1 to ULmaxRank.Range 1..4; Default value is 0xFF */
    uint8_t RbgSize;            /* Selection between config 1 and config 2 for RBG size for PUSCH 
                                  Enum [config2]; Default value is 0xFF */
    uint8_t VrbToPrbInterl;   /* Interleaving unit configurable between 2 and 4 PRBs
                                 Enum [n2, n4]; Default value is 0xFF*/

    uint8_t FreqHop;  /* Configured one of two supported frequency hopping mode. Enum [mode1, mode2]; Default value is 0xFF */  
    uint8_t NbFreqHopOffset;  /* Gives the number of valid elements in FreqHopOffset vector: 1...4; Default value is 0 */
    uint8_t NbPuschAllocDed;  /* Gives the number of valid elements in PuschAllocDed vector: 1...bb_nr5g_MAX_NB_UL_ALLOCS; Default value is 0*/
    /* Field mask according to bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_***_PRESENT to handle DmrsMappingTypeA,DmrsMappingTypeB, PuschPwCtrl and UciOnPusch*/
    uint8_t FieldMask;
    uint16_t FreqHopOffset[4];   /* Set of frequency hopping offsets used when frequency hopping is enabled for granted transmission (not msg3) and type 2
                                    Element range is 1....(bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1). Static list */
#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_DMRS_TYPEA_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_DMRS_UPLINK_CFGt), DmrsMappingTypeA); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type A */
#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_DMRS_TYPEB_PRESENT   0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_DMRS_UPLINK_CFGt), DmrsMappingTypeB); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type B */
#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_PW_CTRL_PRESENT   0x0004
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUSCH_POWERCONTROLt), PuschPwCtrl);
#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_UCI_PRESENT   0x0008
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_UCI_ON_PUSCHt), UciOnPusch);
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt), PuschAllocDed[bb_nr5g_MAX_NB_UL_ALLOCS_OBJ]); /* Dynamic list of time domain allocations for timing of UL assignment to UL data*/
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_CONF_DEDICATEDt);

/* 38.331 PUCCH-ConfigCommon IE: it is used to configure the cell specific PUCCH parameters*/
typedef struct {
    uint8_t PucchResCommon; /* An entry into a 16-row table where each row configures a set of 
                               cell-specific PUCCH resources/parameters.
                               Corresponds to L1 parameter 'PUCCH-resource-common' (see 38.213, section 9.2)
                               Default value is 0xFF; Bitmap size (4)*/
    uint8_t PucchGroupHop;  /* Configuration of group- and sequence hopping for all the PUCCH formats 0, 1, 3 and 4.
                               Corresponds to L1 parameter 'PUCCH-GroupHopping' (see 38.211, section 6.4.1.3)
                               Enum [neither, enable, disable]; Default value is 0xFF*/
    uint16_t HoppingId;     /* Cell-Specific scrambling ID for group hopping and sequence hopping if enabled.
                               Corresponds to L1 parameter 'HoppingID' (see 38.211, section 6.3.2.2)
                               Default value is 0xFF; Bitmap size (10)*/
    int16_t P0Nom;          /* Power control parameter P0 for PUCCH transmissions. Value in dBm.
                               Range [-202..24]*/
    uint8_t Spare[2];
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_CONF_COMMONt);

/* 38.331 PUCCH-Config IE: it is used to configure UE specific PUCCH parameters (per BWP) */
typedef struct {
    uint8_t NbResourceDedToAdd;  /* Gives the number of valid elements in ResourceDedToAdd vector: 1...bb_nr5g_MAX_PUCCH_RESOURCES; Default value is 0*/
    uint8_t NbResourceDedToDel;  /* Gives the number of valid elements in ResourceDedToAdd vector: 1...bb_nr5g_MAX_PUCCH_RESOURCES; Default value is 0*/
    uint8_t NbResourceSetDedToAdd;  /* Gives the number of valid elements in ResourceSetDedToAdd vector: 1...bb_nr5g_MAX_PUCCH_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourceSetDedToDel;  /* Gives the number of valid elements in ResourceSetDedToDel vector: 1...bb_nr5g_MAX_PUCCH_RESOURCE_SETS; Default value is 0*/
    uint8_t NbSpatRelInfoDedToAdd;  /* Gives the number of valid elements in SpatRelInfoDedToAdd vector: 1...bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS; Default value is 0*/
    uint8_t NbSpatRelInfoDedToDel;  /* Gives the number of valid elements in SpatRelInfoDedToDel vector: 1...bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS; Default value is 0*/
    uint8_t NbSRResDedToAdd;  /* Gives the number of valid elements in SRResDedToAdd vector: 1...bb_nr5g_MAX_SR_RESOURCES; Default value is 0*/
    uint8_t NbSRResDedToDel;  /* Gives the number of valid elements in SRResDedToAdd vector: 1...bb_nr5g_MAX_SR_RESOURCES; Default value is 0*/
    uint8_t NbMultiCsiPucchRes;  /* Gives the number of valid elements in MultiCsiPucchRes vector: 1...2; Default value is 0*/
    uint8_t NbDlDataToUlAck;  /* Gives the number of valid elements in DlDataToUlAck vector: 1...8; Default value is 0*/
    /* Field mask according to bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_***_PRESENT to handle Fmt1,Fmt2,Fmt3,Fmt4 and PucchPwCtrl*/
    uint16_t FieldMask;
    uint8_t ResourceSetDedToDel[bb_nr5g_MAX_PUCCH_RESOURCE_SETS]; /* Static list for releasing PUCCH resource sets.*/
    uint8_t SpatRelInfoDedToDel[bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS]; /* Static list for releasing Scheduling Request resources*/
    uint8_t SRResDedToDel[bb_nr5g_MAX_SR_RESOURCES]; /* Static list for releasing PUCCH resource sets.*/
    uint8_t MultiCsiPucchRes[2]; /* Static list for releasing PUCCH resource sets.*/
    uint8_t DlDataToUlAck[8]; /* Static list of timiing for given PDSCH to the DL ACK. Range element 0...15*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT1_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT_CFGt), Fmt1); /*Parameters that are common for all PUCCH resources of format 1*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT2_PRESENT   0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT_CFGt), Fmt2); /*Parameters that are common for all PUCCH resources of format 2*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT3_PRESENT   0x0004
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT_CFGt), Fmt3); /*Parameters that are common for all PUCCH resources of format 3*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT4_PRESENT   0x0008
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_FMT_CFGt), Fmt4); /*Parameters that are common for all PUCCH resources of format 4*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_PW_CTRL_PRESENT   0x0010
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_POWERCONTROLt), PucchPwCtrl);
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_RESOURCEt), ResourceDedToAdd[bb_nr5g_MAX_PUCCH_RESOURCES_OBJ]); /* Dynamic list for adding PUCCH resources applicable for the UL BWP
                                                 and serving cell in which the PUCCH-Conf is defined.*/
    VFIELD(uint32_t, ResourceDedToDel[bb_nr5g_MAX_PUCCH_RESOURCES_OBJ]); /* Dynamic list for releasing PUCCH resources applicable for the UL BWP 
                                                 and serving cell in which the PUCCH-Conf is defined.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUCCH_RESOURCE_SETt), ResourceSetDedToAdd[bb_nr5g_MAX_PUCCH_RESOURCE_SETS_OBJ]); /* Dynamic list for adding PUCCH resource sets.*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SPATIAL_RELATION_INFOt), SpatRelInfoDedToAdd[bb_nr5g_MAX_PUCCH_RESOURCE_SETS_OBJ]); /*Dynamic list of configuration of the spatial relation between a reference RS and PUCCH
                                                             to be added/modified*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SR_RESOURCE_CFGt), SRResDedToAdd[bb_nr5g_MAX_SR_RESOURCES_OBJ]); /* Dynamic list for adding Scheduling Request resources.*/
} STRUCT_NAME(tm_, bb_nr5g_PUCCH_CONF_DEDICATEDt);

/* 38.331 SRS-Config IE: it is used to configure sounding reference signal transmissions */
typedef struct {
    uint8_t TpcAccumulation; /* If absent, UE applies TPC commands via accumulation. If disabled, UE applies the TPC command without accumulation
                                 Enum [disabled]; Default value is 0xFF */
    uint8_t Pad[3];
    uint8_t NbResourceSetsToAdd;  /* Gives the number of valid elements in ResourceSetsToAdd vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourceSetsToDel;  /* Gives the number of valid elements in ResourceSetsToDel vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourcesToAdd;  /* Gives the number of valid elements in ResourceSetsToAdd vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourcesToDel;  /* Gives the number of valid elements in ResourceSetsToDel vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/   
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCEt), ResourcesToAdd[bb_nr5g_MAX_SRS_RESOURCE_SETS_OBJ]); /* Dynamic list for adding SRS resources*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SRS_RESOURCE_SETt), ResourceSetsToAdd[bb_nr5g_MAX_SRS_RESOURCE_SETS_OBJ]); /* Dynamic list for adding SRS resource sets*/
    VFIELD(uint32_t, ResourcessToDel[bb_nr5g_MAX_SRS_RESOURCE_SETS_OBJ]); /* Dynamic list for deleting SRS resources*/
    VFIELD(uint32_t, ResourceSetsToDel[bb_nr5g_MAX_SRS_RESOURCE_SETS_OBJ]); /* Dynamic list for deleting SRS resource sets*/
} STRUCT_NAME(tm_, bb_nr5g_SRS_CONF_DEDICATEDt);

/****************************************************************************************/
/* 38.331 BWP IE : Generic parameters used in Uplink- and Downlink bandwidth parts         */
typedef struct {
    uint16_t  LocAndBw; /* Corresponds to L1 parameter 'DL-BWP-loc'. (see 38.211, section FFS_Section).
                           Range (0..37949); Default/Invalid value is 0xFFFF*/
    uint8_t   SubCarSpacing;    /* Corresponds to subcarrier spacing according to 38.211, Table 4.2-1
                                   Enum kHz15, kHz30, kHz60, kHz120, kHz240; Default/Invalid value is 0xFF*/
    uint8_t   CyclicPrefix;     /* Enum extended; Default value is 0xFF*/
} STRUCT_NAME(tm_, bb_nr5g_BWPt);

/****************************************************************************************/
/* 38.331 BWP-DownlinkCommon IE */
typedef struct {
    STRUCT_NAME(tm_, bb_nr5g_BWPt) GenBwp;
    STRUCT_NAME(tm_, bb_nr5g_PDCCH_CONF_COMMONt) PdcchConfCommon;
    STRUCT_NAME(tm_,bb_nr5g_PDSCH_CONF_COMMONt) PdschConfCommon;
} STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKCOMMONt);

/****************************************************************************************/
/* 38.331 BWP-DownlinkDedicated IE */
typedef struct {
    uint32_t BwpId; /*BwpId is used to refer to Bandwidth Parts (BWP). The initial BWP is 
                      referred to by BwpId 0. 
                      The other BWPs are referred to by  1 to bb_nr5g_MAX_NB_BWPS.*/
    STRUCT_NAME(tm_, bb_nr5g_PDCCH_CONF_DEDICATEDt) PdcchConfDed;
    STRUCT_NAME(tm_, bb_nr5g_PDSCH_CONF_DEDICATEDt) PdschConfDed;
    STRUCT_NAME(tm_, bb_nr5g_SPS_CONF_DEDICATEDt)   SpsConfDed;
} STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKDEDICATEDt);

/****************************************************************************************/
/* 38.331 BWP-Downlink IE */
typedef struct {
    uint8_t BwpId;
    uint8_t Spare[3];                   
    STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKCOMMONt) BwpDLCommon;
    STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKDEDICATEDt) BwpDLDed;
} STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKt);

/****************************************************************************************/
/* 38.331 BWP-UplinkCommon IE */
typedef struct {
    STRUCT_NAME(tm_, bb_nr5g_BWPt)   GenBwp;
    STRUCT_NAME(tm_, bb_nr5g_RACH_CONF_COMMONt) RachCfgCommon;
    STRUCT_NAME(tm_, bb_nr5g_PUSCH_CONF_COMMONt) PuschCfgCommon;
    STRUCT_NAME(tm_, bb_nr5g_PUCCH_CONF_COMMONt) PucchCfgCommon;
} STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKCOMMONt);

/****************************************************************************************/
/* 38.331 BWP-UplinkDedicated IE */
typedef struct {
    uint32_t BwpId; /*BwpId is used to refer to Bandwidth Parts (BWP). The initial BWP is 
                      referred to by BwpId 0. 
                      The other BWPs are referred to by  1 to bb_nr5g_MAX_NB_BWPS.*/
    STRUCT_NAME(tm_, bb_nr5g_PUCCH_CONF_DEDICATEDt) PucchConfDed;
    STRUCT_NAME(tm_, bb_nr5g_PUSCH_CONF_DEDICATEDt) PuschConfDed;
    STRUCT_NAME(tm_, bb_nr5g_SRS_CONF_DEDICATEDt)   SrsConfDed;
} STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKDEDICATEDt);

/****************************************************************************************/
/* 38.331 BWP-Uplink IE */
typedef struct {
    uint8_t BwpId;
    uint8_t Spare[3];                   
    STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKCOMMONt) BwpULCommon;
    STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKDEDICATEDt) BwpULDed;
} STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKt);

/****************************************************************************************/
/* 38.331 PDSCH-ServingCellConfig IE: it is used to configure UE specific PDSCH parameters that are common across the UE's BWPs of one serving cell */
typedef struct {
    uint8_t MaxCodeBlockGroupsPerTB; /* Maximum number of code-block-groups (CBGs) per TB.
                                        Enum [n2, n4, n6, n8]; Default/Invalid value is 0xFF*/ 
    uint8_t CodeBlockGroupFlushIndicator; /*Indicates whether CBGFI for CBG based (re)transmission in DL is enabled (true).
                                            Range 0 or 1; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];
} STRUCT_NAME(tm_, bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt);

typedef struct {
    uint8_t XOverhead; /* Accounts for overhead from CSI-RS, CORESET, etc. If the field is absent, the UE applies value xOh0.
                          Enum [xOh6, xOh12, xOh18]; Default/Invalid value is 0xFF*/
    uint8_t NbHarqProcessesForPDSCH; /*The number of HARQ processes to be used on the PDSCH of a serving cell
                                    Enum [n2, n4, n6, n10, n12, n16]; Default/Invalid value is 0xFF*/
    uint16_t PucchCell; /* The ID of the serving cell (of the same cell group) to use for PUCCH.Default/Invalid value is 0xFFFF*/
    STRUCT_NAME(tm_, bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt) CodeBlockGroupTrans; /*Enables and configures code-block-group (CBG) based transmission*/
} STRUCT_NAME(tm_, bb_nr5g_PDSCH_SERVING_CELL_CFGt);

/****************************************************************************************/
/* 38.331 PDSCH-ServingCellConfig IE: it is used to configure UE specific PDSCH parameters that are common across the UE's BWPs of one serving cell */
typedef struct {
    uint8_t MaxCodeBlockGroupsPerTB; /* Maximum number of code-block-groups (CBGs) per TB.
                                        Enum [n2, n4, n6, n8]; Default/Invalid value is 0xFF*/ 
    uint8_t Pad[3];
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_CODEBLOCKGROUPTRANSMt);

typedef struct {
    uint8_t XOverhead; /* Accounts for overhead from CSI-RS, CORESET, etc. If the field is absent, the UE applies value xOh0.
                          Enum [xOh6, xOh12, xOh18]; Default/Invalid value is 0xFF*/
    uint8_t RateMatching; /* Enables LBRM (Limited buffer rate-matching).
                             Enum [limitedBufferRM]; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];
    STRUCT_NAME(tm_, bb_nr5g_PUSCH_CODEBLOCKGROUPTRANSMt) CodeBlockGroupTrans; /*Enables and configures code-block-group (CBG) based transmission*/
} STRUCT_NAME(tm_, bb_nr5g_PUSCH_SERVING_CELL_CFGt);

/****************************************************************************************/
/* 38.331 CSI-MeasConfig IE: it is used to configure CSI-RS (reference signals) belonging to the serving cell in which CSI-MeasConfig is included and channel state information reports
to be transmitted on L1 (PUCCH, PUSCH) on the serving cell in which CSI-MeasConfig is included */
typedef struct {
} STRUCT_NAME(tm_, bb_nr5g_CSI_MEAS_CFGt);
/****************************************************************************************/
/* 38.331 SCS-SpecificCarrier IE: it provides parameters determining the location and width of the actual carrier */
typedef struct {
    uint8_t SubCarrSpacing;     /*  Subcarrier spacing for this carrier
                                Enum [kHz15, kHz30, kHz60, kHz120, kHz240]; Default/Invalid value is 0xFF*/
    uint8_t K0;                 /* Enum [n-6, n0, n6]; Default/Invalid value is 0xFF*/
    uint16_t OffsetToCarrier;   /* Offset in frequency domain between Point A (lowest subcarrier of common RB 0) and 
                                 the lowest usable subcarrier on this carrier in number of PRBs 
                                 (using the subcarrierSpacing defined for this carrier).
                                 Default value is 0xFF; Range 0...2199 */
    uint16_t CarrierBandwidth;  /* Width of this carrier in number of PRBs 
                                 Default value is 0xFF; Range 1...bb_nr5g_MAX_NB_PHYS_RES_BLOCKS */
    uint8_t Spare[2];
} STRUCT_NAME(tm_, bb_nr5g_SCS_SPEC_CARRIERt);

/* 38.331 FrequencyInfoDL IE: it provides basic parameters of a downlink carrier and transmission thereon.*/
typedef struct {
    uint32_t AbsFreqSSB;    /* Frequency of the SSB to be used for this serving cell 
                               Default value is 0xFFFFFFFF; Range 0 ...3279165 */
    uint32_t AbsFreqPointA; /* Absolute frequency position of the reference resource block (Common RB 0).
                               Default value is 0xFFFFFFFF; Range 0 ...3279165 */
    uint8_t SsbSubcarrierOffset; /* The frequency domain offset between SSB and the overall resource block grid 
                                    in number of subcarriers
                                    Default value is 0xFF; Range 1 ...23 */
    uint8_t NbFreqBandList;     /* Gives the number of valid elements in FreqBandList vector: 
                                    1...bb_nr5g_MAX_NB_MULTIBANDS; Default value is 0*/
    uint8_t NbScsSpecCarrier;     /* Gives the number of valid elements in ScsSpecCarrier vector: 
                                    1...bb_nr5g_MAX_SCS; Default value is 0*/
    uint8_t Spare;
    uint16_t FreqBandList[bb_nr5g_MAX_NB_MULTIBANDS]; /*Range 1...1024 for every element*/
    STRUCT_NAME(tm_, bb_nr5g_SCS_SPEC_CARRIERt) ScsSpecCarrier[bb_nr5g_MAX_SCS];
} STRUCT_NAME(tm_, bb_nr5g_FREQINFO_DLt);

/* 38.331 FrequencyInfoUL IE: provides basic parameters of an uplink carrier and transmission thereon */
typedef struct {
    uint32_t AbsFreqPointA; /* Absolute frequency position of the reference resource block (Common RB 0).
                               Default value is 0xFFFFFFFF; Range 0 ...3279165 */
    uint8_t AddSpectrumEmission; /* Additional spectrum emission requirements to be applied by the UE on this uplink.
                                 Default value is 0xFF; Range 0 ...7 */
    uint8_t FreqShift7p5khz;    /* Enable the NR UL transmission with a 7.5KHz shift to the LTE raster
                                 Default value is 0xFF; Enum [true]*/
    int8_t  PMax;               /* Range -30...33 
                                Default value: If the field is absent, the UE applies the value FFS_RAN4*/
    uint8_t NbFreqBandList;     /* Gives the number of valid elements in FreqBandList vector: 
                                    1...bb_nr5g_MAX_NB_MULTIBANDS; Default value is 0*/
    uint8_t NbScsSpecCarrier;     /* Gives the number of valid elements in ScsSpecCarrier vector: 
                                    1...bb_nr5g_MAX_SCS; Default value is 0*/
    uint8_t Spare[3];
    uint16_t FreqBandList[bb_nr5g_MAX_NB_MULTIBANDS]; /*Range 1...1024 for every element*/
    STRUCT_NAME(tm_, bb_nr5g_SCS_SPEC_CARRIERt) ScsSpecCarrier[bb_nr5g_MAX_SCS];
} STRUCT_NAME(tm_, bb_nr5g_FREQINFO_ULt);

/****************************************************************************************/
/* 38.331 PhysicalCellGroupConfig: Cell-Group specific L1 parameters                    */
typedef struct {
    uint8_t HarqACKSpatialBundlingPUCCH; /* Enables spatial bundling of HARQ ACKs. It is configured per cell group 
                                            (i.e. for all the cells within the cell group) for PUCCH reporting of HARQ-ACK.
                                            Default value is 0xFF that means disable spatial bundling.
                                            Enum [true] */
    uint8_t HarqACKSpatialBundlingPUSCH; /* Enables spatial bundling of HARQ ACKs. It is configured per cell group 
                                            (i.e. for all the cells within the cell group) for PUSCH reporting of HARQ-ACK.
                                            Default value is 0xFF that means disable spatial bundling.
                                            Enum [true] */
    int8_t  PmaxNR;                     /*  The maximum transmit power to be used by the UE in this NR cell group.
                                            Range [-30...33]*/
    uint8_t  PdschHarqACKCodebook;       /*  The PDSCH HARQ-ACK codebook is either semi-static of dynamic.
                                            This is applicable to both CA and none CA operation
                                            Default value is 0xFF; Enum [semiStatic, dynamic]*/
} STRUCT_NAME(tm_, bb_nr5g_PH_CELL_GROUP_CONFIGt);

/****************************************************************************************/
/* 38.331 ServingCellConfigCommon IE: it is used to configure cell specific parameters of a UE’s serving cell*/
typedef struct {
    /* Field mask according to bb_nr5g_STRUCT_SERV_CELL_CONFIG_COMMON***_PRESENT
       As a first implementation this bitmap tell which fields/structures have filled with valid values
       In future implementation this bitmap would be able to support messages with a complete dynamic size */
    uint32_t FieldMask;
    uint32_t ServCellIdx;
    uint8_t SsbPeriodicityServCell; /* SSB periodicity in msec for the rate matching purpose 
                                       Default value is 0xFF; Enum [ms5, ms10, ms20, ms40, ms80, ms160]*/
    uint8_t DmrsTypeAPos;           /* Position of (first) DL DM-RS 
                                       Default value is 0xFF; Enum [pos2, pos3]*/
    uint8_t SubCarSpacing;          /* Subcarrier spacing of SSB
                                       Enum [kHz15, kHz30, kHz60, kHz120, kHz240]; Default/Invalid value is 0xFF*/
    uint8_t SsbPosInBurstIsValid;   /* This field assumes a value defined as bb_nr5g_SSB_POS_IN_BURST_*** in order to read
                                       in good way the associated bitmap */
    union {
        uint8_t  ShortBitmap;    /* bitmap for sub 3 GHz */
        uint8_t  MediumBitmap;   /* bitmap for sub 3-6 GHz */
        uint64_t  LongBitmap;    /* bitmap for sub above 6 GHz */
    } SsbPosInBurst;

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_DL_COMMON_FREQ_INFO_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_FREQINFO_DLt), FreqInfoDL);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_DL_COMMON_INIT_DL_BWP_PRESENT 0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKCOMMONt), InitDLBWP);    /* Initial downlink BWP configuration */

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_UL_COMMON_FREQ_INFO_PRESENT   0x0004
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_FREQINFO_ULt), FreqInfoUL);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_UL_COMMON_INIT_UL_BWP_PRESENT   0x0008
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKCOMMONt), InitULBWP);      /* Initial uplink BWP configuration */

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_SUL_COMMON_FREQ_INFO_PRESENT   0x0010
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_FREQINFO_ULt), FreqInfoSUL);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_SUL_COMMON_INIT_UL_BWP_PRESENT   0x0020    
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKCOMMONt), InitSULBWP);     /* Initial supplementary uplink BWP configuration */

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_TDD_COMMON_TDD_DL_UL_PRESENT   0x0040
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_TDD_UL_DL_CONFIG_COMMONt), TddDlUlConfCommon);  /* A cell-specific TDD UL/DL configuration */
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_TDD_COMMON_TDD2_DL_UL_PRESENT   0x0080
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_TDD_UL_DL_CONFIG_COMMONt), TddDlUlConfCommon2); /* A second cell-specific TDD UL/DL configuration */

    int16_t PBCHBlockPower;             /* TX power that the NW used for SSB transmission. 
                                           The UE uses it to estimate the RA preamble TX power
                                           Range[-60..50] */
    uint8_t NbRateMatchPatternToAddMod; /* Gives the number of valid elements in RateMatchPatternToAddMod vector: 
                                           1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternToDel;    /* Gives the number of valid elements in RateMatchPatternToDel vector: 
                                           1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/

    uint8_t RateMatchPatternToDel[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS];/* List of RateMatchPatternId*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_RATE_MATCH_PATTERNt), RateMatchPatternToAddMod[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS]);
} STRUCT_NAME(tm_, bb_nr5g_SERV_CELL_CONFIG_COMMONt);

/****************************************************************************************/
/* 38.331 ServingCellConfig IE: it is used to configure cell specific parameters of a UE’s serving cell*/
typedef struct {
    /* Field mask according to bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG***_PRESENT */
    uint32_t FieldMask;
    uint8_t FirstActiveDlBwp; /* If configured for an SpCell, this field contains the ID of the DL BWP to be activated upon performing the reconfiguration
                                 in which it is received. If the field is absent, the RRC reconfiguration does not impose a BWP switch.
                                 If configured for an SCell, this field contains the ID of the downlink bandwidth part to be used upon MAC-activation of an SCell.
                                 If not provided, the UE uses the default BWP.
                                 The initial bandwidth part is referred to by BwpId = 0.
                                 Range 0....(bb_nr5g_MAX_NB_BWPS-1); Default value is 0xFF*/
    uint8_t DefaultDlBwp; /* This field is UE specific. When the field is absent the UE uses the the initial BWP as default BWP.
                                 Range 0....(bb_nr5g_MAX_NB_BWPS-1); Default value is 0xFF*/
    uint8_t NbDlBwpIdToDel; /* Gives the number of valid elements in DlBwpIdToDel vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t NbDlBwpIdToAdd; /* Gives the number of valid elements in DlBwpIdToAdd vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t DlBwpIdToDel[bb_nr5g_MAX_NB_BWPS]; /*Static list of additional downlink bandwidth parts to be released*/
    /* The dedicated (UE-specific) configuration for the initial downlink bandwidth-part*/
#define bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_INITIAL_DL_BWP_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKDEDICATEDt), InitialDlBwp);
#define bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDSCH_PRESENT   0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PDSCH_SERVING_CELL_CFGt), PdschServingCellCfg);
#define bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_CSI_MEAS_CFG_PRESENT   0x0004
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_CSI_MEAS_CFGt), CsiMeasCfg);
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_BWP_DOWNLINKDEDICATEDt), DlBwpIdToAdd[bb_nr5g_MAX_NB_BWPS_OBJ]); /*Dynamic list of additional downlink bandwidth parts to be added/modified*/
} STRUCT_NAME(tm_, bb_nr5g_DOWNLINK_DEDICATED_CONFIGt);

typedef struct {
    /* Field mask according to bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG***_PRESENT */
    uint32_t FieldMask;
    uint8_t FirstActiveUlBwp; /* If configured for an SpCell, this field contains the ID of the UL BWP to be activated upon performing the reconfiguration
                                 in which it is received. If the field is absent, the RRC reconfiguration does not impose a BWP switch.
                                 If configured for an SCell, this field contains the ID of the downlink bandwidth part to be used upon MAC-activation of an SCell.
                                 If not provided, the UE uses the default BWP.
                                 The initial bandwidth part is referred to by BwpId = 0.
                                 Range 0....(bb_nr5g_MAX_NB_BWPS-1); Default value is 0xFF*/
    uint8_t DefaultUlBwp; /* This field is UE specific. When the field is absent the UE uses the the initial BWP as default BWP.
                                 Range 0....(bb_nr5g_MAX_NB_BWPS-1); Default value is 0xFF*/
    uint8_t NbUlBwpIdToDel; /* Gives the number of valid elements in UlBwpIdToDel vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t NbUlBwpIdToAdd; /* Gives the number of valid elements in UlBwpIdToAdd vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t UlBwpIdToDel[bb_nr5g_MAX_NB_BWPS]; /*Static list of additional uplink bandwidth parts to be released*/
    /* The dedicated (UE-specific) configuration for the initial uplink bandwidth-part*/
#define bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_INITIAL_UL_BWP_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKDEDICATEDt), InitialUlBwp);
#define bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_PUSCH_PRESENT   0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_PUSCH_SERVING_CELL_CFGt), PuschServingCellCfg);
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_BWP_UPLINKDEDICATEDt), UlBwpIdToAdd[bb_nr5g_MAX_NB_BWPS_OBJ]); /*Dynamic list of additional uplink bandwidth parts to be added/modified*/
} STRUCT_NAME(tm_, bb_nr5g_UPLINK_DEDICATED_CONFIGt);

typedef struct {
    /* Field mask according to bb_nr5g_STRUCT_SERV_CELL_CONFIG_***_PRESENT */
    uint32_t FieldMask;
    uint32_t ServCellIdx;
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_TDD_DED_PRESENT   0x0001
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_TDD_UL_DL_CONFIG_DEDICATEDt), TddDlUlConfDed);  /* A cell-specific TDD UL/DL configuration */
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_DOWNLINK_PRESENT   0x0002
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_DOWNLINK_DEDICATED_CONFIGt), DlCellCfgDed);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_UPLINK_PRESENT   0x0004
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_UPLINK_DEDICATED_CONFIGt), UlCellCfgDed);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_SUP_UPLINK_PRESENT   0x0008
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_UPLINK_DEDICATED_CONFIGt), SulCellCfgDed);
} STRUCT_NAME(tm_, bb_nr5g_SERV_CELL_CONFIGt);

/****************************************************************************************/
/* 38.331 CellGroupConfig IE: it is used to configure a master cell group (MCG) or secondary cell group (SCG). */
typedef struct {
    uint32_t FieldMask;
    /* Cell-Group specific L1 parameters */
#define bb_nr5g_STRUCT_CELL_GROUP_CONFIG_PHY_CELL_CONF_PRESENT   0x0001
	VFIELD(STRUCT_NAME(tm_, bb_nr5g_PH_CELL_GROUP_CONFIGt), PhyCellConf);
    /* Current cell parameter configuration */
#define bb_nr5g_STRUCT_CELL_GROUP_CONFIG_CELL_CFG_COMMON_PRESENT   0x0002
	VFIELD(STRUCT_NAME(tm_, bb_nr5g_SERV_CELL_CONFIG_COMMONt), CellCfgCommon);
    /* Aggregable cell parameter configuration */
    uint8_t NbAggrCellCfgCommon; /* Gives the number of valid elements in AggrCellCfgCommon vector: 
                                    1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SERV_CELL_CONFIG_COMMONt), AggrCellCfgCommon[bb_nr5g_MAX_NB_SERVING_CELLS_OBJ]); /* Dynamic list of aggregable cells */
} STRUCT_NAME(tm_, bb_nr5g_CELL_GROUP_CONFIGt);

/****************************************************************************************/
/* 38.331 CellGroupConfig IE: Serving cell specific MAC and PHY parameters for a SpCell */
typedef struct {
    uint32_t FieldMask;
    /* Current dedicated cell parameter configuration */
#define bb_nr5g_STRUCT_CELL_DEDICATED_CONFIG_CELL_CFG_DED_PRESENT   0x0001
	VFIELD(STRUCT_NAME(tm_, bb_nr5g_SERV_CELL_CONFIGt), CellCfgDed);
    /* Aggregable dedicated cell parameter configuration */
    uint8_t NbAggrCellCfgDed; /* Gives the number of valid elements in AggrCellCfgDed vector: 
                                1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0*/
    VFIELD(STRUCT_NAME(tm_, bb_nr5g_SERV_CELL_CONFIGt), AggrCellCfgDed[bb_nr5g_MAX_NB_SERVING_CELLS_OBJ]); /* Dynamic list of aggregable cells */
} STRUCT_NAME(tm_, bb_nr5g_CELL_DEDICATED_CONFIGt);

#pragma    pack()
#endif
