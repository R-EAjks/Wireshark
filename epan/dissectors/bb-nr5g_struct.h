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

#ifndef  bb_nr5g_struct_DEFINED
#define  bb_nr5g_struct_DEFINED

#include "bb-nr5g_def.h"
#include "bb-nr5g_instr_macros.h"
/* Default behavior: this flag bb_nr5g_INTERNAL is turned off in interface file.
   It is up to application SW to define properly this field when it is necessary */
//#define bb_nr5g_INTERNAL

// was: #pragma  pack(1)
#pragma  pack(push,1)

/*
 * The current bb-nr5g Interface version
 */
#define     bb_nr5g_struct_VERSION       "1.12.1"

/* RNTI */
typedef struct {
    uint16_t          RntiType; /* Rnti type see bb_nr5g_RNTI_*** */
    uint16_t          Rnti;     /* RNTI */
    uint32_t          UeId;     /* User id value */
} PREFIX(bb_nr5g_RNTIt);

/**********************************************************************************************************************
 * The TDD-UL-DL-Config IEs determines the Uplink/Downlink TDD configuration. There are both, UE- and cell specific IEs.*/
/* 38.331 TDD-UL-DL-ConfigCommon */
typedef struct {
    uint8_t     DlULTransmPeriodicityIsValid; /* This field assumes a value defined as bb_nr5g_TDD_UL_DL_PATTERN_TRANSM_PERIOD_***
                                       in order to read in good way the associated parameters in DlULTransmPeriodicity.
                                       If this field is set to default value DlULTransmPeriodicity is read using basic enum for
                                       bb_nr5g_TDD_UL_DL_PATTERN_TRANSM_PERIOD_DEFAULT*/
    uint8_t     DlULTransmPeriodicity; /* Periodicity of the DL-UL pattern.
                                       Corresponds to L1 parameter 'DL-UL-transmission-periodicity' (see 38.211, section FFS_Section)
                                       Default/Invalid value is 0xFF.
                                       [38.331] dl-UL-TransmissionPeriodicity : Enum [ms0p5, ms0p625, ms1, ms1p25, ms2, ms2p5, ms5, ms10]; 
                                       In 15.3 the field dl-UL-TransmissionPeriodicity-v1530 has be added.
                                       Its range is Enum [ms3, ms4]
                                       How to read this value is defined by DlULTransmPeriodicityIsValid field:
                                       DlULTransmPeriodicityIsValid = bb_nr5g_TDD_UL_DL_PATTERN_TRANSM_PERIOD_DEFAULT: the range of
                                       validity enum is the one of dl-UL-TransmissionPeriodicity.
                                       DlULTransmPeriodicityIsValid = bb_nr5g_TDD_UL_DL_PATTERN_TRANSM_PERIOD_V1530EXT the range of
                                       validity enum is the one of dl-UL-TransmissionPeriodicity-v1530. */
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
} PREFIX(bb_nr5g_TDD_UL_DL_PATTERNt);

typedef struct {
    uint8_t     RefSubCarSpacing; /* Corresponds to L1 parameter 'reference-SCS' (see 38.211, section FFS_Section)
                                     Enum kHz15, kHz30, kHz60, kHz120, kHz240; Default/Invalid value is 0xFF*/
    uint8_t     Pad;
    /* Field mask according to bb_nr5g_STRUCT_TDD_UL_DL_CONFIG_COMMON_***_PRESENT */
    uint16_t    FieldMask;
#define bb_nr5g_STRUCT_TDD_UL_DL_CONFIG_COMMON_PATT1_PRESENT   0x0001
    PREFIX(bb_nr5g_TDD_UL_DL_PATTERNt) Pattern1; /* Uplink/Downlink TDD configuration pattern 1*/
#define bb_nr5g_STRUCT_TDD_UL_DL_CONFIG_COMMON_PATT2_PRESENT   0x0002
    PREFIX(bb_nr5g_TDD_UL_DL_PATTERNt) Pattern2; /* Uplink/Downlink TDD configuration pattern 2*/
} PREFIX(bb_nr5g_TDD_UL_DL_CONFIG_COMMONt);

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
} PREFIX(bb_nr5g_TDD_UL_DL_SLOT_CONFIGt);

typedef struct {
    uint16_t NbSlotSpecCfgAddMod; /* Gives the number of valid elements in SlotSpecCfgAddMod. Range (0...bb_nr5g_MAX_NB_SLOTS - 1)*/
    uint16_t NbSlotSpecCfgDel;    /* Gives the number of valid elements in SlotSpecCfgDel. Range (0...bb_nr5g_MAX_NB_SLOTS - 1)*/
    AFIELD(PREFIX(bb_nr5g_TDD_UL_DL_SLOT_CONFIGt), SlotSpecCfgAddMod, bb_nr5g_MAX_NB_SLOTS); /* The SlotSpecCfg* allows overriding UL/DL allocations provided in tdd-UL-DL-configurationCommon
                                                                                                Dynamic list of SlotSpecCfg to be added/modified */
    AFIELD(uint32_t, SlotSpecCfgDel, bb_nr5g_MAX_NB_SLOTS); /* Dynamic list of SlotSpecCfg to be deleted */
} PREFIX(bb_nr5g_TDD_UL_DL_CONFIG_DEDICATEDt);

/****************************************************************************************/
/* 38.331 ControlResourceSet IE:used to configure a time/frequency control resource set (CORESET) in which
   to search for downlink control information */
typedef struct {
    uint8_t  CtrlResSetId;       /* Corresponds to L1 parameter 'CORESET-ID;
                                    Default/Invalid value is 0xFF. Release 15: Range 0... bb_nr5g_MAX_NB_CTRL_RES_SETS -1
                                    Release 16: Range 0... bb_nr5g_MAX_NB_CTRL_RES_SETS_1_R16 */
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
    uint16_t PdcchDMRSScramblingId; /* Corresponds to L1 parameter 'PDCCH-DMRS-Scrambling-ID' (see 38.214, section 5.1)
                                       Range 0 ...65535. No invalid value is defined; it is needed to use PdcchDMRSScramblingIdIsValid
                                       field to understand if the DMRS scrambling is configured or not */
    uint8_t PdcchDMRSScramblingIdIsValid; /* This field assumes a value defined as bb_nr5g_PDCCH_DMSR_SCRAMB_***
                                             in order to read in good way the associated parameter PdcchDMRSScramblingId.
                                             If this field is set to bb_nr5g_PDCCH_DMSR_SCRAMB_PRESENT PdcchDMRSScramblingId is read and used.
                                             Otherwise it will be ignored */
    uint8_t TciPresentInDci;    /*  Corresponds to L1 parameter 'TCI-PresentInDCI' (see 38,213, section 5.1.5)
                                    Enum [enable]; Default/Invalid value is 0xFF  */

    uint8_t NbTciStates;        /*  Gives the number of valid elements in TciStates vector: 1....bb_nr5g_MAX_NB_TCI_STATES_PDCCH */

    uint8_t RbOffset_r16;                /*        Range (0..5)   */
    uint8_t TciPresentDCI_r16;           /*        tci-PresentInDCI-ForDCI-Format1-2-r16:     Range (1..3)   */
    uint8_t CoresetPoolIndex_r16;        /*        Range (0..1)   */
    uint8_t TciStates[bb_nr5g_MAX_NB_TCI_STATES_PDCCH]; /* Corresponds to L1 parameter 'TCI-StatesPDCCH' (see 38.214, section FFS_Section)*/
} PREFIX(bb_nr5g_CTRL_RES_SETt);

/****************************************************************************************/
/* 38.331 SearchSpace IE:defines how/where to search for PDCCH candidates */
typedef struct {
    uint8_t AggLev1;  /* Default/Invalid value is 0xFF: Enum [n0, n1, n2, n3, n4, n5, n6, n8] */
    uint8_t AggLev2;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t AggLev4;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t AggLev8;  /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t AggLev16; /* Default/Invalid value is 0xFF; Enum [n0, n1, n2, n3, n4, n5, n6, n8]  */
    uint8_t Spare[3];
} PREFIX(bb_nr5g_MONITOR_NBCANDIDATESt);

typedef struct {
    uint8_t DciFmts00And10;  /* Default value is 0: If this field is set to 1 by TSTM, DCI format has to be set as valid 
                                If configured, the UE monitors the DCI formats 0_0 and 1_0 according to TS 38.213*/
    uint8_t DciFmts20;       /* Default value is 0: If this field is set to 1 by TSTM, DCI format has to be set as valid 
                                If configured, the UE monitors the DCI formats 2_0 according to TS 38.213*/
    uint8_t DciFmts21;      /* Default value is 0: If this field is set to 1 by TSTM, DCI format has to be set as valid 
                                If configured, the UE monitors the DCI formats 2_1 according to TS 38.213*/  
    uint8_t DciFmts22;      /* Default value is 0: If this field is set to 1 by TSTM, DCI format has to be set as valid 
                                If configured, the UE monitors the DCI formats 2_2 according to TS 38.213*/ 
    uint8_t DciFmts23;      /* Default value is 0: If this field is set to 1 by TSTM, DCI format has to be set as valid 
                                If configured, the UE monitors the DCI formats 2_3 according to TS 38.213*/
    uint8_t DciFmts23MonPeriodicity; /* It is filled with valid values if DciFmts23 is different than 0*/
                                    /*  Default/Invalid value is 0xFF; Enum [sl1, sl2, sl4, sl5, sl10, sl16, sl20]  */
    uint8_t DciFmts23PdcchCand;     /*  It is filled with valid values if DciFmts23 is different than 0*/
                                    /*  Default/Invalid value is 0xFF; Enum [n1, n2]  */
    uint8_t Spare;
    PREFIX(bb_nr5g_MONITOR_NBCANDIDATESt) DciFmts20CandSFI; /* It is filled with valid values if DciFmts20 is different than 0xFF*/

} PREFIX(bb_nr5g_SEARCH_SPACETYPE_COMMONt);

typedef struct {
    uint8_t DciFmts; /* Default/Invalid value is 0xFF: Release 15: Enum [formats0-0-And-1-0, formats0-1-And-1-1] */
                     /* Release 16: Enum [formats0-2-And-1-2, formats0-1-And-1-1And-0-2-And-1-2] - [0-1]*/
    uint8_t DciFormatsR16Present;   /* Default/Invalid value is 0xFF. If it is 1, the dci-Formats values are ignored and dci-FormatsExt is used instead. */
    uint16_t Spare;
} PREFIX(bb_nr5g_SEARCH_SPACETYPE_DEDICATEDt);

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
    union {
        uint8_t Sl1;  /* Default value is 0xFF */
        uint8_t Sl2;  /* Default value is 0xFF; Range 0...1 */
        uint8_t Sl4;  /* Default value is 0xFF; Range 0...3 */
        uint8_t Sl5;  /* Default value is 0xFF; Range 0...4 */
        uint8_t Sl8;  /* Default value is 0xFF; Range 0...7 */
        uint8_t Sl10; /* Default value is 0xFF; Range 0...9 */
        uint8_t Sl16; /* Default value is 0xFF; Range 0...15 */
        uint8_t Sl20; /* Default value is 0xFF; Range 0...19 */
        uint8_t Sl40; /* Default value is 0xFF; Range 0...39 */
        uint8_t Sl80; /* Default value is 0xFF; Range 0...79 */
        uint8_t Sl160; /* Default value is 0xFF; Range 0...159 */
        uint16_t Sl320; /* Default value is 0xFF; Range 0...319 */
        uint16_t Sl640; /* Default value is 0xFF; Range 0...639 */
        uint16_t Sl1280; /* Default value is 0xFF; Range 0...1279 */
        uint16_t Sl2560; /* Default value is 0xFF; Range 0...2559 */
    } MonitorSlot; /* Slots for PDCCH Monitoring configured as periodicity and offset. The field to be read is linked to
                      MonitorSlotIsValid field */
    PREFIX(bb_nr5g_MONITOR_NBCANDIDATESt)      NbCandidates;   /* Number of PDCCH candidates per aggregation level*/
    union {
        PREFIX(bb_nr5g_SEARCH_SPACETYPE_COMMONt)    SearchSpaceTypeCommon;
        PREFIX(bb_nr5g_SEARCH_SPACETYPE_DEDICATEDt) SearchSpaceTypeDedicated;
    } SearchSpaceType;

    uint16_t SearchSpaceDuration; /* Number of consecutive slots that a SearchSpace lasts in every occasion, i.e., upon every 
                                     period as given in the periodicityAndOffset. If the field is absent, the UE applies the value 1 slot, 
                                     except for DCI format 2_0. The UE ignores this field for DCI format 2_0. 
                                     The maximum valid duration is periodicity-1 (periodicity as given in the MonitorSlot).
                                     Range 2...2559. Default is 0xFFFF*/
    uint8_t Pad[2];
} PREFIX(bb_nr5g_SEARCH_SPACEt);

/****************************************************************************************/
/* 38.331 DownlinkPreemption IE: Configuration of downlink preemption indication on PDCCH. */

typedef struct {
    uint16_t ServCellIdx;  /*Serving cell identifier */
    uint8_t PositionInDCI; /* Starting position (in number of bit) of the 14 bit INT value applicable
                            for this serving cell (servingCellId) within the DCI payload.
                            Default/Invalid value is 0xFF; Range 0....(bb_nr5g_MAX_INT_DCI_PAYLOAD_SIZE-1)*/
    uint8_t Pad;
} PREFIX(bb_nr5g_INT_CFG_PER_SERVINGCELLt);

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
    PREFIX(bb_nr5g_RNTIt) IntRnti;      /* RNTI used for indication pre-emption in DL. */
    AFIELD(PREFIX(bb_nr5g_INT_CFG_PER_SERVINGCELLt), IntConfPerServingCell, bb_nr5g_MAX_NB_SERVING_CELLS);
                                /* Dynamic list: Indicates (per serving cell) the position of the 14 bit INT values inside the DCI payload.*/
} PREFIX(bb_nr5g_DOWNLINK_PREEMPTIONt);

/****************************************************************************************/
/* 38.331 SlotFormatCombinations applicable for one serving cell.*/
typedef struct {
    uint16_t SlotFormatCombinationId; /* SFI index that is assoicated with a certian slot-format-combination
                                       Range:1 ..bb_nr5g_MAX_SLOT_FMT_COMBS_PER_SET; Default/Invalid value is 0xFFFF*/
    uint16_t NbSlotFormats; /*Gives the number of valid elements in SlotFormats vector:
                                     Range:1 ..bb_nr5g_MAX_NB_SLOT_FMTS_PER_COMB; Default/Invalid value is 0*/
    AFIELD(uint32_t, SlotFormats, bb_nr5g_MAX_NB_SLOT_FMTS_PER_COMB); /* Dynamic list. Element range is 0 ...255 */
} PREFIX(bb_nr5g_SLOT_FMT_COMBt);

typedef struct {
    uint16_t ServCellIdx;  /*Serving cell identifier */
    uint8_t SubcarrierSpacing;  /* Reference subcarrier spacing for this Slot Format Combination*/
    uint8_t SubcarrierSpacing2; /* Reference subcarrier spacing for a Slot Format Combination on an FDD or SUL cell*/
    uint8_t PositionInDCI;      /* The (starting) position (bit) of the slotFormatCombinationId (SFI-Index)
                                   Range 0..bb_nr5g_MAX_SFI_DCI_PAYLOAD_SIZE;Default/Invalid value is 0xFF*/
    uint8_t Pad;
    uint16_t NbSlotFormatCombinations; /* Gives the number of valid elements in slotFormatCombinations vector:
                                         Range:1 ..bb_nr5g_MAX_SLOT_FMT_COMBS_PER_SET; Default/Invalid value is 0*/
    AFIELD(PREFIX(bb_nr5g_SLOT_FMT_COMBt), slotFormatCombinations, bb_nr5g_MAX_SLOT_FMT_COMBS_PER_SET);/*Dynamic list*/
} PREFIX(bb_nr5g_SLOT_FMT_COMBSPERCELLt);

/* SlotFormatIndicator IE*/
typedef struct {
    uint8_t DciPayloadSize;  /* Total length of the DCI payload scrambled with SFI-RNTI.
                                Default/Invalid value is 0xFF; Range 1....bb_nr5g_MAX_SFI_DCI_PAYLOAD_SIZE*/
    uint8_t NbSlotFormatCombToAdd; /*Gives the number of valid elements in slotFormatCombToAdd vector:
                                     Range:1 ..bb_nr5g_MAX_AGG_CELLS_PER_GROUP; Default/Invalid value is 0*/
    uint8_t NbSlotFormatCombToDel; /*Gives the number of valid elements in SlotFormatCombToDel vector:
                                     Range:1 ..bb_nr5g_MAX_AGG_CELLS_PER_GROUP; Default/Invalid value is 0*/
    uint8_t Pad;
    PREFIX(bb_nr5g_RNTIt) Rnti;               /* RNTI used for SFI on the given cell */
    AFIELD(uint32_t, SlotFormatCombToDel, bb_nr5g_MAX_AGG_CELLS_PER_GROUP); /* Dynamic list */
    AFIELD(PREFIX(bb_nr5g_SLOT_FMT_COMBSPERCELLt), slotFormatCombToAdd, bb_nr5g_MAX_AGG_CELLS_PER_GROUP); /* Dynamic list */
} PREFIX(bb_nr5g_SLOT_FMT_INDICATORt);

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
} PREFIX(bb_nr5g_PUSCH_TPC_CFGt);

/* PUCCH-TPC-CommandConfig IE */
typedef struct {
    uint8_t TpcIndexPCell; /*An index determining the position of the first bit
                        of TPC command inside the DCI format 2-2
                        Range:1 ..15; Default/Invalid value is 0xFF*/
    uint8_t TpcIndexSCell;/*An index determining the position of the first bit
                        of TPC command inside the DCI format 2-2
                        Range:1 ..15; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];
} PREFIX(bb_nr5g_PUCCH_TPC_CFGt);

/* SRS-TPC-CommandConfig IE */
typedef struct {
    uint8_t StartingBitOfFormat23; /* The starting bit position of a block within the group DCI with SRS request fields (optional) 
                                    and TPC commands . Range:1 ..31; Default/Invalid value is 0xFF*/
    uint8_t FieldTypeFormat23;      /* The type of a field within the group DCI with SRS request fields (optional), 
                                        which indicates how many bits in the field are for SRS request (0 or 2).
                                        Range:0..1; Default/Invalid value is 0xFF*/
    uint8_t StartingBitOfFormat23Sul; /* The starting bit position of a block within the group DCI with SRS request fields (optional) 
                                         and TPC commands for SUL carrier. Range:1 ..31; Default/Invalid value is 0xFF*/
    uint8_t Pad;
} PREFIX(bb_nr5g_SRS_TPC_CFGt);
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
    uint8_t MaxNrofPorts;        /* Enum [n1,n2]; Default value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_PTRS_DOWNLINK_CFGt);

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
    uint8_t DmrsDownlink_r16;     /* Enum [enabled]; Default/Invalid value is 0xFF */
    uint8_t Pad[3];
    PREFIX(bb_nr5g_PTRS_DOWNLINK_CFGt) PhaseTrackingRS;
} PREFIX(bb_nr5g_DMRS_DOWNLINK_CFGt);

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
} PREFIX(bb_nr5g_CP_OFDM_CFGt);

typedef struct {
    uint8_t NbSampleDensity; /* Gives the number of valid elements in SampleDensity vector:
                                    Range: 5; Default value is 0*/
    uint8_t TimeDensity; /* Time density. Enum [d2]; Default/Invalid value is 0xFF*/
    uint16_t SampleDensity[5]; /* Sample density of PT-RS
                                  Element range 1..276. Size of the static vector is 5 */
} PREFIX(bb_nr5g_DFT_S_OFDM_CFGt);

typedef struct {
    uint8_t ModeSpecParamsIsValid;/* This field assumes a value defined as bb_nr5g_PTRS_UPLINK_MODE_SPEC_PARAMS_***
                                       in order to read in good way the associated parameters in ModeSpecPars.
                                       If this field is set to default value ModeSpecPars is neither read or used.
                                       In this case PREFIX(bb_nr5g_PTRS_UPLINK_CFGt) is considered as not configured*/
    uint8_t Pad[3];
    PREFIX(bb_nr5g_CP_OFDM_CFGt) CpOfdmMode;
    PREFIX(bb_nr5g_DFT_S_OFDM_CFGt) DftsOfdmMode;
} PREFIX(bb_nr5g_PTRS_UPLINK_CFGt);

/* DMRS-UplinkConfig IE */
typedef struct {
    uint32_t ScramblingID0; /* UL DMRS scrambling initalization for CP-OFDM
                               Valid range 0....65535; Invalid value is 0xFFFFFFFF */
    uint32_t ScramblingID1; /* UL DMRS scrambling initalization for CP-OFDM
                               Valid range 0....65535; Invalid value is 0xFFFFFFFF */
    uint8_t DmrsUplink_r16;     /* Enum [enabled]; Default/Invalid value is 0xFF */
    uint8_t Pad[3];
} PREFIX(bb_nr5g_TRANSF_PRECOD_DISABLEt);

typedef struct {
    uint16_t PuschIdentity;/* Parameter: N_ID^(PUSCH) for DFT-s-OFDM DMRS
                               Range 0....1007 */
    uint8_t DisableSeqGroupHop; /* Sequence-group hopping for PUSCH can be disabled for a certain UE despite being enabled on a cell basis
                            Enum [disabled]; Default/Invalid value is 0xFF*/
    uint8_t SeqHopEnabled; /* Determines if sequence hopping is enabled or not
                            Enum [enabled]; Default/Invalid value is 0xFF*/

    uint32_t Pi2BPSKScramblingID0;                 /* Range(0..65535)       */
    uint32_t Pi2BPSKScramblingID1;                 /* Range(0..65535)       */
} PREFIX(bb_nr5g_TRANSF_PRECOD_ENABLEt);

typedef struct {
    uint8_t DmrsType;   /* Selection of the DMRS type to be used for UL
                           Enum [type2]; Default/Invalid value is 0xFF*/
    uint8_t DmrsAddPos; /* Position for additional DM-RS in UL
                           Enum [pos0, pos1, pos3]; Default/Invalid value is 0xFF*/
    uint8_t MaxLength;   /* The maximum number of OFDM symbols for UL front loaded DMRS
                            Enum [len2]; Default/Invalid value is 0xFF*/
    uint8_t TransfPrecodIsValid;/* This field assumes a value defined as bb_nr5g_DMRS_UPLINK_TRANSF_PRECOD_***
                                       in order to read in good way the associated parameters in TransfPrecod***.
                                       If this field is set to default value TransfPrecodDisable or TransfPrecodEnable is neither read or used */
    PREFIX(bb_nr5g_TRANSF_PRECOD_DISABLEt) TransfPrecodDisable;
    PREFIX(bb_nr5g_TRANSF_PRECOD_ENABLEt) TransfPrecodEnable;
    PREFIX(bb_nr5g_PTRS_UPLINK_CFGt) PhaseTrackingRS;
} PREFIX(bb_nr5g_DMRS_UPLINK_CFGt);

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
                                     When the field is absent the UE applies the value 13. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetCsiPart1Idx2; /* Up to 11 bits CSI part 1 bits. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 13. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetCsiPart2Idx1; /* Up to 11 bits CSI part 2 bits. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 13. Range 0...31; Default value is 0xFF */
    uint8_t BetaOffsetCsiPart2Idx2; /* Up to 11 bits CSI part 2 bits. (see 38.213, section 9.3)
                                     When the field is absent the UE applies the value 13. Range 0...31; Default value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_BETAOFFSETSt);

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
    PREFIX(bb_nr5g_BETAOFFSETSt) BetaOffsets[4];
} PREFIX(bb_nr5g_UCI_ON_PUSCHt);

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
} PREFIX(bb_nr5g_QCL_INFOt);

/* TCI-State IE */
typedef struct {
    uint8_t TciStateId; /* Range 0....(bb_nr5g_MAX_NB_TCI_STATES-1); Default/Invalid is 0xFF */
    uint8_t NbPtrsPorts; /*Enum [n1, n2]; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];
    PREFIX(bb_nr5g_QCL_INFOt) QclType1;
    PREFIX(bb_nr5g_QCL_INFOt) QclType2;
} PREFIX(bb_nr5g_TCI_STATEt);

/****************************************************************************************/
/* RateMatchPattern IE*/
typedef struct {
    uint8_t  SymbInResBlockIsValid; /* This field assumes a value defined as bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SYMBRES_***
                                       in order to read in good way the associated parameter SymbInResBlock.
                                       If this field is set to default value SymbInResBlock is neither read or used */
    uint8_t  PeriodicityAndPatternIsValid; /* This field assumes a value defined as bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_***
                                       in order to read in good way the associated parameter PeriodicityAndPattern.
                                       If this field is set to default value PeriodicityAndPattern is neither read or used */
    uint8_t  Pad[2];
    uint32_t ResBlocks[bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SIZERES]; /* A resource block level bitmap in the frequency domain
                                                                      Bitmap Size(275) */
    uint32_t SymbInResBlock;
    uint64_t PeriodicityAndPattern; /* A time domain repetition pattern. Bitmap size to be considered as valid is
                                       defined by means of PeriodicityAndPatternIsValid field*/

} PREFIX(bb_nr5g_RATE_MATCH_PATTERN_BITMAPt);

typedef struct {
    uint8_t RateMatchPatternId;     /* Identifies one RateMatchMattern
                                       Default value is 0XFF; Range 0..bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS-1*/
    uint8_t RateMatchPatternType;   /* This field assumes a value defined as bb_nr5g_RATE_MATCH_PATTERN_*** in order to read
                                       in good way the associated structures. If this field is set to default value
                                       or it is set to bb_nr5g_RATE_MATCH_PATTERN_CTRLRESSET 
                                       dynamic RateMatchPatternBitmap structure will not be present */
    uint8_t RateMatchPatternCtrlResSet; /* This field is used as a PDSCH rate matching pattern.
                                           Defaul value is 0xFF; it is assumed as to be valid only if RateMatchPatternType
                                           is set to bb_nr5g_RATE_MATCH_PATTERN_CTRLRESSET. 
                                           Release 15: Range (0..11). Release 16: Range (0..15) */
    uint8_t  SubCarSpacing;          /* SubcarrierSpacing for this resource pattern
                                        Enum [kHz15, kHz30, kHz60, kHz120, kHz240]; Default/Invalid value is 0xFF*/
    uint8_t  Dummy;                  /* Enum [dynamic, semiStatic]; Default/Invalid value is 0xFF */
    uint8_t  Pad[3];
    PREFIX(bb_nr5g_RATE_MATCH_PATTERN_BITMAPt) RateMatchPatternBitmap; /* It is assumed as to be valid only if RateMatchPatternType
                                                is set to bb_nr5g_RATE_MATCH_PATTERN_BITMAP */
} PREFIX(bb_nr5g_RATE_MATCH_PATTERNt);

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
} PREFIX(bb_nr5g_PDSCH_TIMEDOMAINRESALLOCt);

/****************************************************************************************/
/* CSI-FrequencyOccupation IE */
typedef struct {
    uint16_t StartingRB; /* PRB where this CSI resource starts in relation to PRB 0 of the associated BWP
                            Range 0...(bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1)*/
    uint16_t NrRBs;     /* Number of PRBs across which this CSI resource spans
                            Range 24...bb_nr5g_MAX_NB_PHYS_RES_BLOCKS*/
} PREFIX(bb_nr5g_CSI_FREQUENCY_OCCt);

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
    PREFIX(bb_nr5g_CSI_FREQUENCY_OCCt) FreqBand; /* Wideband or partial band CSI-RS */
} PREFIX(bb_nr5g_CSI_RS_RES_MAPPINGt);

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
} PREFIX(bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt);

/* ZP-CSI-RS-Resource IE */
typedef struct {
    uint8_t ResourceId; /* ZP CSI-RS resource set ID. Range 0.... (bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES-1) */
    uint8_t Pad[3];
    PREFIX(bb_nr5g_CSI_RS_RES_MAPPINGt) ResourceMapping; /* OFDM symbol and subcarrier occupancy of the ZP-CSI-RS resource within a slot */
    PREFIX(bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt) PeriodicityAndOffset;/*Periodicity and slot offset for periodic/semi-persistent ZP-CSI-RS*/
} PREFIX(bb_nr5g_ZP_CSI_RS_RESt);

/* ZP-CSI-RS-ResourceSet IE: it refers to a set of ZP-CSI-RS-Resources using their ZP-CSI-RS-ResourceIds.*/
typedef struct {
    uint8_t ResourceSetId; /* ZP CSI-RS resource configuration ID. Range 0.... (bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS-1) */
    uint8_t ResourceType;  /* Time domain behavior of ZP-CSI-RS resource configuration
                              Enum [aperiodic, semiPersistent, periodic]; Default value is 0xFF 
                              This field is not present in 15.2 38.331. It is left to guarantee the backward compatibility */
    uint8_t Pad;
    uint8_t NbResourceSetIdList; /* Gives the number of valid elements in ResourceSetIdList vector: 1 .. bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES_PER_SET;
                                    Default value is 0*/
    uint8_t ResourceSetIdList[bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES_PER_SET];
} PREFIX(bb_nr5g_ZP_CSI_RS_RES_SETt);

/****************************************************************************************/
/* PUCCH-Resource IE */
/* A PUCCH Format 0 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t InitCyclicShift; /* Range 0 ...11; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 1..2; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..13; Default value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_PUCCH_FMT0t);

/* A PUCCH Format 1 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t InitCyclicShift; /* Range 0 ...11; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 4..14; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..10; Default value is 0xFF */
    uint8_t TimeDomainOCC;   /* Range 0..6; Default value is 0xFF */
} PREFIX(bb_nr5g_PUCCH_FMT1t);

/* A PUCCH Format 2 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t NrPRBs;          /* Range 1..16; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 1..2; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..13; Default value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_PUCCH_FMT2t);

/* A PUCCH Format 3 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t NrPRBs;          /* Range 1..16; Default value is 0xFF */
    uint8_t NrofSymbols;     /* Range 4..14; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..10; Default value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_PUCCH_FMT3t);

/* A PUCCH Format 4 resource configuration (see 38.213, section 9.2) */
typedef struct {
    uint8_t NrofSymbols;     /* Range 4..14; Default value is 0xFF */
    uint8_t OccLength;      /* Enum [n2,n4]; Default value is 0xFF */
    uint8_t OccIndex;        /* Enum [n0,n1,n2,n3]; Default value is 0xFF */
    uint8_t StartingSymbIdx; /* Range 0..10; Default value is 0xFF */
} PREFIX(bb_nr5g_PUCCH_FMT4t);

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
        PREFIX(bb_nr5g_PUCCH_FMT0t) fmt0;
        PREFIX(bb_nr5g_PUCCH_FMT1t) fmt1;
        PREFIX(bb_nr5g_PUCCH_FMT2t) fmt2;
        PREFIX(bb_nr5g_PUCCH_FMT3t) fmt3;
        PREFIX(bb_nr5g_PUCCH_FMT4t) fmt4;
    } Format;
} PREFIX(bb_nr5g_PUCCH_RESOURCEt);

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
        uint8_t Ssb;             /* Range 0....63; Default is 0xFF */
        uint8_t CsiRs;           /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
        struct {
            uint8_t resource;
            uint8_t uplinkBWP;
        } Srs; /* Range 0....(bb_nr5g_MAX_SRS_RESOURCES-1); Default is 0xFF */
    } RefSig;
    uint16_t ServCellIdx;        /*Serving cell identifier */
} PREFIX(bb_nr5g_SPATIAL_RELATION_INFOt);

typedef struct {
    uint8_t ResourceSetId; /* Range 0 ...(bb_nr5g_MAX_PUCCH_RESOURCE_SETS -1); Default value is 0xFF */
    uint8_t NbResources; /* Gives the number of valid elements in Resources vector: Range 8 ...bb_nr5g_MAX_PUCCH_RESOURCE_SETS; Default value is 0xFF */
    uint16_t MaxPayloadMinus1; /* Range 4...256. Default value is 0xFFFF*/
    uint8_t Resources[bb_nr5g_MAX_PUCCH_RESOURCES_PERSET]; /*PUCCH resources of format0 and format1 are only allowed in the first PUCCH reosurce set*/
} PREFIX(bb_nr5g_PUCCH_RESOURCE_SETt);

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
} PREFIX(bb_nr5g_PUCCH_FMT_CFGt);

/****************************************************************************************/
/* 38.331 PUSCH-PowerControl IE: it is used to configure UE specific power control parameter for PUSCH.*/
typedef struct {
    uint8_t AlphaSetId; /* Range 0 ...(bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS-1); Default/Invalid value is 0xFF */
    int8_t P0;            /* P0 value for PUSCH with grant (except msg3) in steps of 1dB.Range -16...15 */
    uint8_t Alpha;       /* Alpha value for PUSCH with grant (except msg3)
                                Enum [alpha0, alpha04, alpha05, alpha06, alpha07, alpha08, alpha09, alpha1]; Default/Invalid value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_P0_PUSCH_ALPHASETt);

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
} PREFIX(bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RSt);

typedef struct {
    uint8_t SriPwCtrlId; /* Range 0 ...(bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING-1); Default/Invalid value is 0xFF */
    uint8_t SriPathlossRefRSId; /* Range 0 ...(bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS-1); Default/Invalid value is 0xFF */
    uint8_t SriAlphaSetId;  /* Range 0 ...(bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS-1); Default/Invalid value is 0xFF */
    uint8_t SriClosedLoopIdx; /* The index of the closed power control loop associated with this SRI-PUSCH-PowerControl
                                Enum [i0, i1]; Default/Invalid value is 0xFF */
} PREFIX(bb_nr5g_SRI_PUSCH_POWERCONTROLt);

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
    AFIELD(PREFIX(bb_nr5g_P0_PUSCH_ALPHASETt), P0AlphaSets, bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS); /*Dynamic list for configuration {p0-pusch,alpha} sets for PUSCH (except msg3).*/
    AFIELD(PREFIX(bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RSt), PathlossRefRsToAdd, bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS); /* Dynamic list of Reference Signals (e.g. a CSI-RS config or a SSblock)
                                                                    to be used for PUSCH path loss estimation to be added/modified */
    AFIELD(PREFIX(bb_nr5g_SRI_PUSCH_POWERCONTROLt), SriPuschMapToAdd, bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING); /* Dynamic list of SRI-PUSCH-PowerControl elements among which one is selected
                                                            by the SRI field in DCI to be added/modified*/
    AFIELD(uint32_t, SriPuschMapToDel, bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING); /* Dynamic list of SRI-PUSCH-PowerControl elements to be deleted */
} PREFIX(bb_nr5g_PUSCH_POWERCONTROLt);


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
} PREFIX(bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RSt);

typedef struct {
    uint8_t P0Id;    /* Range 1..8; Default value is 0xFF*/
    int8_t  P0Value; /* Range -16..15; */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_PUCCH_P0t);

typedef struct {
    int8_t DeltaFPucchF0; /* deltaF for PUCCH format 0 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t DeltaFPucchF1; /* deltaF for PUCCH format 1 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t DeltaFPucchF2; /* deltaF for PUCCH format 2 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t DeltaFPucchF3; /* deltaF for PUCCH format 3 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    int8_t DeltaFPucchF4; /* deltaF for PUCCH format 4 with 1dB step size (see 38.213, section 7.2). Range -16..15 */
    uint8_t TwoPucchPCAdjStates; /*Number of PUCCH power control adjustment states maintained by the UE (i.e., fc(i)).
                               Enum [twoStates]; Default/Invalid value is 0xFF */
    uint8_t NbP0Set; /* Gives the number of valid elements in P0Set vector: 1..bb_nr5g_MAX_PUCCH_P0_PERSET; Default value is 0*/
    uint8_t NbPathlossRefRs; /* Gives the number of valid elements in PathlossRefRs vector: 1..bb_nr5g_MAX_NB_PUCCH_PATHLOSS_REFERENCE_RS; Default value is 0*/
    PREFIX(bb_nr5g_PUCCH_P0t) P0Set[bb_nr5g_MAX_PUCCH_P0_PERSET];
    PREFIX(bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RSt) PathlossRefRs[bb_nr5g_MAX_NB_PUCCH_PATHLOSS_REFERENCE_RS];
} PREFIX(bb_nr5g_PUCCH_POWERCONTROLt);

/* 38.331 SchedulingRequestResourceConfig IE: it determines physical layer resources on PUCCH where the UE may send the dedicated scheduling request*/
typedef struct {
    uint8_t SRResourceId;/* Range 1 ...bb_nr5g_MAX_SR_RESOURCES; Default/Invalid value is 0xFF */
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
} PREFIX(bb_nr5g_SR_RESOURCE_CFGt);

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
} PREFIX(bb_nr5g_SRS_TRANSMISSION_COMBt);

typedef struct {
    uint8_t StartPos;  /* Release 15: Range 0..5; Release 16: (0..13) */
    uint8_t NbSymbols; /* Enum [n1, n2, n4]; Default/Invalid value is 0xFF */
    uint8_t RepFactor; /* Enum [n1, n2, n4]; Default/Invalid value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_SRS_RESOURCE_MAPPINGt);

typedef struct {
    uint8_t CSrs; /* Range 0..63; Default/Invalid value is 0xFF */
    uint8_t BSrs; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t BHop; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_SRS_SPATIAL_RELATION_INFOt);

typedef struct {
    uint8_t CSrs; /* Range 0..63; Default/Invalid value is 0xFF */
    uint8_t BSrs; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t BHop; /* Range 0..3; Default/Invalid value is 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_SRS_FREQ_HOPPINGt);

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
} PREFIX(bb_nr5g_SRS_RESOURCETYPEt);

typedef struct {
    uint8_t SrsResourceTypeSetIsValid; /* This field assumes a value defined as bb_nr5g_SRS_RESOURCETYPESET_***
                                    in good way the associated parameter SrsResourceTypeSet.
                                    If this field is set to default value SrsResourceTypeSet is neither read or used */
    union{
        struct
        {
            uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
            uint8_t ResTrigger;       /* Range 0....(bb_nr5g_MAX_NB_SRS_TRIGGER_STATES-1); Default is 0xFF */
            uint8_t SlotOffset;       /* Range 1...32; Default is 0xFF */
        } Aperiodic;
        struct
        {
            uint8_t CsiRs;            /* Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFF */
        } PeriodicOrSemiPers;
    } SrsResourceTypeSet;

} PREFIX(bb_nr5g_SRS_RESOURCETYPESETt);

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
    PREFIX(bb_nr5g_SRS_TRANSMISSION_COMBt) TransmissionComb; /* Comb value (2 or 4) and comb offset (0..combValue-1).*/
    PREFIX(bb_nr5g_SRS_RESOURCE_MAPPINGt) ResourceMapping; /*OFDM symbol location of the SRS resource within a slot including number of OFDM symbols*/
    PREFIX(bb_nr5g_SRS_FREQ_HOPPINGt) FreqHop; /*Includes parameters capturing SRS frequency hopping*/
    PREFIX(bb_nr5g_SRS_RESOURCETYPEt) ResourceType; /*Time domain behavior of SRS resource configuration*/
} PREFIX(bb_nr5g_SRS_RESOURCEt);

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
    PREFIX(bb_nr5g_SRS_RESOURCETYPESETt) ResourceType;
} PREFIX(bb_nr5g_SRS_RESOURCE_SETt);

/* nrofCandidates-IAB-r16 or nrofCandidates-CI-r16 */
typedef struct {
   uint8_t AggregationLevel1_r16;               /* Enum [n1,n2]; Default value is 0xFF */
   uint8_t AggregationLevel2_r16;               /* Enum [n1,n2]; Default value is 0xFF */
   uint8_t AggregationLevel4_r16;               /* Enum [n1,n2]; Default value is 0xFF */
   uint8_t AggregationLevel8_r16;               /* Enum [n1,n2]; Default value is 0xFF */
   uint8_t AggregationLevel16_r16;              /* Enum [n1,n2]; Default value is 0xFF */
   uint8_t Spare[3];
} PREFIX(bb_nr5g_SEARCH_SPACE_DCI_FMT2_R16t);

/* common-r16 */
typedef struct {
    PREFIX(bb_nr5g_SEARCH_SPACE_DCI_FMT2_R16t) DciFormat24_r16;
    PREFIX(bb_nr5g_SEARCH_SPACE_DCI_FMT2_R16t) DciFormat25_r16;
} PREFIX(bb_nr5g_SEARCH_SPACE_TYPE_COMMON_R16t);

/* SearchSpaceExt-r16 */
typedef struct {
    uint32_t FieldMask;
    uint16_t Len;
    uint16_t Spare;
    uint8_t ControlResourceSetId_r16;
    uint8_t FreqMonitorLocations_r16;           /* BIT STRING (SIZE (5)) */
    uint8_t NbSearchSpaceGroupIdList;
    uint8_t SearchSpaceGroupIdList_r16[2];
    uint8_t Pad[3];

#define bb_nr5g_STRUCT_SEARCH_SPACE_TYPE_COMMON_PRESENT   0x0001
    PREFIX(bb_nr5g_SEARCH_SPACE_TYPE_COMMON_R16t) SearchSpaceTypeCommon_r16;

} PREFIX(bb_nr5g_SEARCH_SPACE_EXTt);

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
    uint8_t ControlResourceSetZero; /* Parameters of the common CORESET#0. The values are interpreted like the corresponding bits 
                                       in MIB pdcch-ConfigSIB1. Range 0...15;  Default/Invalid value 0xFF*/
    uint8_t SearchSpaceZero;    /* Parameters of the common SearchSpace#0. The values are interpreted like the corresponding bits in MIB pdcch-ConfigSIB1. 
                                Range 0...15;  Default/Invalid value 0xFF*/
    uint8_t FirstPdcchMonitOccOfPOIsValid; /* This field assumes a value defined as bb_nr5g_FIRST_PDCCH_MON_OCC__***
                                       in order to read in good way the associated parameters FirstPdcchMonitOccOfPO.
                                       If this field is set to default value FirstPdcchMonitOccOfPO is neither read or used */

    uint8_t NbFirstPdcchMonitOccOfPO;
    uint8_t NbCommonSearchSpacesExt;
    PREFIX(bb_nr5g_CTRL_RES_SETt) CommonCtrlResSets[bb_nr5g_COMMON_CTRL_RES_SET_SIZE];
                                                   /* A list of common control resource sets. Only CORESETs with ControlResourceSetId = 0
                                                   or 1 are allowed. The CORESET#0 corresponds to the CORESET configured in MIB
                                                   (see pdcch-ConfigSIB1) and is used to provide that information to the UE
                                                    by dedicated signalling during handover and (P)SCell addition.
                                                    The CORESET#1 may be configured an used for RAR (see RaCtrlResSet).
                                                    15.3 38.331: This vector has got one only element */
    PREFIX(bb_nr5g_SEARCH_SPACEt) CommonSearchSpaces[bb_nr5g_COMMON_SEARCH_SPACE_SIZE];
    uint16_t FirstPdcchMonitOccOfPO[bb_nr5g_MAX_PO_PERPF];

    PREFIX(bb_nr5g_SEARCH_SPACE_EXTt) CommonSearchSpacesExt_r16[bb_nr5g_COMMON_SEARCH_SPACE_SIZE];
} PREFIX(bb_nr5g_PDCCH_CONF_COMMONt);

/****************************************************************************************/

/* 38.331 PDSCH-ConfigCommon IE: is used to configure FFS */
typedef struct {
    uint8_t NbPdschAlloc;  /* Gives the number of valid elements in PdschAlloc vector:
                              1...bb_nr5g_MAX_NB_DL_ALLOCS; Default value is 0*/
    uint8_t Spare[3];
    PREFIX(bb_nr5g_PDSCH_TIMEDOMAINRESALLOCt)  PdschAlloc[bb_nr5g_MAX_NB_DL_ALLOCS];
} PREFIX(bb_nr5g_PDSCH_CONF_COMMONt);

/****************************************************************************************/
/* 38.331 CI-ConfigurationPerServingCell-r16 IE */
typedef struct {
    uint8_t ServingCellId;                            /* Range ( 0..bb_nr5g_MAX_NB_SERVING_CELLS_1) */
    uint8_t PositionInDCI_r16;                        /* Range (0..bb_nr5g_CI_DCI_PAYLOADSIZE_1) */
    uint8_t PositionInDCI_ForSUL_r16;                 /* Range (0..bb_nr5g_CI_DCI_PAYLOADSIZE_1) */
    uint8_t CiPayloadSize_r16;                        /* Enum {n1, n2, n4, n5, n7, n8, n10, n14, n16, n20, n28, n32, n35, n42, n56, n112} */
    uint8_t UplinkCancelPriority_v1610;               /* Enum {enabled} */

/* timeFrequencyRegion_r16 */
    uint8_t TimeDurationForCI_r16;                   /*  Enum {n2, n4, n7, n14}    */
    uint8_t TimeGranularityForCI_r16;                /*  Enum {n1, n2, n4, n7, n14, n28} */
    uint8_t DeltaOffset_r16;                         /*  Range (0..2)*/
    uint16_t TimeFrequencyRegionForCI_r16;           /*  Range (0..37949) */
    uint16_t Pad;
} PREFIX(bb_nr5g_UP_CANCEL_CICONF_PER_SERV_CELL_R16t);

/* 38.331 UplinkCancellation-r16 IE */
typedef struct {
   uint16_t CiRNTI_r16;
   uint8_t DciPayloadSizeForCI_r16;
   uint8_t NbCiConfigPerServingCell_r16;

   PREFIX(bb_nr5g_UP_CANCEL_CICONF_PER_SERV_CELL_R16t) CiConfigPerServingCell_r16[bb_nr5g_MAX_NB_SERVING_CELLS];
} PREFIX(bb_nr5g_UPLINK_CANCELt);
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
    VFIELD(PREFIX(bb_nr5g_DOWNLINK_PREEMPTIONt), DownlinkPreemption); /*Configuration of downlink preemtption indications to be monitored in this cell*/
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_TPC_PUSCH_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_PUSCH_TPC_CFGt), TpcPusch); /* Enable and configure reception of group TPC commands for PUSCH*/
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_TPC_PUCCH_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_PUCCH_TPC_CFGt), TpcPucch); /* Enable and configure reception of group TPC commands for PUCCH*/
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_TPC_SRS_PRESENT   0x0008
    VFIELD(PREFIX(bb_nr5g_SRS_TPC_CFGt), TpcSrs); /* Enable and configure reception of group TPC commands for SRS*/
    AFIELD(PREFIX(bb_nr5g_CTRL_RES_SETt), DedCtrlResSetsToAdd, bb_nr5g_DED_CTRL_RES_SET_SIZE); /* A dynamic list of dedicated control resource sets to add.*/
    AFIELD(PREFIX(bb_nr5g_SEARCH_SPACEt), DedSearchSpacesToAdd, bb_nr5g_DED_SEARCH_SPACE_SIZE);/* A dynamic list of dedicated search space to add.*/
    AFIELD(uint32_t, DedSearchSpacesIdToDel, bb_nr5g_DED_SEARCH_SPACE_SIZE); /* A dynamic list of dedicated search space identifier to delete.*/
} PREFIX(bb_nr5g_PDCCH_CONF_DEDICATEDt);

/****************************************************************************************/
/* The following structures bb_nr5g_PDSCH_PRBBUNDLTYPESTATICt and bb_nr5g_PDSCH_PRBBUNDLTYPEDYNAMICt are not aligned
to 32 bit because they are used in a union of bb_nr5g_PDSCH_CONF_DEDICATEDt */
typedef struct {
    uint8_t BundSize ;  /* Enum [n4, wideband]; Default value is 0xFF */
} PREFIX(bb_nr5g_PDSCH_PRBBUNDLTYPESTATICt);

typedef struct {
    uint8_t BundSizeSet1;  /* Enum [n4, wideband, n2-wideband, n4-wideband]; Default value is 0xFF */
    uint8_t BundSizeSet2;  /* Enum [n4, wideband]; Default value is 0xFF */
} PREFIX(bb_nr5g_PDSCH_PRBBUNDLTYPEDYNAMICt);

/* FDM-TDM-r16 */
typedef struct {
    uint8_t RepetitionScheme_r16;               /* enum {fdmSchemeA, fdmSchemeB,tdmSchemeA } */
    uint8_t StartingSymbolOffsetK_r16;          /* Range (0..7) */
    uint16_t Spare;
} PREFIX(bb_nr5g_FDM_TDMt);

/* SlotBased-r16 */
typedef struct {
    uint8_t TciMapping_r16;                     /* enum {cyclicMapping, sequenticalMapping} */
    uint8_t SeqOffsetforRV_r16;                 /* Range (1..3) */
    uint16_t Spare;
} PREFIX(bb_nr5g_SLOT_BASEDt);

/* RepetitionSchemeConfig-r16 */
typedef struct {
    uint32_t FieldMask;

#define bb_nr5g_STRUCT_FDM_TDM_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_FDM_TDMt), FdmTDM);

#define bb_nr5g_STRUCT_SLOT_BASED_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_SLOT_BASEDt), SlotBased);
} PREFIX(bb_nr5g_REPETITION_SCHEME_CONFIG_R16t);

/* PTRS_DownlinkConfig*/
typedef struct {
   uint32_t MaxNrofPorts_r16;                           /* enum {n1, n2} */
   uint32_t ResourceElementOffset;                      /* Enum { offset01, offset10, offset11 } */

   uint8_t EpreRatio;
   uint8_t NbFrequencyDensity;
   uint8_t NbTimeDensity;
   uint8_t TimeDensity[3];                     /* SEQUENCE (SIZE (3)) OF INTEGER (0..29) */
   uint8_t Pad[2];
  
   uint16_t FrequencyDensity[2];               /* SEQUENCE (SIZE (2)) OF INTEGER (1..276) */
} PREFIX(bb_nr5g_PTRS_DOWNLINK_CONFIGt);

/* PDSCH-TimeDomainResourceAllocation-r16 */
typedef struct {
   uint8_t K0_r16;                          /*  Range (0..32)     */
   uint8_t MappingType_r16;                 /*  enum  {typeA, typeB} */
   uint8_t StartSymbAndLen_r16;             /*  Range (0..127)    */
   uint8_t RepetitionNumber_r16;            /* enum  {n2, n3, n4, n5, n6, n7, n8, n16} */
} PREFIX(bb_nr5g_PDSCH_TIME_DOMAIN_RES_ALLOCATION_R16t);

/* */
typedef struct {
    uint32_t FieldMask;

    uint8_t MaxMIMOLayers_r16;                      /* Range (1..8)                       */
    uint8_t AntennaPortsFieldPresenceDCI12_r16;     /* Enum {enabled}                       */
    uint8_t DmrsSequenceInitializationDCI12_r16;    /* Enum {enabled}                       */
    uint8_t HarqProcessNumberSizeDCI12_r16;         /* Range (0..4)                       */
    uint8_t McsTableDCI12_r16;                      /* Enum {qam256, qam64LowSE}      */
    uint8_t NumberOfBitsForRVDCI12_r16;             /* Range (0..2)                       */

    uint8_t PriorityIndicatorDCI12_r16;                         /* Enum {enabled}               */
    uint8_t ResourceAllocationType1GranularityDCI12_r16;        /* Enum {n2,n4,n8,n16}          */
    uint8_t VrbToPRBInterleaverDCI12_r16;                       /* Enum {n2, n4}                */
    uint8_t ReferenceOfSLIVDCI12_r16;                           /* Enum {enabled}               */
    uint8_t ResourceAllocationDCI12_r16;                        /* Enum { resourceAllocationType0, resourceAllocationType1, dynamicSwitch}  */

    uint8_t PriorityIndicatorDCI11_r16;                         /* Enum {enabled}               */
    uint16_t DataScramblingIdentityPDSCH2_r16;                  /* Range (0..1023)                  */

    uint8_t PrbBundlTypeDCI12IsValid;                           /* This field assumes a value defined as bb_nr5g_PDSCH_CONF_DED_BUNDLING_***
                                                                in order to read in good way the associated parameters in SearchSpaceType.
                                                                If this field is set to default value SearchSpaceType is neither read or used */
    union {
        PREFIX(bb_nr5g_PDSCH_PRBBUNDLTYPESTATICt) BundTypeSize;
        PREFIX(bb_nr5g_PDSCH_PRBBUNDLTYPEDYNAMICt) BundTypeDynamic;
    } PrbBundlTypeDCI12_r16; /* Indicates the PRB bundle type and bundle size(s).*/

    uint8_t NbRateMatchPatternGroup1DCI12;  /* Gives the number of valid elements in RateMatchPatternGroup1 vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternGroup2DCI12;  /* Gives the number of valid elements in RateMatchPatternGroup2 vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/

    uint8_t NbMinimumSchedulingOffsetK0_r16;
    uint8_t NbAperiodicZpCsiRSResSetsToAddDCI12_r16;
    uint8_t NbAperiodicZpCsiRSResSetsToDelDCI12_r16;
    uint8_t NbPdschTimeDomainAllocationDCI12_r16;
    uint8_t NbPdschTimeDomainAllocation_r16;
    uint8_t RateMatchPatternGroup1DCI12_r16[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS];    /* Bit 0..6: IDs of a first group of RateMatchPatterns defined in the RateMatchPatternDed.
                                                                                             Range 1... bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0
                                                                                             Bit 7: 0 means cellLevel, 1 means BWP level*/
    uint8_t RateMatchPatternGroup2DCI12_r16[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS]; /* Bit 0..6: IDs of a first group of RateMatchPatterns defined in the RateMatchPatternDed.
                                                                                          Range 1... bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0
                                                                                          Bit 7: 0 means cellLevel, 1 means BWP level*/
    uint8_t MinimumSchedulingOffsetK0_r16[2];

#define bb_nr5g_STRUCT_DMRS_DOWNLINK_PDSCH_MAPPING_TYPEA_DCI_1_2_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_DMRS_DOWNLINK_CFGt), DmrsDownlinkForPDSCHMappingTypeADCI12_r16);
#define bb_nr5g_STRUCT_DMRS_DOWNLINK_PDSCH_MAPPING_TYPEB_DCI_1_2_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_DMRS_DOWNLINK_CFGt), DmrsDownlinkForPDSCHMappingTypeBDCI12_r16);

#define bb_nr5g_STRUCT_REPETITION_SCHEME_CONFIG_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_REPETITION_SCHEME_CONFIG_R16t), RepetitionSchemeConfig_r16);

    AFIELD(PREFIX(bb_nr5g_ZP_CSI_RS_RES_SETt), AperiodicZpCsiRSResSetsToAddDCI12_r16, bb_nr5g_MAX_NB_ZP_CSI_RS_RES_SETS );
    AFIELD(uint8_t, AperiodicZpCsiRSResSetsToDelDCI12_r16, bb_nr5g_MAX_NB_ZP_CSI_RS_RES_SETS); /* Range (0..15) */
    AFIELD(PREFIX(bb_nr5g_PDSCH_TIME_DOMAIN_RES_ALLOCATION_R16t), PdschTimeDomainAllocationDCI12_r16, bb_nr5g_MAX_NB_DL_ALLOCATIONS);
    AFIELD(PREFIX(bb_nr5g_PDSCH_TIME_DOMAIN_RES_ALLOCATION_R16t), PdschTimeDomainAllocation_r16, bb_nr5g_MAX_NB_DL_ALLOCATIONS);

} PREFIX(bb_nr5g_PDSCH_CONF_DEDICATED_R16_IESt);

/* 38.331 PDSCH-Config IE: is used to configure the UE specific PDSCH parameters.*/
typedef struct {
    uint16_t DataScrIdentity; /* Identifer used to initalite data scrambling (c_init) for both PDSCH.
                                 Range 0...1023. Default value is 0xFFFF*/
    uint8_t VrbToPrbInterl;   /* Interleaving unit configurable between 2 and 4 PRBs
                                 Enum [n2, n4]; Default value is 0xFF*/
    uint8_t ResAllocType;   /*  Configuration of resource allocation type 0 and resource allocation type 1 for non-fallback DCI
                                Enum [resourceAllocationType0, resourceAllocationType1, dynamicSwitch]; Default value is 0xFF */

    uint8_t AggregationFactor;  /* Number of repetitions for data
                                  Enum [n2, n4, n8]; Default value is 0xFF */
    uint8_t RbgSize;            /* Selection between config 1 and config 2 for RBG size for PDSCH
                                  Enum [config1, config2]; Default value is 0xFF */
    uint8_t McsTable;           /* Indicates which MCS table the UE shall use for PDSCH
                                   Enum [qam64, qam256]; 15.3 38.331 Enum [qam256, qam64LowSE]; Default value is 0xFF */
    uint8_t MaxCwSchedByDCI;    /* Maximum number of code words that a single DCI may schedule.
                                   Enum [n1,n2]; Default value is 0xFF */

    uint8_t PrbBundlTypeIsValid;/* This field assumes a value defined as bb_nr5g_PDSCH_CONF_DED_BUNDLING_***
                                       in order to read in good way the associated parameters in SearchSpaceType.
                                       If this field is set to default value SearchSpaceType is neither read or used */
    union {
        PREFIX(bb_nr5g_PDSCH_PRBBUNDLTYPESTATICt) BundTypeS;
        PREFIX(bb_nr5g_PDSCH_PRBBUNDLTYPEDYNAMICt) BundTypeD;
    } PrbBundlType; /* Indicates the PRB bundle type and bundle size(s).*/

    uint8_t NbTciStatesToAdd;       /* Gives the number of valid elements in TciStatesToAdd vector: 1..bb_nr5g_MAX_NB_TCI_STATES; Default value is 0*/
    uint8_t NbTciStatesToDel;       /* Gives the number of valid elements in TciStatesToDel vector: 1..bb_nr5g_MAX_NB_TCI_STATES; Default value is 0*/
    uint8_t NbPdschAllocDed;  /* Gives the number of valid elements in PdschAllocDed vector: 1...bb_nr5g_MAX_NB_DL_ALLOCS; Default value is 0*/
    uint8_t NbRateMatchPatternDedToAdd;  /* Gives the number of valid elements in RateMatchPatternDedToAdd vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/

    uint8_t NbRateMatchPatternDedToDel;  /* Gives the number of valid elements in RateMatchPatternDedToDel vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternGroup1;  /* Gives the number of valid elements in RateMatchPatternGroup1 vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternGroup2;  /* Gives the number of valid elements in RateMatchPatternGroup2 vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbZpCsiRsResourceToAdd;/* Gives the number of valid elements in ZpCsiRsResourceToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES; Default value is 0*/

    uint8_t NbZpCsiRsResourceToDel;/* Gives the number of valid elements in ZpCsiRsResourceToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES; Default value is 0*/
    uint8_t NbAperiodicZpCsiRsResSetsToAdd;/* Gives the number of valid elements in AperiodicZpCsiRsResSetsToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/
    uint8_t NbAperiodicZpCsiRsResSetsToDel;/* Gives the number of valid elements in AperiodicZpCsiRsResSetsToDel vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/
    uint8_t NbSpZpCsiRsResSetsToAdd;/* Gives the number of valid elements in SpZpCsiRsResSetsToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/

    uint8_t NbSpZpCsiRsResSetsToDel;/* Gives the number of valid elements in SpZpCsiRsResSetsToDel vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_SETS; Default value is 0*/
    uint16_t Spare;

    /* Field mask according to bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_***_PRESENT to handle DmrsMappingTypeA and DmrsMappingTypeB*/
    uint32_t FieldMask;

    uint8_t RateMatchPatternGroup1[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS]; /* Bit 0..6: IDs of a first group of RateMatchPatterns defined in the RateMatchPatternDed.
                                                                                     Range 1... bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0
                                                                           Bit 7: 0 means cellLevel, 1 means BWP level*/
    uint8_t RateMatchPatternGroup2[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS];/*  Bit 0..6: IDs of a second group of RateMatchPatterns defined in the RateMatchPatternDed.
                                                                                    Range 1... bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0
                                                                           Bit 7: 0 means cellLevel, 1 means BWP level*/
#define bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_DMRS_TYPEA_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_DMRS_DOWNLINK_CFGt), DmrsMappingTypeA); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type A */
#define bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_DMRS_TYPEB_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_DMRS_DOWNLINK_CFGt), DmrsMappingTypeB); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type B */
#define bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_P_ZP_CSI_RS_RESOURCE_SET_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_ZP_CSI_RS_RES_SETt), PZpCsiRsResSet); /* A set of periodically occurring ZP-CSI-RS-Resources (the actual resources are defined in the ZpCsiRsResourceToAdd). 
                                                                   The network uses the ZP-CSI-RS-ResourceSetId=0 for this set. */
#define bb_nr5g_STRUCT_PDSCH_CONF_DEDICATED_R16_IES_PRESENT 0x0008
    VFIELD(PREFIX(bb_nr5g_PDSCH_CONF_DEDICATED_R16_IESt), PdschConfExtR16);

    AFIELD(PREFIX(bb_nr5g_TCI_STATEt), TciStatesToAdd, bb_nr5g_MAX_NB_TCI_STATES);    /* Dynamic list of Transmission Configuration Indicator (TCI) states for dynamically indicating (over DCI)
                                                                                 a transmission configuration to be added/modified.*/
    AFIELD(uint32_t, TciStatesToDel, bb_nr5g_MAX_NB_TCI_STATES); /* Dynamic list of Transmission Configuration Indicator (TCI) states to be deleted.*/
    AFIELD(PREFIX(bb_nr5g_PDSCH_TIMEDOMAINRESALLOCt), PdschAllocDed, bb_nr5g_MAX_NB_DL_ALLOCS); /* Dynamic list of time-domain configurations for timing of DL assignment to DL data.*/
    AFIELD(PREFIX(bb_nr5g_RATE_MATCH_PATTERNt), RateMatchPatternDedToAdd, bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS);  /* Dynamic list of Resources patterns which the UE should rate match PDSCH around to be added/modified.*/
    AFIELD(uint32_t, RateMatchPatternDedToDel, bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS); /* Dynamic list of Resources patterns to be deleted.*/
    AFIELD(PREFIX(bb_nr5g_ZP_CSI_RS_RESt), ZpCsiRsResourceToAdd, bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES); /* Dynamic list of Zero-Power (ZP) CSI-RS resources used for PDSCH rate-matching to be added/modified.*/
    AFIELD(uint32_t, ZpCsiRsResourceToDel, bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES); /* Dynamic list of Zero-Power (ZP) CSI-RS resource identifier used for PDSCH rate-matching to be deleted.*/
    AFIELD(PREFIX(bb_nr5g_ZP_CSI_RS_RES_SETt), AperiodicZpCsiRsResSetsToAdd, bb_nr5g_MAX_NB_ZP_CSI_RS_SETS); /* Dynamic list of sets to be added/modified. Each set contains a set-ID and the IDs of one or more ZP-CSI-RS-Resources.*/
    AFIELD(uint32_t, AperiodicZpCsiRsResSetsToDel, bb_nr5g_MAX_NB_ZP_CSI_RS_SETS); /* Dynamic list of set identifiers to be deleted.*/
    AFIELD(PREFIX(bb_nr5g_ZP_CSI_RS_RES_SETt), SpZpCsiRsResSetsToAdd, bb_nr5g_MAX_NB_ZP_CSI_RS_SETS); /* Dynamic list of sets to be added/modified. Each set contains a set-ID and the IDs of one or more ZP-CSI-RS-Resources.*/
    AFIELD(uint32_t, SpZpCsiRsResSetsToDel, bb_nr5g_MAX_NB_ZP_CSI_RS_SETS); /* Dynamic list of set identifiers to be deleted.*/
} PREFIX(bb_nr5g_PDSCH_CONF_DEDICATEDt);

/****************************************************************************************/
/* 38.331 SPS-Config IE is used to configure downlink semi-persistent transmission. TODO*/
typedef struct {
    uint8_t Periodicity; /* Periodicity for DL SPS
                            Enum [ms10, ms20, ms32, ms40, ms64, ms80, ms128, ms160, ms320, ms640]; Default value is 0xFF*/
    uint8_t NbHarqProcesses; /* Number of configured HARQ processes for SPS DL
                                Range 0...8; Default value is 0xFF*/
    uint8_t McsTable;       /* Indicates the MCS table the UE shall use for DL SPS. Enum[qam64LowSE]; Default value is 0xFF*/
    uint8_t N1PucchAn; /* HARQ resource for PUCCH for DL SPS. The network configures the resource 
                           either as format0 or format1. 
                           The actual PUCCH-Resource is configured in PUCCH-Config and referred to by its ID. */

    uint8_t Sps_ConfigIndex_r16; /* Range (0.. maxNrofSPS-Config-r16-1) (7); Default 0xFF */
    uint8_t Harq_ProcID_Offset_r16; /* Range (0..15); Default 0xFF */
    uint16_t PeriodicityExt_r16; /* Range (1..5120); Default 0xFF */
    uint8_t Harq_CodebookID_r16; /* Range (1..2); Default 0xFF */
    uint8_t Pdsch_AggregationFactor_r16; /* Enum[n1, n2, n4, n8]; Default 0xFF */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_SPS_CONF_DEDICATEDt);

/****************************************************************************************/
/* 38.331 RACH-ConfigGeneric IE: it is used to specify the cell specific random-access parameters
    both for regular random access as well as for beam failure recovery.*/
typedef struct {
    uint16_t PrachConfigIndex; /* PRACH configuration index. R15: Range 0...255; R16: Range (256..262 */
    uint8_t Msg1FDM;          /* The number of PRACH transmission occasions FDMed in one time instance
                                 Enum [one, two, four, eight]; Default value is 0xFF*/
    uint16_t Msg1FrequencyStart; /* Offset of lowest PRACH transmission occasion in frequency domain with respective to PRB 0.
                                    Default value is 0xFFFF; Range 0... bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1*/
    uint8_t  ZeroCorrZone;        /* N-CS configuration, see Table 6.3.3.1-3 in 38.211
                                     Default value is 0xFFFF; Range 0...15 */
    int16_t  PreambleRecTargetPwr; /* The target power level at the network receiver side
                                      (see 38.213, section 7.4, 38.321, section 5.1.2, 5.1.3)
                                      Default value is -1; Range -202...-60 */
} PREFIX(bb_nr5g_RACH_CONF_GENERICt);

/* RA-Prioritization IE */
typedef struct {
    uint8_t PowerRampingStepHighPriority;           /* dB0, dB2, dB4, dB6 */
    uint8_t ScalingFactorBI;                        /* {zero, dot25, dot5, dot75} */
    uint8_t  Spare[2];
} PREFIX(bb_nr5g_RA_PRIORITIZATIONt);

typedef struct {
    uint8_t RaPrioritizationForAI_r16;              /* BIT STRING (SIZE (2)) */
    uint8_t Pad[3];
    PREFIX(bb_nr5g_RA_PRIORITIZATIONt) RaPrioritization_r16;
} PREFIX(bb_nr5g_RA_PRIO_FOR_ACCESS_ID_R16t);

/* 38.331 RACH-ConfigCommon IE: it is used to specify the cell specific random-access parameters*/
typedef struct {
    uint32_t FieldMask;

    PREFIX(bb_nr5g_RACH_CONF_GENERICt) RachConfGeneric;
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
                                     Range[ 0...837]  if  PrachRootSeqIndexIsValid is L839
                                     Range[ 0...137]  if  PrachRootSeqIndexIsValid is L139
                                     Range[ 0...569]  if  PrachRootSeqIndexIsValid is L571
                                     Range[ 0...1149] if  PrachRootSeqIndexIsValid is L1151 */

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

    struct {
        uint8_t Ra_Msg3SizeGroupA;          /* Enum [b56,b144,b208,b256,b282,b480,b640,b800,b1000,b72,spare6,spare5,spare4,spare3,spare2,spare1]; Default/Reset is 0xFF */
        uint8_t MessagePowerOffsetGroupB;   /* Enum [minusinfinity, dB0, dB5, dB8, dB10, dB12, dB15, dB18];  Default/Reset is 0xFF */
        uint8_t NumberOfRA_PreamblesGroupA; /* Range 1..64; Default/Reset is 0xFF */
    } GroupBconfigured;                     /* Reset if ra_Msg3SizeGroupA is 0xFF */

    uint8_t Ra_ContentionResolutionTimer; /* Enum [sf8, sf16, sf24, sf32, sf40, sf48, sf56, sf64]; */
    uint8_t Pad;

#define bb_nr5g_STRUCT_RA_PRIO_FOR_ACCESS_IDENTITY_PRESENT 0x0001
    PREFIX(bb_nr5g_RA_PRIO_FOR_ACCESS_ID_R16t) RaPrioritizationForAccessIdentity_r16;
} PREFIX(bb_nr5g_RACH_CONF_COMMONt);

/* PUSCH-Allocation-r16 IE */
typedef struct {
    uint8_t MappingType_r16;                /* PUSCH mapping type. Enum [typeA, typeB]; Default value is 0xFF*/
    uint8_t StartSymbAndLen_r16;            /* Range (0..127); Default value is 0xFF*/
    uint8_t StartSymbol_r16;                /* Range (0..13); Default value is 0xFF*/
    uint8_t Length_r16;                     /* Range (1..14) Default value is 0xFF */
    uint8_t NumberOfRepetitions_r16;        /* Enum {n1, n2, n3, n4, n7, n8, n12, n16} */
    uint8_t Pad[3];
} PREFIX(bb_nr5g_PUSCH_ALLOCATION_R16t);

/* PUSCH-TimeDomainResourceAllocation-r16 IE */
typedef struct {
    uint8_t K2_r16;                         /* Range (0..32); Default value is 0xFF*/

    uint8_t NbPuschAllocation_r16;
    uint16_t Len;

    AFIELD(PREFIX(bb_nr5g_PUSCH_ALLOCATION_R16t), PuschAllocation_r16, 8);
} PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOC_R16t);

/* 38.331 PUSCH-ConfigCommon IE: it is used to configure the cell specific PUSCH parameters*/
typedef struct {
    uint8_t K2;     /*  Corresponds to L1 parameter 'K2' (see 38.214, section FFS_Section)
                        When the field is absent the UE applies the value 1 when PUSCH SCS is 15/30KHz;
                        2 when PUSCH SCS is 60KHz and 3 when PUSCH SCS is 120KHz.
                        Default value is 0xFF. Range 0...32  */
    uint8_t MappingType;    /* PUSCH mapping type.
                               Corresponds to L1 parameter 'Mapping-type' (see 38.214, section FFS_Section)
                               Enum [typeA, typeB]; Default value is 0xFF*/
    uint8_t StartSymbAndLen;  /* An index giving valid combinations of start symbol and length (jointly encoded) as start and length indicator 
                                Corresponds to L1 parameter 'Index-start-len' (see 38.214, section FFS_Section)
                                Range 0..127; Default value is 0xFFFF*/
    uint8_t Pad;
} PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt);

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
    PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt)  PuschTimeDomResAlloc[bb_nr5g_MAX_NB_UL_ALLOCS];
} PREFIX(bb_nr5g_PUSCH_CONF_COMMONt);

/* UCI-OnPUSCH-DCI-0-2-r16 IE*/
typedef struct {
    uint8_t ScalingDCI02;           /* Indicates a scaling factor to limit the number of resource elements assigned to UCI on PUSCH
                                    Enum [f0p5, f0p65, f0p8, f1]; Default/Invalid value is 0xFF*/

    uint8_t BetaOffsetsIsValid;     /* This field assumes a value defined as bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_***
                                       in order to read in good way the associated parameters in BetaOffsets.
                                       If this field is set to default value BetaOffsets is neither read or used */
    uint8_t NbBetaOffsets;          /* Gives the number of valid elements in BetaOffsets vector:
                                    Range: 1 if BetaOffsetsIsValid=bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_SEMISTATIC,
                                    2 if BetaOffsetsIsValid=bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_ONEBIT_DYNAMIC,
                                    4 if BetaOffsetsIsValid=bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_TWOBITS_DYNAMIC
                                    Default value is 0*/
    uint8_t Pad;
    PREFIX(bb_nr5g_BETAOFFSETSt) BetaOffsets[4];
} PREFIX(bb_nr5g_UCI_ON_PUSCH_DCI02_R16t);

/* PUSCH-PathlossReferenceRS-r16 */
typedef struct {
    uint8_t PuschPathlossReferenceRSId_r16; /* Range(4..63) */
    uint8_t ReferenceSignalR16IsValid;           /* This field assumes a value defined as bb_nr5g_PATHLOSS_REFERENCE_SIGNAL_***, bb_nr5g_PATHLOSS_REFERENCE_SIGNAL_DEFAULT is the default*/
    union {
        uint8_t SsbIndex_r16;                    /* Range (0..maxNrofSSBs-1=63) */
        uint8_t CsiRSIndex_r16;                  /* Range (0..maxNrofNZP-CSI-RS-Resources-1=191) */
    } ReferenceSignal_r16;
    uint8_t Spare;
} PREFIX(bb_nr5g_PUSCH_PATHLOSS_REF_RS_R16t);

/* P0-PUSCH-Set-r16 */
typedef struct {
    uint8_t P0PuschSetId_r16;                  /*   Range (0..15)  */
    uint8_t NbP0List_r16;
    uint16_t Spare;

    int8_t P0List_r16[bb_nr5g_MAX_NB_P0_PUSCH_SET_R16];
} PREFIX(bb_nr5g_P0_PUSCH_SET_R16t);

/* PUSCH-PowerControl-v1610 */
typedef struct  {
    uint16_t Len;
    uint8_t OlpcParameterSetDCI01_r16;      /*  Range (1..2)  */
    uint8_t OlpcParameterSetDCI02_r16;      /*  Range (1..2)  */
    uint8_t Pad;

    uint8_t NbPathlossReferenceRSToAddModList2_r16;     /* Range(1..60); Default value is 0  */
    uint8_t NbPathlossReferenceRSToReleaseList2_r16;    /* Range(4..63); Default value is 0  */
    uint8_t NbP0PuschSetList_r16;                       /* Range(1..16); Default value is 0  */

    AFIELD(PREFIX(bb_nr5g_PUSCH_PATHLOSS_REF_RS_R16t), PathlossReferenceRSToAddModList2_r16, bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REF_RSs_DIFF);
    AFIELD(uint8_t, PathlossReferenceRSToReleaseList2_r16, bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REF_RSs_DIFF);                         /* Range(4..63) */
    AFIELD(PREFIX(bb_nr5g_P0_PUSCH_SET_R16t), P0PuschSetList_r16, bb_nr5g_MAX_NB_SRI_PUSCH_MAPPINGS);
} PREFIX(bb_nr5g_PUSCH_POWER_CONTROL_r16);

/* InvalidSymbolPattern-r16 IE*/
typedef struct {
    uint8_t  SymbInResBlockIsValid; /* This field assumes a value defined as bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_SYMBRES_***
                                       in order to read in good way the associated parameter SymbInResBlock.
                                       If this field is set to default value SymbInResBlock is neither read or used */
    uint8_t  PeriodicityAndPatternIsValid; /* This field assumes a value defined as bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_***
                                       in order to read in good way the associated parameter PeriodicityAndPattern.
                                       If this field is set to default value PeriodicityAndPattern is neither read or used */

    uint16_t Spare;
    uint32_t SymbInResBlock;
    uint64_t PeriodicityAndPattern; /* A time domain repetition pattern. Bitmap size to be considered as valid is
                                       defined by means of PeriodicityAndPatternIsValid field*/

} PREFIX(bb_nr5g_INVALID_SYMB_PATTERN_R16t);

/* 38.331 PUSCH-Config: it is used to configure the UE specific PUSCH parameters applicable to a particular BWP*/
typedef struct {
    uint16_t DataScrIdentity; /* Identifer used to initalite data scrambling (c_init) for both PUSCH.
                                 Range 0...1023. Default value is 0xFFFF*/
    uint8_t TxConfig; /*Whether UE uses codebook based or non-codebook based transmission
                            Enum [codebook, nonCodebook]; Default value is 0xFF */
    uint8_t ResAllocType;   /*  Configuration of resource allocation type 0 and resource allocation type 1 for non-fallback DCI
                                Enum [resourceAllocationType0, resourceAllocationType1, dynamicSwitch]; Default value is 0xFF */
    uint8_t AggregationFactor;  /* Number of repetitions for data
                                  Enum [n2, n4, n8]; Default value is 0xFF */
    uint8_t McsTable;           /* Indicates which MCS table the UE shall use for PUSCH
                                   Enum [qam256]; 15.3 38.331 Enum [qam256, qam64LowSE]; Default value is 0xFF */
    uint8_t McsTableTransfPrecoder; /* Indicates which MCS table the UE shall use for PUSCH with transform precoding
                                   Enum [qam256]; 15.3 38.331 Enum [qam256, qam64LowSE]; Default value is 0xFF */
    uint8_t TransfPrecoder; /* The UE specific selection of transformer precoder for PUSCH.
                                   Enum [enabled, disabled]; Default value is 0xFF */
    uint8_t CodebookSubset;     /* Subset of PMIs addressed by TPMI, where PMIs are those supported by UEs with maximum coherence capabilities
                                  Enum [fullyAndPartialAndNonCoherent, partialAndNonCoherent, nonCoherent]; Default value is 0xFF */
    uint8_t MaxRank; /* Subset of PMIs addressed by TRIs from 1 to ULmaxRank.Range 1..4; Default value is 0xFF */
    uint8_t RbgSize;            /* Selection between config 1 and config 2 for RBG size for PUSCH
                                  Enum [config2]; Default value is 0xFF */
    uint8_t TpPi2Qpsk_VrbToPrbInterl;   /* bit 0...3 : Interleaving unit configurable between 2 and 4 PRBs Enum [n2, n4]; Invalid value is 0xF
                                           bit 4..7:  Enables pi/2-BPSK modulation with transform precoding if the field is present and disables it otherwise. 
                                           Enum[enabled]; Invalid value is 0xF */
    uint8_t FreqHop;  /* Configured one of two supported frequency hopping mode. Enum [mode1, mode2]; Default value is 0xFF */

    uint8_t HarqProcessNumberSizeDCI02_r16;              /*  Range (0..4)   */
    uint8_t DmrsSeqInitDCI02_r16;                        /*  Enum {enabled} */
    uint8_t NumberOfBitsForRVDCI02_r16;                  /*  Range (0..2)  */
    uint8_t AntennaPortsFieldPresenceDCI02_r16;          /*  Enum {enabled} */
    
    uint8_t FrequencyHoppingDCI02IsValid;

    union {
        uint8_t PuschRepTypeA;                                      /*      Enum {intraSlot, interSlot}  */
        uint8_t PuschRepTypeB;                                      /*      Enum {interRepetition, interSlot}  */
    } FrequencyHoppingDCI02_r16;

    uint8_t CodebookSubsetDCI02_r16;                        /*  Enum {fullyAndPartialAndNonCoherent, partialAndNonCoherent,nonCoherent} */
    uint8_t InvalidSymbolPatternIndicatorDCI02_r16;         /*  Enum {enabled}                       */
    uint8_t MaxRankDCIDCI02_r16;                            /*      Range (1..4)   */

    uint8_t McsTableDCI02_r16;                              /*       Enum {qam256, qam64LowSE}  */
    uint8_t McsTableTransformPrecoderDCI02_r16;             /*        Enum {qam256, qam64LowSE} */
    uint8_t PriorityIndicatorDCI02_r16;                     /*         Enum {enabled}   */
    uint8_t PuschRepTypeIndicatorDCI02_r16;                 /*       Enum { pusch-RepTypeA, pusch-RepTypeB}  */
    uint8_t PuschRepTypeIndicatorDCI01_r16;                  /*  Enum { pusch-RepTypeA, pusch-RepTypeB}      */
    uint8_t ResourceAllocationDCI02_r16;                    /*         Enum { resourceAllocationType0, resPUSCH-ConfigourceAllocationType1, dynamicSwitch} */

    uint8_t ResourceAllocationType1GranularityDCI02_r16;    /*       Enum { n2,n4,n8,n16 }  */
    uint8_t InvalidSymbolPatternIndicatorDCI01_r16;          /*  Enum {enabled}   */
    uint8_t PriorityIndicatorDCI01_r16;                      /*  Enum {enabled}   */

    uint8_t FrequencyHoppingDCI01_r16;                       /*  Enum {interRepetition, interSlot}         */

    uint8_t NbUciOnPUSCHListDCI01_r16;                       /* Default value 0 */
    uint8_t NbUciOnPUSCHListDCI02_r16;                      /* Default value 0 */
    uint8_t NbMinSchedOffsetK2_r16;                         /* Gives the number of valid elements in PuschAllocDed vector: 1...bb_nr5g_MAX_NB_UL_ALLOCS; Default value is 0 */
    uint8_t NbFrequencyHoppingDCI02Lists_r16;         
    uint8_t NbPuschTimeDomainAlloListDCI01_r16;              /* Default value 0 */
    uint8_t NbPuschTimeDomainAlloListDCI02_r16;              /* Default value 0 */

    uint8_t UlFullPowerTransmission_r16;                        /* Enum {fullpower, fullpowerMode1, fullpoweMode2}    */
    uint8_t NumberOfInvalidSymbolsForDLULSwitching_r16;        /* Range (1..4) */
    uint8_t NbPuschTimeDomainAllocListForMultiPUSCH_r16;

    uint8_t NbFreqHopOffset;  /* Gives the number of valid elements in FreqHopOffset vector: 1...4; Default value is 0 */
    uint8_t NbPuschAllocDed;  /* Gives the number of valid elements in PuschAllocDed vector: 1...bb_nr5g_MAX_NB_UL_ALLOCS; Default value is 0*/
    /* Field mask according to bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_***_PRESENT to handle DmrsMappingTypeA,DmrsMappingTypeB, PuschPwCtrl and UciOnPusch*/
    uint32_t FieldMask;
    uint16_t FreqHopOffset[4];   /* Set of frequency hopping offsets used when frequency hopping is enabled for granted transmission (not msg3) and type 2
                                    Element range is 1....(bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1). Static list */
    uint8_t Pad;

#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_DMRS_TYPEA_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_DMRS_UPLINK_CFGt), DmrsMappingTypeA); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type A */
#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_DMRS_TYPEB_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_DMRS_UPLINK_CFGt), DmrsMappingTypeB); /* DMRS configuration for PDSCH transmissions using PDSCH mapping type B */
#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_PW_CTRL_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_PUSCH_POWERCONTROLt), PuschPwCtrl);
#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_UCI_PRESENT   0x0008
    VFIELD(PREFIX(bb_nr5g_UCI_ON_PUSCHt), UciOnPusch);

#define bb_nr5g_STRUCT_PUSCH_CONF_DEDICATED_PW_CTRL_R16_PRESENT   0x0010
    VFIELD(PREFIX(bb_nr5g_PUSCH_POWER_CONTROL_r16), PuschPwCtrl_r16);
#define bb_nr5g_STRUCT_INVALID_SYMB_PATTERN_r16_PRESENT   0x0020
    VFIELD(PREFIX(bb_nr5g_INVALID_SYMB_PATTERN_R16t), InvalidSymbolPattern_r16);

    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOCt), PuschAllocDed, bb_nr5g_MAX_NB_UL_ALLOCS); /* Dynamic list of time domain allocations for timing of UL assignment to UL data*/
    AFIELD(uint8_t, MinSchedOffsetK2_r16, bb_nr5g_MAX_NB_MIN_SCHED_OFFSET_VALUES_R16);
    AFIELD(uint16_t, FrequencyHoppingDCI02Lists_r16, 4);   /* 1..274 */
    AFIELD(PREFIX(bb_nr5g_UCI_ON_PUSCH_DCI02_R16t), UciOnPUSCHListDCI02_r16, bb_nr5g_UCI_ONPUSCH_DCI_0_2_R16);
    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOC_R16t), PuschTimeDomainAlloListDCI02_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);    
    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOC_R16t), PuschTimeDomainAlloListDCI01_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);
    AFIELD(PREFIX(bb_nr5g_UCI_ON_PUSCHt), UciOnPUSCHListDCI01_r16, 2);
    AFIELD(PREFIX(bb_nr5g_PUSCH_TIMEDOMAINRESALLOC_R16t), PuschTimeDomainAllocListForMultiPUSCH_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);
} PREFIX(bb_nr5g_PUSCH_CONF_DEDICATEDt);

typedef struct {
    uint16_t TimeDomOffset;         /* Offset related to SFN=0; Range 0..5119; Default value 0xFF */
    uint8_t TimeDomAlloc;           /* Indicates a combination of start symbol and length and PUSCH mapping type
                                        Range 0..15; Default value 0xFF */
    uint32_t FreqDomAlloc;          /* Indicates the frequency domain resource allocation; Size 18 bit
                                        Default value 0xFF */
    uint8_t AntennaPort;            /* Indicates the antenna port(s) to be used for this configuration;
                                        the maximum bitwidth is 5 (0..31); default value 0xFF */
    uint8_t DmrsSeqInit;            /* The network configures this field if transformPrecoder is disabled.
                                        Otherwise the field is absent (0XFF) */
    uint8_t PrecodAndNbLayers;      /* Range 0..63; Default value 0xFF */
    uint8_t SrsResourceInd;         /* Indicates the SRS resource to be used. Range 0..15; Default value 0xFF */
    uint8_t McsAndTbs;              /* The modulation order, target code rate and TB size. The NW does not configure
                                        the values 28~31 in this version of the specification. Default value 0xFF */
    uint16_t FreqHopOffset;         /* Frequency hopping offset used when frequency hopping is enabled; Default 0xFF
                                        Element range is 1....(bb_nr5g_MAX_NB_PHYS_RES_BLOCKS-1) */
    uint8_t PathlossRefIdx;         /* Range 0 ...(bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS-1); Default/Invalid value is 0xFF */ 

    uint8_t PuschRepTypeIndicator_r16;              /*   Enum {pusch-RepTypeA=0,pusch-RepTypeB=1}     */
    uint8_t FrequencyHoppingPUSCHRepTypeB_r16;      /*   Enum {interRepetition=0, interSlot=1}        */
    uint8_t TimeReferenceSFN_r16;                   /*   Enum {sfn512=0}  */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_RRC_CONFIGURED_UL_GRANTt);

/* 38.331 NR-ConfiguredGrantConfig IE: it is used to configure uplink transmission without dynamic grant */
typedef struct {
    uint32_t FieldMask; 
    uint16_t Len;
    uint8_t FreqHop;                /* Configured one of two supported frequency hopping mode. Enum [mode1, mode2]; Default value is 0xFF */
    uint8_t McsTable;               /* Indicates which MCS table the UE shall use for PUSCH
                                        Enum [qam256]; 15.3 38.331 Enum [qam256, qam64LowSE]; Default value is 0xFF */
    uint8_t McsTableTransfPrecoder; /* Indicates which MCS table the UE shall use for PUSCH with transform precoding
                                        Enum [qam256]; 15.3 38.331 Enum [qam256, qam64LowSE]; Default value is 0xFF */
    uint8_t ResAllocType;           /* Configuration of resource allocation type 0 and resource allocation type 1 for non-fallback DCI
                                        Enum [resourceAllocationType0, resourceAllocationType1, dynamicSwitch]; Default value is 0xFF */
    uint8_t RbgSize;                /* Selection between config 1 and config 2 for RBG size for PDSCH
                                        Enum [config1, config2]; Default value is 0xFF */
    uint8_t PwrCtrlLoop;            /* Closed control loop to apply; Enum [n0, n1]; Default value is 0xFF */
    uint8_t P0Alpha;                /* Index of the p0-alpha set determining the power control for this CSI report
                                        transmission.Range 0...(bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS-1).
                                        Default/Invalid value 0xff*/
    uint8_t TransfPrecoder;         /* The UE specific selection of transformer precoder for PUSCH.
                                        Enum [enabled, disabled]; Default value is 0xFF */
    uint8_t NbHarqProcesses;        /* The number of HARQ processes configured. Range 1..16; Default value 0xFF */
    uint8_t RepK;                   /* The number of repetitions of K. Enum [n1, n2, n4, n8]; Default value 0xFF */
    uint8_t RepKRV;                 /* The redundancy version (RV) sequence to use if repK is set to n2, n4 or n8.
                                        Otherwise, the field is absent. Default value 0xFF */
    uint8_t Periodicity;            /* Enum [sym2, sym7, sym1x14, sym2x14, sym4x14, sym5x14, sym8x14, sym10x14, sym16x14, sym20x14,
                                        sym32x14, sym40x14, sym64x14, sym80x14, sym128x14, sym160x14, sym256x14, sym320x14, sym512x14,
                                        sym640x14, sym1024x14, sym1280x14, sym2560x14, sym5120x14, sym6, sym1x12, sym2x12, sym4x12,
                                        sym5x12, sym8x12, sym10x12, sym16x12, sym20x12, sym32x12, sym40x12, sym64x12, sym80x12, sym128x12,
                                        sym160x12, sym256x12, sym320x12, sym512x12, sym640x12, sym1280x12, sym2560x12]; Default value is 0xFF */
    uint8_t Timer;                  /* Indicates the initial value of the configured grant timer in multiples of periodicity.
                                       Range 1..64; Default value 0xFF */

    uint8_t CgNrofPUSCHInSlot_r16;  /* Range 1..7; Default value 0xFF */
    uint8_t CgNrofSlots_r16;        /* Range 1..40; Default value 0xFF */
    uint8_t CgUCIMultiplexing;      /* Enum [enabled];  Default value 0xFF */
    uint8_t BetaOffsetCG_UCI_r16;   /* Range 0..31; Default value 0xFF */
    uint8_t HarqProcIDOffset_r16;   /* Range 0..15; Default value 0xFF */
    uint8_t HarqProcIDOffset2_r16;  /* Range 0..15; Default value 0xFF */

    uint8_t ConfigGrantConfigIndex_r16; /* Range (0.. maxNrofConfiguredGrantConfig-r16-1=11) */
    uint8_t ConfigGrantConfigIndexMAC_r16; /* Range (0.. maxNrofConfiguredGrantConfigMAC-r16-1=31) */

    uint16_t PeriodicityExt_r16;          /* Range (1.. 5120 */

    uint8_t StartingFromRV0_r16;      /* Enum [on, off];  Default value 0xFF */
    uint8_t Phy_PriorityIndex_r16;    /* Enum [p0, p1];   Default value 0xFF */
    uint8_t AutonomousTx_r16;         /* Enum [enabled];  Default value 0xFF */

    PREFIX(bb_nr5g_DMRS_UPLINK_CFGt) DmrsConfiguration;
#define bb_nr5g_STRUCT_CONFIGURED_GRANT_CONF_UCI_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_UCI_ON_PUSCHt), UciOnPusch);
#define bb_nr5g_STRUCT_CONFIGURED_GRANT_CONF_UL_GRANT_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_RRC_CONFIGURED_UL_GRANTt), RrcConfUlGrant);
} PREFIX(bb_nr5g_CONFIGURED_GRANT_CONFt);

/* PUCCH-ResourceExt-r16 IE */
typedef struct {
   uint8_t RbSetIndex;      /* Range (0..4) */
   uint8_t Interlace0IsValid; /* This field assumes a value defined as bb_nr5g_INTERLACE0_***
                                 in order to read in good way the associated parameters in Interlace0. */
   union {
        uint8_t Scs15;      /* Range (0..9) */
        uint8_t Scs30;      /* Range (0..4) */
   } Interlace0;

   uint8_t Pad;
} PREFIX(bb_nr5g_INTERLACE_ALLOCATION_R16t);

typedef struct {
    uint32_t FieldMask;
    uint16_t Len;
    uint16_t Spare;
    uint8_t FormatExtIsValid; /* This field assumes a value defined as bb_nr5g_PUCCH_RESOURCE_EXT_***
                                 in order to read in good way the associated parameters in FormatExt_v1610.
                                 If this field is set to default value FormatExt_v1610 is neither read or used.
                                 If this field is set to bb_nr5g_PUCCH_RESOURCE_EXT_OCC value OccLength_v1610 and OccIndex_v1610 both are read. */

    uint8_t Interlace1_v1610;                          /* Range (0..9) */
    uint8_t OccLength_v1610;                           /* Enum {n2,n4} */
    uint8_t OccIndex_v1610;                            /* Enum {n0,n1,n2,n3} */
    
#define bb_nr5g_INTERLACE_ALLOCATION_r16_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_INTERLACE_ALLOCATION_R16t), InterlaceAllocation_r16);
} PREFIX(bb_nr5g_PUCCH_RESOURCE_EXT_R16t);

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
                               Default value is 0xFFFF; Bitmap size (10)*/
    int16_t P0Nom;          /* Power control parameter P0 for PUCCH transmissions. Value in dBm.
                               Range [-202..24]*/
    uint8_t Spare[2];
} PREFIX(bb_nr5g_PUCCH_CONF_COMMONt);

typedef struct {
    uint8_t Pucch_SpatialRelationInfoId_v1610; /* Range (maxNrofSpatialRelationInfos-plus-1..maxNrofSpatialRelationInfos-r16) (9..64); Default 0xFF */
    uint8_t Pucch_PathlossReferenceRS_Id_v1610; /* Range (maxNrofPUCCH-PathlossReferenceRSs..maxNrofPUCCH-PathlossReferenceRSs-1-r16) (4..63); Default 0xFF */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_PUCCH_SPATIALRELATIONINFO_EXTt);

/* PUCCH-ResourceGroup-r16 */
typedef struct {
    uint8_t Pucch_ResourceGroupId_r16;
    uint8_t NbResourcePerGroupList_r16;
    uint16_t Len;
    AFIELD(uint8_t, ResourcePerGroupList_r16, 128);
} PREFIX(bb_nr5g_PUCCH_RESOURCE_GROUP_R16t);

typedef struct {
    uint8_t Sps_PUCCH_AN_ResourceID_r16;
    uint16_t MaxPayloadSize_r16; /* Optional; Default value 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_SPS_PUCCH_ANt);

typedef struct {
    uint8_t NbResourceToAdd; /* 1..maxNrofPUCCH-Resources (128); Default 0 */
    uint8_t NbSpatialRelationInfoToAdd;
    uint8_t NbSpatialRelationInfoToDel;
    uint8_t NbSpatialRelationInfoToAddExt;
    uint8_t NbSpatialRelationInfoToDelExt;
    uint8_t NbResourceGroupToAdd;
    uint8_t NbResourceGroupToDel;
    uint8_t NbDl_DataToUL_ACK_DCI_1_2_r16;
    uint8_t NbDl_DataToUL_ACK_r16;
    uint8_t NbUl_AccessConfigListDCI_1_1_r16;
    uint8_t NbSps_PUCCH_AN_r16;
    uint8_t NbSchedulingRequestResourceToAdd;
    uint8_t SubslotLengthForPUCCHIsValid; /* To indicate which value of the following is valid; Default is 0xFF */
    uint8_t SubslotLengthForPUCCH_normalCP; /* Enum[n2, n7] */
    uint8_t SubslotLengthForPUCCH_extendedCP; /* Enum[n2, n6] */ 
    uint8_t NumberOfBitsForPUCCH_ResourceIndicatorDCI_1_2_r16;
    uint8_t Dmrs_UplinkTransformPrecodingPUCCH_r16; /* 0xFF for disabled or absent */
    uint8_t Pad[3];
    AFIELD(PREFIX(bb_nr5g_PUCCH_RESOURCE_EXT_R16t), ResourceToAdd, bb_nr5g_MAX_PUCCH_RESOURCES);
    AFIELD(int8_t, Dl_DataToUL_ACK_r16, 8);
    AFIELD(uint8_t, Ul_AccessConfigListDCI_1_1_r16, 16);
    AFIELD(uint8_t, Dl_DataToUL_ACK_DCI_1_2_r16, 8);
    AFIELD(PREFIX(bb_nr5g_SPATIAL_RELATION_INFOt), SpatialRelationInfoToAdd, bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS_DIFF);
    AFIELD(uint8_t, SpatialRelationInfoToDel, bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS_DIFF);
    AFIELD(PREFIX(bb_nr5g_PUCCH_SPATIALRELATIONINFO_EXTt), SpatialRelationInfoToAddExt, bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS_R16);
    AFIELD(uint8_t, SpatialRelationInfoToDelExt, bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS_R16);
    AFIELD(PREFIX(bb_nr5g_PUCCH_RESOURCE_GROUP_R16t), ResourceGroupToAdd, bb_nrg5_MAX_PUCCH_RESOURCE_GROUPS);
    AFIELD(uint8_t, ResourceGroupToDel, bb_nrg5_MAX_PUCCH_RESOURCE_GROUPS);
    AFIELD(PREFIX(bb_nr5g_SPS_PUCCH_ANt), Sps_PUCCH_AN_r16, 4);
    AFIELD(uint8_t, SchedulingRequestResourceToAdd, bb_nr5g_MAX_SR_RESOURCES); /* Enum[p0, p1] */
} PREFIX(bb_nr5g_PUCCH_CONF_DEDICATED_R16_IESt);

/* 38.331 PUCCH-Config IE: it is used to configure UE specific PUCCH parameters (per BWP) */
typedef struct {
    uint16_t Len;
    uint16_t Spare;
    uint8_t NbResourceDedToAdd;  /* Gives the number of valid elements in ResourceDedToAdd vector: 1...bb_nr5g_MAX_PUCCH_RESOURCES; Default value is 0*/
    uint8_t NbResourceDedToDel;  /* Gives the number of valid elements in ResourceDedToDel vector: 1...bb_nr5g_MAX_PUCCH_RESOURCES; Default value is 0*/
    uint8_t NbResourceSetDedToAdd;  /* Gives the number of valid elements in ResourceSetDedToAdd vector: 1...bb_nr5g_MAX_PUCCH_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourceSetDedToDel;  /* Gives the number of valid elements in ResourceSetDedToDel vector: 1...bb_nr5g_MAX_PUCCH_RESOURCE_SETS; Default value is 0*/

    uint8_t NbSpatRelInfoDedToAdd;  /* Gives the number of valid elements in SpatRelInfoDedToAdd vector: 1...bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS; Default value is 0*/
    uint8_t NbSpatRelInfoDedToDel;  /* Gives the number of valid elements in SpatRelInfoDedToDel vector: 1...bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS; Default value is 0*/
    uint8_t NbSRResDedToAdd;  /* Gives the number of valid elements in SRResDedToAdd vector: 1...bb_nr5g_MAX_SR_RESOURCES; Default value is 0*/
    uint8_t NbSRResDedToDel;  /* Gives the number of valid elements in SRResDedToDel vector: 1...bb_nr5g_MAX_SR_RESOURCES; Default value is 0*/

    uint8_t NbMultiCsiPucchRes;  /* Gives the number of valid elements in MultiCsiPucchRes vector: 1...2; Default value is 0*/
    uint8_t NbDlDataToUlAck;  /* Gives the number of valid elements in DlDataToUlAck vector: 1...8; Default value is 0*/
    /* Field mask according to bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_***_PRESENT to handle Fmt1,Fmt2,Fmt3,Fmt4 and PucchPwCtrl*/
    uint32_t FieldMask;

    uint8_t ResourceSetDedToDel[bb_nr5g_MAX_PUCCH_RESOURCE_SETS]; /* Static list for releasing PUCCH resource sets.*/
    uint8_t SpatRelInfoDedToDel[bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS]; /* Static list for releasing spatial relation information*/
    uint8_t SRResDedToDel[bb_nr5g_MAX_SR_RESOURCES]; /* Static list for releasing Scheduling Request resources.*/

    uint8_t MultiCsiPucchRes[2]; /* Static list for releasing PUCCH resource sets.*/

    uint8_t DlDataToUlAck[8]; /* Static list of timing for given PDSCH to the DL ACK. Range element 0...15*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT1_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_PUCCH_FMT_CFGt), Fmt1); /*Parameters that are common for all PUCCH resources of format 1*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT2_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_PUCCH_FMT_CFGt), Fmt2); /*Parameters that are common for all PUCCH resources of format 2*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT3_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_PUCCH_FMT_CFGt), Fmt3); /*Parameters that are common for all PUCCH resources of format 3*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_FMT4_PRESENT   0x0008
    VFIELD(PREFIX(bb_nr5g_PUCCH_FMT_CFGt), Fmt4); /*Parameters that are common for all PUCCH resources of format 4*/
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_PW_CTRL_PRESENT   0x0010
    VFIELD(PREFIX(bb_nr5g_PUCCH_POWERCONTROLt), PucchPwCtrl);
#define bb_nr5g_STRUCT_PUCCH_CONF_DEDICATED_R16_IES_PRESENT 0x0020
    VFIELD(PREFIX(bb_nr5g_PUCCH_CONF_DEDICATED_R16_IESt), PucchConfExtR16);

    AFIELD(PREFIX(bb_nr5g_PUCCH_RESOURCEt), ResourceDedToAdd, bb_nr5g_MAX_PUCCH_RESOURCES); /* Dynamic list for adding PUCCH resources applicable for the UL BWP
                                                 and serving cell in which the PUCCH-Conf is defined.*/
    AFIELD(uint32_t, ResourceDedToDel, bb_nr5g_MAX_PUCCH_RESOURCES); /* Dynamic list for releasing PUCCH resources applicable for the UL BWP
                                                 and serving cell in which the PUCCH-Conf is defined.*/
    AFIELD(PREFIX(bb_nr5g_PUCCH_RESOURCE_SETt), ResourceSetDedToAdd, bb_nr5g_MAX_PUCCH_RESOURCE_SETS); /* Dynamic list for adding PUCCH resource sets.*/
    AFIELD(PREFIX(bb_nr5g_SPATIAL_RELATION_INFOt), SpatRelInfoDedToAdd, bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS); /*Dynamic list of configuration of the spatial relation between a reference RS and PUCCH
                                                             to be added/modified*/
    AFIELD(PREFIX(bb_nr5g_SR_RESOURCE_CFGt), SRResDedToAdd, bb_nr5g_MAX_SR_RESOURCES); /* Dynamic list for adding Scheduling Request resources.*/
} PREFIX(bb_nr5g_PUCCH_CONF_DEDICATEDt);

/* NR_SRS_PosResourceSet_r16 */
typedef struct {
    uint8_t SrsPosResourceSetId;
    uint8_t NbPosResourceAperiodic;
    uint8_t NbPosResourceIdList;
    uint8_t Alpha;
    int16_t P0;
    uint16_t Len;
    AFIELD(uint8_t, PosResourceSetAperiodic, bb_nr5g_MAX_NB_SRS_TRIGGER_STATES);
    AFIELD(uint8_t, PosResourceIdList, bb_nr5g_MAX_SRS_RESOURCE_PER_SET);
} PREFIX(bb_nr5g_SRS_POS_RESOURCE_SETt);

/* 38.331  NR_SRS_SpatialRelationInfoPos_r16_servingRS_r16 */
typedef struct {
    uint8_t ServingCellId; /* Range (0..maxNrofServingCells-1); maxNrofServingCells-1 INTEGER ::= 31; Default 0xFF */
    uint8_t SpatialRelationInfoPosIsValid; /* to check which values has to be read from the following Default: bb_nr5g_SPATIALRELINFOPOS_REFERENCESIGNAL_DEFAULT*/
    uint8_t SsbIndexServing_r16; /* Range (0..maxNrofSSBs-1); maxNrofSSBs-1 INTEGER ::= 63; Default 0xFF */
    uint8_t CsiRSIndexServing_r16; /* Range (0..maxNrofNZP-CSI-RS-Resources-1); maxNrofNZP-CSI-RS-Resources-1 INTEGER ::= 191; Default 0xFF */
    uint8_t SrsResourceId_r16; /* Range (0..maxNrofSRS-Resources-1); maxNrofSRS-Resources-1 INTEGER ::= 63; Default 0xFF */
    uint8_t SrsPosResourceId_r16; /* Range (0..maxNrofSRS-PosResources-1-r16); maxNrofSRS-PosResources-1-r16 INTEGER ::= 63; Default 0xFF */
    uint8_t uplinkBWP_r16; /* Range (0..maxNrofBWPs); maxNrofBWPs INTEGER ::= 4 */
    uint8_t Pad;
} PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SERVINGRSt);

typedef struct {
    uint16_t SfnOffset_r16; /* Range (0..1023) */
    uint8_t IntegerSubframeOffset_r16; /* Range (0..9); Default 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELL_SSB_CONFIG_SFN0_OFFSETt);

typedef struct {
    uint8_t FieldMask;
    uint32_t SsbFreq_r16;
    uint8_t HalfFrameIndex_r16; /* Enum[NR_zero, NR_one] */
    uint8_t SsbSubcarrierSpacing_r16; /* Enum[NR_kHz15, NR_kHz30, NR_kHz60, NR_kHz120, NR_kHz240, spare5, spare6, spare7] */
    uint8_t SsbPeriodicity_r16; /* Enum[NR_ms5, NR_ms10, NR_ms20, NR_ms40, NR_ms80, NR_ms160, spare6, spare7]; Default 0xFF */
    uint8_t SfnSSBOffset_r16; /* Range (0..15) */
    int8_t SsPBCHBlockPower_r16; /* Range (-60..50); Default 0xFF */
    uint8_t Pad[2];
#define bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELL_SSB_CONFIG_SFN0_OFFSET_PRESENT 0x0001
    VFIELD(PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELL_SSB_CONFIG_SFN0_OFFSETt), Sfn0Offset_r16);
} PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELL_SSB_CONFIGt);

typedef struct {
    uint32_t FieldMask;
    uint16_t PhysicalCellId_r16; /* PhysCellId Range (0..1007) */
    uint8_t SsbIndexNcell_r16; /* Range (0..maxNrofSSBs-1) maxNrofSSBs-1 INTEGER ::= 63; Default 0xFF */
    uint8_t Spare;
#define bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELL_SSB_CONFIG_PRESENT 0x0001
    VFIELD(PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELL_SSB_CONFIGt), SsbConfiguration_r16);
} PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELLt);

typedef struct {
    uint8_t DlPRSID_r16; /* Range (0..255) */
    uint8_t DlPRSResourceSetId_r16; /* Range (0..7) */
    uint8_t DlPRSResourceId_r16; /* Range (0..63); Default 0xFF */
    uint8_t Pad;
} PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_DL_PRSt);

typedef struct {
    uint32_t FieldMask;
   
#define bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SERVINGRS_PRESENT 0x0001
    VFIELD(PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SERVINGRSt), ServingRS_r16);
#define bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELL_PRESENT 0x0002
    VFIELD(PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_SSB_NCELLt), SsbNcell_r16);
#define bb_nr5g_SRS_SPATIALRELATIONINFOPOS_DL_PRS_PRESENT 0x0004
    VFIELD(PREFIX(bb_nr5g_SRS_SPATIALRELATIONINFOPOS_DL_PRSt), DlPRS_r16);
} PREFIX(bb_nr5g_SRS_SPATIAL_RELATION_INFO_POS_R16t);

typedef struct {
    uint32_t FieldMask;
    uint16_t Len;
    uint16_t Spare;
    uint8_t SrsPosResourceId_r16;
    uint8_t FreqHopping_r16; /* Range (0..63) */
    uint8_t GroupOrSequenceHopping_r16; /* Enum [neither, groupHopping, sequenceHopping] */
    uint16_t FreqDomainShift_r16; /* Range (0..268) */
    uint32_t SequenceId_r16; /* Range (0..65535) */

    struct {
        uint8_t StartPosition_r16; /* INTEGER (0..13) */
        uint8_t NrofSymbols_r16; /* Enum [n1, n2, n4, n8, n12] */
    } ResourceMapping_r16;

    uint8_t Pad;
    PREFIX(bb_nr5g_SRS_TRANSMISSION_COMBt) TransmissionComb; /* Comb value (2, 4, 8) and comb offset (0..combValue-1).*/
    
#define bb_nr5g_SPATIALRELATIONINFOPOS_R16_PRESENT 0x0001
    VFIELD(PREFIX(bb_nr5g_SRS_SPATIAL_RELATION_INFO_POS_R16t), SpatialRelationInfoPos_r16);
} PREFIX(bb_nr5g_SRS_POS_RESOURCESt);

/* 38.331 SRS-Config IE: it is used to configure sounding reference signal transmissions */
typedef struct {
    uint8_t TpcAccumulation; /* If absent, UE applies TPC commands via accumulation. If disabled, UE applies the TPC command without accumulation
                                 Enum [disabled]; Default value is 0xFF */
    uint8_t NbResourceSetsToAdd;  /* Gives the number of valid elements in ResourceSetsToAdd vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourceSetsToDel;  /* Gives the number of valid elements in ResourceSetsToDel vector: 1...bb_nr5g_MAX_SRS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbResourcesToAdd;  /* Gives the number of valid elements in ResourceSetsToAdd vector: 1...bb_nr5g_MAX_SRS_RESOURCES; Default value is 0*/
    uint8_t NbResourcesToDel;  /* Gives the number of valid elements in ResourceSetsToDel vector: 1...bb_nr5g_MAX_SRS_RESOURCES; Default value is 0*/

    uint8_t SrsRequestDCI_1_2_r16; /* Range (1..2) */
    uint8_t SrsRequestDCI_0_2_r16; /* Range (1..2) */
    uint8_t NbResourceSetToAddDCI_0_2_r16; /* SEQUENCE (SIZE(1..maxNrofSRS-ResourceSets)) OF SRS-ResourceSet */
    uint8_t NbResourceSetToDelDCI_0_2_r16; /* SEQUENCE (SIZE(1..maxNrofSRS-ResourceSets)) OF SRS-ResourceSetId */
    uint8_t NbPosResourceSetToDel_r16; /* SEQUENCE (SIZE(1..maxNrofSRS-PosResourceSets-r16)) OF SRS-PosResourceSetId-r16 */
    uint8_t NbPosResourceSetToAdd_r16; /* SEQUENCE (SIZE(1..maxNrofSRS-PosResourceSets-r16)) OF SRS-PosResourceSet-r16 */
    uint8_t NbPosResourceToDel_r16; /* SEQUENCE (SIZE(1..maxNrofSRS-PosResources-r16)) OF SRS-PosResourceId-r16 */
    uint8_t NbPosResourceToAdd_r16; /* SEQUENCE (SIZE(1..maxNrofSRS-PosResources-r16)) OF SRS-PosResource-r16 */
    uint8_t Pad[3];

    AFIELD(PREFIX(bb_nr5g_SRS_RESOURCEt), ResourcesToAdd, bb_nr5g_MAX_SRS_RESOURCES); /* Dynamic list for adding SRS resources*/
    AFIELD(PREFIX(bb_nr5g_SRS_RESOURCE_SETt), ResourceSetsToAdd, bb_nr5g_MAX_SRS_RESOURCE_SETS); /* Dynamic list for adding SRS resource sets*/
    AFIELD(uint32_t, ResourcessToDel, bb_nr5g_MAX_SRS_RESOURCES); /* Dynamic list for deleting SRS resources*/
    AFIELD(uint32_t, ResourceSetsToDel, bb_nr5g_MAX_SRS_RESOURCE_SETS); /* Dynamic list for deleting SRS resource sets*/
    AFIELD(PREFIX(bb_nr5g_SRS_RESOURCE_SETt), ResourceSetToAddDCI_0_2_r16, bb_nr5g_MAX_SRS_RESOURCE_SETS);
    AFIELD(PREFIX(bb_nr5g_SRS_POS_RESOURCE_SETt), PosResourceSetToAdd_r16, bb_nr5g_MAX_SRS_POS_RESOURCES_SETS);
    AFIELD(PREFIX(bb_nr5g_SRS_POS_RESOURCESt), PosResourceToAdd_r16, bb_nr5g_MAX_SRS_POS_RESOURCES);
    AFIELD(uint8_t, ResourceSetToDelDCI_0_2_r16, bb_nr5g_MAX_SRS_RESOURCE_SETS);
    AFIELD(uint8_t, PosResourceSetToDel_r16, bb_nr5g_MAX_SRS_POS_RESOURCES_SETS);
    AFIELD(uint8_t, PosResourceToDel_r16, bb_nr5g_MAX_SRS_POS_RESOURCES);
} PREFIX(bb_nr5g_SRS_CONF_DEDICATEDt);

/* 38.331 SRS-CarrierSwitching IE: it is used to configure for SRS carrier switching when PUSCH is 
          not configured and independent SRS power control from that of PUSCH*/
typedef struct {
   uint8_t CCSetIndex; /*Indicates the CC set index for Type A associated. Range 0...3; Invalid value 0Xff */
   uint8_t CCIndexInOneCSet; /*Indicates the CC index in one CC set for Type A . Range 0...7; Invalid value 0Xff */
   uint8_t Pad[2];
} PREFIX(bb_nr5g_SRS_CC_SETINDEXt);

typedef struct {
    uint8_t NbSrsCCSetIndexList; /* Gives the number of valid elements in SrsCCSetIndexList vector: 1...4; Default value is 0*/
    uint8_t Pad[3];
    PREFIX(bb_nr5g_SRS_CC_SETINDEXt) SrsCCSetIndexList[4]; /* Static list of one trigger configuration for SRS-Carrier Switching */
} PREFIX(bb_nr5g_SRS_TPC_PDCCH_CFGt);

typedef struct {
    uint8_t SrsSwitchFromServCellIndex; /* Indicates the serving cell whose UL transmission may be interrupted 
                                           during SRS transmission on a PUSCH-less cell. Range 1...bb_nr5g_MAX_NB_SERVING_CELLS
                                           Default/Invalid value is 0xff*/
    uint8_t SrsSwitchFromCarrier;         /*Enum [sUL, nUL]; Default/Invalid value is 0xff*/
    uint8_t SrsTpcPdcchGroupIsValid;      /* This field assumes a value defined as bb_nr5g_SRS_TPC_PDCCH_GROUP_***
                                             in order to read in good way the associated parameter SrsTpcPdcchGroup.
                                             If this field is set to bb_nr5g_SRS_TPC_PDCCH_GROUP_DEFAULT SrsTpcPdcchGroup
                                             will be ignored */
    uint8_t NbSrsTpcPdcchGroup;           /* Gives the number of valid elements in SrsTpcPdcchGroup vector:
                                             1...32; Default value is 0*/
    uint8_t NbMonitoringCells;           /* Gives the number of valid elements in MonitoringCells vector:
                                             1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0*/
    uint8_t Pad[3];
    AFIELD(PREFIX(bb_nr5g_SRS_TPC_PDCCH_CFGt), SrsTpcPdcchGroup, 32); /*Dynamic list of trigger configuration for SRS transmission on a PUSCH-less SCell  */
    AFIELD(uint32_t, MonitoringCells, bb_nr5g_MAX_NB_SERVING_CELLS); /*Dynamic list of serving cells for monitoring PDCCH conveying SRS DCI format with CRC scrambled by TPC-SRS-RNTI  */
} PREFIX(bb_nr5g_SRS_CARRIER_SWITCHING_CFGt);

/* 38.331 BeamFailureRecoveryConfig IE: it is used to configure the UE with RACH resources and candidate beams for beam failure recovery in case of beam 
   failure detection */
typedef struct {
    uint8_t SsbIndex; /* The ID of an SSB transmitted by this serving cell. It determines a candidate beam for beam failure recovery (BFR)
                       Range 0....63; Default is 0xFF */
    uint8_t RaPreambleIndex;  /* The preamble index that the UE shall use when performing BFR upon selecting the candidate beams identified by this SSB.
                               Range 0....63; Default is 0xFFFF*/
    uint8_t Pad[2];
} PREFIX(bb_nr5g_BFR_SSB_RESOURCEt);

typedef struct {
    uint16_t CsiRsId; /* The ID of a NZP-CSI-RS-Resource configured in the CSI-MeasConfig of this serving cell. 
                          This reference signal determines a candidate beam for beam failure recovery (BFR).
                          Range 0....(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1); Default is 0xFFFF */
    uint8_t RaPreambleIndex;  /*  The RA preamble index to use in the RA occasions associated with this CSI-RS. 
                                If the field is absent, the UE uses the preamble index associated with the SSB that is QCLed with this CSI-RS.
                                Range 0....63; Default is 0xFF*/
    uint8_t NbRaOccasionList; /*Gives the number of valid elements in RaOccasionList vector:
                                  Range: 1...bb_nr5g_MAX_RA_OCCASIONS_PER_CSIRS; Default value is 0 */
    AFIELD(uint32_t, RaOccasionList, bb_nr5g_MAX_RA_OCCASIONS_PER_CSIRS); /*Dynamic list RA occasions that the UE shall
                                                                            use when performing BFR upon selecting the candidate beam identified by this CSI-RS*/
} PREFIX(bb_nr5g_BFR_CSIRS_RESOURCEt);

typedef struct {
    uint8_t PrachResDedBfrCfgIsValid; /* This field assumes a value defined as bb_nr5g_PRACH_RESOURCE_DED_BFR_CFG_*
                                         in order to read in good way the associated parameter Ssb or CsiRs.
                                         This field defines the presence and the kind of PRACH resource
                                         bb_nr5g_PRACH_RESOURCE_DED_BFR_CFG_SSB -> only Ssb field is present
                                         bb_nr5g_PRACH_RESOURCE_DED_BFR_CFG_CSIRS -> only CsiRs field is present
                                         If this field is set to default value bb_nr5g_PRACH_RESOURCE_DED_BFR_CFG_DEFAULT 
                                         Ssb/CsiRs is not present */
    uint8_t Pad[3];
    VFIELD(PREFIX(bb_nr5g_BFR_SSB_RESOURCEt), Ssb);
    VFIELD(PREFIX(bb_nr5g_BFR_CSIRS_RESOURCEt), CsiRs);
} PREFIX(bb_nr5g_PRACH_RESOURCE_DED_BFR_CFGt);

typedef struct {
    PREFIX(bb_nr5g_RACH_CONF_GENERICt) RachConfGenericBFR; /* Configuration of contention free random access occasions for BFR. Optional.*/
    uint16_t PrachRootSeqIndexBFR;   /* PRACH root sequence index. Range[ 0...137]. Optional. Default value is 0xFFFF */
    uint8_t  RsrpThresholdSsb;       /* L1-RSRP threshold used for determining whether a candidate beam may be used by the UE to attempt 
                                        contention free Random Access to recover from beam failure.Optional.
                                        Default value is 0xFF; Range 0...127 */
    uint8_t  SsbPerRachOccasion;      /*Number of SSBs per RACH occasion for CF-BFR (L1 parameter 'SSB-per-rach-occasion').Optional.
                                        Enum [oneEighth, oneFourth, oneHalf, one, two, four, eight, sixteen].Default value is 0xFF */
    uint8_t  RaSsbOccasionMaskIndex;    /*The mask is valid for all SSB resources.Optional.
                                          Range: 0...15; Default value is 0xFF*/
    uint8_t  RecoverySearchSpaceId;    /* Search space to use for BFR RAR. The network configures this search space to be within the linked DL BWP 
                                          (i.e., within the DL BWP with the same bwp-Id) of the UL BWP in 
                                          which the BeamFailureRecoveryConfig is provided. The CORESET 
                                          associated with the recovery search space cannot be associated with another search space.Optional.
                                          Default/Invalid value is 0xFF. Range 0... bb_nr5g_MAX_NB_SEARCH_SPACES -1 */
    uint8_t BeamFailureRecoveryTimer; /* Timer for beam failure recovery timer.  Upon expiration of the timer the UE does not use CFRA for BFR. 
                                         Value in ms. ms10 corresponds to 10ms, ms20 to 20ms, and so on.Optional.
                                         Enum [ms10, ms20, ms40, ms60, ms80, ms100, ms150, ms200].Default value is 0xFF*/
    uint8_t Msg1SubCarrSpacing; /*  Subcarrier spacing for contention free beam failure recovery. 
                                    Only the values 15 or 30 kHz (<6GHz), 60 or 120 kHz (>6GHz) are applicable. Optional.
                                    Enum [kHz15, kHz30, kHz60, kHz120, kHz240]; Default/Invalid value is 0xFF*/
    uint8_t NbCandBeamRSList;  /* Gives the number of valid elements in CandBeamRSList vector:
                                  Range: 1...bb_nr5g_MAX_NB_CANDIDATE_BEAMS; Default value is 0 */
    uint8_t Pad[3];
    AFIELD(PREFIX(bb_nr5g_PRACH_RESOURCE_DED_BFR_CFGt), CandBeamRSList, bb_nr5g_MAX_NB_CANDIDATE_BEAMS); /* Dynamic list of reference signals (CSI-RS and/or SSB) identifying the candidate beams for 
                                                                                                            recovery and the associated RA parameters. The network configures these reference signals 
                                                                                                            to be within the linked DL BWP (i.e., within the DL BWP with the same bwp-Id) of 
                                                                                                            the UL BWP in which the BeamFailureRecoveryConfig is provided.   */
} PREFIX(bb_nr5g_BEAM_FAIL_RECOVERY_CFGt);

/****************************************************************************************/
/* 38.331 BWP IE : Generic parameters used in Uplink- and Downlink bandwidth parts         */
typedef struct {
    uint16_t  LocAndBw; /* Corresponds to L1 parameter 'DL-BWP-loc'. (see 38.211, section FFS_Section).
                           Range (0..37949); Default/Invalid value is 0xFFFF*/
    uint8_t   SubCarSpacing;    /* Corresponds to subcarrier spacing according to 38.211, Table 4.2-1
                                   Enum kHz15, kHz30, kHz60, kHz120, kHz240; Default/Invalid value is 0xFF*/
    uint8_t   CyclicPrefix;     /* Enum extended; Default value is 0xFF*/
} PREFIX(bb_nr5g_BWPt);

/****************************************************************************************/
/* 38.331 BWP-DownlinkCommon IE. It is prepared to become dynamic. 
   Actually we decide to use the structure as static to simplify the handling */
typedef struct {
    uint32_t FieldMask; 
    PREFIX(bb_nr5g_BWPt)   GenBwp;
#define bb_nr5g_STRUCT_BWP_DOWNLINK_COMMON_PDCCH_CFG_PRESENT   0x0001
    PREFIX(bb_nr5g_PDCCH_CONF_COMMONt) PdcchConfCommon;
#define bb_nr5g_STRUCT_BWP_DOWNLINK_COMMON_PDSCH_CFG_PRESENT   0x0002
    PREFIX(bb_nr5g_PDSCH_CONF_COMMONt) PdschConfCommon;
} PREFIX(bb_nr5g_BWP_DOWNLINKCOMMONt);

/* 38.331 NR_SPS_ConfigDeactivationState_r16 */
typedef struct {
    uint32_t NbSPS_ConfigIndex_r16;
    uint8_t SPS_ConfigIndex_r16[bb_nr5g_MAX_NR_OF_SPS_CONFIG_R16];
} PREFIX(bb_nr5g_SPS_CONFIG_INDEXt);

/****************************************************************************************/
typedef struct {
    uint32_t FieldMask;
    uint16_t Len;
    uint16_t Spare;
    uint8_t NbDedCtrlResSetsToAdd_r16;
    uint8_t NbDedCtrlResSetsToDel_r16;
    uint8_t NbSearchSpacesToAddExt_r16;
    uint8_t DedCtrlResSetsToDel_r16[5];  /* Range (0..15) */
#define bb_nr5g_STRUCT_UPLINK_CANCELLATION_PRESENT   0x0001
    PREFIX(bb_nr5g_UPLINK_CANCELt) UplinkCancellation_r16;

    PREFIX(bb_nr5g_CTRL_RES_SETt) DedCtrlResSetsToAdd_r16[2];
    PREFIX(bb_nr5g_SEARCH_SPACE_EXTt) SearchSpacesToAddExt_r16[10];
} PREFIX(bb_nr5g_PDCCH_CONF_DEDICATED_R16t);
/****************************************************************************************/
/* 38.331 BWP-DownlinkDedicated IE. It is prepared to become dynamic. 
   Actually we decide to use the structure as static to simplify the handling */
typedef struct {
    uint32_t FieldMask; 
    uint8_t NbSpsConfToAdd_r16;
    uint8_t NbConfigDeactivationState_r16;
    uint8_t Pad[2];

#define bb_nr5g_STRUCT_BWP_DOWNLINK_DED_PDCCH_CFG_PRESENT   0x0001
    PREFIX(bb_nr5g_PDCCH_CONF_DEDICATEDt) PdcchConfDed;
#define bb_nr5g_STRUCT_BWP_DOWNLINK_DED_PDSCH_CFG_PRESENT   0x0002
    PREFIX(bb_nr5g_PDSCH_CONF_DEDICATEDt) PdschConfDed;
#define bb_nr5g_STRUCT_BWP_DOWNLINK_DED_SPS_CFG_PRESENT     0x0004
    PREFIX(bb_nr5g_SPS_CONF_DEDICATEDt)   SpsConfDed;
#define bb_nr5g_STRUCT_BWP_DOWNLINK_DED_SPS_CFG_R16_PRESENT             0x0008
    VFIELD(PREFIX(bb_nr5g_SPS_CONFIG_INDEXt), SpsConfToDel_r16);
#define bb_nr5g_STRUCT_PDCCH_CONF_DEDICATED_R16_PRESENT   0x00010
    VFIELD(PREFIX(bb_nr5g_PDCCH_CONF_DEDICATED_R16t), PdcchConfDedR16);

#define bb_nr5g_STRUCT_BWP_DOWNLINK_DED_PDCCH_CFG_RELEASE   0x0020
#define bb_nr5g_STRUCT_BWP_DOWNLINK_DED_PDSCH_CFG_RELEASE   0x0040

    AFIELD(PREFIX(bb_nr5g_SPS_CONF_DEDICATEDt), SpsConfToAdd_r16, bb_nr5g_MAX_NR_OF_SPS_CONFIG_R16);
    AFIELD(PREFIX(bb_nr5g_SPS_CONFIG_INDEXt), ConfigDeactivationState_r16, bb_nr5g_MAX_NR_OF_SPS_DEACTIVATIONSTATE);
} PREFIX(bb_nr5g_BWP_DOWNLINKDEDICATEDt);

/****************************************************************************************/
/* Currentlly not used */
/* 38.331 BWP-Downlink IE */
typedef struct {
     uint8_t BwpId;  /* BwpId is used to refer to Bandwidth Parts (BWP). The initial BWP is
                        referred to by BwpId 0.
                        The other BWPs are referred to by 1 to bb_nr5g_MAX_NB_BWPS.*/
    uint8_t  Spare;
    uint16_t FieldMask;
#define bb_nr5g_STRUCT_BWP_DOWNLINK_COMMON_CFG_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_BWP_DOWNLINKCOMMONt), BwpDLCommon);
#define bb_nr5g_STRUCT_BWP_DOWNLINK_DEDICATED_CFG_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_BWP_DOWNLINKDEDICATEDt), BwpDLDed);
} PREFIX(bb_nr5g_BWP_DOWNLINKt);

/****************************************************************************************/
/* 38.331 BWP-UplinkCommon IE : It is prepared to become dynamic. 
   Actually we decide to use the structure as static to semplify the handling */
typedef struct {
    uint32_t FieldMask;
    uint8_t UseInterlacePUCCH_PUSCH_r16; /* Enum {enabled} */
    uint8_t Pad[3];

    PREFIX(bb_nr5g_BWPt)   GenBwp;
#define bb_nr5g_STRUCT_BWP_UPLINK_COMMON_RACH_CFG_PRESENT    0x0001
    PREFIX(bb_nr5g_RACH_CONF_COMMONt) RachCfgCommon;
#define bb_nr5g_STRUCT_BWP_UPLINK_COMMON_PUSCH_CFG_PRESENT   0x0002
    PREFIX(bb_nr5g_PUSCH_CONF_COMMONt) PuschCfgCommon;
#define bb_nr5g_STRUCT_BWP_UPLINK_COMMON_PUCCH_CFG_PRESENT   0x0004
    PREFIX(bb_nr5g_PUCCH_CONF_COMMONt) PucchCfgCommon;
} PREFIX(bb_nr5g_BWP_UPLINKCOMMONt);

typedef struct {
   uint8_t NbConfiguredGrantConfig_r16;   /* Default value is 0 */
   uint8_t Pad;
   uint16_t Len;

   AFIELD(uint8_t, ConfiguredGrantConfig_r16, bb_nr5g_MAX_NB_CONFIGURED_GRANT_CONFIG);
} PREFIX(bb_nrg5_CONFIGURED_GRANT_TYPE2_DEACT_STATEt);
/****************************************************************************************/
/* 38.331 BWP-UplinkDedicated IE. It is prepared to become totally dynamic. 
   Actually we decide to use the structures bb_nr5g_PUCCH_CONF_DEDICATEDt,  bb_nr5g_PUSCH_CONF_DEDICATEDt,
   and bb_nr5g_SRS_CONF_DEDICATEDt as static to semplify the handling.
   Instead the presence of bb_nr5g_BEAM_FAIL_RECOVERY_CFGt structure is optional. 
   It has to be read by BB and filled by TSTM only if present in RRC message */
typedef struct {
    uint32_t FieldMask; 

    uint8_t CpExtensionC2_r16;                  /* Range (1..28) */
    uint8_t CpExtensionC3_r16;                  /* Range (1..28) */
    uint8_t UseInterlacePUCCH_PUSCH_r16;        /* Enum {enabled} */

    uint8_t NbConfigGrantConfigToAdd_r16;       /* Default value is 0 */
    uint8_t NbConfigGrantConfigToRel_r16;       /* Default value is 0 */
    uint8_t NbConfigGrantConfigType2DeactState_r16;       /* Default value is 0 */
    uint8_t NbPucchConfDedToAdd;                /* Range (1..2) */
    uint8_t Pad;

#define bb_nr5g_STRUCT_BWP_UPLINK_DED_PUCCH_CFG_PRESENT   0x0001
    PREFIX(bb_nr5g_PUCCH_CONF_DEDICATEDt) PucchConfDed;
#define bb_nr5g_STRUCT_BWP_UPLINK_DED_PUSCH_CFG_PRESENT   0x0002
    PREFIX(bb_nr5g_PUSCH_CONF_DEDICATEDt) PuschConfDed;
#define bb_nr5g_STRUCT_BWP_UPLINK_DED_SRS_CFG_PRESENT   0x0004
    PREFIX(bb_nr5g_SRS_CONF_DEDICATEDt)   SrsConfDed;
#define bb_nr5g_STRUCT_BWP_UPLINK_DED_CONFIGURED_GRANT_PRESENT 0x0008
    PREFIX(bb_nr5g_CONFIGURED_GRANT_CONFt) GrantConfDed;
    /* Configuration of beam failure recovery. It can be present only for SpCell.
       If supplementaryUplink is present, the field is present 
       only in one of the uplink carriers, either UL or SUL. */
#define bb_nr5g_STRUCT_BWP_UPLINK_DED_BEAM_RECOVERY_CFG_PRESENT   0x0010
    VFIELD(PREFIX(bb_nr5g_BEAM_FAIL_RECOVERY_CFGt),   BeamFailRecConfDed);

#define bb_nr5g_STRUCT_BWP_UPLINK_DED_PUSCH_CFG_RELEASE   0x0020

    AFIELD(PREFIX(bb_nr5g_PUCCH_CONF_DEDICATEDt), PucchConfigurationList_r16, 2);
    AFIELD(PREFIX(bb_nr5g_CONFIGURED_GRANT_CONFt), ConfiguredGrantConfigToAddMod_r16, bb_nr5g_MAX_NB_CONFIGURED_GRANT_CONFIG );
    AFIELD(uint8_t, ConfigGrantConfigToRel_r16, bb_nr5g_MAX_NB_CONFIGURED_GRANT_CONFIG);
    AFIELD(PREFIX(bb_nrg5_CONFIGURED_GRANT_TYPE2_DEACT_STATEt), ConfigGrantConfigType2DeactState_r16, bb_nr5g_MAX_NB_CG_TYPE2_DEACT_STATE);
} PREFIX(bb_nr5g_BWP_UPLINKDEDICATEDt);
/****************************************************************************************/
/* 38.331 BWP-Uplink IE */
typedef struct {
     uint8_t BwpId;  /* BwpId is used to refer to Bandwidth Parts (BWP). The initial BWP is
                        referred to by BwpId 0.
                        The other BWPs are referred to by 1 to bb_nr5g_MAX_NB_BWPS.*/
    uint8_t  Spare;
    uint16_t FieldMask;
#define bb_nr5g_STRUCT_BWP_UPLINK_COMMON_CFG_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_BWP_UPLINKCOMMONt), BwpULCommon);
#define bb_nr5g_STRUCT_BWP_UPLINK_DEDICATED_CFG_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_BWP_UPLINKDEDICATEDt), BwpULDed);
} PREFIX(bb_nr5g_BWP_UPLINKt);

/* PDSCH-CodeBlockGroupTransmission-r16 */
typedef struct {
    uint8_t MaxCodeBlockGroupsPerTransportBlock; /* Enum {n2, n4, n6, n8} */
    uint8_t CodeBlockGroupFlushIndicator;
    uint8_t Pad[2];
} PREFIX(bb_nr5g_PDSCH_CODEBLOCKGROUP_TRANS_R16t);

/****************************************************************************************/
/* 38.331 PDSCH-ServingCellConfig IE: it is used to configure UE specific PDSCH parameters that are common across the UE's BWPs of one serving cell */
typedef struct {
    uint8_t MaxCodeBlockGroupsPerTB; /* Maximum number of code-block-groups (CBGs) per TB.
                                        Enum [n2, n4, n6, n8]; Default/Invalid value is 0xFF*/
    uint8_t CodeBlockGroupFlushIndicator; /*Indicates whether CBGFI for CBG based (re)transmission in DL is enabled (true).
                                            Range 0 or 1; Default/Invalid value is 0xFF*/
    uint8_t Pad[2];
} PREFIX(bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt);

typedef struct {
    uint8_t XOverhead; /* Accounts for overhead from CSI-RS, CORESET, etc. If the field is absent, the UE applies value xOh0.
                          Enum [xOh6, xOh12, xOh18]; Default/Invalid value is 0xFF*/
    uint8_t NbHarqProcessesForPDSCH; /*The number of HARQ processes to be used on the PDSCH of a serving cell
                                    Enum [n2, n4, n6, n10, n12, n16]; Default/Invalid value is 0xFF*/
    uint16_t PucchCell; /* The ID of the serving cell (of the same cell group) to use for PUCCH.
                            Default/Invalid value is 0xFFFF*/
    uint8_t MaxMimoLayers; /*Indicates the maximum MIMO layer to be used for PDSCH in all BWPs of this serving cell
                             Range 1...8; Default/Invalid value is 0xFF*/
    uint8_t ProcessingType2Enabled;/*Enables configuration of advanced processing time capability 2 for PDSCH 
                                     Range 0..1; Default/Invalid value is 0xFF*/
    uint8_t NbCodeBlockGroupTransmission_r16;
    uint8_t Pad;

    PREFIX(bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt) CodeBlockGroupTrans; /*Enables and configures code-block-group (CBG) based transmission*/
    AFIELD(PREFIX(bb_nr5g_PDSCH_CODEBLOCKGROUPTRANSMt), CodeBlockGroupTransmissionList_r16, 2);
} PREFIX(bb_nr5g_PDSCH_SERVING_CELL_CFGt);

/****************************************************************************************/
/* 38.331 PDCCH-ServingCellConfig IE: is used to configure UE specific PDCCH parameters applicable across all bandwidth parts of a serving cell */
typedef struct {
    PREFIX(bb_nr5g_SLOT_FMT_INDICATORt) SlotFormatIndicator;
} PREFIX(bb_nr5g_PDCCH_SERVING_CELL_CFGt);

/****************************************************************************************/
/* 38.331 PDSCH-ServingCellConfig IE: it is used to configure UE specific PDSCH parameters that are common across the UE's BWPs of one serving cell */
typedef struct {
    uint8_t MaxCodeBlockGroupsPerTB; /* Maximum number of code-block-groups (CBGs) per TB.
                                        Enum [n2, n4, n6, n8]; Default/Invalid value is 0xFF*/
    uint8_t Pad[3];
} PREFIX(bb_nr5g_PUSCH_CODEBLOCKGROUPTRANSMt);

typedef struct {
    uint8_t XOverhead; /* Accounts for overhead from CSI-RS, CORESET, etc. If the field is absent, the UE applies value xOh0.
                          Enum [xOh6, xOh12, xOh18]; Default/Invalid value is 0xFF*/
    uint8_t RateMatching; /* Enables LBRM (Limited buffer rate-matching).
                             Enum [limitedBufferRM]; Default/Invalid value is 0xFF*/
    uint8_t MaxMimoLayers; /*Indicates the maximum MIMO layer to be used for PUSCH in all BWPs of this serving cell
                             Range 1...8; Default/Invalid value is 0xFF*/
    uint8_t ProcessingType2Enabled;/*Enables configuration of advanced processing time capability 2 for PUSCH
                                     Range 0..1; Default/Invalid value is 0xFF*/
    uint8_t MaxMIMOLayersDCI02_r16;       /*  Range (1..4); Default/Invalid value is 0xFF*/
    uint8_t Pad[3];

    PREFIX(bb_nr5g_PUSCH_CODEBLOCKGROUPTRANSMt) CodeBlockGroupTrans; /*Enables and configures code-block-group (CBG) based transmission*/
} PREFIX(bb_nr5g_PUSCH_SERVING_CELL_CFGt);

/****************************************************************************************/
/* 38.331 NZP-CSI-RS-Resource IE: it is used to configure Non-Zero-Power (NZP) CSI-RStransmitted in the cell where the IE is included, 
which the UE may be configured to measure on (see 38.214, section 5.2.2.3.1). */
typedef struct {
    uint8_t ResourceId; /* NZP_CSI_RS_ResourceId. Range 0 ...(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES-1). 
                           Default/Invalid value is 0xff*/
    int8_t  PwrCtrlOffset; /* Power offset of NZP CSI-RS RE to PDSCH RE. Value in dB.
                              Range [-8..15]; Default/Invalid value is 0xff*/
    uint8_t  PwrCtrlOffsetSS; /* Power offset of NZP CSI-RS RE to SS RE. Value in dB.
                                 Enum [db-3, db0, db3, db6]; Default/Invalid value is 0xff*/
    uint8_t  QclInfoPeriodicCsiRs; /* For a target periodic CSI-RS, contains a reference to one TCI-State in TCI-States
                                       for providing the QCL source and QCL type.
                                       Range 0....(bb_nr5g_MAX_NB_TCI_STATES-1); Default/Invalid is 0xFF */
    uint16_t ScramblingID; /* Range [0...1023]; Default/Invalid value is 0xffff */
    uint8_t Pad[2];
    PREFIX(bb_nr5g_CSI_RS_RES_MAPPINGt) ResourceMapping; /* OFDM symbol location(s) in a slot and subcarrier occupancy in a PRB of the CSI-RS resource */
    PREFIX(bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt) PeriodicityAndOffset;/* Periodicity and slot offset sl1 corresponds to a periodicity of 1 slot, sl2 to a periodicity of two slots, 
                                                                          and so on. */
} PREFIX(bb_nr5g_NZP_CSI_RS_RES_CFGt);

/* 38.331 NZP-CSI-RS-ResourceSet IE: it is a set of Non-Zero-Power (NZP) CSI-RS resources (their IDs) and set-specific parameters. */
typedef struct {
    uint8_t ResSetId; /* NZP_CSI_RS_ResourceSetId. Range 0 ...(bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS-1). 
                           Default/Invalid value is 0xff*/
    uint8_t Repetition; /*Indicates whether repetition is on/off. If set to set to 'OFF', the UE may not assume that the NZP-CSI-RS
                          resources within the resource set are transmitted with the same downlink spatial domain transmission filter
                          and with same NrofPorts in every symbol.
                          Enum [on,off]; Default/Invalid value is 0xff*/
    uint8_t AperTriggerOffset; /* Offset X between the slot containing the DCI that triggers a set of aperiodic NZP CSI-RS resources
                                  and the slot in which the CSI-RS resource set is transmitted. When the field is absent the UE applies the value 0.
                                  ver15.3 Range 0...4; ver15.4 Range 0...6;Default/Invalid value is 0xff*/
    uint8_t TrsInfo; /* Indicates that the antenna port for all NZP-CSI-RS resources in the CSI-RS resource set is same.
                          Enum [true]; Default/Invalid value is 0xff*/
    uint8_t AperTriggerOffset_r16;       /*  Range (0..31); Default/Invalid value is 0xFF*/
    uint8_t Pad[2];

    uint8_t NbNzpCsiRsResLis; /* Gives the number of valid elements in NzpCsiRsResList vector: 1...bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES; Default value is 0*/
    uint8_t NzpCsiRsResList[bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES_PER_SET]; /* NZP-CSI-RS-Resources associated with this NZP-CSI-RS resource set */
} PREFIX(bb_nr5g_NZP_CSI_RS_RES_SET_CFGt);

/* 38.331 CSI-IM-Resource IE: it is used to configure one CSI Interference Management (IM) resource.*/
typedef struct {
    uint8_t PatternIsValid; /*This field assumes a value defined as bb_nr5g_CSI_IM_RES_ELEM_PATTERN_*** in order to read
                              in good way the other parameters of the structure */
    uint8_t SubCarLocation; /* If PatternIsValid = bb_nr5g_CSI_IM_RES_ELEM_PATTERN_P0: Enum[s0, s2, s4, s6, s8, s10]
                               If PatternIsValid = bb_nr5g_CSI_IM_RES_ELEM_PATTERN_P1: Range 0..12
                               Default/Invalid value is 0xff */
    uint8_t SymLocation;    /* If PatternIsValid = bb_nr5g_CSI_IM_RES_ELEM_PATTERN_P0: Enum[s0, s2, s4, s6, s8, s10]
                               If PatternIsValid = bb_nr5g_CSI_IM_RES_ELEM_PATTERN_P1: Range 0..13
                               Default/Invalid value is 0xff */
    uint8_t Pad;
} PREFIX(bb_nr5g_CSI_IM_RES_ELEM_PATTERN_CFGt);

typedef struct {
    uint8_t ResourceId; /* CSI-IM-ResourceId. Range 0 ...(bb_nr5g_MAX_NB_CSI_IM_RESOURCES-1). 
                           Default/Invalid value is 0xff*/
    uint8_t Pad[3];
    PREFIX(bb_nr5g_CSI_IM_RES_ELEM_PATTERN_CFGt) ResElemPattern;
    PREFIX(bb_nr5g_CSI_FREQUENCY_OCCt) FreqBand; /* Frequency-occupancy of CSI-IM */
    PREFIX(bb_nr5g_CSI_RES_PERIODICITYANDOFFSETt) PeriodicityAndOffset;/*Periodicity and slot offset for periodic/semi-persistent CSI-IM*/
} PREFIX(bb_nr5g_CSI_IM_RES_CFGt);

/* 38.331 CSI-IM-ResourceSet IE; it is used to configure a set of one or more CSI Interference Management (IM) resources (their IDs) 
and set-specific parameters. */
typedef struct {
    uint8_t ResSetId; /* CSI-IM-ResourceSetId. Range 0 ...(bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SET-1). 
                           Default/Invalid value is 0xff*/
    uint8_t NbCsiImResList; /* Gives the number of valid elements in CsiImResList vector: 1...bb_nr5g_MAX_NB_CSI_IM_RESOURCES_PER_SET; Default value is 0*/
    uint8_t Pad[2];
    uint8_t CsiImResList[bb_nr5g_MAX_NB_CSI_IM_RESOURCES_PER_SET];
} PREFIX(bb_nr5g_CSI_IM_RES_SET_CFGt);

/* 38.331 CSI-SSB-ResourceSet IE: it is used to configure one SS/PBCH block resource set which refers to SS/PBCH as indicated in 
   ServingCellConfigCommon*/
typedef struct {
    uint8_t ResSetId; /* CSI-SSB-ResourceSetId. Range 0 ...(bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS - 1). 
                           Default/Invalid value is 0xff*/
    uint8_t NbCsiSsbResList; /* Gives the number of valid elements in CsiSsbResList vector: 1...bb_nr5g_MAX_NB_CSI_SSB_RESOURCES_PER_SET; Default value is 0*/
    uint8_t Pad[2];
    uint8_t CsiSsbResList[bb_nr5g_MAX_NB_CSI_SSB_RESOURCES_PER_SET]; /* List of SSB-Index: Range 0...63*/
} PREFIX(bb_nr5g_CSI_SSB_RES_SET_CFGt);

/* 38.331 CSI-ReportConfig IE: it is used to configure a periodic or semi-persistent report sent on 
PUCCH on the cell in which the CSI-ReportConfig is included, or to configure a semi-persistent 
or aperiodic report sent on PUSCH triggered by DCI received on the cell in which the CSI-ReportConfig 
is included (in this case, the cell on which the report is sent is determined by the received DCI). 
See 38.214, section 5.2.1. */

/* CSI-ReportPeriodicityAndOffset IE */
typedef struct {
    uint8_t CsiReportPeriodAndOffSetIsValid;/* This field assumes a value defined as bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_***
                                            in order to read in good way the associated parameter CsiReportPeriodAndOffSet.
                                            If this field is set to default value CsiReportPeriodAndOffSet is neither read or used */
    uint8_t Pad;
    union{
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
    } CsiReportPeriodAndOffSet;
} PREFIX(bb_nr5g_CSI_REPORT_PERIODICITYANDOFFSETt);

/* PUCCH-CSI-Resource IE */
typedef struct {
    uint8_t UplinkBwpId; /*BwpId is used to refer to Bandwidth Parts (BWP). */
    uint8_t PucchResId;  /*Range 0 ...(bb_nr5g_MAX_PUCCH_RESOURCES -1); Default value is 0xFF */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_PUCCH_CSI_RESOURCEt);
 
typedef struct {
    uint8_t NbPucchCsiResList; /* Gives the number of valid elements in PucchCsiResList vector: Range 1...bb_nr5g_MAX_NB_BWPS
                                  Default value is 0*/
    uint8_t Pad[3];
    PREFIX(bb_nr5g_CSI_REPORT_PERIODICITYANDOFFSETt) RepSlotCfg; /* Periodicity and slot offset.*/
    PREFIX(bb_nr5g_PUCCH_CSI_RESOURCEt) PucchCsiResList[bb_nr5g_MAX_NB_BWPS]; /*Indicates which PUCCH resource to use for reporting on PUCCH*/
} PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODICt);

typedef struct {
    uint8_t NbPucchCsiResList; /* Gives the number of valid elements in PucchCsiResList vector: Range 1...bb_nr5g_MAX_NB_BWPS
                                  Default value is 0*/
    uint8_t Pad[3];
    PREFIX(bb_nr5g_CSI_REPORT_PERIODICITYANDOFFSETt) RepSlotCfg; /* Periodicity and slot offset.*/
    PREFIX(bb_nr5g_PUCCH_CSI_RESOURCEt) PucchCsiResList[bb_nr5g_MAX_NB_BWPS]; /*Indicates which PUCCH resource to use for reporting on PUCCH*/
} PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCHt);

typedef struct {
    uint8_t RepSlotCfg; /*Periodicity and slot offset.
                          Enum:[sl5, sl10, sl20, sl40, sl80, sl160, sl320].
                          Default/Invalid value 0xff*/
    uint8_t P0Alpha;  /* Index of the p0-alpha set determining the power control for this CSI report
                         transmission.Range 0...(bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS-1).
                         Default/Invalid value 0xff*/
    uint8_t NbRepSlotOffsetList; /* Gives the number of valid elements in RepSlotOffsetList vector: Range 1...bb_nr5g_MAX_NB_UL_ALLOCS
                                  Default value is 0*/
    uint8_t Pad;
    uint8_t RepSlotOffsetList[bb_nr5g_MAX_NB_UL_ALLOCS]; /*List of integer 0...32*/
} PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCHt);

typedef struct {
    uint8_t NbRepSlotOffsetList; /* Gives the number of valid elements in RepSlotOffsetList vector: Range 1...bb_nr5g_MAX_NB_UL_ALLOCS
                                  Default value is 0*/
    uint8_t Pad[3];
    uint8_t RepSlotOffsetList[bb_nr5g_MAX_NB_UL_ALLOCS]; /*List of integer 0...32*/
} PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_APERIODICt);

typedef struct {
    uint8_t CqiFmtIndicator; /* Enum [widebandCQI, subbandCQI]. Default/Invalid value is 0xff*/
    uint8_t PmiFmtIndicator; /* Enum [widebandPMI, subbandPMI]. Default/Invalid value is 0xff*/
    uint8_t CsiReportingBandIsValid;/* This field assumes a value defined as bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_***
                              in order to read in good way the associated parameter CsiReportingBand.
                              If this field is set to default value CsiReportingBand is neither read or used */
    uint8_t Pad;
    uint32_t CsiReportingBand;
} PREFIX(bb_nr5g_CSI_REPORT_FREQ_CFGt);

/* 38.331 CodebookConfig IE: it is used to configure codebooks of Type-I and Type-II (see 38.214, section 5.2.2.2) */
typedef struct {
    uint8_t TwoTXCodebookSubsetRestriction; /* Codebook subset restriction for 2TX codebook. BIT STRING (SIZE (6)).
                                               Default/invalid value is 0xff*/
    uint8_t Pad[3];
}PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_TWO_ANT_PORTS_CFGt);

typedef struct {
    /* Number of antenna ports in first (n1) and second (n2) dimension and codebook subset restriction*/
    uint8_t N1N2IsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_*
                              in order to read in good way the associated parameter N1N2.
                              If this field is set to default value N1N2 is neither read or used*/
    uint8_t TypeISinglePanelCodebookSubsetRestrI2IsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_TYPEI_**
                                                             in order to read in good way the associated parameter TypeISinglePanelCodebookSubsetRestrI2 */
    uint16_t TypeISinglePanelCodebookSubsetRestrI2;  /*i2 codebook subset restriction for Type I Single-panel codebook used when reportQuantity is CRI/Ri/i1/CQI
                                                       BIT STRING (SIZE (16)). This field will be read only if TypeISinglePanelCodebookSubsetRestrI2IsValid=
                                                       bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_TYPEI_PRESENT*/
    uint8_t N1N2[32]; /* BIT STRING (SIZE (x)) where x depends on bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_TYPEI_* ; 256/8 is the maximum admitted value */
}PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_CFGt);

typedef struct {
    uint8_t NbOfAntPortsIsValid;/* This field assumes a value defined as bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_*
                              in order to read in good way the associated parameter NbOfAntPorts.
                              If this field is set to default value NbOfAntPorts is neither read or used*/
    uint8_t TypeISinglePanelRiRestr;  /* Restriction for RI for TypeI-SinglePanel-RI-Restriction*/
    uint8_t Pad[2];
    union{
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_TWO_ANT_PORTS_CFGt) TwoNbOfAntPorts;
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_CFGt) MoreThanTwoNbOfAntPorts;
    } NbOfAntPorts;
}PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_SINGLE_PANEL_CFGt);

typedef struct {
    /* Number of antenna ports in first (n1) and second (n2) dimension and codebook subset restriction*/
    uint8_t N1N2IsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_*
                              in order to read in good way the associated parameter N1N2.
                              If this field is set to default value N1N2 is neither read or used*/
    uint8_t TypeIMultiPanelRiRestr;  /* Codebook subset restriction for Type I Multi-panel codebook. BIT STRING (SIZE (4)).Default/Invalid value is 0xff */
    uint8_t Pad[2];
    uint8_t N1N2[32]; /* BIT STRING (SIZE (x)) where x depends on bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_* ; 256/8 is the maximum admitted value */
}PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_CFGt);

typedef struct {
    uint8_t CodeBookSubType1IsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_*
                                       in order to read in good way the associated parameter NbOfAntPorts.
                                       If this field is set to default value NbOfAntPorts is neither read or used*/
    uint8_t CodebookMode; /*CodebookMode as specified in 38.214 section 5.2.2.2.2. Range 1..2. Default/Invalid value */
    uint8_t Pad[2];
    union{
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_SINGLE_PANEL_CFGt) TypeISinglePanel;
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_CFGt) TypeIMultiPanel;
    } CodeBookSubType1;
}PREFIX(bb_nr5g_CODEBOOK_TYPE1_CFGt);

/**/
typedef struct {
    /* Number of antenna ports in first (n1) and second (n2) dimension and codebook subset restriction*/
    uint8_t N1N2IsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_*
                              in order to read in good way the associated parameter N1N2.
                              If this field is set to default value N1N2 is neither read or used*/
    uint8_t TypeIIRiRestr;  /* Restriction for RI for TypeII-RI-Restriction. BIT STRING (SIZE (2)).Default/Invalid value is 0xff */
    uint8_t Pad[2];
    uint8_t N1N2[18]; /* BIT STRING (SIZE (x)) where x depends on bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_* ; 139/8 is the maximum admitted value */
}PREFIX(bb_nr5g_CODEBOOK_SUBTYPE2_CFGt);

typedef struct {
    uint8_t PortSelSamplingSize; /* The size of the port selection codebook (parameter d)
                                    Enum[n1,n2,n3,n4]. Default/Invalid value is 0xff*/
    uint8_t TypeIIPortSelRiRestr;  /* Restriction for RI for TypeII-PortSelection-RI-Restriction.
                                    BIT STRING (SIZE (2)).Default/Invalid value is 0xff */
    uint8_t Pad[2];
}PREFIX(bb_nr5g_CODEBOOK_SUBTYPE2_PORTSELECTION_CFGt);

typedef struct {
    uint8_t CodeBookSubType2IsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_TYPE2_SUBTYPE_*
                                       in order to read in good way the associated parameter CodeBookSubType2.
                                       If this field is set to default value CodeBookSubType2 is neither read or used*/
    uint8_t PhaseAlphabetSize; /* The size of the PSK alphabet, QPSK or 8-PSK. Enum[n4, n8]. Default/Invalid value is 0xff */
    uint8_t SubbandAmplitude;  /* If subband amplitude reporting is activated (true). Range 0..1. Default/Invalid value is 0xff */
    uint8_t NumberOfBeams;     /* Number of beams, L, used for linear combination. Enum[{two, three, four]. Default/Invalid value is 0xff */
    union{
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE2_CFGt) TypeII;
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE2_PORTSELECTION_CFGt) TypeIIPortSel;
    } CodeBookSubType2;
}PREFIX(bb_nr5g_CODEBOOK_TYPE2_CFGt);

typedef struct {
    uint8_t CodeBookTypeIsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_TYPE_*
                                    in order to read in good way the associated parameter CodeBookType.
                                    If this field is set to default value CodeBookType is neither read or used*/
    uint8_t Pad[3];
    union{
        PREFIX(bb_nr5g_CODEBOOK_TYPE1_CFGt) CodeBookType1;
        PREFIX(bb_nr5g_CODEBOOK_TYPE2_CFGt) CodeBookType2;
    } CodeBookType;
}PREFIX(bb_nr5g_CODEBOOK_CFGt);

typedef struct {
    uint8_t PortIndexIsValid; /* This field assumes a value defined as bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_*
                              in order to read in good way the associated parameters NbPortIndexList/PortIndexList.
                              If this field is set to default value NbPortIndexList/PortIndexList is neither read or used */
    uint8_t NbPortIndexList; /*If PortIndexIsValid bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_2: Range 1..2
                            If PortIndexIsValid bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_4: Range 1..4
                            If PortIndexIsValid bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_8: Range 1..8
                            Default/Invalid value is 0*/
    uint8_t Pad[2];
    uint8_t PortIndexList[8];/*  If PortIndexIsValid bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_2: Range 0..1
                                    If PortIndexIsValid bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_4: Range 0..3
                                    If PortIndexIsValid bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_8: Range 0..7
                                    Default/Invalid value is 0xff*/
}PREFIX(bb_nr5g_PORT_INDEX_FOR8RANKSt);

typedef struct {
    uint8_t ReportSlotConfig_v1530; /* Enum[sl4, sl8, sl16]; Default 0xFF */
    uint8_t Pad[3];
} PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1530t);

typedef struct {
    uint8_t NbReportSlotOffsetListDCI_0_2_r16;
    uint8_t NbReportSlotOffsetListDCI_0_1_r16;
    uint8_t Pad[2];
    AFIELD(uint8_t, ReportSlotOffsetListDCI_0_2_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);
    AFIELD(uint8_t, ReportSlotOffsetListDCI_0_1_r16, bb_nr5g_MAX_NR_OF_UL_ALLOCATION);
} PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610t);

/* CodebookConfig-r16 IE */
typedef struct {
    uint8_t CodeBookSubType2IsValid; /* This field assumes a value defined as bb_nr5g_CODEBOOK_TYPE2_SUBTYPE_*
                                       in order to read in good way the associated parameter CodeBookSubType2.
                                       If this field is set to default value CodeBookSubType2 is neither read or used*/

    uint8_t NumberOfPMISubbandsPerCQISubband_r16;
    uint8_t ParamCombination_r16;
    uint8_t Pad;

    union{
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE2_CFGt) TypeII;
        PREFIX(bb_nr5g_CODEBOOK_SUBTYPE2_PORTSELECTION_CFGt) TypeIIPortSel;
    } CodeBookSubType2;
} PREFIX(bb_nr5g_CODEBOOK_TYPE2_CFG_R16t);

typedef struct {
    uint32_t FieldMask;
    uint8_t CsiRepCfgId; /* CSI-ReportConfigId. Range 0 ...(bb_nr5g_MAX_NB_CSI_REPORT_CFGS-1).
                           Default/Invalid value is 0xff*/
    uint8_t ResForChannelMeas;            /* CSI-ResourceConfigId: Range 0 ...(bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS)
                                            Default/Invalid value is 0xff*/
    uint8_t CsiIMResForInterference;    /* CSI-ResourceConfigId: Range 0 ...(bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS)
                                            Default/Invalid value is 0xff*/
    uint8_t NzpCsiRSResForInterference;        /* CSI-ResourceConfigId: Range 0 ...(bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS)
                                                Default/Invalid value is 0xff*/

    uint8_t Carrier;    /*Serving cell identifier */
    uint8_t TimeRestForChannelMeas    ;        /* Time domain measurement restriction for the channel (signal) measurements
                                            Enum [configured, notConfigured]
                                                Default/Invalid value is 0xff*/
    uint8_t TimeRestForInterferenceMeas;        /* Time domain measurement restriction for interference measurements
                                                Enum [configured, notConfigured]
                                                Default/Invalid value is 0xff*/
    uint8_t NrOfCQIsPerReport; /* ver 15.3 Maximum number of CQIs per CSI report. Enum [n1, n2]
                                  ver 15.4 It is a dummy field.
                                 Default/Invalid value is 0xff*/
    uint8_t GroupBasedBeamRepIsValid; /* This field assumes a value defined as bb_nr5g_CSI_REPORT_CFG_GROUP_BEAM_REP***
                              in order to read in good way the associated parameter GroupBasedBeamRepValue.
                              If this field is set to default value GroupBasedBeamRepValue is neither read or used */
    uint8_t GroupBasedBeamRepValue; /* If GroupBasedBeamRepIsValid=bb_nr5g_CSI_REPORT_CFG_GROUP_BEAM_REP_DISABLE
                                       this field is an Enum [n1, n2, n3, n4].Default/Invalid value is 0xff* */
    uint8_t CqiTable;        /* Which CQI table to use for CQI calculation
                                Enum [table1, table2] Default/Invalid value is 0xff*/
    uint8_t SubBandSize;        /* Indicates one out of two possible BWP-dependent values for the subband size
                                as indicated in 38.214 table 5.2.1.4-2
                                Enum [value1, value2] Default/Invalid value is 0xff*/
    uint8_t NbNonPmiPortInd;    /* Gives the number of valid elements in NonPmiPortInd vector: 1.bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES_PER_CFG
                               Default value is 0*/
    uint8_t ReportConfigTypeIsValid; /* This field assumes a value defined as bb_nr5g_CSI_REPORT_CFG_TYPE_***
                              in order to read in good way the associated parameter ReportConfigType.
                              If this field is set to default value ReportConfigType is neither read or used */
    uint8_t ReportQuantityIsValid;/* This field assumes a value defined as bb_nr5g_CSI_REPORT_CFG_QUANTITY_***
                                in order to read in good way the associated parameter ReportQuantity.
                                If this field is set to default value ReportQuantity is neither read or used
                                bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_CRI_SINR shall be used to set CriSinr_r16
                                bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_SSB_INDEX_SINR shall be used to set IndexSinr_r16 */
    union{
        uint8_t None;           /* 0. Default/Invalid value is 0xff */
        uint8_t CriRiPmiCqi;    /* 0. Default/Invalid value is 0xff */
        uint8_t CriRiI1;        /* 0. Default/Invalid value is 0xff */
        uint8_t CriRiI1Cqi;     /* Enum [n2, n4]. Default/Invalid value is 0xff */
        uint8_t CriRiCqi;       /* 0. Default/Invalid value is 0xff */
        uint8_t CriRsrp;        /* 0. Default/Invalid value is 0xff */
        uint8_t SsbIdxRsrp;     /* 0. Default/Invalid value is 0xff */
        uint8_t CriRiLiPmiCqi;  /* 0. Default/Invalid value is 0xff */
        uint8_t CriSinr_r16;    /* 0. Default/Invalid value is 0xff */
        uint8_t IndexSinr_r16;  /* 0. Default/Invalid value is 0xff */
    } ReportQuantity;
    union{
        PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODICt) RepCfgPer;
        PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCHt) RepCfgSemiPersOnPucch;
        PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCHt) RepCfgSemiPersOnPusch;
        PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_APERIODICt) RepCfgAper;
    } ReportConfigType;
    PREFIX(bb_nr5g_CSI_REPORT_FREQ_CFGt) RepFreqCfg;
    PREFIX(bb_nr5g_CODEBOOK_CFGt)  CodebookCfg;

#define bb_nr5g_STRUCT_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1530_PRESENT 0x0001
    VFIELD(PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1530t), SemiPersistentOnPUSCH_v1530);
#define bb_nr5g_STRUCT_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610_PRESENT 0x0002
    VFIELD(PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610t), SemiPersistentOnPUSCH_v1610);
#define bb_nr5g_STRUCT_CSI_REPORT_CFG_TYPE_APERIODIC_v1610_PRESENT 0x0004
    VFIELD(PREFIX(bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH_v1610t), Aperiodic_v1610);
#define bb_nr5g_STRUCT_CODEBOOK_CFG_TYPE2_R16_PRESENT 0x0008
    VFIELD(PREFIX(bb_nr5g_CODEBOOK_TYPE2_CFG_R16t), CodebookType2Cfg_r16);

    AFIELD(PREFIX(bb_nr5g_PORT_INDEX_FOR8RANKSt), NonPmiPortInd, bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES_PER_CFG); /*Dynamic list of NZP-CSI-RS-Resource which can be referred to from CSI-ResourceConfig */
} PREFIX(bb_nr5g_CSI_REPORT_CFGt);

/* 38.331 CSI-ResourceConfig IE: it refers to one or more NZP-CSI-RS-ResourceSet, CSI-IM-ResourceSet 
and/or CSI-SSB-ResourceSet.*/
typedef struct {
    uint8_t NbCsiImResourceSetList; /* Gives the number of valid elements in CsiImResourceSetList
                                        vector: 1...bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS_PER_CFG.
                                        Default value is 0*/
    uint8_t Pad[3];
    uint8_t CsiImResourceSetList[bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS_PER_CFG];
} PREFIX(bb_nr5g_CSI_RESOURCE_CFG_CSI_IMt);

typedef struct {
    uint8_t NbNzpCsiRsResourceSetList; /* Gives the number of valid elements in NzpCsiRsResourceSetList
                                        vector: 1...bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS_PER_CFG.
                                        Default value is 0*/
    uint8_t NbCsiSsbResourceSetList; /* Gives the number of valid elements in CsiSsbResourceSetList
                                        vector: 1...bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS_PER_CFG.
                                        Default value is 0*/
    uint8_t Pad;
    uint8_t CsiSsbResourceSetList[bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS_PER_CFG];
    uint8_t NzpCsiRsResourceSetList[bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS_PER_CFG];
} PREFIX(bb_nr5g_CSI_RESOURCE_CFG_NZP_CSI_RS_SSBt);

typedef struct {
    uint8_t CsiResId; /* Used in CSI-ReportConfig to refer to an instance of CSI-ResourceConfig
                         Range 0 ...(bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS-1)
                         Default/Invalid value is 0xff*/
    uint8_t BwpId;      /* DL BWP which the CSI-RS associated with this CSI-ResourceConfig are located in.
                        BwpId is used to refer to Bandwidth Parts (BWP). */
    uint8_t CsiResType; /* Time domain behavior of resource configuration
                        Enum [aperiodic, semiPersistent, periodic]; Default/Invalid value is 0xff **/
    uint8_t CsiRsResSetListIsValid; /* This field assumes a value defined as bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_***
                              in order to read in good way the associated parameter ReportQuantity.
                              If this field is set to default value ReportQuantity is neither read or used */
    union{
        PREFIX(bb_nr5g_CSI_RESOURCE_CFG_NZP_CSI_RS_SSBt) NzpCsiRsSsbResSetType;
        PREFIX(bb_nr5g_CSI_RESOURCE_CFG_CSI_IMt) CsiImResSetType;
    } CsiRsResSetListType;
} PREFIX(bb_nr5g_CSI_RESOURCE_CFGt);

/* 38.331 CSI-AperiodicTriggerStateList IE : itis used to configure the UE with a list of aperiodic trigger states.*/
/* 38.331 CSI-AssociatedReportConfigInfo IE */
typedef struct {
    uint8_t RepCfgId; /* The reportConfigId of one of the CSI-ReportConfigToAddMod configured in CSI-MeasConfig
                         Range 0....(bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS-1). Default/Invalid value is 0xff*/
    uint8_t CsiImResForInterference; /* CSI-IM-ResourceSet for interference measurement: Range 1 ...bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS_PER_CFG */
    uint8_t NzpCsiRsResForInterference; /* NZP-CSI-RS-ResourceSet for interference measurement: Range 1 ...bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS_PER_CFG */
    uint8_t ResForChannelIsValid; /* This field assumes a value defined as bb_nr5g_CSI_ASSOCIATED_REPORT_CFG_INFO_RES_FOR_CHANNEL_***
                              in order to read in good way the associated parameter GroupBasedBeamRepValue.
                              If this field is set to default value GroupBasedBeamRepValue is neither read or used */
    union {
        uint8_t  NzpCsiRsResSet; /* NZP-CSI-RS-ResourceSet for channel measurements: Range 1 ...bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS_PER_CFG */
        uint8_t  CsiSsbResSet;   /* CSI-SSB-ResourceSet for channel measurements: Range 1 ...bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS_PER_CFG */
    } ResForChannel;
    uint8_t NbQclInfo; /* Gives the number of valid elements in QclInfo vector: 1...bb_nr5g_MAX_NB_AP_CSI_RS_RESOURCES_PER_SET; Default value is 0
                          This field and the related vector can assume meaning only if ResForChannelIsValid = bb_nr5g_CSI_ASSOCIATED_REPORT_CFG_INFO_RES_FOR_CHANNEL_NZP_CSI_RS*/
    uint8_t Pad[2];
    uint8_t QclInfo[bb_nr5g_MAX_NB_AP_CSI_RS_RESOURCES_PER_SET];
}PREFIX(bb_nr5g_CSI_ASSOCIATED_REPORT_CFG_INFOt);

typedef struct {
    uint8_t NbAssRepCfInfoList; /* Gives the number of valid elements in AssRepCfInfoList vector: 1...bb_nr5g_MAX_NB_REP_CFG_APERIODIC_TRIGGERS; Default value is 0*/
    uint8_t Pad[3];
    AFIELD(PREFIX(bb_nr5g_CSI_ASSOCIATED_REPORT_CFG_INFOt), AssRepCfInfoList, bb_nr5g_MAX_NB_REP_CFG_APERIODIC_TRIGGERS); /*Dynamic list of CSI-AssociatedReportConfigInfo */
} PREFIX(bb_nr5g_CSI_APERIODIC_TRIGGER_STATE_CFGt);

/* 38.331 CSI-SemiPersistentOnPUSCH-TriggerState IE: it is used to configure the UE with list of trigger states for semi-persistent 
reporting of channel state information on L1*/
typedef struct {
    uint8_t CsiRepCfgId; /* Range 0..(bb_nr5g_MAX_NB_CSI_REPORT_CFGS-1); Default/invalid value is 0ff*/
    uint8_t Pad[3];
} PREFIX(bb_nr5g_CSI_SEMIPERSISTENT_ONPUSCH_TRIGGER_STATE_CFGt);

/* 38.331 CSI-MeasConfig IE: it is used to configure CSI-RS (reference signals) belonging to the serving cell in which CSI-MeasConfig is included and channel state information reports
to be transmitted on L1 (PUCCH, PUSCH) on the serving cell in which CSI-MeasConfig is included */
typedef struct {
    uint8_t NbNzpCsiRsResToAdd; /* Gives the number of valid elements in NzpCsiRsResToAdd vector: 1...bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES; Default value is 0*/
    uint8_t NbNzpCsiRsResToDel; /* Gives the number of valid elements in NzpCsiRsResToDel vector: 1...bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES; Default value is 0*/
    uint8_t NbNzpCsiRsResSetToAdd; /* Gives the number of valid elements in NzpCsiRsResSetToAdd vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbNzpCsiRsResSetToDel; /* Gives the number of valid elements in NzpCsiRsResSetToDel vector: 1...bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS; Default value is 0*/
    uint8_t NbCsiImResToAdd; /* Gives the number of valid elements in CsiImResToAdd vector: 1...bb_nr5g_MAX_NB_CSI_IM_RESOURCES; Default value is 0*/
    uint8_t NbCsiImResToDel; /* Gives the number of valid elements in CsiImResToDel vector: 1...bb_nr5g_MAX_NB_CSI_IM_RESOURCES; Default value is 0*/
    uint8_t NbCsiImResSetToAdd; /* Gives the number of valid elements in CsiImResSetToAdd vector: 1...bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS; Default value is 0*/
    uint8_t NbCsiImResSetToDel; /* Gives the number of valid elements in CsiImResSetToDel vector: 1...bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS; Default value is 0*/
    uint8_t NbCsiSsbResSetToAdd; /* Gives the number of valid elements in CsiSsbResSetToAdd vector: 1...bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS; Default value is 0*/
    uint8_t NbCsiSsbResSetToDel; /* Gives the number of valid elements in CsiSsbResSetToDel vector: 1...bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS; Default value is 0*/
    uint8_t NbCsiResCfgToAdd; /* Gives the number of valid elements in CsiResCfgToAdd vector: 1...bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS; Default value is 0*/
    uint8_t NbCsiResCfgToDel; /* Gives the number of valid elements in CsiResCfgToDel vector: 1...bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS; Default value is 0*/
    uint8_t NbCsiRepCfgToAdd; /* Gives the number of valid elements in CsiRepCfgToAdd vector: 1...bb_nr5g_MAX_NB_CSI_REPORT_CFGS; Default value is 0*/
    uint8_t NbCsiRepCfgToDel; /* Gives the number of valid elements in CsiRepCfgToDel vector: 1...bb_nr5g_MAX_NB_CSI_REPORT_CFGS; Default value is 0*/
    uint8_t NbAperTriggerStateList; /* Gives the number of valid elements in AperTriggerStateList vector: 1...bb_nr5g_MAX_NB_CSI_APERIODIC_TRIGGERS; Default value is 0*/
    uint8_t NbSPOnPuschTriggerStateList; /* Gives the number of valid elements in SPOnPuschTriggerStateList vector: 1...bb_nr5g_MAX_NB_SEMIPERS_ONPUSCH_TRIGGERS; Default value is 0*/
    uint8_t ReportTriggerSize; /*Size of CSI request field in DCI (bits). Range 0...6. Default/Invalid value is 0xff*/
    uint8_t ReportTriggerSizeDCI02_r16;  /*        Range (0..6)   */
    uint8_t Pad[2];

    AFIELD(PREFIX(bb_nr5g_NZP_CSI_RS_RES_CFGt), NzpCsiRsResToAdd, bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES); /*Dynamic list of NZP-CSI-RS-Resource which can be referred to from CSI-ResourceConfig */
    AFIELD(PREFIX(bb_nr5g_NZP_CSI_RS_RES_SET_CFGt), NzpCsiRsResSetToAdd, bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS); /*Dynamic list of NZP-CSI-RS-ResourceSet to be added/modify */
    AFIELD(PREFIX(bb_nr5g_CSI_IM_RES_CFGt), CsiImResToAdd, bb_nr5g_MAX_NB_CSI_IM_RESOURCES); /*Dynamic list of CSI-IM-Resource to be added/modify */
    AFIELD(PREFIX(bb_nr5g_CSI_IM_RES_SET_CFGt), CsiImResSetToAdd, bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS); /*Dynamic list of CSI-IM-ResourcSet to be added/modify */
    AFIELD(PREFIX(bb_nr5g_CSI_SSB_RES_SET_CFGt), CsiSsbResSetToAdd, bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS); /*Dynamic list of CSI-SSB-ResourceSet to be added/modify */
    AFIELD(PREFIX(bb_nr5g_CSI_RESOURCE_CFGt), CsiResCfgToAdd, bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS); /*Dynamic list of Configured CSI resource settings to be added/modify */
    AFIELD(PREFIX(bb_nr5g_CSI_REPORT_CFGt), CsiRepCfgToAdd, bb_nr5g_MAX_NB_CSI_REPORT_CFGS); /*Dynamic list of Configured CSI report settings to be added/modify */    
    AFIELD(PREFIX(bb_nr5g_CSI_APERIODIC_TRIGGER_STATE_CFGt), AperTriggerStateList, bb_nr5g_MAX_NB_CSI_APERIODIC_TRIGGERS); /*Dynamic list of aperiodic trigger states */    
    AFIELD(PREFIX(bb_nr5g_CSI_SEMIPERSISTENT_ONPUSCH_TRIGGER_STATE_CFGt), SPOnPuschTriggerStateList, bb_nr5g_MAX_NB_SEMIPERS_ONPUSCH_TRIGGERS); /*Dynamic list of aperiodic trigger states */
    AFIELD(uint32_t, NzpCsiRsResToDel, bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES); /*Dynamic list of NZP-CSI-RS-ResourceSet to be deleted */
    AFIELD(uint32_t, NzpCsiRsResSetToDel, bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS); /*Dynamic list of NZP-CSI-RS-ResourceSet to be deleted  */
    AFIELD(uint32_t, CsiImResToDel, bb_nr5g_MAX_NB_CSI_IM_RESOURCES); /*Dynamic list of CSI-IM-Resources to be deleted  */
    AFIELD(uint32_t, CsiImResSetToDel, bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS); /*Dynamic list of CSI-IM-ResourceSet to be deleted  */
    AFIELD(uint32_t, CsiSsbResSetToDel, bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS); /*Dynamic list of CSI-SSB-ResourceSet to be deleted  */
    AFIELD(uint32_t, CsiResCfgToDel, bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS); /*Dynamic list of CSI Resource Configurations to be deleted  */
    AFIELD(uint32_t, CsiRepCfgToDel, bb_nr5g_MAX_NB_CSI_REPORT_CFGS); /*Dynamic list of CSI Report to be deleted  */
} PREFIX(bb_nr5g_CSI_MEAS_CFGt);
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
} PREFIX(bb_nr5g_SCS_SPEC_CARRIERt);

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
    PREFIX(bb_nr5g_SCS_SPEC_CARRIERt) ScsSpecCarrier[bb_nr5g_MAX_SCS];
} PREFIX(bb_nr5g_FREQINFO_DLt);

/* 38.331 FrequencyInfoUL IE: provides basic parameters of an uplink carrier and transmission thereon */
typedef struct {
    uint32_t AbsFreqPointA; /* Absolute frequency position of the reference resource block (Common RB 0).
                               Default value is 0xFFFFFFFF; Range 0 ...3279165 */
    uint8_t AddSpectrumEmission; /* Additional spectrum emission requirements to be applied by the UE on this uplink.
                                 Default value is 0xFF; Range 0 ...7 */
    uint8_t FreqShift7p5khz;    /* Enable the NR UL transmission with a 7.5KHz shift to the LTE raster
                                 Default value is 0xFF; Enum [true]*/
    int8_t  PMax;               /* Range -30...33
                                Default value (any value out of valid range): If the field is absent, the UE applies the value FFS_RAN4*/
    uint8_t NbFreqBandList;     /* Gives the number of valid elements in FreqBandList vector:
                                    1...bb_nr5g_MAX_NB_MULTIBANDS; Default value is 0*/
    uint8_t NbScsSpecCarrier;     /* Gives the number of valid elements in ScsSpecCarrier vector:
                                    1...bb_nr5g_MAX_SCS; Default value is 0*/
    uint8_t Spare[3];
    uint16_t FreqBandList[bb_nr5g_MAX_NB_MULTIBANDS]; /*Range 1...1024 for every element*/
    PREFIX(bb_nr5g_SCS_SPEC_CARRIERt) ScsSpecCarrier[bb_nr5g_MAX_SCS];
} PREFIX(bb_nr5g_FREQINFO_ULt);

/****************************************************************************************/
/* 38.331: RateMatchPatternLTE-CRS IE is used to configure a pattern to rate match around LTE CRS */
typedef struct {
    uint8_t RadioFrameAllocPeriod;  /* Field as defined in MBSFN-SubframeConfig in TS 36.331 [10], 
                                        where SFN refers to the SFN of the NR serving cell.
                                        Enum: [n1, n2, n4, n8, n16, n32]; Default value is 0xFF*/
    uint8_t RadioFrameAllocOffset;  /* Field as defined in MBSFN-SubframeConfig in TS 36.331 [10], 
                                        where SFN refers to the SFN of the NR serving cell.
                                        Range [0...7]; Default value is 0xFF*/
    uint8_t SubframeAlloc1IsValid;   /* This field assumes a value defined as bb_nr5g_MBSFN_SUBFRAME_ALLOC_*** in order to read
                                       in good way the associated bitmap SubframeAlloc1*/
    uint8_t SubframeAlloc2IsValid;   /* This field assumes a value defined as bb_nr5g_MBSFN_SUBFRAME_ALLOC_*** in order to read
                                       in good way the associated bitmap SubframeAlloc2*/
    uint8_t SubframeAlloc2; /* if SubframeAlloc2IsValid = bb_nr5g_MBSFN_SUBFRAME_ALLOC_ONE_FRAME : SubframeAlloc2 is 
                                BIT STRING (SIZE(2))
                                if SubframeAlloc2IsValid = bb_nr5g_MBSFN_SUBFRAME_ALLOC_FOUR_FRAMES: SubframeAlloc2 is 
                                BIT STRING (SIZE(8))
                                if SubframeAlloc2IsValid = bb_nr5g_MBSFN_SUBFRAME_ALLOC_DEFAULT: SubframeAlloc2 is not read */
    uint8_t Pad[3];
    uint32_t SubframeAlloc1; /* if SubframeAlloc1IsValid = bb_nr5g_MBSFN_SUBFRAME_ALLOC_ONE_FRAME : SubframeAlloc1 is 
                                BIT STRING (SIZE(6))
                                if SubframeAlloc1IsValid = bb_nr5g_MBSFN_SUBFRAME_ALLOC_FOUR_FRAMES: SubframeAlloc1 is 
                                BIT STRING (SIZE(24))
                                if SubframeAlloc1IsValid = bb_nr5g_MBSFN_SUBFRAME_ALLOC_DEFAULT: SubframeAlloc1 is not read */

} PREFIX(bb_nr5g_EUTRA_MBSFN_SUBFRAME_CFGt);

typedef struct {
    uint16_t CarrierFreqDL; /* Center of the LTE carrier (see TS 38.214 [19], clause 5.1.4.2). 
                               Range [0..16383]; Default value is 0xFFFF*/
    uint8_t  CarrierBwDL;   /* BW of the LTE carrier in number of PRBs (see TS 38.214 [19], clause 5.1.4.2). 
                               Enum: [n6, n15, n25, n50, n75, n100]; Default value is 0xFF*/
    uint8_t  NrOfCrsPorts;   /*Number of LTE CRS antenna port to rate-match around (see TS 38.214 [19], clause 5.1.4.2). 
                               Enum: [n1, n2, n4]; Default value is 0xFF*/
    uint8_t  VShift;        /* Shifting value v-shift in LTE to rate match around LTE CRS (see TS 38.214 [19], clause 5.1.4.2).. 
                               Enum: [n0, n1, n2, n3, n4, n5]; Default value is 0xFF*/
    uint8_t  NbMbsfnAlloc;  /* Gives the number of valid elements in MbsfnAlloc vector: 1...bb_nr5g_MAX_MBSFN_ALLOCATIONS; 
                                Default value is 0*/
    uint8_t  Pad[2];
    PREFIX(bb_nr5g_EUTRA_MBSFN_SUBFRAME_CFGt) MbsfnAlloc[bb_nr5g_MAX_MBSFN_ALLOCATIONS]; /*Static list of MBSFN allocations */
} PREFIX(bb_nr5g_RATE_MATCH_PATTERN_LTEt);

/****************************************************************************************/
/* 38.331 NR_PhysicalCellGroupConfig_dcp_Config_r16 */
typedef struct {
    uint16_t Ps_RNTI_r16;
    uint8_t Ps_Offset_r16;
    uint8_t SizeDCI_2_6_r16;
    uint8_t Ps_PositionDCI_2_6_r16;
    uint8_t Ps_WakeUp_r16; /* Enum[true]; Default is 0xFF */
    uint8_t Ps_TransmitPeriodicL1_RSRP_r16; /* Enum[true]; Default is 0xFF */
    uint8_t Ps_TransmitOtherPeriodicCSI_r16; /* Enum[true]; Default is 0xFF */
} PREFIX(bb_nr5g_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16t);

/* 38.331 NR_PhysicalCellGroupConfig_pdcch_BlindDetectionCA_CombIndicator_r16 */
typedef struct {
    uint8_t Pdcch_BlindDetectionCA1_r16; /* Range (1..15) */
    uint8_t Pdcch_BlindDetectionCA2_r16; /* Range (1..15) */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16t);

/* 38.331 PhysicalCellGroupConfig: Cell-Group specific L1 parameters                    */
typedef struct {
    uint32_t FieldMask;
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
    uint8_t  PdschHarqACKCodebook;      /*  The PDSCH HARQ-ACK codebook is either semi-static of dynamic.
                                            This is applicable to both CA and none CA operation
                                            Default value is 0xFF; Enum [semiStatic, dynamic]*/
    uint8_t McsCRntiValid;              /*  This parameter handles if the McsCRnti has to be considered as optional or not.
                                            If this parameter is set to 0 -> McsCRnti field is not read because not valid */

    uint16_t McsCRnti;                  /*  RNTI to indicate use of qam64LowSE for grant-based transmissions. When the
                                            mcs-C-RNTI is configured, RNTI scrambling of DCI CRC is used to choose the
                                            corresponding MCS table */
    int8_t PUE_FR1;                     /* Range [-30...33]*/
    uint32_t TpcSrsRNTI;                /* RNTI-Value := Range (0..65535): Default value is 0xFFFFFFFF */
    uint32_t TpcPucchRNTI;              /* RNTI-Value := Range (0..65535) */
    uint32_t TpcPuschRNTI;              /* RNTI-Value := Range (0..65535) */
    uint32_t SpCsiRNTI;                 /* RNTI-Value := Range (0..65535) */
    uint32_t CsRNTI;                    /* RNTI-Value := Range (0..65535); Default value is 0xFF */

    uint8_t Pdcch_BlindDetection; /* Range (1..15); Default value is 0xFF */
    uint8_t Harq_ACK_SpatialBundlingPUCCH_secondaryPUCCHgroup_r16; /* Enum[enabled, disabled] */
    uint8_t Harq_ACK_SpatialBundlingPUSCH_secondaryPUCCHgroup_r16; /* Enum[enabled, disabled] */
    uint8_t Pdsch_HARQ_ACK_Codebook_secondaryPUCCHgroup_r16; /* Enum[semiStatic, dynamic] */
    int8_t P_NR_FR2_r16; /* Range (-30..33) */
    int8_t P_UE_FR2_r16; /* Range (-30..33) */
    uint8_t Nrdc_PCmode_FR1_r16; /* Enum[isemi-static-mode1, semi-static-mode2, dynamic] */
    uint8_t Nrdc_PCmode_FR2_r16; /* Enum[isemi-static-mode1, semi-static-mode2, dynamic] */
    uint8_t Pdsch_HARQ_ACK_Codebook_r16; /* Enum[enhancedDynamic]; Default 0xFF */
    uint8_t Nfi_TotalDAI_Included_r16; /* Enum[true]; Default 0xFF */
    uint8_t Ul_TotalDAI_Included_r16; /* Enum[true]; Default 0xFF */
    uint8_t Pdsch_HARQ_ACK_OneShotFeedback_r16; /* Enum[true]; Default 0xFF */
    uint8_t pdsch_HARQ_ACK_OneShotFeedbackNDI_r16; /* Enum[true]; Default 0xFF */
    uint8_t pdsch_HARQ_ACK_OneShotFeedbackCBG_r16; /* Enum[true]; Default 0xFF */
    uint8_t DownlinkAssignmentIndexDCI_0_2_r16; /* Enum[enabled]; Default 0xFF */
    uint8_t DownlinkAssignmentIndexDCI_1_2_r16; /* Enum[n1, n2, n4]; Default 0xFF */
    uint8_t NbPdsch_HARQ_ACK_CodebookList_r16;
    uint8_t AckNackFeedbackMode_r16; /* Enum[joint, separate]; Default 0xFF */
    uint8_t Pdcch_BlindDetection2_r16; /* Range (1..15) */
    uint8_t Pdcch_BlindDetection3_r16; /* Range (1..15) */
    uint8_t BdFactorR_r16; /* Enum[n1]; Default 0xFF */
    uint8_t Pdsch_HARQ_ACK_CodebookList_r16[2]; /* Enum[semiStatic, dynamic]; Default 0xFF */
    uint8_t Pad;

#define bb_nr5g_STRUCT_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16_PRESENT 0x0001
    PREFIX(bb_nr5g_PH_CELL_GROUP_CONFIG_DCP_CONFIG_R16t) Dcp_Config_r16;
#define bb_nr5g_STRUCT_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16_PRESENT 0x0002
    PREFIX(bb_nr5g_PDCCH_BLIND_DETECTION_CA_COMB_INDICATOR_R16t) Pdcch_BlindDetectionCA_CombIndicator_r16;
} PREFIX(bb_nr5g_PH_CELL_GROUP_CONFIGt);

/* HighSpeedConfig-r16 IE */
typedef struct
{
    uint8_t HighSpeedMeasFlag_r16;    /* Default value is 0xFF that means apply the enhanced RRM requirements to support high speed up to 500 km/h as specified in TS 38.133. Enum [true] */
    uint8_t HighSpeedDemodFlag_r16;   /* If the field is present, the UE shall apply the enhanced demodulation processing for HST-SFN joint transmission scheme with velocity up to 500km/h as specified in TS 38.101-4 */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_HIGH_SPEED_CONFIG_R16t);

/****************************************************************************************/
/* 38.331 ServingCellConfigCommon IE: it is used to configure cell specific parameters of a UE’s serving cell*/
typedef struct {
    /* Field mask according to bb_nr5g_STRUCT_SERV_CELL_CONFIG_COMMON***_PRESENT
       As a first implementation this bitmap tell which fields/structures have filled with valid values
       In future implementation this bitmap would be able to support messages with a complete dynamic size */
    uint32_t FieldMask;
    uint16_t ServCellIdx;
    uint8_t SsbPeriodicityServCell; /* SSB periodicity in msec for the rate matching purpose
                                       Default value is 0xFF; Enum [ms5, ms10, ms20, ms40, ms80, ms160]*/
    uint8_t DmrsTypeAPos;           /* Position of (first) DL DM-RS
                                       Default value is 0xFF; Enum [pos2, pos3]*/
    uint8_t SubCarSpacing;          /* Subcarrier spacing of SSB
                                       Enum [kHz15, kHz30, kHz60, kHz120, kHz240]; Default/Invalid value is 0xFF*/
    uint8_t SsbPosInBurstIsValid;   /* This field assumes a value defined as bb_nr5g_SSB_POS_IN_BURST_*** in order to read
                                       in good way the associated bitmap */
    uint8_t NTimingAdvanceOffset;   /* The N_TA-Offset to be applied for random access on this serving cell. If the field is absent, 
                                       the UE applies the value defined for the duplex mode and frequency range of this serving cell.
                                       Enum [n0, n25600, n39936]; Default/Invalid value is 0xFF*/
    uint8_t Pad;
    union {
        uint8_t  ShortBitmap;    /* bitmap for sub 3 GHz */
        uint8_t  MediumBitmap;   /* bitmap for sub 3-6 GHz */
        uint64_t  LongBitmap;    /* bitmap for sub above 6 GHz */
    } SsbPosInBurst;

    int16_t PBCHBlockPower;             /* TX power that the NW used for SSB transmission.
                                           The UE uses it to estimate the RA preamble TX power
                                           Range[-60..50] */
    uint8_t NbRateMatchPatternToAddMod; /* Gives the number of valid elements in RateMatchPatternToAddMod vector:
                                           1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternToDel;    /* Gives the number of valid elements in RateMatchPatternToDel vector:
                                           1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_FREQINFO_DL_COMMON_PRESENT   0x0001
    PREFIX(bb_nr5g_FREQINFO_DLt) FreqInfoDL;
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_BWP_DL_COMMON_PRESENT   0x0002
    PREFIX(bb_nr5g_BWP_DOWNLINKCOMMONt) InitDLBWP;    /* Initial downlink BWP configuration */

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_FREQINFO_UL_COMMON_PRESENT   0x0004
    PREFIX(bb_nr5g_FREQINFO_ULt) FreqInfoUL;
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_BWP_UL_COMMON_PRESENT   0x0008
    PREFIX(bb_nr5g_BWP_UPLINKCOMMONt) InitULBWP;      /* Initial uplink BWP configuration */

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_FREQINFO_SUL_COMMON_PRESENT   0x0010
    PREFIX(bb_nr5g_FREQINFO_ULt) FreqInfoSUL;
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_BWP_SUL_COMMON_PRESENT   0x0020
    PREFIX(bb_nr5g_BWP_UPLINKCOMMONt) InitSULBWP;     /* Initial supplementary uplink BWP configuration */

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_TDD_COMMON_PRESENT   0x0040
    PREFIX(bb_nr5g_TDD_UL_DL_CONFIG_COMMONt) TddDlUlConfCommon;  /* A cell-specific TDD UL/DL configuration */

    uint8_t RateMatchPatternToDel[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS];/* List of RateMatchPatternId*/
    PREFIX(bb_nr5g_RATE_MATCH_PATTERNt) RateMatchPatternToAddMod[bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS]; 

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_COMMON_TOMATCHAROUND_PRESENT   0x0080
    PREFIX(bb_nr5g_RATE_MATCH_PATTERN_LTEt) LteCrsToMatchAround;

#define bb_nr5g_STRUCT_HIGH_SPEED_CONFIG_R16_PRESENT 0x0100
    PREFIX(bb_nr5g_HIGH_SPEED_CONFIG_R16t) HighSpeedConfig_r16;
} PREFIX(bb_nr5g_SERV_CELL_CONFIG_COMMONt);

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
    uint8_t NbDlBwpScsSpecCarrier;  /* Gives the number of valid elements in DlChannelBwPerScs vector:
                                    1...bb_nr5g_MAX_SCS; Default value is 0*/
    uint8_t NbRateMatchPatternDedToAdd;  /* Gives the number of valid elements in RateMatchPatternDedToAdd vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t NbRateMatchPatternDedToDel;  /* Gives the number of valid elements in RateMatchPatternDedToDel vector: 1...bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS; Default value is 0*/
    uint8_t Pad;
    uint8_t DlBwpIdToDel[bb_nr5g_MAX_NB_BWPS]; /*Static list of additional downlink bandwidth parts to be released*/
    /* The dedicated (UE-specific) configuration for the initial downlink bandwidth-part*/
#define bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_INITIAL_DL_BWP_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_BWP_DOWNLINKDEDICATEDt), InitialDlBwp);
#define bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDSCH_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_PDSCH_SERVING_CELL_CFGt), PdschServingCellCfg);
#define bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_PDCCH_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_PDCCH_SERVING_CELL_CFGt), PdcchServingCellCfg);
#define bb_nr5g_STRUCT_DOWNLINK_DEDICATED_CONFIG_CSI_MEAS_CFG_PRESENT   0x0008
    VFIELD(PREFIX(bb_nr5g_CSI_MEAS_CFGt), CsiMeasCfg);
    AFIELD(PREFIX(bb_nr5g_BWP_DOWNLINKt), DlBwpIdToAdd, bb_nr5g_MAX_NB_BWPS); /*Dynamic list of additional downlink bandwidth parts to be added/modified*/
    AFIELD(PREFIX(bb_nr5g_SCS_SPEC_CARRIERt), DlChannelBwPerScs, bb_nr5g_MAX_SCS); /*Dynamic list of A set of UE specific carrier configurations for different subcarrier spacings (numerologies). */
    AFIELD(PREFIX(bb_nr5g_RATE_MATCH_PATTERNt), RateMatchPatternDedToAdd, bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS);  /* Dynamic Resources patterns which the UE should rate match PDSCH around to bee added/modified.*/
    AFIELD(uint32_t, RateMatchPatternDedToDel, bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS); /* Dynamic list of Resources patterns identifiers to be deleted.*/
} PREFIX(bb_nr5g_DOWNLINK_DEDICATED_CONFIGt);

typedef struct {
    /* Field mask according to bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG***_PRESENT */
    uint32_t FieldMask;
    uint8_t FirstActiveUlBwp; /* If configured for an SpCell, this field contains the ID of the UL BWP to be activated upon performing the reconfiguration
                                 in which it is received. If the field is absent, the RRC reconfiguration does not impose a BWP switch.
                                 If configured for an SCell, this field contains the ID of the downlink bandwidth part to be used upon MAC-activation of an SCell.
                                 If not provided, the UE uses the default BWP.
                                 The initial bandwidth part is referred to by BwpId = 0.
                                 Range 0....(bb_nr5g_MAX_NB_BWPS-1); Default value is 0xFF*/
    uint8_t PowerBoostPi2BPSK; /*If this field is set to TRUE, the UE determines the maximum output 
                                power for PUCCH/PUSCH transmissions that use pi/2 BPSK modulation
                                Range 0....1; Default value is 0xFF*/
    uint8_t NbUlBwpIdToDel; /* Gives the number of valid elements in UlBwpIdToDel vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t NbUlBwpIdToAdd; /* Gives the number of valid elements in UlBwpIdToAdd vector: 1...bb_nr5g_MAX_NB_BWPS; Default value is 0*/
    uint8_t NbUlBwpScsSpecCarrier;  /* Gives the number of valid elements in ScsSpecCarrier vector:
                                    1...bb_nr5g_MAX_SCS; Default value is 0*/
    uint8_t Pad[3];
    uint8_t UlBwpIdToDel[bb_nr5g_MAX_NB_BWPS]; /*Static list of additional uplink bandwidth parts to be released*/
    /* The dedicated (UE-specific) configuration for the initial uplink bandwidth-part*/
#define bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_INITIAL_UL_BWP_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_BWP_UPLINKDEDICATEDt), InitialUlBwp);
#define bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_PUSCH_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_PUSCH_SERVING_CELL_CFGt), PuschServingCellCfg);
    AFIELD(PREFIX(bb_nr5g_BWP_UPLINKt), UlBwpIdToAdd, bb_nr5g_MAX_NB_BWPS); /*Dynamic list of additional uplink bandwidth parts to be added/modified*/
#define bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_SRS_CARRIER_SWITCHING_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_SRS_CARRIER_SWITCHING_CFGt), CarrierSwitching);

#define bb_nr5g_STRUCT_UPLINK_DEDICATED_CONFIG_PUSCH_RELEASE   0x0008

    AFIELD(PREFIX(bb_nr5g_SCS_SPEC_CARRIERt), UlChannelBwPerScs, bb_nr5g_MAX_SCS); /*Dynamic list of A set of UE specific carrier configurations for different subcarrier spacings (numerologies). */
} PREFIX(bb_nr5g_UPLINK_DEDICATED_CONFIGt);

typedef struct {
    uint8_t  SchedCellIsValid;       /* This field assumes a value defined as bb_nr5g_CROSS_CARRIER_SCHED_CFG_***
                                       in order to read in good way the associated parameters .
                                       If this field is set to default value anything more is neither read or used */
    uint8_t  CifPresence;           /* This field can assume meaning only if SchedCellIsValid is set to bb_nr5g_CROSS_CARRIER_SCHED_CFG_OWN.
                                       Range 0..1. Invalid value is 0xFF*/
    uint8_t  CifInSchedulingCell;   /* This field can assume meaning only if SchedCellIsValid is set to bb_nr5g_CROSS_CARRIER_SCHED_CFG_OTHER.
                                       Range 1..7. Invalid value is 0xFF*/                 
   uint8_t   ServCellIdx;           /* This field can assume meaning only if SchedCellIsValid is set to bb_nr5g_CROSS_CARRIER_SCHED_CFG_OTHER.
                                       Invalid value is 0xFF*/                 
} PREFIX(bb_nr5g_CROSS_CARRIER_SCHEDULING_CONFIGt);

/* 38.331 NR_WithinActiveTimeConfig_r16 */                                                                                                                                                                         
typedef struct {
    uint8_t FirstWithinActiveTimeBWP_Id_r16; /* 0xFF */
    uint8_t DormancyGroupWithinActiveTime_r16; /* 0xFF */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_DORMANTBWP_WITHINt);

/* 38.331 NR_OutsideActiveTimeConfig_r16 */
typedef struct {
    uint8_t FirstOutsideActiveTimeBWP_Id_r16; /* 0xFF */
    uint8_t DormancyGroupOutsideActiveTime_r16; /* 0xFF */
    uint8_t Pad[2];
} PREFIX(bb_nr5g_DORMANTBWP_OUTSIDEt);

/* 38.331 NR_ServingCellConfig_dormantBWP_Config_r16
 * NR_DormantBWP_Config_r16
 * */
typedef struct {
    uint8_t FieldMask;
    uint8_t DormantBWP_Id_r16;
    uint8_t Pad[2];
#define bb_nrg5_STRUCT_DORMANTBWP_WITHIN_PRESENT 0x0001
    VFIELD(PREFIX(bb_nr5g_DORMANTBWP_WITHINt), WithinActiveTimeConfig_r16);
#define bb_nrg5_STRUCT_DORMANTBWP_OUTSIDE_PRESENT 0x0002
    VFIELD(PREFIX(bb_nr5g_DORMANTBWP_OUTSIDEt), OutsideActiveTimeConfig_r16);
} PREFIX(bb_nr5g_DORMANTBWP_CONFIGt);

typedef struct {
    /* Field mask according to bb_nr5g_STRUCT_SERV_CELL_CONFIG_***_PRESENT */
    uint32_t FieldMask;
    uint32_t ServCellIdx;
    uint8_t  BwpInactivityTimer; /* The duration in ms after which the UE falls back to the default Bandwidth Part
                                    Enum: [ms2, ms3, ms4, ms5, ms6, ms8, ms10, ms20, ms30, ms40,ms50, ms60, ms80,ms100, ms200,ms300, ms500,
                                           ms750, ms1280, ms1920, ms2560]. Invalid value is 0xFF */
    uint8_t  TagId;             /* Timing Advance Group ID. Range 0 ...(bb_nr5g_MAX_NB_OF_TAGS-1); Invalid value is 0xFF*/
    uint8_t  SCellDeactTimer;   /*  SCell deactivation timer 
                                    Enum: [ms20, ms40, ms80, ms160, ms200, ms240,ms320, ms400, ms480, ms520, ms640, ms720, ms840, ms12800]. 
                                    Invalid value is 0xFF that means infinity timer */
    uint8_t dummy;              /*  Until to 15.4 this field was devoted to Enables the "UE beam lock function (UBF)", 
                                    which disable changes to the UE beamforming configuration when in NR_RRC_CONNECTED 
                                    In 15.5 dummy field. Enum[Enabled]. Invalid value is 0xFF*/    
    uint8_t PathlossRefLinking ; /* Indicates whether UE shall apply as pathloss reference either the downlink of PCell or of SCell that corresponds with this uplink. 
                                    Enum[pCell, sCell]. Invalid value is 0xFF*/   
    uint8_t ServCellMO;         /*  measObjectId of the MeasObjectNR in MeasConfig which is associated to the serving cell.
                                    Range 1 ...bb_nr5g_MAX_NB_OF_OBJECT_ID. Invalid value is 0xFF*/ 

    uint8_t DefaultDlBwpId;         /* 1 to bb_nr5g_MAX_NB_BWPS; Default/Absent 0xFF */
    uint8_t SupplUlRel;             /* Enum[true]; Default 0xFF */
    uint8_t CaSlotOffsetIsValid;    /* This field assumes a value defined as bb_nr5g_CA_SLOT_OFFSET_REF_*** */
    uint8_t NbLteCrsPatternList1_r16;
    uint8_t NbLteCrsPatternList2_r16;

    union {
        int8_t refSCS15kHz; /* Range(-2..2) */
        int8_t refSCS30KHz; /* Range(-5..5) */
        int8_t refSCS60KHz; /* Range(-10..10) */
        int8_t refSCS120KHz; /* Range(-20..20) */
    } CaSlotOffset_r16;

    uint8_t CsiRsValidWithDCI_r16; /* Enum[enabled]; Default 0xFF */
    uint8_t CrsRateMatchPerCORESETPoolIdx_r16; /* Enum[enabled]; Default 0xFF */
    uint8_t EnableTwoDefaultTCIStates_r16; /* Enum[enabled]; Default 0xFF */
    uint8_t EnableDefTCIStatePerCoresetPoolIdx_r16; /* Enum[enabled]; Default 0xFF */
    uint8_t EnableBeamSwitchTiming_r16; /* Enum[true]; Default 0xFF */
    uint8_t CbgTxDiffTBsProcessingType1_r16; /* Enum[enabled]; Default 0xFF */
    uint8_t CbgTxDiffTBsProcessingType2_r16; /* Enum[enabled]; Default 0xFF */
    uint8_t FirstActiveUlBwp_pCell; /* The FirstActiveUlBwp of the SpCell. See bb_nr5g_UPLINK_DEDICATED_CONFIGt */

#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_TDD_DED_PRESENT   0x0001
    VFIELD(PREFIX(bb_nr5g_TDD_UL_DL_CONFIG_DEDICATEDt), TddDlUlConfDed);  /* A cell-specific TDD UL/DL configuration */
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_DOWNLINK_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_DOWNLINK_DEDICATED_CONFIGt), DlCellCfgDed);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_UPLINK_PRESENT   0x0004
    VFIELD(PREFIX(bb_nr5g_UPLINK_DEDICATED_CONFIGt), UlCellCfgDed);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_SUP_UPLINK_PRESENT   0x0008
    VFIELD(PREFIX(bb_nr5g_UPLINK_DEDICATED_CONFIGt), SulCellCfgDed);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_CROSS_CARRIER_SCHED_PRESENT   0x0010
    VFIELD(PREFIX(bb_nr5g_CROSS_CARRIER_SCHEDULING_CONFIGt), CrossCarrierSchedulingConfig);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_TOMATCHAROUND_PRESENT   0x0020
    VFIELD(PREFIX(bb_nr5g_RATE_MATCH_PATTERN_LTEt), LteCrsToMatchAround);

#define bb_nr5g_STRUCT_DORMANTBWP_CONFIG_PRESENT 0x0080
    VFIELD(PREFIX(bb_nr5g_DORMANTBWP_CONFIGt), DormantBWP_Config_r16);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_PATTERN_LIST1_PRESENT   0x0100
    AFIELD(PREFIX(bb_nr5g_RATE_MATCH_PATTERN_LTEt), LteCrsPatternList1_r16, bb_nr5g_MAX_LTE_CRS_PATTERNS_R16);
#define bb_nr5g_STRUCT_SERV_CELL_CONFIG_LTE_CRS_PATTERN_LIST2_PRESENT   0x0200
    AFIELD(PREFIX(bb_nr5g_RATE_MATCH_PATTERN_LTEt), LteCrsPatternList2_r16, bb_nr5g_MAX_LTE_CRS_PATTERNS_R16);
} PREFIX(bb_nr5g_SERV_CELL_CONFIGt);

/****************************************************************************************/
/* 38.331 CellGroupConfig IE: it is used to configure a master cell group (MCG) or secondary cell group (SCG). 
   In BB this primitive is used to configure cell specific parameters of current serving cell */
typedef struct {
    /* Cell-Group specific L1 parameters */
    PREFIX(bb_nr5g_PH_CELL_GROUP_CONFIGt) PhyCellConf;
    /* Current cell parameter configuration : typically this part of message contains parameters which are acquired
       from SSB, MIB or SIBs*/
    PREFIX(bb_nr5g_SERV_CELL_CONFIG_COMMONt) CellCfgCommon;
} PREFIX(bb_nr5g_CELL_GROUP_CONFIGt);

/****************************************************************************************/
/* 38.331 SCellConf IE: it is used to configure secondary cell for a specific UE */
typedef struct {
    /* To simplify the handling we decide to have ServCellIdx also at this level*/
    uint16_t ServCellIdx;
    /* Field mask according to bb_nr5g_STRUCT_SCELL_CONFIG_***_PRESENT */
    uint32_t FieldMask;
    uint8_t sCellState_r16;                /*   Enum {activated} */
    uint8_t Pad;

#define bb_nr5g_STRUCT_SCELL_CONFIG_DED_PRESENT   0x0001
    /* Secondary cell dedicated parameter configuration */
    VFIELD(PREFIX(bb_nr5g_SERV_CELL_CONFIGt), SCellCfgDed);
#define bb_nr5g_STRUCT_SCELL_CONFIG_COMMON_PRESENT   0x0002
    /* Secondary cell common parameter configuration. This structure has been put in interface but actually it is not 
       used. So it is not needed to handle its filling */
    VFIELD(PREFIX(bb_nr5g_SERV_CELL_CONFIG_COMMONt), SCellCfgCommon);
} PREFIX(bb_nr5g_SCELL_CONFIGt);

/****************************************************************************************/
/* 38.331 CellGroupConfig IE: Serving cell specific MAC and PHY parameters for a SpCell and for SCell*/
typedef struct {
    /*  Message static part has to be put at the beginning */
    uint8_t NbSCellCfgAdd;     /* Gives the number of valid elements in SCellCfgAdd vector:
                                   1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0*/
    uint8_t NbSCellCfgDel;     /* Gives the number of valid elements in SCellCfgDel vector:
                                   1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0*/
    /* Field mask according to bb_nr5g_STRUCT_SPCELL_CONFIG_***_PRESENT */
    uint8_t FieldMask;
    uint8_t SetupReconf;       /* Indicates if message is triggered by a RrcSetup(=1) or RrcReconfiguration(=2).
                                  Invalid value is 0xFF. */
    /* Cell-Group specific L1 parameters */
    PREFIX(bb_nr5g_PH_CELL_GROUP_CONFIGt) PhyCellConf;
    /* Primary cell dedicated parameter configuration */
#define bb_nr5g_STRUCT_SPCELL_CONFIG_DED_PRESENT   0x0001
    PREFIX(bb_nr5g_SERV_CELL_CONFIGt) SpCellCfgDed;
    /* Primary cell common parameter configuration. This structure has meaning when RNTI is created in a not PCell.
       This structure has been put in interface but actually it is not used. So it is not needed to handle its filling */
#define bb_nr5g_STRUCT_SPCELL_CONFIG_COMMON_PRESENT   0x0002
    VFIELD(PREFIX(bb_nr5g_SERV_CELL_CONFIG_COMMONt), SpCellCfgCommon);
    AFIELD(PREFIX(bb_nr5g_SCELL_CONFIGt), SCellCfgAdd, bb_nr5g_MAX_NB_SERVING_CELLS); /* Dynamic list of aggregable cells to be added or to modified */
    AFIELD(uint32_t, SCellCfgDel, bb_nr5g_MAX_NB_SERVING_CELLS); /*Dynamic list of serving cell id of aggregable cells to be deleted */
} PREFIX(bb_nr5g_CELL_DEDICATED_CONFIGt);

/*******************************************************************************************/
/* bb_nr5g_RNTI_MEASSET structures to configure BLER simulation for Link Adaptation feature*/
typedef struct {
    /* (Number of layers / number of RX antennas) 
        We can see 8 different combinations according to number of layers (1..8) and to number of RX antennas
        (2,4 or 8). number of RX antennas >= number of layers
        This field is an Enum [1, 2, 4, 4/3, 8/7, 8/6, 8/5, 8/3] as described in bb_nr5g_RNTI_MULTI_ANT_DIV_*
    */
    uint8_t  MultiAntDiv; 
    uint8_t  Pad;
    uint16_t Bler;      /* BLER for this channels */
}PREFIX(bb_nr5g_MEASSET_ANT_DIV_BLER_SIMt);

typedef struct {
    uint8_t Mcs;             /* MCS */
    uint8_t NumBlerAntDiv;   /* Number of valid elements in BlerAntDiv vector: 1..bb_nr5g_RNTI_NUM_MULTI_ANT_DIV*/
    uint8_t Pad[2];
    /* Vector of BLER configuration for this channels */
    AFIELD(PREFIX(bb_nr5g_MEASSET_ANT_DIV_BLER_SIMt), BlerAntDiv, bb_nr5g_RNTI_NUM_MULTI_ANT_DIV);    
}PREFIX(bb_nr5g_MEASSET_MCS_BLER_SIMt);

typedef struct {
    uint8_t NumBlerMcs; /* Number of valid elements in BlerMcs vector. Default value is 0 */
    uint8_t Pad[3];
    /* DL BLER to be simulated for every specified MCS */
    AFIELD(PREFIX(bb_nr5g_MEASSET_MCS_BLER_SIMt), BlerMcs, bb_nr5g_RNTI_NUM_MCS);  
}PREFIX(bb_nr5g_MEASSET_DL_BLER_SIMt);

/* bb_nr5g_RNTI_MEASSET to configure CSI report */
typedef struct {
    uint16_t Index;
    uint8_t  Pad[2];
    uint32_t L1Rsrp;         /* L1 RSRP */
}PREFIX(bb_nr5g_BEAM_L1RSRP);

typedef struct {
    uint32_t  FieldMask;      /* This field mask is used to handle in a proper way the changes in LI, RI and Wideband parameters
                                 in order to speed up the processing of those fields.
                                 According to bb_nr5g_STRUCT_MEASSET_CSI_CFG***_CHANGED */
    uint16_t  ServCellIdx;    /* a cell identity, used to identify an PCell or SCell */

    /*The following set of parameters is always present. Field mask identifies if the associated parameter is changed or not*/
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_LI_CHANGED   0x0001
    uint8_t   Li;             /* Layer indicator */
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_RI_CHANGED   0x0002
    uint8_t   Ri;             /* Rank indicator */
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_WBCQI_CHANGED   0x0004
    uint8_t   WbCqi;          /* Wideband Channel Quality Indicator */
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_WBPMIX1I1_CHANGED   0x0008
    uint8_t   WbPmiX1i1;      /* index i1 for X1 Wideband Precoding Matrix Indicator 3GPP 38.212 (maximum allowed value is 32) */
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_WBPMIX1I2_CHANGED   0x0010
    uint8_t   WbPmiX1i2;      /* index i2 for X1 Wideband Precoding Matrix Indicator 3GPP 38.212 (maximum allowed value is 32) */
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_WBPMIX1I3_CHANGED   0x0020
    uint8_t   WbPmiX1i3;      /* index i3 for X1 Wideband Precoding Matrix Indicator 3GPP 38.212 (maximum allowed value is 32)*/
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_WBPMIX2_CHANGED   0x0040
    uint32_t  WbPmiX2;        /* X2 Wideband Precoding Matrix Indicator 3GPP 38.212 */
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_FREQSELECT_CHANGED   0x0080
    uint8_t   FreqSelectivity;/* Channel frequency selectivity 
                                0 means the channel is completely flat,
                                values 1, 2, 3 indicates a low, medium or high frequency
                                selectivity */
#define bb_nr5g_STRUCT_MEASSET_CSI_CFG_LOS_CHANGED   0x0100
    uint8_t    Los;             /* Line of sight flag */    
    /* The following set of parameters gives the size if the associated vector */
    uint8_t   NumSsb;         /* Number of SSBs in Ssb vector. Default value is 0. Range 1 ...bb_nr5g_MAX_NUM_BEAM. If NumSsb=0 no Ssb element is present*/
    uint8_t   NumCsiRs;       /* Number of CSI-RSs in CsiRs vector. Default value is 0. Range 1 ...bb_nr5g_MAX_NB_CSI_CFGS. If NumCsiRs=0 no CsiRs element is present */

    /* The following set of vectors is present only the associated size is different to 0 
       Every vector trasports only the elements that are changed */
    AFIELD(PREFIX(bb_nr5g_BEAM_L1RSRP), Ssb, bb_nr5g_MAX_NUM_BEAM);      /* Dynamic list of SSBs.*/
    AFIELD(PREFIX(bb_nr5g_BEAM_L1RSRP), CsiRs, bb_nr5g_MAX_NB_CSI_CFGS); /* Dynamic list of CSI-RSs*/
}PREFIX(bb_nr5g_MEASSET_CSI_CFGt);

/* bb_nr5g_RNTI_MEASSET structures to configure CSI report */
typedef struct {
    /*  Message static part has to be put at the beginning */
    uint32_t NbAggrCellCfgDed;     /* Gives the number of valid elements in AggrCsiReportCfgCarrier vector:
                                      1...bb_nr5g_MAX_NB_SERVING_CELLS; Default value is 0 */
    /* Current cell dedicated parameter configuration */
    PREFIX(bb_nr5g_MEASSET_CSI_CFGt) CurrCsiReportCfgCarrier;
    AFIELD(PREFIX(bb_nr5g_MEASSET_CSI_CFGt), AggrCsiReportCfgCarrier, bb_nr5g_MAX_NB_SERVING_CELLS); /* Dynamic list of aggregable cells */
}PREFIX(bb_nr5g_MEASSET_CSI_REPORT_CFGt);

// was: #pragma    pack()
#pragma    pack(pop)
#endif
