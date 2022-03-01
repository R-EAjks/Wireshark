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

#ifndef  bb_nr5g_def_DEFINED
#define  bb_nr5g_def_DEFINED

/* General verbosity bitmask */
#define bb_nr5g_GENVERB_MUTE_ALL          0x0000000000000001LL
#define bb_nr5g_GENVERB_DEVONLY           0x0000000000000002LL

/* Per-project-area verbosity bitmask */

// BB-L2 messages
#define bb_nr5g_DLVERB_MSG_TX             0x0000000000000001LL
// BB-AP driver interface
#define bb_nr5g_DLVERB_AP_ITF             0x0000000000000002LL
// SSB (PSS-SSS-PBCH)
#define bb_nr5g_DLVERB_SSB                0x0000000000000004LL
// PDCCH
#define bb_nr5g_DLVERB_PDCCH              0x0000000000000008LL
// Polar decoder
#define bb_nr5g_DLVERB_POLAR              0x0000000000000010LL
// DCI
#define bb_nr5g_DLVERB_DCI                0x0000000000000020LL
// Equalizer
#define bb_nr5g_DLVERB_EQL                0x0000000000000040LL
// CSI reference signal
#define bb_nr5g_DLVERB_CSI_RS             0x0000000000000080LL
// PDSCH
#define bb_nr5g_DLVERB_PDSCH              0x0000000000000100LL
// LDPC decoder
#define bb_nr5g_DLVERB_LDPC               0x0000000000000200LL
// DL HARQ
#define bb_nr5g_DLVERB_DL_HARQ            0x0000000000000400LL
// DL RNTI configuration
#define bb_nr5g_DLVERB_RNTI               0x0000000000000800LL
// DL RNTI Measurement Set configuration
#define bb_nr5g_DLVERB_RNTI_MEAS_SET      0x0000000000001000LL
// DL RNTI reader configuration
#define bb_nr5g_DLVERB_RNTI_PARSER        0x0000000000002000LL
// DL CELL configuration
#define bb_nr5g_DLVERB_CELL_CFG           0x0000000000004000LL
// LDPC accelerator
#define bb_nr5g_DLVERB_LDPC_ACC           0x0000000000008000LL

// L2-BB messages
#define bb_nr5g_ULVERB_MSG_RX             0x0000000000000001LL
// PUSCH
#define bb_nr5g_ULVERB_PUSCH              0x0000000000000002LL
// PUCCH
#define bb_nr5g_ULVERB_PUCCH              0x0000000000000004LL
// SRS
#define bb_nr5g_ULVERB_SRS                0x0000000000000008LL
// SR
#define bb_nr5g_ULVERB_SR                 0x0000000000000010LL
// Power control
#define bb_nr5g_ULVERB_POWER_CONTROL      0x0000000000000020LL
// CSI reporting
#define bb_nr5g_ULVERB_CSI_REP            0x0000000000000040LL
// DL_HARQ feedback
#define bb_nr5g_ULVERB_DL_HARQ_FB         0x0000000000000080LL
// UL RNTI configuration
#define bb_nr5g_ULVERB_RNTI               0x0000000000000100LL
// UL RNTI Measurement Set configuration
#define bb_nr5g_ULVERB_RNTI_MEAS_SET      0x0000000000000200LL
// DL RNTI parser configuration
#define bb_nr5g_ULVERB_RNTI_PARSER        0x0000000000000400LL
// UL CELL configuration
#define bb_nr5g_ULVERB_CELL_CFG           0x0000000000000800LL

/* Event triggered verbosity bitmask */

// DL bindump on first RACH
#define bb_nr5g_DLDUMP_RACH                 0x0000000000000001LL
// DL bindump on first RRCsetup
#define bb_nr5g_DLDUMP_RRCSETUP             0x0000000000000002LL
// DL bindump on 100th attached UE
#define bb_nr5g_DLDUMP_100UE                0x0000000000000004LL
// DL bindump on 500th attached UE
#define bb_nr5g_DLDUMP_500UE                0x0000000000000008LL
// DL bindump on 2000th attached UE
#define bb_nr5g_DLDUMP_2000UE               0x0000000000000010LL
// DL bindump on 20th CRC error on PDSCH in one second
#define bb_nr5g_DLDUMP_CRCERR_20            0x0000000000000020LL
// DL bindump on 100th CRC error on PDSCH in one second
#define bb_nr5g_DLDUMP_CRCERR_100           0x0000000000000040LL
// DL bindump MASK
#define bb_nr5g_DLDUMP_MASK                 0x000000000000007FLL
// UL bindump on first RACH
#define bb_nr5g_ULDUMP_RACH                 0x0000000000000080LL
// UL bindump on first RRCsetup
#define bb_nr5g_ULDUMP_RRCSETUP             0x0000000000000100LL
// UL bindump on 100th attached UE
#define bb_nr5g_ULDUMP_100UE                0x0000000000000200LL
// UL bindump on 500th attached UE
#define bb_nr5g_ULDUMP_500UE                0x0000000000000400LL
// UL bindump on 2000th attached UE
#define bb_nr5g_ULDUMP_2000UE               0x0000000000000800LL
// UL bindump MASK
#define bb_nr5g_ULDUMP_MASK                 0x0000000000000F80LL
// unused
#define bb_nr5g_RES1                        0x0000000000001000LL
// unused
#define bb_nr5g_RES2                        0x0000000000002000LL
// unused
#define bb_nr5g_RES3                        0x0000000000004000LL
// unused
#define bb_nr5g_RES4                        0x0000000000008000LL
// create FFT dumps only for crc errors
#define bb_nr5g_PDSCH_DUMPCRC               0x0000000000010000LL


#define bb_nr5g_RNTI_C_RNTI         0
#define bb_nr5g_RNTI_SI_RNTI        1   /* SIB1 and oSIB */
#define bb_nr5g_RNTI_P_RNTI         2   /* PAGING */
#define bb_nr5g_RNTI_RA_RNTI        3   /* MSG2 RAR */
#define bb_nr5g_RNTI_INT_RNTI       4   /* Interrupted tx DCI 2_1 (preemption) */
#define bb_nr5g_RNTI_SFI_RNTI       5   /* SlotFormatIndicator DCI 2_0 */
#define bb_nr5g_RNTI_T_RNTI         6
#define bb_nr5g_RNTI_PBCH           7
#define bb_nr5g_RNTI_TPCPUCCH       8   /* TCP for PUCCH DCI format 2_2 */
#define bb_nr5g_RNTI_TPCPUSCH       9   /* TCP for PUSCH DCI format 2_2 */
#define bb_nr5g_RNTI_TPCSRS        10   /* TPC SRS DCI format 2_3 */

/* bb_nr5g_RNTI_MEASSET defines */
#define  bb_nr5g_RNTI_NUM_MCS             (29)  /*MCS range 0...28; [29,30,31] are reserved*/
#define  bb_nr5g_RNTI_NUM_MULTI_ANT_DIV   (8)

#define  bb_nr5g_RNTI_MULTI_ANT_DIV_1     (0)  /*2A-2L; 4A-4L; 8A-8L*/
#define  bb_nr5g_RNTI_MULTI_ANT_DIV_2     (1)  /*2A-1L; 4A-2L; 8A-4L*/
#define  bb_nr5g_RNTI_MULTI_ANT_DIV_4     (2)  /*4A-1L; 8A-4L*/
#define  bb_nr5g_RNTI_MULTI_ANT_DIV_4_3   (3)  /*4A-3L*/
#define  bb_nr5g_RNTI_MULTI_ANT_DIV_8_7   (4)  /*8A-7L*/
#define  bb_nr5g_RNTI_MULTI_ANT_DIV_8_6   (5)  /*8A-6L*/
#define  bb_nr5g_RNTI_MULTI_ANT_DIV_8_5   (6)  /*8A-5L*/
#define  bb_nr5g_RNTI_MULTI_ANT_DIV_8_3   (7)  /*8A-3L*/

#define  bb_nr5g_MAX_NB_CSI_CFGS          (16)  /* Maximum number of CSI elements configured in bb_nr5g_RNTI_MEASSETt*/
#define  bb_nr5g_MAX_NUM_BEAM             (32)  /* Maximum number of beams handled by a DBEAM */
#define  bb_nr5g_MAX_NB_CSI_SUBBAND       (18)  /* Maximum number of CSI subbands */

/* bb_nr5g_RNTI_ACT_DEACT_SCELL defines */
#define  bb_nr5g_DEACT_COMMAND_SCELL        (0)  /* SCell is deactivated if it receives this flag in bb_nr5g_RNTI_ACT_DEACT_SCELLt*/
#define  bb_nr5g_ACT_COMMAND_SCELL          (1)  /* SCell is activated if it receives this flag in bb_nr5g_RNTI_ACT_DEACT_SCELLt*/

#define  bb_nr5g_ACT_ALL_SCELL              (0xFFFFFFFF)  /* In RNTI create message this value specifies that added/modified SCells 
                                                             are configured and activated at the same time */
#define  bb_nr5g_DEACT_ALL_SCELL            (0)           /* In RNTI create message this value specifies that added/modified SCells 
                                                             are configured but not activated */

/********************************************************************/
/* The following defines are related to 3GPP 38.331 V15.1.0         */
/********************************************************************/
/* 38.331 maxNrofBWPs : Maximum number of BWPs per serving cell */
#define bb_nr5g_MAX_NB_BWPS  (4)
/* 38.331 maxNrofSlots : Maximum number of slots in a 10 ms period*/
#define bb_nr5g_MAX_NB_SLOTS (320)
/* 38.331 maxNrofSymbols : Maximum index identifying a symbol within a slot (14 symbols, indexed from 0..13)*/
#define bb_nr5g_MAX_NB_SYMBS (14)
/* 38.331 maxNrofSearchSpaces: Max number of Search Spaces */
#define bb_nr5g_MAX_NB_SEARCH_SPACES (40)
/* 38.331 maxNrofControlResourceSets: Max number of CoReSets configurable on a serving cell*/
#define bb_nr5g_MAX_NB_CTRL_RES_SETS (12)
/* 38.331 maxNrofControlResourceSets-r16: Max number of CoReSets configurable on a serving cell extended */
#define bb_nr5g_MAX_NB_CTRL_RES_SETS_EXT (16)
/* 38.331 maxCoReSetDuration:Max number of OFDM symbols in a control resource set*/
#define bb_nr5g_MAX_CORESET_DURATION (3)
/* 38.331 maxNrofPhysicalResourceBlocks: Maximum number of PRBs*/
#define bb_nr5g_MAX_NB_PHYS_RES_BLOCKS (275)
/* 38.331 maxNrofTCI-StatesPDCCH */
#define bb_nr5g_MAX_NB_TCI_STATES_PDCCH (64)
/* 38.331 maxNrofDL-Allocations: Maximum number of PDSCH time domain resource allocations */
#define bb_nr5g_MAX_NB_DL_ALLOCS (16)
/* 38.331 maxNrofUL-Allocations: Maximum number of PUSCH time domain resource allocations */
#define bb_nr5g_MAX_NB_UL_ALLOCS (16)
/* 38.331 maxNrofServingCells: Max number of serving cells (SpCell + SCells) per cell group */
#define bb_nr5g_MAX_NB_SERVING_CELLS (32)
/* 38.331 maxNrofRateMatchPatterns: Max number of rate matching patterns that may be configured */
#define bb_nr5g_MAX_NB_RATE_MATCH_PATTERNS (4)
/* 38.331 maxNrofMultiBands */
#define bb_nr5g_MAX_NB_MULTIBANDS (8)
/* 38.331 maxSCSs */
#define bb_nr5g_MAX_SCS (5)
/* 38.331 maxINT-DCI-PayloadSize */
#define bb_nr5g_MAX_INT_DCI_PAYLOAD_SIZE (126)
/* 38.331 maxSFI-DCI-PayloadSize*/
#define bb_nr5g_MAX_SFI_DCI_PAYLOAD_SIZE (128)
/* 38.331 maxNrofAggregatedCellsPerCellGroup*/
#define bb_nr5g_MAX_AGG_CELLS_PER_GROUP (16)
/* 38.331 maxNrofSlotFormatCombinationsPerSet*/
#define bb_nr5g_MAX_SLOT_FMT_COMBS_PER_SET (4096)
/* 38.331 maxNrofSlotFormatsPerCombination*/
#define bb_nr5g_MAX_NB_SLOT_FMTS_PER_COMB (256)
/* 38.331 maxNrofNZP-CSI-RS-Resources*/
#define bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES (192)
/* 38.331 maxNrofNZP-CSI-RS-ResourceSets*/
#define bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS (64)
/* 38.331 maxNrofTCI-States*/
#define bb_nr5g_MAX_NB_TCI_STATES (64)
/* 38.331 maxNrofZP-CSI-RS-Resources*/
#define bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES (32)
/* 38.331 maxNrofZP-CSI-RS-ResourceSets */
#define bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCE_SETS (16)
/* 38.331 maxNrofZP-CSI-RS-ResourcesPerSet*/
#define bb_nr5g_MAX_NB_ZP_CSI_RS_RESOURCES_PER_SET (16)
/* 38.331 maxNrofZP-CSI-RS-Sets */
#define bb_nr5g_MAX_NB_ZP_CSI_RS_SETS (16)
/* 38.331 maxNrofPUCCH-Resources */
#define bb_nr5g_MAX_PUCCH_RESOURCES (128)
/* 38.331 maxNrofPUCCH-ResourceSets */
#define bb_nr5g_MAX_PUCCH_RESOURCE_SETS (4)
/* 38.331 maxNrofPUCCH-ResourcesPerSet */
#define bb_nr5g_MAX_PUCCH_RESOURCES_PERSET (32)
/* 38.331 maxNrofP0-PUSCH-AlphaSets*/
#define bb_nr5g_MAX_NB_P0_PUSCH_ALPHA_SETS (30)
/* 38.331 maxNrofPUSCH-PathlossReferenceRSs*/
#define bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REFERENCE_RS (4)
/* 38.331 maxNrofSRI-PUSCH-Mappings*/
#define bb_nr5g_MAX_NB_SRI_PUSCH_MAPPING (16)
/* 38.331 maxNrofSpatialRelationInfos*/
#define bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS (8)
/* 38.331 maxNrofSRS-Resources*/
#define bb_nr5g_MAX_SRS_RESOURCES (64)
/* 38.331 maxNrofSRS-ResourceSets */
#define bb_nr5g_MAX_SRS_RESOURCE_SETS (16)
/* 38.331 maxNrofSRS-ResourcesPerSet */
#define bb_nr5g_MAX_SRS_RESOURCE_PERSET (16)
/* 38.331 maxNrofSR-Resources */
#define bb_nr5g_MAX_SR_RESOURCES (8)
/* 38.331 maxNrofPUCCH-P0-PerSet */
#define bb_nr5g_MAX_PUCCH_P0_PERSET (8)
/* 38.331 maxNrofPUCCH-PathlossReferenceRSs*/
#define bb_nr5g_MAX_NB_PUCCH_PATHLOSS_REFERENCE_RS (4)
/* 38.331 maxNrofSRS-TriggerStates*/
#define bb_nr5g_MAX_NB_SRS_TRIGGER_STATES (3)
/* 38.331 maxNrofCSI-IM-Resources*/
#define bb_nr5g_MAX_NB_CSI_IM_RESOURCES (32)
/* 38.331 maxNrofCSI-IM-ResourceSets*/
#define bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS (64)
/* 38.331 maxNrofCSI-IM-ResourcesPerSet*/
#define bb_nr5g_MAX_NB_CSI_IM_RESOURCES_PER_SET (8)
/* 38.331 maxNrofCSI-SSB-ResourceSets*/
#define bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS (64)
/* 38.331 maxNrofCSI-SSB-ResourcePerSet*/
#define bb_nr5g_MAX_NB_CSI_SSB_RESOURCES_PER_SET (64)
/* 38.331 maxNrofCSI-ResourceConfigurations*/
#define bb_nr5g_MAX_NB_CSI_RESOURCE_CFGS (112)
/* 38.331 maxNrofCSI-ReportConfigurations*/
#define bb_nr5g_MAX_NB_CSI_REPORT_CFGS (48)
/* 38.331 maxNrofNZP-CSI-RS-ResourcesPerConfig*/
#define bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES_PER_CFG (128)
/* 38.331 maxNrofNZP-CSI-RS-ResourceSetsPerConfig*/
#define bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCE_SETS_PER_CFG (16)
/* 38.331 maxNrofNZP-CSI-RS-ResourcesPerSet*/
#define bb_nr5g_MAX_NB_NZP_CSI_RS_RESOURCES_PER_SET (64)
/* 38.331 maxNrofCSI-SSB-ResourceSetsPerConfig*/
#define bb_nr5g_MAX_NB_CSI_SSB_RESOURCE_SETS_PER_CFG (1)
/* 38.331 maxNrofCSI-IM-ResourceSetsPerConfig*/
#define bb_nr5g_MAX_NB_CSI_IM_RESOURCE_SETS_PER_CFG (16)
/* 38.331 maxNrOfCSI-AperiodicTriggers*/
#define bb_nr5g_MAX_NB_CSI_APERIODIC_TRIGGERS (128)
/* 38.331 maxNrofReportConfigPerAperiodicTrigger*/
#define bb_nr5g_MAX_NB_REP_CFG_APERIODIC_TRIGGERS (16)
/* 38.331 maxNrofAP-CSI-RS-ResourcesPerSet*/
#define bb_nr5g_MAX_NB_AP_CSI_RS_RESOURCES_PER_SET (16)
/* 38.331 maxNrOfSemiPersistentPUSCH-Triggers*/
#define bb_nr5g_MAX_NB_SEMIPERS_ONPUSCH_TRIGGERS (16)
/* 38.331 maxNrofObjectId */
#define bb_nr5g_MAX_NB_OF_OBJECT_ID (64)
/* 38.331 maxNrofTAGs */
#define bb_nr5g_MAX_NB_OF_TAGS (4)
/* 38.331 maxPO-perPF */
#define bb_nr5g_MAX_PO_PERPF (4)
/* 38.331 maxNrofSSBs */
#define bb_nr5g_MAX_NB_SSB (64)
/* 38.331 maxNrofCandidateBeams */
#define bb_nr5g_MAX_NB_CANDIDATE_BEAMS (16)
/* 38.331 maxRA-OccasionsPerCSIRS */
#define bb_nr5g_MAX_RA_OCCASIONS_PER_CSIRS (64)
/* 38.331 maxRA-Occasions */
#define bb_nr5g_MAX_RA_OCCASIONS (512)
/* 38.331 maxMBSFN-Allocations */
#define bb_nr5g_MAX_MBSFN_ALLOCATIONS (8)

/* R16 */
/* 38.331 maxNrofP0-PUSCH-Set-r16 */
#define bb_nr5g_MAX_NB_P0_PUSCH_SET_R16 (2)
/* 38.331 maxNrofSRI-PUSCH-Mappings */
#define bb_nr5g_MAX_NB_SRI_PUSCH_MAPPINGS (16)
/* 38.331 maxNrofPUSCH-PathlossReferenceRSsDiff-r16 */
#define bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REF_RSS_DIFF (60)
/* 38.331 maxNrofConfiguredGrantConfig-r16 */
#define bb_nr5g_MAX_NB_CONFIGURED_GRANT_CONFIG (12)
/* 38.331 maxNrofCG-Type2DeactivationState-r16 */
#define bb_nr5g_MAX_NB_CG_TYPE2_DEACT_STATE (16)
/* 38.331  maxNrofControlResourceSets-1-r16 */
#define bb_nr5g_MAX_NB_CTRL_RES_SETS_1_R16 (15)
/* 38.331 maxNrofDL_Allocations */
#define bb_nr5g_MAX_NB_DL_ALLOCATIONS (16)
/* 38.331 maxNrofZP-CSI-RS-ResourceSets-1 */
#define bb_nr5g_MAX_NB_ZP_CSI_RS_RES_SETS_1 (15)
/* 38.331 maxNrofZP-CSI-RS-ResourceSets */
#define bb_nr5g_MAX_NB_ZP_CSI_RS_RES_SETS (16)
/* 38.331 maxNrofServingCells-1: Max number of serving cells (SpCell + SCells) per cell group */
#define bb_nr5g_MAX_NB_SERVING_CELLS_1 (31)
/* 38.331 maxCI-DCI-PayloadSize-r16 */
#define bb_nr5g_CI_DCI_PAYLOADSIZE (126)
/* 38.331 maxCI-DCI-PayloadSize-r16-1 */
#define bb_nr5g_CI_DCI_PAYLOADSIZE_1 (125)
/* 38.331 maxNrofPUSCH-PathlossReferenceRSsDiff-r16 */
#define bb_nr5g_MAX_NB_PUSCH_PATHLOSS_REF_RSs_DIFF (60)
/* 38.331 maxNrofSRS-PosResourceSets-r16 */
#define bb_nr5g_MAX_SRS_POS_RESOURCES_SETS (16)
/* 38.331 maxNrofSRS-ResourcesPerSet */
#define bb_nr5g_MAX_SRS_RESOURCE_PER_SET (16)
/* 38.331 maxNrofSRS-PosResources-r16 */
#define bb_nr5g_MAX_SRS_POS_RESOURCES (64)

/* R16 end */

/**************************************************************************/
/* The following defines are specific defines related to L2 communication */
/**************************************************************************/
/* TDD-UL-DL-SlotConfig */
#define bb_nr5g_TDD_UL_DL_SLOT_ALLDL     (0)
#define bb_nr5g_TDD_UL_DL_SLOT_ALLUL     (1)
#define bb_nr5g_TDD_UL_DL_SLOT_EXPLICIT  (2)
#define bb_nr5g_TDD_UL_DL_SLOT_DEFAULT   (0xff)

/* SearchSpace */
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL1     (0)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL2     (1)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL4     (2)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL5     (3)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL8     (4)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL10    (5)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL16    (6)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL20    (7)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL40    (8)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL80    (9)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL160   (10)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL320   (11)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL640   (12)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL1280  (13)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_SL2560  (14)
#define bb_nr5g_SEARCH_SPACE_MONSLOT_DEFAULT (0xff)

#define bb_nr5g_SEARCH_SPACE_TYPE_COMMON        (0)
#define bb_nr5g_SEARCH_SPACE_TYPE_DEDICATED     (1)
#define bb_nr5g_SEARCH_SPACE_TYPE_DEFAULT       (0xff)

/* RACH-ConfigCommon */
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_ONEEIGHT  (0)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_ONEFOURTH (1)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_ONEHALF   (2)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_ONE       (3)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_TWO       (4)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_FOUR      (5)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_EIGHT     (6)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_SIXTEEN   (7)
#define bb_nr5g_RACH_CONF_COMMON_OCCASION_DEFAULT   (0xff)

#define bb_nr5g_RACH_CONF_COMMON_ROOTSEQINDEX_L839  (0)
#define bb_nr5g_RACH_CONF_COMMON_ROOTSEQINDEX_L139  (1)
#define bb_nr5g_RACH_CONF_COMMON_ROOTSEQINDEX_L571  (2)
#define bb_nr5g_RACH_CONF_COMMON_ROOTSEQINDEX_L1151 (3)
#define bb_nr5g_RACH_CONF_COMMON_ROOTSEQINDEX_DEFAULT   (0xff)

/* RateMatchPattern */
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP               (0)
#define bb_nr5g_RATE_MATCH_PATTERN_CTRLRESSET           (1)
#define bb_nr5g_RATE_MATCH_PATTERN_CTRLRESSET_R16       (2)
#define bb_nr5g_RATE_MATCH_PATTERN_DEFAULT              (0xff)

#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SIZERES    ((bb_nr5g_MAX_NB_PHYS_RES_BLOCKS/32) + 1)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SYMBRES_ONE        (0)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SYMBRES_TWO        (1)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_SYMBRES_DEFAULT    (0xff)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_N2     (0)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_N4     (1)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_N5     (2)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_N8     (3)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_N10    (4)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_N20    (5)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_N40    (6)
#define bb_nr5g_RATE_MATCH_PATTERN_BITMAP_PERIODICITY_DEFAULT    (0xff)

/* ServingCellConfigCommon */
#define bb_nr5g_SSB_POS_IN_BURST_SHORT     (0)
#define bb_nr5g_SSB_POS_IN_BURST_MEDIUM    (1)
#define bb_nr5g_SSB_POS_IN_BURST_LONG      (2)
#define bb_nr5g_SSB_POS_IN_BURST_DEFAULT   (0xff)

/* PDCCH-ConfigCommon */
#define bb_nr5g_COMMON_CTRL_RES_SET_SIZE   (1) /*From 15.4 this value is 1*/
#define bb_nr5g_COMMON_SEARCH_SPACE_SIZE   (4)

/* PDCCH-Config */
#define bb_nr5g_DED_CTRL_RES_SET_SIZE     (3)
#define bb_nr5g_DED_SEARCH_SPACE_SIZE     (10)

#define bb_nr5g_PDSCH_CONF_DED_BUNDLING_STATIC        (0)
#define bb_nr5g_PDSCH_CONF_DED_BUNDLING_DYNAMIC      (1)
#define bb_nr5g_PDSCH_CONF_DED_BUNDLING_DEFAULT    (0xff)

/*QCL-Info */
#define bb_nr5g_QCL_INFO_REF_SIG_ZP_CSI_RS_RESOURCES        (0)
#define bb_nr5g_QCL_INFO_REF_SIG_SSB_INDEX                  (1)
#define bb_nr5g_QCL_INFO_REF_SIG_ZP_CSI_RS_RESOURCE_SETS    (2)
#define bb_nr5g_QCL_INFO_REF_SIG_DEFAULT                    (0xff)

/*PUCCH-SpatialRelationInfo */
#define bb_nr5g_SPATIAL_RELATION_INFO_REF_SIG_SSB_INDEX                  (0)
#define bb_nr5g_SPATIAL_RELATION_INFO_REF_SIG_ZP_CSI_RS_RESOURCES        (1)
#define bb_nr5g_SPATIAL_RELATION_INFO_REF_SIG_SRS                        (2)
#define bb_nr5g_SPATIAL_RELATION_INFO_REF_SIG_DEFAULT                    (0xff)

/*PUSCH-PathlossReferenceRS*/
#define bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RS_REF_SIG_ZP_CSI_RS_RESOURCES        (0)
#define bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RS_REF_SIG_SSB_INDEX                  (1)
#define bb_nr5g_PUSCH_PATHLOSS_REFERENCE_RS_REF_SIG_DEFAULT                    (0xff)

/* CSI-RS-ResourceMapping*/
#define bb_nr5g_CSI_RS_RES_MAPPING_FREQ_DOMAIN_ROW1    (0)
#define bb_nr5g_CSI_RS_RES_MAPPING_FREQ_DOMAIN_ROW2    (1)
#define bb_nr5g_CSI_RS_RES_MAPPING_FREQ_DOMAIN_ROW4    (2)
#define bb_nr5g_CSI_RS_RES_MAPPING_FREQ_DOMAIN_OTHER   (3)
#define bb_nr5g_CSI_RS_RES_MAPPING_FREQ_DOMAIN_DEFAULT  (0xff)

#define bb_nr5g_CSI_RS_RES_MAPPING_DENSITY_DOT5    (0)
#define bb_nr5g_CSI_RS_RES_MAPPING_DENSITY_ONE     (1)
#define bb_nr5g_CSI_RS_RES_MAPPING_DENSITY_THREE   (2)
#define bb_nr5g_CSI_RS_RES_MAPPING_DENSITY_DEFAULT  (0xff)

/* CSI-ResourcePeriodicityAndOffset */
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT4    (0)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT5    (1)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT8    (2)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT10    (3)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT16    (4)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT20    (5)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT32    (6)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT40    (7)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT64    (8)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT80    (9)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT160    (10)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT320    (11)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_SLOT640    (12)
#define bb_nr5g_CSI_RS_RES_PERIODICITYANDOFFSET_DEFAULT  (0xff)

/* PUCCH resource */
#define bb_nr5g_PUCCH_RESOURCE_FORMAT_0    (0)
#define bb_nr5g_PUCCH_RESOURCE_FORMAT_1    (1)
#define bb_nr5g_PUCCH_RESOURCE_FORMAT_2    (2)
#define bb_nr5g_PUCCH_RESOURCE_FORMAT_3    (3)
#define bb_nr5g_PUCCH_RESOURCE_FORMAT_4    (4)
#define bb_nr5g_PUCCH_RESOURCE_FORMAT_DEFAULT    (0xff)

/*DMRS-UplinkConfig*/
#define bb_nr5g_DMRS_UPLINK_TRANSF_PRECOD_DISABLE    (0)
#define bb_nr5g_DMRS_UPLINK_TRANSF_PRECOD_ENABLE    (1)
#define bb_nr5g_DMRS_UPLINK_TRANSF_PRECOD_BOTH       (2)
#define bb_nr5g_DMRS_UPLINK_TRANSF_PRECOD_DEFAULT    (0xff)

/*PTRS-UplinkConfig*/
#define bb_nr5g_PTRS_UPLINK_MODE_SPEC_PARAMS_CP_OFDM    (0)
#define bb_nr5g_PTRS_UPLINK_MODE_SPEC_PARAMS_DFTS_OFDM  (1)
#define bb_nr5g_PTRS_UPLINK_MODE_SPEC_PARAMS_BOTH       (2)
#define bb_nr5g_PTRS_UPLINK_MODE_SPEC_PARAMS_DEFAULT    (0xff)

/*UCI-OnPUSCH*/
#define bb_nr5g_UCI_ON_PUSCH_BETAOFFSETS_DYNAMIC    (0)
#define bb_nr5g_UCI_ON_PUSCH_BETAOFFSETS_SEMISTATIC   (1)
#define bb_nr5g_UCI_ON_PUSCH_BETAOFFSETS_DEFAULT    (0xff)

/*UCI-OnPUSCH-DCI-0-2*/
#define bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_ONEBIT_DYNAMIC    (0)
#define bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_TWOBITS_DYNAMIC    (1)
#define bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_SEMISTATIC   (2)
#define bb_nr5g_UCI_ON_PUSCH_DCI02_BETAOFFSETS_DEFAULT    (0xff)

/* SchedulingRequestResourceConfig */
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SYM2     (0)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SYM6_7   (1)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT1    (2)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT2    (3)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT4    (4)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT5    (5)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT8    (6)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT10    (7)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT16    (8)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT20    (9)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT40    (10)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT80    (11)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT160    (12)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT320    (13)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_SLOT640    (14)
#define bb_nr5g_SR_PERIODICITYANDOFFSET_DEFAULT  (0xff)

/*PUCCH-PathlossReferenceRS*/
#define bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RS_REF_SIG_ZP_CSI_RS_RESOURCES        (0)
#define bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RS_REF_SIG_SSB_INDEX                  (1)
#define bb_nr5g_PUCCH_PATHLOSS_REFERENCE_RS_REF_SIG_DEFAULT                    (0xff)

/*SRS-Config*/

/*SRS_Resource_transmissionComb and SRS_PosResource_r16_transmissionComb_r16*/
#define bb_nr5g_SRS_TRANSMISSION_COMB_N2        (0)
#define bb_nr5g_SRS_TRANSMISSION_COMB_N4        (1)
#define bb_nr5g_SRS_TRANSMISSION_COMB_N8        (2)
#define bb_nr5g_SRS_TRANSMISSION_COMB_DEFAULT   (0xff)

#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT1    (0)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT2    (1)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT4    (2)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT5    (3)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT8    (4)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT10    (5)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT16    (6)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT20    (7)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT32    (8)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT40    (9)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT64    (10)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT80    (11)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT160    (12)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT320    (13)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT640    (14)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT1280    (15)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_SLOT2560    (16)
#define bb_nr5g_SRS_PERIODICITYANDOFFSET_DEFAULT  (0xff)

#define bb_nr5g_SRS_RESOURCETYPE_APERIODIC        (0)
#define bb_nr5g_SRS_RESOURCETYPE_SEMIPERSISTENT    (1)
#define bb_nr5g_SRS_RESOURCETYPE_PERIODIC        (2)
#define bb_nr5g_SRS_RESOURCETYPE_DEFAULT   (0xff)

#define bb_nr5g_SRS_SPATIAL_RELATION_INFO_REF_SIG_SSB_INDEX                  (0)
#define bb_nr5g_SRS_SPATIAL_RELATION_INFO_REF_SIG_ZP_CSI_RS_RESOURCES        (1)
#define bb_nr5g_SRS_SPATIAL_RELATION_INFO_REF_SIG_SRS                        (2)
#define bb_nr5g_SRS_SPATIAL_RELATION_INFO_REF_SIG_DEFAULT                    (0xff)

#define bb_nr5g_SRS_PATHLOSS_REFERENCE_RS_ZP_CSI_RS_RESOURCES        (0)
#define bb_nr5g_SRS_PATHLOSS_REFERENCE_RS_SSB_INDEX                  (1)
#define bb_nr5g_SRS_PATHLOSS_REFERENCE_RS_DEFAULT                    (0xff)

#define bb_nr5g_SRS_RESOURCETYPESET_APERIODIC        (0)
#define bb_nr5g_SRS_RESOURCETYPESET_SEMIPERSISTENT    (1)
#define bb_nr5g_SRS_RESOURCETYPESET_PERIODIC          (2)
#define bb_nr5g_SRS_RESOURCETYPESET_DEFAULT          (0xff)

#define bb_nr5g_CSI_IM_RES_ELEM_PATTERN_P0 (0)
#define bb_nr5g_CSI_IM_RES_ELEM_PATTERN_P1 (1)
#define bb_nr5g_CSI_IM_RES_ELEM_PATTERN_DEFAULT (0xff)

#define bb_nr5g_CSI_REPORT_CFG_TYPE_PERIODIC (0)
#define bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUCCH    (1)
#define bb_nr5g_CSI_REPORT_CFG_TYPE_SEMIPERSISTENT_ONPUSCH    (2)
#define bb_nr5g_CSI_REPORT_CFG_TYPE_APERIODIC (3)
#define bb_nr5g_CSI_REPORT_CFG_TYPE_DEFAULT (0xff)

/* CSI-ReportPeriodicityAndOffset */
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT4    (0)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT5    (1)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT8    (2)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT10    (3)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT16    (4)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT20    (5)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT40    (6)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT80    (7)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT160    (8)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_SLOT320    (9)
#define bb_nr5g_CSI_RS_REPORT_PERIODICITYANDOFFSET_DEFAULT  (0xff)

/* 38.331 ReportQuantity and ReportQuantity-r16 */
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_NONE    		(0)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_PMI_CQI  (1)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_I1    	(2)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_I1_CQI   (3)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_CQI    	(4)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RSRP    	(5)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_SSBINDEX_RSRP   (6)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_CRI_RI_LII_PMI_CQI (7)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_CRI_SINR        (8)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_R16_SSB_INDEX_SINR  (9)
#define bb_nr5g_CSI_REPORT_CFG_QUANTITY_DEFAULT   (0xff)

#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_3    		(0)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_4    		(1)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_5    		(2)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_6    		(3)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_7    		(4)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_8    		(5)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_9    		(6)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_10    		(7)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_11    		(8)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_12    		(9)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_13    		(10)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_14    		(11)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_15    		(12)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_16    		(13)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_17    		(14)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_18    		(15)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_19    		(16)
#define bb_nr5g_CSI_REPORT_FREQ_CSI_REPORT_SUBBAND_DEFAULT   (0xff)    		

#define bb_nr5g_CSI_REPORT_CFG_GROUP_BEAM_REP_ENABLE    		(0)
#define bb_nr5g_CSI_REPORT_CFG_GROUP_BEAM_REP_DISABLE    		(1)
#define bb_nr5g_CSI_REPORT_CFG_GROUP_BEAM_REP_DEFAULT    		(0xff)

#define bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_2    		    (0)
#define bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_4    		    (1)
#define bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_8    		    (2)
#define bb_nr5g_CSI_REPORT_CFG_PORT_INDEX_RANKS_DEFAULT    		(0xff)

#define bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_NZP_CSI_RS_SSB   (0)
#define bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_CSI_IM    		(1)
#define bb_nr5g_CSI_RESOURCE_CFG_RES_SET_LIST_DEFAULT    		(0xff)

#define bb_nr5g_CSI_ASSOCIATED_REPORT_CFG_INFO_RES_FOR_CHANNEL_NZP_CSI_RS   (0)
#define bb_nr5g_CSI_ASSOCIATED_REPORT_CFG_INFO_RES_FOR_CHANNEL_CSI_SSB  (1)
#define bb_nr5g_CSI_ASSOCIATED_REPORT_CFG_INFO_RES_FOR_CHANNEL_DEFAULT    		(0xff)

#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_TYPEI_ABSENT    (0)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_TYPEI_PRESENT   (1)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_TYPEI_DEFAULT	(0xff)

#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_TWO_ONE_T1   (0)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_TWO_TWO_T1   (1)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_FOUR_ONE_T1   (2)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_THREE_TWO_T1   (3)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_SIX_ONE_T1  (4)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_FOUR_TWO_T1   (5)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_EIGHT_ONE_T1   (6)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_FOUR_THREE  (7)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_SIX_TWO  (8)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_TWELVE_ONE  (9)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_FOUR_FOUR  (10)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_EIGHT_TWO  (11)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_SIXTEEN_ONE  (12)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MORETHANTWO_ANT_PORTS_N1N2_DEFAULT (0xff)

#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_TWO_ONE   (0)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_TWO_TWO   (1)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_FOUR_ONE  (2)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_THREE_TWO (3)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_SIX_ONE   (4)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_FOUR_TWO   (5)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_EIGHT_ONE  (6)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_FOUR_THREE (7)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_SIX_TWO    (8)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_TWELVE_ONE (9)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_FOUR_FOUR  (10)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_EIGHT_TWO  (11)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_SIXTEEN_ONE (12)
#define bb_nr5g_CODEBOOK_SUBTYPE2_N1N2_DEFAULT (0xff)

#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_TWO_TWO_ONE   (0)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_TWO_FOUR_ONE   (1)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_FOUR_TWO_ONE   (2)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_TWO_TWO_TWO   (3)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_TWO_EIGHT_ONE   (4)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_FOUR_FOUR_ONE   (5)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_TWO_FOUR_TWO   (6)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_FOUR_TWO_TWO   (7)
#define bb_nr5g_CODEBOOK_SUBTYPE1_MULTI_PANEL_N1N2_DEFAULT   (0xff)

#define bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_TWO (0)
#define bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_MORETHANTWO (1)
#define bb_nr5g_CODEBOOK_SUBTYPE1_NB_ANT_PORTS_DEFAULT (0xff)

#define bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_I_SINGLE_PANEL (0)
#define bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_I_MULTI_PANEL (1)
#define bb_nr5g_CODEBOOK_TYPE1_SUBTYPE_DEFAULT (0xff)

#define bb_nr5g_CODEBOOK_TYPE2_SUBTYPE_II (0)
#define bb_nr5g_CODEBOOK_TYPE2_SUBTYPE_II_PORT_SELECTION (1)
#define bb_nr5g_CODEBOOK_TYPE2_SUBTYPE_DEFAULT (0xff)

#define bb_nr5g_CODEBOOK_SUBTYPE_1 (0)
#define bb_nr5g_CODEBOOK_SUBTYPE_2 (1)
#define bb_nr5g_CODEBOOK_SUBTYPE_DEFAULT (0xff)

#define bb_nr5g_CODEBOOK_TYPE_1 (0)
#define bb_nr5g_CODEBOOK_TYPE_2 (1)
#define bb_nr5g_CODEBOOK_TYPE_DEFAULT (0xff)

/* CrossCarrierSchedulingConfig */
#define bb_nr5g_CROSS_CARRIER_SCHED_CFG_OWN     (0)
#define bb_nr5g_CROSS_CARRIER_SCHED_CFG_OTHER   (1)
#define bb_nr5g_CROSS_CARRIER_SCHED_CFG_DEFAULT    (0xff)

/* SRS-CarrierSwitching*/
#define bb_nr5g_SRS_CARRIER_SWITCHING_PDCCH_GROUP_TYPEA     (0)
#define bb_nr5g_SRS_CARRIER_SWITCHING_PDCCH_GROUP_TYPEB   (1)
#define bb_nr5g_SRS_CARRIER_SWITCHING_PDCCH_GROUP_DEFAULT    (0xff)

/* Ctrl Res Set */
#define bb_nr5g_PDCCH_DMSR_SCRAMB_NOT_PRESENT (0)
#define bb_nr5g_PDCCH_DMSR_SCRAMB_PRESENT     (1)
#define bb_nr5g_PDCCH_DMSR_SCRAMB_DEFAULT     (0xff)

/*Paging*/
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS15KHZoneT                                (0)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS30KHZoneT_SCS15KHZhalfT                  (1)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS60KHZoneT_SCS30KHZhalfT_SCS15KHZquarterT (2)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZoneT_SCS60KHZhalfT_SCS30KHZquarterT_SCS15KHZoneEighthT (3)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZhalfT_SCS60KHZquarterT_SCS30KHZoneEighthT_SCS15KHZoneSixteenthT (4)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZquarterT_SCS60KHZoneEighthT_SCS30KHZoneSixteenthT (5)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZoneEighthT_SCS60KHZoneSixteenthT (6)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_SCS120KHZoneSixteenthT (7)
#define bb_nr5g_FIRST_PDCCH_MON_OCC_DEFAULT                    (0xff)

/*SRS Carrier Switching*/ 
#define bb_nr5g_SRS_TPC_PDCCH_GROUP_TYPE_A (0)
#define bb_nr5g_SRS_TPC_PDCCH_GROUP_TYPE_B     (1)
#define bb_nr5g_SRS_TPC_PDCCH_GROUP_DEFAULT     (0xff)

/* Beam Recovery Procedure */ 
#define bb_nr5g_PRACH_RESOURCE_DED_BFR_CFG_SSB    (0)
#define bb_nr5g_PRACH_RESOURCE_DED_BFR_CFG_CSIRS    (1)
#define bb_nr5g_PRACH_RESOURCE_DED_BFR_CFG_DEFAULT  (0xff)

/* TDD Ul Dl pattern transmission periodicity*/
#define bb_nr5g_TDD_UL_DL_PATTERN_TRANSM_PERIOD_V1530EXT    (0)
#define bb_nr5g_TDD_UL_DL_PATTERN_TRANSM_PERIOD_DEFAULT  (0xff)

/* MBSFN Subframe configuration */
#define bb_nr5g_MBSFN_SUBFRAME_ALLOC_ONE_FRAME    (0)
#define bb_nr5g_MBSFN_SUBFRAME_ALLOC_FOUR_FRAMES  (1)
#define bb_nr5g_MBSFN_SUBFRAME_ALLOC_DEFAULT      (0xff)

/* R16 IEs */
/* SpatialRelationInfoPosIsValid NR_SRS_SpatialRelationInfoPos_r16_servingRS_r16_referenceSignal_r16 */
#define bb_nr5g_SPATIALRELINFOPOS_REFERENCESIGNAL_SSB_INDEXSERVING (0)
#define bb_nr5g_SPATIALRELINFOPOS_REFERENCESIGNAL_CSI_RS_INDEXSERVING (1)
#define bb_nr5g_SPATIALRELINFOPOS_REFERENCESIGNAL_SRS_RESOURCEID (2)
#define bb_nr5g_SPATIALRELINFOPOS_REFERENCESIGNAL_SRS_POSRESOURCEID (3)
#define bb_nr5g_SPATIALRELINFOPOS_REFERENCESIGNAL_DEFAULT (0xff)

/* SubslotLengthForPUCCHIsValid */
#define bb_nr5g_SUBSLOT_LENGHT_FOR_PUCCH_NORMAL_CP (0)
#define bb_nr5g_SUBSLOT_LENGHT_FOR_PUCCH_EXTENDED_CP (1)
#define bb_nr5g_SUBSLOT_LENGHT_FOR_PUCCH_DEFAULT (0xff)

/* 38.331 maxNrofSpatialRelationInfosDiff-r16 */
#define bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS_DIFF (56)
/* 38.331 maxNrofSpatialRelationInfos-r16 */
#define bb_nr5g_MAX_NB_SPATIAL_RELATION_INFOS_R16 (64)
/* 38.331 maxNrofPUCCH-ResourceGroups-r16 */
#define bb_nrg5_MAX_PUCCH_RESOURCE_GROUPS (4)
/* 38.331 maxNrofUL-Allocations-r16 */
#define bb_nr5g_MAX_NR_OF_UL_ALLOCATION (64)
/*38.331 maxNrofSPS-Config-r16 */
#define bb_nr5g_MAX_NR_OF_SPS_CONFIG_R16 (8)
/* 38.331 maxNrofSPS-DeactivationState */
#define bb_nr5g_MAX_NR_OF_SPS_DEACTIVATIONSTATE (16)
/* 38.331 maxLTE-CRS-Patterns-r16 */
#define bb_nr5g_MAX_LTE_CRS_PATTERNS_R16 (3)

/* PUCCH RESOURCE EXT */
#define bb_nr5g_PUCCH_RESOURCE_EXT_INTERLACE1   (0)
#define bb_nr5g_PUCCH_RESOURCE_EXT_OCC  (1)
#define bb_nr5g_PUCCH_RESOURCE_EXT_DEFAULT      (0xff)

/* InvalidSymbolPattern-r16 IE */
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_SYMBRES_ONE        (0)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_SYMBRES_TWO        (1)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_SYMBRES_DEFAULT    (0xff)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_N2     (0)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_N4     (1)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_N5     (2)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_N8     (3)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_N10    (4)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_N20    (5)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_N40    (6)
#define bb_nr5g_INVALID_SYMB_PATTERN_BITMAP_PERIODICITY_DEFAULT    (0xff)

/* UCI-OnPUSCH-DCI-0-2-r16 */
#define bb_nr5g_UCI_ONPUSCH_DCI_0_2_R16 (2)

/* 38.331 maxNrOfMinSchedulingOffsetValues-r16 */
#define bb_nr5g_MAX_NB_MIN_SCHED_OFFSET_VALUES_R16 (2)

/* maxNrofPhysicalResourceBlocks-1 */
#define bb_nr5g_MAX_NB_PHY_RESOURCE_BLOCKS_1 (274)

/* 38.331 PUSCH_PathlossReferenceRS_r16_referenceSignal_r16 */
#define bb_nr5g_PATHLOSS_REFERENCE_SIGNAL_SSB_INDEX      (0)
#define bb_nr5g_PATHLOSS_REFERENCE_SIGNAL_CSI_RS_INDEX   (1)
#define bb_nr5g_PATHLOSS_REFERENCE_SIGNAL_DEFAULT        (0xFF)

/* bb_nr5g_INTERLACE_ALLOCATION__ */
#define  bb_nr5g_INTERLACE0_SCS15 (0)
#define  bb_nr5g_INTERLACE0_SCS30 (1)
#define  bb_nr5g_INTERLACE0_DEFAULT (0xFF)

/* NR_ServingCellConfig_ca_SlotOffset_r16 */
#define bb_nr5g_CA_SLOT_OFFSET_REF_SCS_15KHZ            (0)
#define bb_nr5g_CA_SLOT_OFFSET_REF_SCS_30KHZ            (1)
#define bb_nr5g_CA_SLOT_OFFSET_REF_SCS_60KHZ            (2)
#define bb_nr5g_CA_SLOT_OFFSET_REF_SCS_120KHZ           (3)
#define bb_nr5g_CA_SLOT_OFFSET_REF_SCS_DEFAULT          (0xff)
/* R16 IEs end */
#endif
