/*********************************************************************
  Title: Common NR5G Definitions
 *********************************************************************/

#ifndef nr5g_DEFINED
#define nr5g_DEFINED


#define nr5g_VERSION   "0.1.0"


/*------------------------------------------------------------------*
 |  NOTES (read before interface use                                |
 *------------------------------------------------------------------*
 *
 * This interface conforms to the rules specified in `lsu.h'.
 *  
 */

#pragma pack(1)


/*------------------------------------------------------------------*
 |  COMMON DEFINES                                                  |
 *------------------------------------------------------------------*/

#define nr5g_MaxNrOfPDCP         1000    // Prop.
#define nr5g_MaxNrOfPDP_CTX      32      // Prop. (per UE)
#define nr5g_MaxNrOfRB           32      // Prop. (per UE)
#define nr5g_MaxNrOfRB_C_MRB     8       // RB for MCCHs (up to 8 for a single cell, 1 for an MBSFN Area): range 33 - 40
#define nr5g_MaxNrOfRB_T_MRB     23      // RB for MTCHs (up to 23 for a PMCH of an MBSFN Area, max number of sessions for PMCH for Area 29): range 41 - 63
#define nr5g_MaxLchIdxSch        32
#define nr5g_MaxLchIdMch         28
#define nr5g_MaxLchPrio          16
#define nr5g_MinLchPrio          1
#define nr5g_NumLchGroup         8
#define nr5g_MaxNumSR            8
#define nr5g_MaxNumSCells        31
#define nr5g_MaxDrvCells         8
#define nr5g_MaxDrv              8
#define nr5g_MaxNumAggCells      8 // TODO vedere valore
#define nr5g_MaxDbeam            16 // TODO vedere valore
#define nr5g_MaxBeam             256 // Number of Beam per Dbeam TODO vedere valore
#define nr5g_maxNrofQFIs         64
/*------------------------------------------------------------------*
 |  COMMON INFORMATION ELEMENTS                                     |
 *------------------------------------------------------------------*/

/*
 * Type of RLC entity
 */
typedef enum {

    nr5g_TM = 1,  /* Transparent Mode (TM) Entity.         */
    nr5g_UM = 2,  /* Unacknowledged Mode (UM) RLC Entity.  */
    nr5g_AM = 3,  /* Acknowledged Mode (AM) RLC Entity.    */

} nr5g_RlcMode_e;
typedef uchar nr5g_RlcMode_v;


typedef enum {

    nr5g_SIG = 1,
    nr5g_UP  = 2,
    nr5g_PBT_SPARE_0  = 3,
    nr5g_RbTypeNum =  3,

} nr5g_RbType_e;
typedef uchar nr5g_RbType_v;


typedef enum {
    nr5g_USER        = 1,
    nr5g_NET         = 2,
    nr5g_DEB_USER    = 3, /* debug network mode */
    nr5g_DEB_NET     = 4, /* debug network mode */
} nr5g_Side_e;
typedef uchar nr5g_Side_v;


typedef enum {
    nr5g_BCH     = 1,
    nr5g_PCH     = 2,
    nr5g_RACH    = 3,
    nr5g_DLSCH   = 4,
    nr5g_ULSCH   = 5,
    /* TODO */
} nr5g_Trch_e;
typedef uchar nr5g_Trch_v;


typedef enum {
    nr5g_LT_SPARE = 0,
    nr5g_BCCHoBCH = 1,
    nr5g_BCCHoDLSCH  = 2, 
    nr5g_PCCH = 3,
    nr5g_CCCH = 4,
    nr5g_DCCH = 5,
    nr5g_DTCH = 6,
    /* ADD Other */
} nr5g_LchType_e;
typedef uchar nr5g_LchType_v;

typedef enum {
    nr5g_UL = nr5g_USER,
    nr5g_DL = nr5g_NET,
} nr5g_Direction_e;
typedef uchar nr5g_Direction_v;

typedef enum {
    nr5g_C_RNTI      = 1,
    nr5g_SPS_RNTI    = 2,
    nr5g_T_RNTI      = 3,
    nr5g_RA_RNTI     = 4,
    nr5g_SI_RNTI     = 5,
    nr5g_P_RNTI      = 6,
} nr5g_RntiType_e;
typedef uchar nr5g_RntiType_v;



typedef enum {
    
    nr5g_RA_SUCCESS = 1,
    nr5g_RA_RECOVER_FROM_PROBLEM = 2,
    nr5g_RA_UNSUCCESFULL = 3, /* Random access Unsuccessful */
    nr5g_CR_UNSUCCESFULL = 4, /* Contention Resolution Unsuccessful */
    
} nr5g_RA_RES_e;
typedef uchar nr5g_RA_RES_v;

/* 33.501 */
typedef enum {
    nr5g_NEA0 = 0x00, // equal to EEA0
    nr5g_NEA1 = 0x01, // equal to EEA1
    nr5g_NEA2 = 0x02, // equal to EEA2
    nr5g_NEA3 = 0x03, // equal to EEA3

    nr5g_NEA_NONE = 0xff     /* not in 33.501; for security de-activation */
} nr5g_NEA_e;
typedef uchar nr5g_NEA_v;

/* 33.501 */
typedef enum {
    nr5g_NIA1 = 0x01, // equal to EIA1
    nr5g_NIA2 = 0x02, // equal to EIA2
    nr5g_NIA3 = 0x03, // equal to EIA3

    nr5g_NIA_NONE = 0xff     /* not in 33.501; for security de-activation */
} nr5g_NIA_e;
typedef uchar nr5g_NIA_v;

typedef enum {
    nr5g_ABSENT   = 0,
    nr5g_PRESENT  = 1,
} nr5g_SdapHeader_e;
typedef uchar nr5g_SdapHeader_v;

typedef enum {
    nr5g_FALSE = 0,
    nr5g_TRUE  = 1,
} nr5g_DefaultDRB_e;
typedef uchar nr5g_DefaultDRB_v;

/*
 * NR5G Identifier.
 * Univocally identify an NR5G UE or NR5G Cell.
 * Restrictions on admitted values can be specified in including interfaces.
 */
typedef struct {
    uint               UeId;      /* UE Identifier (Note 1,3) */
    uint               CellId;    /* Cell Identifier (Note 2,3) */
    uint               BeamIdx;   /* Beam Index (Note 4) */
} nr5g_Id_t;

/*
 * Functions for logging reference START
 */
/* In nr5g nr5g_MAX_LI=1 because 1 PDCP SDU (<-> 1 PDCP PDU <-> 1 RLC SDU) <-> 1 RLC PDU */
/* In lte  nr5g_MAX_LI=64 because 1 PDCP SDU <-> 1 RLC PDU but often: */
/*                               2...64 PDCP SDU <-> 1 RLC PDU or */
/*                               1 PDCP SDU <-> 2...64... RLC PDU */
#define nr5g_MAX_LI (1) // debug: Was 64
/* This structure takes into account the reference for UL logging trough layers */
typedef struct {
    uint PdcpSn;
} nr5g_Ref_Ul_t;

typedef struct {
    ushort rlcPdcpSn[nr5g_MAX_LI];
    ushort sduLen[nr5g_MAX_LI];
} nr5g_Ref_Dl_SduInfo_t;

//nr5g_MAX_MAC_SDU -> it must be 1024 to be aligned with sw architecture, but it has been decremented to 256 due to memory allocation issue
#define nr5g_MAX_MAC_SDU (256)
/* This structure takes into account the reference for DL logging trough layers (MAC to RLC) */
typedef struct {
    uchar logRefFlag;
    ushort numPdu;
    ushort RlcSn[nr5g_MAX_MAC_SDU];
    uint UeId[nr5g_MAX_MAC_SDU];
    uchar RbId[nr5g_MAX_MAC_SDU];
} nr5g_Ref_Dl_t;

/* This structure takes into account the reference for DL logging trough layers (RLC to PDCP) */
typedef struct {
    uint UeId;
    uchar RbId;
    uchar numPduForSdu;
    nr5g_Ref_Dl_SduInfo_t SduInfo;
} nr5g_Ref_Dl_1_t;

#define nr5g_RefDl_PDCP_Size (9)

/*
 * Note 1
 * 'UeId' != -1 univocally identify an UE.
 * -1 value means "no UE ID" and 'CellId' must be valid.
 *
 *  Note 2
 * If 'UeId' == -1, 'CellId' != -1 univocally identify a Cell.
 * -1 value means "no CELL ID", and 'UeId' must be valid.
 * 
 *  Note 3
 * One between 'CellId' and 'UeId' must be different from -1 (i.e. valid).
 * If both 'UeId' 'CellId' are valid, only 'UeId' is considered
 */

/*
 * Functions for logging reference END
 */

#define nr5g_BOT_PDCP         1
#define nr5g_BOT_RLCMAC       2
#define nr5g_BOT_PHY          3

#define nr5g_TRF_PDCP         1
#define nr5g_TRF_UDG          2
#define nr5g_TRF_CNTR_UDG     3

#define nr5g_TRF_TM_HARQ      4
#define nr5g_TRF_TM_MAC       5
#define nr5g_TRF_TM_RLC       6
#define nr5g_TRF_TM_PDCP      7
#define nr5g_TRF_TM_NAS       8
#define nr5g_TRF_RLC          9

#pragma pack()
 #endif
