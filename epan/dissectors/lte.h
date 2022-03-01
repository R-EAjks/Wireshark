/*********************************************************************
  Title: Common LTE Definitions
 *********************************************************************/

#ifndef lte_DEFINED
#define lte_DEFINED


#define lte_VERSION   "1.3.2"


/*------------------------------------------------------------------*
 |  NOTES (read before interface use                                |
 *------------------------------------------------------------------*
 *
 * This interface conforms to the rules specified in `lsu.h'.
 *  
 *  
 * REFERENCES
 * 
 * [A] X.X.X refers to 3GPP TS 25.427 specification.
 * [B] X.X.X refers to 3GPP TS 25.435 specification.
 * [X Y] Z.Z.Z refers to paragraph Z.Z.Z of [Y] reference of [X].
 * Example:
 * [B 2] 1.4 <=> paragraph 1.4 of 3GPP TS 25.402, which is 
 * reference [2] of [B] (3GPP TS 25.435)
 *
 *  
 * PARAMETER VALUE DESCRIPTION
 *
 * {X, Y, Z} indicates an enumerated value range.
 * {X .. Y} indicates a value range.
 * 'gran.' means granularity.
 *
 * In some cases, struct must not be intended as real C stuct, but as 
 * "variable size" stuct. In this case an object DONT exactly match 
 * with relative struct, which have only a symbolic means.
 * 
 * A struct is a Variable Size Struct when contains some Variable
 * Size Field.
 * 
 * There are two Variable Size Field type:
 * 1- First Element defined Variable Size Field (FE Field);
 * 2- Virtual Element defined Variable Size Field (V Field);
 * 
 * A FE Field must be explicitly indicated, and appears as:
 * 
 * > uint   Field[1];   // [FE Field]
 * 
 * in the C struct appears only the first element of the field.
 * A FE Field can contains some elements of the same type of the 
 * fist, forming in fact a C array of variable length.
 *
 * A V Field must be explicitly indicated, and appears as:
 * 
 * > // uint   Field[];    // [V Field]
 * 
 * in C struct appears nothing, only a comment which symbolically
 * represents the field element(s) (virtual element). 
 * A V Field can contains some elements of the same type of the 
 * virtual element, forming in fact a C array of variable length.
 * 
 * TODO see how def length
 * 
 * When more V or FE Fields are concatenated, corrispondent objects
 * must be concatenated in the same order.
 * 
 * DEFINES & STRUCT VALIDITY
 *
 * The defines & structures present in this interface are used
 * both by Node B and RNC stacks.
 * Some elements can be actually used only by one type of stack.
 * 
 */

#pragma pack(1)


/*------------------------------------------------------------------*
 |  COMMON DEFINES                                                  |
 *------------------------------------------------------------------*/

#define lte_MaxNrOfPDCP         1000    // Prop.
#define lte_MaxNrOfPDP_CTX      32      // Prop. (per UE)
#define lte_MaxNrOfRB           32      // Prop. (per UE)
#define lte_MaxNrOfRB_C_MRB     8       // RB for MCCHs (up to 8 for a single cell, 1 for an MBSFN Area): range 33 - 40
#define lte_MaxNrOfRB_T_MRB     23      // RB for MTCHs (up to 23 for a PMCH of an MBSFN Area, max number of sessions for PMCH for Area 29): range 41 - 63
#define lte_MaxLchIdxSch        10
#define lte_MaxLchIdMch         28
#define lte_MaxLchPrio          16
#define lte_MinLchPrio          1
#define lte_NumLchGroup         4
#define lte_MaxNumSCells        7
#define lte_MaxDrvCells         8
#define lte_MaxDrv              8
#define lte_MaxNumAggCells      8 // TODO vedere valore

/*------------------------------------------------------------------*
 |  COMMON INFORMATION ELEMENTS                                     |
 *------------------------------------------------------------------*/

/*
 * Type of RLC entity
 */
typedef enum {

    lte_TM = 1,  /* Transparent Mode (TM) Entity.         */
    lte_UM = 2,  /* Unacknowledged Mode (UM) RLC Entity.  */
    lte_AM = 3,  /* Acknowledged Mode (AM) RLC Entity.    */

} lte_RlcMode_e;
typedef uchar lte_RlcMode_v;


typedef enum {

    lte_SIG = 1,
    lte_SAE = 2,
    lte_UP = lte_SAE,
    lte_MRB = 3

} lte_RbType_e;
typedef uchar lte_RbType_v;


typedef enum {
    lte_USER        = 1,
    lte_NET         = 2,
    lte_DEB_USER    = 3, /* debug network mode */
    lte_DEB_NET     = 4, /* debug network mode */
} lte_Side_e;
typedef uchar lte_Side_v;


typedef enum {
    lte_BCH     = 1,
    lte_PCH     = 2,
    lte_RACH    = 3,
    lte_DLSCH   = 4,
    lte_ULSCH   = 5,
    lte_MCH     = 6
    /* TODO */
} lte_Trch_e;
typedef uchar lte_Trch_v;


typedef enum {
    lte_LT_SPARE = 0,
    lte_BCCHoBCH = 1,
    lte_BCCHoDLSCH = 2,
    lte_PCCH = 3,
    lte_CCCH = 4,
    lte_DCCH = 5,
    lte_DTCH = 6,
    lte_MCCH = 7,
    lte_MTCH = 8,
    lte_BCCHoDLSCHoBR = 9,
    lte_BCCHoBCHNB = 10,
    lte_BCCHoDLSCHNB = 11,
    lte_CCCH_NB = 12,
    lte_DCCH_NB = 13,
	lte_PCCH_NB = 14,
    /* ADD Other */
} lte_LchType_e;
typedef uchar lte_LchType_v;

typedef enum {
    lte_UL = lte_USER,
    lte_DL = lte_NET,
} lte_Direction_e;
typedef uchar lte_Direction_v;

typedef enum {
    lte_C_RNTI      = 1,
    lte_SPS_RNTI    = 2,
    lte_T_RNTI      = 3,
    lte_RA_RNTI     = 4,
    lte_SI_RNTI     = 5,
    lte_P_RNTI      = 6,
    lte_M_RNTI      = 7
} lte_RntiType_e;
typedef uchar lte_RntiType_v;



typedef enum {
    
    lte_RA_SUCCESS = 1,
    lte_RA_RECOVER_FROM_PROBLEM = 2,
    lte_RA_UNSUCCESFULL = 3, /* Random access Unsuccessful */
    lte_CR_UNSUCCESFULL = 4, /* Contention Resolution Unsuccessful */
    lte_RA_UNSUCCESFULL_NB = 5, /* Random access Unsuccessful: procedure unsuccessfully completed */
    lte_CR_UNSUCCESFULL_NB = 6, /* Contention Resolution Unsuccessful: procedure unsuccessfully completed */
    
} lte_RA_RES_e;
typedef uchar lte_RA_RES_v;

/* 33.401 - 5.1.3.2 */
typedef enum {
    lte_EEA0 = 0x00,
    lte_EEA1 = 0x01,
    lte_EEA2 = 0x02,
    lte_EEA3 = 0x03,

    lte_EEA_NONE = 0xff     /* not in 33.401; for security de-activation */
} lte_EEA_e;
typedef uchar lte_EEA_v;

/* 33.401 - 5.1.4.2 */
typedef enum {
    lte_EIA1 = 0x01,
    lte_EIA2 = 0x02,
    lte_EIA3 = 0x03,

    lte_EIA_NONE = 0xff     /* not in 33.401; for security de-activation */
} lte_EIA_e;
typedef uchar lte_EIA_v;

/*
 * LTE Identifier.
 * Univocally identify an LTE UE or LTE Cell.
 * Restrictions on admitted values can be specified in including interfaces.
 */
typedef struct {
    uint               UeId;      /* UE Identifier (Note 1,3) */
    uint               CellId;    /* Cell Identifier (Note 2,3) */
} lte_Id_t;

#define lte_MAX_LI (64)
/* This structure takes into account the reference for UL logging trough layers */
typedef struct {
	uint UeId;
	uchar RbId;
	ushort PdcpSn;
	uchar NumLi;
	ushort PdcpRlcSn[lte_MAX_LI];
	ushort Li[lte_MAX_LI];
} lte_Ref_Ul_t;

typedef struct {
	ushort rlcPdcpSn[lte_MAX_LI];
	ushort sduLen[lte_MAX_LI];
} lte_Ref_Dl_SduInfo_t;

//lte_MAX_MAC_SDU -> it must be 1024 to be aligned with sw architecture, but it has been decremented to 256 due to memory allocation issue
#define lte_MAX_MAC_SDU (256)
/* This structure takes into account the reference for DL logging trough layers (MAC to RLC) */
typedef struct {
	uchar logRefFlag;
	ushort numPdu;
	ushort RlcSn[lte_MAX_MAC_SDU];
	uint UeId[lte_MAX_MAC_SDU];
	uchar RbId[lte_MAX_MAC_SDU];
} lte_Ref_Dl_t;

/* This structure takes into account the reference for DL logging trough layers (RLC to PDCP) */
typedef struct {
	uint UeId;
	uchar RbId;
	uchar numPduForSdu;
	lte_Ref_Dl_SduInfo_t SduInfo;
} lte_Ref_Dl_1_t;

#define lte_RefDl_PDCP_Size (9)

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

#define lte_BOT_PDCP         1
#define lte_BOT_RLCMAC       2
#define lte_BOT_PHY          3

#define lte_TRF_PDCP         1
#define lte_TRF_UDG          2
#define lte_TRF_CNTR_UDG     3

#define lte_TRF_TM_HARQ         4
#define lte_TRF_TM_MAC          5
#define lte_TRF_TM_RLC          6
#define lte_TRF_TM_PDCP         7
#define lte_TRF_TM_NAS          8

#pragma pack()
#endif
