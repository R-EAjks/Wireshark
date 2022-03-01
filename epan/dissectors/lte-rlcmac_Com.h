/*********************************************************************
  Title: Common LTE-PDCP Definitions
 *********************************************************************/


#ifndef lte_rlcmac_Com_DEFINED
#define lte_rlcmac_Com_DEFINED


#define lte_rlcmac_Com_VERSION   "2.4.3"

/*------------------------------------------------------------------*
 |  NOTES                                                           |
 *------------------------------------------------------------------*
 *
 * This interface conforms to the rules specified in `lsu.h'.
 *  
 *  
 * REFERENCES TODO
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
 * When more V or FE Fields are concatenated, correspondent objects
 * must be concatenated in the same order.
 * 
 * DEFINES & STRUCT VALIDITY
 *
 * The defines & structures present in this interface are used
 * both by Node B and RNC stacks.
 * Some elements can be actually used only by one type of stack.
 * 
 */

/*------------------------------------------------------------------*
 |  PARAMETERS USED IN PRIMITIVES                                   |
 *------------------------------------------------------------------*/

#define lte_rlcmac_Com_MAX_DATA_SIZE    1600 /* Max value of PDCP SDU data size */

/*------------------------------------------------------------------*
 |  CODES USED IN PRIMITIVES                                        |
 *------------------------------------------------------------------*/

/*
 * ERROR AND RESULT CODES (lte_rlcmac_Com_EXXX)
 */

/* GENERIC ERRORS */
#define lte_rlcmac_Com_ENOERR           0  /* (0x0000) No Error */
#define lte_rlcmac_Com_ELEN             -1 /* (0xFFFF) Wrong msg length */
#define lte_rlcmac_Com_EPDULEN          -2 /* (0xFFFE) Wrong PDU length */
#define lte_rlcmac_Com_EEXP             -3 /* (0xFFFD) Primitive not expected */
#define lte_rlcmac_Com_ERES             -4 /* (0xFFFC) Resource error */
#define lte_rlcmac_Com_EPARM            -6 /* (0xFFFA) Wrong parameter */
#define lte_rlcmac_Com_ETYPE            -7 /* (0xFFF9) Invalid primitive type */

/* LAYER ERRORS */
#define lte_rlcmac_Com_EBIND            -8  /* Bind error */
#define lte_rlcmac_Com_ESOCK            -9  /* Socket error */
#define lte_rlcmac_Com_EFUEID           -10 /* Cannot find UE Id */
#define lte_rlcmac_Com_EDUPUEID         -11 /* Duplicated UE Id */
#define lte_rlcmac_Com_EFCELL           -12 /* Cannot find Cell */
#define lte_rlcmac_Com_EFCELLID         -13 /* Cannot find Cell Id */
#define lte_rlcmac_Com_ECELLID          -14 /* Cell Id error */
#define lte_rlcmac_Com_EDUPCELLID       -15 /* Duplicated Cell Id */
#define lte_rlcmac_Com_EMAXRB           -16 /* TODO */
#define lte_rlcmac_Com_EFRBID           -17 /* Cannot find RbId */
#define lte_rlcmac_Com_ERLCMODE         -18 /* RLC mode error */
#define lte_rlcmac_Com_EMAX_RA_TRANSM   -19 /* TODO */
#define lte_rlcmac_Com_EEXPFR           -20 /* Unexpected frame */
#define lte_rlcmac_Com_EPROC            -21 /* Procedure error */
#define lte_rlcmac_Com_EFRNTI           -22 /* Cannot find RNTI */
#define lte_rlcmac_Com_ECELL_CFG        -23 /* CELL not configured */
#define lte_rlcmac_Com_EFRLC            -24 /* Cannot find RLC */
#define lte_rlcmac_Com_EFUE             -25 /* Cannot find UE */
#define lte_rlcmac_Com_EMAX_SCELL       -26 /* Too many SCell Ids */
#define lte_rlcmac_Com_EFRBTYPE         -27 /* Cannot find Rb type */
#define lte_rlcmac_Com_EDUP_RBID        -28 /* Duplicated Rb Id */
#define lte_rlcmac_Com_ELCTYPE          -29 /* Unexpected Lch type */
#define lte_rlcmac_Com_EMBMS_CFG        -30 /* MBMS not correctly configured */
#define lte_rlcmac_Com_ESIDE            -31 /* */
#define lte_rlcmac_Com_ENUMINFO         -32 /* */
#define lte_rlcmac_Com_EAREAIDX         -33 /* */
#define lte_rlcmac_Com_ERBUNCFG         -34 /* */
#define lte_rlcmac_Com_ERACHPROBE       -35 /* Rach Probe procedure is already ongoing */
#define lte_rlcmac_Com_ELTEMNBINCONST   -36 /* LTE-M, NB-IOT configuration inconsistency */
#define lte_rlcmac_Com_ERANOTPERF       -37 /* RA cannot be performed */

#define lte_rlcmac_Com_ERRNONE            (0) /* Ack/Nack no error */
/* MBMS ACK ERRORS */
#define lte_rlcmac_Com_ACKERRINIT         (1) /* MBMS ack error initializing value */
#define lte_rlcmac_Com_ACKERRTOOEARLY     (2) /* MBMS ack error command arrived too early */
#define lte_rlcmac_Com_ACKERRNOENOUGHRES  (3) /* MBMS ack error no enough resources */
#define lte_rlcmac_Com_ACKERRRLCNETALRCFG (4) /* MBMS ack error rlc net already configured */
#define lte_rlcmac_Com_ACKERRRLCNETNOTCFG (5) /* MBMS ack error rlc net not configured yet */

/* RCP ACK ERRORS */
#define lte_rlcmac_Com_NACKERRNOUE        (6)  /* RCP nack error ue not found */
#define lte_rlcmac_Com_NACKERRSHREX       (7)  /* RCP nack error shared memory exhausted */
#define lte_rlcmac_Com_NACKERRPRODRVSYNC  (8)  /* RCP nack error PRO-DRV synchronization */
#define lte_rlcmac_Com_NACKERRNOTFWDDRV   (9)  /* RCP nack error not forwarded to DRV */
#define lte_rlcmac_Com_NACKERRSTOREFLAG   (10) /* RCP nack error invalid toStore flag */

#undef uint64
#define uint64 unsigned long long int   /* 64 bit integer */

/* RLC and MAC statistics */
typedef struct
{
    uint    CqiLen;         /* CQI bit length */
    uint    Cqi_lo;         /* Channel Quality Indicator (LSB) */
    uint    Cqi_hi;         /* Channel Quality Indicator (MSB) */
    uint    Bsr;            /* BSR counter TODO capire se serve. forse ha piu' senso il valore BSR riportato */

    int     PowerHeadr;     /* Power Headroom [dB] */
    int     Pcmax;          /* Maximum configured power [dB] */

    int Pue_PUSCH;          /* PUSCH power level of uplink tx for the UE (0.25 dBm) */
    int Pue_PUCCH;          /* PUCCH power level of uplink tx for the UE (0.25 dBm) */
    uint SR_attemptsMax;       /* Maximum number of scheduling request sent
                                  before receiving a grant last second. */
    uint SR_attemptsMean;       /* Number of scheduling request sent
                                   before receiving grants last second
                                   divided by number of grants. */

    int     TimingAdv;      /* Timing Advance (cumulative) (1) */
    
    uint    RlcSduTx;       /* Number of RLC SDU transmitted */
    uint    RlcSduRx;       /* Number of RLC SDU received */
    uint    RlcPduTx;       /* Number of RLC PDU transmitted */
    uint    RlcPduRx;       /* Number of RLC PDU received */
    uint    RlcPduDisc;     /* Number of RLC PDU discarded */
    uint    RlcSegPduTx;    /* Number of RLC segment PDU transmitted (just a retransmission) */
    uint    RlcSegPduRx;    /* Number of RLC segment PDU received */
    uint    RlcSegPduDisc;  /* Number of RLC segment PDU discarded */

    uint    RlcNakPduRecv;   /* Number of RLC PDU pointed out in received Status Report */
    uint    RlcNakSegPduRecv;/* Number of RLC segment PDU (SOStart/SOEnd) pointed out in received Status Report */
    uint    RlcReTxPdu;      /* Number of RLC PDU retransmitted */
    uint    RlcNakPduSent;   /* Number of RLC PDU pointed out in transmitted Status Report */
    uint    RlcNakSegPduSent;/* Number of RLC segment PDU (SOStart/SOEnd) pointed out in transmitted Status Report */

    uint    macDrxRx;       /* Number of MAC PDU received in a non ActiveState subframe */
    uint    macDrxTx;       /* Number of MAC PDU transmitted in a non ActiveState subframe */

    uint    UlHarqAdaptRetx;    /* Number of UL HARQ Adaptive Retx */
    uint    UlHarqNonAdaptRetx; /* Number of UL HARQ Non-Adaptive Retx */
    uint    TtibNonAdaptRetx;   /* Number of TTIB Non-Adaptive Retx */

    uint    CurrCeLev; /* Current value of LTE-M CE level  */

} lte_rlcmac_Com_Stat_t;

typedef struct
{
    uint    CeLevVolume[4]; /* LTE-M CE level volume (CE level: 0, 1, 2, 3)  */

} lte_rlcmac_Com_Cell_Stat_t;

typedef struct
{
    uint MbsfnRlcPduDisc;     /* Number of RLC PDU discarded */
    uint MbsfnRlcPduRx;       /* Number of RLC PDU received */
    uint MbsfnRlcSduRx;       /* Number of RLC SDU received */
    uint64 OnlyAnt0Rx;        /* Mbsfn only on Antenna0 */
    uint64 Ant01RxMatched;    /* Mbsfn on Antenna0 and Antenna1 and matched Data */
    uint64 Ant01RxMisMatched; /* Mbsfn on Antenna0 and Antenna1 but mismatched Data */
} lte_rlcmac_Com_Mbms_Stat_t;

typedef struct
{
    uint MbsfnRlcPduTx;     /* Number of RLC PDU transmitted */
    uint MbsfnRlcSduTx;     /* Number of RLC SDU transmitted */
} lte_rlcmac_Com_Net_Mbms_Stat_t;

/*
 * NOTES
 *
 * 1) The Timing Adjustment is expressed in units of 16*Ts, 
 *    where Ts is the base time unit equal to 1/(15000*2048) seconds.
 */

#endif
