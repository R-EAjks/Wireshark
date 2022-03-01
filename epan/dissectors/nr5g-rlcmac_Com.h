/*********************************************************************
  Title: Common LTE-PDCP Definitions
 *********************************************************************/


#ifndef nr5g_rlcmac_Com_DEFINED
#define nr5g_rlcmac_Com_DEFINED

#ifdef VERSION_15
#define nr5g_rlcmac_Com_VERSION   "0.5.0"
#else
#define nr5g_rlcmac_Com_VERSION   "0.6.0"
#endif

/*------------------------------------------------------------------*
 |  NOTES                                                           |
 *------------------------------------------------------------------*
 *
 * This interface conforms to the rules specified in `lsu.h'.
 */

/*------------------------------------------------------------------*
 |  PARAMETERS USED IN PRIMITIVES                                   |
 *------------------------------------------------------------------*/

#define nr5g_rlcmac_Com_MAX_DATA_SIZE    1600 /* Max value of PDCP SDU data size TODO da togliere */

/*------------------------------------------------------------------*
 |  CODES USED IN PRIMITIVES                                        |
 *------------------------------------------------------------------*/

/*
 * ERROR AND RESULT CODES (nr5g_rlcmac_Com_EXXX)
 */

/* GENERIC ERRORS */
#define nr5g_rlcmac_Com_ENOERR           0  /* (0x0000) No Error */
#define nr5g_rlcmac_Com_ELEN             -1 /* (0xFFFF) Wrong msg length */
#define nr5g_rlcmac_Com_EPDULEN          -2 /* (0xFFFE) Wrong PDU length */
#define nr5g_rlcmac_Com_EEXP             -3 /* (0xFFFD) Primitive not expected */
#define nr5g_rlcmac_Com_ERES             -4 /* (0xFFFC) Resource error */
#define nr5g_rlcmac_Com_EPARM            -6 /* (0xFFFA) Wrong parameter */
#define nr5g_rlcmac_Com_ETYPE            -7 /* (0xFFF9) Invalid primitive type */

/* LAYER ERRORS */
#define nr5g_rlcmac_Com_EBIND            -8  /* Bind error */
#define nr5g_rlcmac_Com_ESOCK            -9  /* Socket error */
#define nr5g_rlcmac_Com_EFUEID           -10 /* Cannot find UE Id */
#define nr5g_rlcmac_Com_EDUPUEID         -11 /* Duplicated UE Id */
#define nr5g_rlcmac_Com_EFCELL           -12 /* Cannot find Cell */
#define nr5g_rlcmac_Com_EFCELLID         -13 /* Cannot find Cell Id */
#define nr5g_rlcmac_Com_ECELLID          -14 /* Cell Id error */
#define nr5g_rlcmac_Com_EDUPCELLID       -15 /* Duplicated Cell Id */
#define nr5g_rlcmac_Com_EMAXRB           -16 /* TODO */
#define nr5g_rlcmac_Com_EFRBID           -17 /* Cannot find RbId */
#define nr5g_rlcmac_Com_ERLCMODE         -18 /* RLC mode error */
#define nr5g_rlcmac_Com_EMAX_RA_TRANSM   -19 /* TODO */
#define nr5g_rlcmac_Com_EEXPFR           -20 /* Unexpected frame */
#define nr5g_rlcmac_Com_EPROC            -21 /* Procedure error */
#define nr5g_rlcmac_Com_EFRNTI           -22 /* Cannot find RNTI */
#define nr5g_rlcmac_Com_ECELL_CFG        -23 /* CELL not configured */
#define nr5g_rlcmac_Com_EFRLC            -24 /* Cannot find RLC */
#define nr5g_rlcmac_Com_EFUE             -25 /* Cannot find UE */
#define nr5g_rlcmac_Com_EMAX_SCELL       -26 /* Too many SCell Ids */
#define nr5g_rlcmac_Com_EFRBTYPE         -27 /* Cannot find Rb type */
#define nr5g_rlcmac_Com_EDUP_RBID        -28 /* Duplicated Rb Id */
#define nr5g_rlcmac_Com_ELCTYPE          -29 /* Unexpected Lch type */
#define nr5g_rlcmac_Com_ESIDE            -31 /* */
#define nr5g_rlcmac_Com_ENUMINFO         -32 /* */
#define nr5g_rlcmac_Com_ERBUNCFG         -34 /* */
#define nr5g_rlcmac_Com_EFDBEAM          -35 /* Cannot find Dbeam */
#define nr5g_rlcmac_Com_EFDBEAMID        -36 /* Cannot find DbeamId */

/* RCP ACK ERRORS */
#define nr5g_rlcmac_Com_NACKERRNOUE        (-37)  /* RCP nack error ue not found */
#define nr5g_rlcmac_Com_NACKERRSHREX       (-38)  /* RCP nack error shared memory exhausted */
#define nr5g_rlcmac_Com_NACKERRPRODRVSYNC  (-39)  /* RCP nack error PRO-DRV synchronization */
#define nr5g_rlcmac_Com_NACKERRNOTFWDDRV   (-40)  /* RCP nack error not forwarded to DRV */
#define nr5g_rlcmac_Com_NACKERRSTOREFLAG   (-41) /* RCP nack error invalid toStore flag */

/* LOWER LAYER ERRORS */
#define nr5g_rlcmac_Com_ELL_BASE         (-256) /* Lower Layer error base */
#define nr5g_rlcmac_Com_ELL_EFMAT        (nr5g_rlcmac_Com_ELL_BASE - 1) /* Message is too long */
#define nr5g_rlcmac_Com_ELL_EINVAL       (nr5g_rlcmac_Com_ELL_BASE - 2) /* Illegal parameter */
#define nr5g_rlcmac_Com_ELL_EUNEXP       (nr5g_rlcmac_Com_ELL_BASE + 1) /* Unexpected primitive */
#define nr5g_rlcmac_Com_ELL_ESRCH        (nr5g_rlcmac_Com_ELL_BASE + 3) /* Invalid object identifier */
#define nr5g_rlcmac_Com_ELL_EMAX         (nr5g_rlcmac_Com_ELL_BASE + 5) /* Maximum number of objects reached */


// NR TODO da ridefinire
/* VERBOSITY */

// NR TODO da ridefinire


/* RLC statistics */
typedef struct
{
    uint32_t TxPduNum;            // Number of UL RLC data PDUs transmitted
    uint32_t TxPduVol;            // Volume of UL RLC data PDUs transmitted [bytes]
    uint32_t RxPduNum;            // Number of DL RLC data PDUs received
    uint32_t RxPduVol;            // Volume of DL RLC data PDUs received [bytes]
        uint32_t TxPduNumRetx;                  // Number of UL RLC PDU retransmitted
    uint32_t RxPduNumDisc;        // Number of DL RLC data PDUs discarded

    uint32_t RlcNakPduRecv;         /* Number of NACK RLC PDU received in STATUS REPORT */
    uint32_t RlcAckPduRecv;         /* Number of ACK RLC PDU received in STATUS REPORT */

        uint32_t RlcNakPduSent;   /* Number of RLC PDU pointed out in transmitted Status Report */
        uint32_t RlcAckPduSent;   /* Number of RLC PDU pointed out in transmitted Status Report */

    uint32_t PduOfWinSt;       //PDU out of win in received STATUS

    uint32_t Vta, Vts;         //Rlc Tx Status
    uint32_t Vrr, Vrh;         //Rlc Rx Status

        uint32_t RlcReTxPduMax;    // Number of RLC PDU retransmitted till to Max RTX times
} nr5g_rlcmac_Com_RlcStatElem_t;

/* NOTE
 * UL(DL) means consider UL for simulated UE side and DL for simulated net side. 
 * DL(UL) means consider DL for simulated UE side and UL for simulated net side.
 */

/* MAC statistics */
typedef struct
{
    uint32_t    NormPH;            // The normalized Power Headroom reported by UE [dB]

    uint32_t    TimingAdvRAR;   /* Timing Advance Command in received RAR (index value) */

    uint32_t    NumAccPrach;     // Number of access on PRACH
    uint32_t    NumRcvdRar;     // Number of received RAR
    uint32_t    NumAccPrachFail; // Number of failed access on PRACH

    uint32_t    NumPucch;           // Number of PUCCH Data Req
    uint32_t    NumPusch;           //Number of PUSCH Data Req
    uint32_t    NumHarqPucch;       // Number of PUCCH Harq
    uint32_t    NumHarqPusch;       //Number of PUSCH Harq
    uint32_t    NumSr;              // Number of SR
    uint32_t    NumSrsA;            // Number of aperiodic SRS
    uint32_t    NumSrsP;            // Number of periodic SRS
    uint32_t    NumCsiA;            // Number of aperiodic CSI
    uint32_t    NumCsiP;            // Number of periodic CSI

    uint32_t    NumDrxRx;       /* Number of PDCCH for DL data received during not active time */
    uint32_t    NumDrxTx;       /* Number of PDCCH for UL data received during not active time */

} nr5g_rlcmac_Com_MacStatBasic_t;

typedef struct
{
    uint32_t    BufferSize[8];    // The Buffer Size per logical channel group [bytes]

} nr5g_rlcmac_Com_MacStatBuff_t;

#define nr5g_rlcmac_Com_MAX_TX_DL_LAYER  4
#define nr5g_rlcmac_Com_MAX_TX_UL_LAYER  2

typedef struct
{
    /*PDSCH part */
    uint32_t        xPdschIniTxNum;    // Number of initial trasmissions on xPDSCH
    uint32_t        xPdschIniTxVol;    // Volume of transport blocks of initial transmission on xPDSCH [bytes]
    uint32_t        xPdschTxNum;    // Sum of initial and retrasmissions on xPDSCH
    uint32_t        xPdschTxVol;    // Volume of initial and retrasmissions on xPDSCH
    uint32_t        xPdschRtxUne;    // Sum of unexpected Rtx on xPDSCH (no previous CRC KO)
    uint32_t        xPdschRtxRv0;    // Sum of retransmissions with RV =0
    uint32_t        xPdschRtxRvN;    // Sum of retransmissions with RV != 0

    uint32_t    NumTbCrcSucc;   // Number of TB CRC success
    uint32_t    NumTbCrcFail;   // Number of TB CRC fail
    uint32_t        NumTbCrcFailAmm;// Number of TB CRC fail for mobility (Simulated)

    uint32_t    NumCbCrcSucc;   // Number of CB CRC success
    uint32_t    NumCbCrcFail;   // Number of CB CRC fail

    uint32_t        xPdschTxNum4L[nr5g_rlcmac_Com_MAX_TX_DL_LAYER]; //Sum of Tx for layer

    /*PUSCH part */
    uint32_t        xPuschIniTxNum;    // Number of initial trasmissions on xPUSCH
    uint32_t        xPuschIniTxVol;    // Volume of transport blocks of initial transmission on xPUSCH [bytes]
    uint32_t        xPuschTxNum;    // Sum of initial and retrasmissions on xPUSCH
    uint32_t        xPuschTxVol;    // Volume of initial and retrasmissions on xPUSCH
    uint32_t        xPuschRtxRv0;    // Sum of retransmissions with RV =0
    uint32_t        xPuschRtxRvN;    // Sum of retransmissions with RV != 0
    uint32_t        HarqFeed;       // Number of HARQ feedback received
    uint32_t        HarqFeedAck;    // Number of ACK HARQ feedback

    uint32_t        xPuschTxNum4L[nr5g_rlcmac_Com_MAX_TX_UL_LAYER]; //Sum of Tx for layer
} nr5g_rlcmac_Com_MacStatPxsch_t;

/*
 *  PDSCH Troughput = xPdschTxVol/DeltaTs
 *  PDSCH Rtx = xPdschTxNum - xPdschIniTxNum
 *  PDSCH Bler = (NumTbCrcFail/(NumTbCrcFail + NumTbCrcSucc))
 *  PDSCH AMM Bler = (NumTbCrcFailAmm/(NumTbCrcFailAmm + NumTbCrcSucc))
 *  CRC CB KO ratio (CB BLER)= (NumCbCrcFail / (NumCbCrcSucc + NumCbCrcFail))
 *  RTX Ratio = (xPdschTxNum - xPdschIniTxNum)/xPdschTxNum
 *
 *
 *   PUSCH Troughput = xPuschTxVol/DeltaTs
 *   PUSCH Rtx      = xPuschTxNum - xPuschIniTxNum
 *   PUSCH RtxRate  = (xPuschTxNum - xPuschIniTxNum)/xPuschTxNum
 *   NAK HARQ ratio = (HarqFeed - HarqFeedAck) / HarqFeed
 *
 */

typedef struct
{
    uint32_t        NDci0_0;        //Number of DCIs (0_0)
    uint32_t        NDci0_1;        //Number of DCIs (0_1)
    uint32_t        NDci1_0;        //Number of DCIs (1_0)
    uint32_t        NDci1_1;        //Number of DCIs (1_1)
    uint32_t        NDci2_0;        //Number of DCIs (2_0)
    uint32_t        NDci2_1;        //Number of DCIs (2_1)
    uint32_t        NDci2_2;        //Number of DCIs (2_2)
    uint32_t        NDci2_3;        //Number of DCIs (2_3)

    uint32_t        DciSameSlot;    // DCI (both UL and DL) in the same slot

    uint32_t        uDciDisc;       //Discarded DCI for uplink
    uint32_t        dDciDisc;       //Discarded DCI for downlink

} nr5g_rlcmac_Com_MacStatPdcch_t;

#define nr5g_rlcmac_Com_MAX_ANTENNAS  4

typedef struct
{
    uint    BeamId;                      /* Beam Identifier */
    uint    SsbIndex;                    /* SS block index */
    int     minRsrp[nr5g_rlcmac_Com_MAX_ANTENNAS];     /* minimum RSRP (Reference Signal Received Power or antenna 0 - 3 dBm) [1]*/
    int     maxRsrp[nr5g_rlcmac_Com_MAX_ANTENNAS];     /* maximum RSRP (Reference Signal Received Power or antenna 0 - 3 dBm) [1]*/
    int     Rsrp[nr5g_rlcmac_Com_MAX_ANTENNAS];        /* Average RSRP (Reference Signal Received Power or antenna 0 - 3 dBm) [1]*/
    
    int     minSnr[nr5g_rlcmac_Com_MAX_ANTENNAS];      /* minimum SNR (Signal to noise ratio or antenna 0 - 3 dB) [1] */
    int     maxSnr[nr5g_rlcmac_Com_MAX_ANTENNAS];      /* maximum SNR (Signal to noise ratio or antenna 0 - 3 dB) [1] */
    int     Snr[nr5g_rlcmac_Com_MAX_ANTENNAS];         /* Average SNR (Signal to noise ratio or antenna 0 - 3 dB) [1] */

    int     minRsrq[nr5g_rlcmac_Com_MAX_ANTENNAS];     /* minimum RSRQ (Reference Signal Received Qualiti or antenna 0 - 3 dB) [1]*/
    int     maxRsrq[nr5g_rlcmac_Com_MAX_ANTENNAS];     /* maximum RSRQ (Reference Signal Received Quality or antenna 0 - 3 dB) [1]*/
    int     Rsrq[nr5g_rlcmac_Com_MAX_ANTENNAS];        /* Average RSRQ (Reference Signal Received Quality or antenna 0 - 3 dB) [1]*/

#ifdef VERSION_15
    int     UlGain[nr5g_rlcmac_Com_MAX_ANTENNAS];      /* Digital ul gain per antenna port */
    int     DlGain[nr5g_rlcmac_Com_MAX_ANTENNAS];      /* Digital dl gain per antenna port */
#endif
} nr5g_rlcmac_Com_BeamStat_t; /* Base band specific statistic  */


typedef struct {
    uint8_t   WbPmiX1i1;      /* index i1 for X1 Wideband Precoding Matrix Indicator 3GPP 38.212 (maximum allowed value is 32) */
    uint8_t   WbPmiX1i2;      /* index i2 for X1 Wideband Precoding Matrix Indicator 3GPP 38.212 (maximum allowed value is 32) */
    uint8_t   WbPmiX1i3;      /* index i3 for X1 Wideband Precoding Matrix Indicator 3GPP 38.212 (maximum allowed value is 32)*/
    uint32_t  WbPmiX2;        /* X2 Wideband Precoding Matrix Indicator 3GPP 38.212 */
    uint8_t   Ri;             /* Estimated Rank indicator */
    uint8_t   NumCsiRsPort;
    uint8_t   ReportId;
    uint8_t   Pad;       
} nr5g_rlcmac_Com_PMIt;


typedef struct
{
#ifndef VERSION_15
    int     UlGain[nr5g_rlcmac_Com_MAX_ANTENNAS];      /* Digital ul gain per antenna port */
    int     DlGain[nr5g_rlcmac_Com_MAX_ANTENNAS];      /* Digital dl gain per antenna port */
#endif
    uchar                       NBeam;
    nr5g_rlcmac_Com_BeamStat_t  Beam[1];
} nr5g_rlcmac_Com_BbStat_t; /* Base band specific statistic  */
/*
 * Notes:
 *
 * 1 - To calcultate the right value divide for 10.0
 *
 */



#endif
