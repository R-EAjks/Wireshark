/*******************************************************************************
 * SDR driver.
 *
 * Public definitions.
 ******************************************************************************/

#ifndef sdrdrv_lte_def_INCLUDED
#define sdrdrv_lte_def_INCLUDED

#define sdrdrv_lte_def_VER "1.7.0"

/* Statistics of the cell */
typedef struct  sdrdrv_ltedef_FddCellStat_t
{
    ushort  cell_id;        /* cell identifier [0] */
    uchar   spare1[2];
    
    int     sens[4];        /* current sensitivity level for antenna 0 - 3 (dBm) [1] */
    int     outpwr;         /* current output power (dBm) [1] */
    
    ushort  sfn;            /* system frame number, -1 = Not synchronized */
    ushort  subframe;       /* subframe number */
    
    uchar   bound;          /* cell available or bounded (True/False) */
    uchar   spare2[3];
    
    int     freqError;      /* Frequency error [Hz] */

    /* MIB info, see TS 36.331, MasterInformationBlock ie */
    uchar   dl_Bandwidth;    /* Trasmission bandwidth (Number of Resource Block NRB)
                             (6, 15, 25, 50, 75, 100) */
    uchar   phich_Duration; /* PHICH-Duration, see see TS 36.211, 6.9.3.
                             ( 0 = normal, 1 = extended) */
    uchar   phich_Resource; /* Ng, see TS 36.211, 6.9.
                             (0 = oneSixth, 1 = half, 2 = one, 3 = two) */
    uchar   spare3;
    
    /* Stats */
    uint    pdcchDci_0;     /* DCI0 counter */
    uint    pdcchDci_1;     /* DCI1 counter */
    uint    pdcchDci_1A;    /* DCI1A counter */
    uint    pdcchDci_2;     /* DCI2 counter */
    uint    pdcchDci_2A;    /* DCI2A counter */

    uint    pdschMcs[32];   /* PDSCH MCS counters */
    uint    puschMcs[32];   /* PUSCH MCS counters */

    uint    dl_prb_0_10;       /* DL PRB between 0 and 10 (0 <= PRB < 10) counter */
    uint    dl_prb_10_20;      /* DL PRB between 10 and 20 (10 <= PRB < 20) counter */
    uint    dl_prb_20_30;      /* DL PRB between 20 and 30 (20 <= PRB < 30) counter */
    uint    dl_prb_30_40;      /* DL PRB between 30 and 40 (30 <= PRB < 40) counter */
    uint    dl_prb_40_50;      /* DL PRB between 40 and 50 (40 <= PRB < 50) counter */
    uint    dl_prb_50_60;      /* DL PRB between 50 and 60 (50 <= PRB < 60) counter */
    uint    dl_prb_60_70;      /* DL PRB between 60 and 70 (60 <= PRB < 70) counter */
    uint    dl_prb_70_80;      /* DL PRB between 70 and 80 (70 <= PRB < 80) counter */
    uint    dl_prb_80_90;      /* DL PRB between 80 and 90 (80 <= PRB < 90) counter */
    uint    dl_prb_90_100;     /* DL PRB between 90 and 100 (90 <= PRB < 100) counter */

    uint    ul_prb_0_10;       /* UL PRB between 0 and 10 (0 <= PRB < 10) counter */
    uint    ul_prb_10_20;      /* UL PRB between 10 and 20 (10 <= PRB < 20) counter */
    uint    ul_prb_20_30;      /* UL PRB between 20 and 30 (20 <= PRB < 30) counter */
    uint    ul_prb_30_40;      /* UL PRB between 30 and 40 (30 <= PRB < 40) counter */
    uint    ul_prb_40_50;      /* UL PRB between 40 and 50 (40 <= PRB < 50) counter */
    uint    ul_prb_50_60;      /* UL PRB between 50 and 60 (50 <= PRB < 60) counter */
    uint    ul_prb_60_70;      /* UL PRB between 60 and 70 (60 <= PRB < 70) counter */
    uint    ul_prb_70_80;      /* UL PRB between 70 and 80 (70 <= PRB < 80) counter */
    uint    ul_prb_80_90;      /* UL PRB between 80 and 90 (80 <= PRB < 90) counter */
    uint    ul_prb_90_100;     /* UL PRB between 90 and 100 (90 <= PRB < 100) counter */
    
    int     minRspl[4];     /* minimum RSPL (Reference signal power level for antenna 0 - 3)(dBm) [2][1] */
    int     maxRspl[4];     /* maximum RSPL (Reference signal power level for antenna 0 - 3)(dBm) [2][1] */
    int     Rspl[4];        /* RSPL (Reference signal power level for antenna 0 - 3)(dBm) [2][1] */
    
    int     minSnr[4];      /* minimum SNR (Signal to noise ratio for antenna 0 - 3)(dB) [6][1] */
    int     maxSnr[4];      /* maximum SNR (Signal to noise ratio for antenna 0 - 3)(dB) [6][1] */
    int     Snr[4];         /* SNR (dB) [6][1] */
    
    int     minPathloss[4]; /* minimum signal pathloss for antenna 0 - 3 (dB) [2][1] */
    int     maxPathloss[4]; /* maximum signal pathloss for antenna 0 - 3 (dB) [2][1] */
    int     Pathloss[4];    /* signal pathloss for antenna 0 - 3 (dB) [2][1] */
    
    uint    pdschBytes;     /* PDSCH received bytes [5] */
    uint    puschBytes;     /* PUSCH trasmitted bytes [5] */
    uint    pdschTrough;    /* PDSCH troughput (kByte/sec) [5] */
    uint    puschTrough;    /* PUSCH troughput (kByte/sec) [5] */
    
    uint    pdschCrcOk;     /* PDSCH CRC OK counter [7] */
    uint    pdschCrcOkRetx; /* PDSCH CRC OK of Retx counter [7] */
    uint    pdschCrcError;  /* PDSCH CRC error counter [7] */
    uint    pdschCrcErrorRetx; /* PDSCH CRC error of Retx counter [7] */
    uint    pdschCrcErrorSim;  /* Simulated PDSCH CRC error counter [7] */
    uint    pdschUnexpRetx; /* PDSCH Unexpected ReTx counter [7] */

    uint    phichAck;          /* PHICH ACK counter [8] */
    uint    ndiToggled;        /* NDI toggled in DCI counter [8] */
    uint    phichNack;         /* PHICH NACK counter [8] */
    uint    phichDtx;          /* PHICH DTX counter [8] */
    uint    ndiNotToggled;     /* NDI not toggled in DCI counter [8] */
    uint    ackFromPhich;      /* Effective PHICH ACK counter [8] */
    uint    ackFromNdiToggled; /* Effective ACK from NDI toggled in DCI counter [8] */
    uint    nackFromPhich;     /* Effective PHICH NACK counter [8] */
    uint    nackFromDtx;       /* Effective DTX NACK counter [8] */
    uint    nackFromNdi;       /* Effective NACK from NDI not toggled in DCI counter [8] */
    uint    newTx;             /* New Trasmission counter [8] */
    uint    nonAdaptRetx;      /* Non adaptative Retx counter [8] */
    uint    adaptRetx;         /* Adaptative Retx counter [8] */

    ushort  pdschBlerPerc;  /* PDSCH BLER [3] */
    ushort  phichNackPerc;  /* PHICH NACK percentage [3][4] */
    
    int     cellMng;        /* Cell management state 
                                    0=Downloading 
                                    1=Active 
                                    2=Ethernet link down */
    ushort        NumTxAntennas;  // Number of eNb Tx antennas

} sdrdrv_ltedef_FddCellStat_t;
/*
    Note 0 - All ones (0xFFFF...) means that the result is not currently available.
   
    Note 1 - All ones exept first (0x7FFF...) means that the result is not currently available.
   
    Note 2 - The value is encoded in Q.2 format. So the effective value is:
      eff_value = enc_val / 4.
   
    Note 3 - The value is encoded in Q.16 format. So the effective value is:
      eff_value = enc_val / 65536.
   
    Note 4 - Calculated as nack per sum of nack plus ack:
      perc = NumNack/(NumNack + NumAck)
   
    Note 5 - referred to the Transport Block (TB) data.
   
    Note 6 - The value is encoded in Q.8 format. So the effective value is:
      eff_value = enc_val / 256.
   
    Note 7 - see sdrdrv_ltedef_FddUeStat_t Note 6.
    
    Note 8 - see sdrdrv_ltedef_FddUeStat_t Note 7.
 */


/* Statistic descriptor for UEs */
typedef struct sdrdrv_ltedef_FddUeStat_t
{
    uint    pdcchDci_0;     /* DCI0 counter */
    uint    pdcchDci_1;     /* DCI1 counter */
    uint    pdcchDci_1A;    /* DCI1A counter */
    uint    pdcchDci_2;     /* DCI2 counter */
    uint    pdcchDci_2A;    /* DCI2A counter */

    uint    pdschMcs[32];   /* PDSCH MCS counters */
    uint    puschMcs[32];   /* PUSCH MCS counters */

    uint    lastPdschMcs;   /* Last assigned PDSCH MCS */
    uint    lastPuschMcs;   /* Last assigned PUSCH MCS */

    uint    dl_prb_0_10;       /* DL PRB between 0 and 10 (0 <= PRB < 10) counter */
    uint    dl_prb_10_20;      /* DL PRB between 10 and 20 (10 <= PRB < 20) counter */
    uint    dl_prb_20_30;      /* DL PRB between 20 and 30 (20 <= PRB < 30) counter */
    uint    dl_prb_30_40;      /* DL PRB between 30 and 40 (30 <= PRB < 40) counter */
    uint    dl_prb_40_50;      /* DL PRB between 40 and 50 (40 <= PRB < 50) counter */
    uint    dl_prb_50_60;      /* DL PRB between 50 and 60 (50 <= PRB < 60) counter */
    uint    dl_prb_60_70;      /* DL PRB between 60 and 70 (60 <= PRB < 70) counter */
    uint    dl_prb_70_80;      /* DL PRB between 70 and 80 (70 <= PRB < 80) counter */
    uint    dl_prb_80_90;      /* DL PRB between 80 and 90 (80 <= PRB < 90) counter */
    uint    dl_prb_90_100;     /* DL PRB between 90 and 100 (90 <= PRB < 100) counter */

    uint    ul_prb_0_10;       /* UL PRB between 0 and 10 (0 <= PRB < 10) counter */
    uint    ul_prb_10_20;      /* UL PRB between 10 and 20 (10 <= PRB < 20) counter */
    uint    ul_prb_20_30;      /* UL PRB between 20 and 30 (20 <= PRB < 30) counter */
    uint    ul_prb_30_40;      /* UL PRB between 30 and 40 (30 <= PRB < 40) counter */
    uint    ul_prb_40_50;      /* UL PRB between 40 and 50 (40 <= PRB < 50) counter */
    uint    ul_prb_50_60;      /* UL PRB between 50 and 60 (50 <= PRB < 60) counter */
    uint    ul_prb_60_70;      /* UL PRB between 60 and 70 (60 <= PRB < 70) counter */
    uint    ul_prb_70_80;      /* UL PRB between 70 and 80 (70 <= PRB < 80) counter */
    uint    ul_prb_80_90;      /* UL PRB between 80 and 90 (80 <= PRB < 90) counter */
    uint    ul_prb_90_100;     /* UL PRB between 90 and 100 (90 <= PRB < 100) counter */

    uint    pdschBytes;     /* PDSCH received bytes [5] */
    uint    puschBytes;     /* PUSCH trasmitted bytes [5] */
    
    uint    pdschTrough;    /* PDSCH troughput (kByte/sec) [5] */
    uint    puschTrough;    /* PUSCH troughput (kByte/sec) [5] */

    uint    pdschCrcOk;     /* PDSCH CRC OK counter [6] */
    uint    pdschCrcOkRetx; /* PDSCH CRC OK of Retx counter [6] */
    uint    pdschCrcError;  /* PDSCH CRC error counter [6] */
    uint    pdschCrcErrorRetx; /* PDSCH CRC error of Retx counter [6] */
    uint    pdschCrcErrorSim;  /* Simulated PDSCH CRC error counter [6] */
    uint    pdschUnexpRetx; /* PDSCH Unexpected ReTx counter [6] */

    uint    phichAck;          /* PHICH ACK counter [8] */
    uint    ndiToggled;        /* NDI toggled in DCI counter [8] */
    uint    phichNack;         /* PHICH NACK counter [8] */
    uint    phichDtx;          /* PHICH DTX counter [8] */
    uint    ndiNotToggled;     /* NDI not toggled in DCI counter [8] */
    uint    ackFromPhich;      /* Effective PHICH ACK counter [8] */
    uint    ackFromNdiToggled; /* Effective ACK from NDI toggled in DCI counter [8] */
    uint    nackFromPhich;     /* Effective PHICH NACK counter [8] */
    uint    nackFromDtx;       /* Effective DTX NACK counter [8] */
    uint    nackFromNdi;       /* Effective NACK from NDI not toggled in DCI counter [8] */
    uint    newTx;             /* New Trasmission counter [8] */
    uint    nonAdaptRetx;      /* Non adaptative Retx counter [8] */
    uint    adaptRetx;         /* Adaptative Retx counter [8] */

    ushort  pdschBlerPerc;  /* PDSCH BLER [3] */
    ushort  phichNackPerc;  /* PHICH NACK percentage [3][4] */

    uint    tpc;            /* TPC counter */
    uint    lastTpc;        /* Last required TPC */

    uint    rankInfo;       /* Rank information [0]
                               0 = Rank 1
                               1 = Ranf 2 */
    
    short   profSnr;        /* Profile SNR (dB) (1) */
    short   profRadial_speed; /* Radial Speed [km/h] (1) */

    int     profPosition;   /* Profile position relative to station [meters] (1) */
    uchar   profPathloss;   /* Profile Pathloss (dB) (0) */
    char    spare[3];
} sdrdrv_ltedef_FddUeStat_t;
/*
    Note 0 - All ones (0xFFFF...) means that the result is not currently available.
   
    Note 1 - All ones exept first (0x7FFF...) means that the result is not currently available.
   
    Note 2 - The value is encoded in Q.2 format. So the effective value is:
      eff_value = enc_val / 4.
   
    Note 3 - The value is encoded in Q.16 format. So the effective value is:
      eff_value = enc_val / 256.
    Take into account real CRC errors only.
   
    Note 4 - Calculated as nack per sum of nack plus ack:
      perc = NumNack/(NumNack + NumAck)
   
    Note 5 - referred to the Transport Block (TB) data.
   
    Note 6 - The meaning of the counters depends on some conditions.
    Two cases are possible.
    First case is when DL HARQ is disabled and possibly AMM enabled.
    In this case:
    pdschCrcOk consider all first Tx with CRC OK. DL CRC errors/NAK simulated are not considered.
    pdschCrcOkRetx does not apply (zero). 
    pdschCrcError consider all first Tx with CRC error. Only first Tx is possible.
    pdschCrcErrorRetx does not apply (zero).
    pdschCrcErrorSim consider DL CRC errors/NAK simulated.
    pdschUnexpRetx consider all (Unexpected) Retx.
      In case of AMM disabled, Retrasmissions should not apply but are possible in case of some UL errors. For this are considered Unexpected.
      In case of AMM enabled, Retrasmissions should be triggered by DL CRC errors/NAK simulation.
    
    Some formulas:
      Total NAK received by net side = pdschCrcError + pdschCrcErrorSim
      BLERreal = pdschCrcError/(pdschCrcOk+pdschCrcError)
      BLERsim_only = (pdschCrcErrorSim)/(pdschCrcOk+pdschCrcError)
      BLERtotal = BLERreal + BLERsim_only   (BLER as it appears to net side).
    
    Second case is when DL HARQ is enabled.
    In this case:
    pdschCrcOk consider all Tx with CRC OK (both first Tx and Retx).
    pdschCrcOkRetx consider all Retx with CRC OK.
    pdschCrcError consider all first Tx with CRC error.
    pdschCrcErrorRetx consider all Retx with CRC error.
    pdschCrcErrorSim does not apply (zero)
    pdschUnexpRetx consider all Unexpected Retx (i.e. not expected considering HARQ state).

    Note 7 - Counters releative to UL HARQ.

    This set counts some events:
      phichAck count the ACK received on PHICH.
      ndiToggled count the NDI toggled in DCI.
      phichNack count the NACK received on PHICH.
      phichDtx count the implicit NACK due to ne feedback received on PHICH.
      ndiNotToggled count the NDI not toggled in DCI.

    For each one of the previous counters, there is a corresponding counter that counts when the event effectively provide ACK or NACK, i.e. when not preempted by some other event and applicable:
      ackFromPhich
      ackFromNdiToggled count the ACK triggered by reception of a DCI/grant with not toggling NDI.
      nackFromPhich
      nackFromDtx
      effNdiNack count the NACK triggered by reception of a DCI/grant with not toggling NDI.

    This set counts the specific transmissions:
      newTx count the new trasmission i.e. first trasmission of a TB.
      nonAdaptRetx count the non adaptative Retx of a TB.
      adaptRetx count the adaptative Retx of a TB.
    
 */


# endif     /* # ifndef  sdrdrv_lte_def_INCLUDED */

/* eof */
