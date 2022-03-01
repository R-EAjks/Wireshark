/**********************************************************************
  Title:    sdrLte.h - The SDR Lte PHYSICAL and O&M interface
 ----------------------------------------------------------------------

 **********************************************************************/


#ifndef sdrLteStruct_DEFINED
#define sdrLteStruct_DEFINED

#define sdrLteStruct_VERSION            "0.9.1"

/* DCI format values */
#define sdrLte_DciFormat_0          0
#define sdrLte_DciFormat_1          1
#define sdrLte_DciFormat_1A         2
#define sdrLte_DciFormat_1B         3
#define sdrLte_DciFormat_1C         4
#define sdrLte_DciFormat_1D         5
#define sdrLte_DciFormat_2          6
#define sdrLte_DciFormat_2A         7
#define sdrLte_DciFormat_3          8
#define sdrLte_DciFormat_3A         9
#define sdrLte_DciFormat_2B         10
#define sdrLte_DciFormat_2C         11      
#define sdrLte_DciFormat_2D         12
#define sdrLte_DciFormat_6_1A       13
#define sdrLte_DciFormat_6_1B       14
#define sdrLte_DciFormat_6_0A       15
#define sdrLte_DciFormat_6_0B       16
#define sdrLte_DciFormat_6_2        17
#define sdrLte_DciFormat_N0         18
#define sdrLte_DciFormat_N1         19
#define sdrLte_DciFormat_N2         20

#define sdrLte_MAX_SECONDARY_CARRIERS_v0   1
#define sdrLte_MAX_CARRIERS_AGGREGATED_v0  2

#define sdrLte_MAX_SECONDARY_CARRIERS_v1   3
#define sdrLte_MAX_CARRIERS_AGGREGATED_v1  4

#define sdrLte_MAX_SECONDARY_CARRIERS_v2   4
#define sdrLte_MAX_CARRIERS_AGGREGATED_v2  5

#define sdrLte_MAX_SECONDARY_CARRIERS_v3   7
#define sdrLte_MAX_CARRIERS_AGGREGATED_v3  8

#define sdrLte_MAX_SECONDARY_CARRIERS   sdrLte_MAX_SECONDARY_CARRIERS_v3
#define sdrLte_MAX_CARRIERS_AGGREGATED  sdrLte_MAX_CARRIERS_AGGREGATED_v3

#define sdrLte_MAX_CELLS_INTERF_v0  2

//---------------------------------------------------------------------
// LTE-M
#define sdrLteMAXCE_LEVEL_v0    0x04     // Maximum number of enhanced coverage levels
#define sdrLteMAXCE_LEVEL       sdrLteMAXCE_LEVEL_v0

#define sdrLteMAXSI_MESSAGE_v0    32   // Maximum number of SI messages
#define sdrLteMAXSI_MESSAGE       sdrLteMAXSI_MESSAGE_v0

//---------------------------------------------------------------------
// NARROWBAND-IoT
#define sdrLteMAXNPRACH_RES_v0    0x03     // Maximum number of NPRACH resources for NB-IoT
#define sdrLteMAXNPRACH_RES       sdrLteMAXNPRACH_RES_v0

#define sdrLteMAXSI_MESSAGE_NB_v0    8   // Maximum number of SI messages
#define sdrLteMAXSI_MESSAGE_NB    sdrLteMAXSI_MESSAGE_NB_v0

#define sdrLteMAX_NONANCHORCARRIERS_NB_v0    15   // Maximum number of non-anchor carriers for NB-IoT
#define sdrLteMAX_NONANCHORCARRIERS_NB    sdrLteMAX_NONANCHORCARRIERS_NB_v0

// ------------------------------------------------
// uplink verbosity
#define sdrLteVERB_TPC    0x0001
#define sdrLteVERB_SR     0x0002
#define sdrLteVERB_PUCCH  0x0004
#define sdrLteVERB_ACK    0x0008
#define sdrLteVERB_SRS    0x0010
#define sdrLteVERB_RF     0x0020

// downlink verbosity
#define sdrLteVERB_PDCCH  0x0100
#define sdrLteVERB_PHICH  0x0200
#define sdrLteVERB_MBSFN  0x0400
#define sdrLteVERB_HARQ   0x0800
#define sdrLteVERB_SPS    0x4000
#define sdrLteVERB_TA     0x0040
#define sdrLteVERB_EPDCCH 0x0080

// Carrier aggregation verbosity
#define sdrLteVERB_CA     0x1000

// Measurement gap verbosity
#define sdrLteVERB_MEAS   0x2000

// ICIS verbosity
#define sdrLteVERB_ICIS   0x8000

// NB verbosity for DL and for UL
#define sdrLteVERB_NB_DL   0x10000
#define sdrLteVERB_NB_UL   0x20000

// Verbosity to use to mute traces
#define sdrLteVERB_MUTE   0x80000000

// Uplink report format
#define sdrLteULREP_NOREP  0x00   // Uplink report not required
#define sdrLteULREP_BASE   0x01   // Basic report 
#define sdrLteULREP_AMM    0x02   // Basic report + AMM information
//---------------------------------------------------------------------
typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    uchar         Dai;            // Downlink assignement index [0, 1, 2, 3, 255]
                                  // 255 means that the trasmission has been
                                  // triggered by an implicit grant
    } sdrLteDecGrantUl_00;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    uchar         Dai;            // Downlink assignement index [0, 1, 2, 3, 255]
                                  // 255 means that the trasmission has been
                                  // triggered by an implicit grant
    uchar         CqiSize;        // CQI request size [0 = 1 bit, 1 = 2 bit]
    uchar         Spare[3];
    } sdrLteDecGrantUl_01;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    uchar         Dai;            // Downlink assignement index [0, 1, 2, 3, 255]
                                  // 255 means that the trasmission has been
                                  // triggered by an implicit grant
    uchar         CqiSize;        // CQI request size [0 = 1 bit, 1 = 2 bit]
    uchar         RarGrant;       // RAR Grant [0, 1]
    uchar         Spare[2];
    uint          SR_attempts;    // Number of scheduling request sent before receiving this grant
    } sdrLteDecGrantUl_02;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    uchar         Dai;            // Downlink assignement index [0, 1, 2, 3, 255]
                                  // 255 means that the trasmission has been
                                  // triggered by an implicit grant
    uchar         CqiSize;        // CQI request size [0 = 1 bit, 1 = 2 bit]
    uchar         RarGrant;       // RAR Grant [0, 1]
    uchar         ttiBundling;    // = 1 when TTI-bundling is active
    uchar         Spare;
    uint          SR_attempts;    // Number of scheduling request sent before receiving this grant
    } sdrLteDecGrantUl_03;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    uchar         Dai;            // Downlink assignement index [0, 1, 2, 3, 255]
                                  // 255 means that the trasmission has been
                                  // triggered by an implicit grant
    uchar         CqiSize;        // CQI request size [0 = 1 bit, 1 = 2 bit]
    uchar         RarGrant;       // RAR Grant [0, 1]
    uchar         ttiBundling;    // = 1 when TTI-bundling is active
    uchar         Msg3_4_MpdcchNarrowband ; // Msg3/4 MPDCCH Narrowband Value for CEmodeA and CEmodeB
                                            // according to table 6.2-B TS 36.213
    uchar         NRep;           // Number of repetition for UEs in Enhanced Coverage 
    uchar         DCINRep;        // Number of DCI subframe repetition for UEs in Enhanced Coverage expressed as enum
    ushort        SR_attempts;    // Number of scheduling request sent before receiving this grant
    } sdrLteDecGrantUl_04;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    union {                           
        uchar     Dai;        // Downlink assignement index [0, 1, 2, 3, 255]
                              // 255 means that the trasmission has been
                              // triggered by an implicit grant
        uchar     UlIndex;    // This field is read as UL index in case of TDD configuration 0                                 
    };

    uchar         CqiSize;        // CQI request size [0 = 1 bit, 1 = 2 bit]
    uchar         RarGrant;       // RAR Grant [0, 1]
    uchar         ttiBundling;    // = 1 when TTI-bundling is active
    uchar         Msg3_4_MpdcchNarrowband ; // Msg3/4 MPDCCH Narrowband Value for CEmodeA and CEmodeB
                                            // according to table 6.2-B TS 36.213
    uchar         NRep;           // Number of repetition for UEs in Enhanced Coverage; 0xff invalid value
    uchar         DCINRep;        // Number of DCI subframe repetition for UEs in Enhanced Coverage expressed as enum; 0xff invalid value
    ushort        SR_attempts;    // Number of scheduling request sent before receiving this grant
    } sdrLteDecGrantUl_05;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    union {
        uchar     Dai;        // Downlink assignement index [0, 1, 2, 3, 255]
                              // 255 means that the trasmission has been
                              // triggered by an implicit grant
        uchar     UlIndex;    // This field is read as UL index in case of TDD configuration 0
    };

    uchar         CqiSize;        // CQI request size [0 = 1 bit, 1 = 2 bit]
    uchar         RarGrant;       // RAR Grant [0, 1]
    uchar         ttiBundling;    // = 1 when TTI-bundling is active
    uchar         Msg3_4_MpdcchNarrowband ; // Msg3/4 MPDCCH Narrowband Value for CEmodeA and CEmodeB
                                            // according to table 6.2-B TS 36.213
    uchar         NRep;           // Number of repetition for UEs in Enhanced Coverage; 0xff invalid value
    uchar         DCINRep;        // Number of DCI subframe repetition for UEs in Enhanced Coverage expressed as enum; 0xff invalid value
    ushort        SR_attempts;    // Number of scheduling request sent before receiving this grant

    /* NB-IoT */
    uchar         Isc;            // Subcarrier indication field [0..18] (3GPP 36.213 - Table 16.5.1.1-1)
    uchar         Iru;            // Resource assignment field [0..7] (3GPP 36.213 - Table 16.5.1.1-2)
    uchar         Idelay;         // Scheduling delay [0..3] (3GPP 36.213 - Table 16.5.1-1)
    uchar         spare;
    } sdrLteDecGrantUl_06;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         Ndi_AntSel;     // bit 0: New data indication
                                  // bit 7: Antenna selection
    uchar         Irv;            // IRV (IRV, see TS 36.321)
    ushort        NumByte;        // Number of byte to be transmitted
    uchar         Mcs;            // Modulation Coding scheme: [0..28] - 29 PUCCH only and no data
    uchar         StartingRB;     // Starting resource block [0..49]
    uchar         NumRB;          // Number of resource blocks [1..50]
    uchar         Dmrs;           // dynamic cyclic shift for reference signal
    uchar         Fh;             // frequency hopping flag (not used in LA01)
    uchar         Tpc;            // power control of PUSCH
    uchar         Cqi;            // CQI, Channel Quality Indicator [0, 1]
    union {
        uchar     Dai;        // Downlink assignement index [0, 1, 2, 3, 255]
                              // 255 means that the trasmission has been
                              // triggered by an implicit grant
        uchar     UlIndex;    // This field is read as UL index in case of TDD configuration 0
    };

    uchar         CqiSize;        // CQI request size [0 = 1 bit, 1 = 2 bit]
    uchar         RarGrant;       // RAR Grant [0, 1]
    uchar         RntiFlag_TtiBundling;    //  bit 0...3 : = 1 when TTI-bundling is active
                                           //  bit 4...7 : RNTI flag: 0 means legacy/CATM RNTI ( default value ), 1 means NBIoT RNTI
    uchar         Msg3_4_MpdcchNarrowband ; // Msg3/4 MPDCCH Narrowband Value for CEmodeA and CEmodeB
                                            // according to table 6.2-B TS 36.213
    uchar         NRep;           // Number of repetition for UEs in Enhanced Coverage; 0xff invalid value
    uchar         DCINRep;        // Number of DCI subframe repetition for UEs in Enhanced Coverage expressed as enum; 0xff invalid value
    ushort        SR_attempts;    // Number of scheduling request sent before receiving this grant

    /* NB-IoT */
    uchar         Isc;            // Subcarrier indication field [0..18] (3GPP 36.213 - Table 16.5.1.1-1)
    uchar         Iru;            // Resource assignment field [0..7] (3GPP 36.213 - Table 16.5.1.1-2)
    uchar         Idelay;         // Scheduling delay [0..3] (3GPP 36.213 - Table 16.5.1-1)
    uchar         CarrierIdNB;    // NBIoT Anchor Carrier identifier. Default value is 0xff 
    } sdrLteDecGrantUl_07;

typedef sdrLteDecGrantUl_07 sdrLteDecGrantUl;

typedef struct
    {
    sdrLteDecGrantUl_00 grant;       // Decoded Grant parameters
    ushort           TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    uchar            BbAtt;          // Baseband attenuation (dB)
    ushort           Ta;             // Timing advance, see TS 36.213, 4.2.3.
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_00;

typedef struct
    {
    sdrLteDecGrantUl_00 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_01;

typedef struct
    {
    sdrLteDecGrantUl_01 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_02;

typedef struct
    {
    sdrLteDecGrantUl_02 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_03;

typedef struct
    {
    sdrLteDecGrantUl_03 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_04;

typedef struct
    {
    sdrLteDecGrantUl_04 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_05;

typedef struct
    {
    sdrLteDecGrantUl_05 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_06;

typedef struct
    {
    sdrLteDecGrantUl_06 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_07;

typedef struct
    {
    sdrLteDecGrantUl_07 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    char             LastPwRach;     // Last RACH Output power (dB) [0x7F means not apply]
    ushort           PhrOff;         // PHR offset (0xFFFF means not apply).
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_08;

typedef struct
    {
    sdrLteDecGrantUl_07 grant;       // Decoded Grant parameters
    uchar            TxNb;           // Tx NB (TX_NB, see TS 36.321)
    uchar            HarqProcess;    // HarqProcess [0 .. 8]
    uchar            WrongCrc;       // set to 1 to force a wrong CRC
    uchar            Pad;
    short            LastPwRach;     // Last RACH Output power (dB) [0x7FFF means not apply]
    ushort           Len;            // Data length
    uchar            Data [1];       // 'Len' bytes of data
    } sdrLte_DataUl_09;

typedef sdrLte_DataUl_09 sdrLte_DataUl;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         RntiFlag;       // RNTI flag: 0 means legacy/CATM RNTI ( default value ), 1 means NBIoT RNTI
    uchar         Spare[3];
    } sdrLte_DataSR_00;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uchar         RntiFlag;       // RNTI flag: 0 means legacy/CATM RNTI ( default value ), 1 means NBIoT RNTI
    uchar         CarrierIdNB;    // NBIoT Anchor Carrier identifier if RNTI is NBIoT. 
                                  // Default value 0xFF invalid value
    uchar         Spare[2];
    } sdrLte_DataSR_01;
    
typedef sdrLte_DataSR_01 sdrLte_DataSR;

typedef struct
    {
    uint          Rnti;           // RNTI value
    uint          Ack;            // 1 = ACK, 0 = NACK
    } sdrLtePhich_00;

typedef struct
    {
    uint          Rnti;           // RNTI value
    ushort        Ack;            // 1 = ACK, 0 = NACK, 2 = DTX
    ushort        Iphich;         // admitted values 0,1
    } sdrLtePhich_01;

typedef struct
    {
    uint          Rnti;           // RNTI value
    ushort        Ack;            // 1 = ACK, 0 = NACK, 2 = DTX
    uchar         Iphich;         // admitted values 0,1
    uchar         RntiFlag;       // RNTI flag: 0 means legacy/CATM RNTI ( default value ), 1 means NBIoT RNTI. This has been done only for future developments
    } sdrLtePhich_02;

typedef sdrLtePhich_02 sdrLtePhich;

typedef struct
    {
    uchar         RootSeqIdx;     // Root-sequence-index, see TS 36.211, table 5.7.2-4 and 5.7.2-5
                                  // (0..837)
    uchar         PrachConfig;    // PRACH configuration index, see TS 36.211, 5.7.1: table 5.7.1-1 and 5.7.1-2
                                  // providing mapping of Preamble format and PRACH configuration to PRACH Configuration Index
                                  // (0..63)
    uchar         HighSpeed;      // High-speed-flag, see TS 36.211, 5.7.2
                                  // 1 = Restricted set, 0 = Unrestricted set
    uchar         ZeroCorrZone;   // NCS configuration, see TS 36.211, 5.7.2: table 5.7.2-2 for preamble
                                  // format 0..3 and table 5.7.2-3 for preamble format 4
                                  // (0..15)
    uint          FreqOffset;     // prach-FrequencyOffset, see TS 36.211, 5.7.1
                                  // (0..104)
    int           InitRxTargetPw; // Preamble initial received target power
                                  // (-120 .. -90)
    } sdrLte_Prach_00;

typedef struct
    {
    ushort        RootSeqIdx;     // Root-sequence-index, see TS 36.211, table 5.7.2-4 and 5.7.2-5
                                  // (0..1023)
    uchar         PrachConfig;    // PRACH configuration index, see TS 36.211, 5.7.1: table 5.7.1-1 and 5.7.1-2
                                  // providing mapping of Preamble format and PRACH configuration to PRACH Configuration Index
                                  // (0..63)
    uchar         HighSpeed;      // High-speed-flag, see TS 36.211, 5.7.2
                                  // 1 = Restricted set, 0 = Unrestricted set
    uchar         ZeroCorrZone;   // NCS configuration, see TS 36.211, 5.7.2: table 5.7.2-2 for preamble
                                  // format 0..3 and table 5.7.2-3 for preamble format 4
                                  // (0..15)
    uchar         FreqOffset;     // prach-FrequencyOffset, see TS 36.211, 5.7.1
                                  // (0..104)
    short         InitRxTargetPw; // Preamble initial received target power
                                  // (-120 .. -90)
    } sdrLte_Prach_01;

typedef struct
    {
    short         RefSigPower;    // Downlink Reference-signal power EPRE, see TS 36.213, 5.2
                                  // The actual value in dBm (-60..50)
    ushort        Pb;             // Pb, see TS 36.213, Table 5.2-1
                                  // the actual value depends of the number of antennas used (0, 1, 2, 3)
    } sdrLte_Pdsch;

typedef struct
    {
    uchar         Nsb;            // Nsb, see TS 36.211, 5.3.4
                                  // (1, 2, 3, 4)
    uchar         HoppingMode;    // Hopping-mode, see TS 36.211, 5.3.4
                                  // 0 = interSubFrame, 1 = intraAndInterSubFrame
    uchar         HoppingOffset;  // Nrb(ho), see TS 36.211, 5.3.4
                                  // (0..98)
    uchar         Enable64Qam;    // See TS 36.213, 8.6.1
                                  // This field summarizes the meaning of 
                                  // enable64QAM in PUSCH-ConfigCommon and the optional 
                                  // enable64QAM-v1270 in PUSCH-ConfigCommon-v1270
                                  // 0 = no 64 QAM is allowed ( enable64QAM = false and enable64QAM-v1270 is not present or false)
                                  // 1 = 64 QAM is enabled ( enable64QAM = true and enable64QAM-v1270 is not present or false)
                                  // This flag indicates that 64QAM is allowed for UE categories 5 and 8 indicated in ue-Category 
                                  // and UL categories indicated in ue-CategoryUL which support UL 64QAM and can fallback to category 5 or 8
                                  // 2 = 64 QAM is enabled ( enable64QAM = true and enable64QAM-v1270 = true)
                                  // This flag indicates that 64QAM is allowed for UL categories indicated in ue-CategoryUL which 
                                  // support UL 64QAM but cannot fallback category 5 or 8
    uchar         GroupHopping;   // Group-hopping-enabled, see TS 36.211, 5.5.1.3
                                  // 1 = enabled, 0 = disabled
    uchar         GroupAssignment;// Delta SS, see TS 36.211, 5.5.1.3
                                  // (0..29)
    uchar         SequenceHopping;// Sequence-hopping-enabled, see TS 36.211, 5.5.1.4
                                  // 1 = enabled, 0 = disabled
    uchar         CyclicShift;    // CyclicShift n(1)dmrs, see TS 36.211, Table 5.5.2.1.1-2
                                  // (0..7)
    } sdrLte_Pusch;

typedef struct
    {
    ushort        DeltaShift;     // Delta shift (PUCCH), see 36.211, 5.4.1
                                  // (1, 2, 3)
    ushort        NrbCqi;         // N(2)RB, see TS 36.211, 5.4
                                  // (0..98)
    ushort        NcsAn;          // N(1)cs, see TS 36.211, 5.4
                                  // (0..7)
    ushort        N1PUCCH_AN;     // N(1)PUCCH, see TS 36.213, 10.1
                                  // (0..2047)
    } sdrLte_Pucch;

typedef struct
    {
    uchar         BwConf;         // SRS Bandwidth Configuration, see TS 36.211
                                  // table 5.5.3.2-1, 5.5.3.2-2, 5.5.3.2-3 and 5.5.3.2-4
                                  // Actual configuration depends on UL bandwidth (0..7)
    uchar         SubFraneConf;   // SRS SubframeConfiguration, see TS 36.211, 5.5.3.3
                                  // Table 5.5.3.3-1 [0..15]
    uchar         AckNack;        // Simultaneous-AN-and-SRS, see TS 36.213, 8.2
                                  // (0, 1)
    uchar         MaxUpPts;       // SRS MaxUpPts, see TS 36.211
                                  // (0, 1)
    } sdrLte_UlSrs;

typedef struct
    {
    short         P0NominalPUSCH; // P0,NOMINAL_PUSCH, see TS 36.213, 5.1.1.1, unit dBm step 1
                                  // This field is applicable for non-persistent scheduling only
                                  // (-126..24)
    ushort        Alpha;          // alfa, see TS 36.213, 5.1.1.1
                                  // (0, 0.4, 0.5 ... 1)
    short         P0NominalPUCCH; // P0, NOMINAL_PUCCH, see TS 36.213, 5.1.2.1
                                  // unit dBm (-127..-96)
    char          DeltaF_1;       // DeltaF-PUCCH-Format1, see TS 36.213, 5.1.2
                                  // (-2, 0, 2)
    char          DeltaF_1b;      // DeltaF-PUCCH-Format1b, see TS 36.213, 5.1.2
                                  // (-2, 0, 2)
    char          DeltaF_2;       // DeltaF-PUCCH-Format2, see TS 36.213, 5.1.2
                                  // (1, 3, 5)
    char          DeltaF_2a;      // DeltaF-PUCCH-Format2a, see TS 36.213, 5.1.2
                                  // (-2, 0, 1, 2)
    char          DeltaF_2b;      // DeltaF-PUCCH-Format2b, see TS 36.213, 5.1.2
                                  // (-2, 0, 2)
    char          DeltaPreamble;  // DeltaPreambleMsg3, see TS 36.213, 5.1.1.1
                                  // (-1..6); actualValue(dB) = DeltaPreamble*2
    } sdrLte_Pwr;

typedef struct
    {
    short         P0NominalPUSCH; // P0,NOMINAL_PUSCH, see TS 36.213, 5.1.1.1, unit dBm step 1
                                  // This field is applicable for non-persistent scheduling only
                                  // (-126..24)
    ushort        Alpha;          // alfa, see TS 36.213, 5.1.1.1
                                  // (0, 0.4, 0.5 ... 1)
    short         P0NominalPUCCH; // P0, NOMINAL_PUCCH, see TS 36.213, 5.1.2.1
                                  // unit dBm (-127..-96)
    char          DeltaF_1;       // DeltaF-PUCCH-Format1, see TS 36.213, 5.1.2
                                  // (-2, 0, 2)
    char          DeltaF_1b;      // DeltaF-PUCCH-Format1b, see TS 36.213, 5.1.2
                                  // (-2, 0, 2)
    char          DeltaF_2;       // DeltaF-PUCCH-Format2, see TS 36.213, 5.1.2
                                  // (1, 3, 5)
    char          DeltaF_2a;      // DeltaF-PUCCH-Format2a, see TS 36.213, 5.1.2
                                  // (-2, 0, 1, 2)
    char          DeltaF_2b;      // DeltaF-PUCCH-Format2b, see TS 36.213, 5.1.2
                                  // (-2, 0, 2)
    char          DeltaPreamble;  // DeltaPreambleMsg3, see TS 36.213, 5.1.1.1
                                  // (-1..6) Unit 2dB
    char          DeltaF_3;       // DeltaF-PUCCH-Format2b, see TS 36.213, 5.1.2
                                  // (-1, 0, 1, 2, 3, 4, 5, 6)
    char          DeltaF_1bCS;    // DeltaF-PUCCH-Format2b, see TS 36.213, 5.1.2
                                  // (1, 2)
    char          Pad[2];
    } sdrLte_Pwr_01;

typedef struct
    {
    ushort        SfAssignment;   // Subframe assignment: DL/UL subframe configuration
                                  // see TS 36.211, table 4.2.2
    ushort        SpecialSf;      // Special subframe patterns
                                  // see TS 36.211, table 4.2.1
    } sdrLte_Tdd;

typedef struct
    {
    uint          WdwLength;      // Common SI scheduling window for all SIs. Unit in milliseconds.
                                  // [1, 2, 5, 10, 15, 20, 40]
    uchar         SiPeriod[32];   // List of the SI periodicity ordered according to the mapping info
                                  // enumeration 0-6 corresponding to: [8, 16, 32, 64, 128, 256, 512]
                                  // The list is terminated by the value 0xff
    } sdrLte_Sib;

typedef struct
    {
    uchar  RadioFrameAllocationPeriod;  // Radio-frames that contain MBSFN subframes occur when equation
                                  // SFN mod radioFrameAllocationPeriod = radioFrameAllocationOffset is satisfied
                                  // [1, 2, 4, 8, 16, 32]
    uchar  radioFrameAllocationOffset;  // [0..7]
    ushort        OneFrame;       // "1" denotes that the corresponding subframe is allocated for MBSFN
                                  // 0xffff if fourFrame option is used
    uint          FourFrame;      // A bit-map indicating MBSFN subframe allocation in four consecutive radio frames,
                                        // "1" denotes that the corresponding subframe is allocated for MBSFN
                                  // 0xffffffff if oneFrame option is used
    } sdrLte_MbsfnSubframeConfig;

typedef struct
    {
    uint            PreambleLen;    // Uplink cyclic prefix length see 36.211, 5.2.1
                                    // 0 = normal 1= extended
    sdrLte_Prach_01 PrachInfo;      // PRACH configuration

    sdrLte_Pdsch    PdschInfo;      // PDSCH configuration

    sdrLte_Pusch    PuschInfo;      // PUSCH configuration

    sdrLte_Pucch    PucchInfo;      // PUCCH configuration

    sdrLte_UlSrs    UlSrsInfo;      // Sounding reference signal configuration

    sdrLte_Pwr_01   PwrInfo;        // Uplink power control configuration

    sdrLte_Tdd      TddConfig;      // TDD specific physical channel configuration

    int             Pmax;           // from RadioResourceConfigCommon: used to limit the UE's uplink
                                    // transmission power (dBm)
    sdrLte_Sib      SibInfo;        // SIB Sceduling information

    uint                          NumMbsfnSFConfig;      // Number of MBSFN allocations

    sdrLte_MbsfnSubframeConfig    MbsfnSFConfigList[8];  // MBSFN allocation configuration list

    } sdrLte_SibData;
    
// ************************************************
// PDSCH-ConfigDedicated

// This structure is used only for TM10
typedef struct
    {
    uint          Enabled;        // 0 = disabled, 1 = enabled

    ushort        ScrIdentity;    // nDMRS_id_0 see TS 36.211, 6.10.3.1

    ushort        ScrIdentity2;   // nDMRS_id_1 see TS 36.211, 6.10.3.1

    } sdrLte_DmrsConfig;

typedef struct
    {
    uchar                       Id;            // PDSCH-RE-MappingQCL identifier
                                               // (0..3)
    uchar                       CrsPortsCount; // (0, 2, 4) 0xff if the field is absent
                                               // If absent, the UE releases the configuration provided previously
                                               // if any and applies the values from the serving cell configured on the same frequency
    uchar                       CrsFreqShift;  // (0..5) 0xff if the field is absent
                                               // If absent, the UE releases the configuration provided previously
                                               // if any and applies the values from the serving cell configured on the same frequency

    uchar                       NumMbsfnSFConfig;     // Number of MBSFN allocations

    sdrLte_MbsfnSubframeConfig  MbsfnSFConfigList[8]; // MBSFN allocation configuration list

    ushort                      PdschStart;           // The starting OFDM symbol of PDSCH for the concerned serving cell
                                                      // see TS 36.213 [7.1.6.4].
                                                      // (1, 2, 3, 4)
    uchar                       CsiRSConfigZPId;      // The CSI-RS resource configuration, for which UE assumes zero transmission power
                                                      // (1..4)
    uchar                       QclCsiRSConfigNZPId;  // Indicates the CSI-RS resource that is quasi co-located with the PDSCH antenna ports
                                                      // EUTRAN configures this field if and only if the UE is configured with
                                                      // qcl-Operation set to typeB.
                                                      // (1..3)
    } sdrLte_RE_MapQCLConfig;

typedef struct
    {
    int           Pa;             // Pa, see TS 36.213, 5.2
                                  // (-6, -4.77, -3, -1.77, 0, 1, 2, 3) dB
    } sdrLte_PdschDed;

typedef struct
    {
    int                     Pa;                     // Pa, see TS 36.213, 5.2
                                                    // (-6, -4.77, -3, -1.77, 0, 1, 2, 3) dB
    // The following structures are used only for TM10 - static version
    // TM10 
    sdrLte_DmrsConfig       DmrsConfig;             // DMRS configuration
    // TM10 
    ushort                  QclOperation;           // Indicates the CSI-RS resource that is quasi co-located with
                                                    // the PDSCH antenna ports, see TS 36.213 [23, 7.1.9]. EUTRAN
                                                    // configures this field if and only if the UE is configured with
                                                    // qcl-Operation set to typeB.
                                                    // 0 = typeA, 1 = typeB, 0xffff if the field is not present
    // TM10 
    uchar                   Num_RE_MapQCLConfigRel; // Number of PDSCH-RE-MappingQCL to be released
                                                    // (0..3)
    // TM10 
    uchar                   Num_RE_MapQCLConfigAdd; // Number of PDSCH-RE-MappingQCL to be added or modified
                                                    // (0..3)
    // TM10 
    uchar                   RE_MapQCLConfigRel[4];  // List of PDSCH-RE-MappingQCL to be release
                                                    // (0..3)
    // TM10 
    sdrLte_RE_MapQCLConfig  RE_MapQCLConfigAdd[4];  // List of PDSCH-RE-MappingQCL to be added or modified 

    } sdrLte_PdschDed_01;
    
typedef struct
    {
    short           Pa;     // Pa, see TS 36.213, 5.2
                            // (-6, -4.77, -3, -1.77, 0, 1, 2, 3) dB
    ushort          AltCQI; // Selects 36.213 table 7.1.7.1-1 or table 7.1.7.1-1A
                            // altCQI = 0xFFFF (256QAM disabled)
                            // altCQI = 0 (256QAM enabled - allSubframes)
                            // altCQI = 1 (256QAM enabled - csi_SubframeSet1)
                            // altCQI = 2 (256QAM enabled - csi_SubframeSet2)
    } sdrLte_PdschDed_02;
    
typedef struct
    {
    short           Pa;     // Pa, see TS 36.213, 5.2
                            // (-6, -4.77, -3, -1.77, 0, 1, 2, 3) dB
    uchar           AltCQI; // Selects 36.213 table 7.1.7.1-1 or table 7.1.7.1-1A
                            // altCQI = 0xFF (256QAM disabled)
                            // altCQI = 0 (256QAM enabled - allSubframes)
                            // altCQI = 1 (256QAM enabled - csi_SubframeSet1)
                            // altCQI = 2 (256QAM enabled - csi_SubframeSet2)
    uchar           TbsIndexAlt2_TbsIndexAlt; // bit 0...3: tbsIndexAlt
                                               // Indicates the applicability of the alternative TBS 
                                               // index for the ITBS 26 and 33. Enum [a26, a33]. Invalid value is 0xf
                                               // bit 4...7: tbsIndexAlt2
                                               // Indicates the applicability of the alternative TBS index for the 
                                               // ITBS 33. Enum [b33]. Invalid value is 0xf
                                               // E.g. TbsIndexAlt2_TbsIndexAlt = 0xf1 means : use the alternative TBS index ITBS 33A
                                               // E.g. TbsIndexAlt2_TbsIndexAlt = 0x0f means : use the alternative TBS index ITBS 33B
                                               // E.g. TbsIndexAlt2_TbsIndexAlt = 0xff means: no alternative is to be used
    } sdrLte_PdschDed_03;

// ************************************************
// PUSCH-ConfigDedicated

typedef struct
    {
    uchar         DeltaOffsetACK; // Ioffset(HARQ-ACK), see TS 36.213, Table 8.6.3-1
                                  // (0..15)
    uchar         DeltaOffsetRi;  // Ioffset(HARQ-RI), see TS 36.213, Table 8.6.3-1
                                  // (0..15)
    ushort        DeltaOffsetCqi; // Ioffset(HARQ-CQI), see TS 36.213, Table 8.6.3-1
                                  // (0..15)
    } sdrLte_PuschDed;

typedef struct
    {
    uchar         DeltaOffsetACK;    // Ioffset(HARQ-ACK), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetRi;     // Ioffset(HARQ-RI), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetCqi;    // Ioffset(HARQ-CQI), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetACK_MC; // Ioffset(HARQ-ACK) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetRi_MC;  // Ioffset(HARQ-RI) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetCqi_MC; // Ioffset(HARQ-CQI) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         Pad[2];

    } sdrLte_PuschDed_01;

typedef struct
    {
    uchar         DeltaOffsetACK;    // Ioffset(HARQ-ACK), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetRi;     // Ioffset(HARQ-RI), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetCqi;    // Ioffset(HARQ-CQI), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetACK_MC; // Ioffset(HARQ-ACK) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetRi_MC;  // Ioffset(HARQ-RI) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetCqi_MC; // Ioffset(HARQ-CQI) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         HoppingConfig;     // For BL UEs and UEs in EC, frequency hopping activation/deactivation for unicast PUSCH, see TS 36.211 
                                     // 0 -> on, 1 -> off
    uchar         Pad[1];

    } sdrLte_PuschDed_02;

typedef struct
    {
    uchar         DeltaOffsetACK;    // Ioffset(HARQ-ACK), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetRi;     // Ioffset(HARQ-RI), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetCqi;    // Ioffset(HARQ-CQI), see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetACK_MC; // Ioffset(HARQ-ACK) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetRi_MC;  // Ioffset(HARQ-RI) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    uchar         DeltaOffsetCqi_MC; // Ioffset(HARQ-CQI) for multiple codeword, see TS 36.213, Table 8.6.3-1
                                     // (0..15)
    ushort        Enable256QamCfg;   // BitMap needed to be used for 256QAM UL configuration. 
                                     // This is a brief description that explains how to be filled:
                                     // Bit 0...9: tpc-SubframeSet BIT STRING (SIZE(10)) as defined in UplinkPowerControlDedicated-v1250
                                     // It indicates the uplink subframes of the uplink power control subframe sets. 
                                     // Value 0 means the subframe belongs to uplink power control subframe set 1, 
                                     // and value 1 means the subframe belongs to uplink power control subframe set 2.
                                     // If one of bits 10...13 is true we read the first 10 bits that must indicate the 
                                     // uplink power control subframe set configuration
                                     // Otherwise these 10 bits will be ignored
                                     // Bit 10 : subframeSet1-DCI-Format0-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 11 : subframeSet1-DCI-Format4-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 12 : subframeSet2-DCI-Format0-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 13 : subframeSet2-DCI-Format4-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 14 : dci-Format0-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 15 : dci-Format4-r14 in Enable256QAM-r14: 0-> false 1-> true    
    uchar         HoppingConfig;     // For BL UEs and UEs in EC, frequency hopping activation/deactivation for unicast PUSCH, see TS 36.211 
                                     // 0 -> on, 1 -> off
    uchar         Pad[3];

    } sdrLte_PuschDed_03;


typedef struct
    {
    ushort       GroupHopping;   // Group Hopping Enabled
                                 // 0 = disabled, 1 = enabled
    ushort       DmrsWithOCC;    // Parameter Activate-DMRS-with OCC, see TS 36.211
                                 // [0, 1]
    } sdrLte_PuschDed_SC_00;
    
typedef struct
    {
    uchar       GroupHopping;   // Group Hopping Enabled
                                 // 0 = disabled, 1 = enabled
    uchar       DmrsWithOCC;    // Parameter Activate-DMRS-with OCC, see TS 36.211
                                 // [0, 1]
    ushort      Enable256QamCfg;   // BitMap needed to be used for 256QAM UL configuration. 
                                     // This is a brief description that explains how to be filled:
                                     // Bit 0...9: tpc-SubframeSet BIT STRING (SIZE(10)) as defined in UplinkPowerControlDedicated-v1250
                                     // It indicates the uplink subframes of the uplink power control subframe sets. 
                                     // Value 0 means the subframe belongs to uplink power control subframe set 1, 
                                     // and value 1 means the subframe belongs to uplink power control subframe set 2.
                                     // If one of bits 10...13 is true we read the first 10 bits that must indicate the 
                                     // uplink power control subframe set configuration
                                     // Otherwise these 10 bits will be ignored
                                     // Bit 10 : subframeSet1-DCI-Format0-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 11 : subframeSet1-DCI-Format4-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 12 : subframeSet2-DCI-Format0-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 13 : subframeSet2-DCI-Format4-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 14 : dci-Format0-r14 in Enable256QAM-r14: 0-> false 1-> true
                                     // Bit 15 : dci-Format4-r14 in Enable256QAM-r14: 0-> false 1-> true    
} sdrLte_PuschDed_SC_01;
    
typedef sdrLte_PuschDed_SC_01 sdrLte_PuschDed_SC;

// ***************************************************************************
// PUCCH-ConfigDedicated

typedef struct
    {
    ushort        AckNackRep;    // Indicates whether ACK/NACK repetition is enable or disabled, see TS 36.213, 10.1
                                 // 0 = disabled, 1 = enabled
    ushort        Factor;        // Parameter NARep, see TS 36.213, 10.1
                                 // (2, 4, 6)
    ushort        SrPucchResIdx; // sr-PUCCH-ResourceIndex, alias n(1)PUCCH,SRI , see TS 36.213, 10.1
                                 // (0..2047)
    ushort        AckNakFeedback;// Parameter indicates one of the two TDD ACK/NACK feedback modes used, see TS 36.213, 7.3.
                                 // 0 = bundling, 1 = multiplexing
    } sdrLte_PucchDed;

typedef struct
    {
    uchar         AckNackRep;        // Indicates whether ACK/NACK repetition is enable or disabled, see TS 36.213, 10.1
                                     // 0 = disabled, 1 = enabled
    uchar         Factor;            // Parameter NARep, see TS 36.213, 10.1
                                     // (2, 4, 6)
    ushort        SrPucchResIdx;     // sr-PUCCH-ResourceIndex, alias n(1)PUCCH,SRI , see TS 36.213, 10.1
                                     // (0..2047)
    uchar         AckNakFeedback;    // Parameter indicates one of the two TDD ACK/NACK feedback modes used, see TS 36.213, 7.3.
                                     // 0 = bundling, 1 = multiplexing
    uchar         PucchFormat;       // Parameter indicates one of the PUCCH formats for transmission of HARQ-ACK, see TS 36.213 [23, 10.1]
                                     // For TDD, if the UE is configured with PCell only, the channelSelection indicates the transmission of
                                     // HARQ-ACK multiplexing as defined in Tables 10.1.3-5, 10.1.3-6, and 10.1.3-7 in TS 36.213 [23]
                                     // 0 = format 3; 1 = channel selection
    ushort        TwoAntennaPort;    // Indicates whether two antenna ports are configured for PUCCH format 1a/1b for HARQ-ACK, see TS
                                     // 36.213 [23, 10.1]. The field also applies for PUCCH format 1a/1b transmission when format3 is
                                     // configured, see TS 36.213 [23, 10.1.2.2.2, 10.1.3.2.2]
                                     // 0 = disabled, 1 = enabled
    ushort        N3PucchAn_p0[4];   // Parameter n(3,p) PUCCH for antenna port P0, see TS 36.213
                                     // (0..549)
    ushort        N3PucchAn_p1[4];   // Parameter n(3,p) PUCCH for antenna port P1, see TS 36.213
                                     // (0..549)
    ushort        N1PucchAnCs_p0[4]; // Parameter n(1,p) PUCCH for antenna port P0, see TS 36.213
                                     // (0..2047)
    ushort        N1PucchAnCs_p1[4]; // Parameter n(1,p) PUCCH for antenna port P1, see TS 36.213
                                     // (0..2047)
    uint          N1PucchAnRepP1;    // Parameter n(1, p) PUCCH, ANRep for antenna port P1, see TS 36.213 [23, 10.1].
                                     // (0..2047)
    } sdrLte_PucchDed_01;
    
typedef struct 
{
    uchar  ModeA_format1;   // ENUMERATED [r1, r2, r4, r8]; 0xff invalid value
    uchar  ModeA_format2;   // ENUMERATED [r1, r2, r4, r8]; 0xff invalid value
    uchar  ModeB_format1;   // ENUMERATED [r4, r8, r16, r32]; 0xff invalid value
    uchar  ModeB_format2;   // ENUMERATED [r4, r8, r16, r32]; 0xff invalid value
} sdrLte_PucchDedNumRepetitionCE_00;

typedef struct
    {
    uchar         AckNackRep;        // Indicates whether ACK/NACK repetition is enable or disabled, see TS 36.213, 10.1
                                     // 0 = disabled, 1 = enabled
    uchar         Factor;            // Parameter NARep, see TS 36.213, 10.1
                                     // (2, 4, 6)
    ushort        SrPucchResIdx;     // sr-PUCCH-ResourceIndex, alias n(1)PUCCH,SRI , see TS 36.213, 10.1
                                     // (0..2047)
    uchar         AckNakFeedback;    // Parameter indicates one of the two TDD ACK/NACK feedback modes used, see TS 36.213, 7.3.
                                     // 0 = bundling, 1 = multiplexing
    uchar         PucchFormat;       // Parameter indicates one of the PUCCH formats for transmission of HARQ-ACK, see TS 36.213 [23, 10.1]
                                     // For TDD, if the UE is configured with PCell only, the channelSelection indicates the transmission of
                                     // HARQ-ACK multiplexing as defined in Tables 10.1.3-5, 10.1.3-6, and 10.1.3-7 in TS 36.213 [23]
                                     // 0 = format 3; 1 = channel selection
    ushort        TwoAntennaPort;    // Indicates whether two antenna ports are configured for PUCCH format 1a/1b for HARQ-ACK, see TS
                                     // 36.213 [23, 10.1]. The field also applies for PUCCH format 1a/1b transmission when format3 is
                                     // configured, see TS 36.213 [23, 10.1.2.2.2, 10.1.3.2.2]
                                     // 0 = disabled, 1 = enabled
    ushort        N3PucchAn_p0[4];   // Parameter n(3,p) PUCCH for antenna port P0, see TS 36.213
                                     // (0..549)
    ushort        N3PucchAn_p1[4];   // Parameter n(3,p) PUCCH for antenna port P1, see TS 36.213
                                     // (0..549)
    ushort        N1PucchAnCs_p0[4]; // Parameter n(1,p) PUCCH for antenna port P0, see TS 36.213
                                     // (0..2047)
    ushort        N1PucchAnCs_p1[4]; // Parameter n(1,p) PUCCH for antenna port P1, see TS 36.213
                                     // (0..2047)
    uint          N1PucchAnRepP1;    // Parameter n(1, p) PUCCH, ANRep for antenna port P1, see TS 36.213 [23, 10.1].
                                     // (0..2047)
    sdrLte_PucchDedNumRepetitionCE_00 PucchNumRepCE; // Number of PUCCH repetitions for enhanced coverage modes A and B, 
                                                     // see TS 36.211 and TS 36.213.
    } sdrLte_PucchDed_02;

// ***********************************************************
    
typedef struct
    {
    uchar         Enabled;        // Uplink SRS enabled
                                  // 0 = disabled, 1 = enabled
    uchar         Bw;             // b, see TS 36.211, 5.5.3.2, table 5.5.3.2-1
                                  // (0, 1, 2, 3)
    uchar         HopBw;          // SRS hopping bandwidth, see TS 36.211, 5.5.3.2
                                  // (0, 1, 2, 3)
    uchar         FreqPos;        // nRRC see TS 36.211, 5.5.3.2
                                  // (0..23)
    uchar         Duration;       // Duration, see TS 36.213, 8.2
                                  // 0 = single, 1 = indefinite
    uchar         ConfigIndex;    // Isrs, see TS 36.213, Table8.2-1
                                  // (0..1023)
    uchar         TxComb;         // Ktc, see TS 36.211, 5.5.3.2
                                  // 0 = false, 1 = true
    uchar         CyclicShift;    // n_SRS, see TS 36.211, 5.5.3.1
                                  // (0..7)
    } sdrLte_UlSrsDed_00;

typedef struct
    {
    uchar         SrsAntennaPort;  // Indicates the number of antenna ports used for aperiodic
                                   // sounding reference signal transmission respectively, see TS 36.211
                                   // (1, 2, 4)
    uchar         Bw;              // b, see TS 36.211, 5.5.3.2, table 5.5.3.2-1
                                   // (0, 1, 2, 3)
    uchar         FreqPos;         // nRRC see TS 36.211, 5.5.3.2
                                   // (0..23)
    uchar         TxComb;          // Ktc, see TS 36.211, 5.5.3.2
                                   // 0 = false, 1 = true
    uint          CyclicShift;     // n_SRS, see TS 36.211, 5.5.3.1
                                   // (0..7)
    } sdrLte_SrsAp;

typedef struct
    {
    uchar         Enabled;         // Uplink SRS enabled
                                   // 0 = disabled, 1 = enabled
    uchar         Bw;              // b, see TS 36.211, 5.5.3.2, table 5.5.3.2-1
                                   // (0, 1, 2, 3)
    uchar         HopBw;           // SRS hopping bandwidth, see TS 36.211, 5.5.3.2
                                   // (0, 1, 2, 3)
    uchar         FreqPos;         // nRRC see TS 36.211, 5.5.3.2
                                   // (0..23)
    ushort        ConfigIndex;     // Isrs, see TS 36.213, Table8.2-1
                                   // (0..1023)
    uchar         Duration;        // Duration, see TS 36.213, 8.2
                                   // 0 = single, 1 = indefinite
    uchar         TxComb;          // Ktc, see TS 36.211, 5.5.3.2
                                   // 0 = false, 1 = true
    uchar         CyclicShift;     // n_SRS, see TS 36.211, 5.5.3.1
                                   // (0..7)
    uchar         SrsAntennaPort;  // Indicates the number of antenna ports used for periodic
                                   // sounding reference signal transmission respectively, see TS 36.211
                                   // (1, 2, 4)
    uchar         SrsApEnabled;    // Uplink aperiodic SRS enabled
                                   // 0 = disabled, 1 = enabled
    uchar         SrsApConfIdx;    // Parameter ISRS for aperiodic sounding reference signal transmission respectively. See TS 36.213
                                   // (0..31)
    sdrLte_SrsAp  SrsApConfDCI_4[3];   // Parameters indicate the resource configurations for aperiodic sounding reference signal transmissions
                                       // triggered by DCI formats 4.
    sdrLte_SrsAp  SrsApConfDCI_0;      // Parameters indicate the resource configurations for aperiodic sounding reference signal transmissions
                                       // triggered by DCI formats 0.
    sdrLte_SrsAp  SrsApConfDCI_1a2a2c; // Parameters indicate the resource configurations for aperiodic sounding reference signal transmissions
                                       // triggered by DCI formats 1a 2a 2c.
    } sdrLte_UlSrsDed_01;
    
typedef struct
    {

    uchar         SrsApEnabled;    // Uplink aperiodic SRS enabled
                                   // 0 = disabled, 1 = enabled
    uchar         SrsApConfIdx;    // Parameter ISRS for aperiodic sounding reference signal transmission respectively. See TS 36.213
                                   // (0..31)
    uchar         Spare[2];
    sdrLte_SrsAp  SrsApConfDCI_4[3];   // Parameters indicate the resource configurations for aperiodic sounding reference signal transmissions
                                       // triggered by DCI formats 4.
    sdrLte_SrsAp  SrsApConfDCI_0;      // Parameters indicate the resource configurations for aperiodic sounding reference signal transmissions
                                       // triggered by DCI formats 0.
    sdrLte_SrsAp  SrsApConfDCI_1a2a2c; // Parameters indicate the resource configurations for aperiodic sounding reference signal transmissions
                                       // triggered by DCI formats 1a 2a 2c.
    } sdrLte_UlSrsAperiodicDed_00;

typedef sdrLte_UlSrsAperiodicDed_00 sdrLte_UlSrsAperiodicDed;
    
typedef struct
    {
    uchar         Enabled;         // Uplink SRS enabled
                                   // 0 = disabled, 1 = enabled
    uchar         SrsAntennaPort;  // Indicates the number of antenna ports used for periodic
                                   // sounding reference signal transmission respectively, see TS 36.211
                                   // (1, 2, 4)
    uchar         HopBw_Bw;        // Bit 0...3: b, see TS 36.211, 5.5.3.2, table 5.5.3.2-1. Valid range: (0, 1, 2, 3). 
                                   // Bit 4...7: SRS hopping bandwidth, see TS 36.211, 5.5.3.2. Valid range: (0, 1, 2, 3).
                                   // Invalid value 0xff ( that means: bit 0..3 = 0xf and bit 4...7 = 0xf)
    uchar         FreqPos;         // nRRC see TS 36.211, 5.5.3.2
                                   // (0..23)
    ushort        ConfigIndex;     // Isrs, see TS 36.213, Table8.2-1
                                   // (0..1023)
    uchar         TxComb_Duration; // Bit 0...3: Duration, see TS 36.213, 8.2. Admitted values are 0 = single, 1 = indefinite
                                   // Bit 4...7: Ktc, see TS 36.211, 5.5.3.2
                                   // Admitted values are 0 = false, 1 = true
    uchar         CyclicShift;     // n_SRS, see TS 36.211, 5.5.3.1
                                   // (0..7)
    } sdrLte_UlSrsDed_02;

typedef sdrLte_UlSrsDed_02 sdrLte_UlSrsDed;
    
typedef struct
    {
    uchar         Enabled;         // Uplink SRS enabled
                                   // 0 = disabled, 1 = enabled
    uchar         Bw;              // b, see TS 36.211, 5.5.3.2, table 5.5.3.2-1
                                   // (0, 1, 2, 3)
    uchar         HopBw;           // SRS hopping bandwidth, see TS 36.211, 5.5.3.2
                                   // (0, 1, 2, 3)
    uchar         FreqPos;         // nRRC see TS 36.211, 5.5.3.2
                                   // (0..23)
    ushort        ConfigIndex;     // Isrs, see TS 36.213, Table8.2-1
                                   // (0..1023)
    uchar         Duration;        // Duration, see TS 36.213, 8.2
                                   // 0 = single, 1 = indefinite
    uchar         TxComb;          // Ktc, see TS 36.211, 5.5.3.2
                                   // 0 = false, 1 = true
    uchar         CyclicShift;     // n_SRS, see TS 36.211, 5.5.3.1
                                   // (0..7)
    uchar         SrsAntennaPort;  // Indicates the number of antenna ports used for periodic
                                   // sounding reference signal transmission respectively, see TS 36.211
                                   // (1, 2, 4)
    uchar         SrsApEnabled;    // Uplink aperiodic SRS enabled
                                   // 0 = disabled, 1 = enabled
    uchar         SrsApConfIdx;    // Parameter ISRS for aperiodic sounding reference signal transmission respectively. See TS 36.213
                                   // (0..31)
    } sdrLte_UlSrsDed_SC_00;

typedef struct
    {
    uchar         TxMode;         // Points to one of Transmission modes defined in TS 36.213, 7.1
                                  // (1..7)
    uchar         TxAntSelection; // Indicates whether UE transmit antenna selection control is closed-loop or open-loop
                                  // as described in TS 36.213 [23, 8.7]
                                  // 0 = disabled, 1 = closed loop, 2 = open loop
    uchar         CbsRestriction; // Codebook subset restriction
                                  // 0 = disabled, 1 = enabled
    uchar         n2Ant_tm3;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm3;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n2Ant_tm4;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm4[8];   // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n2Ant_tm5;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm5[2];   // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n2Ant_tm6;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm6[2];   // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]

    } sdrLte_AntInfo;

typedef struct
    {
    uchar         TxMode;         // Points to one of Transmission modes defined in TS 36.213, 7.1
                                  // (1..7)
    uchar         TxAntSelection; // Indicates whether UE transmit antenna selection control is closed-loop or open-loop
                                  // as described in TS 36.213 [23, 8.7]
                                  // 0 = disabled, 1 = closed loop, 2 = open loop
    uchar         CbsRestriction; // Codebook subset restriction
                                  // 0 = disabled, 1 = enabled
    uchar         n2Ant_tm3;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm3;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n2Ant_tm4;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm4[8];   // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n2Ant_tm5;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm5[2];   // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n2Ant_tm6;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm6[2];   // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n2Ant_tm8;      // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         n4Ant_tm8[4];   // CodebookSubsetRestriction, see TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    uchar         pad[3];
    } sdrLte_AntInfo_01;

typedef struct
    {
    uchar         TxMode;         // Points to one of Transmission modes defined in TS 36.213, 7.1
                                  // (1..7)
    uchar         TxAntSelection; // Indicates whether UE transmit antenna selection control is closed-loop or open-loop
                                  // as described in TS 36.213 [23, 8.7]
                                  // 0 = disabled, 1 = closed loop, 2 = open loop
    uchar         CbsRestriction[14]; // Codebook subset restriction bit string; TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    } sdrLte_AntInfo_02;

typedef struct
    {
    uchar         TxMode;         // Points to one of Transmission modes defined in TS 36.213, 7.1
                                  // (1..7)
    uchar         MaxLayersMimo_TxAntSelection; // bit 0..3: Indicates whether UE transmit antenna selection control is closed-loop or open-loop
                                                // as described in TS 36.213 [23, 8.7]
                                                // 0 = disabled, 1 = closed loop, 2 = open loop
                                                // bit 4..7 maxLayersMIMO-r10 in 36.331
                                                // Indicates the maximum number of layers for spatial multiplexing used 
                                                // to determine the rank indication bit width and Kc determination of 
                                                // the soft buffer size for the corresponding serving cell according to TS 36.212
                                                // EUTRAN configures this field only when transmissionMode is set to tm3, tm4, tm9 or tm10
                                                // ENUM [twoLayers, fourLayers, eightLayers]
                                                // Default value is 0xF ( when all the four bits are set to 1)
    uchar         CbsRestriction[14]; // Codebook subset restriction bit string; TS 36.213 [7.2] and TS 36.211 [6.3.4.2.3]
    } sdrLte_AntInfo_03;

typedef struct
    {
    uchar         TxMode;         // Points to one of Transmission modes defined in TS 36.213, 7.1
                                  // (1..7)
    uchar         TxAntSelection; // Indicates whether UE transmit antenna selection control is closed-loop or open-loop
                                  // as described in TS 36.213 [23, 8.7]
                                  // 0 = disabled, 1 = closed loop, 2 = open loop
    uchar           pad[2];
    } sdrLte_AntInfo_SC_00;

typedef struct
    {
    ushort        TxMode;         // Points to one of Transmission modes defined in TS 36.213, 7.1
                                  // (1..7)
    ushort        FourAntenna;    // Parameter indicates if four antenna ports are used.
                                  // 0 = disabled, 1 = enabled
    } sdrLte_AntInfo_UL;

typedef struct
    {
    short         P0UePUSCH;      // P0,UE_PUSCH See TS 36.213, 5.1.1.1, unit dB
                                  // This field is applicable for non-persistent scheduling only
                                  // (-8..7)
    uchar         DeltaMCS;       // Ks, see TS 36.213, 5.1.1.1
                                  // 0 = disabled, 1 = enabled
    uchar         Accumulation;   // Accumulation-enabled, see TS 36.213, 5.1.1.1
                                  // 0 = disabled, 1 = enabled
    short         P0UEPUCCH;      // P0, UE_PUCCH, see TS 36.213, 5.1.2.1
                                  // unit dBm (-8..7)
    ushort        PSRS_Offset;    // PSRS_OFFSET, see TS 36.213, 5.1.3.1
                                  // For Ks=1.25, the actual parameter value is pSRS-Offset value -3
                                  // For Ks=0, the actual parameter value is -10.5 + 1.5*pSRS-Offset value
                                  // (0..15)
    } sdrLte_PwrDed;

typedef struct
    {
    short         P0UePUSCH;        // P0,UE_PUSCH See TS 36.213, 5.1.1.1, unit dB
                                    // This field is applicable for non-persistent scheduling only
                                    // (-8..7)
    uchar         DeltaMCS;         // Ks, see TS 36.213, 5.1.1.1
                                    // 0 = disabled, 1 = enabled
    uchar         Accumulation;     // Accumulation-enabled, see TS 36.213, 5.1.1.1
                                    // 0 = disabled, 1 = enabled
    short         P0UEPUCCH;        // P0, UE_PUCCH, see TS 36.213, 5.1.2.1
                                    // unit dBm (-8..7)
    uchar         PSRS_Offset;      // PSRS_OFFSET, see TS 36.213, 5.1.3.1
                                    // For Ks=1.25, the actual parameter value is pSRS-Offset value -3
                                    // For Ks=0, the actual parameter value is -10.5 + 1.5*pSRS-Offset value
                                    // (0..15)
    uchar         PSRSAP_Offset;    // PSRS_OFFSET for aperiodic SRS, see TS 36.213, 5.1.3.1
                                    // For Ks=1.25, the actual parameter value is pSRS-Offset value -3
                                    // For Ks=0, the actual parameter value is -10.5 + 1.5*pSRS-Offset value
                                    // (0..15)
    uchar         Pucch1_Offset;    // Parameter Delta_F_PUCCH(F) for PUCCH format 1
                                    // (-2, 0)
    uchar         Pucch1a1b_Offset; // Parameter Delta_F_PUCCH(F) for PUCCH format 1a and 1b
                                    // (-2, 0)
    uchar         Pucch22a2b_Offset;// Parameter Delta_F_PUCCH(F) for PUCCH format 2a and 2b
                                    // (-2, 0)
    uchar         Pucch3_Offset;     // Parameter Delta_F_PUCCH(F) for PUCCH format 3
                                    // (-2, 0)
    } sdrLte_PwrDed_01;

typedef struct
    {
    short         P0UePUSCH;        // P0,UE_PUSCH See TS 36.213, 5.1.1.1, unit dB
                                    // This field is applicable for non-persistent scheduling only
                                    // (-8..7)
    ushort        DeltaMCS;         // Ks, see TS 36.213, 5.1.1.1
                                    // 0 = disabled, 1 = enabled
    uchar         Accumulation;     // Accumulation-enabled, see TS 36.213, 5.1.1.1
                                    // 0 = disabled, 1 = enabled
    uchar         PSRS_Offset;      // PSRS_OFFSET, see TS 36.213, 5.1.3.1
                                    // For Ks=1.25, the actual parameter value is pSRS-Offset value -3
                                    // For Ks=0, the actual parameter value is -10.5 + 1.5*pSRS-Offset value
                                    // (0..15)
    uchar         PSRSAP_Offset;    // PSRS_OFFSET for aperiodic SRS, see TS 36.213, 5.1.3.1
                                    // For Ks=1.25, the actual parameter value is pSRS-Offset value -3
                                    // For Ks=0, the actual parameter value is -10.5 + 1.5*pSRS-Offset value
                                    // (0..15)
    uchar         PathlossRef;      // Indicates whether the UE shall apply as pathloss reference either the
                                    // downlink of the PCell or of the SCell that corresponds with this uplink
                                    // 0 = primary cell, 1 = secondary cell
    } sdrLte_PwrDed_SC_00;

typedef struct
    {
    char         P0UePUSCH;        // P0,UE_PUSCH See TS 36.213, 5.1.1.1, unit dB
                                    // This field is applicable for non-persistent scheduling only
                                    // (-8..7)
    uchar        PathlossRef_Accumulation_DeltaMCS;   // Bit 0..1: DeltaMCS, see TS 36.213, 5.1.1.1. 
                                          // Admitted values: 0 = disabled, 1 = enabled
                                          // Bit 2..3: Accumulation-enabled, see TS 36.213, 5.1.1.1
                                          // Admitted values: 0 = disabled, 1 = enabled
                                          // Bit 4..7: PathlossRef indicates whether the UE shall apply as pathloss reference either the
                                          // downlink of the PCell or of the SCell that corresponds with this uplink
                                          // 0 = primary cell, 1 = secondary cell
    uchar         PSRS_Offset;      // PSRS_OFFSET, see TS 36.213, 5.1.3.1
                                    // For Ks=1.25, the actual parameter value is pSRS-Offset value -3
                                    // For Ks=0, the actual parameter value is -10.5 + 1.5*pSRS-Offset value
                                    // (0..15)
    uchar         PSRSAP_Offset;    // PSRS_OFFSET for aperiodic SRS, see TS 36.213, 5.1.3.1
                                    // For Ks=1.25, the actual parameter value is pSRS-Offset value -3
                                    // For Ks=0, the actual parameter value is -10.5 + 1.5*pSRS-Offset value
                                    // (0..15)
    } sdrLte_PwrDed_SC_01;
typedef sdrLte_PwrDed_SC_01 sdrLte_PwrDed_SC;

typedef struct
    {
    uint          Enabled;        // TPC enabled
                                  // 0 = disabled, 1 = enabled
    uint          Rnti;           // RNTI for power control using DCI format 3/3A, see TS 36.212
    ushort        Format;         // 0 = format 3, 1 = format 3A
    ushort        Index;          // Index of N or M, see TS 36.212, 5.3.3.1.6 and 5.3.3.1.7,
                                  // where N or M is dependent on the used DCI format.
    } sdrLte_Tpc;

typedef struct
    {
    ushort        Enabled;        // CQI periodic reporting enabled
                                  // 0 = disabled, 1 = enabled
    ushort        PUCCH_ResIdx;   // n(2)PUCCH, see TS 36.213, 7.2
                                  // (0..767)
    ushort        PmiConfigIdx;   // CQI/PMI Periodicity and Offset Configuration Index ICQI/PMI, see TS 36.213, 7.2.2-1A
                                  // (0..511)
    ushort        FormatInd;      // Format Indicator Periodic
                                  // 0 = widebandCQI, 1 = subbandCQI
    ushort        K;              // K, see TS 36.213 [23, 7.2.2]
                                  // (1..4)
    ushort        RiConfigIdx;    // RI Config Index IRI, see TS 36.213, 7.2.2-1B
                                  // (0..1023)
    uint          AckNackCQI;     // Simultaneous-AN-and-CQI. see TS 36.213, 10.1
                                  //  1= allowed.
    } sdrLte_CqiPer;

typedef struct
    {
    ushort        Enabled;        // CQI periodic reporting enabled
                                  // 0 = disabled, 1 = enabled
    ushort        PUCCH_ResIdxP0; // n(2)PUCCH, see TS 36.213, 7.2 for port 0
                                  // (0..1184)
    ushort        PUCCH_ResIdxP1; // n(2)PUCCH, see TS 36.213, 7.2 for port 1
                                  // (0..1184)
    ushort        PmiConfigIdx;   // CQI/PMI Periodicity and Offset Configuration Index ICQI/PMI, see TS 36.213, 7.2.2-1A
                                  // (0..1023)
    uchar         FormatInd;      // Format Indicator Periodic
                                  // 0 = widebandCQI, 1 = subbandCQI
    uchar         CsiRepMode;     // Parameter PUCCH_format1-1_CSI_reporting_mode, see TS 36.213
                                  // 0 = submode1, 1 = submode2
    uchar         PerFactor;      // Parameter H, see 36.213
                                  // (2..4)
    uchar         K;              // K, see TS 36.213 [23, 7.2.2]
                                  // (1..4)
    ushort        RiConfigIdx;    // RI Config Index IRI, see TS 36.213, 7.2.2-1B
                                  // (0..1023)
    uchar         AckNackCQI;     // Simultaneous-AN-and-CQI. see TS 36.213, 10.1
                                  // 1 = allowed.
    uchar         CqiMask;        // Limits CQI/PMI/RI reports to the on-duration period of the DRX cycle, see TS 36.321 [6].
                                  // (0, 1)
    uint          CsiEnabled;     // CSI reporting enabled
                                  // 0 = disabled, 1 = enabled
    ushort        CqiPmiConfIdx2; // Parameter CQI/PMI Periodicity and Offset Configuration Index ICQI/PMI, see TS 36.213
                                  // (0..1023)
    ushort        RiConfIdx2;     // Parameter RI Config Index IRI, see TS 36.213
                                  // (0..1023)
    } sdrLte_CqiPer_01;

typedef struct
    {
    ushort        Enabled;        // CQI periodic reporting enabled
                                  // 0 = disabled, 1 = enabled
    ushort        PUCCH_ResIdxP0; // n(2)PUCCH, see TS 36.213, 7.2 for port 0
                                  // (0..1184)
    ushort        PUCCH_ResIdxP1; // n(2)PUCCH, see TS 36.213, 7.2 for port 1
                                  // (0..1184)
    ushort        PmiConfigIdx;   // CQI/PMI Periodicity and Offset Configuration Index ICQI/PMI, see TS 36.213, 7.2.2-1A
                                  // (0..1023)
    uchar         FormatInd;      // Format Indicator Periodic
                                  // 0 = widebandCQI, 1 = subbandCQI
    uchar         CsiRepMode;     // Parameter PUCCH_format1-1_CSI_reporting_mode, see TS 36.213
                                  // 0 = submode1, 1 = submode2
    uchar         PerFactor;      // Parameter H, see 36.213
                                  // (2..4)
    uchar         K;              // K, see TS 36.213 [23, 7.2.2]
                                  // (1..4)
    ushort        RiConfigIdx;    // RI Config Index IRI, see TS 36.213, 7.2.2-1B
                                  // (0..1023)
    uchar         AckNackCQI;     // Simultaneous-AN-and-CQI. see TS 36.213, 10.1
                                  // 1 = allowed.
    uchar         AckNackCQI_F3;  // Simultaneous-AN-and-CQI. see TS 36.213, 10.1
                                  // 1 = allowed.
    ushort        CqiMask;        // Limits CQI/PMI/RI reports to the on-duration period of the DRX cycle, see TS 36.321 [6].
                                  // (0, 1)
    ushort        CsiEnabled;     // CSI reporting enabled
                                  // 0 = disabled, 1 = enabled
    ushort        CqiPmiConfIdx2; // Parameter CQI/PMI Periodicity and Offset Configuration Index ICQI/PMI, see TS 36.213
                                  // (0..1023)
    ushort        RiConfIdx2;     // Parameter RI Config Index IRI, see TS 36.213
                                  // (0..1023)
    } sdrLte_CqiPer_02;

typedef struct
    {
    ushort        ReportingMode;  // Reporting mode aperiodic
                                  // (12, 20, 22, 30, 31)
    ushort        NomPdschRsEpreOff; // nom PDSCH RS EPRE Offset
                                  // (-1..6)
    sdrLte_CqiPer ReportingPer;   // CQI periodic reporting

    } sdrLte_Cqi;

typedef struct
    {
    uchar         ReportingMode;  // Reporting mode aperiodic
                                  // (12, 20, 22, 30, 31)
    uchar         NomPdschRsEpreOff; // nom PDSCH RS EPRE Offset
                                  // (-1..6)
    uchar         CqiMask;        // Limits CQI/PMI/RI reports to the on-duration period of the DRX cycle, see TS 36.321 [6].
                                  // (0, 1)
    uchar         PmiRiReport;    // The presence of this field means PMI/RI reporting is configured (tm8 only)
                                  // (0, 1)
    sdrLte_CqiPer ReportingPer;   // CQI periodic reporting

    } sdrLte_Cqi_01;

typedef struct
    {
    uchar            ReportingMode;  // Reporting mode aperiodic
                                     // (12, 20, 22, 30, 31) 0xff means disabled
    uchar            CsiTrigger1;    // Aperiodic CSI report
                                     // indicates for which serving cell(s) the aperiodic CSI report is triggered when one or more SCells are configured.
                                     // trigger1 corresponds to the CSI request field 10 see TS 36.213
    uchar            CsiTrigger2;    // Aperiodic CSI report
                                     // indicates for which serving cell(s) the aperiodic CSI report is triggered when one or more SCells are configured.
                                     // trigger2 corresponds to the CSI request field 11 see TS 36.213
    uchar            NomPdschRsEpreOff; // nom PDSCH RS EPRE Offset
                                     // (-1..6)
    ushort           CqiMask;        // Limits CQI/PMI/RI reports to the on-duration period of the DRX cycle, see TS 36.321 [6].
                                     // (0, 1)
    ushort           PmiRiReport;    // The presence of this field means PMI/RI reporting is configured (tm8 only)
                                     // (0, 1)
    sdrLte_CqiPer_01 ReportingPer;   // CQI periodic reporting

    } sdrLte_Cqi_02;

typedef struct
    {
    uchar            ReportingMode;  // Reporting mode aperiodic
                                     // (12, 20, 22, 30, 31) 0xff means disabled
    uchar            CsiTrigger1;    // Aperiodic CSI report
                                     // indicates for which serving cell(s) the aperiodic CSI report is triggered when one or more SCells are configured.
                                     // trigger1 corresponds to the CSI request field 10 see TS 36.213
    uchar            CsiTrigger2;    // Aperiodic CSI report
    uchar            NomPdschRsEpreOff; // nom PDSCH RS EPRE Offset
                                     // (-1..6)
    ushort           CqiMask;        // Limits CQI/PMI/RI reports to the on-duration period of the DRX cycle, see TS 36.321 [6].
                                     // (0, 1)
    ushort           PmiRiReport;    // The presence of this field means PMI/RI reporting is configured (tm8 only)
                                     // (0, 1)
    sdrLte_CqiPer_02 ReportingPer;   // CQI periodic reporting

    } sdrLte_Cqi_03;

typedef struct
    {
    uchar            ReportingMode;  // Reporting mode aperiodic
                                     // (12, 20, 22, 30, 31) 0xff means disabled
    uchar            NomPdschRsEpreOff; // nom PDSCH RS EPRE Offset
                                     // (-1..6)
    ushort           PmiRiReport;    // The presence of this field means PMI/RI reporting is configured (tm8 only)
                                     // (0, 1)
    sdrLte_CqiPer_01 ReportingPer;   // CQI periodic reporting

    } sdrLte_Cqi_SC_00;

typedef struct
    {
    uchar            ReportingMode;  // Reporting mode aperiodic
                                     // (12, 20, 22, 30, 31) 0xff means disabled
    uchar            NomPdschRsEpreOff; // nom PDSCH RS EPRE Offset
                                     // (-1..6)
    ushort           PmiRiReport;    // The presence of this field means PMI/RI reporting is configured (tm8 only)
                                     // (0, 1)
    sdrLte_CqiPer_02 ReportingPer;   // CQI periodic reporting

    } sdrLte_Cqi_SC_01;

typedef struct
    {
    uchar PmiRiReportEnabled_CsiEnabled_CqiPerEnabled;       // Bit 0..1: CQI periodic reporting enabled
                                                             // 0 = disabled, 1 = enabled
                                                             // Bit 2..3: CSI reporting enabled
                                                             // 0 = disabled, 1 = enabled
                                                             // Bit 4..7: PMI RI reporting enabled 
                                                             // The presence of this field means PMI/RI reporting is configured (tm8 only)
                                                             // 0 = disabled, 1 = enabled
    uchar   ReportingMode;     // Reporting mode aperiodic
                               // (12, 20, 22, 30, 31) 0xff means disabled
    char    NomPdschRsEpreOff; // nom PDSCH RS EPRE Offset
                               // (-1..6)
    uchar  K_CsiRepMode_FormatInd;      // Bit 0..1: Format Indicator Periodic
                                        // 0 = widebandCQI, 1 = subbandCQI
                                        // Bit 2..3: CsiRepMode Parameter PUCCH_format1-1_CSI_reporting_mode, see TS 36.213
                                        // 0 = submode1, 1 = submode2
                                        // Bit 4..7: K, see TS 36.213 [23, 7.2.2]
                                        // (1..4)
    ushort        PUCCH_ResIdxP0; // n(2)PUCCH, see TS 36.213, 7.2 for port 0
                                  // (0..1184)
    ushort        PUCCH_ResIdxP1; // n(2)PUCCH, see TS 36.213, 7.2 for port 1
                                  // (0..1184)
    ushort        PmiConfigIdx;   // CQI/PMI Periodicity and Offset Configuration Index ICQI/PMI, see TS 36.213, 7.2.2-1A
                                  // (0..1023)
    ushort        RiConfigIdx;    // RI Config Index IRI, see TS 36.213, 7.2.2-1B
                                  // (0..1023)
    ushort        CqiPmiConfIdx2; // Parameter CQI/PMI Periodicity and Offset Configuration Index ICQI/PMI, see TS 36.213
                                  // (0..1023)
    ushort        RiConfIdx2;     // Parameter RI Config Index IRI, see TS 36.213
                                  // (0..1023)
    } sdrLte_Cqi_SC_02;
    
typedef sdrLte_Cqi_SC_02 sdrLte_Cqi_SC; 

typedef struct
    {
    uchar            CsiEnabled;     // CSI reporting enabled
                                     // 0 = disabled, 1 = enabled
    uchar            AntennaPort;    // Parameter represents the number of antenna ports used for transmission of CSI reference signals
                                     // (1, 2, 4, 8)
    uchar            ResConfig;      // CSI reference signal configuration, see TS 36.211
                                     // (0..31)
    uchar            SfConfig;       // Parameter ICSI-RS, see TS 36.211
                                     // (0..154)
    short            Pc;             // Parameter Pc, see TS 36.213
                                     // (-8..15)
    ushort           ZeroTxPowerCSI; // ZeroTxPowerCSI enabled
                                     // 0 = disabled, 1 = enabled
    } sdrLte_Csi;

typedef struct
    {
    // TM10 
    uchar                       CsiRSConfigNZPId;     // CSI-RS-ConfigNZP id
                                                      // (1..3)
    uchar                       AntennaPortsCount;    // Parameter represents the number of antenna ports used for transmission
                                                      // of CSI reference signals. see TS 36.211 [6.10.5]
                                                      // (1, 2, 4, 8)
    uchar                       ResourceConfig;       // CSI reference signal configuration. see TS 36.211 [table 6.10.5.2-1 and 6.10.5.2-2]
                                                      // (0..31)
    uchar                       SubframeConfig;       // ICSI−RS , see TS 36.211 [table 6.10.5.3-1]
                                                      // (0..154)
    ushort                      ScramblingId;         // Pseudo-random sequence generator parameter, ID n. see TS 36.213 [7.2.5].
                                                      // (0..503)
    // TM10 
    ushort                      QclScramblingId;      // Pseudo-random sequence generator parameter, ID n. see TS 36.213 [7.2.5].
                                                      // (0..503)
    // TM10 
    ushort                      CrsPortsCount;        // Number of ports
                                                      // (1, 2, 4)
    // TM10 
    ushort                      NumMbsfnSFConfig;     // Number of MBSFN allocations
    // TM10 
    sdrLte_MbsfnSubframeConfig  MbsfnSFConfigList[8]; // MBSFN allocation configuration list

    } sdrLte_CsiRSConfigNZP_00;

// Release 10
typedef struct {
        uchar               AntennaPort;            // Parameter represents the number of antenna ports used for transmission of CSI reference signals
                                                    // (1, 2, 4, 8)
        uchar               ResConfig;              // CSI reference signal configuration, see TS 36.211
                                                    // (0..31)
        uchar               SfConfig;               // Parameter ICSI-RS, see TS 36.211
                                                    // (0..154)
        char                Pc;                     // Parameter Pc, see TS 36.213
    } sdrLte_CsiRSConfigNZP_R10;

// Release 11   
typedef struct
    {
    // The following field is used in TM10 configuration.
    // It is defined because the structure should be padded
    uchar                       CsiRSConfigNZPId;     // CSI-RS-ConfigNZP id
                                                      // (1..3)
    uchar                       AntennaPortsCount;    // Parameter represents the number of antenna ports used for transmission
                                                      // of CSI reference signals. see TS 36.211 [6.10.5]
                                                      // (1, 2, 4, 8)
    uchar                       ResourceConfig;       // CSI reference signal configuration. see TS 36.211 [table 6.10.5.2-1 and 6.10.5.2-2]
                                                      // (0..31)
    uchar                       SubframeConfig;       // ICSI−RS , see TS 36.211 [table 6.10.5.3-1]
                                                      // (0..154)
    ushort                      ScramblingId;         // Pseudo-random sequence generator parameter, ID n. see TS 36.213 [7.2.5].
                                                      // (0..503) - defined in release-11 - if present used for TM-9 and TM-10
    ushort                      Spare;

    } sdrLte_CsiRSConfigNZP_01;

typedef sdrLte_CsiRSConfigNZP_01 sdrLte_CsiRSConfigNZP_R11;
    
// Release 10
typedef struct {
        ushort          ResourceConfigList; // Parameter ZeroPowerCSI-RS, see TS 36.213 [7.2.7]
        uchar           SubframeConfig;     // Parameter ICSI−RS, see TS 36.211 [table 6.10.5.3-1]
                                            // (0..154)
        uchar           Spare;
    } sdrLte_CsiRSConfigZP_R10;

// Release 11
typedef struct
    {
    // The following field is used in TM10 configuration.
    // It is defined because the structure should be padded
    uchar           CsiRSConfigZPId;    // CSI-RS-ConfigZP id
                                        // (1..4)
    uchar           SubframeConfig;     // Parameter ICSI−RS, see TS 36.211 [table 6.10.5.3-1]
                                        // (0..154)
    ushort          ResourceConfigList; // Parameter ZeroPowerCSI-RS, see TS 36.213 [7.2.7]

    } sdrLte_CsiRSConfigZP;

typedef sdrLte_CsiRSConfigZP sdrLte_CsiRSConfigZP_R11;

typedef struct
    {
    uchar                 CsiEnabled;            // CSI reporting enabled
                                                 // 0 = disabled, 1 = enabled
    uchar                 AntennaPort;           // Parameter represents the number of antenna ports used for transmission of CSI reference signals
                                                 // (1, 2, 4, 8)
    uchar                 ResConfig;             // CSI reference signal configuration, see TS 36.211
                                                 // (0..31)
    uchar                 SfConfig;              // Parameter ICSI-RS, see TS 36.211
                                                 // (0..154)
    int                   Pc;                    // Parameter Pc, see TS 36.213
                                                 // (-8..15)
    uchar                 ZeroTxPowerCSI;        // ZeroTxPowerCSI enabled
                                                 // 0 = disabled, 1 = enabled
    // TM10 
    uchar                 NumCsiRSConfigNZPRel;  // Number of CSI-RS-ConfigNZP to be released
                                                 // 0..3
    // TM10 
    uchar                 NumCsiRSConfigNZPAdd;  // Number of CSI-RS-ConfigNZP to be added or modified
                                                 // 0..3
    // TM10 
    uchar                 NumCsiRSConfigZPRel;   // Number of CSI-RS-ConfigZP to be released
                                                 // 0..4
    // TM10 
    uchar                 NumCsiRSConfigZPAdd;   // Number of CSI-RS-ConfigZP to be added or modified
                                                 // 0..4
    // TM10 
    uchar                 CsiRSConfigNZPRel[3];  // CSI-RS-ConfigNZP to be released

    // TM10 
    uchar                 CsiRSConfigZPRel[4];   // CSI-RS-ConfigZP to be released

    // TM10: For TM9 the list contains one only element
    sdrLte_CsiRSConfigNZP_00 CsiRSConfigNZPAdd[3];  // CSI-RS-ConfigNZP to be added or modified

    // TM10: For TM9 the list contains one only element 
    sdrLte_CsiRSConfigZP  CsiRSConfigZPAdd[4];   // CSI-RS-ConfigZP to be added or modified

    } sdrLte_Csi_01;

    typedef struct
    {
    uchar                 CsiEnabled;            // CSI reporting enabled
                                                 // 0 = disabled, 1 = enabled
    uchar                 AntennaPort;           // Parameter represents the number of antenna ports used for transmission of CSI reference signals
                                                 // (1, 2, 4, 8)
    uchar                 ResConfig;             // CSI reference signal configuration, see TS 36.211
                                                 // (0..31)
    uchar                 SfConfig;              // Parameter ICSI-RS, see TS 36.211
                                                 // (0..154)
    short                 Pc;                    // Parameter Pc, see TS 36.213
                                                 // (-8..15)
    uchar                 ZeroTxPowerCSI;        // ZeroTxPowerCSI enabled
                                                 // 0 = disabled, 1 = enabled
    uchar                 Spare;
    sdrLte_CsiRSConfigNZP_01 CsiRSConfigNZPAdd;  // CSI-RS-ConfigNZP (only 1 for TM-9)
    sdrLte_CsiRSConfigZP  CsiRSConfigZPAdd;      // CSI-RS-ConfigZP (only 1 for TM-9)

    } sdrLte_Csi_02;

typedef struct
{
    uchar CsiEnabled_NZP_R10;
    uchar CsiEnabled_ZP_R10;
    uchar CsiEnabled_NZP_R11;
    uchar CsiEnabled_ZP_R11;

    /* Release 10 IEs */
    sdrLte_CsiRSConfigNZP_R10 CsiRSConfigNZPAdd_R10;
    sdrLte_CsiRSConfigZP_R10  CsiRSConfigZPAdd_R10;

    /* Release 11 IEs */
    sdrLte_CsiRSConfigNZP_01  CsiRSConfigNZPAdd_R11;  // CSI-RS-ConfigNZP (only 1 for TM-9)
    sdrLte_CsiRSConfigZP      CsiRSConfigZPAdd_R11;   // CSI-RS-ConfigZP (only 1 for TM-9)

    } sdrLte_Csi_03;
    
typedef sdrLte_Csi_03 sdrLte_Csi_Curr;

typedef struct
    {
    ushort  Enabled;              // Uplink SR enabled
                                  // 0 = disabled, 1 = enabled
    ushort  SrPucchResourceIndex; // n(1)PUCCH,SRI, see TS 36.213, 10.1
                                  // (0..2047)
    ushort  SrConfigurationIndex; // I_SR, see TS 36.213, 10.1
                                  // (0..155)
    ushort  DsrTransMax;          // DSR_TRANS_MAX, see TS 36.321
                                  // [4, 8, 16, 32, 64]
    } sdrLte_SrInfo;

typedef struct
    {
    uchar   Enabled;                // Uplink SR enabled
                                    // 0 = disabled, 1 = enabled
    uchar   DsrTransMax;            // DSR_TRANS_MAX, see TS 36.321
                                    // [4, 8, 16, 32, 64]
                                    // 0xff means infinite
    ushort  SrPucchResourceIndexP0; // n(1)PUCCH,SRI port 0, see TS 36.213, 10.1
                                    // (0..2047)
    ushort  SrPucchResourceIndexP1; // n(1)PUCCH,SRI port 1, see TS 36.213, 10.1
                                    // (0..2047)
    ushort  SrConfigurationIndex;   // I_SR, see TS 36.213, 10.1
                                    // (0..157)
    } sdrLte_SrInfo_01;

typedef struct
    {
    uchar   Enabled;                // Uplink SR enabled
                                    // 0 = disabled, 1 = enabled
    uchar   DsrTransMax;            // DSR_TRANS_MAX, see TS 36.321
                                    // [4, 8, 16, 32, 64]
                                    // 0xff means infinite
    ushort  SrPucchResourceIndexP0; // n(1)PUCCH,SRI port 0, see TS 36.213, 10.1
                                    // (0..2047)
    ushort  SrPucchResourceIndexP1; // n(1)PUCCH,SRI port 1, see TS 36.213, 10.1
                                    // (0..2047)
    uchar   SrConfigurationIndex;   // I_SR, see TS 36.213, 10.1
                                    // (0..157)
    uchar   SrProhibitTimer;        // INTEGER (0..7)

    } sdrLte_SrInfo_02;

typedef struct
    {
    uchar   GapEnabled;           // Measurement gap enabled
                                  // 0 = disabled, 1 = enabled
    uchar   GapPattern;           // Measurement gap pattern
                                  // [0, 1]
    ushort  MeasGapOff;           // Measurement gap offset
                                  // (0..79)
    } sdrLte_MeasInfo;

typedef struct
    {
    uchar              SchedulingInfo; // Cross carrier scheduling enabled
                                       // 0 = disabled, 1 = enabled
    uchar              CifPresence;    // Carrier indication field presence
                                       // only if cross carrier disabled. Range (0..7)
    uchar              SchedCellId;    // Indicates which cell, using ServingCellIdx, signals the downlink allocations
                                       // and uplink grants, if applicable, for the concerned SCell.
    uchar              PdschStart;     // The starting OFDM symbol of PDSCH for the concerned SCell.
                                       // (1..4)
    } sdrLte_CrossCarrier;

    
typedef struct
    {
    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_00       CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    } sdrLte_SCellInfo_00;

typedef struct
    {
    uint                LsuCellIdSC;   // LSU cell identifier for secondary cell ( 4bytes to have pad structure )
    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    } sdrLte_SCellInfo_01;

typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_01   AntennaInfo;    // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    } sdrLte_SCellInfo_02;
    

typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_01   AntennaInfo;    // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi_01       CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed_01  PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00   PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    } sdrLte_SCellInfo_03;

typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_01   AntennaInfo;    // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi_02       CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration
    } sdrLte_SCellInfo_04;

typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_01   AntennaInfo;    // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration
    } sdrLte_SCellInfo_05;

typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_01   AntennaInfo;    // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed_02  PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00  PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration
    } sdrLte_SCellInfo_06;

typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_SC_00   AntennaInfo;    // Antenna configuration
    sdrLte_PdschDed_02     PdschInfo;     // PDSCH configuration
    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration
    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration
    sdrLte_Cqi_SC_01       CqiReporting;  // CQI-Reporting
    sdrLte_UlSrsDed_SC_00  UlSrsInfo;     // Sounding reference signal configuration
    } sdrLte_SCellInfo_06bis;

typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_02   AntennaInfo;    // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed_02  PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration
    } sdrLte_SCellInfo_07;

    typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_02   AntennaInfo;    // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed_03  PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_00  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_00    PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_01    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration
    } sdrLte_SCellInfo_08;

    typedef struct
    {
    char                SCellIndex;     // a short identity, used to identify an SCell // TS 36.331
    char                SCellUplEnable; // 0: secondary cell uplink disabled; !0: secondary cell uplink enabled
    ushort              LsuCellIdSC;    // LSU cell identifier for secondary cell ( 2bytes to have pad structure )
    sdrLte_AntInfo_03   AntennaInfo;    // Antenna configuration

    sdrLte_CrossCarrier CrossCarrier;  // Cross carrier scheduling config

    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_PdschDed_03  PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_SC_01  PuschInfo;     // PUSCH configuration

    sdrLte_PwrDed_SC_01  PwrInfo;       // Uplink power control configuration

    sdrLte_Cqi_SC_02    CqiReporting;  // CQI-Reporting

    sdrLte_UlSrsDed_02  UlSrsInfo;     // Sounding reference signal configuration
    } sdrLte_SCellInfo_09;

typedef sdrLte_SCellInfo_09 sdrLte_SCellInfo;

typedef struct
    {
    uint          Enabled;        // Downlink SPS enabled
                                  // 0 = disabled, 1 = enabled
    uint          Rnti;           // RNTI for SPS, see TS 36.221

    ushort        SpsInterval;    // Semi-persistent scheduling interval in downlink (ms)
                                  // [10, 20, 32, 40, 64, 80, 128, 160, 320, 640]
    ushort        NumHarqProc;    // Number of Configured SPS Processes, see TS 36.321

    uint          NumN1PucchAn;   // List of parameter N1 PUCCH AN [1..4]

    ushort        N1PucchAn[4];   // N1 PUCCH AN [0..2047]

    } sdrLte_SpsInfo;

// **********************************************************************
// EPDCCH Configuration
typedef struct
    {
    uchar       CsiNRepCE;                  // Number of subframes for CSI reference resource, see TS 36.213 [23]. Value sf1 corresponds to 1 subframe, sf2
                                            // corresponds to 2 subframes and so on.
                                            // ENUMERATED [v1, v2, v4, v8, v16, v32]
    uchar       HoppingConfig;              // Frequency hopping activation/deactivation for unicast MPDCCH/PDSCH, see TS 36.211
                                            // ENUMERATED [0->on,1->off],
    uchar       StartSF;                    // Starting subframe configuration for an MPDCCH UE-specific search space, see TS 36.211 
                                            // FDD: ENUMERATED [v1, v1dot5, v2, v2dot5, v4, v5, v8, v10]
                                            // TDD: ENUMERATED [v1, v2, v4, v5, v8, v10, v20, spare1]
    uchar       NRep;                       // Maximum numbers of repetitions for MPDCCH 
                                            // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128, r256],
    ushort      Narrowband;                 // Narrowband for MPDCCH, see TS 36.211 
                                            // INTEGER (1..maxAvailNarrowBands that is equal to 16)
    ushort      Spare;
    } sdrLte_MPDCCHConfig_00;

typedef struct
    {
    uchar                   SetId;          // 0,1
    uchar                   TxType;         // 0-> Localized, 1-> Distributed
    ushort                  NumPrb;         // number of prb for Epdcch set {2,4,8}
    uint                    R_Assign[2];    // BIT STRING size (4,...,38) Indicates the index to a specific combination of PRB 
    ushort                  NepdcchId;      // (0,...,503) DMRS scrambling sequence initialization parameter 36.211 6.10.3A.1 
    ushort                  PucchStartOff;  // (0,...,2047) PUCCH format 1a/b resource starting offset for the EPDCCH set TS 36.213 10.1.1.2
    } sdrLte_EpdcchSetConfig_00;

typedef struct
    {
    uchar                   SetId;          // 0,1
    uchar                   TxType;         // 0-> Localized, 1-> Distributed
    uchar                   NumPrb;         // number of prb for Epdcch set {2,4,8}
    uchar                   NumPrbCE;       // number of prb for BL UEs or UEs in EC 
                                            // Its value is 6. If NumPrbCE field is present ( different from 0xff), 
                                            // the UE shall ignore the value of NumPrb field.
    uint                    R_Assign[2];    // BIT STRING size (4,...,38) Indicates the index to a specific combination of PRB 
    ushort                  NepdcchId;      // (0,...,503) DMRS scrambling sequence initialization parameter 36.211 6.10.3A.1 
    ushort                  PucchStartOff;  // (0,...,2047) PUCCH format 1a/b resource starting offset for the EPDCCH set TS 36.213 10.1.1.2
    sdrLte_MPDCCHConfig_00  MpdcchConf;
    
    } sdrLte_EpdcchSetConfig_01;

typedef struct
    {
    uchar                   Enabled;        // 0 = disabled, 1 = enabled
    uchar                   StartSymbol;    // OFDM start symbol for any EPDCCH  
    uchar                   NumSet;         // number of EPDCCH sets ( 1 or 2) 
    uchar                   N_Rep;          // Epdcch transmission repetition factor
    uint                    SbfPattern[3];  // Bit map of subframes which the UE shall monitor the search space on EPDCCH
                                            // FDD 40 bit, TDD config 1-5 20 bit, TDD config 6 60 bit, TDD config 0 70 bit
    sdrLte_EpdcchSetConfig_00  EpdcchSet[2];
    } sdrLte_EpdcchConfig_00;

typedef struct
    {
    uchar                   Enabled;        // 0 = disabled, 1 = enabled
    uchar                   StartSymbol;    // OFDM start symbol for any EPDCCH  
    uchar                   NumSet;         // number of EPDCCH sets ( 1 or 2) 
    uchar                   N_Rep;          // Epdcch transmission repetition factor
    uint                    SbfPattern[3];  // Bit map of subframes which the UE shall monitor the search space on EPDCCH
                                            // FDD 40 bit, TDD config 1-5 20 bit, TDD config 6 60 bit, TDD config 0 70 bit
    sdrLte_EpdcchSetConfig_01  EpdcchSet[2];
    }sdrLte_EpdcchConfig_01;
    
typedef sdrLte_EpdcchConfig_01 sdrLte_EpdcchConfig;
    
typedef struct
    {
    sdrLte_PdschDed  PdschInfo;   // PDSCH configuration

    sdrLte_PuschDed  PuschInfo;   // PUSCH configuration

    sdrLte_PucchDed  PucchInfo;   // PCCH configuration

    sdrLte_PwrDed    PwrInfo;     // Uplink power control configuration

    sdrLte_Tpc       TpcPucch;    // TPC PUCCH Configuration

    sdrLte_Tpc       TpcPusch;    // TPC PUSCH Configuration

    sdrLte_Cqi       CqiReporting;// CQI-Reporting

    sdrLte_UlSrsDed_00  UlSrsInfo;   // Sounding reference signal configuration

    sdrLte_AntInfo   AntennaInfo; // Antenna configuration

    sdrLte_SrInfo    SrInfo;      // Scheduling request configuration

    sdrLte_MeasInfo  MeasGapInfo; // Measurement configuration

    int              MaxUpPwr;    // Maximum uplink power (in dBm)

    int              UeCategory;  // UE category

    sdrLte_SpsInfo   SpsInfo;     // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_00;

typedef struct
    {
    sdrLte_PdschDed   PdschInfo;   // PDSCH configuration

    sdrLte_PuschDed   PuschInfo;   // PUSCH configuration

    sdrLte_PucchDed   PucchInfo;   // PCCH configuration

    sdrLte_PwrDed     PwrInfo;     // Uplink power control configuration

    sdrLte_Tpc        TpcPucch;    // TPC PUCCH Configuration

    sdrLte_Tpc        TpcPusch;    // TPC PUSCH Configuration

    sdrLte_Cqi_01     CqiReporting;// CQI-Reporting

    sdrLte_UlSrsDed_00   UlSrsInfo;   // Sounding reference signal configuration

    sdrLte_AntInfo_01 AntennaInfo; // Antenna configuration

    sdrLte_SrInfo     SrInfo;      // Scheduling request configuration

    sdrLte_MeasInfo   MeasGapInfo; // Measurement configuration

    int               MaxUpPwr;    // Maximum uplink power (in dBm)

    int               UeCategory;  // UE category

    sdrLte_SpsInfo    SpsInfo;     // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_01;

typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_02       CqiReporting;  // CQI-Reporting

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_01    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_00 SCellInfo;     // Secondary cells info

    char                SCellUplEnable; // 0: secondary cell uplink disabled
                                        // !0: secondary cell uplink enabled
    char                CifPresence;   // Carrier indication field presence
    short               Spare;

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category

    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_02;

typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_01    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_01 SCellInfo;     // Secondary cells info

    char                SCellUplEnable; // 0: secondary cell uplink disabled
                                        // !0: secondary cell uplink enabled
    char                CifPresence;   // Carrier indication field presence
    short               LsuCellIdPC;   // LSU cell identifier for primary cell ( 2bytes spare has been recovered )

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category


    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_03;


typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_01    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_02 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v0];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                spare;
    char                CifPresence;   // Carrier indication field presence
    short               LsuCellIdPC;   // LSU cell identifier for primary cell ( 2bytes spare has been recovered )

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category


    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_04;

typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_02 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v0];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                spare;
    char                CifPresence;   // Carrier indication field presence
    short               LsuCellIdPC;   // LSU cell identifier for primary cell ( 2bytes spare has been recovered )

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category


    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_05;


typedef struct
    {
    sdrLte_PdschDed_01  PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting

    sdrLte_Csi_01       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_03 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                spare;
    char                CifPresence;   // Carrier indication field presence
    short               LsuCellIdPC;   // LSU cell identifier for primary cell ( 2bytes spare has been recovered )

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category


    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_06;
    
typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_02 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                spare;
    char                CifPresence;   // Carrier indication field presence
    short               LsuCellIdPC;   // LSU cell identifier for primary cell ( 2bytes spare has been recovered )

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category


    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_07;
    

typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration

    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting

    sdrLte_Csi          CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_02 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    short               LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category

    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration

    } sdrLte_DedPhyChannelCfg_08;
    

typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_02       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_04 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category
    
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    } sdrLte_DedPhyChannelCfg_09;

typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_05 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category
    
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    } sdrLte_DedPhyChannelCfg_10;

typedef struct
    {
    sdrLte_PdschDed     PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_05 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category
    
    sdrLte_SpsInfo          SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_00  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_11;

typedef struct
    {
    sdrLte_PdschDed_02  PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_01  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_01  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_06 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    int                 UeCategory;    // UE category
    
    sdrLte_SpsInfo          SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_00  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_12;

typedef struct
    {
    sdrLte_PdschDed_02  PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_02  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_02  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_06 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v1];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    ushort              UeCategory;    // UE category
    uchar               CeMode;        // Indicates the enhanced coverage mode as specified in TS 36.213 
                                       // ENUMERATED [ 0->ce-ModeA, 1->ce-ModeB]; 0xff invalid value
    char                Spare;    
    
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_01  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_13;

typedef struct
    {
    sdrLte_PdschDed_02  PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_02  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_02  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_06 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v2];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    ushort              UeCategory;    // UE category
    uchar               CeLevel;        // Indicates the CE level as specified in TS 36.321 [6] 
                                        // INTEGER 0...3; 0xff invalid value
    char                Spare;    
    
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_01  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_14;

typedef struct
    {
    sdrLte_PdschDed_02  PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_02  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_02  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_01   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_06bis SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v3];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    ushort              UeCategory;    // UE category
    uchar               CeLevel;        // Indicates the CE level as specified in TS 36.321 [6] 
                                        // INTEGER 0...3; 0xff invalid value
    char                Spare;    
    
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_01  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_14bis;
    
typedef struct
    {
    sdrLte_PdschDed_02  PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_02  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_02  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_02   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_07 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v2];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    ushort              UeCategory;    // UE category
    uchar               CeLevel;        // Indicates the CE level as specified in TS 36.321 [6] 
                                        // INTEGER 0...3; 0xff invalid value
    char                Spare;    
    
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_01  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_15;

typedef struct
    {
    sdrLte_PdschDed_03  PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_02  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_02  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_01  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_AntInfo_02   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_08 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v2];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char                MaxNumTxLayers; // Number of transmission layers ( up to 8)
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    ushort              UeCategory;    // UE category
    uchar               CeLevel;        // Indicates the CE level as specified in TS 36.321 [6] 
                                        // INTEGER 0...3; 0xff invalid value
    char                Spare;    
    
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_01  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_16;


typedef struct
    {
    sdrLte_PdschDed_03  PdschInfo;     // PDSCH configuration
    
    sdrLte_PuschDed_03  PuschInfo;     // PUSCH configuration

    sdrLte_PucchDed_02  PucchInfo;     // PCCH configuration

    sdrLte_PwrDed_01    PwrInfo;       // Uplink power control configuration

    sdrLte_Tpc          TpcPucch;     // TPC PUCCH Configuration

    sdrLte_Tpc          TpcPusch;      // TPC PUSCH Configuration

    sdrLte_Cqi_03       CqiReporting;  // CQI-Reporting
    
    sdrLte_Csi_03       CsiReporting;  // CSI-Reporting

    sdrLte_UlSrsDed_02  UlSrsInfo;     // Sounding reference signal configuration

    sdrLte_UlSrsAperiodicDed_00 UlSrsAperInfo; // Aperiodic Sounding reference signal configuration
    
    sdrLte_AntInfo_03   AntennaInfo;   // Antenna configuration

    sdrLte_AntInfo_UL   AntennaInfoUL; // Antenna configuration for uplink

    sdrLte_SrInfo_02    SrInfo;        // Scheduling request configuration

    sdrLte_MeasInfo     MeasGapInfo;   // Measurement configuration

    sdrLte_SCellInfo_09 SCellInfo[sdrLte_MAX_SECONDARY_CARRIERS_v3];     // Secondary cells info list; field NumSC gives the elements to be considered ( 0...sdrLte_MAX_SECONDARY_CARRIERS)

    char               MaxNumTxLayers; //Number of transmission layers ( up to 8) 
                                       // as it is configured according to category. See 36.306
                                       // Default value is 0xFF
    char                CifPresence;    // Carrier indication field presence
    char                LsuCellIdPC;    // LSU cell identifier for primary cell ( 2bytes spare has been recovered )
    char                NumSC;          // Added for counting SCellInfo

    int                 MaxUpPwr;      // Maximum uplink power (in dBm)

    uchar               UeCategory;      // UE category: a combined uplink and downlink UE capability.
                                         // If this field is set to invalid value 0xff for legacy UE, 
                                         // UeCategory_Dl and UeCategory_Ul are used to execute the test
                                         // Otherwise UeCategory_Dl and UeCategory_Ul are not used.
                                         // Combined category is kept in IF to support releases
                                         // in which DL and UL categories are not supported
    uchar               UeCategory_Dl;   // downlink UE capability 
    uchar               CeLevel;        // Indicates the CE level as specified in TS 36.321 [6] 
                                        // INTEGER 0...3; 0xff invalid value
    uchar               UeCategory_Ul;  // uplink UE capability 
    sdrLte_SpsInfo      SpsInfo;       // Semi persistent scheduling configuration
    
    sdrLte_EpdcchConfig_01  EpdcchInfo; // E-PDCCH configuration
    } sdrLte_DedPhyChannelCfg_17;

typedef sdrLte_DedPhyChannelCfg_17 sdrLte_DedPhyChannelCfg;

/* NARROWBAND-IoT*/

/*CarrierFreq-NB*/
typedef struct
{
    ushort CarrierFreq;       // Provides the ARFCN applicable for the NB-IoT carrier frequency as defined in TS 36.101 [Table 5.7.3-1]
    uchar  CarrierFreqOffset; //Offset of the NB-IoT channel number to EARFCN as defined in TS 36.101 [42].
                              // ENUMERATED [ v-10, v-9, v-8,   v-7, v-6, v-5, v-4, v-3, v-2, v-1, v-0dot5, v0,  v1,    v2,  v3,  v4,  v5,  v6,  v7,  v8,  v9]
                              // v-10 means -10, v-9 means -9, and so on. 
    uchar  Spare;
}sdrLte_CarrierFreqNB_00;

typedef struct
{
    uint   CarrierFreq;       // Provides the ARFCN applicable for the NB-IoT carrier frequency as defined in TS 36.101 [Table 5.7.3-1]
    uchar  CarrierFreqOffset; //Offset of the NB-IoT channel number to EARFCN as defined in TS 36.101 [42].
                              // ENUMERATED [ v-10, v-9, v-8,   v-7, v-6, v-5, v-4, v-3, v-2, v-1, v-0dot5, v0,  v1,    v2,  v3,  v4,  v5,  v6,  v7,  v8,  v9]
                              // v-10 means -10, v-9 means -9, and so on. 
    uchar  Spare[3];
}sdrLte_CarrierFreqNB_01;

typedef sdrLte_CarrierFreqNB_01 sdrLte_CarrierFreqNB;

/*DL-CarrierConfigDedicated-NB*/
    
/* downlinkBitmapNonAnchor */
typedef struct
    {
        uchar UseNoBitmap;                      // 0xff invalid value   
        uchar UseAnchorBitmap;                  // 0xff invalid value   
        ushort Spare;
        uint  ExplicitBitmapConfiguration[2]; // it is used to specify the set of NB-IoT downlink subframes for downlink transmission
                                              // NB-IoT downlink subframe configuration over 10ms or 40ms for inband and 10ms for standalone/guardband.
                                              // The first/leftmost bit corresponds to the subframe #0 of the radio frame satisfying SFN mod x = 0, where x is the size of the bit string divided by 10.
                                              // Value 0 in the bitmap indicates that the corresponding subframe is invalid for downlink transmission.
                                              // Value 1 in the bitmap indicates that the corresponding subframe is valid for downlink transmission

    } sdrLte_DlBitmapNonAnchorNB_00;

typedef struct
    {
#define sdrLte_DlBitmapNonAnchorNB_USE_NO_BITMAP       (0)
#define sdrLte_DlBitmapNonAnchorNB_USE_ANCHOR_BITMAP   (1)
#define sdrLte_DlBitmapNonAnchorNB_USE_EXPLICIT_BITMAP (2)
#define sdrLte_DlBitmapNonAnchorNB_USE_DEFAULT_VALUE (0xFF)
        uchar DlBitmapNonAnchorValid;         // According this value the other fields will be evaluated
        uchar Spare;
        uchar UseNoBitmap;                    // 0xff invalid value 
        uchar UseAnchorBitmap;                // 0xff invalid value 
        uint  ExplicitBitmapConfiguration[2]; // it is used to specify the set of NB-IoT downlink subframes for downlink transmission
                                              // NB-IoT downlink subframe configuration over 10ms or 40ms for inband and 10ms for standalone/guardband.
                                              // The first/leftmost bit corresponds to the subframe #0 of the radio frame satisfying SFN mod x = 0, where x is the size of the bit string divided by 10.
                                              // Value 0 in the bitmap indicates that the corresponding subframe is invalid for downlink transmission.
                                              // Value 1 in the bitmap indicates that the corresponding subframe is valid for downlink transmission

    } sdrLte_DlBitmapNonAnchorNB_01;

typedef sdrLte_DlBitmapNonAnchorNB_01 sdrLte_DlBitmapNonAnchorNB;

/* dl-GapNonAnchor */
/* DL-GapConfig-NB information element*/
typedef struct
    {
    uchar  DlGapThreshold;      // Coefficient to calculate the gap duration of a DL transmission: dl-GapDurationCoeff * dl-GapPeriodicity, 
                                // Duration in number of subframes. See TS 36.211 and TS 36.213.
                                // ENUMERATED [n32, n64, n128, n256]; 0xff invalid value
    uchar  DlGapPeriodicity;    // Periodicity of a DL transmission gap in number of subframes. See TS 36.211 and TS 36.213.    
                                // ENUMERATED [sf64, sf128, sf256, sf512]; 0xff invalid value
    uchar  DlGapDurationCoeff;  // Threshold on the maximum number of repetitions configured for NPDCCH before application of 
                                // DL transmission gap configuration, See TS 36.211 and TS 36.213.
                                //  ENUMERATED [oneEighth, oneFourth, threeEighth, oneHalf]; 0xff invalid value 
    uchar  Spare;
} sdrLte_DlGapConfigNB_00;
typedef sdrLte_DlGapConfigNB_00 sdrLte_DlGapConfigNB;

typedef struct
{
    uchar  UseNoGap;                            
    uchar  UseAnchorGapConfig;  
    ushort Spare;
    sdrLte_DlGapConfigNB_00 ExplicitGapConfiguration;
} sdrLte_DlGapNonAnchorNB_00;

typedef struct
{
#define sdrLte_DlGapNonAnchorNB_USE_NO_GAP       (0)
#define sdrLte_DlGapNonAnchorNB_USE_ANCHOR_GAP   (1)
#define sdrLte_DlGapNonAnchorNB_USE_EXPLICIT_GAP (2)
#define sdrLte_DlGapNonAnchorNB_USE_DEFAULT_VALUE (0xFF)
    uchar  DlGapNonAnchorValid;         // According this value the other fields will be evaluated
    uchar  Spare;
    uchar  UseNoGap;                            
    uchar  UseAnchorGapConfig;  
    sdrLte_DlGapConfigNB_00 ExplicitGapConfiguration;
} sdrLte_DlGapNonAnchorNB_01;

typedef sdrLte_DlGapNonAnchorNB_01 sdrLte_DlGapNonAnchorNB;

/*inbandCarrierInfo: Provides the configuration of a non-anchor inband carrier. */
typedef struct
{
    uchar SamePCIIndicator; // This parameter specifies whether the non-anchor carrier reuses the same PCI as the EUTRA carrier
                            // 1 -> Same PCI, 0 -> Different PCI
    char IndexToMidPRB;  // In case of non-anchor carrier reuses the same PCI as the EUTRA carrier (SamePCIIndicator=1), this field indicates 
                         // PRB index; it is signaled by offset from the middle of the EUTRA system
                         // Range INTEGER (-55..54)                          
    uchar EutraNumCrsPorts;  // If SamePCIIndicator=0,Number of E-UTRA CRS antenna ports, either the same number of ports as NRS or 4 antenna ports. 
                             // See TS 36.211 [21], TS 36.212 [22], and TS 36.213 [23].
                             // ENUMERATED [same, four]; 0xff invalid value
    uchar Spare;
} sdrLte_InbandCarrierInfoNB_00;

typedef struct
{
    uchar SamePCIIndicator; // This parameter specifies whether the non-anchor carrier reuses the same PCI as the EUTRA carrier
                            // 1 -> Same PCI, 0 -> Different PCI
    char IndexToMidPRB;  // In case of non-anchor carrier reuses the same PCI as the EUTRA carrier (SamePCIIndicator=1), this field indicates 
                         // PRB index; it is signaled by offset from the middle of the EUTRA system
                         // Range INTEGER (-55..54)                          
    uchar EutraNumCrsPorts;  // If SamePCIIndicator=0,Number of E-UTRA CRS antenna ports, either the same number of ports as NRS or 4 antenna ports. 
                             // See TS 36.211 [21], TS 36.212 [22], and TS 36.213 [23].
                             // ENUMERATED [same, four]; 0xff invalid value
    uchar EutraControlRegionSize; // Indicates the control region size of the E-UTRA cell for the in-band operation mode, see TS 36.213 [23]. 
                                  // Unit is in number of OFDM symbols. ENUMERATED {n1, n2, n3} 
                                  // If operationModeInfo in MIB-NB is set to inband-SamePCI (SamePCIIndicator=1) or inband-DifferentPCI (SamePCIIndicator=0), 
                                  // it should be set to the value broadcast in SIB1-NB.
} sdrLte_InbandCarrierInfoNB_01;

typedef sdrLte_InbandCarrierInfoNB_01 sdrLte_InbandCarrierInfoNB;

typedef struct
{
    sdrLte_CarrierFreqNB_00       DlCarrierFreq;     // DL carrier frequency. The downlink carrier is not in a E-UTRA PRB which contains E-UTRA PSS/SSS/PBCH
    sdrLte_DlBitmapNonAnchorNB_00 DlBitmapNonAnchor; // NB-IoT downlink subframe configuration for downlink transmission on the non-anchor carrier.     
    sdrLte_DlGapNonAnchorNB_00    DlGapNonAnchor;    // Downlink transmission gap configuration for the non-anchor carrier, see TS 36.211  [21] and TS 36.213 [23]. 
    sdrLte_InbandCarrierInfoNB_00   InbandCarrierInfo; // Provides the configuration of a non-anchor inband carrier.
                                                           // If absent, the configuration of the anchor carrier applies.
} sdrLte_DLCarrierCfgDedNB_00;

typedef struct
{
    sdrLte_CarrierFreqNB_00       DlCarrierFreq;     // DL carrier frequency. The downlink carrier is not in a E-UTRA PRB which contains E-UTRA PSS/SSS/PBCH
    sdrLte_DlBitmapNonAnchorNB_00 DlBitmapNonAnchor; // NB-IoT downlink subframe configuration for downlink transmission on the non-anchor carrier.     
    sdrLte_DlGapNonAnchorNB_00    DlGapNonAnchor;    // Downlink transmission gap configuration for the non-anchor carrier, see TS 36.211  [21] and TS 36.213 [23]. 
    sdrLte_InbandCarrierInfoNB_01   InbandCarrierInfo; // Provides the configuration of a non-anchor inband carrier.
                                                           // If absent, the configuration of the anchor carrier applies.
} sdrLte_DLCarrierCfgDedNB_01;

typedef struct
{
    sdrLte_CarrierFreqNB_01       DlCarrierFreq;     // DL carrier frequency. The downlink carrier is not in a E-UTRA PRB which contains E-UTRA PSS/SSS/PBCH
    sdrLte_DlBitmapNonAnchorNB_01 DlBitmapNonAnchor; // NB-IoT downlink subframe configuration for downlink transmission on the non-anchor carrier.     
    sdrLte_DlGapNonAnchorNB_01    DlGapNonAnchor;    // Downlink transmission gap configuration for the non-anchor carrier, see TS 36.211  [21] and TS 36.213 [23]. 
    sdrLte_InbandCarrierInfoNB_01   InbandCarrierInfo; // Provides the configuration of a non-anchor inband carrier.
                                                     // If absent, the configuration of the anchor carrier applies.
    uchar NrsPowerOffsetNonAnchor;  /* Provides the power offset of the downlink narrowband reference-signal EPRE of the anchor/ non-anchor carrier
                                       relative to the anchor carrier, unit in dB. Value dB-12 corresponds to -12 dB, dB-10 corresponds to -10 dB and so on.
                                       See TS 36.213 [23, 16.2.2].
                                       ENUM [dB-12, dB-10, dB-8, dB-6,dB-4, dB-2, dB0, dB3]*/
    uchar Spare[3];
} sdrLte_DLCarrierCfgDedNB_02;

typedef sdrLte_DLCarrierCfgDedNB_02 sdrLte_DLCarrierCfgDedNB;

/*NPDCCH-ConfigDedicated-NB*/
typedef struct
{
    uchar NpdcchNumRepetitions;         // Maximum number of repetitions for NPDCCH UE specific search space (USS), see TS 36.213.
                                        // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128, r256, r512, r1024, r2048, spare4, spare3, spare2, spare1 ]
                                        // 0xff invalid value
    uchar NpdcchStartSF;                // Starting subframe configuration for an NPDCCH UE-specific search space, see TS 36.213. 
                                        // Value v1dot5 corresponds to 1.5, value 2 corresponds to 2 and so on.
                                        // ENUMERATED  [v1dot5, v2, v4, v8, v16, v32, v48, v64]; 0xff invalid value
    uchar NpdcchOffset;                 // Fractional period offset of starting subframe for NPDCCH UE specific search space USS.
                                        // ENUMERATED [zero, oneEighth, oneFourth, threeEighth]; 0xff invalid value
    uchar Spare;
}sdrLte_NpdcchCfgDedNB_00;
typedef sdrLte_NpdcchCfgDedNB_00 sdrLte_NpdcchCfgDedNB;

/*NPUSCH-ConfigDedicated-NB*/
typedef struct
{
    uchar   AckNackNumRep; // Number of repetitions for the ACK NACK resource unit carrying HARQ 
                           // response to NPDSCH see TS 36.211 and TS 36.213.
                           // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128]
                           // 0xff invalid value
    uchar   NpuschAllSymbols;   // If set to 1, the UE shall use all NB-IoT symbols for NPUSCH transmission.
                                // If set to 0, the UE punctures the NPUSCH  transmissions in the symbols that collides with SRS.
                                // If the field is not present ( set to 0xff), the UE uses all NB-IoT symbols for NPUSCH transmission.
    uchar   GroupHoppingDisabled; // Disable/Enable sequence-group-hopping
                                  // ENUMERATED {0->enable, 1->disable]     
    uchar   Spare;
}sdrLte_NpuschCfgDedNB_00;
typedef sdrLte_NpuschCfgDedNB_00 sdrLte_NpuschCfgDedNB;

/*UplinkPowerControlDedicated-NB*/
typedef struct
{
    int P0Npusch; // See TS 36.213 [5.1.1.1], unit dB. This field is applicable for non-persistent scheduling, only. 
                  // Range INTEGER  (-8..7)
}sdrLte_UlPwrCtrlNB_00;
typedef sdrLte_UlPwrCtrlNB_00 sdrLte_UlPwrCtrlNB;

typedef struct
{
    uchar   UeCategory;    // UE category;
                           // ENUMERATED [nb1]
    uchar   Multitone;     // Defines whether the UE supports UL multi-tone transmissions on NPUSCH 
                           // ENUMERATED [supported]; 0xff invalid value
    uchar   Multicarrier;  // Defines whether the UE supports multi -carrier operation
                           // ENUMERATED [supported]; 0xff invalid value
    uchar   UlDlCarrierCfgValid;     // This field gives the validity of DlCarrierCfg and UlCarrierFreq
                                     // bit 0...3 : 1 -> DlCarrierConfig is present, 0 -> DlCarrierConfig is not valid
                                     // bit 4...7 : 1 -> UlCarrierFreq is present, 0 -> UlCarrierFreq is not valid
    sdrLte_DLCarrierCfgDedNB_00 DlCarrierConfig;  // Downlink Carrier different form the anchor carrier  used for all unicast transmissions . 
                                                  // If absent, the downlink carrier is the downlink anchor carrier 
    sdrLte_CarrierFreqNB_00     UlCarrierFreq;   // UL carrier frequency  
                                                 // if absent, the same TX-RX frequency separation as for the  anchor carrier applies

    sdrLte_NpdcchCfgDedNB_00    NpdcchCfgDed;    // NPDCCH configuration
    sdrLte_NpuschCfgDedNB_00    NpuschCfgDed;    // UL unicast configuration

    sdrLte_UlPwrCtrlNB_00       PwrInfo;       // Uplink power control configuration
    int                         MaxUpPwr;      // Maximum uplink power (in dBm)

    } sdrLte_DedPhyChannelCfgNB_00;

typedef struct
{
    uchar   CarrierIdNB;   // DL NBIoT Anchor Carrier identifier.
    uchar   UeCategory;    // UE category;
                           // ENUMERATED [nb1]
    uchar   Multitone;     // Defines whether the UE supports UL multi-tone transmissions on NPUSCH 
                           // ENUMERATED [supported]; 0xff invalid value
    uchar   Multicarrier;  // Defines whether the UE supports multi -carrier operation
                           // ENUMERATED [supported]; 0xff invalid value
    uchar   Spare[3];
    uchar   UlDlCarrierCfgValid;     // This field gives the validity of DlCarrierCfg and UlCarrierFreq
                                     // bit 0...3 : 1 -> DlCarrierConfig is present, 0 -> DlCarrierConfig is not valid
                                     // bit 4...7 : 1 -> UlCarrierFreq is present, 0 -> UlCarrierFreq is not valid
    sdrLte_DLCarrierCfgDedNB_01 DlCarrierConfig;  // Downlink Carrier different form the anchor carrier  used for all unicast transmissions . 
                                                  // If absent, the downlink carrier is the downlink anchor carrier 
    sdrLte_CarrierFreqNB_00     UlCarrierFreq;   // UL carrier frequency  
                                                 // if absent, the same TX-RX frequency separation as for the  anchor carrier applies

    sdrLte_NpdcchCfgDedNB_00    NpdcchCfgDed;    // NPDCCH configuration
    sdrLte_NpuschCfgDedNB_00    NpuschCfgDed;    // UL unicast configuration

    sdrLte_UlPwrCtrlNB_00       PwrInfo;       // Uplink power control configuration
    int                         MaxUpPwr;      // Maximum uplink power (in dBm)

    } sdrLte_DedPhyChannelCfgNB_01;

typedef struct
{
    uchar   CarrierIdNB;   // DL NBIoT Anchor Carrier identifier.
    uchar   UeCategory;    // UE category;
                           // ENUMERATED [nb1]
    uchar   Multitone;     // Defines whether the UE supports UL multi-tone transmissions on NPUSCH 
                           // ENUMERATED [supported]; 0xff invalid value
    uchar   Multicarrier;  // Defines whether the UE supports multi -carrier operation
                           // ENUMERATED [supported]; 0xff invalid value
    uchar   TwoHarqProcConfig; // Activation of two HARQ processes, see TS 36.212 [22] and TS 36.213 [23].
                               // ENUM [true]; 0xff invalid value   
    uchar   CeLevel;           // Indicates the CE level as specified in TS 36.321 [6] 
                               // INTEGER 0...2; 0xff invalid value
    uchar   Spare;
    uchar   UlDlCarrierCfgValid;     // This field gives the validity of DlCarrierCfg and UlCarrierFreq
                                     // bit 0...3 : 1 -> DlCarrierConfig is present, 0 -> DlCarrierConfig is not valid
                                     // bit 4...7 : 1 -> UlCarrierFreq is present, 0 -> UlCarrierFreq is not valid
    sdrLte_DLCarrierCfgDedNB_02 DlCarrierConfig;  // Downlink Carrier different form the anchor carrier  used for all unicast transmissions . 
                                                  // If absent, the downlink carrier is the downlink anchor carrier 
    sdrLte_CarrierFreqNB_01     UlCarrierFreq;   // UL carrier frequency  
                                                 // if absent, the same TX-RX frequency separation as for the  anchor carrier applies

    sdrLte_NpdcchCfgDedNB_00    NpdcchCfgDed;    // NPDCCH configuration
    sdrLte_NpuschCfgDedNB_00    NpuschCfgDed;    // UL unicast configuration

    sdrLte_UlPwrCtrlNB_00       PwrInfo;       // Uplink power control configuration
    int                         MaxUpPwr;      // Maximum uplink power (in dBm)

    } sdrLte_DedPhyChannelCfgNB_02;
    
typedef sdrLte_DedPhyChannelCfgNB_02 sdrLte_DedPhyChannelCfgNB;

/*MBMS*/
typedef struct {

    uchar               NotificationRepetitionCoeff; // Actual change notification repetition period common for all MCCHs that are configured
                                                     // = shortest modification period / notificationRepetitionCoeff. The "shortest modification
                                                     // period" corresponds with the lowest value of mcch-ModificationPeriod of all MCCHs that are
                                                     // configured
                                                     // (0, 1)

    uchar               NotificationOffset;          // Indicates, together with the notificationRepetitionCoeff, the radio frames in which the
                                                     // MCCH information change notification is scheduled i.e. the MCCH information change notification
                                                     // is scheduled in radio frames for which: SFN mod notification repetition period = notificationOffset
                                                     // (0..10)

    uchar               NotificationSFIndex;         // Indicates the subframe used to transmit MCCH change notifications on PDCCH.
                                                     // (1..6)

    uchar               Spare;

} sdrLte_NotificationConfig;

typedef struct {

    uchar               McchRepetitionPeriod;    // Defines the interval between transmissions of MCCH information, in radio frame.
                                                 // (32, 64, 128, 256)
    uchar               McchOffset;              // Indicates, together with the mcch-RepetitionPeriod, the radio frames in which MCCH is
                                                 // scheduled i.e. MCCH is scheduled in radio frames for which:
                                                 // SFN mod mcch-RepetitionPeriod = mcch-Offset
                                                 // (0..10)
    uchar               McchModificationPeriod;  // Defines periodically appearing boundaries, i.e. radio frames for which
                                                 // SFN mod mcch-ModificationPeriod = 0
                                                 // (0 means 512, 1 means 1024)
    uchar               SfAllocInfo;             // Indicates the subframes of the radio frames indicated by the
                                                 // mcch-RepetitionPeriod and the mcch-Offset, that may carry MCCH
    uchar               SignallingMCS;           // Indicates the Modulation and Coding Scheme (MCS) applicable for the subframes indicated by the
                                                 // field sf-AllocInfo and for each (P)MCH that is configured for this MBSFN area, for the first
                                                 // subframe allocated to the (P)MCH within each MCH scheduling period
                                                 // (2, 7, 13, 19)
    uchar               Spare[3];

} sdrLte_McchCfg;

typedef struct {

    uchar               MbsfnAreaId;             // Indicates the MBSFN area ID, parameter NIDMBSFN in TS 36.211
                                                 // (0..255)
    uchar               NonMBSFNregionLength;    // Indicates how many symbols from the beginning of the subframe constitute
                                                 // the non-MBSFN region. This value applies in all subframes of the MBSFN area
                                                 // used for PMCH transmissions as indicated in the MSI. see TS 36.211 [21, Table 6.7-1]
                                                 // 1, 2
    uchar               NotificationIndicator;   // Indicates which PDCCH bit is used to notify the UE about change of the MCCH applicable
                                                 // for this MBSFN area. Value 0 corresponds with the least significant bit as defined in TS 36.212
                                                 // (0..7)
    uchar               Spare;                   // RbId

    sdrLte_McchCfg      McchConfig;

    /* lte_rlcmac_Crlc_RxUmParm_t: Start */
    uint                Spare2;
    uchar               Spare3;
    /* lte_rlcmac_Crlc_RxUmParm_t: End */
    uchar               Spare4;                  // Current Area Index: 0 - 7
    uchar               Spare5[2];

} sdrLte_AreaInfo;

typedef struct {

    sdrLte_NotificationConfig   NotificationConfig;

    uchar                       Spare[3];

    char                NumOfAreaInfo;               // Number of MBMS areas

    sdrLte_AreaInfo             AreaInfoList[1];

} sdrLte_MbmsMcchAcquisition;

typedef struct {

    ushort              SfAllocEnd;                 // Indicates the last subframe allocated to this (P)MCH within a period identified
                                                    // by field commonSF-AllocPeriod.
                                                    // (0..1535)
    uchar               DataMCS;                    // Indicates the value for parameter in TS 36.213 [23, Table 7.1.7.1-1], which defines
                                                    // the Modulation and Coding Scheme (MCS) applicable for the subframes of this (P)MCH
                                                    // (0..28)
    uchar               MchSchedulingPeriod;        // Indicates the MCH scheduling period
                                                    // enum (8, 16, 32, 64, 128, 256, 512, 1024)

} sdrLte_PmchConfig;

typedef struct {

    sdrLte_PmchConfig  PmchConfig;

} sdrLte_PmchInfo;

typedef struct {

    uchar                      MbsfnAreaId;         // Indicates the MBSFN area ID, parameter NIDMBSFN in TS 36.211
                                                    // (0..255)

    uchar                      AreaIdx;             // Current Area Index: 0 - 7

    uchar                      CommonSFAllocPeriod; // Indicates the period during which resources corresponding with field commonSF-Alloc are
                                                    // divided between the (P)MCHs that are configured for this MBSFN area.
                                                    // (4, 8, 16, 32, 64, 128, 256)

    char                       NumOfCommonSFAlloc;  // Number of commonSF allocations

    sdrLte_MbsfnSubframeConfig CommonSFAlloc[1];

    uchar                      Spare[3];

    char                       NumOfPmchInfo;       // Number of PMCH Info

    sdrLte_PmchInfo            PmchInfoList[1];

} sdrLte_MbmsAreaConfig;

struct sdrLte_MbsfnInfo_00
    {
    uchar AreaIdx;     // Index of the current Mbsfn area of this subframe

    uchar McchFlag;    // Flag that indicates if MCCH is in this subframe

    ushort PmchIdxMap; // Bit map that indicates which PMCH is in this subframe: bit 0 -> index 0, ..., bit 14 -> index 14 (PMCH index: 0 - 14)
    };

struct sdrLte_MbsfnInfo_01
    {
    uchar AreaIdx;     // Index of the current Mbsfn area of this subframe

    uchar McchFlag;    // Flag that indicates if MCCH is in this subframe

    ushort PmchIdxMap; // Bit map that indicates which PMCH is in this subframe: bit 0 -> index 0, ..., bit 14 -> index 14 (PMCH index: 0 - 14)

    uint Ant1Rx;       // 0 = Mbsfn only on Antenna0; 1 = Mbsfn on Antenna0 and Antenna1 and matched Data;
                       // 2 = Mbsfn on Antenna0 and Antenna1 but mismatched Data; 0xffffffff when not valid
    };

typedef struct sdrLte_MbsfnInfo_00 sdrLte_MbsfnInfo_00;
typedef struct sdrLte_MbsfnInfo_01 sdrLte_MbsfnInfo_01;
typedef struct sdrLte_MbsfnInfo_01 sdrLte_MbsfnInfo;

// ***************************************************************************************************
struct sdrLte_AntennaPortInd_00
    {
    uchar         Bcch;         // BCCH successfully decoding flag ( 1: successfully decoded, 0: otherwise)
    uchar         PSS;          // 1 if antenna transports PSS signal; 0 otherwise 
    ushort        Spare;
    int           Rspl;         // Reference signal power level (0.25 dBm) for antenna 0..3
    int           Snr;          // Signal to noise ratio (ratio * 256) for antenna 0..3
    int           Pathloss;     // Signal pathloss (dB) for antenna 0..3    
    };
    
typedef struct sdrLte_AntennaPortInd_00 sdrLte_AntennaPortInd_00;   
typedef struct sdrLte_AntennaPortInd_00 sdrLte_AntennaPortInd;
    
struct sdrLte_RadioPathInd_00
    {
    int           Sens;         // Sensitivity value applied by AGC for for radio path 0..3
                                // 0x7FFFFFFF = not applicable
    uchar         RadioPathIdx;   // Radio path identifier
    uchar         AntennaBitMask; // How Radio Path is mapped on Antenna Ports ( 1 = valid antenna port; 0 = not valid antenna port)
    ushort        NumAntennaPorInd;                  // Number of configured antenna ports ( it is indicated from AntennaBitMask field)
    sdrLte_AntennaPortInd_00 AntennaPortInd[1];      // Dynamic List of info per antenna ports ( until 4 antennas )
    };

typedef struct sdrLte_RadioPathInd_00 sdrLte_RadioPathInd_00;   
typedef struct sdrLte_RadioPathInd_00 sdrLte_RadioPathInd;

//***********************************************************
struct sdrLteMeasInterfCell_00
{
    uint        LsuCellIdInterf;   // LSU Cell identifier for interfering cell
    int         Pathloss;          // simulated Pathloss for interfered cell.     
    };
        
typedef struct sdrLteMeasInterfCell_00 sdrLteMeasInterfCell_00;
typedef struct sdrLteMeasInterfCell_00 sdrLteMeasInterfCell;

//***********************************************************
struct sdrLte_Prach_ParametersCE_00
{
    uchar   PrachConfig;      // PRACH configuration index
                                  // (0..63)
    uchar   FreqOffset;       // prach-FrequencyOffset
                                  // (0..94)
    uchar   StartingSubframe; // PRACH starting subframe periodicity, see TS 36.211
                                  // ENUMERATED {sf2, sf4, sf8, sf16, sf32, sf64, sf128, sf256}
    uchar   NumRepetitionPerPreambleAttempt; // Number of PRACH repetitions per attempt for each enhanced coverage level, See TS 36.211
                                            // ENUMERATED [n1,n2,n4,n8,n16,n32,n64,n128]                                                 
    uchar   MpdcchNumRepetitionRA;          // Maximum number of repetitions for M-PDCCH common search space (CSS) for RAR, Msg3 and Msg4, 
                                            // see TS 36.211             
                                            // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128, r256],
    uchar   HoppingConfig;           // ENUMERATED [ 0 ->on, 1->off]
    uchar   NarrowbandsToMonitor[2]; // INTEGER (1.. maxAvailNarrowBands) for each element; 0xff invalid value 
                                     // It is not allowed to have invalid both elements or invalid the first element
                                     // The rule is: if there is 1 element this will be the valid,
                                     // if there are 2 elements: the first element is meaningful if the preamble is even,
                                     // the second element is meaningful if the preamble is odd
                                     
    };
typedef struct sdrLte_Prach_ParametersCE_00 sdrLte_Prach_ParametersCE_00;   
typedef struct sdrLte_Prach_ParametersCE_00 sdrLte_Prach_ParametersCE;

struct sdrLte_PrachBR_00
{
    int         RsrpThrInfo[3];    // The criterion for BL UEs and UEs in EC to select PRACH resource set,See TS 36.213 
                                   // SEQUENCE (SIZE(1..3)) OF RSRP-Range
    uchar       MpdcchStartSF;     // Starting subframe configuration for M-PDCCH common search space (CSS) for RAR, 
                                   // Msg3 retransmission, PDSCH with contention resolution and PDSCH with 
                                   // RRCConnectionSetup, See TS 36.211 and TS 36.213.
                                   // For FDD ENUMERATED {v1, v1dot5, v2, v2dot5, v4, v5, v8, v10}, 
                                   // For TDD ENUMERATED {v1, v2, v4, v5, v8, v10, v20, spare}
    uchar       HoppingOffset;     // INTEGER ( 0...94)
    uchar       InitialCElevel;    // Indicates initial PRACH CE level at random access, see TS 36.321 [6]. 
                                   // If not configured, UE selects PRACH CE level based on measured RSRP level, see TS 36.321 [6].
                                   // INTEGER (1..maxCE-Level-r13)
    uchar       NumCELevel;        // This field gives the number of meaningful elements in the Prach_ParametersCE vector
    sdrLte_Prach_ParametersCE_00   Prach_ParametersCE[sdrLteMAXCE_LEVEL_v0]; // Configures PRACH parameters for each enhanced coverage level
    };

typedef struct sdrLte_PrachBR_00 sdrLte_PrachBR_00; 
typedef struct sdrLte_PrachBR_00 sdrLte_PrachBR;

struct sdrLte_PdschBR_00
    {
    ushort        MaxNumRepCEModeA;    // pdsch-maxNumRepetitionCEmodeA:
                                       // Maximum value to indicate the set of PDSCH repetition numbers for CE mode A, see TS 36.211 and TS 36.213.
                                       // ENUMERATED ( r16, r32); 0xff invalid value
    ushort        MaxNumRepCEModeB;    // pdsch-maxNumRepetitionCEmodeB:
                                       // Maximum value to indicate the set of PDSCH repetition numbers for CE mode B, see TS 36.211 and TS 36.213.
                                       // ENUMERATED ( r192, r256, r384, r512, r768, r1024, r1536, r2048); 0xff invalid value
    } ;
    
typedef struct sdrLte_PdschBR_00 sdrLte_PdschBR_00;
typedef struct sdrLte_PdschBR_00 sdrLte_PdschBR;

struct sdrLte_PuschBR_00
    {
    ushort        MaxNumRepCEModeA;    // pusch-maxNumRepetitionCEmodeA:
                                       // Maximum value to indicate the set of PUSCH repetition numbers for EC mode A, see TS 36.211 and TS 36.213.
                                       // ENUMERATED ( r8, r16, r32 ); 0xff invalid value
    ushort        MaxNumRepCEModeB;    // pusch-maxNumRepetitionCEmodeB:
                                       // Maximum value to indicate the set of PDSCH repetition numbers for CE mode B, see TS 36.211 and TS 36.213.
                                       // ENUMERATED ( r192, r256, r384, r512, r768, r1024, r1536, r2048); 0xff invalid value
    uchar         HoppingOffset;       // For BL UEs and UEs in EC, Ffrequency hopping activation/deactivation for unicast PUSCH. TS 36.211 
                                       // INTEGER (1..maxAvailNarrowBands that is equal to 16)

    } ;

struct sdrLte_PuschBR_01
    {
    uchar         MaxNumRepCEModeA;    // pusch-maxNumRepetitionCEmodeA:
                                       // Maximum value to indicate the set of PUSCH repetition numbers for EC mode A, see TS 36.211 and TS 36.213.
                                       // ENUMERATED ( r8, r16, r32 ); 0xff invalid value
    uchar         MaxNumRepCEModeB;    // pusch-maxNumRepetitionCEmodeB:
                                       // Maximum value to indicate the set of PDSCH repetition numbers for CE mode B, see TS 36.211 and TS 36.213.
                                       // ENUMERATED ( r192, r256, r384, r512, r768, r1024, r1536, r2048); 0xff invalid value
    ushort        HoppingOffset;       // For BL UEs and UEs in EC, Ffrequency hopping activation/deactivation for unicast PUSCH. TS 36.211 
                                       // INTEGER (1..maxAvailNarrowBands that is equal to 16)

    } ;
    
typedef struct sdrLte_PuschBR_00 sdrLte_PuschBR_00;
typedef struct sdrLte_PuschBR_01 sdrLte_PuschBR_01;
typedef struct sdrLte_PuschBR_01 sdrLte_PuschBR;

struct sdrLte_PucchBR_00
    {
    uchar         NumRepetitionCEMsg4Level0; // Number of repetitions for PUCCH carrying HARQ response to PDSCH containing Msg4 for PRACH CE levels 0, 1, 2
                                             // and 3, see TS 36.211 [21] and TS 36.213 [23]. 0xff invalid value
                                             // ENUMERATED {n1, n2, n4, n8}
    uchar         NumRepetitionCEMsg4Level1; // ENUMERATED {n1, n2, n4, n8}
    uchar         NumRepetitionCEMsg4Level2; // ENUMERATED {n4, n8, n16, n32}
    uchar         NumRepetitionCEMsg4Level3; // ENUMERATED {n4, n8, n16, n32}
    uint          NumCELevel;       // This field gives the number of meaningful elements in the N1PUCCH_AN vector
    ushort        N1PUCCH_AN[sdrLteMAXCE_LEVEL_v0]; // Starting offsets of the PUCCH resource(s) indicated by SIB1-BR, 
                                                    // see TS 36.213
                                                    // INTEGER (0..2047); 
                                                    // 0xffff invalid value: in this case CE LEVEL will considered as not active
    };
    
typedef struct sdrLte_PucchBR_00 sdrLte_PucchBR_00;
typedef struct sdrLte_PucchBR_00 sdrLte_PucchBR;

struct sdrLte_SchedulingInfoBR_00
    {
        ushort SiNarrowband; // This field indicates the index of the narrowband used to broadcast the SI 
                             // message towards low complexity UEs and UEs supporting CE.
                             // INTEGER (1.. maxAvailNarrowBands) for each element
        ushort SiTbs;        // This field indicates the index of the transport block size used to broadcast the SI 
                             // message towards low complexity UEs and UEs supporting CE.
                             // ENUMERATED [b152, b208, b256, b328, b408, b504, b600, b712, b808, b936]
    };
typedef struct sdrLte_SchedulingInfoBR_00 sdrLte_SchedulingInfoBR_00;
typedef struct sdrLte_SchedulingInfoBR_00 sdrLte_SchedulingInfoBR;

struct sdrLte_PagingBR_00
    {
        uchar   PagingNarrowBands;           // Number of narrowbands used for paging
                                             // INTEGER (1.. maxAvailNarrowBands)
                                             // 0xff invalid value
        uchar   Spare;
        ushort  MpdcchNumRepetitionPaging;   // Maximum number of repetitions for M-PDCCH common search space (CSS) for paging, see TS 36.211
                                             // ENUMERATED {r1, r2, r4, r8, r16, r32, r64, r128, r256}
                                             // 0xff invalid value
    };
typedef struct sdrLte_PagingBR_00 sdrLte_PagingBR_00;
typedef struct sdrLte_PagingBR_00 sdrLte_PagingBR;

struct sdrLte_IntervalBR_00
    {
        ushort IntervalFddBR;                   // ENUMERATED ( see sdrLte_FreqHoppingBR_00 comments)
                                                // 0xffff invalid value
        ushort IntervalTddBR;                   // ENUMERATED ( see sdrLte_FreqHoppingBR_00 comments)
                                                // 0xffff invalid value
        
    };
typedef struct sdrLte_IntervalBR_00 sdrLte_IntervalBR_00;
typedef struct sdrLte_IntervalBR_00 sdrLte_IntervalBR;
    
struct sdrLte_FreqHoppingBR_00
    {
        uchar   MpdcchPdschHoppingNB;        // mpdcch-pdsch-HoppingNB 
                                             // ENUMERATED {nb2, nb4}
                                             // 0xff invalid value
                                             // The number of narrowbands for MPDCCH/PDSCH frequency hopping. 
                                             // Value nb2 corresponds to 2 narrowbands and value nb4 corresponds to 4 narrowbands.
        uchar   MpdcchPdschHoppingOffsetNB;  // mpdcch-pdsch-HoppingOffset
                                             // INTEGER (1..maxAvailNarrowBands that is equal to 16)
                                             // See TS 36.211 [21, 6.4.1].
        ushort  Spare;                      
        sdrLte_IntervalBR_00 IntervalDlHopComModeA; // interval-DLHoppingConfigCommonModeA-r13
                                                    // Number of consecutive absolute subframes over which MPDCCH or PDSCH for CE mode A 
                                                    // stays at the same narrowband before hopping to another narrowband. 
                                                    // For interval-FDD, int1 corresponds to 1 subframe, int2 corresponds to 2 subframes, and so on. 
                                                    // For interval-TDD, int1 corresponds to 1 subframe, int5 corresponds to 5 subframes, and so on.
                                                    // FDD ENUMERATED [int1, int2, int4, int8]
                                                    // TDD ENUMERATED [int1, int5, int10, int20]
                                                    // 0xffff invalid value
        sdrLte_IntervalBR_00 IntervalDlHopComModeB; // interval-DLHoppingConfigCommonModeB-r13
                                                    // Number of consecutive absolute subframes over which MPDCCH or PDSCH for CE mode B 
                                                    // stays at the same narrowband before hopping to another narrowband. 
                                                    // FDD ENUMERATED [int2, int4, int8, int16]
                                                    // TDD ENUMERATED [int5, int10, int20, int40]
                                                    // 0xffff invalid value
        sdrLte_IntervalBR_00 IntervalUlHopComModeA; // interval-ULHoppingConfigCommonModeA-r13
                                                    // Number of consecutive absolute subframes over which PUCCH or PUSCH for CE mode A 
                                                    // stays at the same narrowband before hopping to another narrowband. 
                                                    // For interval-FDD, int1 corresponds to 1 subframe, int2 corresponds to 2 subframes, and so on. 
                                                    // For interval-TDD, int1 corresponds to 1 subframe, int5 corresponds to 5 subframes, and so on.
                                                    // FDD ENUMERATED [int1, int2, int4, int8]
                                                    // TDD ENUMERATED [int1, int5, int10, int20]
                                                    // 0xffff invalid value
        sdrLte_IntervalBR_00 IntervalUlHopComModeB; // interval-ULHoppingConfigCommonModeB-r13
                                                    // Number of consecutive absolute subframes over which PUCCH or PUSCH for CE mode B 
                                                    // stays at the same narrowband before hopping to another narrowband. 
                                                    // FDD ENUMERATED [int2, int4, int8, int16]
                                                    // TDD ENUMERATED [int5, int10, int20, int40]
                                                    // 0xffff invalid value
    };
typedef struct sdrLte_FreqHoppingBR_00 sdrLte_FreqHoppingBR_00;
typedef struct sdrLte_FreqHoppingBR_00 sdrLte_FreqHoppingBR;

struct sdrLte_SibBR_00
    {
    ushort        WdwLength;        // si-WindowLength-BR-r13: Common SI scheduling window for all SIs.
                                    // ENUMERATED [ms20, ms40, ms60, ms80, ms120, ms160, ms200, spare]
                                    // ms20 -> 20 milliseconds; ms40 -> 40 milliseconds and so on
    ushort        RepetitionPattern; // si-RepetitionPattern : Indicates the radio frames within the SI window used for SI message transmission. 
                                     // Value everyRF corresponds to every radio frame, 
                                     // Value every2ndRF corresponds to every second radio frame, and so on.
    uint          FddDlOrTddSbfBitmapLC[2];   // fdd-DownlinkOrTddSubframeBitmapLC-r13: The set of valid subframes for FDD downlink 
                                              // or TDD transmissions, see TS 36.213
                                              // BIT STRING size (10) or BIT STRING size (40)
                                              // 0xffffffff if this field is not present
    ushort        FddUlSbfBitmapLC;           // fdd-UplinkSubframeBitmapLC-r13: The set of valid subframes for FDD uplink 
                                              // transmissions for BL UEs, see TS 36.213. 
                                              // If the field is not present, then all uplink subframes are considered 
                                              // as valid subframes for FDD uplink transmissions
                                              // BIT STRING size (10)
                                              // 0xffff if this field is not present
    uchar         StartSymbolLC;              // For BL and UEs in enhanced coverage, indicates the OFDM starting symbol 
                                              // for any MPDCCH, PDSCH scheduled  on the same cell except the PDSCH 
                                              // carrying SystemInformationBlockType1-BR, see TS 36.213.
                                              // INTEGER [1..4]
    uchar         HoppingConfigCommon;        // Frequency hopping activation/deactivation for BR versions of SI messages 
                                              // and MPDCCH of paging
                                              // ENUMERATED 0 -> on, 1 -> off
                                  
    };

struct sdrLte_SibBR_01
    {
    ushort        WdwLength;        // si-WindowLength-BR-r13: Common SI scheduling window for all SIs. Unit in milliseconds.
                                    // [20, 40, 60, 80, 160, 200]
    uchar         RepetitionPattern; // si-RepetitionPattern : Indicates the radio frames within the SI window used for SI message transmission. 
                                     // Value everyRF corresponds to every radio frame, 
                                     // Value every2ndRF corresponds to every second radio frame, and so on.
    uchar         SchedulingInfoBRSize;     // Range 1..maxSI-Message
                                            // This field gives the number of meaningful elements in the SchedulingInfoBRList vector 
    uint          FddDlOrTddSbfBitmapLC[2];   // fdd-DownlinkOrTddSubframeBitmapLC-r13: The set of valid subframes for FDD downlink 
                                              // or TDD transmissions, see TS 36.213
                                              // BIT STRING size (10) or BIT STRING size (40)
                                              // 0xffffffff if this field is not present
    ushort        FddUlSbfBitmapLC;           // fdd-UplinkSubframeBitmapLC-r13: The set of valid subframes for FDD uplink 
                                              // transmissions for BL UEs, see TS 36.213. 
                                              // If the field is not present, then all uplink subframes are considered 
                                              // as valid subframes for FDD uplink transmissions
                                              // BIT STRING size (10)
                                              // 0xffff if this field is not present
    uchar         StartSymbolLC;              // For BL and UEs in enhanced coverage, indicates the OFDM starting symbol 
                                              // for any MPDCCH, PDSCH scheduled  on the same cell except the PDSCH 
                                              // carrying SystemInformationBlockType1-BR, see TS 36.213.
                                              // INTEGER [1..4]
    uchar         HoppingConfigCommon;        // Frequency hopping activation/deactivation for BR versions of SI messages 
                                              // and MPDCCH of paging
                                              // ENUMERATED 0 -> on, 1 -> off                                 
    sdrLte_SchedulingInfoBR_00 SchedulingInfoBRList[sdrLteMAXSI_MESSAGE_v0]; // List of SchedulingInfo-BR-r13
    };

typedef struct sdrLte_SibBR_00 sdrLte_SibBR_00;
typedef struct sdrLte_SibBR_01 sdrLte_SibBR_01;
typedef struct sdrLte_SibBR_01 sdrLte_SibBR;

struct sdrLte_SibDataBR_00
{
    sdrLte_PrachBR_00  PrachBRInfo;    // PRACH configuration Common for UEs in CE

    sdrLte_PdschBR_00  PdschInfoBR;    // PDSCH configuration Common for UEs in CE

    sdrLte_PuschBR_00  PuschInfoBR;    // PUSCH configuration Common for UEs in CE

    sdrLte_PucchBR_00  PucchInfoBR;    // PUCCH configuration Common for UEs in CE

    sdrLte_SibBR_00 SibBRInfo;         // SIB-BR Scheduling information

};

struct sdrLte_SibDataBR_01
{
    sdrLte_PrachBR_00  PrachBRInfo;    // PRACH configuration Common for UEs in CE

    sdrLte_PdschBR_00  PdschInfoBR;    // PDSCH configuration Common for UEs in CE

    sdrLte_PuschBR_00  PuschInfoBR;    // PUSCH configuration Common for UEs in CE

    sdrLte_PucchBR_00  PucchInfoBR;    // PUCCH configuration Common for UEs in CE

    sdrLte_SibBR_00 SibBRInfo;         // SIB-BR Scheduling information

    uint            MpdcchNumRepetitionPaging; // Maximum number of repetitions for M-PDCCH common search space (CSS) for paging, see TS 36.211
                                               // ENUMERATED {r1, r2, r4, r8, r16, r32, r64, r128, r256}
};

struct sdrLte_SibDataBR_02
{
    sdrLte_PrachBR_00  PrachBRInfo;    // PRACH configuration Common for UEs in CE

    sdrLte_PdschBR_00  PdschInfoBR;    // PDSCH configuration Common for UEs in CE

    sdrLte_PuschBR_01  PuschInfoBR;    // PUSCH configuration Common for UEs in CE

    sdrLte_PucchBR_00  PucchInfoBR;    // PUCCH configuration Common for UEs in CE

    sdrLte_SibBR_01    SibBRInfo;      // SIB-BR Scheduling information

    uint              MpdcchNumRepetitionPaging; // Maximum number of repetitions for M-PDCCH common search space (CSS) for paging, see TS 36.211
                                                 // ENUMERATED {r1, r2, r4, r8, r16, r32, r64, r128, r256}
};

struct sdrLte_SibDataBR_03
{
    sdrLte_PrachBR_00  PrachBRInfo;    // PRACH configuration Common for UEs in CE

    sdrLte_PdschBR_00  PdschInfoBR;    // PDSCH configuration Common for UEs in CE

    sdrLte_PuschBR_01  PuschInfoBR;    // PUSCH configuration Common for UEs in CE

    sdrLte_PucchBR_00  PucchInfoBR;    // PUCCH configuration Common for UEs in CE

    sdrLte_SibBR_01    SibBRInfo;      // SIB-BR Scheduling information

    sdrLte_PagingBR_00 PagingInfoBR;   // Paging in CE
};

struct sdrLte_SibDataBR_04
{
    sdrLte_PrachBR_00  PrachBRInfo;    // PRACH configuration Common for UEs in CE

    sdrLte_PdschBR_00  PdschInfoBR;    // PDSCH configuration Common for UEs in CE

    sdrLte_PuschBR_01  PuschInfoBR;    // PUSCH configuration Common for UEs in CE

    sdrLte_PucchBR_00  PucchInfoBR;    // PUCCH configuration Common for UEs in CE

    sdrLte_SibBR_01    SibBRInfo;      // SIB-BR Scheduling information

    sdrLte_PagingBR_00 PagingInfoBR;   // Paging in CE
    
    sdrLte_FreqHoppingBR_00   FreqHopInfoBR;     // Freq Hopping Parameters for UEs in CE
};

typedef struct sdrLte_SibDataBR_00 sdrLte_SibDataBR_00; 
typedef struct sdrLte_SibDataBR_01 sdrLte_SibDataBR_01; 
typedef struct sdrLte_SibDataBR_02 sdrLte_SibDataBR_02; 
typedef struct sdrLte_SibDataBR_03 sdrLte_SibDataBR_03; 
typedef struct sdrLte_SibDataBR_04 sdrLte_SibDataBR_04; 
typedef struct sdrLte_SibDataBR_04 sdrLte_SibDataBR;

//**********************************************
// NARROWBAND-IoT
//**********************************************

struct sdrLte_Prach_ParametersNB_00
{
    uchar   NprachPeriodicity;    // Periodicity of a NPRACH resource
                                  // ENUMERATED [ms40, ms80, ms160, ms240, ms320, ms640, ms1280, ms2560]
                                  // 0xff invalid value
    uchar   NprachStartTime;      // Start time of the NPRACH resource in one period
                                  // ENUMERATED {ms8, ms16, ms32, ms64, ms128, ms256, ms512, ms1024},
                                  // 0xff invalid value
    uchar   NprachSubcarrierOffset; // Frequency location of the NPRACH resource. In number of subcarriers, offset from sub-carrier 0           
                                    // ENUMERATED [n0, n12, n24, n36, n2, n18, n34, spare1]
                                    // 0xff invalid value
    uchar   NprachNumSubcarriers;   // Number of sub-carriers in a NPRACH resource
                                    // ENUMERATED [n12, n24, n36, n48]
                                   // 0xff invalid value
    uchar   NprachSubcarrierMSG3RangeStart;  // Fraction for calculating the starting subcarrier index of the range reserved for indication of UE support for multi-tone Msg3 transmission, 
                                            // within the NPRACH resource
                                            // ENUMERATED [zero, oneThird, twoThird, one]
                                            // 0xff invalid value                                           
    uchar   MaxNumPreambleAttemptCE;    // Maximum number of preamble transmission attempts per NPRACH resource. See TS 36.321       
                                        // ENUMERATED [n3, n4, n5, n6, n7, n8, n10, spare1]
                                        // 0xff invalid value
    uchar   NumRepetitionsPerPreambleAttempt;// Number of NPRACH repetitions per attempt for each NPRACH resource, See TS 36.211    
                                            // ENUMERATED [n1, n2, n4, n8, n16, n32, n64, n128]
                                            // 0xff invalid value
    uchar   NpdcchNumRepetitionsRA;         // Maximum number of repetitions for NPDCCH common search space (CSS) for RAR, Msg3 retransmission and Msg4, see TS 36.211 
                                            // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128, r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]   
                                            // 0xff invalid value
    ushort   NpdcchStartSfRA;               // Starting subframe configuration for NPDCCH common search space (CSS), including RAR, Msg3 retransmission, and Msg4, see TS 36.211 and TS 36.213.
                                            // ENUMERATED [v1dot5, v2, v4, v8, v16, v32, v48, v64]
                                            // 0xffff invalid value
    ushort   NpdcchOffsetRA;                // Fractional period offset of starting subframe for NPDCCH common search space (CSS Type 2, see TS 36.211 and TS 36.213.
                                            // ENUMERATED [zero, oneEighth, oneFourth, threeEighth]
                                            // 0xffff invalid value
    };
    
struct sdrLte_Prach_ParametersNB_01
{
    uchar   NprachPeriodicity;    // Periodicity of a NPRACH resource
                                  // ENUMERATED [ms40, ms80, ms160, ms240, ms320, ms640, ms1280, ms2560]
                                  // 0xff invalid value
    uchar   NprachStartTime;      // Start time of the NPRACH resource in one period
                                  // ENUMERATED {ms8, ms16, ms32, ms64, ms128, ms256, ms512, ms1024},
                                  // 0xff invalid value
    uchar   NprachSubcarrierOffset; // Frequency location of the NPRACH resource. In number of subcarriers, offset from sub-carrier 0           
                                    // ENUMERATED [n0, n12, n24, n36, n2, n18, n34, spare1]
                                    // 0xff invalid value
    uchar   NprachNumSubcarriers;   // Number of sub-carriers in a NPRACH resource
                                    // ENUMERATED [n12, n24, n36, n48]
                                   // 0xff invalid value
    uchar   NprachSubcarrierMSG3RangeStart;  // Fraction for calculating the starting subcarrier index of the range reserved for indication of UE support for multi-tone Msg3 transmission, 
                                            // within the NPRACH resource
                                            // ENUMERATED [zero, oneThird, twoThird, one]
                                            // 0xff invalid value                                           
    uchar   MaxNumPreambleAttemptCE;    // Maximum number of preamble transmission attempts per NPRACH resource. See TS 36.321       
                                        // ENUMERATED [n3, n4, n5, n6, n7, n8, n10, spare1]
                                        // 0xff invalid value
    uchar   NumRepetitionsPerPreambleAttempt;// Number of NPRACH repetitions per attempt for each NPRACH resource, See TS 36.211    
                                            // ENUMERATED [n1, n2, n4, n8, n16, n32, n64, n128]
                                            // 0xff invalid value
    uchar   NpdcchNumRepetitionsRA;         // Maximum number of repetitions for NPDCCH common search space (CSS) for RAR, Msg3 retransmission and Msg4, see TS 36.211 
                                            // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128, r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]   
                                            // 0xff invalid value
    ushort   NpdcchStartSfRA;               // Starting subframe configuration for NPDCCH common search space (CSS), including RAR, Msg3 retransmission, and Msg4, see TS 36.211 and TS 36.213.
                                            // ENUMERATED [v1dot5, v2, v4, v8, v16, v32, v48, v64]
                                            // 0xffff invalid value
    uchar    NpdcchOffsetRA;                // Fractional period offset of starting subframe for NPDCCH common search space (CSS Type 2, see TS 36.211 and TS 36.213.
                                            // ENUMERATED [zero, oneEighth, oneFourth, threeEighth]
                                            // 0xffff invalid value
    uchar   NprachNumCBRAStartSubcarriers;  // The number of start subcarriers from which a UE can randomly select a start subcarrier as specified in TS 36.321 [6].
                                            // ENUMERATED {n8, n10, n11, n12, n20, n22, n23, n24, n32, n34, n35, n36, n40, n44, n46, n48}
                                            // 0xff invalid value
    };
    
typedef struct sdrLte_Prach_ParametersNB_00 sdrLte_Prach_ParametersNB_00;   
typedef struct sdrLte_Prach_ParametersNB_01 sdrLte_Prach_ParametersNB_01;   
typedef struct sdrLte_Prach_ParametersNB_01 sdrLte_Prach_ParametersNB;

struct sdrLte_PrachNB_00
{
    int         RsrpThrInfo[2];    // The criterion for UEs to select a NPRACH resource. 
                                   // Up to 2 RSRP threshold values can be signalled. See TS 36.213 [23]. 
                                   // The first element corresponds to RSRP threshold 1, the second element corresponds to RSRP threshold 2. See TS 36.321 [6].
                                   //  If absent, there is only one NPRACH resource. 
    ushort      NprachCPLen;       // Cyclic prefix length for NPRACH transmisision, see TS 36.211 [21, 5.2.1]. 
                                   // ENUMERATED [ 0 -> us66dot7, 1 -> us266dot7],
                                   // Value us66dot7 corresponds to 66.7 microseconds and value us266dot7 corresponds to 266.7 microseconds.
                                   // 0xffff invalid value
    ushort       NumNprachRes;      // This field gives the number of meaningful elements in the sdrLte_Prach_ParametersNB_00 vector
    sdrLte_Prach_ParametersNB_00   Nprach_Parameters[sdrLteMAXNPRACH_RES_v0]; // Configures PRACH parameters 
    };

struct sdrLte_PrachNB_01
{
    int         RsrpThrInfo[2];    // The criterion for UEs to select a NPRACH resource. 
                                   // Up to 2 RSRP threshold values can be signalled. See TS 36.213 [23]. 
                                   // The first element corresponds to RSRP threshold 1, the second element corresponds to RSRP threshold 2. See TS 36.321 [6].
                                   //  If absent, there is only one NPRACH resource. 
    ushort      NprachCPLen;       // Cyclic prefix length for NPRACH transmisision, see TS 36.211 [21, 5.2.1]. 
                                   // ENUMERATED [ 0 -> us66dot7, 1 -> us266dot7],
                                   // Value us66dot7 corresponds to 66.7 microseconds and value us266dot7 corresponds to 266.7 microseconds.
                                   // 0xffff invalid value
    ushort       NumNprachRes;      // This field gives the number of meaningful elements in the Prach_ParametersCE vector
    sdrLte_Prach_ParametersNB_01   Nprach_Parameters[sdrLteMAXNPRACH_RES_v0]; // Configures PRACH parameters for each enhanced coverage level
    };
    
struct sdrLte_PrachNB_02
{
    int         RsrpThrInfo[2];    // The criterion for UEs to select a NPRACH resource. 
                                   // Up to 2 RSRP threshold values can be signalled. See TS 36.213 [23]. 
                                   // The first element corresponds to RSRP threshold 1, the second element corresponds to RSRP threshold 2. See TS 36.321 [6].
                                   //  If absent, there is only one NPRACH resource. 
    ushort      NprachCPLen;       // Cyclic prefix length for NPRACH transmisision, see TS 36.211 [21, 5.2.1]. 
                                   // ENUMERATED [ 0 -> us66dot7, 1 -> us266dot7],
                                   // Value us66dot7 corresponds to 66.7 microseconds and value us266dot7 corresponds to 266.7 microseconds.
                                   // 0xffff invalid value
    uchar       InitRxTargetPw;    // Preamble initial received target power. It is necessary in NB Standalone cell
                                   // ENUM [dBm-130, dBm-128, dBm-126, dBm-124, dBm-122, dBm-88, dBm-86, dBm-84,dBm-82, dBm-80]
    uchar       NumNprachRes;      // This field gives the number of meaningful elements in the Prach_ParametersCE vector
    sdrLte_Prach_ParametersNB_01   Nprach_Parameters[sdrLteMAXNPRACH_RES_v0]; // Configures PRACH parameters for each enhanced coverage level
    };
    
typedef struct sdrLte_PrachNB_00 sdrLte_PrachNB_00; 
typedef struct sdrLte_PrachNB_01 sdrLte_PrachNB_01; 
typedef struct sdrLte_PrachNB_02 sdrLte_PrachNB_02; 
typedef struct sdrLte_PrachNB_02 sdrLte_PrachNB;

struct sdrLte_PdschNB_00
{
        int NrsPower;  // Provides the downlink narrowband reference-signal EPRE, see TS 36.213.The actual value in dBm
                       // Range INTEGER (-60..50)
    } ;
    
typedef struct sdrLte_PdschNB_00 sdrLte_PdschNB_00;
typedef struct sdrLte_PdschNB_00 sdrLte_PdschNB;


struct sdrLte_NpuschDmrsConfigNB_00
{
    uchar ThreeToneBaseSequence;            // The base sequence of DMRS sequence in a cell for 3 tones  transmission; see TS 36.211
                                            // If absent, it is given by NB-IoT CellID mod 12. 
                                            // Range INTEGER (0..12) ; 0xff invalid value
    uchar ThreeToneCyclicShift;             // Define 3 cyclic shifts for the 3-tone case, see TS 36.211
                                            // Range INTEGER (0..2) ; 0xff invalid value
    uchar SixToneBaseSequence;              // The base sequence of DMRS sequence in a cell for 6 tones transmission; see TS 36.211
                                            // If absent, it is given by NB-IoT CellID mod 14. 
                                            // Range INTEGER (0..14); 0xff invalid value
    uchar SixToneCyclicShift;               // Define 4 cyclic shifts for the 6-tone case, see TS 36.211 
                                            // Range INTEGER (0..3) ; 0xff invalid value
    ushort  TwelveToneBaseSequence;         // The base sequence of DMRS sequence in a cell for 12 tones  transmission; see TS 36.211
                                            // If absent, it is given by NB-IoT CellID mod 30. 
                                            // Range INTEGER (0..30); 0xffff invalid value
    ushort  Spare;
    };
typedef struct sdrLte_NpuschDmrsConfigNB_00 sdrLte_NpuschDmrsConfigNB_00;
typedef struct sdrLte_NpuschDmrsConfigNB_00 sdrLte_NpuschDmrsConfigNB;

struct sdrLte_NpuschUlRefSigNB_00
{
    uchar  GroupHoppingEnabled;                 // Disable-sequence-group-hopping, see TS 36.211 [5.5.1.3].
                                                // 0,1
    uchar  Spare;
    ushort GroupAssignmentNPUSCH;               // See TS 36.211 [21, 5.5.1.3].
                                                // Range INTEGER (0..29)
    };
typedef struct sdrLte_NpuschUlRefSigNB_00 sdrLte_NpuschUlRefSigNB_00;
typedef struct sdrLte_NpuschUlRefSigNB_00 sdrLte_NpuschUlRefSigNB;
    
struct sdrLte_PuschNB_00
{
    uchar   NumAckNackRepMsg4;      // This field gives the number of meaningful elements in the AckNackNumRepMsg4 vector
    uchar   AckNackNumRepMsg4[sdrLteMAXNPRACH_RES_v0]; // Number of repetitions for ACK/NACK HARQ response to NPDSCH containing Msg4 per NPRACH resource.  
                                                       // see TS 36.211 and TS 36.213.
                                                       // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128]
                                                       // 0xff invalid value
    uint    SrsSubframeConfig;  // SRS SubframeConfiguration. See TS 36.211 [table 5.5.3.3-1]. 
                                // ENUMERATED [sc0, sc1, sc2, sc3, sc4, sc5, sc6, sc7, sc8, sc9, sc10, sc11, sc12, sc13, sc14, sc15]    
                                // 0xffff invalid value

    sdrLte_NpuschDmrsConfigNB_00 DmsrConf;
    sdrLte_NpuschUlRefSigNB_00   UlRefSigNpusch; // Used to specify parameters needed for the transmission on NPUSCH
    } ;
    
typedef struct sdrLte_PuschNB_00 sdrLte_PuschNB_00;
typedef struct sdrLte_PuschNB_00 sdrLte_PuschNB;

struct sdrLte_UplinkPowerControlNB_00
{
    short   P0NominalNPUSCH;     // See TS 36.213 [5.1.1.1], unit dBm. This field is applicable for non-persistent scheduling only. 
                                 // INTEGER (-126..24),
                                 // See TS 36.213 [23, 5.1.1.1] where al0 corresponds to 0, al04 corresponds to value 0.4, 
                                 // al05 to 0.5, al06 to 0.6, al07 to 0.7, al08 to 0.8, al09 to 0.9 and al1 corresponds to 1
    uchar   Alpha;               // ENUMERATED [al0, al04, al05, al06, al07, al08, al09, al1]; 0xff invalid value
    char    DeltaPreambleMsg3;   // DeltaPreambleMsg3, see TS 36.213 [5.1.1.1]. Actual value = IE value * 2 [dB].
                                 // Range INTEGER (-1..6);
    };
    
typedef struct sdrLte_UplinkPowerControlNB_00 sdrLte_UplinkPowerControlNB_00;
typedef struct sdrLte_UplinkPowerControlNB_00 sdrLte_UplinkPowerControlNB;
    
struct sdrLte_SchedulingInfoNB_00
{
    uchar SiPeriodicity;  // si-Periodicity-r13: Periodicity of the SI-message in radio frames, such that rf256 denotes 256 radio frames, 
                          // rf512 denotes 512 radio frames, and so on.
                          // ENUMERATED [rf64, rf128, rf256, rf512, rf1024, rf2048, rf4096, spare]
    uchar SiRepetitionPattern; // si-RepetitionPattern-r13: Indicates the starting radio frames within the SI window used for SI message transmission. 
                             // Value every2ndRF corresponds to every second radio frame, value every4thRF corresponds to every fourth radio frame 
                             // and so on starting from the first radio frame of the SI window used for SI transmission.
                             // ENUMERATED {every2ndRF, every4thRF,  every8thRF,  every16thRF]
    ushort SiTbs;            // This field indicates the index of the transport block size used to broadcast the SI 
                             // message towards NB-IoT UEs.
                             // ENUMERATED [b56, b120, b208, b256, b328, b440, b552, b680]
    };
typedef struct sdrLte_SchedulingInfoNB_00 sdrLte_SchedulingInfoNB_00;
typedef struct sdrLte_SchedulingInfoNB_00 sdrLte_SchedulingInfoNB;

struct sdrLte_SibNB_00
{
    uint    DownlinkBitmap[2];   // it is used to specify the set of NB-IoT downlink subframes for downlink transmission
                                 // BIT STRING size (10) or BIT STRING size (40)
                                 // 0xffffffff if this field is not present
    uchar   WdwLength;           // si-WindowLength-r13: Common SI scheduling window for all SIs. Unit in milliseconds.
                                 // ENUMERATED [ms160,  ms320,  ms480,  ms640, ms960,   ms1280, ms1600, spare1]
    uchar   RadioFrameOffset;    // si-RadioFrameOffset-r13: Offset in number of radio frames to calculate the start of the SI window.
                                 // If the field is absent, no offset is applied.
                                 // Range INTEGER (1..15); 0xff invalid value
    ushort  SchedulingInfoNBSize;     // Range 1..maxSI-Message-NB
                                      // This field gives the number of meaningful elements in the SchedulingInfoNBList vector
    sdrLte_SchedulingInfoNB_00 SchedulingInfoNBList[sdrLteMAXSI_MESSAGE_NB_v0]; // List of SchedulingInfo-NB-r13
    };

struct sdrLte_SibNB_01
{
    uint    DownlinkBitmap[2];   // it is used to specify the set of NB-IoT downlink subframes for downlink transmission
                                 // BIT STRING size (10) or BIT STRING size (40)
                                 // 0xffffffff if this field is not present
    uchar   EutraCtrlSize;       // EutraControlRegionSize-r13: Indicates the control region size of the E-UTRA cell for the in-band
                                 // operation mode, see TS 36.213. Unit is in number of OFDM symbols.
                                 // Range INTEGER (1..3); 0xff invalid value
    uchar   WdwLength;           // si-WindowLength-r13: Common SI scheduling window for all SIs. Unit in milliseconds.
                                 // ENUMERATED [ms160,  ms320,  ms480,  ms640, ms960,   ms1280, ms1600, spare1]
    uchar   RadioFrameOffset;    // si-RadioFrameOffset-r13: Offset in number of radio frames to calculate the start of the SI window.
                                 // If the field is absent, no offset is applied.
                                 // Range INTEGER (1..15); 0xff invalid value
    uchar   HyperSFN_MSB;        // hyperSFN-MSB-r13: Indicates the 8 most significant bits of hyper-SFN.
                                 // Together with hyperSFN-LSB in MIB-NB, the complete hyper-SFN is built up.
                                 // hyper-SFN is incremented by one when the SFN wraps around.
    ushort  Spare;

    ushort  SchedulingInfoNBSize;     // Range 1..maxSI-Message-NB
                                      // This field gives the number of meaningful elements in the SchedulingInfoNBList vector 
    sdrLte_SchedulingInfoNB_00 SchedulingInfoNBList[sdrLteMAXSI_MESSAGE_NB_v0]; // List of SchedulingInfo-NB-r13
};

typedef struct sdrLte_SibNB_00 sdrLte_SibNB_00;
typedef struct sdrLte_SibNB_01 sdrLte_SibNB_01;
typedef struct sdrLte_SibNB_01 sdrLte_SibNB;

/* PCCH-Config-NB */
/* Configure the PCCH parameters for the non-anchor DL carrier.*/
struct sdrLte_DLNonAnchorPdcchConfigCommonNB_00
{
    uchar            NpdcchNumRepetitionPaging;  // Maximum number of repetitions for NPDCCH common search space (CSS) for paging, see TS 36.211.
                                                // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128,  r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]
                                                // Default value is 0xFFFF
                                                // If the field is absent (0xFFFF), the value of npdcch-NumRepetitionPaging configured in 
                                                // SystemInformationBlockType2-NB in IE pcch-Config applies.
    uchar            PagingWeight;              // Weight of the non-anchor paging carrier for uneven paging load distribution across the carriers. 
                                                // w1 corresponds to a relative weight of 1
                                                // ENUMERATED {w1, w2, w3, w4, w5, w6, w7, w8,
                                                // w9, w10, w11, w12, w13, w14, w15, w16}
                                                // Default value is w1
    uchar            Spare[2];

};
typedef struct sdrLte_DLNonAnchorPdcchConfigCommonNB_00 sdrLte_DLNonAnchorPdcchConfigCommonNB_00;
typedef struct sdrLte_DLNonAnchorPdcchConfigCommonNB_00 sdrLte_DLNonAnchorPdcchConfigCommonNB;

/* DL-ConfigCommon-NB */

struct sdrLte_DLNonAnchorCarrierConfigCommonNB_00
{
    sdrLte_CarrierFreqNB_00       DlCarrierFreq;     // DL carrier frequency. The downlink carrier is not in a E-UTRA PRB which contains E-UTRA PSS/SSS/PBCH
    sdrLte_DlBitmapNonAnchorNB_00 DlBitmapNonAnchor; // NB-IoT downlink subframe configuration for downlink transmission on the non-anchor carrier.     
    sdrLte_DlGapNonAnchorNB_00    DlGapNonAnchor;    // Downlink transmission gap configuration for the non-anchor carrier, see TS 36.211  [21] and TS 36.213 [23]. 
    sdrLte_InbandCarrierInfoNB_01 InbandCarrierInfo; // Provides the configuration of a non-anchor inband carrier.
                                                     // If absent, the configuration of the anchor carrier applies.
    uint   NrsPowerOffsetNonAnchor;                  // Provides the downlink narrowband reference-signal EPRE offset of the non-anchor carrier relative 
                                                     // to the downlink narrowband reference-signal EPRE of the anchor carrier, 
                                                     // unit in dB. 
                                                     // ENUMERATED {dB-12, dB-10, dB-8, dB-6, dB-4, dB-2, dB0, dB3}
                                                     // Value dB-12 corresponds to -12 dB, dB-10 corresponds to -10 dB and so on. See TS 36.213 [23, 16.2.2].
};

struct sdrLte_DLNonAnchorCarrierConfigCommonNB_01
{
    sdrLte_CarrierFreqNB_01       DlCarrierFreq;     // DL carrier frequency. The downlink carrier is not in a E-UTRA PRB which contains E-UTRA PSS/SSS/PBCH
    sdrLte_DlBitmapNonAnchorNB_01 DlBitmapNonAnchor; // NB-IoT downlink subframe configuration for downlink transmission on the non-anchor carrier.     
    sdrLte_DlGapNonAnchorNB_01    DlGapNonAnchor;    // Downlink transmission gap configuration for the non-anchor carrier, see TS 36.211  [21] and TS 36.213 [23]. 
    sdrLte_InbandCarrierInfoNB_01 InbandCarrierInfo; // Provides the configuration of a non-anchor inband carrier.
                                                     // If absent, the configuration of the anchor carrier applies.
    uint   NrsPowerOffsetNonAnchor;                  // Provides the downlink narrowband reference-signal EPRE offset of the non-anchor carrier relative 
                                                     // to the downlink narrowband reference-signal EPRE of the anchor carrier, 
                                                     // unit in dB. 
                                                     // ENUMERATED {dB-12, dB-10, dB-8, dB-6, dB-4, dB-2, dB0, dB3}
                                                     // Value dB-12 corresponds to -12 dB, dB-10 corresponds to -10 dB and so on. See TS 36.213 [23, 16.2.2].
};
typedef struct sdrLte_DLNonAnchorCarrierConfigCommonNB_00 sdrLte_DLNonAnchorCarrierConfigCommonNB_00;
typedef struct sdrLte_DLNonAnchorCarrierConfigCommonNB_01 sdrLte_DLNonAnchorCarrierConfigCommonNB_01;
typedef struct sdrLte_DLNonAnchorCarrierConfigCommonNB_01 sdrLte_DLNonAnchorCarrierConfigCommonNB;


/* DL-ConfigCommon-NB */
struct sdrLte_DLNonAnchorConfigCommonNB_00
{
    sdrLte_DLNonAnchorCarrierConfigCommonNB_00 DlCarrierConfig; 
    uint   validPdcchConfig;                                //  This flag defines the validity of PdcchConfig structure
                                                            //  0 -> notValid
                                                            //  1 -> Valid
    sdrLte_DLNonAnchorPdcchConfigCommonNB_00   PdcchConfig; //  This field is optionally present,  
                                                            //  if the field dl-ConfigList is present and at least one of the carriers in dl-ConfigList 
                                                            //  is configured for paging (validPdcchConfig=1). Otherwise the field is not present and 
                                                            //  only the anchor carrier is used for paging (validPdcchConfig=0).

};

struct sdrLte_DLNonAnchorConfigCommonNB_01
{
    sdrLte_DLNonAnchorCarrierConfigCommonNB_01 DlCarrierConfig; 
    uint   validPdcchConfig;                                //  This flag defines the validity of PdcchConfig structure
                                                            //  0 -> notValid
                                                            //  1 -> Valid
    sdrLte_DLNonAnchorPdcchConfigCommonNB_00   PdcchConfig; //  This field is optionally present,  
                                                            //  if the field dl-ConfigList is present and at least one of the carriers in dl-ConfigList 
                                                            //  is configured for paging (validPdcchConfig=1). Otherwise the field is not present and 
                                                            //  only the anchor carrier is used for paging (validPdcchConfig=0).

};

typedef struct sdrLte_DLNonAnchorConfigCommonNB_00 sdrLte_DLNonAnchorConfigCommonNB_00;
typedef struct sdrLte_DLNonAnchorConfigCommonNB_01 sdrLte_DLNonAnchorConfigCommonNB_01;
typedef struct sdrLte_DLNonAnchorConfigCommonNB_01 sdrLte_DLNonAnchorConfigCommonNB;

struct sdrLte_Prach_NonAnchorParametersNB_00
{
    uchar   NprachPeriodicity;    // Periodicity of a NPRACH resource
                                  // ENUMERATED [ms40, ms80, ms160, ms240, ms320, ms640, ms1280, ms2560]
                                  // 0xff invalid value
    uchar   NprachStartTime;      // Start time of the NPRACH resource in one period
                                  // ENUMERATED {ms8, ms16, ms32, ms64, ms128, ms256, ms512, ms1024},
                                  // 0xff invalid value
    uchar   NprachSubcarrierOffset; // Frequency location of the NPRACH resource. In number of subcarriers, offset from sub-carrier 0           
                                    // ENUMERATED [n0, n12, n24, n36, n2, n18, n34, spare1]
                                    // 0xff invalid value
    uchar   NprachNumSubcarriers;   // Number of sub-carriers in a NPRACH resource
                                    // ENUMERATED [n12, n24, n36, n48]
                                   // 0xff invalid value
    uchar   NprachSubcarrierMSG3RangeStart;  // Fraction for calculating the starting subcarrier index of the range reserved for indication of UE support for multi-tone Msg3 transmission, 
                                            // within the NPRACH resource
                                            // ENUMERATED [zero, oneThird, twoThird, one]
                                            // 0xff invalid value                                           
    uchar   NpdcchNumRepetitionsRA;         // Maximum number of repetitions for NPDCCH common search space (CSS) for RAR, Msg3 retransmission and Msg4, see TS 36.211 
                                            // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128, r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]   
                                            // 0xff invalid value
    uchar   NpdcchStartSfRA;                // Starting subframe configuration for NPDCCH common search space (CSS), including RAR, Msg3 retransmission, and Msg4, see TS 36.211 and TS 36.213.
                                            // ENUMERATED [v1dot5, v2, v4, v8, v16, v32, v48, v64]
                                            // 0xff invalid value
    uchar   NpdcchOffsetRA;                 // Fractional period offset of starting subframe for NPDCCH common search space (CSS Type 2, see TS 36.211 and TS 36.213.
                                            // ENUMERATED [zero, oneEighth, oneFourth, threeEighth]
                                            // 0xff invalid value
    uchar   NprachNumCBRAStartSubcarriers;  // The number of start subcarriers from which a UE can randomly select a start subcarrier as specified in TS 36.321 [6].
                                            // ENUMERATED {n8, n10, n11, n12, n20, n22, n23, n24, n32, n34, n35, n36, n40, n44, n46, n48}
                                            // 0xff invalid value
    uchar   NpdcchCarrierIndex;             // Index of the carrier in the list of DL non anchor carriers. The first entry in the list has index ‘1’, 
                                            // the second entry has index ‘2’ and so on.
                                            // If the field is absent, the DL anchor carrier is used.
                                            // RANGE: 1..sdrLteMAX_NONANCHORCARRIERS_NB_v0
                                            // 0xff invalid value
    uchar   Spare[2];
    };
    
typedef struct sdrLte_Prach_NonAnchorParametersNB_00 sdrLte_Prach_NonAnchorParametersNB_00;
typedef struct sdrLte_Prach_NonAnchorParametersNB_00 sdrLte_Prach_NonAnchorParametersNB;

/* UL-ConfigCommon-NB */
struct sdrLte_ULNonAnchorConfigCommonNB_00
{
    sdrLte_CarrierFreqNB_00       UlCarrierFreq;     // UL carrier frequency. 
    uint                          NumNprachRes;      // This field gives the number of meaningful elements in the sdrLte_Prach_NonAnchorParametersNB vector
    sdrLte_Prach_NonAnchorParametersNB_00  Nprach_Parameters[sdrLteMAXNPRACH_RES_v0]; // Configures PRACH parameters  for nonAnchorCarrier
                                                                                      // This field is mandatory present, if the field ul-ConfigList is present 
                                                                                      // and at least one of the carriers in ul-ConfigList is configured 
                                                                                      // for random access (NumNprachRes>0). Otherwise the field is not present and 
                                                                                      // only the anchor carrier is used for random access (NumNprachRes=0) 
};

struct sdrLte_ULNonAnchorConfigCommonNB_01
{
    sdrLte_CarrierFreqNB_01       UlCarrierFreq;     // UL carrier frequency. 
    uint                          NumNprachRes;      // This field gives the number of meaningful elements in the sdrLte_Prach_NonAnchorParametersNB vector
    sdrLte_Prach_NonAnchorParametersNB_00  Nprach_Parameters[sdrLteMAXNPRACH_RES_v0]; // Configures PRACH parameters  for nonAnchorCarrier
                                                                                      // This field is mandatory present, if the field ul-ConfigList is present 
                                                                                      // and at least one of the carriers in ul-ConfigList is configured 
                                                                                      // for random access (NumNprachRes>0). Otherwise the field is not present and 
                                                                                      // only the anchor carrier is used for random access (NumNprachRes=0) 
};
typedef struct sdrLte_ULNonAnchorConfigCommonNB_00 sdrLte_ULNonAnchorConfigCommonNB_00;
typedef struct sdrLte_ULNonAnchorConfigCommonNB_01 sdrLte_ULNonAnchorConfigCommonNB_01;
typedef struct sdrLte_ULNonAnchorConfigCommonNB_01 sdrLte_ULNonAnchorConfigCommonNB;

struct sdrLte_SibDataNB_00
{
    sdrLte_PrachNB_00  PrachInfoNB;      // NPRACH-ConfigSIB-NB : PRACH configuration Common for NB-IoT UEs

    sdrLte_PdschNB_00  PdschInfoNB;      // NPDSCH-ConfigCommon-NB: NPDSCH configuration Common for NB-IoT UEs

    sdrLte_PuschNB_00  PuschInfoNB;      // PUSCH configuration Common for UEs in CE

    sdrLte_DlGapConfigNB_00 DlGapInfoNB; // DL-GapConfig-NB: it is used to specify the downlink gap configuration for NPDCCH and NPDSCH
    
    sdrLte_UplinkPowerControlNB_00  UpPwrCtrNB; // UplinkPowerControl-NB: it is used to specify parameters for uplink power control in the 
                                                // system information for NB-IoT UEs
    
    sdrLte_SibNB_00    SibInfoNB;      // SIB-NB Scheduling information
    
    uint            NpdcchNumRepetitionPaging;  // Maximum number of repetitions for NPDCCH common search space (CSS) for paging, see TS 36.211.
                                                // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128,  r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]
};

struct sdrLte_SibDataNB_01
{
    sdrLte_PrachNB_00  PrachInfoNB;      // NPRACH-ConfigSIB-NB : PRACH configuration Common for NB-IoT UEs

    sdrLte_PdschNB_00  PdschInfoNB;      // NPDSCH-ConfigCommon-NB: NPDSCH configuration Common for NB-IoT UEs

    sdrLte_PuschNB_00  PuschInfoNB;      // PUSCH configuration Common for UEs in CE

    sdrLte_DlGapConfigNB_00 DlGapInfoNB; // DL-GapConfig-NB: it is used to specify the downlink gap configuration for NPDCCH and NPDSCH

    sdrLte_UplinkPowerControlNB_00  UpPwrCtrNB; // UplinkPowerControl-NB: it is used to specify parameters for uplink power control in the
                                                // system information for NB-IoT UEs

    sdrLte_SibNB_01    SibInfoNB;      // SIB-NB Scheduling information

    uint            NpdcchNumRepetitionPaging;  // Maximum number of repetitions for NPDCCH common search space (CSS) for paging, see TS 36.211.
                                                // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128,  r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]
};

struct sdrLte_SibDataNB_02
{
    sdrLte_PrachNB_01  PrachInfoNB;      // NPRACH-ConfigSIB-NB : PRACH configuration Common for NB-IoT UEs in Anchor Carrier

    sdrLte_PdschNB_00  PdschInfoNB;      // NPDSCH-ConfigCommon-NB: NPDSCH configuration Common for NB-IoT UEs

    sdrLte_PuschNB_00  PuschInfoNB;      // PUSCH configuration Common for UEs in CE

    sdrLte_DlGapConfigNB_00 DlGapInfoNB; // DL-GapConfig-NB: it is used to specify the downlink gap configuration for NPDCCH and NPDSCH

    sdrLte_UplinkPowerControlNB_00  UpPwrCtrNB; // UplinkPowerControl-NB: it is used to specify parameters for uplink power control in the
                                                // system information for NB-IoT UEs
    sdrLte_Tdd         TddConfig;               // TDD specific physical channel configuration
    sdrLte_SibNB_01    SibInfoNB;               // SIB-NB Scheduling information

    short              NpdcchNumRepetitionPaging;  // Maximum number of repetitions for NPDCCH common search space (CSS) for paging, see TS 36.211 for current Anchor Carrier.
                                                   // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128,  r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]
                                                   
    uchar              NumNonAnchorCarriersDL;         // This field gives the number of meaningful elements in the DlNonAncConfig vector
    uchar              NumNonAnchorCarriersUL;         // This field gives the number of meaningful elements in the UlNonAncConfig vector
                                                       // List of DL non-anchor carriers and associated configuration that can be used 
                                                       // for paging and/or random access.
    sdrLte_DLNonAnchorConfigCommonNB_00  DlNonAncConfig[1];     // Dynamic list of maximum sdrLteMAX_NONANCHORCARRIERS_NB_v0 elements. It could be empty 
                                                               // The IE DL-CarrierConfigCommon-NB is used to specify the common configuration of a 
                                                               // DL non-anchor carrier in NB-IoT.
    //sdrLte_ULNonAnchorConfigCommonNB_00  UlNonAncConfig[1];  // Dynamic list of maximum sdrLteMAX_NONANCHORCARRIERS_NB_v0 elements. It could be empty 
                                                               // The IE DL-CarrierConfigCommon-NB is used to specify the common configuration of a 
                                                               // UL non-anchor carrier in NB-IoT.
};

struct sdrLte_SibDataNB_03
{
    sdrLte_PrachNB_01  PrachInfoNB;      // NPRACH-ConfigSIB-NB : PRACH configuration Common for NB-IoT UEs in Anchor Carrier

    sdrLte_PdschNB_00  PdschInfoNB;      // NPDSCH-ConfigCommon-NB: NPDSCH configuration Common for NB-IoT UEs

    sdrLte_PuschNB_00  PuschInfoNB;      // PUSCH configuration Common for UEs in CE

    sdrLte_DlGapConfigNB_00 DlGapInfoNB; // DL-GapConfig-NB: it is used to specify the downlink gap configuration for NPDCCH and NPDSCH

    sdrLte_UplinkPowerControlNB_00  UpPwrCtrNB; // UplinkPowerControl-NB: it is used to specify parameters for uplink power control in the
                                                // system information for NB-IoT UEs
    sdrLte_Tdd         TddConfig;               // TDD specific physical channel configuration
    sdrLte_SibNB_01    SibInfoNB;               // SIB-NB Scheduling information
    
    sdrLte_CarrierFreqNB_00       UlCarrierFreq;     // UL carrier frequency as defined in TS 36.101 [42, 5.7.3F]. From SIB2-NB
                                                     // If operationModeInfo in the MIB-NB is set to standalone and the field is absent, 
                                                     // the value of the carrier frequency is determined by the TX-RX frequency separation 
                                                     // defined in TS 36.101 [42, table 5.7.4-1] and the value of the carrier frequency offset is 0. 
                                                     // If operationModeInfo in the MIB-NB is not set to standalone, the field is mandatory present.

    int                 Pmax;           // from RadioResourceConfigCommon: used to limit the UE's uplink
                                        // transmission power (dBm). From SIB1-NB

    short              NpdcchNumRepetitionPaging;  // Maximum number of repetitions for NPDCCH common search space (CSS) for paging, see TS 36.211 for current Anchor Carrier.
                                                   // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128,  r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]
                                                   
    uchar              NumNonAnchorCarriersDL;         // This field gives the number of meaningful elements in the DlNonAncConfig vector
    uchar              NumNonAnchorCarriersUL;         // This field gives the number of meaningful elements in the UlNonAncConfig vector
                                                       // List of DL non-anchor carriers and associated configuration that can be used 
                                                       // for paging and/or random access.
    sdrLte_DLNonAnchorConfigCommonNB_00  DlNonAncConfig[1];     // Dynamic list of maximum sdrLteMAX_NONANCHORCARRIERS_NB_v0 elements. It could be empty 
                                                               // The IE DL-CarrierConfigCommon-NB is used to specify the common configuration of a 
                                                               // DL non-anchor carrier in NB-IoT.
    //sdrLte_ULNonAnchorConfigCommonNB_00  UlNonAncConfig[1];  // Dynamic list of maximum sdrLteMAX_NONANCHORCARRIERS_NB_v0 elements. It could be empty 
                                                               // The IE DL-CarrierConfigCommon-NB is used to specify the common configuration of a 
                                                               // UL non-anchor carrier in NB-IoT.
};

struct sdrLte_SibDataNB_04
{
    sdrLte_PrachNB_02  PrachInfoNB;      // NPRACH-ConfigSIB-NB : PRACH configuration Common for NB-IoT UEs in Anchor Carrier

    sdrLte_PdschNB_00  PdschInfoNB;      // NPDSCH-ConfigCommon-NB: NPDSCH configuration Common for NB-IoT UEs

    sdrLte_PuschNB_00  PuschInfoNB;      // PUSCH configuration Common for UEs in CE

    sdrLte_DlGapConfigNB_00 DlGapInfoNB; // DL-GapConfig-NB: it is used to specify the downlink gap configuration for NPDCCH and NPDSCH

    sdrLte_UplinkPowerControlNB_00  UpPwrCtrNB; // UplinkPowerControl-NB: it is used to specify parameters for uplink power control in the
                                                // system information for NB-IoT UEs
    sdrLte_Tdd         TddConfig;               // TDD specific physical channel configuration
    sdrLte_SibNB_01    SibInfoNB;               // SIB-NB Scheduling information
    
    sdrLte_CarrierFreqNB_01       UlCarrierFreq;     // UL carrier frequency as defined in TS 36.101 [42, 5.7.3F]. From SIB2-NB
                                                     // If operationModeInfo in the MIB-NB is set to standalone and the field is absent, 
                                                     // the value of the carrier frequency is determined by the TX-RX frequency separation 
                                                     // defined in TS 36.101 [42, table 5.7.4-1] and the value of the carrier frequency offset is 0. 
                                                     // If operationModeInfo in the MIB-NB is not set to standalone, the field is mandatory present.

    int                 Pmax;           // from RadioResourceConfigCommon: used to limit the UE's uplink
                                        // transmission power (dBm). From SIB1-NB

    short              NpdcchNumRepetitionPaging;  // Maximum number of repetitions for NPDCCH common search space (CSS) for paging, see TS 36.211 for current Anchor Carrier.
                                                   // ENUMERATED [r1, r2, r4, r8, r16, r32, r64, r128,  r256, r512, r1024, r2048, spare4, spare3, spare2, spare1]
                                                   
    uchar              NumNonAnchorCarriersDL;         // This field gives the number of meaningful elements in the DlNonAncConfig vector
    uchar              NumNonAnchorCarriersUL;         // This field gives the number of meaningful elements in the UlNonAncConfig vector
                                                       // List of DL non-anchor carriers and associated configuration that can be used 
                                                       // for paging and/or random access.
    sdrLte_DLNonAnchorConfigCommonNB_01  DlNonAncConfig[1];     // Dynamic list of maximum sdrLteMAX_NONANCHORCARRIERS_NB_v0 elements. It could be empty 
                                                               // The IE DL-CarrierConfigCommon-NB is used to specify the common configuration of a 
                                                               // DL non-anchor carrier in NB-IoT.
    //sdrLte_ULNonAnchorConfigCommonNB_01  UlNonAncConfig[1];  // Dynamic list of maximum sdrLteMAX_NONANCHORCARRIERS_NB_v0 elements. It could be empty 
                                                               // The IE DL-CarrierConfigCommon-NB is used to specify the common configuration of a 
                                                               // UL non-anchor carrier in NB-IoT.
};

typedef struct sdrLte_SibDataNB_00 sdrLte_SibDataNB_00;
typedef struct sdrLte_SibDataNB_01 sdrLte_SibDataNB_01;
typedef struct sdrLte_SibDataNB_02 sdrLte_SibDataNB_02;
typedef struct sdrLte_SibDataNB_03 sdrLte_SibDataNB_03;
typedef struct sdrLte_SibDataNB_04 sdrLte_SibDataNB_04;
typedef struct sdrLte_SibDataNB_04 sdrLte_SibDataNB;

//**********************************************
// CSI info that depends on the tx-mode
// - for every field = 0xff when invalid
// In current release only the following field are managed:
// - tm4Cqi reported to eNB through CQI message; it overrides the setting from
//   TSTM in PhMeasureSet
// - Every bit set to 1 the tm4PmiMask indicates that the related PMI is suitable for
//   correct decoding
// - tm3Rank, tm4Rank only for monitoring; the setting form PhMeasureSet is reported to eNB
// - tm9 paramters will be managed when full processing of TM9 is ready
//   correct decoding
// - CQI info only in case of air connection
struct sdrLte_CsiInfo_00
{
    uchar tm1Cqi;
    uchar tm2Cqi;
    uchar tm3Cqi;
    uchar tm3Rank;

    uchar tm4Cqi;
    uchar tm4Rank;
    ushort tm4PmiMask;

    uchar tm4Pmi;
    uchar tm6Cqi;
    uchar tm6Pmi;
    uchar tm7Cqi;

    uchar tm9Cqi;
    uchar tm9Rank;
    ushort tm9Pmi1Mask;

    ushort tm9Pmi2Mask;
    uchar tm9Pmi;           // bits 0-3 i1; bits 4-7 i2
    uchar spare;
};

typedef struct sdrLte_CsiInfo_00 sdrLte_CsiInfo_00;
typedef struct sdrLte_CsiInfo_00 sdrLte_CsiInfo;

//**************************************************************/
// LAA Configuration    
struct sdrLte_LAA_00
    {
    uchar         LsuCellIdLaa;     // LSU cell index
    uchar         Spare[3];
    ushort        dmtc_period;      // (40, 80, 160) milliseconds. Used for discovery signals measurement timing (Specs 36.331 5.5.2.10) 
    ushort        dmtc_offset;      // INTEGER(0..159): offset in number of subframes 
    
    };
    
struct sdrLte_LAA_01
    {
    uchar         LsuCellIdLaa;     // LSU cell index
    uchar         isCarrierFreqValid; // This parameter gives the validity of carrierFreq field.
                                      // If this parameter is set to 0 -> carrierFreq field is not read because not valid 
                                      // If this parameter is set to 1 -> carrierFreq field is set to valid value 
    uchar         isDmtcValid;        // This parameter gives the validity of dmtc_period and dmtc_offset fields. 
                                      // If this parameter is set to 0 -> dmtc_period and dmtc_offset fields are not read because not valid 
                                      // If this parameter is set to 1 -> dmtc_period and dmtc_offset fields are set to valid values 
    uchar         Spare;
    ushort        dmtc_period;      // (40, 80, 160) milliseconds. Used for discovery signals measurement timing (Specs 36.331 5.5.2.10) 
    ushort        dmtc_offset;      // INTEGER(0..159): offset in number of subframes 
    uint          carrierFreq;      // DL EARFCN value to be applied for LAA cell 
    };
    
typedef struct sdrLte_LAA_00 sdrLte_LAA_00;
typedef struct sdrLte_LAA_01 sdrLte_LAA_01;
typedef struct sdrLte_LAA_01 sdrLte_LAA;

struct sdrLte_RntiLaaCfg_00
    {
    uint                  Rnti;           // RNTI value                                       
    uchar                 RntiFlag;       // RNTI flag: 0 means legacy/CATM RNTI ( default value ), 1 means NBIoT RNTI
    uchar                 CarrierIdNB;    // NBIoT Anchor Carrier identifier if RNTI is NBIoT. 
                                          // Default value 0xFF invalid value
    uchar                 NumCarrier;     // Number of carriers to be configured for LAA  ( 1 ...sdrLte_MAX_CARRIERS_AGGREGATED) - PCELL is already present
    uchar                 Spare;  
    sdrLte_LAA_00         LaaCarrier[sdrLte_MAX_CARRIERS_AGGREGATED_v2];    // Data to be reported on a per-carrier basis (static length)

};

struct sdrLte_RntiLaaCfg_01
    {
    uint                  Rnti;           // RNTI value                                       
    uchar                 RntiFlag;       // RNTI flag: 0 means legacy/CATM RNTI ( default value ), 1 means NBIoT RNTI
    uchar                 CarrierIdNB;    // NBIoT Anchor Carrier identifier if RNTI is NBIoT. 
                                          // Default value 0xFF invalid value
    uchar                 NumCarrier;     // Number of carriers to be configured for LAA  ( 1 ...sdrLte_MAX_CARRIERS_AGGREGATED) - PCELL is already present
    uchar                 Spare;  
    sdrLte_LAA_01         LaaCarrier[sdrLte_MAX_CARRIERS_AGGREGATED_v2];    // Data to be reported on a per-carrier basis (static length)

};

struct sdrLte_RntiLaaCfg_02
    {
    uint                  Rnti;           // RNTI value                                       
    uchar                 RntiFlag;       // RNTI flag: 0 means legacy/CATM RNTI ( default value ), 1 means NBIoT RNTI
    uchar                 CarrierIdNB;    // NBIoT Anchor Carrier identifier if RNTI is NBIoT. 
                                          // Default value 0xFF invalid value
    uchar                 NumCarrier;     // Number of carriers to be configured for LAA  ( 1 ...sdrLte_MAX_CARRIERS_AGGREGATED) - PCELL is already present
    uchar                 Spare;  
    sdrLte_LAA_01         LaaCarrier[sdrLte_MAX_CARRIERS_AGGREGATED_v3];    // Data to be reported on a per-carrier basis (static length)

};
typedef struct sdrLte_RntiLaaCfg_00 sdrLte_RntiLaaCfg_00;
typedef struct sdrLte_RntiLaaCfg_01 sdrLte_RntiLaaCfg_01;
typedef struct sdrLte_RntiLaaCfg_02 sdrLte_RntiLaaCfg_02;
typedef struct sdrLte_RntiLaaCfg_02 sdrLte_RntiLaaCfg;

#endif

