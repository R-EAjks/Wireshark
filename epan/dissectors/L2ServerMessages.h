#ifndef L2SERVERMESSAGES_H
#define L2SERVERMESSAGES_H

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

#include "lte.h"
//#include "lte-l2_Sap.h"
#include "nr5g-rlcmac_Cmac.h"
//#include "nr5g-rlcmac_Data.h"
//#include "qnx_gen.h"
//#include <string>

#pragma pack(1)

#define TYPE_ACK	0x0100
#define TYPE_NAK	0x0200

#define  lte_l2_Srv_LOGIN_CMD            1
#define  lte_l2_Srv_LOGIN_ACK            (256 + lte_l2_Srv_LOGIN_CMD)
#define  lte_l2_Srv_LOGIN_NAK            (512 + lte_l2_Srv_LOGIN_CMD)

/* Optional server versions information query */
#define  lte_l2_Srv_VERSION_INFO_CMD     30
#define  lte_l2_Srv_VERSION_INFO_ACK     (256 + lte_l2_Srv_VERSION_INFO_CMD)
#define  lte_l2_Srv_VERSION_INFO_NAK     (512 + lte_l2_Srv_VERSION_INFO_CMD)

#define nr5g_l2_Srv_BASE_TYPE         (2048)
#define  nr5g_l2_Srv_CFG_CMD           nr5g_l2_Srv_BASE_TYPE + 1
#define  nr5g_l2_Srv_CFG_ACK           (256 + nr5g_l2_Srv_CFG_CMD)
#define  nr5g_l2_Srv_CFG_NAK           (512 + nr5g_l2_Srv_CFG_CMD)

#define  nr5g_l2_Srv_CELL_PPU_LIST_CMD        nr5g_l2_Srv_BASE_TYPE + 4
#define  nr5g_l2_Srv_CELL_PPU_LIST_ACK       (256 + nr5g_l2_Srv_CELL_PPU_LIST_CMD)
#define  nr5g_l2_Srv_CELL_PPU_LIST_NAK       (512 + nr5g_l2_Srv_CELL_PPU_LIST_CMD)

#define  nr5g_l2_Srv_SETPARM_CMD          nr5g_l2_Srv_BASE_TYPE + 2
#define  nr5g_l2_Srv_SETPARM_ACK          (256 + nr5g_l2_Srv_SETPARM_CMD)
#define  nr5g_l2_Srv_SETPARM_NAK          (512 + nr5g_l2_Srv_SETPARM_CMD)

#define  lte_l2_Srv_START_CMD            4
#define  lte_l2_Srv_START_ACK            (256 + lte_l2_Srv_START_CMD)
#define  lte_l2_Srv_START_NAK            (512 + lte_l2_Srv_START_CMD)

#define  nr5g_l2_Srv_OPEN_CELL_CMD      nr5g_l2_Srv_BASE_TYPE + 3
#define  nr5g_l2_Srv_OPEN_CELL_ACK      (256 + nr5g_l2_Srv_OPEN_CELL_CMD)
#define  nr5g_l2_Srv_OPEN_CELL_NAK      (512 + nr5g_l2_Srv_OPEN_CELL_CMD)

#define  lte_l2_Srv_GETINFO_CMD         52
#define  lte_l2_Srv_GETINFO_ACK         (256 + lte_l2_Srv_GETINFO_CMD)                                                     
#define  lte_l2_Srv_GETINFO_NAK         (512 + lte_l2_Srv_GETINFO_CMD)                                                     
                                                                    
#define  nr5g_l2_Srv_CELL_CONFIG_CMD      nr5g_l2_Srv_BASE_TYPE + 7
#define  nr5g_l2_Srv_CELL_CONFIG_ACK      (256 + nr5g_l2_Srv_CELL_CONFIG_CMD)
#define  nr5g_l2_Srv_CELL_CONFIG_NAK      (512 + nr5g_l2_Srv_CELL_CONFIG_CMD)

#define nr5g_l2_Srv_RCP_LOAD_CMD nr5g_l2_Srv_BASE_TYPE + 13
#define nr5g_l2_Srv_RCP_LOAD_ACK (256 + nr5g_l2_Srv_RCP_LOAD_CMD)
#define nr5g_l2_Srv_RCP_LOAD_NAK (512 + nr5g_l2_Srv_RCP_LOAD_CMD)

#define nr5g_l2_Srv_RCP_LOAD_END_CMD nr5g_l2_Srv_BASE_TYPE + 14
#define nr5g_l2_Srv_RCP_LOAD_END_ACK (256 + nr5g_l2_Srv_RCP_LOAD_END_CMD)
#define nr5g_l2_Srv_RCP_LOAD_END_NAK (512 + nr5g_l2_Srv_RCP_LOAD_END_CMD)

#define tstmLTEL2_FIRST_SAP                                 0x0200
#define  lte_l2_Sap_OM                                      2
#define tstmLTEL2_OM_SAP                                    (tstmLTEL2_FIRST_SAP+lte_l2_Sap_OM)

#define TMPROC_SAPI_SHIFT                                   16
#define TMPROC_WSN_SID(sap, type)                           (((sap)<<TMPROC_SAPI_SHIFT) | (type))
#define nr5gl2TstmSID_NR5G_L2_SRV_CFG_ACK                   TMPROC_WSN_SID(tstmLTEL2_OM_SAP, nr5g_l2_Srv_CFG_ACK)

#define  nr5g_rlcmac_Crlc_CONFIG_CMD	0x01
#define  nr5g_rlcmac_Crlc_CONFIG_ACK	(0x100 + nr5g_rlcmac_Crlc_CONFIG_CMD)
#define  nr5g_rlcmac_Crlc_CONFIG_NAK	(0x200 + nr5g_rlcmac_Crlc_CONFIG_CMD)

#define  nr5g_l2_Srv_CELL_PARM_CMD        nr5g_l2_Srv_BASE_TYPE + 5
#define  nr5g_l2_Srv_CELL_PARM_ACK        (256 + nr5g_l2_Srv_CELL_PARM_CMD)
#define  nr5g_l2_Srv_CELL_PARM_NAK        (512 + nr5g_l2_Srv_CELL_PARM_CMD)

#define nr5g_rlcmac_Cmac_DBEAM_IND            0x408

#define  lte_l2_Sap_NR_RLCMAC_CMAC  143
#define  lte_l2_Sap_NR_RLCMAC_CRLC  144

#define  nr5g_l2_Srv_CREATE_UE_CMD      nr5g_l2_Srv_BASE_TYPE + 9
#define  nr5g_l2_Srv_CREATE_UE_ACK      (256 + nr5g_l2_Srv_CREATE_UE_CMD)
#define  nr5g_l2_Srv_CREATE_UE_NAK      (512 + nr5g_l2_Srv_CREATE_UE_CMD)

#define  lte_l2_Srv_DELETE_UE_CMD      15
#define  lte_l2_Srv_DELETE_UE_ACK      (256 + lte_l2_Srv_DELETE_UE_CMD)
#define  lte_l2_Srv_DELETE_UE_NAK      (512 + lte_l2_Srv_DELETE_UE_CMD)

#define nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD    (nr5g_l2_Srv_BASE_TYPE + 19)
#define nr5g_l2_Srv_RCP_UE_SET_GROUP_ACK    (nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD | TYPE_ACK)
#define nr5g_l2_Srv_RCP_UE_SET_GROUP_NAK    (nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD | TYPE_NAK)

#define nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD    (nr5g_l2_Srv_BASE_TYPE + 20)
#define nr5g_l2_Srv_RCP_UE_SET_INDEX_ACK    (nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD | TYPE_ACK)
#define nr5g_l2_Srv_RCP_UE_SET_INDEX_NAK    (nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD | TYPE_NAK)

/* Indicate re-establish procedure phase 1 (Suspend and New Target Cell Indication) */
#define  nr5g_l2_Srv_REEST_PREPARE_CMD    (nr5g_l2_Srv_BASE_TYPE + 26)
#define  nr5g_l2_Srv_REEST_PREPARE_ACK    (256 + nr5g_l2_Srv_REEST_PREPARE_CMD)
#define  nr5g_l2_Srv_REEST_PREPARE_NAK    (512 + nr5g_l2_Srv_REEST_PREPARE_CMD)

#define  nr5g_l2_Srv_HANDOVER_CMD      nr5g_l2_Srv_BASE_TYPE + 18
#define  nr5g_l2_Srv_HANDOVER_ACK      (256 + nr5g_l2_Srv_HANDOVER_CMD)
#define  nr5g_l2_Srv_HANDOVER_NAK      (512 + nr5g_l2_Srv_HANDOVER_CMD)

/*
 * Activate SIB filtering for a cell
 */
#define nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD    0x05
#define nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK    (0x100 + nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD)
#define nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK    (0x200 + nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD)

#define nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD    0x06
#define nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK    (0x100 + nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD)
#define nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK    (0x200 + nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD)

typedef struct {
    char   CliName[40];    /* Login Name (1) */
} lte_l2_Srv_LOGINt;

#define nr5g_l2_Srv_CFG_01tTYPE 1

typedef struct {
    ushort      Type;              /* Parameter Type (1) */
    lte_Side_v  Side;              /* Interface side */
    uchar       BotLayer;          /* Bottom Layer selected (21) */
    uchar       Trf;               /* Traffic Type (2) */

/* UDG timeout configuration */
    uint    Alive;      /* Keep alive period timeout [s]               (3,4) *
                         * NET side will be closed if NRetry timeout expire  *
                         * before a keep alive indication arrive             */
    uint    TxErr;      /* DATA transmission error timeout [s]         (3,13,5) */
    uint    StartTO;    /* START_REQ retransmission timeout [s]        (3,14) */
    uint    TermTO;     /* TERMIANTE_REQ retransmission timeout [s]    (3,15) */
    uint    TermAckTO;  /* RESULT_IND retransmission error timeout [s] (3,16) */
    uint    NLost;      /* Number of pkt lost after TO (Def=1)         (3,13) */
    uint    NStartRetry;/* Number of START command retry (Def=3)       (3,14) */
    uint    NTermRetry; /* Number of TERM command retry (Def=3)        (3,15) */

/* UDG Ramp configuration, useful to start high bandwith tests smootest    */
/* UDG Global configuration of TUDG socket buf size (Default, see sysctl -a) */
    uint        TstMsk;            /* UDG test type mask (Eg: b1010=0xa=t1,t2) () */
    uint        UlBLim;            /* UL limit [ms/pkt], apply ramp below this limit (0=off) (3) */
    uint        UlRampDt;          /* UL ramp phase duration [ms], should be less then 1" (3) */
    uint        DlBLim;            /* DL limit [ms/pkt], apply ramp below this limit (0=off) (3) */
    uint        DlRampDt;          /* DL ramp phase duration [ms], should be less then 1" (3) */
    uint        SendBuf;           /* TUDG: setsockopt SENDBUF parameter (3) */
    uint        RecvBuf;           /* TUDG: setsockopt RECVBUF parameter () */
    
    uint        En;                /* Interface number en<En> (12) */
    uint        GiIp;              /* IP address on the Gi interface (3,6,7) */
    uint        GiMask;            /* Netmask on the Gi interface (3,6,7) */
    uchar       GiIp6[16];         /* IPv6 address on the Gi interface (10) */
    uint        Prefix;            /* IPv6 prefix len on the Gi interface */
    uchar       Spare;        
    uint        L2MaintenanceFlags;  /* L2 Flags transparent to AirMosaic and TSTM (debug/temporary reasons) */

} nr5g_l2_Srv_CFG_01t;

#define nr5g_l2_Srv_CFG_02tTYPE 2

typedef struct {
    ushort      Type;              /* Parameter Type (1) */
    lte_Side_v  Side;              /* Interface side */
    uchar       BotLayer;          /* Bottom Layer selected (21) */
    uchar       Trf;               /* Traffic Type (2) */

/* UDG timeout configuration */
    uint    Alive;      /* Keep alive period timeout [s]               (3,4) *
                         * NET side will be closed if NRetry timeout expire  *
                         * before a keep alive indication arrive             */
    uint    TxErr;      /* DATA transmission error timeout [s]         (3,13,5) */
    uint    StartTO;    /* START_REQ retransmission timeout [s]        (3,14) */
    uint    TermTO;     /* TERMIANTE_REQ retransmission timeout [s]    (3,15) */
    uint    TermAckTO;  /* RESULT_IND retransmission error timeout [s] (3,16) */
    uint    NLost;      /* Number of pkt lost after TO (Def=1)         (3,13) */
    uint    NStartRetry;/* Number of START command retry (Def=3)       (3,14) */
    uint    NTermRetry; /* Number of TERM command retry (Def=3)        (3,15) */

/* UDG Ramp configuration, useful to start high bandwith tests smootest    */
/* UDG Global configuration of TUDG socket buf size (Default, see sysctl -a) */
    uint        TstMsk;            /* UDG test type mask (Eg: b1010=0xa=t1,t2) () */
    uint        UlBLim;            /* UL limit [ms/pkt], apply ramp below this limit (0=off) (3) */
    uint        UlRampDt;          /* UL ramp phase duration [ms], should be less then 1" (3) */
    uint        DlBLim;            /* DL limit [ms/pkt], apply ramp below this limit (0=off) (3) */
    uint        DlRampDt;          /* DL ramp phase duration [ms], should be less then 1" (3) */
    uint        SendBuf;           /* TUDG: setsockopt SENDBUF parameter (3) */
    uint        RecvBuf;           /* TUDG: setsockopt RECVBUF parameter () */
    
    uint        En;                /* Interface number en<En> (12) */
    uint        GiIp;              /* IP address on the Gi interface (3,6,7) */
    uint        GiMask;            /* Netmask on the Gi interface (3,6,7) */
    uchar       GiIp6[16];         /* IPv6 address on the Gi interface (10) */
    uint        Prefix;            /* IPv6 prefix len on the Gi interface */
#define nr5g_l2_Srv_LTE     1
#define nr5g_l2_Srv_NR      2
    uchar       Technology;        /* Technology used (17) */
#define nr5g_l2_Srv_ENBSIM_00   0
#define nr5g_l2_Srv_ENBSIM_01   1
    uchar       ENbSim;            /* Control simulation of LTE Uu on eNB. (18) */

    uint        Flags;             /* see lte_l2_Srv_CFLAG_* */
    uint        L2MaintenanceFlags;  /* L2 Flags transparent to AirMosaic and TSTM (debug/temporary reasons) */
} __attribute__((packed)) nr5g_l2_Srv_CFG_02t;

#define nr5g_l2_Srv_SETPARM_L1SIM_04 6

typedef struct {
    ushort  Type;                       /* Parameter Type (1) */
    uint    MaxUe;                      /* Max number of UE's (2,4) */
    uint    MaxPdcp;                    /* Max number of PDCP (2,6) */
    uint    MaxNat;                     /* Max number of NAT bearers (7) */
    uint    MaxUdgSess;                 /* Max number of UDG entity (8) */
    uint    MaxCntr;                    /* Max number of Filter/Counters (9) */
    uint    Verbosity;                           /* Lte Global Trace Verbosity bit mask */
    uint    L2_nr5g_RlcMac_Verbosity;            /* Nr5g RlcMac Global Trace Verbosity bit mask */
    uint    L2_nr5g_pdcp_Verbosity;              /* Nr5g Pdcp Global Trace Verbosity bit mask */
    uint    Spare[1];                   /* Reserved set to 0 */
    uchar   NumStkPpu;                  /* Number of elements of StkPpu[] list */
    comgen_qnxPPUIDt  StkPpu[];         /* PPU list where put the stack processes (higher level) (12) */
/*  nr5g_l2_Srv_CellL1Sim_t CellL1Sim[]; */ /* Cell parameters for L1Sim connection */
} nr5g_l2_Srv_SETPARM_L1SIM_04t;

#define nr5g_l2_Srv_SETPARM_02          3

typedef struct {
    ushort  Type;                 /* Parameter Type (1) */
    uint    MaxUe;                /* Max number of UE's (2,4) */
    uint    MaxPdcp;              /* Max number of PDCP (2,6) */
    uint    MaxNat;               /* Max number of NAT bearers (7) */
    uint    MaxUdgSess;           /* Max number of UDG entity (8) */
    uint    MaxCntr;              /* Max number of Filter/Counters (9) */
    
    uint    Verbosity;                           /* Lte Global Trace Verbosity bit mask */
    uint    L2_nr5g_RlcMac_Verbosity;            /* Nr5g RlcMac Global Trace Verbosity bit mask */
    uint    L2_nr5g_pdcp_Verbosity;              /* Nr5g Pdcp Global Trace Verbosity bit mask */
    
    ushort  BeamChangeTimer;      /* Beam Change Timer [ms, 0 means disabled] */
    uchar   FieldTestMode;        /* 1 -> Field test mode enabled; 0 -> AMM based behaviour */
#define nr5g_l2_Srv_DL_HARQ_OFF         (0)  /* DL HARQ is off (no feedback is sent to peer) */
#define nr5g_l2_Srv_DL_HARQ_L1          (1)  /* the DL HARQ feedback are handled autonomously by L1 */
#define nr5g_l2_Srv_DL_HARQ_L2_DCI      (2)  /* the DL HARQ feedback are handle by L2 immediately
                                                after a downlink grant reception */
#define nr5g_l2_Srv_DL_HARQ_L2_PDSCH    (3)  /* the DL HARQ feedback are handle by L2 process
                                                after the pdsch reception */
    uchar   DlHarqMode;           /* see nr5g_l2_Srv_DL_HARQ_* above; default=nr5g_l2_Srv_DL_HARQ_L2_DCI */
#define nr5g_l2_Srv_MEAS_MODE_PRIM      (0) /* measurement set feeded */
#define nr5g_l2_Srv_MEAS_MODE_CSV       (1) /* AMM csv feeded (not yet implemented) */
#define nr5g_l2_Srv_MEAS_MODE_REAL      (2) /* real measurements (field mode) */
    uchar   MeasMode;             /* see nr5g_l2_Srv_MEAS_MODE_* above; default=nr5g_l2_Srv_MEAS_MODE_PRIM */
    uchar   UlFsAdvance;          /* Uplink frame sync adavance in OFDM symbols (0xff means an optimal value is choosen by the software); default=0xff */
    char    DeltaNumLdpcIteration;     /* Provides a difference to be applied to the optimal LDPC iteration value selected by the software 
                                                (-5 .. 5) (0xff means no difference is applied) */
    uchar   DlSoftCombining;      /* DL HARQ soft combining algorithm enabled (1) or disabled (0). Def=0 */
    uchar   MaxRach;              /* Maximum number of preambles per slot, Def=8 */
    uchar   SpareC[3];            /* set to zero */
    uint    Spare[19];            /* set to zero */    

    uchar   NumStkPpu;            /* Number of elements of StkPpu[] list */
    uchar   NumNrProPpu;          /* Number of elements of NrProPpu[] list */
    uchar   NumLteCell;
    uchar   NumNrCell;
    comgen_qnxPPUIDt StkPpu[];    /* PPU list where put the nr5g.stk processes (12) */
/*  comgen_qnxPPUIDt NrProPpu[]; */ /* PPU list where put the nr5g-l2.pro processes (13) */
/*  uchar   LteCellIdList[]; */   /* Start of the list of LTE cell's CellId  */
/*  uchar   NrCellIdList[];  */   /* Start of the list of NR5G cell's CellId */
} nr5g_l2_Srv_SETPARM_02t;

#define nr5g_l2_Srv_SETPARM_03		    7

typedef struct {
    ushort  Type:16;                 /* Parameter Type (1) */
    uint    MaxUe:32;                /* Max number of UE's (2,4) */
    uint    MaxPdcp:32;              /* Max number of PDCP (2,6) */
    uint    MaxNat:32;               /* Max number of NAT bearers (7) */
    uint    MaxUdgSess:32;           /* Max number of UDG entity (8) */
    uint    MaxCntr:32;              /* Max number of Filter/Counters (9) */
    
    uint    Verbosity:32;                           /* Lte Global Trace Verbosity bit mask */
    uint    L2_nr5g_RlcMac_Verbosity:32;            /* Nr5g RlcMac Global Trace Verbosity bit mask */
    uint    L2_nr5g_pdcp_Verbosity:32;              /* Nr5g Pdcp Global Trace Verbosity bit mask */
    
    ushort  BeamChangeTimer:16;      /* Beam Change Timer [ms, 0 means disabled] */
    uchar   FieldTestMode:8;        /* 1 -> Field test mode enabled; 0 -> AMM based behaviour */
#define nr5g_l2_Srv_DL_HARQ_OFF         (0)  /* DL HARQ is off (no feedback is sent to peer) */
#define nr5g_l2_Srv_DL_HARQ_L1          (1)  /* the DL HARQ feedback are handled autonomously by L1 */
#define nr5g_l2_Srv_DL_HARQ_L2_DCI      (2)  /* the DL HARQ feedback are handle by L2 immediately
                                                after a downlink grant reception */
#define nr5g_l2_Srv_DL_HARQ_L2_PDSCH    (3)  /* the DL HARQ feedback are handle by L2 process
                                                after the pdsch reception */
    uchar   DlHarqMode:8;           /* see nr5g_l2_Srv_DL_HARQ_* above; default=nr5g_l2_Srv_DL_HARQ_L2_DCI */
#define nr5g_l2_Srv_MEAS_MODE_PRIM      (0) /* measurement set feeded */
#define nr5g_l2_Srv_MEAS_MODE_CSV       (1) /* AMM csv feeded (not yet implemented) */
#define nr5g_l2_Srv_MEAS_MODE_REAL      (2) /* real measurements (field mode) */
    uchar   MeasMode:8;             /* see nr5g_l2_Srv_MEAS_MODE_* above; default=nr5g_l2_Srv_MEAS_MODE_PRIM */
    uchar   UlFsAdvance:8;          /* Uplink frame sync adavance in OFDM symbols (0xff means an optimal value is choosen by the software); default=0xff */
    char    DeltaNumLdpcIteration:8; /* Number of LDPC iterations (0xff means an optimal value is choosen by the software); default=0xff */
    uchar   DlSoftCombining:8;      /* DL HARQ soft combining algorithm enabled (1) or disabled (0). Def=0 */
    uchar   MaxRach;              /* Maximum number of preambles per slot, Def=8 */
    uchar   SpareC[3];            /* set to zero */
    uint    Spare[19];            /* set to zero */

    uchar   NumUpStkPpu:8;          /* Number of elements of UpStkPpu[] list */
    uchar   NumDwnStkPpu:8;         /* Number of elements of DWnStkPpu[] list */
    uchar   NumLteProPpu:8;         /* Number of elements of LteProPpu[] list (in case of LTE/DSP set to 0)*/
    uchar   NumNrProPpu:8;          /* Number of elements of NrProPpu[] list */
    uchar   NumLteCell:8;
    uchar   NumNrCell:8;
    
    // Changed to pointer. Was originally UpStkPpu[]
    
    comgen_qnxPPUIDt *UpStkPpu;    /* PPU list where put the lte.stk.up processes (12) */
/*  comgen_qnxPPUIDt DwnStkPpu[]; */ /* PPU list where put the lte.stk.dwn processes (12) */
/*  comgen_qnxPPUIDt LteProPpu[]; */ /* PPU list where put the lte-l2.pro processes (13) */
/*  comgen_qnxPPUIDt NrProPpu[]; */ /* PPU list where put the nr5g-l2.pro processes (13) */
/*  uchar   LteCellIdList[]; */   /* Start of the list of LTE cell's CellId  */
    uchar   *NrCellIdList;       /* Start of the list of NR5G cell's CellId */
} __attribute__((packed)) nr5g_l2_Srv_SETPARM_03t;

// created this
typedef struct {
    ushort Type;
}lte_l2_Srv_start_cmd;

/*********************************************
 * nr5g_l2_Srv_OPEN_CELL_CMD
 *********************************************/

typedef struct
{
    uint      CellId;         /* Cell Identifier */
    uint      L1Verbosity;    /* L1 Verbosity bit mask (see sdrLteVERB* defines from sdrLteStruct.h) */
    uint      L1UlReport;     /* Uplink report activation and format configuration (see sdrLteULREP* defines from sdrLteStruct.h) */ 
    uint      EnableCapsTest; /* If different from zero -> CAPS test will be executed */
} nr5g_l2_Srv_OPEN_CELLt;


/*********************************************
 * nr5g_l2_Srv_CELL_PPU_LIST_CMD
 *********************************************/
 //No Body dlen = 0

/*********************************************
 * nr5g_l2_Srv_CELL_PPU_LIST_ACK
 *********************************************/
typedef struct
{
    uchar     NCellLte;
    uchar     NCellNr;
    uchar     NumLteProPpu;         /* Number of elements of LteProPpu[] list */
    uchar     NumNrProPpu;          /* Number of elements of NrProPpu[] list */
    uchar     CellIdLteList[];      /* Start of the list of cell's CellId which */
/*  uchar     CellIdNrList[]; */    /* Start of the list of cell's CellId which */
/*  comgen_qnxPPUIDt LteProPpu[]; */   /* PPU list available for lte-l2.pro processes  */
/*  comgen_qnxPPUIDt NrProPpu[]; */   /* PPU list available for nr5g-l2.pro processes  */
} nr5g_l2_Srv_CELL_PPU_LIST_ACKt;

/*******************************************
 * lte_l2_SrvGETINFO_CMD
 ******************************************/

typedef struct lte_l2_Srv_GETINFOs {

    uint    Type;   // Type 0
    uint    Flags;  // Requested info 
    #define lte_l2_Srv_GET_UDG_OSLIST   1
} lte_l2_Srv_GETINFOt;

typedef struct {
    uint    NOs;        // Number of supported OsId
    ushort  OsId[0];    // List of supported OsId
} lte_l2_Srv_GETINFO_UDG_OSLISTt;

typedef struct lte_l2_Srv_GETINFO_ACKs {
    uint    Type;   // Type 0
    uint    Flags;  // Available info
    #define lte_l2_Srv_GET_UDG_OSLIST   1

    // Follow info:
    // lte_l2_Srv_GETINFO_UDG_OSLISTt   if UDG_OSLIST is set
    char Info[0];
} lte_l2_Srv_GETINFO_ACKt;

/*********************************************
 * nr5g_l2_Srv_CELL_CONFIG_CMD
 *********************************************/

typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    uchar       Ta;            /* Time Advance Command [TODO, -1 for none] (see MAC par. TODO) */
    uchar       RaInfoValid;   /* To Validate RA Info */
    uchar       RachProbeReq;  /* If 1 RAch probe is requested */
    
    /* cell RA configuration */
    nr5g_rlcmac_Cmac_RA_Info_t      RA_Info;
    
    /* cell configuration */
    
    nr5g_rlcmac_Cmac_CellCfg_t     CellCfg;
    
} nr5g_l2_Srv_CELL_CONFIGt;

/*********************************************
 * nr5g_l2_Srv_RCP_LOAD_CMD
 *********************************************/
typedef struct
{
    uint       RcGroup;        /* Radio Condition Group (1) */
    uint       CellId;         /* Cell Identifier */
    uint       DbeamId;        /* Dbeam Identifier */
    char Fname[100];        /* Path/Filename as ASCIIZ string of profile file */

} nr5g_l2_Srv_RCP_LOADt;

/*********************************************
 * nr5g_l2_Srv_RCP_LOAD_END_CMD
 *********************************************/
typedef struct
{
    uint       Spare;

} nr5g_l2_Srv_RCP_LOAD_ENDt;

typedef struct {

	uint        discardTimer; /* [ms] -1 means "infinity" */

} nr5g_rlcmac_Crlc_TxTmParm_t;

typedef struct {

	uchar	Spare;

} nr5g_rlcmac_Crlc_RxTmParm_t;

typedef struct nr5g_rlcmac_Crlc_TmParm_s {

	uchar							TxActiveFlag;
	nr5g_rlcmac_Crlc_TxTmParm_t		Tx;
	
	uchar							RxActiveFlag;
	nr5g_rlcmac_Crlc_RxTmParm_t		Rx;

} nr5g_rlcmac_Crlc_TmParm_t;

typedef uchar nr5g_rlcmac_Crlc_ER_t;
typedef uchar nr5g_rlcmac_Crlc_SnLength_Um_t;

typedef struct {

	nr5g_rlcmac_Crlc_SnLength_Um_t	SnLength;
	uint	discardTimer; /* [ms] -1 means "infinity" */

} nr5g_rlcmac_Crlc_TxUmParm_t;

typedef struct {

	nr5g_rlcmac_Crlc_SnLength_Um_t	SnLength;
	uint		t_Reassembly; /* [ms] */

} nr5g_rlcmac_Crlc_RxUmParm_t;

typedef struct {

	uchar							TxActiveFlag;
	nr5g_rlcmac_Crlc_TxUmParm_t		Tx;
	
	uchar							RxActiveFlag;
	nr5g_rlcmac_Crlc_RxUmParm_t		Rx;
	
} nr5g_rlcmac_Crlc_UmParm_t;

typedef uchar nr5g_rlcmac_Crlc_SnLength_Am_t;
typedef struct {

	nr5g_rlcmac_Crlc_SnLength_Am_t	SnLength;
	uint		t_PollRetransmit; /* [ms] */
	uchar		pollPDU;   /* -1 means infinity */
	ushort		pollByte; /* -1 means infinity */
	uchar		maxRetxThreshold;

	uint        discardTimer; /* [ms] -1 means "infinity" */

} nr5g_rlcmac_Crlc_TxAmParm_t;

typedef struct {

	nr5g_rlcmac_Crlc_SnLength_Am_t	SnLength;
	uint t_Reassembly;      /* [ms] */
	uint t_StatusProhibit;  /* [ms] */

} nr5g_rlcmac_Crlc_RxAmParm_t;

typedef struct {

	nr5g_rlcmac_Crlc_TxAmParm_t Tx;
	nr5g_rlcmac_Crlc_RxAmParm_t Rx;

} nr5g_rlcmac_Crlc_AmParm_t;

typedef struct {
	uint							UeId;		/* UE Id (4) */
	uchar							RbId;		/* Rb id (1) */
	
	/*
	 * The parameter E/R indicates establishment, re-establishment,
	 * release or modification of an RLC entity
	 */
	nr5g_rlcmac_Crlc_ER_t			ER;
	
	nr5g_RbType_v					RbType;
	
	nr5g_RlcMode_v					RlcMode;
	
	/*
	 * The following fields refers to a specific entity type
	 */
	union {
		nr5g_rlcmac_Crlc_TmParm_t  Tm;  /* (TM) */
		nr5g_rlcmac_Crlc_UmParm_t  Um;  /* (UM) */
		nr5g_rlcmac_Crlc_AmParm_t  Am;  /* (AM) */
	} Parm;

} nr5g_rlcmac_Crlc_CONFIG_CMD_t;

typedef struct
{
    uchar       CellId;       /* Cell Identifier */
} nr5g_l2_Srv_CELL_PARM_CMDt;

typedef struct {
    ushort  phy_cell_id;    /* physical cell identifier [0] */
    uint    dlFreq[2];         /* 0 not found, 1st freq rf,2nd freq udc [kHz] */
    uint    dlEarfcn[2];    /* 0 not found, 1st arfcn rf,2nd arfcn udc [kHz] */
    uint    ulFreq[2];        /* 0 not found, 1st freq rf,2nd freq udc [kHz] */
    uint    ulEarfcn[2];    /* 0 not found, 1st arfcn rf,2nd arfcn udc [kHz] */
    uint    SsbArfcn;       /* ARFCN of cell (-1 not available) */
} __attribute__((packed)) nr5g_l2_Srv_Cell_Parm_t;

typedef struct {
    comgen_qnxPPUIDt  Ppu;
    uint16_t          DbeamId;
} nr5g_l2_Srv_Dbeam_t;

typedef struct
{
    uchar                      CellId;             /* Cell Identifier */
    nr5g_l2_Srv_Cell_Parm_t    Parm;               /* Cell parameters */
    uint                       NumDbeam;           /* # of Dbeam for this cell */
    nr5g_l2_Srv_Dbeam_t        Dbeam[nr5g_MaxDbeam]; /* Dbeam List */
} __attribute__((packed)) nr5g_l2_Srv_CELL_PARM_ACKt;

/*********************************************
 * nr5g_l2_Srv_CREATE_UE_CMD
 *********************************************/

typedef struct
{
    uint            UeId;           /* Ue Identifier (1) */
    uint            CellId;         /* Cell Identifier */
    uint            UeFlags;        /* see lte_l2_Srv_LOG_* */
    uint            StkInst;        /* stack process Instance (3) */
    uint            UdgStkInst;     /* UDG stack process Instance (3) */
} nr5g_l2_Srv_CREATE_UEt;

typedef struct
{
    uint    UeId;                /* UE Identifier */
    uint    RelCellId;           /* Cell Identifier for release */
    uint    AddCellId;           /* Cell Identifier for add */
    uint    ScgType;             /* SCG type for add, nr5g_l2_Srv_SCG_* (1a) */
    uchar   drb_ContinueROHC;    /* drb-ContinueROHC 
                                        [ 0 means 'not configured/false' 
                                        !=0 means 'true' ] */

    uint    MacConfigLen;        /* Length of MacConfig field */
    nr5g_rlcmac_Cmac_CONFIG_CMD_t MacConfig; /* MAC configuration, see nr5g-rlcmac_Cmac.h (2a) */
} nr5g_l2_Srv_SCG_REL_AND_ADDt;

/*********************************************
 * nr5g_l2_Srv_HANDOVER_CMD
 *********************************************/

typedef nr5g_l2_Srv_SCG_REL_AND_ADDt nr5g_l2_Srv_HANDOVERt;



/*********************************************
 * lte_l2_Srv_DELETE_UE_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
} lte_l2_Srv_DELETE_UEt;




/*
 * nr5g_pdcp_Ctrl_SIB_FILTER_ACT_CMD
 * nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_CMD
 */
typedef struct {
    uint            CellId;         /* Cell Identification */
    uint            SibFilterFlag;  /* 0 -> Legacy */

} nr5g_pdcp_Ctrl_SIB_FILTER_CMDt;

/*
 * nr5g_pdcp_Ctrl_SIB_FILTER_ACT_ACK
 * nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_ACK
 */
typedef struct {
    uint            CellId;   /* Cell Identification */
    uint            SibFilterFlag;  /* 0 -> Legacy */

} nr5g_pdcp_Ctrl_SIB_FILTER_ACKt;

/*
 * nr5g_pdcp_Ctrl_SIB_FILTER_ACT_NAK
 * nr5g_pdcp_Ctrl_SIB_FILTER_DEACT_NAK
 */
typedef struct {
    uint            CellId;   /* Cell Identification */
    short           Err;      /* Error code */

} nr5g_pdcp_Ctrl_SIB_FILTER_NAKt;


#define bb_nr5g_STRUCT_CELL_GROUP_CONFIG_PHY_CELL_CONF_PRESENT   0x0001
#define bb_nr5g_STRUCT_CELL_GROUP_CONFIG_CELL_CFG_COMMON_PRESENT   0x0002

#pragma pack()
#endif
