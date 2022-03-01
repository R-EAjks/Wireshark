/********************************************************************
$Source$
$Author$
$Date$
---------------------------------------------------------------------
Project :       v5G SERVER
Description :   The CLIENT INTERFACE - nr5g_l2_Srv.h
---------------------------------------------------------------------
$Revision$
$State$
$Name$
---------------------------------------------------------------------
$Log$
*********************************************************************/

#ifndef  nr5g_l2_Srv_DEFINED
#define  nr5g_l2_Srv_DEFINED

#include "qnx_gen.h" 
#include "nr5g.h"

// include added to compile in TM
#include "lte-l2_Srv.h"
#include "nr5g-rlcmac_Cmac.h"
#include "nr5g-pdcp_Com.h"

#pragma  pack(1)


/********************************************************************
 * THE CLIENT INTERFACE
 ********************************************************************/


        /********************************************
         *                                          *
         * This interface conforms to the rules     *
         *          specified in `lsu.h'.           *
         *                                          *
         ********************************************/


/*
 * The current Server Interface version
 */
#define     nr5g_l2_Srv_VERSION       "1.14.1"

/*
 * The default TCP Port
 */
#define     nr5g_l2_Srv_PORT          5141

/*
 * Max client message length
 */
#define     nr5g_l2_Srv_MSGSIZE       (4*1024)

#define nr5g_l2_Srv_BASE_TYPE         (2048)


/********************************************************************
 * NR OM SAP Message Types
 ********************************************************************/

/*
 * CONFIGURE NR STARTUP
 */
/* Additional NR configuration.
 * Depending on Mode of Operation selected, it can be used after lte_l2_Srv_CFG_V1_CMD or stand alone. */
#define  nr5g_l2_Srv_CFG_CMD           nr5g_l2_Srv_BASE_TYPE + 1
#define  nr5g_l2_Srv_CFG_ACK           (256 + nr5g_l2_Srv_CFG_CMD)
#define  nr5g_l2_Srv_CFG_NAK           (512 + nr5g_l2_Srv_CFG_CMD)

/*
 * Configuration Settings
 */
#define  nr5g_l2_Srv_SETPARM_CMD          nr5g_l2_Srv_BASE_TYPE + 2
#define  nr5g_l2_Srv_SETPARM_ACK          (256 + nr5g_l2_Srv_SETPARM_CMD)
#define  nr5g_l2_Srv_SETPARM_NAK          (512 + nr5g_l2_Srv_SETPARM_CMD)


/*
 * Optional UDG OOB configuration
 */
#define  nr5g_l2_Srv_UDGOOB_CMD          nr5g_l2_Srv_BASE_TYPE + 27
#define  nr5g_l2_Srv_UDGOOB_ACK          (256 + nr5g_l2_Srv_UDGOOB_CMD)
#define  nr5g_l2_Srv_UDGOOB_NAK          (512 + nr5g_l2_Srv_UDGOOB_CMD)


/******************
 * NR CELL MANAGEMENT
 ******************/

#define  nr5g_l2_Srv_OPEN_CELL_CMD      nr5g_l2_Srv_BASE_TYPE + 3
#define  nr5g_l2_Srv_OPEN_CELL_ACK      (256 + nr5g_l2_Srv_OPEN_CELL_CMD)
#define  nr5g_l2_Srv_OPEN_CELL_NAK      (512 + nr5g_l2_Srv_OPEN_CELL_CMD)

/* Optional request of available Cells (User/Net) */
#define  nr5g_l2_Srv_CELL_PPU_LIST_CMD        nr5g_l2_Srv_BASE_TYPE + 4
#define  nr5g_l2_Srv_CELL_PPU_LIST_ACK       (256 + nr5g_l2_Srv_CELL_PPU_LIST_CMD)
#define  nr5g_l2_Srv_CELL_PPU_LIST_NAK       (512 + nr5g_l2_Srv_CELL_PPU_LIST_CMD)

/* Optional cell parameters query (User) */
#define  nr5g_l2_Srv_CELL_PARM_CMD        nr5g_l2_Srv_BASE_TYPE + 5
#define  nr5g_l2_Srv_CELL_PARM_ACK        (256 + nr5g_l2_Srv_CELL_PARM_CMD)
#define  nr5g_l2_Srv_CELL_PARM_NAK        (512 + nr5g_l2_Srv_CELL_PARM_CMD)

/* Optional cell state/configuration query (User) */
#define  nr5g_l2_Srv_CELL_INFO_CMD        nr5g_l2_Srv_BASE_TYPE + 6
#define  nr5g_l2_Srv_CELL_INFO_ACK        (256 + nr5g_l2_Srv_CELL_INFO_CMD)
#define  nr5g_l2_Srv_CELL_INFO_NAK        (512 + nr5g_l2_Srv_CELL_INFO_CMD)

#define  nr5g_l2_Srv_CELL_CONFIG_CMD      nr5g_l2_Srv_BASE_TYPE + 7
#define  nr5g_l2_Srv_CELL_CONFIG_ACK      (256 + nr5g_l2_Srv_CELL_CONFIG_CMD)
#define  nr5g_l2_Srv_CELL_CONFIG_NAK      (512 + nr5g_l2_Srv_CELL_CONFIG_CMD)

/*
 * Release all prev. opened PDCP-Entity on a cell */
#define nr5g_l2_Srv_CELL_PDCP_RELEASE_CMD   nr5g_l2_Srv_BASE_TYPE + 8
#define nr5g_l2_Srv_CELL_PDCP_RELEASE_ACK   (256 + nr5g_l2_Srv_CELL_PDCP_RELEASE_CMD)
#define nr5g_l2_Srv_CELL_PDCP_RELEASE_NAK   (512 + nr5g_l2_Srv_CELL_PDCP_RELEASE_CMD)

/*******************
 * UE MANAGEMENT TODO centralizzare?
 *******************/

#define  nr5g_l2_Srv_CREATE_UE_CMD      nr5g_l2_Srv_BASE_TYPE + 9
#define  nr5g_l2_Srv_CREATE_UE_ACK      (256 + nr5g_l2_Srv_CREATE_UE_CMD)
#define  nr5g_l2_Srv_CREATE_UE_NAK      (512 + nr5g_l2_Srv_CREATE_UE_CMD)

#define  nr5g_l2_Srv_UE_SETATTR_CMD     nr5g_l2_Srv_BASE_TYPE + 22
#define  nr5g_l2_Srv_UE_SETATTR_ACK     (256 + nr5g_l2_Srv_UE_SETATTR_CMD)
#define  nr5g_l2_Srv_UE_SETATTR_NAK     (512 + nr5g_l2_Srv_UE_SETATTR_CMD)

/* Change the cell where an UE is on */
#define  nr5g_l2_Srv_UE_SET_CELL_CMD     nr5g_l2_Srv_BASE_TYPE + 21
#define  nr5g_l2_Srv_UE_SET_CELL_ACK    (256 + nr5g_l2_Srv_UE_SET_CELL_CMD)
#define  nr5g_l2_Srv_UE_SET_CELL_NAK    (512 + nr5g_l2_Srv_UE_SET_CELL_CMD)
 
/*
 * Add a Secondary Cell Group (SCG) to the UE. */
#define  nr5g_l2_Srv_SCG_ADD_CMD      nr5g_l2_Srv_BASE_TYPE + 10
#define  nr5g_l2_Srv_SCG_ADD_ACK      (256 + nr5g_l2_Srv_SCG_ADD_CMD)
#define  nr5g_l2_Srv_SCG_ADD_NAK      (512 + nr5g_l2_Srv_SCG_ADD_CMD)

/*
 * Release a Secondary Cell Group (SCG) of the UE. */
#define  nr5g_l2_Srv_SCG_RELEASE_CMD      nr5g_l2_Srv_BASE_TYPE + 11
#define  nr5g_l2_Srv_SCG_RELEASE_ACK      (256 + nr5g_l2_Srv_SCG_RELEASE_CMD)
#define  nr5g_l2_Srv_SCG_RELEASE_NAK      (512 + nr5g_l2_Srv_SCG_RELEASE_CMD)

/*
 * Release and Add a Secondary Cell Group (SCG) of the UE. */
#define  nr5g_l2_Srv_SCG_REL_AND_ADD_CMD      nr5g_l2_Srv_BASE_TYPE + 12
#define  nr5g_l2_Srv_SCG_REL_AND_ADD_ACK      (256 + nr5g_l2_Srv_SCG_REL_AND_ADD_CMD)
#define  nr5g_l2_Srv_SCG_REL_AND_ADD_NAK      (512 + nr5g_l2_Srv_SCG_REL_AND_ADD_CMD)

/*
 * Trigger handover to target NR cell. */
#define  nr5g_l2_Srv_HANDOVER_CMD      nr5g_l2_Srv_BASE_TYPE + 18
#define  nr5g_l2_Srv_HANDOVER_ACK      (256 + nr5g_l2_Srv_HANDOVER_CMD)
#define  nr5g_l2_Srv_HANDOVER_NAK      (512 + nr5g_l2_Srv_HANDOVER_CMD)

/* I-RAT handover LTE -> NR */
#define  nr5g_l2_Srv_HANDOVER_LTE_TO_NR_CMD    nr5g_l2_Srv_BASE_TYPE + 28
#define  nr5g_l2_Srv_HANDOVER_LTE_TO_NR_ACK    (256 + nr5g_l2_Srv_HANDOVER_LTE_TO_NR_CMD)
#define  nr5g_l2_Srv_HANDOVER_LTE_TO_NR_NAK    (512 + nr5g_l2_Srv_HANDOVER_LTE_TO_NR_CMD)

/* I-RAT handover NR -> LTE */
#define  nr5g_l2_Srv_HANDOVER_NR_TO_LTE_CMD    nr5g_l2_Srv_BASE_TYPE + 29
#define  nr5g_l2_Srv_HANDOVER_NR_TO_LTE_ACK    (256 + nr5g_l2_Srv_HANDOVER_NR_TO_LTE_CMD)
#define  nr5g_l2_Srv_HANDOVER_NR_TO_LTE_NAK    (512 + nr5g_l2_Srv_HANDOVER_NR_TO_LTE_CMD)

#define  nr5g_l2_Srv_PROCEDURE_FAIL_CMD    nr5g_l2_Srv_BASE_TYPE + 30
#define  nr5g_l2_Srv_PROCEDURE_FAIL_ACK    (256 + nr5g_l2_Srv_PROCEDURE_FAIL_CMD)
#define  nr5g_l2_Srv_PROCEDURE_FAIL_NAK    (512 + nr5g_l2_Srv_PROCEDURE_FAIL_CMD)

#define  nr5g_l2_Srv_HANDOVER_SUCC_CMD    nr5g_l2_Srv_BASE_TYPE + 31
#define  nr5g_l2_Srv_HANDOVER_SUCC_ACK    (256 + nr5g_l2_Srv_HANDOVER_SUCC_CMD)
#define  nr5g_l2_Srv_HANDOVER_SUCC_NAK    (512 + nr5g_l2_Srv_HANDOVER_SUCC_CMD)

/* Indicate re-establish procedure phase 1 (Suspend and New Target Cell Indication) */
#define  nr5g_l2_Srv_REEST_PREPARE_CMD    (nr5g_l2_Srv_BASE_TYPE + 26)
#define  nr5g_l2_Srv_REEST_PREPARE_ACK    (256 + nr5g_l2_Srv_REEST_PREPARE_CMD)
#define  nr5g_l2_Srv_REEST_PREPARE_NAK    (512 + nr5g_l2_Srv_REEST_PREPARE_CMD)

/* Indicate re-establish procedure phase 1 (Suspend and New Target Cell Indication) */
#define  nr5g_l2_Srv_REEST_1_CMD    (nr5g_l2_Srv_BASE_TYPE + 23)
#define  nr5g_l2_Srv_REEST_1_ACK    (256 + nr5g_l2_Srv_REEST_1_CMD)
#define  nr5g_l2_Srv_REEST_1_NAK    (512 + nr5g_l2_Srv_REEST_1_CMD)

/* Indicate re-establish procedure phase 2 (reestablish of SRB1) */
#define  nr5g_l2_Srv_REEST_2_CMD    (nr5g_l2_Srv_BASE_TYPE + 24)
#define  nr5g_l2_Srv_REEST_2_ACK    (256 + nr5g_l2_Srv_REEST_2_CMD)
#define  nr5g_l2_Srv_REEST_2_NAK    (512 + nr5g_l2_Srv_REEST_2_CMD)

/* Indicate re-establish procedure phase 3 (reestablish of SRB2 and DRBs) */
#define  nr5g_l2_Srv_REEST_3_CMD    (nr5g_l2_Srv_BASE_TYPE + 25)
#define  nr5g_l2_Srv_REEST_3_ACK    (256 + nr5g_l2_Srv_REEST_3_CMD)
#define  nr5g_l2_Srv_REEST_3_NAK    (512 + nr5g_l2_Srv_REEST_3_CMD)

/*
 * Configuration of Radio Condition profile 
 */
#define nr5g_l2_Srv_RCP_LOAD_CMD nr5g_l2_Srv_BASE_TYPE + 13
#define nr5g_l2_Srv_RCP_LOAD_ACK (256 + nr5g_l2_Srv_RCP_LOAD_CMD)
#define nr5g_l2_Srv_RCP_LOAD_NAK (512 + nr5g_l2_Srv_RCP_LOAD_CMD)

#define nr5g_l2_Srv_RCP_LOAD_END_CMD nr5g_l2_Srv_BASE_TYPE + 14
#define nr5g_l2_Srv_RCP_LOAD_END_ACK (256 + nr5g_l2_Srv_RCP_LOAD_END_CMD)
#define nr5g_l2_Srv_RCP_LOAD_END_NAK (512 + nr5g_l2_Srv_RCP_LOAD_END_CMD)

#define nr5g_l2_Srv_RCP_CLOSE_CMD nr5g_l2_Srv_BASE_TYPE + 15
#define nr5g_l2_Srv_RCP_CLOSE_ACK (256 + nr5g_l2_Srv_RCP_CLOSE_CMD)
#define nr5g_l2_Srv_RCP_CLOSE_NAK (512 + nr5g_l2_Srv_RCP_CLOSE_CMD)

#define nr5g_l2_Srv_RCP_CMD  nr5g_l2_Srv_BASE_TYPE + 16
#define nr5g_l2_Srv_RCP_ACK  (256 + nr5g_l2_Srv_RCP_CMD)
#define nr5g_l2_Srv_RCP_NAK  (512 + nr5g_l2_Srv_RCP_CMD)

#define nr5g_l2_Srv_RCP_UECFG_CMD (nr5g_l2_Srv_BASE_TYPE + 17)
#define nr5g_l2_Srv_RCP_UECFG_ACK (256 + nr5g_l2_Srv_RCP_UECFG_CMD)
#define nr5g_l2_Srv_RCP_UECFG_NAK (512 + nr5g_l2_Srv_RCP_UECFG_CMD)

#define nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD    (nr5g_l2_Srv_BASE_TYPE + 19)
#define nr5g_l2_Srv_RCP_UE_SET_GROUP_ACK    (nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD | TYPE_ACK)
#define nr5g_l2_Srv_RCP_UE_SET_GROUP_NAK    (nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD | TYPE_NAK)

#define nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD    (nr5g_l2_Srv_BASE_TYPE + 20)
#define nr5g_l2_Srv_RCP_UE_SET_INDEX_ACK    (nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD | TYPE_ACK)
#define nr5g_l2_Srv_RCP_UE_SET_INDEX_NAK    (nr5g_l2_Srv_RCP_UE_SET_INDEX_CMD | TYPE_NAK)

/*********************************************
 * STRUCT
 *********************************************/

typedef struct {
    ushort  phy_cell_id;    /* physical cell identifier [0] */
    uint    dlFreq[2];      /* 0 not found, 1st freq rf,2nd freq udc [kHz] */
    uint    dlEarfcn[2];    /* 0 not found, 1st arfcn rf,2nd arfcn udc [kHz] */
    uint    ulFreq[2];      /* 0 not found, 1st freq rf,2nd freq udc [kHz] */
    uint    ulEarfcn[2];    /* 0 not found, 1st arfcn rf,2nd arfcn udc [kHz] */
    uint    SsbArfcn;       /* ARFCN of cell (-1 not available) */
} nr5g_l2_Srv_Cell_Parm_t;

typedef struct {
// TODO parametri dipendenti da Lower Layer.
    uint Spare;
} nr5g_l2_Srv_Cell_State_t;

typedef struct {
    comgen_qnxPPUIDt  Ppu;
    uint16_t          DbeamId;
} nr5g_l2_Srv_Dbeam_t;


typedef struct {
    comgen_qnxPPUIDt  Ppu;
    uint16_t          DbeamId;
    lte_l2_Srv_UDP_Parm_t   Udp;    /* UDP transport parameters */
} nr5g_l2_Srv_L1Sim_Dbeam_t;

#define nr5g_l2_Srv_L1Sim_MaxDb (4)
typedef struct {
    uchar                       CellId;
    uint                        NumDbeam;
    nr5g_l2_Srv_L1Sim_Dbeam_t   Dbeam[nr5g_l2_Srv_L1Sim_MaxDb]; /* Simulated Dbeam */
} nr5g_l2_Srv_CellL1Sim_t;

/*********************************************
 * nr5g_l2_Srv_CFG_CMD
 *********************************************/

/* This type must be used in case LTE is not configured. */
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


/* This type must be used in case LTE is configured. */
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
} nr5g_l2_Srv_CFG_02t;

/*
 * NOTES (for nr5g_l2_Srv_CFG_CMD)
 *
 * (1) This field is intended for future expansion of the parameter set.
 *
 *      Currently choices are:
 *      
 *      Type        Primitive format
 *      -----------------------------------------------------
 *      1           nr5g_l2_Srv_CFG_01t
 *      2           nr5g_l2_Srv_CFG_02t
 *
 * (17)
 *   Technology to be simulated lte_nr5g_tm_l2_Srv_LTE or lte_nr5g_tm_l2_Srv_NR or 
 *      (nr5g_l2_Srv_LTE | nr5g_l2_Srv_NR)
 *
 * (18) ENbSim.
 *      nr5g_l2_Srv_ENBSIM_00:    Deactivated.
 *      
 *      nr5g_l2_Srv_ENBSIM_01:    Simulation type 1.
 *
 *          In this mode LTE Uu radio is not present.
 *          LTE cells don't really exist, and don't need a configuration.
 *          PDCP is activated only when a real NR5G radio is present. 
 *
 * (19) Peer acknowledge is not mandatory, primitive is successfully completed
 *      on peer ack or anyway at the end of retransmission phases (if any)
 *
 * (20) In case the variable is enabled, the system should try to survive
 *      as long as possible, trying to recover automatically the major errors, 
 *      in order to achieve the test duration target.
 *
 *      In case the variable is disabled, the simulation is stopped as soon as a 
 *      major error is detected to freeze the memory when the error occurred and 
 *      make the analysis possible. 
 *
 * (21) Bot layer bit field
 *  bits 7..4   NR Bot layer      nr5g_BOT_*
 *  bits 3..0   LTE Bot Layer     lte_BOT_*
 *  Backward compatibility: if (NR Bot layer == 0)  NR Bot layer = LTE Bot layer 
 */

/*********************************************
 * nr5g_l2_Srv_SETPARM_CMD
 *********************************************/
#define nr5g_l2_Srv_SETPARM_01          1
#define nr5g_l2_Srv_SETPARM_L1SIM_01    2
#define nr5g_l2_Srv_SETPARM_02          3
#define nr5g_l2_Srv_SETPARM_L1SIM_02    4
#define nr5g_l2_Srv_SETPARM_L1SIM_03    5
#define nr5g_l2_Srv_SETPARM_L1SIM_04    6
#define nr5g_l2_Srv_SETPARM_03          7

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
} nr5g_l2_Srv_SETPARM_L1SIM_01t;

/*
 * nr5g_l2_Srv_SETPARM_L1SIM_02t:
 * - compare to nr5g_l2_Srv_SETPARM_L1SIM_01t includes:
 * LteCellIdList[] with NumLteCell
 * - compare to nr5g_l2_Srv_SETPARM_02t does not include:
 * NrCellIdList[] NrProPpu[] with NumNrCell and NumNrProPpu
 * info included in CellL1Sim[] with Dbeams[].
*/
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
    
    uchar   Spare1[3];            /* Reserved set to 0 */
#define nr5g_l2_Srv_DL_HARQ_OFF         (0)  /* DL HARQ is off (no feedback is sent to peer) */
#define nr5g_l2_Srv_DL_HARQ_L1          (1)  /* the DL HARQ feedback are handled autonomously by L1 */
#define nr5g_l2_Srv_DL_HARQ_L2_DCI      (2)  /* the DL HARQ feedback are handle by L2 immediately
                                                after a downlink grant reception */
#define nr5g_l2_Srv_DL_HARQ_L2_PDSCH    (3)  /* the DL HARQ feedback are handle by L2 process
                                                after the pdsch reception.
                                                In case no pdsch received default NACK is sent. */
#define nr5g_l2_Srv_DL_HARQ_SMART       (4)  /* the DL HARQ feedback are handle by L2 process
                                                after the pdsch reception.
                                                In case no pdsch received default ACK is sent. */
    uchar   DlHarqMode;           /* see nr5g_l2_Srv_DL_HARQ_* above; default=nr5g_l2_Srv_DL_HARQ_L2_DCI */
#define nr5g_l2_Srv_MEAS_MODE_PRIM      (0) /* measurement set feeded */
#define nr5g_l2_Srv_MEAS_MODE_CSV       (1) /* AMM csv feeded (not yet implemented) */
#define nr5g_l2_Srv_MEAS_MODE_REAL      (2) /* real measurements (field mode) */
    uchar   MeasMode;             /* see nr5g_l2_Srv_MEAS_MODE_* above; default=nr5g_l2_Srv_MEAS_MODE_PRIM */
    uchar   UlFsAdvance;          /* Uplink frame sync adavance in OFDM symbols (0xff means an optimal value is choosen by the software); default=0xff */
    char    DeltaNumLdpcIteration;     /* Provides a difference to be applied to the optimal LDPC iteration value selected by the software 
                                                (-5 .. 5) (0xff means no difference is applied) */
    uchar   NumStkPpu;                  /* Number of elements of StkPpu[] list */
    uchar   NumLteCell;
    comgen_qnxPPUIDt  StkPpu[];         /* PPU list where put the stack processes (higher level) (12) */
/*  uchar   LteCellIdList[]; */             /* Start of the list of LTE cell's CellId  */
/*  nr5g_l2_Srv_CellL1Sim_t CellL1Sim[]; */ /* Cell parameters for L1Sim connection */
} nr5g_l2_Srv_SETPARM_L1SIM_02t;

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

    // NET-BB Simulator parameters START (configured by TSTM UU and propagated by L2 to NET-BB Simulator)
#define nr5g_l2_Srv_NET_BB_SIM_NO_PEER  (0)
#define nr5g_l2_Srv_NET_BB_SIM_UDP_PEER (1)
#define nr5g_l2_Srv_NET_BB_SIM_MEM_PEER (2)
    uchar   NetBbSim;                      // see nr5g_l2_Srv_NET_BB_SIM_* above; default=nr5g_l2_Srv_NET_BB_SIM_NO_PEER
    uint    NetBbSim_FrameSyncPeriod;      // Values: 0 or 0xffffffff (500 microseconds), 125 (125 microseconds)... Default: 0
    uint    NetBbSim_TbSegmented;          // Values: 0 (TB in 1 segment) 1 (TB in more segments) Default: 0
    uint    NetBbSim_UlGrant_Slot[3];      // 80 Slots used for uplink grant:   0xeeeeeeee 0xeeeeeeee 0xeeee means slots 1,2,3 5,6,7 9,10,11 ... Default: 0 0 0 = 0xaaaaaaaa 0xaaaaaaaa 0xaaaa
    uint    NetBbSim_DlGrant_Slot[3];      // 80 Slots used for downlink grant: 0xeeeeeeee 0xeeeeeeee 0xeeee means slots 1,2,3 5,6,7 9,10,11 ... Default: 0 0 0 = 0xaaaaaaaa 0xaaaaaaaa 0xaaaa
    uint    NetBbSim_Drop;                 // Values: 0 (no drop), 10000 (1 dropped, 10000 no dropped), 1000 (1 dropped, 1000 no dropped)... Default: 0
    uint    NetBbSim_DebugFlags;           // Transparent value propagated from TSTM to L2. Default: 0
    uint    Spare[20];
    // NET-BB Simulator parameters END

    uchar   Spare1[2];            /* Reserved set to 0 */
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
    uchar   NumStkPpu;                  /* Number of elements of StkPpu[] list */
    uchar   NumLteCell;
    comgen_qnxPPUIDt  StkPpu[];         /* PPU list where put the stack processes (higher level) (12) */
/*  uchar   LteCellIdList[]; */             /* Start of the list of LTE cell's CellId  */
/*  nr5g_l2_Srv_CellL1Sim_t CellL1Sim[]; */ /* Cell parameters for L1Sim connection */
} nr5g_l2_Srv_SETPARM_L1SIM_03t;

/* struct for 5G NSA */
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
    
    uchar   HostInterfaceId;       /* See nr5g_l2_Srv_HOST_ID_*/
    uchar   Spare1[2];            /* Reserved set to 0 */
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
    uchar   NumStkPpu;                  /* Number of elements of StkPpu[] list */
    uchar   NumLtePpu;              /* Num of lte_l2_Srv_InstParmUdp_t */
    uchar   NumNrCell;
    comgen_qnxPPUIDt  StkPpu[];         /* PPU list where put the stack processes (higher level) (12) */
/*  lte_l2_Srv_InstParmUdp_t LtePPuL1Sim[]; */             /* Ppu parameters for LTE L1Sim connection including LTE Cell parameters  */
/*  nr5g_l2_Srv_CellL1Sim_t CellL1Sim[]; */ /* Cell parameters for NR L1Sim connection */
} nr5g_l2_Srv_SETPARM_L1SIM_04t;


#define   nr5g_l2_Srv_HOST_ID_INTERNAL   0
#define   nr5g_l2_Srv_HOST_ID_MODE_A     1
#define   nr5g_l2_Srv_HOST_ID_MODE_PRT   2
#define   nr5g_l2_Srv_HOST_ID_MODE_NFAPI 3


/* This type must be used in case LTE is not configured. */
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
    
    uint    Spare[1];             /* Reserved set to 0 */
    uchar   NumStkPpu;            /* Number of elements of StkPpu[] list */
    uchar   NumProPpu;            /* Number of elements of ProPpu[] list */
    comgen_qnxPPUIDt StkPpu[];    /* PPU list where put the nr5g.stk processes (12) */
/*  comgen_qnxPPUIDt ProPpu[]; */ /* PPU list where put the nr5g-l2.pro processes (13) */
/*  uchar   CellId[]; */          /* Start of the list of cell's CellId which
                                   * will be used in the test */
} nr5g_l2_Srv_SETPARM_01t;


/* This type must be used in case LTE is configured. */
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

/* This type must be used in case LTE and/or NR  is configured. */
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
    char    DeltaNumLdpcIteration; /* Number of LDPC iterations (0xff means an optimal value is choosen by the software); default=0xff */
    uchar   DlSoftCombining;      /* DL HARQ soft combining algorithm enabled (1) or disabled (0). Def=0 */
    uchar   MaxRach;              /* Maximum number of preambles per slot, Def=8 */
    uchar   LteDlHarqMode;        /* see nr5g_l2_Srv_DL_HARQ_* above; default=nr5g_l2_Srv_DL_HARQ_L2_DCI (no nr5g_l2_Srv_DL_HARQ_SMART)*/
    uchar   PdcchType;            /* PDCCH type bitmask
                                         bit 0: PDCCH type 0 (1 CCE)
                                         bit 1: PDCCH type 1 (2 CCEs)
                                         bit 2: PDCCH type 2 (4 CCEs)
                                         bit 3: PDCCH type 3 (8 CCEs)
                                      default = 15*/
    uchar   CatmEnable;           /* Enable CatM support; values = 0/1; default=1 */
    uchar   LteDlSoftCombining;   /* LTE DL HARQ soft combining algorithm enabled (1) or disabled (0). Def=0 */
    uchar   SpareC[3];            /* set to zero */
    uint    Spare[18];            /* set to zero */

    uchar   NumUpStkPpu;          /* Number of elements of UpStkPpu[] list */
    uchar   NumDwnStkPpu;         /* Number of elements of DWnStkPpu[] list */
    uchar   NumLteProPpu;         /* Number of elements of LteProPpu[] list (in case of LTE/DSP set to 0)*/
    uchar   NumNrProPpu;          /* Number of elements of NrProPpu[] list */
    uchar   NumLteCell;
    uchar   NumNrCell;
    comgen_qnxPPUIDt UpStkPpu[];    /* PPU list where put the lte.stk.up processes (12) */
/*  comgen_qnxPPUIDt DwnStkPpu[]; */ /* PPU list where put the lte.stk.dwn processes (12) */
/*  comgen_qnxPPUIDt LteProPpu[]; */ /* PPU list where put the lte-l2.pro processes (13) */
/*  comgen_qnxPPUIDt NrProPpu[]; */ /* PPU list where put the nr5g-l2.pro processes (13) */
/*  uchar   LteCellIdList[]; */   /* Start of the list of LTE cell's CellId  */
/*  uchar   NrCellIdList[];  */   /* Start of the list of NR5G cell's CellId */
} nr5g_l2_Srv_SETPARM_03t;


/*
 * NOTES
 *
 * This primitive is optional; if not issued, the default value
 * shall be assumed for each parameter.
 *
 * (1) This field is intended for future expansion of the parameter set.
 *
 *      Currently choices are:
 *      
 *      Type        Primitive format
 *      -----------------------------------------------------
 *      1             nr5g_l2_Srv_SETPARMt
 *      2             nr5g_l2_Srv_SETPARM_L1SIM_01t
 *      3             nr5g_l2_Srv_SETPARM_02t
 *      4             nr5g_l2_Srv_SETPARM_L1SIM_02t
 *      7             nr5g_l2_Srv_SETPARM_03t
 *     
 *     Type == 1 MUST be used if "BotLayer" in CFG primitive is set to
 *     "nr5g_BOT_PDCP" or "nr5g_BOT_RLCMAC".
 *
 * (2) A value of zero means default.
 *
 * (3) The maximum number of Node B resources (default 1).
 *
 * (4) The maximum number of UE's to simulate (default 1).
 *
 * (6) The maximum number of PDCP entity to simulate (default 1).
 *
 * (7) The maximum number of NAT entity to handle (default 1).
 *     May be up to MaxPdcp
 *
 * (8) The maximum number of UDG entity to simulate (default 1).
 *     Differ from MaxPdcp on multisession scenarios
 *
 * (9) The maximum number of CNTR entity to handle (default 1).
 *
 * (10) Primitive valid only on NET side.
 *
 * (11) Debug Mode.
 *     nr5g_l2_Srv_DEBUG_MODE_NONE:     Debug mode not active.
 *     nr5g_l2_Srv_DEBUG_MODE_SIM_NET:  Support the fully simulated net.
 *
 * (12) The Client can load one process on
 *      each PPU/CPU (from here we call it PPU).
 *      PPUs are indicated in a variable length list.
 *      StkPpu[0] is the PPU number where to load instance 0 of the processes
 *      (this is mandatory).
 *      StkPpu[1..NumPpu] are optional; when present, they specify where
 *      to load instances 1..NumPpu of processes; they can be also set to special 
 *      value -1 (0xFF) indicating no association and end of PPU list.
 *      StkPpu[x] can be `lsuPPU(n)'.
 *
 * (13) The Client can load one process on
 *      each PPU/CPU (from here we call it PPU).
 *      PPUs are indicated in a variable length list.
 *      *Ppu[0] is the PPU number where to load instance 0 of the processes
 *      (this is mandatory).
 *      *Ppu[1..NumPpu] are optional; when present, they specify where
 *      to load instances 1..NumPpu of processes; they can be also set to special 
 *      value -1 (0xFF) indicating no association and end of PPU list.
 *      *Ppu[x] can be `lsuPPU(n)'.
 *
 */


/*****************************
 * RADIO CONDITION MANAGEMENT
 *****************************/


/*
 * Configuration of Radio Condition profile 
 * (use after START)
 */
/* TODO */

/*********************************************
 * nr5g_l2_Srv_UDGOOB_CMD
 *********************************************/

typedef struct
{
    int Flags;            // 1=ONv4,0=Off

    int NetSigPort;       // Net Signaling UDP port [should be well known one] set 0=DEF
    int NetSub,NetPrefix; // NUDG standard subnet (All NetIP should live here)
    int SigSub,SigPrefix; // SigPrefix should be equal to (NetPrefix-1) and all SigIp should live in
                          // SigSub/SigPrefix but not in SigSub/NetPrefix

    uchar   NrOfInst;     /* Number on stack instances */
    struct nr5g_l2_Srv_OOB_ELEM {
        int SigIp;        // UUDG Signaling IP for each lte.stk instance
        int SigPort;      // Optional (Set 0=DEF)
    } Uu[];

} nr5g_l2_Srv_UDGOOBt;

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


/*********************************************
 * nr5g_l2_Srv_CELL_PARM_CMD
 *********************************************/

typedef struct
{
    uchar       CellId;       /* Cell Identifier */
} nr5g_l2_Srv_CELL_PARM_CMDt;

typedef struct
{
    uchar                      CellId;             /* Cell Identifier */
    nr5g_l2_Srv_Cell_Parm_t    Parm;               /* Cell parameters */
    uint                       NumDbeam;           /* # of Dbeam for this cell */
    nr5g_l2_Srv_Dbeam_t        Dbeam[nr5g_MaxDbeam]; /* Dbeam List */
} nr5g_l2_Srv_CELL_PARM_ACKt;

/*********************************************
 * nr5g_l2_Srv_CELL_INFO_CMD
 *********************************************/

typedef struct
{
    uchar       CellId;       /* Cell Identifier */
    
} nr5g_l2_Srv_CELL_INFO_CMDt;

typedef struct
{
    uchar                    CellId; /* Cell Identifier */
    nr5g_l2_Srv_Cell_State_t State;  /* Cell State */
    
} nr5g_l2_Srv_CELL_INFO_ACKt;

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
    nr5g_rlcmac_Cmac_RA_Info_t    RA_Info;
    
    /* cell configuration */
    
    nr5g_rlcmac_Cmac_CellCfg_t     CellCfg;
    
} nr5g_l2_Srv_CELL_CONFIGt;


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

/*
 * NOTES
 * (1) This is a value assigned by the client and is used
 *     to uniquely identify the UE.
 *     It shall be in the range 0..(MaxUe-1) where MaxUe is
 *     defined in lte_l2_Srv_SETPARMt or lte_l2_Srv_SETPARM_UDPt.
 *     
 * (2) If log client (e.g. wireshark) has logging enabled
 *     for selected UEs only UEs with Log Ue Flag set will be
 *     logged.
 *     
 * (3) This controls the stack process where the UE is located.
 *  if split is abled UdgStkInst is instance of UDG, StkInst is instance of PDCP
 *  if split isn't abled UdgStkInst isn't used , StkInst is instance of PDCP/UDG
 */

/*********************************************
 * nr5g_l2_Srv_UE_SETATTR_CMD
 *********************************************/

typedef struct
{
    uint            UeId;           /* Ue Identifier (1) */
    uint            CellId;         /* Cell Identifier */
    uchar           ImsiLen;        /* IMSI oct. 2    (GSM 4.08-10.5.1.4) */
    uchar           Imsi [9];       /* IMSI oct. 3-11 (GSM 4.08-10.5.1.4) */
} nr5g_l2_Srv_UE_SETATTRt;

/*********************************************
 * nr5g_l2_Srv_UE_SET_CELL_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    CellId;          /* Cell Identifier */
} nr5g_l2_Srv_UE_SET_CELLt;

/*********************************************
 * nr5g_l2_Srv_SCG_ADD_CMD
 *********************************************/

typedef struct
{
    uint            UeId;           /* Ue Identifier */
    uint            CellId;         /* Cell Identifier */
#define nr5g_l2_Srv_SCG_NR   1
    uint            ScgType;        /* SCG type, nr5g_l2_Srv_SCG_* (1a) */
} nr5g_l2_Srv_SCG_ADDt;

/*********************************************
 * nr5g_l2_Srv_SCG_RELEASE_CMD
 *********************************************/

typedef struct
{
    uint            UeId;           /* Ue Identifier */
    uint            CellId;         /* Cell Identifier */
} nr5g_l2_Srv_SCG_RELEASEt;

/*********************************************
 * nr5g_l2_Srv_SCG_REL_AND_ADD_CMD
 *********************************************/

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

/*
 * NOTES
 * 
 * (1a) Type of SCG added.
 *
 * (2a) The configuration is applied on the cell added.
 */

/*********************************************
 * nr5g_l2_Srv_HANDOVER_CMD
 *********************************************/

typedef nr5g_l2_Srv_SCG_REL_AND_ADDt nr5g_l2_Srv_HANDOVERt;
/*
 * NOTES
 * 
 * (1a) This field is ignored.
 *
 * (2a) The configuration is applied on the target cell.
 */

/*********************************************
 * nr5g_l2_Srv_HANDOVER_LTE_TO_NR_CMD
 *********************************************/

typedef struct
{
    uint    UeId;                /* UE Identifier */
    uint    OrigLteCellId;       /* Cell Identifier (LTE cell) */
    uint    TargNrCellId;        /* Cell Identifier (NR cell) */
    uchar   drb_ContinueROHC;    /* drb-ContinueROHC (1) 
                                    [ 0 means 'not configured/false' 
                                      !=0 means 'true' ] */
    uint    MacConfigLen;        /* Length of (NR) MacConfig field */
    nr5g_rlcmac_Cmac_CONFIG_CMD_t   MacConfig; /* MAC configuration, see nr5g-rlcmac_Cmac.h */
} nr5g_l2_Srv_HANDOVER_LTE_TO_NRt;

/*
 * NOTES
 * 
 * (1) see 38.323 and 38.331
 */

/*********************************************
 * nr5g_l2_Srv_HANDOVER_NR_TO_LTE_CMD
 *********************************************/

typedef struct
{
    uint    UeId;                /* UE Identifier */
    uint    OrigNrCellId;        /* Cell Identifier (NR cell) */
    uint    TargLteCellId;       /* Cell Identifier (LTE cell) */
    uchar   drb_ContinueROHC;    /* drb-ContinueROHC (1) 
                                    [ 0 means 'not configured/false' 
                                      !=0 means 'true' ] */
    lte_l2_Srv_RntiCfg CrntiCfg; /* Configured C-RNTI on Target Cell */
    uint    MacConfigLen;     /* Length of MacConfig field */
    lte_rlcmac_Cmac_CONFIG_CMD_t   MacConfig; /* LTE MAC configuration, see lte-rlcmac_Cmac.h */
} nr5g_l2_Srv_HANDOVER_NR_TO_LTEt;

/*
 * NOTES
 * 
 * (1) see 36.323 and 36.331
 */

/*********************************************
 * nr5g_l2_Srv_PROCEDURE_FAIL_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    OrigCellId;      /* Originating Cell Identifier */
    uint    TargCellId;      /* Target Cell Identifier      */
} nr5g_l2_Srv_PROCEDURE_FAILt;

/*********************************************
 * nr5g_l2_Srv_HANDOVER_SUCC_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    OrigCellId;      /* Originating Cell Identifier */
    uint    TargCellId;      /* Target Cell Identifier */
} nr5g_l2_Srv_HANDOVER_SUCCt;

/*********************************************
 * nr5g_l2_Srv_REEST_PREPARE_CMD
 *********************************************/
#define nr5g_l2_Srv_NUM_PDCP_ACTION  32
typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    NumPdcpAction;
    nr5g_pdcp_Com_Action_t    PdcpAction[nr5g_l2_Srv_NUM_PDCP_ACTION];
} nr5g_l2_Srv_REEST_PREPAREt;

/*********************************************
 * nr5g_l2_Srv_REEST_1_CMD
 *********************************************/
typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    OrigCellId;      /* Originating Cell Identifier */
    uint    TargCellId;      /* Target Cell Identifier */
} nr5g_l2_Srv_REEST_1_CMDt;

/*********************************************
 * nr5g_l2_Srv_REEST_2_CMD
 *********************************************/
typedef struct
{
    uint    UeId;           /* UE Identifier */
} nr5g_l2_Srv_REEST_2_CMDt;

/*********************************************
 * nr5g_l2_Srv_REEST_3_CMD
 *********************************************/
typedef struct
{
    uint    UeId;           /* UE Identifier */
} nr5g_l2_Srv_REEST_3_CMDt;

/*********************************************
 * nr5g_l2_Srv_CELL_PDCP_RELEASE_CMD
 *********************************************/

/*
This primitive is used to request for release of all PDCP on a given cell.
*/
typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
} nr5g_l2_Srv_CELL_PDCP_RELEASEt;

/*********************************************
 * nr5g_l2_Srv_RCP_LOAD_CMD
 *********************************************/
typedef struct
{
    uint       RcGroup;        /* Radio Condition Group (1) */
    uint       CellId;         /* Cell Identifier */
    uint       DbeamId;        /* Dbeam Identifier */
    char       Fname[];        /* Path/Filename as ASCIIZ string of profile file */

} nr5g_l2_Srv_RCP_LOADt;

/*********************************************
 * nr5g_l2_Srv_RCP_LOAD_END_CMD
 *********************************************/
typedef struct
{
    uint       Spare;

} nr5g_l2_Srv_RCP_LOAD_ENDt;

/*********************************************
 * nr5g_l2_Srv_RCP_CLOSE_CMD
 *********************************************/
typedef struct
{
    uint       Spare;  /* Radio Condition Group */

} nr5g_l2_Srv_RCP_CLOSEt;

/*********************************************
 * nr5g_l2_Srv_RCP_UECFG_CMD
 *********************************************/
typedef struct
{
    uint RcGroup; /* Radio Condition Group */
    uint NumUePerRcGroup;   /* it's assumed to be 1 */
    uint UeIdRcGroup[0]; /* UeId array */

} nr5g_l2_Srv_RCP_UECFGt;

/*********************************************
 * nr5g_l2_Srv_RCP_CMD
 *********************************************/
typedef struct
{
    uint UeId; /* Ue Identifier */
    uint RcpIdx; /* Radio Condition Profile Index */

} nr5g_l2_Srv_RCP_INFOt;

typedef struct
{
    uint NumRcpInfo;    /* it's assumed to be 1 */
    nr5g_l2_Srv_RCP_INFOt RcpInfo[0];

} nr5g_l2_Srv_RCPt;

/*********************************************
 * nr5g_l2_Srv_RCP_ACK/NACK
 *********************************************/
typedef struct
{
    uint UeId; /* Ue Identifier */
    uint Info; /* Info -> RcpIdx if nr5g_l2_Srv_RCP_CMD, RcGroup if nr5g_l2_Srv_RCP_UECFG_CMD */
    int Err;   /* Error code (0 -> No Error) */

} nr5g_l2_Srv_RCP_ACKt;

/*********************************************
 * nr5g_l2_Srv_RCP_UE_SET_GROUP_CMD
 *********************************************/

typedef struct
{
    uint UeId;      /* Ue Identifier */
    uint Group;     /* Radio Condition Group */
} nr5g_l2_Srv_RCP_UE_SET_GROUPt;

/*********************************************
 * nr5g_l2_Srv_RCP_UE_SET_IDX_CMD
 *********************************************/

typedef struct
{
     uint UeId;     /* Ue Identifier */
     uint Index;    /* Radio Condition Profile Index */
} nr5g_l2_Srv_RCP_UE_SET_INDEXt;



/********************************************************************
 * The union of all messages
 ********************************************************************/

union nr5g_l2_Srv_MSGu
{
    nr5g_l2_Srv_CFG_01t           Cfg01;
    
    nr5g_l2_Srv_UDGOOBt           UdgOOB;
    
    nr5g_l2_Srv_OPEN_CELLt        OpenCell;

    nr5g_l2_Srv_CELL_PPU_LIST_ACKt    CellPpuListAck;

    nr5g_l2_Srv_CELL_PARM_CMDt    CellParmCmd;
    nr5g_l2_Srv_CELL_PARM_ACKt    CellParmAck;

    nr5g_l2_Srv_CELL_INFO_CMDt    CellInfoCmd;
    nr5g_l2_Srv_CELL_INFO_ACKt    CellInfoAck;
    
    nr5g_l2_Srv_CELL_CONFIGt      CellConfigCmd;

    nr5g_l2_Srv_CREATE_UEt        CreateNrUe;
    nr5g_l2_Srv_UE_SETATTRt       UeSetAttr;
    nr5g_l2_Srv_UE_SET_CELLt      UeSetCell;
    nr5g_l2_Srv_SCG_ADDt          ScgAdd;
    nr5g_l2_Srv_SCG_RELEASEt      ScgRelease;
    nr5g_l2_Srv_SCG_REL_AND_ADDt  ScgRelAndAdd;
    nr5g_l2_Srv_HANDOVERt         Handover;
    nr5g_l2_Srv_HANDOVER_NR_TO_LTEt  HandoverNrToLte;
    nr5g_l2_Srv_HANDOVER_LTE_TO_NRt  HandoverLteToNr;
    nr5g_l2_Srv_PROCEDURE_FAILt   ProcedureFail;
    nr5g_l2_Srv_HANDOVER_SUCCt    HandoverSucc;
    nr5g_l2_Srv_REEST_PREPAREt    ReestPrepare;
    nr5g_l2_Srv_REEST_1_CMDt      Reest1Cmd;
    nr5g_l2_Srv_REEST_2_CMDt      Reest2Cmd;
    nr5g_l2_Srv_REEST_3_CMDt      Reest3Cmd;

    nr5g_l2_Srv_CELL_PDCP_RELEASEt CellPdcpReleaseCmd;

    nr5g_l2_Srv_RCP_LOADt        RcpLoadCmd;
    nr5g_l2_Srv_RCP_LOAD_ENDt    RcpLoadEndCmd;
    nr5g_l2_Srv_RCP_CLOSEt       RcpCloseCmd;
    nr5g_l2_Srv_RCPt             RcpCmd;
    nr5g_l2_Srv_RCP_UECFGt       RcpUeCfgCmd;
    nr5g_l2_Srv_RCP_ACKt         RcpAck;

    nr5g_l2_Srv_RCP_UE_SET_GROUPt RcpUeSetGroupCmd;
    nr5g_l2_Srv_RCP_UE_SET_INDEXt RcpUeSetIndexCmd;

};


#pragma    pack()
#endif
