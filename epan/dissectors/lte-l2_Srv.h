/********************************************************************
$Source$
$Author: rohgomes $
$Date: 2021/09/05 $
---------------------------------------------------------------------
Project :       LTE SERVER
Description :   The CLIENT INTERFACE - lte_l2_Srv.h
---------------------------------------------------------------------
$Revision: #1 $
$State$
$Name$
---------------------------------------------------------------------
$Log$
*********************************************************************/

#ifndef  lte_l2_Srv_DEFINED
#define  lte_l2_Srv_DEFINED

//#include "qnx_gen.h"
#include "lte.h"
#include "lte-rlcmac_Cmac.h"
#include "lte-pdcp_Com.h"
#include "nr5g-rlcmac_Cmac.h"

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
#define     lte_l2_Srv_VERSION       "1.33.0"

/*
 * The default TCP Port
 */
#define     lte_l2_Srv_PORT          5130

/*
 * Max client message length
 */
#define     lte_l2_Srv_MSGSIZE       (22*1024)


#define TYPE_ACK	0x0100
#define TYPE_NAK	0x0200



/********************************************************************
 * ERROR SAP Message Types
 ********************************************************************/

#define  lte_l2_Srv_ERROR_IND        1025    /* Error indication */
#define  lte_l2_Srv_REJECT_IND       1026    /* Message rejected */


/********************************************************************
 * OM SAP Message Types
 ********************************************************************/


/*******************
 * LOGIN and SETUP
 *******************/

/*
 * Mandatory Login
 */
#define  lte_l2_Srv_LOGIN_CMD            1
#define  lte_l2_Srv_LOGIN_ACK            (256 + lte_l2_Srv_LOGIN_CMD)
#define  lte_l2_Srv_LOGIN_NAK            (512 + lte_l2_Srv_LOGIN_CMD)


/*
 * Alternative mandatory Login
 */
#define  lte_l2_Srv_LOGIN_ZOT_CMD        100
#define  lte_l2_Srv_LOGIN_ZOT_ACK        (256 + lte_l2_Srv_LOGIN_ZOT_CMD)
#define  lte_l2_Srv_LOGIN_ZOT_NAK        (512 + lte_l2_Srv_LOGIN_ZOT_CMD)


/*
 * CONFIGURE STARTUP
 */
/* Config. primitive */
#define  lte_l2_Srv_CFG_V1_CMD           8
#define  lte_l2_Srv_CFG_V1_ACK           (256 + lte_l2_Srv_CFG_V1_CMD)
#define  lte_l2_Srv_CFG_V1_NAK           (512 + lte_l2_Srv_CFG_V1_CMD)

/* Optional server versions information query */
#define  lte_l2_Srv_VERSION_INFO_CMD     30
#define  lte_l2_Srv_VERSION_INFO_ACK     (256 + lte_l2_Srv_VERSION_INFO_CMD)
#define  lte_l2_Srv_VERSION_INFO_NAK     (512 + lte_l2_Srv_VERSION_INFO_CMD)

/*
 * Optional report of some LSU configuration parameters 
 * (use after CFG and before START)
 */
#define  lte_l2_Srv_GET_FILE_CMD        31
#define  lte_l2_Srv_GET_FILE_ACK        (256 + lte_l2_Srv_GET_FILE_CMD)
#define  lte_l2_Srv_GET_FILE_NAK        (512 + lte_l2_Srv_GET_FILE_CMD)

/*
 * Configuration Settings
 */
#define  lte_l2_Srv_SETPARM_CMD          3
#define  lte_l2_Srv_SETPARM_ACK          (256 + lte_l2_Srv_SETPARM_CMD)
#define  lte_l2_Srv_SETPARM_NAK          (512 + lte_l2_Srv_SETPARM_CMD)

/*
 * ROHC configuration
 */
#define  lte_l2_Srv_SETROHC_CMD          9
#define  lte_l2_Srv_SETROHC_ACK          (256 + lte_l2_Srv_SETROHC_CMD)
#define  lte_l2_Srv_SETROHC_NAK          (512 + lte_l2_Srv_SETROHC_CMD)


/*
 * Mandatory Start of Test
 */
#define  lte_l2_Srv_START_CMD            4
#define  lte_l2_Srv_START_ACK            (256 + lte_l2_Srv_START_CMD)
#define  lte_l2_Srv_START_NAK            (512 + lte_l2_Srv_START_CMD)

/*
 * Optional msg memory allocation configuration
 */
#define  lte_l2_Srv_SETMSGMEM_CMD        7
#define  lte_l2_Srv_SETMSGMEM_ACK        (256 + lte_l2_Srv_SETMSGMEM_CMD)
#define  lte_l2_Srv_SETMSGMEM_NAK        (512 + lte_l2_Srv_SETMSGMEM_CMD)

/*
 * Optional feature that can be enable/disable.
 * If not used, defaults are applied (see lte_l2_Srv_FEATUREt).
 */
#define  lte_l2_Srv_FEATURE_CMD        34
#define  lte_l2_Srv_FEATURE_ACK        (256 + lte_l2_Srv_FEATURE_CMD)
#define  lte_l2_Srv_FEATURE_NAK        (512 + lte_l2_Srv_FEATURE_CMD)

/*
 * Flush Mode feature that can be enable/disable.
 * If not specified, default value is applied (see lte_l2_Srv_NODELAYt).
 */
#define  lte_l2_Srv_NODELAY_CMD        5
#define  lte_l2_Srv_NODELAY_ACK        (256 + lte_l2_Srv_NODELAY_CMD)
#define  lte_l2_Srv_NODELAY_NAK        (512 + lte_l2_Srv_NODELAY_CMD)

/* DB (DbPlayer test) preload (Valid only when TOP=UDGM) */
#define  lte_l2_Srv_DB_PRELOAD_CMD      48 
#define  lte_l2_Srv_DB_PRELOAD_ACK      (256 + lte_l2_Srv_DB_PRELOAD_CMD)
#define  lte_l2_Srv_DB_PRELOAD_NAK      (512 + lte_l2_Srv_DB_PRELOAD_CMD)

/*                                                                                                                    
 * Optional request for server info (Eg: UDG DB Player supported OSs)
 */                                                                                                                   
#define  lte_l2_Srv_GETINFO_CMD         52
#define  lte_l2_Srv_GETINFO_ACK         (256 + lte_l2_Srv_GETINFO_CMD)                                                     
#define  lte_l2_Srv_GETINFO_NAK         (512 + lte_l2_Srv_GETINFO_CMD)                                                     
                                                                    

/*
 * Optional UDG OOB configuration
 */
#define  lte_l2_Srv_UDGOOB_CMD          10
#define  lte_l2_Srv_UDGOOB_ACK          (256 + lte_l2_Srv_UDGOOB_CMD)
#define  lte_l2_Srv_UDGOOB_NAK          (512 + lte_l2_Srv_UDGOOB_CMD)


/******************
 * CELL MANAGEMENT
 ******************/

#define  lte_l2_Srv_CREATE_CELL_CMD      12
#define  lte_l2_Srv_CREATE_CELL_ACK      (256 + lte_l2_Srv_CREATE_CELL_CMD)
#define  lte_l2_Srv_CREATE_CELL_NAK      (512 + lte_l2_Srv_CREATE_CELL_CMD)

/* Create a Cell, simulating SDRs (Net) */
#define  lte_l2_Srv_CREATE_NET_CELL_CMD  22
#define  lte_l2_Srv_CREATE_NET_CELL_ACK  (256 + lte_l2_Srv_CREATE_NET_CELL_CMD)
#define  lte_l2_Srv_CREATE_NET_CELL_NAK  (512 + lte_l2_Srv_CREATE_NET_CELL_CMD)

#define  lte_l2_Srv_DELETE_CELL_CMD      13
#define  lte_l2_Srv_DELETE_CELL_ACK      (256 + lte_l2_Srv_DELETE_CELL_CMD)
#define  lte_l2_Srv_DELETE_CELL_NAK      (512 + lte_l2_Srv_DELETE_CELL_CMD)

/* Optional request of available Cells (User/Net) */
#define  lte_l2_Srv_CELL_LIST_CMD        19
#define  lte_l2_Srv_CELL_LIST_ACK       (256 + lte_l2_Srv_CELL_LIST_CMD)
#define  lte_l2_Srv_CELL_LIST_NAK       (512 + lte_l2_Srv_CELL_LIST_CMD)

/* Optional cell parameters query (User) */
#define  lte_l2_Srv_CELL_PARM_CMD        20
#define  lte_l2_Srv_CELL_PARM_ACK        (256 + lte_l2_Srv_CELL_PARM_CMD)
#define  lte_l2_Srv_CELL_PARM_NAK        (512 + lte_l2_Srv_CELL_PARM_CMD)

/* Optional cell state/configuration query (User) */
#define  lte_l2_Srv_CELL_INFO_CMD        21
#define  lte_l2_Srv_CELL_INFO_ACK        (256 + lte_l2_Srv_CELL_INFO_CMD)
#define  lte_l2_Srv_CELL_INFO_NAK        (512 + lte_l2_Srv_CELL_INFO_CMD)

/* Configure CELL profiles for error simulation (Optional after CREATE_CELL) */
#define  lte_l2_Srv_CELL_ERRPROF_CMD     26
#define  lte_l2_Srv_CELL_ERRPROF_ACK    (256 + lte_l2_Srv_CELL_ERRPROF_CMD)
#define  lte_l2_Srv_CELL_ERRPROF_NAK    (512 + lte_l2_Srv_CELL_ERRPROF_CMD)

#if 0
/* NYI */
/* Create an error agent (optional) */
#define  lte_l2_Srv_ERRAG_CREATE_CMD    24
#define  lte_l2_Srv_ERRAG_CREATE_ACK    (256 + lte_l2_Srv_CELL_LIST_CMD)
#define  lte_l2_Srv_ERRAG_CREATE_NAK    (512 + lte_l2_Srv_CELL_LIST_CMD)

/* Delete an error agent (optional) */
#define  lte_l2_Srv_ERRAG_DELETE_CMD    25
#define  lte_l2_Srv_ERRAG_DELETE_ACK    (256 + lte_l2_Srv_CELL_LIST_CMD)
#define  lte_l2_Srv_ERRAG_DELETE_NAK    (512 + lte_l2_Srv_CELL_LIST_CMD)
#endif


#define  lte_l2_Srv_CELL_CONFIG_CMD     37
#define  lte_l2_Srv_CELL_CONFIG_ACK    (256 + lte_l2_Srv_CELL_CONFIG_CMD)
#define  lte_l2_Srv_CELL_CONFIG_NAK    (512 + lte_l2_Srv_CELL_CONFIG_CMD)

#define  lte_l2_Srv_CELL_PRECONFIG_CMD     38
#define  lte_l2_Srv_CELL_PRECONFIG_ACK    (256 + lte_l2_Srv_CELL_PRECONFIG_CMD)
#define  lte_l2_Srv_CELL_PRECONFIG_NAK    (512 + lte_l2_Srv_CELL_PRECONFIG_CMD)

#define  lte_l2_Srv_CELL_CONFIG_BR_CMD     53
#define  lte_l2_Srv_CELL_CONFIG_BR_ACK    (256 + lte_l2_Srv_CELL_CONFIG_BR_CMD)
#define  lte_l2_Srv_CELL_CONFIG_BR_NAK    (512 + lte_l2_Srv_CELL_CONFIG_BR_CMD)

#define  lte_l2_Srv_CELL_PRECONFIG_BR_CMD     54
#define  lte_l2_Srv_CELL_PRECONFIG_BR_ACK    (256 + lte_l2_Srv_CELL_PRECONFIG_BR_CMD)
#define  lte_l2_Srv_CELL_PRECONFIG_BR_NAK    (512 + lte_l2_Srv_CELL_PRECONFIG_BR_CMD)

#define  lte_l2_Srv_CELL_CONFIG_NB_CMD     55
#define  lte_l2_Srv_CELL_CONFIG_NB_ACK    (256 + lte_l2_Srv_CELL_CONFIG_NB_CMD)
#define  lte_l2_Srv_CELL_CONFIG_NB_NAK    (512 + lte_l2_Srv_CELL_CONFIG_NB_CMD)

#define  lte_l2_Srv_CELL_PRECONFIG_NB_CMD     56
#define  lte_l2_Srv_CELL_PRECONFIG_NB_ACK    (256 + lte_l2_Srv_CELL_PRECONFIG_NB_CMD)
#define  lte_l2_Srv_CELL_PRECONFIG_NB_NAK    (512 + lte_l2_Srv_CELL_PRECONFIG_NB_CMD)

/*
 * Release all prev. opened PDCP-Entity on a cell */
#define lte_l2_Srv_CELL_PDCP_RELEASE_CMD   39
#define lte_l2_Srv_CELL_PDCP_RELEASE_ACK   (256 + lte_l2_Srv_CELL_PDCP_RELEASE_CMD)
#define lte_l2_Srv_CELL_PDCP_RELEASE_NAK   (512 + lte_l2_Srv_CELL_PDCP_RELEASE_CMD)

/*******************
 * UE MANAGEMENT
 *******************/

#define  lte_l2_Srv_CREATE_UE_CMD      14
#define  lte_l2_Srv_CREATE_UE_ACK      (256 + lte_l2_Srv_CREATE_UE_CMD)
#define  lte_l2_Srv_CREATE_UE_NAK      (512 + lte_l2_Srv_CREATE_UE_CMD)

#define  lte_l2_Srv_UE_SETATTR_CMD     24
#define  lte_l2_Srv_UE_SETATTR_ACK     (256 + lte_l2_Srv_UE_SETATTR_CMD)
#define  lte_l2_Srv_UE_SETATTR_NAK     (512 + lte_l2_Srv_UE_SETATTR_CMD)

#define  lte_l2_Srv_DELETE_UE_CMD      15
#define  lte_l2_Srv_DELETE_UE_ACK      (256 + lte_l2_Srv_DELETE_UE_CMD)
#define  lte_l2_Srv_DELETE_UE_NAK      (512 + lte_l2_Srv_DELETE_UE_CMD)

/* Configure UE profiles for error simulation (Optional after CREATE_UE) */
#define  lte_l2_Srv_UE_ERRPROF_CMD     27
#define  lte_l2_Srv_UE_ERRPROF_ACK    (256 + lte_l2_Srv_UE_ERRPROF_CMD)
#define  lte_l2_Srv_UE_ERRPROF_NAK    (512 + lte_l2_Srv_UE_ERRPROF_CMD)

/* Trigger handover to target cell */
#define  lte_l2_Srv_HANDOVER_CMD      16
#define  lte_l2_Srv_HANDOVER_ACK      (256 + lte_l2_Srv_HANDOVER_CMD)
#define  lte_l2_Srv_HANDOVER_NAK      (512 + lte_l2_Srv_HANDOVER_CMD)

#define  lte_l2_Srv_HANDOVER_PREP_CMD     17
#define  lte_l2_Srv_HANDOVER_PREP_ACK     (256 + lte_l2_Srv_HANDOVER_PREP_CMD)
#define  lte_l2_Srv_HANDOVER_PREP_NAK     (512 + lte_l2_Srv_HANDOVER_PREP_CMD)

#define  lte_l2_Srv_HANDOVER_COMM_CMD     18
#define  lte_l2_Srv_HANDOVER_COMM_ACK     (256 + lte_l2_Srv_HANDOVER_COMM_CMD)
#define  lte_l2_Srv_HANDOVER_COMM_NAK     (512 + lte_l2_Srv_HANDOVER_COMM_CMD)

/* Indicate procedure (handover, reestablish) failure to lower layers */
#define  lte_l2_Srv_PROCEDURE_FAIL_CMD    23
#define  lte_l2_Srv_PROCEDURE_FAIL_ACK    (256 + lte_l2_Srv_PROCEDURE_FAIL_CMD)
#define  lte_l2_Srv_PROCEDURE_FAIL_NAK    (512 + lte_l2_Srv_PROCEDURE_FAIL_CMD)

/* Indicate handover success to lower layers */
#define  lte_l2_Srv_HANDOVER_SUCC_CMD     25
#define  lte_l2_Srv_HANDOVER_SUCC_ACK    (256 + lte_l2_Srv_HANDOVER_SUCC_CMD)
#define  lte_l2_Srv_HANDOVER_SUCC_NAK    (512 + lte_l2_Srv_HANDOVER_SUCC_CMD)

/* Trigger handover simulating source side only */
#define  lte_l2_Srv_HANDOVER_SOURCE_CMD     32
#define  lte_l2_Srv_HANDOVER_SOURCE_ACK    (256 + lte_l2_Srv_HANDOVER_SOURCE_CMD)
#define  lte_l2_Srv_HANDOVER_SOURCE_NAK    (512 + lte_l2_Srv_HANDOVER_SOURCE_CMD)

/* Trigger handover simulating target side only */
#define  lte_l2_Srv_HANDOVER_TARGET_CMD     33
#define  lte_l2_Srv_HANDOVER_TARGET_ACK    (256 + lte_l2_Srv_HANDOVER_TARGET_CMD)
#define  lte_l2_Srv_HANDOVER_TARGET_NAK    (512 + lte_l2_Srv_HANDOVER_TARGET_CMD)

/* Change the cell where an UE is on */
/* TODO implementare */
#define  lte_l2_Srv_UE_SET_CELL_CMD     28
#define  lte_l2_Srv_UE_SET_CELL_ACK    (256 + lte_l2_Srv_UE_SET_CELL_CMD)
#define  lte_l2_Srv_UE_SET_CELL_NAK    (512 + lte_l2_Srv_UE_SET_CELL_CMD)
 
/* Indicate re-establish procedure to lower layers */
#define  lte_l2_Srv_REEST_CMD     29
#define  lte_l2_Srv_REEST_ACK    (256 + lte_l2_Srv_REEST_CMD)
#define  lte_l2_Srv_REEST_NAK    (512 + lte_l2_Srv_REEST_CMD)

/* Indicate re-establish procedure phase 1 (MAC/L1 reset) */
#define  lte_l2_Srv_REEST_1_CMD     49
#define  lte_l2_Srv_REEST_1_ACK    (256 + lte_l2_Srv_REEST_1_CMD)
#define  lte_l2_Srv_REEST_1_NAK    (512 + lte_l2_Srv_REEST_1_CMD)

/* Indicate re-establish procedure phase 2 (reestablish of SRB1) */
#define  lte_l2_Srv_REEST_2_CMD     50
#define  lte_l2_Srv_REEST_2_ACK    (256 + lte_l2_Srv_REEST_2_CMD)
#define  lte_l2_Srv_REEST_2_NAK    (512 + lte_l2_Srv_REEST_2_CMD)

/* Indicate re-establish procedure phase 3 (reestablish of SRB2 and DRBs) */
#define  lte_l2_Srv_REEST_3_CMD     51
#define  lte_l2_Srv_REEST_3_ACK    (256 + lte_l2_Srv_REEST_3_CMD)
#define  lte_l2_Srv_REEST_3_NAK    (512 + lte_l2_Srv_REEST_3_CMD)

/* X2 external linking - get local link info */
#define  lte_l2_Srv_X2_GETLINK_CMD    35
#define  lte_l2_Srv_X2_GETLINK_ACK   (256 + lte_l2_Srv_X2_GETLINK_CMD)
#define  lte_l2_Srv_X2_GETLINK_NAK   (512 + lte_l2_Srv_X2_GETLINK_CMD)

/* X2 external linking - set link to remote process */
#define  lte_l2_Srv_X2_SETLINK_CMD    36
#define  lte_l2_Srv_X2_SETLINK_ACK   (256 + lte_l2_Srv_X2_SETLINK_CMD)
#define  lte_l2_Srv_X2_SETLINK_NAK   (512 + lte_l2_Srv_X2_SETLINK_CMD)

/* IRAT external linking - get local link info */
#define  lte_l2_Srv_IRAT_GETLINK_CMD    45
#define  lte_l2_Srv_IRAT_GETLINK_ACK   (256 + lte_l2_Srv_IRAT_GETLINK_CMD)
#define  lte_l2_Srv_IRAT_GETLINK_NAK   (512 + lte_l2_Srv_IRAT_GETLINK_CMD)

/* IRAT external linking - set link to remote process */
#define  lte_l2_Srv_IRAT_SETLINK_CMD    46
#define  lte_l2_Srv_IRAT_SETLINK_ACK   (256 + lte_l2_Srv_IRAT_SETLINK_CMD)
#define  lte_l2_Srv_IRAT_SETLINK_NAK   (512 + lte_l2_Srv_IRAT_SETLINK_CMD)

/*****************************
 * RADIO CONDITION MANAGEMENT
 *****************************/


/*
 * Configuration of Radio Condition profile 
 * (use after START)
 */
#define lte_l2_Srv_RCP_LOAD_CMD 42
#define lte_l2_Srv_RCP_LOAD_ACK (256 + lte_l2_Srv_RCP_LOAD_CMD)
#define lte_l2_Srv_RCP_LOAD_NAK (512 + lte_l2_Srv_RCP_LOAD_CMD)

#define lte_l2_Srv_RCP_LOAD_END_CMD 43
#define lte_l2_Srv_RCP_LOAD_END_ACK (256 + lte_l2_Srv_RCP_LOAD_END_CMD)
#define lte_l2_Srv_RCP_LOAD_END_NAK (512 + lte_l2_Srv_RCP_LOAD_END_CMD)

#define lte_l2_Srv_RCP_CLOSE_CMD 44
#define lte_l2_Srv_RCP_CLOSE_ACK (256 + lte_l2_Srv_RCP_CLOSE_CMD)
#define lte_l2_Srv_RCP_CLOSE_NAK (512 + lte_l2_Srv_RCP_CLOSE_CMD)

/* IRAT external linking - get local link info (Previded, NYI) */
#define  lte_l2_Srv_IRAT_GETLINK_CMD    45
#define  lte_l2_Srv_IRAT_GETLINK_ACK   (256 + lte_l2_Srv_IRAT_GETLINK_CMD)
#define  lte_l2_Srv_IRAT_GETLINK_NAK   (512 + lte_l2_Srv_IRAT_GETLINK_CMD)

/* IRAT external linking - set link to remote process (Previded, NYI) */
#define  lte_l2_Srv_IRAT_SETLINK_CMD    46
#define  lte_l2_Srv_IRAT_SETLINK_ACK   (256 + lte_l2_Srv_IRAT_SETLINK_CMD)
#define  lte_l2_Srv_IRAT_SETLINK_NAK   (512 + lte_l2_Srv_IRAT_SETLINK_CMD)

#define lte_l2_Srv_RCP_CMD  40
#define lte_l2_Srv_RCP_ACK  (256 + lte_l2_Srv_RCP_CMD)
#define lte_l2_Srv_RCP_NAK  (512 + lte_l2_Srv_RCP_CMD)

#define lte_l2_Srv_RCP_UECFG_CMD 41
#define lte_l2_Srv_RCP_UECFG_ACK (256 + lte_l2_Srv_RCP_UECFG_CMD)
#define lte_l2_Srv_RCP_UECFG_NAK (512 + lte_l2_Srv_RCP_UECFG_CMD)

#define lte_l2_Srv_RCP_FADING_CMD 47
#define lte_l2_Srv_RCP_FADING_ACK (256 + lte_l2_Srv_RCP_FADING_CMD)
#define lte_l2_Srv_RCP_FADING_NAK (512 + lte_l2_Srv_RCP_FADING_CMD)

#define lte_l2_Srv_RCP_UE_SET_GROUP_CMD (57)
#define lte_l2_Srv_RCP_UE_SET_GROUP_ACK (lte_l2_Srv_RCP_UE_SET_GROUP_CMD | TYPE_ACK)
#define lte_l2_Srv_RCP_UE_SET_GROUP_NAK	(lte_l2_Srv_RCP_UE_SET_GROUP_CMD | TYPE_NAK)

#define lte_l2_Srv_RCP_UE_SET_INDEX_CMD	(58)
#define lte_l2_Srv_RCP_UE_SET_INDEX_ACK	(lte_l2_Srv_RCP_UE_SET_INDEX_CMD | TYPE_ACK)
#define lte_l2_Srv_RCP_UE_SET_INDEX_NAK	(lte_l2_Srv_RCP_UE_SET_INDEX_CMD | TYPE_NAK)


/********************************************************************
 * ERROR CODES
 ********************************************************************/
#define  lte_l2_Srv_NOERR    0      /* No error */


                /*********************
                 * FATAL Error Codes *
                 *********************/


#define  lte_l2_Srv_EFMAT    -1      /* Message is too long */
#define  lte_l2_Srv_EEXIT    -2      /* A stack process exited */

#define  lte_l2_Srv_EPHASE   -3      /* Missing LOGIN/CFG/START */
#define  lte_l2_Srv_ELOGIN   -4      /* Duplicate Login name */

#define  lte_l2_Srv_ESAPI    -5      /* Unknown or unreachable SAP */
#define  lte_l2_Srv_ETYPE    -6      /* Unknown Server message type */
#define  lte_l2_Srv_ELEN     -7      /* Invalid Server message length */
#define  lte_l2_Srv_EINVAL   -8      /* Illegal parameter */

#define  lte_l2_Srv_ESTRT    -9      /* Stack failure on START */
#define  lte_l2_Srv_ESTK     -10     /* Stack failure */

#define  lte_l2_Srv_EAMM     -11     /* AMM/BRC features inconsistency */
#define  lte_l2_Srv_ENBIOT   -12     /* NB-IOT/BR features inconsistency */



                /*************************
                 * NON FATAL Error Codes *
                 *************************/


#define  lte_l2_Srv_EUNEXP   1       /* Unexpected primitive */

#define  lte_l2_Srv_EPARM    2       /* Invalid Server message parameter */

#define  lte_l2_Srv_ESRCH    3       /* Invalid object identifier */
#define  lte_l2_Srv_EDUP     4       /* Duplicate object or resource */
#define  lte_l2_Srv_EMAX     5       /* Maximum number of objects reached */
#define  lte_l2_Srv_ETNE     6       /* Tree Not Empty */

#define  lte_l2_Srv_EWTAK    7       /* Wait for ACK */
#define  lte_l2_Srv_ENAK     8       /* NAK received from stack */
#define  lte_l2_Srv_ESEND    9       /* Reported error sending message */
#define  lte_l2_Srv_EFILE    10      /* Error managing file */

typedef struct {
    uint    LocAddr;    /* Local UDP/IP Address 
                           (host order) */
    ushort  LocPort;    /* Local UDP/IP Port 
                           (host order) */
    uint    RemAddr;    /* Remote UDP/IP Address 
                           (host order) */
    ushort  RemPort;    /* Remote UDP/IP Port 
                           (host order) */

} lte_l2_Srv_UDP_Parm_t;

typedef struct {
    ushort  PhyCellId;        /* cell identifier Physical Cell Id [0]*/
    uchar   SdrNeedCalibration; /* Indicate that it is needed to calibrate SDR where the cell is created
                                   -1 -> not available, 0 -> no calibration, 1 -> calibration */
    uchar   LaaFlag; /* LAA configuration
					 0 = cell no LAA
					 1 = cell LAA (this cell needs to have an associated cell that gives the synchronization)
					 2 = cell that provides synchronization for a LAA cell that will be configured on the same SDR */
    uint    mode;           /* User or Network Mode */
    uchar   dl_Bandwidth;    /* Downlink trasmission bandwith configured 
                               (Number of Resource Block NRB)
                               (6, 15, 25, 50, 75, 100) */

    uchar   Master;         /* Master Cell [0] 0: Slave -- 1: Master*/
    uchar   CellCfgMsk;     /* Cell configuration mask [2]*/
    uchar   spare1[1];
    
    uint    ulEarfcn;       /* Uplink EARFCN */
    uint    dlEarfcn;       /* Downlink EARFCN */
    uint    portMsk;        /* mezzanine bitmask [1] */
    int     outpwr;         /* default output power (dBm) */
    int     sens[4];        /* sensitivity (dBm) */
    uint    sibWin;         /* New SIB acquiring window (Prop.) */
    uint    nSdr;           /* number of SDR for this cell */
    uchar   interferenceId; /* interference id group */
    uchar   sdrIdx;			/* sdr idx */
    uchar   localCellId;    /* Local cell index */
    uchar   spare3;
    uchar   aggrId;         /* aggregation/sibling id (0
                                => not "aggregable") */
    uchar   dlHarq;         /* Activate complete downlink HARQ 
                               0: not active, 1: active */
} lte_l2_Srv_Cell_Parm_t;
/*
    Note 0 - All ones (0xFFFF...) means that the result is not currently available.
   
    Note 1 - Each port/mezzanine is mapped to an antenna.
 
    Note 2 - bit 0 If 1 cell is a legacy LTE cell
             bit 1 If 1 cell is a CAT-M cell
             bit 2 If 1 cell is a NB cell
*/

typedef struct {
    ushort  cell_id;        /* cell identifier [0] */
    
    uint    dlEarfcn;       /* Downlink EARFCN
                               (-1 = Frequency scan not active) */
    
    ushort        NumTxAntennas;  // Number of eNb Tx antennas

    /* MIB info, see TS 36.331, MasterInformationBlock ie */
    uchar   dl_Bandwidth;    /* Trasmission bandwidth (Number of Resource Block NRB)
                             (6, 15, 25, 50, 75, 100) */
	uchar  spare;

} lte_l2_Srv_Cell_State_t;

/*
    Note 0 - All ones (0xFFFF...) means that the result is not currently available.
   
    Note 1 - All ones exept first (0x7FFF...) means that the result is not currently available.
   
    Note 2 - The value is encoded in Q.2 format. So the effective value is:
      eff_value = enc_val / 4.
   
    Note 3 - The value is encoded in Q.16 format. So the effective value is:
      eff_value = enc_val / 256.
   
    Note 4 - Calculated as nack per sum of nack plus ack:
      perc = NumNack/(NumNack + NumAck)
   
    Note 5 - referred to the Transport Block (TB) data.
   
 */

typedef struct {
    uchar wb_cqi_cw1;           /* TODO reference */
    uint sb_cqi_cw1;            /* TODO reference */
    uchar wb_cqi_cw2;           /* TODO reference */
    uint sb_cqi_cw2;            /* TODO reference */
    uint pmi;                   /* Precoding Matrix Indication */
    uchar ri;                   /* Rank indicator TODO reference */
    uint R;                     /* Position of the M selected subbands */
    char norm_pow_headr;        /* Normalized Power Headroom (dB) (2) */
    uchar pathloss;             /* Pathloss (dB) */
    short snr;                  /* SNR (dB) [0x7FFF means not apply] */
    uchar fading_prof;          /* Fading Profile (dB) */
    char ptx;                   /* Trasmission power (dB) */
    ushort ul_bler_coeff;       /* (0 - 100.0), granularity is 1/10 of percentage */
    ushort dl_bler_coeff_txdiv; /* (0 - 100.0), granularity is 1/10 of percentage */
    ushort dl_bler_coeff_mimo;  /* (0 - 100.0), granularity is 1/10 of percentage */
    short radial_speed;         /* Radial Speed [km/h, 0x7FFF means not apply] (3) */
    int position;               /* position relative to station [meters, 0x7FFFFFFF means not apply] (3) */
    uchar radio_off;            /* Radio Off flag [0 -> restore normal radio, 1 -> radio off, 0xFF means 'not apply'] (4) */
    uint duration;              /* Profile element duration (ms) (1) */
    
} lte_l2_Srv_ProfElem_t;
/*
 * NOTES
 * (1) value -1 means that the ProfElem apply forever.
 * (2) TODO
 * (3) TODO da decidere come gestire l'ultima riga del profilo per avere (o no) consistenza di velocita' e posizione 
 * nel caso di profilo ciclicamente ripetuto.
 * (4) UE suspend UL activity and discard DL assignments creating a DL and UL gap.
*/
typedef struct {
    comgen_qnxPPUIDt        Ppu;         /* PPU number */
    lte_l2_Srv_UDP_Parm_t   Udp;         /* UDP transport parameters */
    uchar                   NumCell;     /* Number of Cells for this PPU */
    uchar                   CellId[];    /* Start of the list of cells which
                                          * will be used in the test (for
                                          * this instance) */
} lte_l2_Srv_InstParmUdp_t;

typedef struct {
    comgen_qnxPPUIDt        Ppu;         /* PPU number */
    uchar                   CellId;
} lte_l2_Srv_InstParmNet_t;

typedef struct {
    uint Rnti; /* RNTI value */

    /* uchar NumSC = 0; Valid only zero */
    sdrLte_DedPhyChannelCfg Cfg; /* Dedicated physical channel configuration (1) */

} lte_l2_Srv_RntiCfg;
/*
 * NOTES
 * (1) defined in lte-rlcmac_Cmac.h interface.
 */



/********************************************************************
 * lte_l2_Srv_ERROR_SAP Structures
 ********************************************************************/

/**********************************************
 * lte_l2_Srv_ERROR_IND
 *********************************************/

typedef struct {
    short   Err;        /* Error code */
    char    Desc[1];    /* Error description (var len ASCIIZ string) */
} lte_l2_Srv_ERRORt;

/*********************************************
 * lte_l2_Srv_REJECT_IND
 *********************************************/

typedef struct {
    short   Err;        /* Cause of rejection */
    short   spare;      /* zero */
    /*
     * The full rejected message (including its header) is placed here
     */
} lte_l2_Srv_REJECTt;

/*********************************************
 * Common ACK/NAK structures
 *********************************************/

/*
 * All O&M procedures are acknowledged.
 *
 * The Client application should not send a new primitive before
 * receiving the positive/negative acknowledgment to the previous
 * one (if it does, the new primitive shall be rejected with
 * cause lte_l2_Srv_EWTAK).
 *
 * Therefore, only the two following structures are needed
 * for all ACK/NAK primitives.
 */


/****************
 *     ACK      *
 ****************/

typedef struct
{
	union {
		uint    UeId;           /* Ue Identifier (1) */
		uint    CellId;         /* Cell Identifier */
		uint    RcGroup;        /* Radio Condition Group */
	}u;
} lte_l2_Srv_ACKt;

/*
 * NOTES
 * (1) This is a value assigned by the client and is used
 *     to uniquely identify the UE.
 *     It shall be in the range 0..(MaxUe-1) where MaxUe is
 *     defined in lte_l2_Srv_SETPARMt or lte_l2_Srv_SETPARM_UDPt.
 *
 */

/****************
 *     NAK      *
 ****************/

typedef struct {
	union {
		uint    UeId;           /* Ue Identifier (1) */
		uint    CellId;         /* Cell Identifier */
		uint    RcGroup;        /* Radio Condition Group */
	}u;
    short   Err;            /* Error code */
} lte_l2_Srv_NAKt;

/*
 * NOTES
 * (1) This is a value assigned by the client and is used
 *     to uniquely identify the UE.
 *     It shall be in the range 0..(MaxUe-1) where MaxUe is
 *     defined in lte_l2_Srv_SETPARMt or lte_l2_Srv_SETPARM_UDPt.
 *
 */


/*********************************************
 * lte_l2_Srv_LOGIN_XXX_CMD
 *********************************************/

typedef struct {
    char   CliName[40];    /* Login Name (1) */
} lte_l2_Srv_LOGINt;

/*
 * NOTES
 * (1) The Login Name is a fixed length ASCIIZ string, and must be
 *      unique among all currently logged in clients.
 */

#define lte_l2_Srv_SPEC_3GPP_840    0
#define lte_l2_Srv_SPEC_3GPP_860    1

#define lte_l2_Srv_RES_DIV_FDD      1
#define lte_l2_Srv_RES_DIV_TDD      2

/*********************************************
 * lte_l2_Srv_CFG_V1_CMD
 *********************************************/

typedef struct {
    ushort      Type;              /* Parameter Type (11) */
    lte_Side_v  Side;              /* Interface side */
    uchar       BotLayer;          /* Bottom Layer selected (1) */
    uchar       Trf;               /* Traffic Type (2) */
    uint        AliveTout;         /* Timeout for UDG Alive indication (3,4)*/
    uint        TxErrTout;         /* Transmission UDG Error Timeout (3,5) */
    uint        En;                /* Interface number en<En> (12) */
    uint        GiIp;              /* IP address on the Gi interface (3,6,7) */
    uint        GiMask;            /* Netmask on the Gi interface (3,6,7) */
    uchar       GiIp6[16];         /* IPv6 address on the Gi interface (10) */
    uint        Prefix;            /* IPv6 prefix len on the Gi interface */
    ushort      SpecVersion;       /* Specification version (8) */
    uchar       MbmsTx;            /* If set, MBMS Net Tx is allowed */
} lte_l2_Srv_CFG_V1t;


typedef struct {
    ushort      Type;              /* Parameter Type (11) */
    lte_Side_v  Side;              /* Interface side */
    uchar       BotLayer;          /* Bottom Layer selected (1) */
    uchar       Trf;               /* Traffic Type (2) */
    
/* UDG timeout configuration */
    uint        Alive;             /* Alive period timeout (sec) (3,4) */
    uint        TxErr;             /* Transmission error timeout (sec) (3,5) */

/* UDG lost/retry configuration */
    uint        NRetry;            /* Number of command retry (Def=3) (3) */
    uint        NLost;             /* Number of accepted pkt lost before abort (Def=1) (3,14) */

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
    ushort      SpecVersion;       /* Specification version (8) */
    uchar       Spare;
} lte_l2_Srv_CFG_V2t;


typedef struct {
    lte_l2_Srv_CFG_V2t   Cfg;
    
    uint    Flags;                  
    #define lte_l2_Srv_CFLAG_C64ON    0x01   /* Enable 64bit UDG coutners */
    #define lte_l2_Srv_CFLAG_RESv2ON  0x02   /* Enable RESULTv2 UDG stats */

} lte_l2_Srv_CFG_V3t;


typedef struct {
    ushort      Type;              /* Parameter Type (11) */
    lte_Side_v  Side;              /* Interface side */
    uchar       BotLayer;          /* Bottom Layer selected (1) */
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
    ushort      SpecVersion;       /* Specification version (8) */
    uchar       Spare;        

    uint    Flags;                  
    #define lte_l2_Srv_CFLAG_C64ON    0x01   /* Enable 64bit UDG coutners */
    #define lte_l2_Srv_CFLAG_RESv2ON  0x02   /* Enable RESULTv2 UDG stats */
    #define lte_l2_Srv_CFLAG_UDG_UM   0x04   /* Enable unsafe unacked UDG  (17) */
    #define lte_l2_Srv_CFLAG_IRAT     0x08   /* Enable IRAT mode           */
    #define lte_l2_Srv_CFLAG_USLAVE   0x10   /* Enable IRAT SLAVE/[MASTER] */
    #define lte_l2_Srv_CFLAG_FRGIPON  0x20   /* Enable NAT IP fragmentation */
    #define lte_l2_Srv_CFLAG_UDGV1    0x40   /* Enable xUDG to use IUDG V1 */
    #define lte_l2_Srv_CFLAG_STATRST  0x80   /* Enable CNTR reset on STAT_REQ */
    #define lte_l2_Srv_CFLAG_ENDURANCE 0x0100 /* Enable Endurance Mode (18) */
    #define lte_l2_Srv_CFLAG_UDG_NPEER 0x0200 /* Enable UDG without any peer */
    #define lte_l2_Srv_CFLAG_MSW_MULBE 0x0400 /* Enable MSWITCH multibearer  */
    #define lte_l2_Srv_CFLAG_UDG_EITF  0x0800 /* Enable UDG Extended Interface (19) */
    #define lte_l2_Srv_CFLAG_UDG_MTCP  0x1000 /* Enable UDG internal MTCP lib (20) */

} lte_l2_Srv_CFG_V4t;



/*
 * NOTES (for lte_l2_Srv_CFG_CMD and lte_l2_Srv_CFG_Vx_CMD)
 *
 * (1) Bottom Layer Selected;
 *     set the active layers and the type of transport used.
 *     
 *     lte_BOT_PDCP: only PDCP layer active, UDP transport is used by PDCP
 *     lte_BOT_RLCMAC: PDCP and RLC/MAC layers active, UDP transport is used by MAC
 *     lte_BOT_PHY: PDCP and RLC/MAC layers active, PHY transport is used by MAC
 *
 * (2) This parameter specifies how is configured the traffic for User Plane.
 *     
 *     lte_TRF_PDCP: PDCP layer is on top of the lte_l2_ process; UDG disabled.
 *     lte_TRF_UDG: UDG is on top of the lte_l2_ process; UDG enabled;
 *     lte_TRF_CNTR_UDG: UDG is on top of the lte_l2_ process; UDG and CNTR are enabled;
 *
 * (3) Valid only if UDG is enabled (see 'Trf'). If not valid, fill with 0.
 *
 * (4) In seconds; default disabled. A value of zero means default.
 *
 * (5) In seconds; default udgTXERR_TOUT. A value of zero means default.
 *
 * (6) Valid only on NET side.
 *
 * (7) IP addresses considered in host order; e.g.:
 *
 * For a little endian host:
 * 
 * IP 1.2.3.4 <-> "number" 0x01020304 <-> memory dump 04 03 02 01 (from first to last byte)
 * 
 * (8) lte_l2_Srv_SPEC_3GPP_840: 3GPP 8.4.0 (December 2008);
 *     lte_l2_Srv_SPEC_3GPP_860: 3GPP 8.6.0 (June 2009)
 *
 * (9) lte_l2_Srv_RES_DIV_FDD: selected FDD
 *     lte_l2_Srv_RES_DIV_TDD: selected TDD
 *
 * (10) Set address to zero to configure only IPv4 or IPv6.
 *  
 * (11) This field is intended for future expansion of the parameter set.
 *
 *      Currently choices are:
 *      
 *      Type        Primitive format
 *      -----------------------------------------------------
 *      1           lte_l2_Srv_CFG_V1t
 *      2           lte_l2_Srv_CFG_V2t
 *      3           lte_l2_Srv_CFG_V3t
 *      4           lte_l2_Srv_CFG_V4t
 *     
 * (12) Interface number is the old style enX.
 *      Value -1 means that interface number is assigned by driver.
 *
 * (13) DATA reception timeout; on timeout expiratin, NLost additional pkts are
 *          accepted before aborting this pdp
 *
 * (14) START/RESUME retransmission timeout (Up to NStart retry)
 *
 * (15) TERM/SUSPEND retransmission timeout (Up to NTerm retry)
 *
 * (16) RESULT_IND retransmission timeout   (Up to NTerm retry)
 * 
 * (17) Peer acknowledge is not mandatory, primitive is successfully completed
 *      on peer ack or anyway at the end of retransmission phases (if any)
 *
 * (18) In case the variable is enabled, the system should try to survive
 *      as long as possible, trying to recover automatically the major errors, 
 *      in order to achieve the test duration target.
 *
 *      In case the variable is disabled, the simulation is stopped as soon as a 
 *      major error is detected to freeze the memory when the error occurred and 
 *      make the analysis possible. 
 * (19) Full supported if lte_l2_Srv_CFLAG_UDGV1 is set (iudg send only 8bit)
 * (20) Using internal MTCP we have some difference respect to standard io-pkt:
 *      - no alias is required because all IP are accepetd
 *      - TCP buffer space (Rx/Tx) are hardcoded (TODO: add specific CFG)
 *      - max number of TCP client is hardcoded (Eg: 10, TODO .. add specific CFG)
 *      - TCP Timeouts, one additional core fore MTCP is needed ... .. .. 
 */


/*********************************************
 * lte_l2_Srv_UDGOOB_CMD
 *********************************************/

typedef struct
{
    int Flags;            // 1=ONv4,0=Off

    int NetSigPort;       // Net Signaling UDP port [should be well known one] set 0=DEF
    int NetSub,NetPrefix; // NUDG standard subnet (All NetIP should live here)
    int SigSub,SigPrefix; // SigPrefix should be equal to (NetPrefix-1) and all SigIp should live in
                          // SigSub/SigPrefix but not in SigSub/NetPrefix

    uchar   NrOfInst;     /* Number on stack instances */
    struct lte_l2_Srv_OOB_ELEM {
        int SigIp;        // UUDG Signaling IP for each lte.stk instance
        int SigPort;      // Optional (Set 0=DEF)
    } Uu[];

} lte_l2_Srv_UDGOOBt;

/*********************************************
 * lte_l2_Srv_VERSION_INFO_CMD
 *********************************************/

typedef struct
{
    ushort      Spare;      /* Zero */
    
} lte_l2_Srv_VERSION_INFO_CMDt;

typedef struct
{
    uchar       PackageType;                  /* See lte_l2_Srv_SERVER_TYPE_* below */
    char        PackageVersion[60];           /* Server package version (ASCIIZ string) */
    char        AmmVersion[60];               /* AMM module version used (ASCIIZ string) */
    
} lte_l2_Srv_VERSION_INFO_ACKt;

#define lte_l2_Srv_SERVER_TYPE_MULTI_OS       1 /* Server is _multiOS_ type    */

/*********************
 * With HASH
 **********************/
typedef struct
{
    ushort      Type;      /* Type for future ext set to lte_l2_Srv_VERSION_HASH */
    ushort      Spare;     /* Zero */
    uint	HashCode;  /* Hash value of interfaces */
} lte_l2_Srv_VERSION_TYPE1_INFO_CMDt;

typedef struct
{
    uint	Spare;
} lte_l2_Srv_VERSION_TYPE1_INFO_ACKt;

typedef struct
{
    char       VerString[1];
} lte_l2_Srv_VERSION_TYPE1_INFO_NACKt;

#define lte_l2_Srv_VERSION_HASH       1 

/*********************************************
 * lte_l2_Srv_GET_FILE_CMD
 *********************************************/

typedef struct
{
    uchar      Spare;      /* Zero */
    uchar      Type;       /* Type of informations requested, see lte_l2_Srv_SERVER_TYPE_* below  */
    char       Fname[];    /* Filename as ASCIIZ string; optional; Fname[0] == 0 means "no specific name requested"  */
    
} lte_l2_Srv_GET_FILE_CMDt;

#define lte_l2_Srv_INFO_TYPE_LSU_CFG     0 /* LSU basic configuration       */
#define lte_l2_Srv_INFO_TYPE_FADING      1 /* Simulated fading informations */
#define lte_l2_Srv_INFO_TYPE_LICENSE     2 /* License informations */
#define lte_l2_Srv_INFO_TYPE_MACINFO     3 /* LSU MAC addresses informations */

typedef struct
{
    uchar       Type;       /* Type of informations contained, see lte_l2_Srv_SERVER_TYPE_* below  */
    char        Info[];     /* LSU specific informations (ASCII file) */
    
} lte_l2_Srv_GET_FILE_ACKt;


/*********************************************
 * lte_l2_Srv_SETPARM_CMD
 *********************************************/

typedef struct {
    ushort  Type;                       /* Parameter Type (1) */
    uint    MaxUe;                      /* Max number of UE's (2,4) */
    uint    MaxPdcp;                    /* Max number of PDCP (2,6) */
    uchar   NrOfInst;                   /* Number on stack instances */
    lte_l2_Srv_InstParmUdp_t    Parm[]; /* stack instances parameters */
} lte_l2_Srv_SETPARM_UDPt;


typedef struct {
    ushort  Type;                 /* Parameter Type (1, 10) */
    uint    MaxUe;                /* Max number of UE's (2,4) */

    uint    MaxPdcp;              /* Max number of PDCP (2,6) */
    uchar   NrOfInst;                   /* Number of cell instances */
    lte_l2_Srv_InstParmNet_t    Parm[]; /* cell instances parameters */
} lte_l2_Srv_SETPARM_NETt;


typedef struct {
    ushort  Type;                 /* Parameter Type (1) */
    uint    MaxUe;                /* Max number of UE's (2,4) */
    uint    MaxPdcp;              /* Max number of PDCP (2,6) */
    uchar   NumStkPpu;            /* Number of elements of StkPpu[] list */
    comgen_qnxPPUIDt   StkPpu[];  /* PPU list where put the stack processes (higher level) (12) */
/*  uchar   CellId[]; */          /* Start of the list of cell's CellId which
                                   * will be used in the test */
} lte_l2_Srv_SETPARM_05t;


typedef struct {
    ushort  Type;                 /* Parameter Type (1) */
    uint    MaxUe;                /* Max number of UE's (2,4) */
    uint    MaxPdcp;              /* Max number of PDCP (2,6) */
    uint    MaxNat;               /* Max number of NAT bearers (7) */
    uint    MaxUdgSess;           /* Max number of UDG entity (8) */
    uint    MaxCntr;              /* Max number of Filter/Counters (9) */
    
    uint    Verbosity;            /* Global Trace Verbosity bit mask */
    #define lte_l2_Srv_GVERB_MAC_CONF        0x0001 /* MAC basic configuration */
    #define lte_l2_Srv_GVERB_L2SR            0x0002 /* L2 SR */
    #define lte_l2_Srv_GVERB_BSR             0x0004 /* MAC BSR */
    #define lte_l2_Srv_GVERB_L2TA            0x0008 /* L2 TA  */
    #define lte_l2_Srv_GVERB_ULSPS           0x0010 /* Uplink SPS */
    #define lte_l2_Srv_GVERB_ULHARQ          0x0020 /* Uplink HARQ */
    #define lte_l2_Srv_GVERB_RLC             0x0040 /* RLC */
    #define lte_l2_Srv_GVERB_SCELL           0x0080 /* Secondary cells */
    #define lte_l2_Srv_GVERB_AMM             0x0100 /* AMM (basic) */
    #define lte_l2_Srv_GVERB_AMM1            0x0200 /* AMM (verbose) */
    #define lte_l2_Srv_GVERB_L1              0x0400 /* L1 interface */
    /* Better to keep reserved consecutive bits for RLCMAC: [12 13 14 15 16 17 18 19 20] */
    /* Better to keep consecutive bits for PDCP: [21 22 23 24 25 26 27 28 29 30 31 32] */
    #define lte_l2_Srv_GVERB_PDCP_SHIFT        (20) /* Bit Shift */
    #define lte_l2_Srv_GVERB_PDCP_PDU      0x100000 /* Bit 21 PDCP */
    #define lte_l2_Srv_GVERB_PDCP_REORDER  0x200000 /* Bit 22 PDCP */
    
    uint    Spare[3];             /* Reserved set to 0 */
    uchar   NumStkPpu;            /* Number of elements of StkPpu[] list */
    comgen_qnxPPUIDt   StkPpu[];  /* PPU list where put the stack processes (higher level) (12) */
/*  uchar   CellId[]; */          /* Start of the list of cell's CellId which
                                   * will be used in the test */
} lte_l2_Srv_SETPARM_06t;



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
 *      1           lte_l2_Srv_SETPARM_UDPt
 *      2           lte_l2_Srv_SETPARM_NETt
 *      5           lte_l2_Srv_SETPARM_05t
 *      6           lte_l2_Srv_SETPARM_06t
 *     
 *     Type == 1 MUST be used if "BotLayer" in CFG primitive is set to
 *     "lte_BOT_PDCP" or "lte_BOT_RLCMAC".
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
 * (11) Void.
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
 */


/*********************************************
 * lte_l2_Srv_SETROHC_CMD
 *********************************************/

typedef struct {
    uint    Type;       /* Parameter Type (1) */

    uint    Num;        /* Number of RTPoUDP ports (max = 16) */
    ushort  RtpPorts[]; /* Start of the RTPoUDP port set */
} lte_l2_Srv_SETROHCt;

/*
 * NOTES
 *  (1) This field is intended for future expansion of the
 *      parameter set. Currently it must be set to zero.
 */


typedef struct {
    uint  MsgMemSize_128;  /* Memory allocated for  msgs with max data size = 128 bytes (3) */
    uint  MsgMemSize_256;  /* Memory allocated for  msgs with max data size = 256 bytes (3) */
    uint  MsgMemSize_512;  /* Memory allocated for  msgs with max data size = 512 bytes (3) */
    uint  MsgMemSize_1024; /* Memory allocated for  msgs with max data size = 1024 bytes (3) */
    uint  MsgMemSize_2048; /* Memory allocated for  msgs with max data size = 2048 bytes (3) */
    uint  MsgMemSize_3072; /* Memory allocated for  msgs with max data size = 3072 bytes (3) */
    uint  MsgMemSize_9728; /* Memory allocated for  msgs with max data size = 9728 bytes (3) */
    uint  MsgMemSize_18880;/* Memory allocated for  msgs with max data size = 18880 bytes (3) */
} lte_l2_Srv_MemSet_t;


/*********************************************
 * lte_l2_Srv_SETMSGMEM_CMD
 *********************************************/

typedef struct {
    ushort              Type;       /* Parameter Type (1) */
    lte_l2_Srv_MemSet_t MsgMemSet;  /* Memory sets for messages (2) */
} lte_l2_Srv_SETMSGMEMt;

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
 *      0           lte_l2_Srv_SETMSGMEMs
 *
 * (2) The MsgMemSet apply to all stack instances.
 *
 * (3) Expressed in bytes.
 */

/*********************************************
 * lte_l2_Srv_FEATURE_CMD
 *********************************************/

typedef struct
{
    uchar Spare; /* no feature optional currently previded */
} lte_l2_Srv_FEATUREt;

/*********************************************
 * lte_l2_Srv_NODELAY_CMD
 *********************************************/

typedef struct
{
    uchar FlushMode; /* if set Flush Mode enabled.
                          Default is 0 */
} lte_l2_Srv_NODELAYt;


/*********************************************
 * lte_l2_Srv_DB_PRELOAD_CMD
 *********************************************/

typedef struct {
    uchar   Type;       /*          Type == 0           */
    uchar   NDb;
    #define lte_l2_SrvMAXDB    256
    uchar   DbId[lte_l2_SrvMAXDB]; /*  DB Id (stored on /lsu/cfg/udgply)   *
                                 *  First NDb must be set, 0 padded     */
} lte_l2_Srv_DBt;


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

/*
 * Main Errors:
 *      lte_l2_Srv_EINVAL        Invalid parameters
 */


/*********************************************
 * lte_l2_Srv_CREATE_CELL_CMD
 *********************************************/

typedef struct
{
    uint      CellId;         /* Cell Identifier */
    uint      L1Verbosity;    /* L1 Verbosity bit mask (see sdrLteVERB* defines from sdrLteStruct.h) */
    uint      L1UlReport;     /* Uplink report activation and format configuration (see sdrLteULREP* defines from sdrLteStruct.h) */ 
} lte_l2_Srv_CREATE_CELLt;

/*********************************************
 * lte_l2_Srv_CREATE_NET_CELL_CMD
 *********************************************/

typedef struct
{
    uint      CellId;         /* Cell Identifier */
    uchar       ResDiv;            /* Resource division (9) */
    
    uint        DrvAddr;        /* SDR Driver address (net order) */
    uchar       NumSdrAddr;     /* num. of SdrAddr */
    uint        SdrAddr[10];    /* SDR Addresses (net order) */
    
} lte_l2_Srv_CREATE_NET_CELLt;

/*********************************************
 * lte_l2_Srv_DELETE_CELL_CMD
 *********************************************/

typedef struct
{
    uint    CellId;        /* Cell Identifier */
} lte_l2_Srv_DELETE_CELLt;

/*********************************************
 * lte_l2_Srv_CELL_LIST_CMD
 *********************************************/

typedef struct
{
    ushort      Spare;      /* Zero */
    
} lte_l2_Srv_CELL_LIST_CMDt;

typedef struct
{
    uchar       CellId[1];    /* Start of CellId list */

} lte_l2_Srv_CELL_LIST_ACKt;

/*********************************************
 * lte_l2_Srv_CELL_PARM_CMD
 *********************************************/

typedef struct
{
    uchar       CellId;       /* Cell Identifier */
} lte_l2_Srv_CELL_PARM_CMDt;

typedef struct
{
    uchar                       CellId;         /* Cell Identifier */
    lte_l2_Srv_Cell_Parm_t      Parm;           /* Cell parameters */
    char                        FadingSim[128]; /* ASCIIZ fading simulation file name */
} lte_l2_Srv_CELL_PARM_ACKt;

/*********************************************
 * lte_l2_Srv_CELL_INFO_CMD
 *********************************************/

typedef struct
{
    uchar       CellId;       /* Cell Identifier */
    
} lte_l2_Srv_CELL_INFO_CMDt;

typedef struct
{
    uchar                   CellId; /* Cell Identifier */
    lte_l2_Srv_Cell_State_t State;  /* Cell State */
    
} lte_l2_Srv_CELL_INFO_ACKt;

/*********************************************
 * lte_l2_Srv_CELL_ERRPROF_CMD
 *********************************************/

typedef struct
{
    uchar                   CellId; /* Cell Identifier */
    ushort                  UlCoeff[29]; /* Scale coefficients for Uplink [1] */
    ushort                  DlCoeff[29]; /* Scale coefficients for Downlink [2] */
} lte_l2_Srv_CELL_ERRPROFt;

/*
    Note 1 - The coefficients are applied to the following parameters:
        TODO
        The index in the table is the relative MCS to which apply the coefficient.
        The values are expressed in decimal fix point with 2 decimal digit, e.g.
        value 1234 (decimal) == "12.34 (decimal)"

    Note 2 - The coefficients are applied to the following parameters:
        TODO
        The index in the table is the relative MCS to which apply the coefficient.
        The values are expressed in decimal fix point with 2 decimal digit, e.g.
        value 1234 (decimal) == "12.34 (decimal)"
 */
/*********************************************
 * lte_l2_Srv_CREATE_UE_CMD
 *********************************************/

typedef struct
{
    uint            UeId;           /* Ue Identifier (1) */
    uint            CellId;         /* Cell Identifier */
    #define lte_l2_Srv_LOG_UE   1   /* Log Ue Flag (2) */
    #define lte_l2_Srv_MBMS_UE  2   /* This UE is for MBMS */
	uint            UeFlags;
    uint            StkInst;        /* stack process Instance (3) */
    uint            UdgStkInst;     /* UDG stack process Instance (3) */
} lte_l2_Srv_CREATE_UEt;

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
 * 	if split is abled UdgStkInst is instance of UDG, StkInst is instance of PDCP
 * 	if split isn't abled UdgStkInst isn't used , StkInst is instance of PDCP/UDG
 */

/*********************************************
 * lte_l2_Srv_UE_SETATTR_CMD
 *********************************************/

typedef struct
{
    uint            UeId;           /* Ue Identifier (1) */
    uint            CellId;         /* Cell Identifier */
    uchar           ImsiLen;        /* IMSI oct. 2    (GSM 4.08-10.5.1.4) */
    uchar           Imsi [9];       /* IMSI oct. 3-11 (GSM 4.08-10.5.1.4) */
} lte_l2_Srv_UE_SETATTRt;

/*********************************************
 * lte_l2_Srv_DELETE_UE_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
} lte_l2_Srv_DELETE_UEt;

/*********************************************
 * lte_l2_Srv_UE_ERRPROF_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
    uint    NumPe;
    lte_l2_Srv_ProfElem_t Pe[50]; /* Profile elements */
} lte_l2_Srv_UE_ERRPROFt;

/*
    Note 1 - The coefficients are applied to the following parameters:
        TODO
        The index in the table is the relative MCS to which apply the coefficient.
        The values are expressed in decimal fix point with 2 decimal digit, e.g.
        value 1234 (decimal) == "12.23 (decimal)"

    Note 2 - The coefficients are applied to the following parameters:
        TODO
        The index in the table is the relative MCS to which apply the coefficient.
        The values are expressed in decimal fix point with 2 decimal digit, e.g.
        value 1234 (decimal) == "12.23 (decimal)"
 */
/*********************************************
 * lte_l2_Srv_HANDOVER_CMD
 *********************************************/

typedef struct
{
    uint    UeId;                /* UE Identifier */
    lte_l2_Srv_RntiCfg CrntiCfg; /* Configured C-RNTI on Target Cell */
    uint    OrigCellId;          /* Cell Identifier */
    uint    TargCellId;          /* Cell Identifier */
    uchar   drb_ContinueROHC;    /* drb-ContinueROHC (1) 
                                    [ 0 means 'not configured/false' 
                                      !=0 means 'true' ] */
} lte_l2_Srv_HANDOVERt;

/*
 * NOTES
 * 
 * (1) see 36.323 and 36.331 R11
 */

/*********************************************
 * lte_l2_Srv_HANDOVER_PREP_CMD
 *********************************************/

typedef struct
{
    uint    UeId;             /* UE Identifier */
    lte_l2_Srv_RntiCfg  CrntiCfg; /* Configured C-RNTI on Target Cell */
    uint    OrigCellId;      /* Cell Identifier */
    uint    TargCellId;      /* Cell Identifier */
} lte_l2_Srv_HANDOVER_PREPt;

/*********************************************
 * lte_l2_Srv_HANDOVER_COMM_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
} lte_l2_Srv_HANDOVER_COMMt;

/*********************************************
 * lte_l2_Srv_PROCEDURE_FAIL_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    OrigCellId;      /* Originating Cell Identifier */
    uint    TargCellId;      /* Target Cell Identifier      */
} lte_l2_Srv_PROCEDURE_FAILt;

/*********************************************
 * lte_l2_Srv_HANDOVER_SUCC_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    OrigCellId;      /* Originating Cell Identifier */
    uint    TargCellId;      /* Target Cell Identifier */
} lte_l2_Srv_HANDOVER_SUCCt;

/*********************************************
 * lte_l2_Srv_HANDOVER_SOURCE_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
} lte_l2_Srv_HANDOVER_SOURCEt;

/*********************************************
 * lte_l2_Srv_HANDOVER_TARGET_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
    lte_l2_Srv_RntiCfg CrntiCfg; /* Configured C-RNTI on Target Cell */
} lte_l2_Srv_HANDOVER_TARGETt;

/*********************************************
 * lte_l2_Srv_UE_SET_CELL_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    CellId;          /* Cell Identifier */
} lte_l2_Srv_UE_SET_CELLt;

/*********************************************
 * lte_l2_Srv_REEST_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    CellId;          /* Cell Identifier */
} lte_l2_Srv_REESTt;

/*********************************************
 * lte_l2_Srv_REEST_1_CMD
 *********************************************/

typedef struct
{
    uint    UeId;            /* UE Identifier */
    uint    OrigCellId;      /* Originating Cell Identifier */
    uint    TargCellId;      /* Target Cell Identifier */
} lte_l2_Srv_REEST_1t;

/*********************************************
 * lte_l2_Srv_REEST_2_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
} lte_l2_Srv_REEST_2t;

/*********************************************
 * lte_l2_Srv_REEST_3_CMD
 *********************************************/

typedef struct
{
    uint    UeId;           /* UE Identifier */
} lte_l2_Srv_REEST_3t;

/*********************************************
 * lte_l2_Srv_CELL_PRECONFIG_CMD
 *********************************************/

/*
This primitive is used to request for configuration of some TDD
specific parameters before the complete cell configuration.
*/
typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    uchar       Valid;      /* 0 -> message not valid ( cell PRECONFIG and CONFIG for cell legacy have to be considered as not valid )
                               1 -> default value ( message valid ) */

    lte_rlcmac_Cmac_Tdd    TddConfig; // TDD specific physical channel configuration
    
    lte_rlcmac_Cmac_Sib    SibInfo;   // SIB Scheduling information
    
} lte_l2_Srv_CELL_PRECONFIGt;

/*********************************************
 * lte_l2_Srv_CELL_CONFIG_CMD
 *********************************************/

typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    uchar       Valid;      /* 0 -> message not valid ( cell PRECONFIG and CONFIG for cell legacy have to be considered as not valid )
                               1 -> default value ( message valid ) */

    /* Random Access Info */
    lte_rlcmac_Cmac_RA_Info_t    RA_Info;
    
    uchar       RachProbeSkip;  /* Set to 1 to skip RACH probe */
    uchar       Ta;         /* Time Advance Command [0-63, -1 for none] (see MAC par. 6.1.3.5) (1) */
    
    /* Physical channels configuration */
    
//    uint        SyncTimer;  /* Max physical out of synchronization timeout */
    
    lte_rlcmac_Cmac_PhChannelsCfg     PhChannelsCfg;
    
} lte_l2_Srv_CELL_CONFIGt;

/*********************************************
 * lte_l2_Srv_CELL_PRECONFIG_BR_CMD
 *********************************************/

/*
This primitive is used to request for configuration of some TDD
specific parameters before the complete cell BR configuration.
*/
typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    lte_rlcmac_Cmac_Tdd    TddConfig; // TDD specific physical channel configuration
    
    lte_rlcmac_Cmac_Sib    SibInfo;   // SIB Scheduling information
    lte_rlcmac_Cmac_SibBR  SibInfoBR; // SIB (BR) Scheduling information
    
} lte_l2_Srv_CELL_PRECONFIG_BRt;

/*********************************************
 * lte_l2_Srv_CELL_CONFIG_BR_CMD
 *********************************************/

typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    /* Random Access Info */
    lte_rlcmac_Cmac_RA_Info_BR_t RA_Info_BR; /* RA_Info for BL UE or UE in EC */
    
    uchar       RachProbeSkip;  /* Set to 1 to skip RACH probe */
    uchar       Ta;         /* Time Advance Command [0-63, -1 for none] (see MAC par. 6.1.3.5) (1) */
    
    /* Physical channels configuration */
    
    lte_rlcmac_Cmac_PhChannelsCfgBR   PhChannelsCfgBR;
    
} lte_l2_Srv_CELL_CONFIG_BRt;
/*
 * (1) 'Ta' set the initial Time Advance Command for all UE's on the cell if
 *     the RACH is not enable (i.e. for any debug mode with UL transmission but without RACH or without TA from Random Access).
 */

/*********************************************
 * lte_l2_Srv_CELL_PRECONFIG_NB_CMD
 *********************************************/

/*
This primitive is used to request for configuration of some TDD
specific parameters before the complete cell NB configuration.
*/
typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
    lte_rlcmac_Cmac_Tdd    TddConfig; // TDD specific physical channel configuration
    
    lte_rlcmac_Cmac_SibNB  SibInfoNB; // SIB (NB) Scheduling information
    
} lte_l2_Srv_CELL_PRECONFIG_NBt;

/*********************************************
 * lte_l2_Srv_CELL_CONFIG_NB_CMD
 *********************************************/

typedef struct {

    uint       Spare;      /* must be set to -1 */
    uint       CellId;
    
    uchar       RachProbeSkip;  /* Set to 1 to skip RACH probe */

    /* Random Access Info */
    lte_rlcmac_Cmac_RA_Info_NB_t RA_Info_NB; /* RA_Info for NB-IoT */
    
    /* Physical channels configuration */
    lte_rlcmac_Cmac_PhChannelsCfgNB   PhChannelsCfgNB;
    
} lte_l2_Srv_CELL_CONFIG_NBt;
/*********************************************
 * lte_l2_Srv_CELL_PDCP_RELEASE_CMD
 *********************************************/

/*
This primitive is used to request for release of all PDCP on a given cell.
*/
typedef struct {

    uint        Spare;      /* must be set to -1 */
    uint        CellId;
    
} lte_l2_Srv_CELL_PDCP_RELEASEt;

/*********************************************
 * lte_l2_Srv_X2_GETLINK_CMD
 *********************************************/


typedef struct {
    uint    ProcInst;   // "instance" (1)

    uint    RemId;      // Remote process ID (>0xFF, set it to 0x100)
} lte_l2_Srv_X2_GETLINKt;

#define LNK_SIZE 256
typedef struct {
    uint    ProcInst;   // "instance" (1)

    char    Lnk[LNK_SIZE];   // Link info
} lte_l2_Srv_X2_GETLINK_ACKt;

/*********************************************
 * lte_l2_Srv_X2_SETLINK_CMD
 *********************************************/

typedef struct {
    uint    ProcInst;   // "instance" (1)

    uint    LocId;      // Local process ID  (>0xFF, set it to 0x100)
    uint    RemId;      // Remote process ID (>0xFF, set it to 0x100)

    char    Lnk[LNK_SIZE];   // Link info
} lte_l2_Srv_X2_SETLINKt;


typedef struct {
    uint    ProcInst;   // "instance" (1)
} lte_l2_Srv_X2_ACKt;

typedef struct {
    uint    ProcInst;   // "instance" (1)
    short   Err;        /* Error code */
} lte_l2_Srv_X2_NAKt;


/* Note 1) On multios version, X2 external linking is between lte.stk and only
 *          one stk is avaliable up to now, so no ProcInst is required (set 0)
 *         On single version, X2 external linking is between lte-l2.pro so
 *          ProcInst = CellId allow to reach the desired instance
 */

/* These primitives allow to link processes (A,B) spowned by different servers
 * To link external process is required to GET link info from B and SET it to A
 * and configure A and B with remote link IDs (used by fw on link callback)
 * In X2 is used LocId=RemId=0x100 (global code 0x100 = "external link") 
 */


/*********************************************
 * lte_l2_Srv_IRAT_GETLINK_CMD
 *********************************************/


typedef struct {
    uint    ProcInst;   // "instance" (1)

    // IRAT stack enable masks
    #define lte_l2_Srv_IRAT_UMTS_MSK   0x02
    #define lte_l2_Srv_IRAT_GSM_MSK    0x04
    #define lte_l2_Srv_IRAT_WIFI_MSK   0x08
    uint    IratMsk;    // Mask of expected remote processes
    uint    Spare;      // Reserved, set to 0

} lte_l2_Srv_IRAT_GETLINKt;

typedef struct {
    uint    ProcInst;   // "instance" (1)

    char    Lnk[LNK_SIZE];   // Link info
} lte_l2_Srv_IRAT_GETLINK_ACKt;

/*********************************************
 * lte_l2_Srv_IRAT_SETLINK_CMD
 *********************************************/

typedef struct {
    uint    ProcInst;   // "instance" (1)

    uint    IratMsk;    // Remote process to link (see GETLINK)
    uint    RemInst;    // Remote instance to link (Ignored, set to 0)

    char    Lnk[LNK_SIZE];   // Link info
} lte_l2_Srv_IRAT_SETLINKt;

typedef struct {
    uint    ProcInst;   // "instance" (1)
} lte_l2_Srv_IRAT_ACKt;

typedef struct {
    uint    ProcInst;   // "instance" (1)
    short   Err;        /* Error code */
} lte_l2_Srv_IRAT_NAKt;


/* Note 1) On multios version, IRAT external linking is between lte.stk and only
 *          one stk is avaliable up to now, so no ProcInst is required (set 0)
 *         On single version, IRAT external linking is between lte-l2.pro so
 *          ProcInst = CellId allow to reach the desired instance
 */

/* These primitives allow to link processes (A,B) spowned by different servers
 * To link external process is required to GET link info from B and SET it to A
 * and configure A and B with remote link IDs (used by fw on link callback)
 * In IRAT is used stack IDs as defined in uudgIratExtPrim.h (ignored by Cli)
 *  only remote process mask is know by client
 */
/*********************************************
 * lte_l2_Srv_RCP_LOAD_CMD
 *********************************************/

typedef struct
{
    uint       RcGroup;        /* Radio Condition Group (1) */
    uint       CellId;         /* Cell Identifier */
    char       Fname[];        /* Path/Filename as ASCIIZ string of profile file */
    
} lte_l2_Srv_RCP_LOADt;
/*
 * NOTES
 * (1) A radio condition group is a group of UE that are simulating the
 *     same radio conditions (i.e. same topological path in space and time 
 *     exept an initial offset in both space and time).
 *     The radio conditions are defined in a set of files, one per each 
 *     cell previded. We call this set of files the "radio condition profile".
 *     The 'CellId' for a given profile is assotiated to a single file with path
 *     and name indicated in 'Fname'.
 *
 *     The operations needed to have a radio condition simulation are:
 *     
 *     1) load the profile files 'Fname' for each 'CellId' to be assotiated to
 *     a given 'RcGroup' using RCP_GROUP_CMD
 *
 *     2) populate the radio condition group 'RcGroup' with wanted UEs using
 *        RCP_UECFG_CMD
 *
 *     3) indicate the given radio condition inside the profile to be used for
 *        e given UE and/or condition group
 */

/*********************************************
 * lte_l2_Srv_RCP_LOAD_END_CMD
 *********************************************/

typedef struct
{
    uint       Spare;
    
} lte_l2_Srv_RCP_LOAD_ENDt;

/*********************************************
 * lte_l2_Srv_RCP_CLOSE_CMD
 *********************************************/

typedef struct
{
    uint       Spare;  /* Radio Condition Group */
    
} lte_l2_Srv_RCP_CLOSEt;

/*
 * RCP NACK Info
 */
typedef struct
{
	uint UeId; /* Ue Identifier */
	uint Info; /* Info -> RcpIdx if lte_l2_Srv_RCP_CMD, RcGroup if lte_l2_Srv_RCP_UECFG_CMD */
	int Err; /* Error code */

} lte_l2_Srv_RCP_NACK_INFOt;

/*********************************************
 * lte_l2_Srv_RCP_ACK
 *********************************************/
typedef struct
{
	uint NumRcpNackInfo;
	lte_l2_Srv_RCP_NACK_INFOt RcpNackInfo[0];

} lte_l2_Srv_RCP_ACKt;

/*********************************************
 * lte_l2_Srv_RCP_UECFG_CMD
 *********************************************/
typedef struct
{
	uint RcGroup; /* Radio Condition Group */
	uint NumUePerRcGroup;
	uint UeIdRcGroup[0]; /* UeId array */

} lte_l2_Srv_RCP_UECFGt;

/*
 * RCP Info: one per user at time
 */
typedef struct
{
	uint UeId; /* Ue Identifier */
	uint RcpIdx; /* Radio Condition Profile Index */

} lte_l2_Srv_RCP_INFOt;

/*********************************************
 * lte_l2_Srv_RCP_CMD
 *********************************************/
typedef struct
{
	uint NumRcpInfo;
	lte_l2_Srv_RCP_INFOt RcpInfo[0];

} lte_l2_Srv_RCPt;

/*********************************************
 * lte_l2_Srv_RCP_FADING_CMD
 *********************************************/

typedef struct
{
    uint       CellId;      /* Cell Identifier */
    char       FadingSim[]; /* ASCIIZ fading simulation file name */
    
} lte_l2_Srv_RCP_FADINGt;

/*********************************************
 * lte_l2_Srv_RCP_UE_SET_GROUP_CMD
 *********************************************/

typedef struct
{
    uint UeId;		/* Ue Identifier */
    uint Group;		/* Radio Condition Group */
} lte_l2_Srv_RCP_UE_SET_GROUPt;
 
/*********************************************
 * lte_l2_Srv_RCP_UE_SET_INDEX_CMD
 *********************************************/

typedef struct
{
     uint UeId;		/* Ue Identifier */
     uint Index;	/* Radio Condition Profile Index */
} lte_l2_Srv_RCP_UE_SET_INDEXt;


/********************************************************************
 * The union of all messages
 ********************************************************************/

union lte_l2_Srv_MSGu
{
    lte_l2_Srv_ERRORt            Error;
    lte_l2_Srv_REJECTt           Reject;
    lte_l2_Srv_ACKt              Ack;
    lte_l2_Srv_NAKt              Nak;

    lte_l2_Srv_LOGINt            Login;

    lte_l2_Srv_CFG_V2t           CfgV2;
    lte_l2_Srv_CFG_V3t           CfgV3;
    lte_l2_Srv_CFG_V4t           CfgV4;

    lte_l2_Srv_UDGOOBt           UdgOOB;

    lte_l2_Srv_VERSION_INFO_CMDt VersionInfoCmd;
    lte_l2_Srv_VERSION_INFO_ACKt VersionInfoAck;

    lte_l2_Srv_GET_FILE_CMDt     GetFileCmd;
    lte_l2_Srv_GET_FILE_ACKt     GetFileAck;

    lte_l2_Srv_SETPARM_UDPt      SetParmUdp;
    lte_l2_Srv_SETPARM_05t       SetParm05;
    lte_l2_Srv_SETPARM_06t       SetParm06;

    lte_l2_Srv_SETMSGMEMt        SetMsgMem;

    lte_l2_Srv_FEATUREt          Feature;

    lte_l2_Srv_NODELAYt          Flush;

    lte_l2_Srv_DBt               DbPreloadCmd;
    lte_l2_Srv_GETINFOt          GetInfoCmd;
    lte_l2_Srv_GETINFO_ACKt      GetInfoAck;

    lte_l2_Srv_SETROHCt          SetRohc;

    lte_l2_Srv_CREATE_CELLt      CreateCell;
    lte_l2_Srv_CREATE_NET_CELLt  CreateNetCell;
    lte_l2_Srv_DELETE_CELLt      DeleteCell;

    lte_l2_Srv_CELL_LIST_CMDt    CellListCmd;
    lte_l2_Srv_CELL_LIST_ACKt    CellListAck;

    lte_l2_Srv_CELL_PARM_CMDt    CellParmCmd;
    lte_l2_Srv_CELL_PARM_ACKt    CellParmAck;

    lte_l2_Srv_CELL_INFO_CMDt    CellInfoCmd;
    lte_l2_Srv_CELL_INFO_ACKt    CellInfoAck;

    lte_l2_Srv_CELL_ERRPROFt     CellErrprof;
    
    lte_l2_Srv_CREATE_UEt        CreateUe;
    lte_l2_Srv_UE_SETATTRt       UeSetAttr;
    lte_l2_Srv_DELETE_UEt        DeleteUe;
    lte_l2_Srv_UE_ERRPROFt       UeErrprof;
    lte_l2_Srv_HANDOVERt         Handover;
    lte_l2_Srv_HANDOVER_PREPt    HandoverPrep;
    lte_l2_Srv_HANDOVER_COMMt    HandoverComm;
    lte_l2_Srv_PROCEDURE_FAILt   ProcedureFail;
    lte_l2_Srv_HANDOVER_SUCCt    HandoverSucc;
    lte_l2_Srv_HANDOVER_SOURCEt  HandoverSource;
    lte_l2_Srv_HANDOVER_TARGETt  HandoverTarget;

    lte_l2_Srv_UE_SET_CELLt      UeSetCell;
    lte_l2_Srv_REESTt            Reest;
    lte_l2_Srv_REEST_1t          Reest1;
    lte_l2_Srv_REEST_2t          Reest2;
    lte_l2_Srv_REEST_3t          Reest3;

    lte_l2_Srv_X2_GETLINKt          X2GetLinkCmd;
    lte_l2_Srv_X2_GETLINK_ACKt      X2GetLinkAck;
    lte_l2_Srv_X2_NAKt              X2GetLinkNak;

    lte_l2_Srv_X2_SETLINKt          X2SetLinkCmd;
    lte_l2_Srv_X2_ACKt              X2SetLinkAck;
    lte_l2_Srv_X2_NAKt              X2SetLinkNak;

    lte_l2_Srv_IRAT_GETLINKt        IRatGetLinkCmd;
    lte_l2_Srv_IRAT_GETLINK_ACKt    IRatGetLinkAck;
    lte_l2_Srv_IRAT_NAKt            IRatGetLinkNak;

    lte_l2_Srv_IRAT_SETLINKt        IRatSetLinkCmd;
    lte_l2_Srv_IRAT_ACKt            IRatSetLinkAck;
    lte_l2_Srv_IRAT_NAKt            IRatSetLinkNak;

    lte_l2_Srv_CELL_CONFIGt     CellConfigCmd;
    lte_l2_Srv_CELL_PRECONFIGt  CellPreconfigCmd;
    lte_l2_Srv_CELL_CONFIG_BRt     CellConfigBRCmd;
    lte_l2_Srv_CELL_PRECONFIG_BRt  CellPreconfigBRCmd;
    lte_l2_Srv_CELL_CONFIG_NBt     CellConfigNBCmd;
    lte_l2_Srv_CELL_PRECONFIG_NBt  CellPreconfigNBCmd;

    lte_l2_Srv_CELL_PDCP_RELEASEt CellPdcpReleaseCmd;

    /* Map Driven Mobility */
    lte_l2_Srv_RCP_LOADt            RcpLoadCmd;
    lte_l2_Srv_RCP_LOAD_ENDt        RcpLoadEndCmd;
    lte_l2_Srv_RCP_CLOSEt           RcpCloseCmd;
    lte_l2_Srv_RCPt                 RcpCmd;
    lte_l2_Srv_RCP_UECFGt           RcpUeCfgCmd;
    lte_l2_Srv_RCP_ACKt             RcpAck;
    lte_l2_Srv_RCP_FADINGt          RcpFadingCmd;
    lte_l2_Srv_RCP_UE_SET_GROUPt    RcpUeSetGroupCmd;
    lte_l2_Srv_RCP_UE_SET_INDEXt    RcpUeSetIndexCmd;

};


#pragma    pack()
#endif
