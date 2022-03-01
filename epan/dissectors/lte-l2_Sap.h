/********************************************************************
$Source$
$Author$
$Date$
---------------------------------------------------------------------
Project :       LTE SERVER
Description :   The LTE SAPIs - lte_l2_Sap.h
---------------------------------------------------------------------
$Revision$
$State$
$Name$
---------------------------------------------------------------------
$Log$
*********************************************************************/

#ifndef  lte_l2_Sap_DEFINED
#define  lte_l2_Sap_DEFINED



/********************************************************************
 * THE LTE SAPIs
 ********************************************************************/

#define  lte_l2_Sap_VERSION      "1.5.0"


/*
 * Server
 */
#define  lte_l2_Sap_SRV_ERROR        1
#define  lte_l2_Sap_OM               2
#define  lte_l2_Sap_LIC              3
//OM Test mode
#define  lte_l2_Sap_OM_TM            4


/*
 * RLCMAC
 */
#define  lte_l2_Sap_RLCMAC_ERROR	11
#define  lte_l2_Sap_RLCMAC_CMAC		12
#define  lte_l2_Sap_RLCMAC_CRLC		13
#define  lte_l2_Sap_RLCMAC_STAT		14
#define  lte_l2_Sap_RLCMAC_TEST		15
#define  lte_l2_Sap_RLCMAC_CMAC_TM	16
#define  lte_l2_Sap_RLCMAC_CRLC_TM	17
#define  lte_l2_Sap_RLCMAC_SCHED	20
#define  lte_l2_Sap_RLCMAC_MBMS 	21
#define  lte_l2_Sap_RLCMAC_DRLC_TM 	27
#define  lte_l2_Sap_RLCMAC_STAT_TM 	28

/*
 * PDCP
 */
#define	 lte_l2_Sap_PDCP_ERROR	    31
#define  lte_l2_Sap_PDCP_CTRL		32
#define  lte_l2_Sap_PDCP_AUX		33
#define  lte_l2_Sap_PDCP_DATA		34
#define  lte_l2_Sap_PDCP_STAT		35
#define  lte_l2_Sap_PDCP_CTRL_TM	36
#define  lte_l2_Sap_NR_PDCP_CTRL	37
#define  lte_l2_Sap_NR_PDCP_AUX		38
#define  lte_l2_Sap_NR_PDCP_DATA	39
#define  lte_l2_Sap_NR_PDCP_STAT	40
#define  lte_l2_Sap_NR_PDCP_CTRL_TM	43


/*
 * UUDG
 */
#define  lte_l2_Sap_UUDG_ERROR       51
#define  lte_l2_Sap_UUDG_UUDG        52
#define  lte_l2_Sap_UUDG_NAT         53
#define  lte_l2_Sap_UUDG_NAT6        54
#define  lte_l2_Sap_UUDG_ICMP6       55
#define  lte_l2_Sap_UUDG_CTL         56

/*
 * NUDG
 */
#define  lte_l2_Sap_NUDG_ERROR       71
#define  lte_l2_Sap_NUDG_NUDG        72
#define  lte_l2_Sap_NUDG_GI          73
#define  lte_l2_Sap_NUDG_GI6         74
#define  lte_l2_Sap_NUDG_CTL         75


/*
 * DATA SOURCE for TM 
 */
#define lte_l2_Sap_TM_DATA_ERROR     81
#define lte_l2_Sap_TM_DATA_PATT      82
#define lte_l2_Sap_TM_DATA_LOOP      83
#define lte_l2_Sap_TM_DATA_PRBS      84
#define lte_l2_Sap_TM_DATA_XTRN      85
#define lte_l2_Sap_TM_DATA_TSRV      86


/*
 * CNTR
 */
#define  lte_l2_Sap_CNTR_ERROR       121
#define  lte_l2_Sap_CNTR_CNTR        122

/*
 * MSWITCH
 */
#define  lte_l2_Sap_MSWITCH_ERROR    111
#define  lte_l2_Sap_MSWITCH_MSWITCH  112

/*
 * ROHC
 */
#define  lte_l2_Sap_ROHC_ERROR       91
#define  lte_l2_Sap_ROHC_ROHC        92

/*
 * NR RLCMAC
 */
#define  lte_l2_Sap_NR_RLCMAC_ERROR	141
#define  lte_l2_Sap_NR_RLCMAC_L1_TEST	142
#define  lte_l2_Sap_NR_RLCMAC_CMAC	143
#define  lte_l2_Sap_NR_RLCMAC_CRLC	144
#define  lte_l2_Sap_NR_RLCMAC_CMAC_TM	146
#define  lte_l2_Sap_NR_RLCMAC_CRLC_TM	147
#define  lte_l2_Sap_NR_RLCMAC_DRLC_TM	148
#define  lte_l2_Sap_NR_RLCMAC_AUX       149  /* to PDCP */
#define  lte_l2_Sap_NR_RLCMAC_TM        150  /* to PDCP */
#define  lte_l2_Sap_NR_RLCMAC_UM        151  /* to PDCP */
#define  lte_l2_Sap_NR_RLCMAC_AM        152  /* to PDCP */
#define  lte_l2_Sap_NR_RLCMAC_STAT      154
#define  lte_l2_Sap_NR_RLCMAC_STAT_TM   155
#define  lte_l2_Sap_NR_SCG_RLCMAC_CMAC		156
#define  lte_l2_Sap_NR_SCG_RLCMAC_CRLC		157
#define  lte_l2_Sap_NR_SCG_RLCMAC_CMAC_TM	158
#define  lte_l2_Sap_NR_SCG_RLCMAC_CRLC_TM	159
#define  lte_l2_Sap_NR_SCG_RLCMAC_DRLC_TM	160
#define  lte_l2_Sap_NR_SCG_RLCMAC_STAT      161

#endif
