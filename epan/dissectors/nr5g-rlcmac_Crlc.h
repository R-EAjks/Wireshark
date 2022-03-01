#ifndef nr5g_rlcmac_Crlc_DEFINED
#define nr5g_rlcmac_Crlc_DEFINED

//#include "lsu.h"
#include "nr5g.h"

#define nr5g_rlcmac_Crlc_VERSION   "0.1.1"

/*
 * This interface conforms to the rules specified in 'lsu.h'.
 */

#pragma pack(1)

/*------------------------------------------------------------------*
 |  PRIMITIVES OPCODES                                              |
 *------------------------------------------------------------------*/

/*
 * ERR SAP
 */

#define nr5g_rlcmac_Crlc_ERROR_IND			0x401
#define nr5g_rlcmac_Crlc_REJECT_IND			0x402
#define nr5g_rlcmac_Crlc_NC_ERROR_IND		0x403

/*
 * CRLC SAP
 */

#define  nr5g_rlcmac_Crlc_CONFIG_CMD	0x01
#define  nr5g_rlcmac_Crlc_CONFIG_ACK	(0x100 + nr5g_rlcmac_Crlc_CONFIG_CMD)
#define  nr5g_rlcmac_Crlc_CONFIG_NAK	(0x200 + nr5g_rlcmac_Crlc_CONFIG_CMD)

#define  nr5g_rlcmac_Crlc_STATUS_IND    0x402

/* Trigger a Recommended bit rate query. */
#define  nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_CMD   0x04
#define  nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_ACK   (0x100 + nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_CMD)
#define  nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_NAK   (0x200 + nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_CMD)

/* Indicate a Recommended bit rate from net side */
#define  nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_IND   (0x400 + nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_CMD)

/*------------------------------------------------------------------*
 |  STRUCTURES USED IN PRIMITIVES                                   |
 *------------------------------------------------------------------*/

/*
 * ER field value
 */
typedef enum {

	nr5g_rlcmac_Crlc_ER_VOID       = 0, /* No Action */
	nr5g_rlcmac_Crlc_ER_ESTABLISH,      /* Establish a new RLC entity */
	nr5g_rlcmac_Crlc_ER_RE_ESTABLISH,   /* Re-establish a RLC entity */
	nr5g_rlcmac_Crlc_ER_MODIFY,         /* Modify RLC entity parameters */
	nr5g_rlcmac_Crlc_ER_RELEASE,        /* Release a RLC entity */
	nr5g_rlcmac_Crlc_ER_SUSPEND,        /* Supend a RLC entity */
    nr5g_rlcmac_Crlc_ER_RESUME,         /* Resume a RLC entity */

} nr5g_rlcmac_Crlc_ER_v;
typedef uchar nr5g_rlcmac_Crlc_ER_t;

typedef struct {

	uint        discardTimer; /* [ms] -1 means "infinity" */

} nr5g_rlcmac_Crlc_TxTmParm_t;

typedef struct {

	uchar	Spare;

} nr5g_rlcmac_Crlc_RxTmParm_t;

/*
 * Transparent mode configuration
 */
typedef struct nr5g_rlcmac_Crlc_TmParm_s {

	uchar							TxActiveFlag;
	nr5g_rlcmac_Crlc_TxTmParm_t		Tx;
	
	uchar							RxActiveFlag;
	nr5g_rlcmac_Crlc_RxTmParm_t		Rx;

} nr5g_rlcmac_Crlc_TmParm_t;

typedef enum {
	nr5g_rlcmac_Crlc_SnLength_Um_6	= 6,
	nr5g_rlcmac_Crlc_SnLength_Um_12	= 12,
} nr5g_rlcmac_Crlc_SnLength_Um_v;
typedef uchar nr5g_rlcmac_Crlc_SnLength_Um_t;

typedef enum {
	nr5g_rlcmac_Crlc_SnLength_Am_12	= 12,
	nr5g_rlcmac_Crlc_SnLength_Am_18	= 18,
} nr5g_rlcmac_Crlc_SnLength_Am_v;
typedef uchar nr5g_rlcmac_Crlc_SnLength_Am_t;

typedef struct {

	nr5g_rlcmac_Crlc_SnLength_Um_t	SnLength;
	uint	discardTimer; /* [ms] -1 means "infinity" */

} nr5g_rlcmac_Crlc_TxUmParm_t;

typedef struct {

	nr5g_rlcmac_Crlc_SnLength_Um_t	SnLength;
	uint		t_Reassembly; /* [ms] */

} nr5g_rlcmac_Crlc_RxUmParm_t;

/*
 * Unacknowledged mode configuration
 */
typedef struct {

	uchar							TxActiveFlag;
	nr5g_rlcmac_Crlc_TxUmParm_t		Tx;
	
	uchar							RxActiveFlag;
	nr5g_rlcmac_Crlc_RxUmParm_t		Rx;
	
} nr5g_rlcmac_Crlc_UmParm_t;

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

/*
 * Acknowledged mode configuration
 */
typedef struct {

	nr5g_rlcmac_Crlc_TxAmParm_t Tx;
	nr5g_rlcmac_Crlc_RxAmParm_t Rx;

} nr5g_rlcmac_Crlc_AmParm_t;

/*------------------------------------------------------------------*
 |  LAYOUT OF PRIMITIVES                                            |
 *------------------------------------------------------------------*/

/*
 * nr5g_rlcmac_Crlc_ERROR_IND
 */
typedef struct {
    short   Err;        /* Error code */
    char    Desc[1];    /* Error description (var len ASCIIZ string) */
} nr5g_rlcmac_Crlc_ERROR_t;


/*
 * nr5g_rlcmac_Crlc_REJECT_IND
 */
typedef struct {
    short   Err;        /* Cause of rejection */
    short   Spare;      /* zero */
    /*
     * The full rejected message (including its header) is placed here */
} nr5g_rlcmac_Crlc_REJECT_t;


/*
 * ACK
 */

typedef struct {
	uint		UeId;		/* UE Id */
	nr5g_RbType_v	RbType;
	uchar		RbId;		/* Rb id */
} nr5g_rlcmac_Crlc_ACK_t;

/*
 * NAK
 */

typedef struct {
	uint		UeId;		/* UE Id */
	nr5g_RbType_v	RbType;
	uchar		RbId;		/* Rb id */
	short	    Err;		/* Error code */
} nr5g_rlcmac_Crlc_NAK_t;

/*
 * nr5g_rlcmac_Crlc_CONFIG_CMD
 * This primitive is used by upper layers to establish, re-establish,
 * release, stop, continue or modify one RLC entity.
 */
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

/*
 * NOTES
 *
 * (1) The value of 'RbId' is the srb-Identity
 *     or the drb-Identity (3GPP 38.331), depending on 'RbType'.
 *     Ranges used: 1-2 SRB (srb-Identity 1-2), 4-32 DRB (drb-Identity 4-32).
 */
/*
 * nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_CMD
 * nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_IND
 */
typedef struct {
    uint                UeId;       /* UE Id */
    nr5g_RbType_v       RbType;
    uchar               RbId;       /* Rb id */
    nr5g_Direction_v    Direction;  /* UL for TX and DL for RX. */
    uint                Bitrate;    /* Bit Rate [kbit/s, must be != 0] */

} nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_t;


/*------------------------------------------------------------------*
 |  SUMMARY OF PRIMITIVES                                           |
 *------------------------------------------------------------------*/

typedef union {

	/* ERR SAP */
	nr5g_rlcmac_Crlc_ERROR_t	ErrorInd;
	nr5g_rlcmac_Crlc_REJECT_t	RejectInd;
	
	nr5g_rlcmac_Crlc_ACK_t		Ack;
	nr5g_rlcmac_Crlc_NAK_t		Nak;

	/* CRLC SAP */
	nr5g_rlcmac_Crlc_CONFIG_CMD_t       ConfigCmd;
    nr5g_rlcmac_Crlc_RECOMMENDED_BITRATE_t RecBitrate;
} nr5g_rlcmac_Crlc_PRIMt;


#pragma    pack()
#endif
