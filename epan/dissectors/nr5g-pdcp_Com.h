/*********************************************************************
  Title: Common PDCP Definitions
 *********************************************************************/


#ifndef nr5g_pdcp_Com_DEFINED
#define nr5g_pdcp_Com_DEFINED


#define nr5g_pdcp_Com_VERSION   "0.2.0"

/*------------------------------------------------------------------*
 |  NOTES                                                           |
 *------------------------------------------------------------------*
 *
 * This interface conforms to the rules specified in `lsu.h'.
 *  
 */

/*------------------------------------------------------------------*
 |  PARAMETERS USED IN PRIMITIVES                                   |
 *------------------------------------------------------------------*/

#define nr5g_pdcp_Com_MAX_DATA_SIZE  9000 /* Max value of PDCP SDU data size
                                            see TS 38.323, par. 4.3.1 */

/*------------------------------------------------------------------*
 |  CODES USED IN PRIMITIVES                                        |
 *------------------------------------------------------------------*/

/*
 * ERROR AND RESULT CODES (nr5g_pdcp_Com_EXXX)
 */

/* GENERIC ERRORS */
#define nr5g_pdcp_Com_ENOERR     0  /* (0x0000) No Error */
#define nr5g_pdcp_Com_ELEN       -1 /* (0xFFFF) Wrong msg length */
#define nr5g_pdcp_Com_EPDULEN    -2 /* (0xFFFE) Wrong PDU length */
#define nr5g_pdcp_Com_EEXP       -3 /* (0xFFFD) Primitive not expected */
#define nr5g_pdcp_Com_ERES       -4 /* (0xFFFC) Resource error */
#define nr5g_pdcp_Com_EPARM      -6 /* (0xFFFA) Wrong parameter */
#define nr5g_pdcp_Com_ETYPE      -7 /* (0xFFF9) Invalid primitive type */

/* LAYER ERRORS */
#define nr5g_pdcp_Com_EFPDCPID   -8 /* */
#define nr5g_pdcp_Com_EBIND      -9 /* */
#define nr5g_pdcp_Com_ESOCK      -10 /* */
#define nr5g_pdcp_Com_EDUP_RBID  -11 /* */
#define nr5g_pdcp_Com_EPDCPID    -12 /* */
#define nr5g_pdcp_Com_EFUEID     -13 /* */
#define nr5g_pdcp_Com_EFCELLID   -14 /* */
#define nr5g_pdcp_Com_EFRBID     -15 /* */
#define nr5g_pdcp_Com_EPDPCTX    -16 /* */
#define nr5g_pdcp_Com_EFPDCP     -17 /* */
#define nr5g_pdcp_Com_EDUPUEID   -18 /* */
#define nr5g_pdcp_Com_EFNSAPI    -19 /* */
#define nr5g_pdcp_Com_ECELLID    -20 /* */
#define nr5g_pdcp_Com_EDUPCELLID -21 /* */
#define nr5g_pdcp_Com_ERLCMODE   -22 /* */
#define nr5g_pdcp_Com_ESAP       -23 /* */
#define nr5g_pdcp_Com_EINTEGRITY -24 /* */
#define nr5g_pdcp_Com_ESOCKCONN  -25 /* */
#define nr5g_pdcp_Com_EFRBTYPE   -26 /* */
#define nr5g_pdcp_Com_ELCTYPE    -27 /* */
#define nr5g_pdcp_Com_ENUMINFO   -28 /* */
#define nr5g_pdcp_Com_ESIDE      -29 /* */
#define nr5g_pdcp_Com_ERBUNCFG   -30 /* */
#define nr5g_pdcp_Com_EFILTFLAG  -31 /* */
#define nr5g_pdcp_Com_EPDCP_TYPE -32 /* */


/* PDCP statistics */
typedef struct
{
	uint TxSduNum;			// Number of UL(DL) PDCP SDUs transmitted
	uint TxSduVol;			// Volume of UL(DL) PDCP SDUs transmitted [bytes]

	uint RxSduNum;			// Number of DL(UL) PDCP SDUs received
	uint RxSduVol;			// Volume of DL(UL) PDCP SDUs received [bytes]

	uint TxSduNumRelDisc;	// Number of UL(DL) PDCP SDUs discarded due to bearer release
	uint TxSduNumOthDisc;	// Number of UL(DL) PDCP SDUs discarded due to other causes
	uint TxSduVolRelDisc;	// Volume of UL(DL) PDCP SDUs discarded due to bearer release [bytes]
	uint TxSduVolOthDisc;	// Volume of UL(DL) PDCP SDUs discarded due to other causes [bytes]

	uint RxPduNumCorrDisc;	// Number of DL(UL) PDCP PDUs discarded due to corrupted header
	uint RxPduNumIntDisc;	// Number of DL(UL) PDCP PDUs discarded due to integrity check fail
	uint RxPduNumReordGap;	// Number of DL(UL) PDCP PDUs gaps after re-ordering
	uint RxPduNumOthDisc;	// Number of DL(UL) PDCP PDUs discarded due to other causes
	uint RxPduVolCorrDisc;	// Volume of DL(UL) PDCP PDUs discarded due to corrupted header
	uint RxPduVolIntDisc;	// Volume of DL(UL) PDCP PDUs discarded due to integrity check fail
	uint RxPduVolOthDisc;	// Volume of DL(UL) PDCP PDUs discarded due to other causes [bytes]

} nr5g_pdcp_Com_StatElem_t;

/* NOTE
 * UL(DL) means consider UL for simulated UE side and DL for simulated net side. 
 * DL(UL) means consider DL for simulated UE side and UL for simulated net side.
 */

typedef enum {

    nr5g_pdcp_Com_ACT_VOID       = 0, /* No Action */
    nr5g_pdcp_Com_ACT_RE_ESTABLISH,   /* Re-establish the entity */
    nr5g_pdcp_Com_ACT_RECOVERY,       /* Data recovery on the entity  */

} nr5g_pdcp_Com_ACT_v;
typedef uchar nr5g_pdcp_Com_ACT_t;

typedef struct {
    nr5g_RbType_v            RbType;
    uchar                    RbId;
    nr5g_pdcp_Com_ACT_t      Action;
} nr5g_pdcp_Com_Action_t;


#endif
