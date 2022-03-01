/*********************************************************************
  Title: Common LTE-PDCP Definitions
 *********************************************************************/


#ifndef lte_pdcp_Com_DEFINED
#define lte_pdcp_Com_DEFINED


#define lte_pdcp_Com_VERSION   "2.1.4"

/*
 * This interface is aligned with LTE specification TS 36.323 V8.5.0
 */

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
 * When more V or FE Fields are concatenated, corrispondent objects
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

#define lte_pdcp_Com_MAX_DATA_SIZE  9000 /* Max value of PDCP SDU data size
                                            current implementation differ from LTE spec. value 8188, 
                                            see TS 36.323, par. 4.3.1 */

/*------------------------------------------------------------------*
 |  CODES USED IN PRIMITIVES                                        |
 *------------------------------------------------------------------*/

/*
 * ERROR AND RESULT CODES (lte_pdcp_Com_EXXX)
 */

/* GENERIC ERRORS */
#define lte_pdcp_Com_ENOERR     0  /* (0x0000) No Error */
#define lte_pdcp_Com_ELEN       -1 /* (0xFFFF) Wrong msg length */
#define lte_pdcp_Com_EPDULEN    -2 /* (0xFFFE) Wrong PDU length */
#define lte_pdcp_Com_EEXP       -3 /* (0xFFFD) Primitive not expected */
#define lte_pdcp_Com_ERES       -4 /* (0xFFFC) Resource error */
#define lte_pdcp_Com_EPARM      -6 /* (0xFFFA) Wrong parameter */
#define lte_pdcp_Com_ETYPE      -7 /* (0xFFF9) Invalid primitive type */

/* LAYER ERRORS */
#define lte_pdcp_Com_EFPDCPID   -8 /* */
#define lte_pdcp_Com_EBIND      -9 /* */
#define lte_pdcp_Com_ESOCK      -10 /* */
#define lte_pdcp_Com_EDUP_RBID  -11 /* */
#define lte_pdcp_Com_EPDCPID    -12 /* */
#define lte_pdcp_Com_EFUEID     -13 /* */
#define lte_pdcp_Com_EFCELLID   -14 /* */
#define lte_pdcp_Com_EFRBID     -15 /* */
#define lte_pdcp_Com_EPDPCTX    -16 /* */
#define lte_pdcp_Com_EFPDCP     -17 /* */
#define lte_pdcp_Com_EDUPUEID   -18 /* */
#define lte_pdcp_Com_EFNSAPI    -19 /* */
#define lte_pdcp_Com_ECELLID    -20 /* */
#define lte_pdcp_Com_EDUPCELLID -21 /* */
#define lte_pdcp_Com_ERLCMODE   -22 /* */
#define lte_pdcp_Com_ESAP       -23 /* */
#define lte_pdcp_Com_EINTEGRITY -24 /* */
#define lte_pdcp_Com_ESOCKCONN  -25 /* */
#define lte_pdcp_Com_EFRBTYPE   -26 /* */
#define lte_pdcp_Com_ELCTYPE    -27 /* */
#define lte_pdcp_Com_ENUMINFO   -28 /* */
#define lte_pdcp_Com_ESIDE      -29 /* */
#define lte_pdcp_Com_ERBUNCFG   -30 /* */
#define lte_pdcp_Com_EFILTFLAG  -31 /* */
#define lte_pdcp_Com_EPDCP_TYPE -32 /* */
#define lte_pdcp_Com_EROHC      -33 /* */

/* MBMS ACK ERRORS */
#define lte_pdcp_Com_ACKERRNONE          (0) /* MBMS ack no error */
#define lte_pdcp_Com_ACKERRPDCPNETNOTCFG (1) /* MBMS ack error pdcp net not configured yet */
#define lte_pdcp_Com_ACKERRPDCPNOTCFG    (2) /* MBMS ack error pdcp not configured yet */
#define lte_pdcp_Com_ACKERRPDCPNETALRCFG (3) /* MBMS ack error pdcp net already configured */
#define lte_pdcp_Com_ACKERRPDCPALRCFG    (4) /* MBMS ack error pdcp already configured */
#define lte_pdcp_Com_ACKERRNOENOUGHRES   (5) /* MBMS ack error no enough resources */


/* PDCP statistics */
typedef struct
{
    uint PdcpTroughTx; /* PDCP Tx throughput (throughput at application layer) (Byte/sec) */
    uint PdcpTroughRx; /* PDCP Tx throughput (throughput at application layer) (Byte/sec) */
} lte_pdcp_Com_Stat_t;

#endif
