#ifndef __PACKET_EXTREMEMESH_H__
#define __PACKET_EXTREMEMESH_H__

/*
 * The Mesh header and all extension headers use a "next protocol" enumeration.
 * This tells what protocol is to come.  The next protocol may be an extension
 * header (like the AHR header) or it may terminate (as with a payload).
 */

#ifndef ETHERTYPE_IEEE_EXTREME_MESH
#define ETHERTYPE_IEEE_EXTREME_MESH 0x88a9
#endif

typedef enum _MeshNextProtocol
{
    MESH_NEXT_PROTOCOL_INVALID                      = -1,

    MESH_NEXT_PROTOCOL_MESH                         = 0,    // Extension
    MESH_NEXT_PROTOCOL_MCH                          = 1,    // Extension
    MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH             = 2,    // Terminating
    MESH_NEXT_PROTOCOL_PS                           = 3,    // Terminating
    MESH_NEXT_PROTOCOL_HELLO                        = 4,    // Terminating
    MESH_NEXT_PROTOCOL_LOCATION                     = 5,    // Terminating
    MESH_NEXT_PROTOCOL_SECURITY                     = 6,    // Terminating
    MESH_NEXT_PROTOCOL_SECURED_PAYLOAD              = 7,    // Extension
    MESH_NEXT_PROTOCOL_TEST                         = 8,    // Terminating
    MESH_NEXT_PROTOCOL_FRAGMENT                     = 9,    // Terminating
    MESH_NEXT_PROTOCOL_CFPU                         = 10,   // Terminating
    MESH_NEXT_PROTOCOL_EAPOM                        = 11,   // Terminating
    MESH_NEXT_PROTOCOL_NULL                         = 12,   // Terminating
    MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH_NO_ADDR     = 13,   // Terminating
    MESH_NEXT_PROTOCOL_L2_UPDATE                    = 14,   // Terminating
    MESH_NEXT_PROTOCOL_PROBE_MESSAGE                = 15,   // Terminating

    MESH_NEXT_PROTOCOL_EOL
} MeshNextProtocol;


typedef enum _MeshPathSelectionFrameType
{
    MESH_PS_FRAME_INVALID = -1,

    MESH_PS_FRAME_AREQ    =  1,    // Authorization Request
    MESH_PS_FRAME_AREP    =  2,    // Authorization Reply
    MESH_PS_FRAME_BREQ    =  3,    // Bind Request
    MESH_PS_FRAME_BREP    =  4,    // Bind Reply
    MESH_PS_FRAME_BANN    =  5,    // Bind Announcement
    MESH_PS_FRAME_BRED    =  6,    // Bind Removed
    MESH_PS_FRAME_SREQ    =  7,    // Status Request
    MESH_PS_FRAME_SREP    =  8,    // Status Reply
    MESH_PS_FRAME_PREQ    =  9,    // Path Request
    MESH_PS_FRAME_PREP    =  10,   // Path Reply
    MESH_PS_FRAME_PERR    =  11,   // Path Error
    MESH_PS_FRAME_PRST    =  12,   // Path Reset
    MESH_PS_FRAME_PREM    =  13,   // Proxy Remove
    MESH_PS_FRAME_TRACE   =  14,   // Trace Path
    MESH_PS_FRAME_PRER    =  15,   // Proxy Error

    MESH_PS_FRAME_EOL
} MeshPathSelectionFrameType;

#define MESH_NEXT_PROTOCOL_STRINGS  {"Mesh", "MCH", "Eth", "PS", "Hello", \
                                     "Loc", "Sec", "MSH", "Test", "Frag", \
                                     "CFPU", "EAPOM", "NULL", "ENA", "L2Up", \
                                     "Probe"}
extern const char *gMeshNextProtocolStrings[MESH_NEXT_PROTOCOL_EOL];

void proto_register_handoff_extrememesh(void);

#endif
