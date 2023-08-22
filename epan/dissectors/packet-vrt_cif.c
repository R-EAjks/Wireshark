/* packet-vrt-cif.c
 * Routines for CIF portion of VRT (VITA 49) packet disassembly
 * Copyright 2020 The MITRE Corporation: original extension
 * This software was produced for the U. S. Government under Contract No. FA8702-19-C-0001,
 * and is subject to the Rights in Noncommercial Computer Software and Noncommercial Computer
 * Software Documentation Clause DFARS 252.227-7014 (FEB 2014)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector layers on top of the packet-vrt dissector to parse context and command payloads.
 * The VITA Radio Transport (VRT) as described in ANSI/VITA 49.2-2017 provides a baseline description
 * but is open ended regarding extension packet types. To handle both of these, this dissector is
 * structured to read the configuration from a separate description file.
 */


#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/ftypes/ftypes.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>
#include <wsutil/strtoi.h>
#include <wsutil/type_util.h>
#include "ws_attributes.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>

#include "packet-vrt.h"

/*******************************************************************************/
/* LOCAL TYPE DEFINITIONS */
/*******************************************************************************/
typedef enum {
    vrt_payload_empty = 0,           /* payload is empty */
    vrt_payload_cif = 1,             /* payload has CIFs only */
    vrt_payload_cif_field = 2,       /* payload has CIFs + fields */
    vrt_payload_warn = 3,            /* payload has Warning map & fields only */
    vrt_payload_err = 4,             /* payload has Error map & fields only */
    vrt_payload_warn_err = 5,        /* payload has both Warning and Error maps & fields */
    vrt_payload_undefined = 6        /* Payload is undefined */
} vrt_payload_type_t;

typedef struct vrt_cif_info_descript_struct
{
  char *text;
  expert_field *ei;

} vrt_cif_info_descript_t;

typedef struct vrt_cif_warnerr_struct
{
  char *name;
  char *descript;

} vrt_cif_warnerr_t;

typedef enum {
    vrt_cif_type_raw, 
    vrt_cif_type_hex, 
    vrt_cif_type_int, 
    vrt_cif_type_uint, 
    vrt_cif_type_bool, 
    vrt_cif_type_fixed, 
    vrt_cif_type_ufixed, 
    vrt_cif_type_dynamic,
    vrt_cif_type_string,
    vrt_cif_type_enum,
    vrt_cif_type_array,
    /* pseudo-field types */
    vrt_cif_type_link
} vrt_cif_type_t;

typedef struct vrt_cif_record_descript_struct
{
  char *name;
  char *abbrev;
  wmem_list_t *fields;  /* of (vrt_cif_field_descript_t *) */
  /* Space to hold handles for each possible associated display field */
  int   tree_pid;
  int   ett_pid;
  vrt_cif_info_descript_t *info;
} vrt_cif_record_descript_t;

typedef struct vrt_cif_record_array_descript_struct
{
  /* Basic properties are already stored in field_descript holding pointer to this structure.
     we just need to add the hierarchical part underneath that. */
  vrt_cif_record_descript_t *hdr_req;
  guint32 hdr_bitmap;
  vrt_cif_record_descript_t *hdr_opt[32]; /* index bit # */

  vrt_cif_record_descript_t *rec_req;
  guint32 rec_bitmap;
  vrt_cif_record_descript_t *rec_opt[32]; /* index bit # */

  guint rec_idx_offset;
  guint rec_idx_width;  /* use 0 as alias for no index */

  /* Space to hold handles for each possible associated display field */
  int field_ett_pid;
  int hdr_pid;
  int hdr_ett_pid;
  int hdr_map_pid;
  int hdr_map_ett_pid;
  int hdr_map_bit_pid[32];
// [FIXME] I think?? you can use the same pid for calls to each record??
  int rec_pid;
  int rec_ett_pid;
  int rec_map_pid;
  int rec_map_ett_pid;
  int rec_map_bit_pid[32];

} vrt_cif_record_array_descript_t;

/* Description of a CIF data field element */
typedef struct vrt_cif_field_descript_struct
{
   vrt_cif_type_t type;
   guint offset;
   gboolean is_relative;
   guint width;

   /* this could be a union based on type, but we'll just ignore the irrelevant fields */
   const char *name;
   const char *abbrev;
   const char *text;
   guint point;
   gdouble scale;

   /* use structures to match the hf_register_info so we can manage the allocations all in one place */
   value_string *enum_strings;
   unit_name_string unit_strings;

   vrt_cif_record_array_descript_t *array_descript;

   guint link; // index of map_descript with chained cif
  /* Space to hold handles for each possible associated display field */
   int   pid;
   vrt_cif_info_descript_t *info;

} vrt_cif_field_descript_t;

typedef struct vrt_cif_enable_descript_struct
{
  char *name;
  char *abbrev;
  gboolean is_link;
  wmem_list_t *fields;  /* of (vrt_cif_field_descript_t *) */
  /* Space to hold handles for each possible associated display field */
  int   bit_pid;
  int   tree_pid;
  int   ett_pid;
  int   warn_bit_pid;
  int   warn_tree_pid;
  int   warn_ett_pid;
  int   warn_tree_array[32];
  int   err_bit_pid;
  int   err_tree_pid;
  int   err_ett_pid;
  int   err_tree_array[32];
  vrt_cif_info_descript_t *info;
} vrt_cif_enable_descript_t;

/* A cif map describes the indicator bits for a given cif.
   At dissection, the description of the enabled bits are used to parse the data fields
   Both the map and the fields must be processed in order
 */
typedef struct vrt_cif_map_descript_struct
{
  char *name;
  char *abbrev;
  guint index;
  guint32 bitmap;
  vrt_cif_enable_descript_t enables[32]; /* index = bit # */
  /* Space to hold handles for each possible associated display field */
  int   pid;
  int   ett_pid;
  int   warn_pid;
  int   warn_ett_pid;
  int   err_pid;
  int   err_ett_pid;
  vrt_cif_info_descript_t *info;
} vrt_cif_map_descript_t;

/* The cam field of control packets is mostly defined at the parent dissector level,
   but extension control packets have some user defiend fields which can be redefined
   for a given packet class
 */
typedef struct vrt_cif_extension_cam_descript_struct
{
  vrt_payload_type_t user_req;  /* override reserved bit 15 */
  int   pid;
  int   ett_pid;
  wmem_list_t *fields;  /* of (vrt_cif_field_descript_t *) */
  vrt_cif_info_descript_t *info;
} vrt_cif_extension_cam_descript_t;

typedef struct vrt_cif_class_descript_struct
{
  wmem_array_t *cif_list;  /* of (vrt_cif_map_descript *); key = cif # */
  wmem_map_t   *warnerr_bitmap;   /* of (vrt_cif_warnerr_t *); key = bit # */
  vrt_cif_extension_cam_descript_t *extension_cam;
  vrt_cif_info_descript_t *info;
} vrt_cif_class_descript_t;

typedef struct vrt_cif_class_id_index_struct
{
  guint64 base;
  guint64 mask;
  guint64 index;
} vrt_cif_class_id_index_t;

typedef struct vrt_cif_class_id_map_struct
{
  wmem_map_t *descript_table;     /* of (vrt_cif_class_descript_t *); key = class id */
  wmem_array_t *id_map_list;        /* of vrt_cif_class_id_index_t */

} vrt_cif_class_id_map_t;

typedef struct vrt_cif_configuration_struct
{
  vrt_cif_class_id_map_t cif_class_table;
  vrt_cif_class_id_map_t ecif_class_table;
  guint node_count;          /* total number of fields with subtrees across all descriptions */
  guint leaf_count;          /* total number of leaf fields across all descriptions */
  const gchar *filename;

} vrt_cif_configuration_t;

typedef struct vrt_cif_register_info_struct
{
  hf_register_info *hf;
  guint hf_size;
  gint **ett;
  guint ett_size;

  guint hf_count;
  guint ett_count;

} vrt_cif_register_info_t;

typedef struct vrt_cif_register_info_index_struct
{
  hf_register_info *hf;
  gint **ett;

} vrt_cif_register_info_index_t;

typedef struct vrt_cif_field_display_cb_data_struct
{
  packet_info *pinfo;
  tvbuff_t *tvb;
  int offset;
  gint nwords;
  proto_tree *tree;
  gint offset_delta;  /* running max value over loop */

} vrt_cif_field_display_cb_data_t;

/*******************************************************************************/
/* LOCAL VARIABLES */
/*******************************************************************************/

void proto_register_vrt_cif(void);
void proto_reg_handoff_vrt_cif(void);

static const gchar *pref_filename = NULL;
static gboolean pref_class_fallback = FALSE;
static wmem_allocator_t *vrt_cif_cfg_scope = NULL;

static int proto_vrt_cif = -1;

/* PIDs for default fields */
static int hf_vrt_cif_raw = -1; /* Undecoded payload */
static gint ett_top = -1;

static int hf_vrt_cif_warn = -1;
static gint ett_warn = -1;
static int hf_vrt_cif_err = -1;
static gint ett_err = -1;

static expert_field ei_proto_err = EI_INIT;
static expert_field ei_proto_warn = EI_INIT;
static expert_field ei_proto_note = EI_INIT;
static expert_field ei_cfg_err = EI_INIT;
static expert_field ei_cfg_warn = EI_INIT;
static expert_field ei_cfg_note = EI_INIT;

static vrt_cif_register_info_t vrt_cif_register_info = { NULL, 0, NULL, 0, 0, 0 };
static vrt_cif_configuration_t *vrt_cif_configuration = NULL;
/* This isn't a value that will ever appear, but we use it as a proxy for not defined/unknown */
static const guint64 default_classid = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);

/* functions to handle building local config structure from XML */
static vrt_cif_class_descript_t *find_class_descript(vrt_cif_class_id_map_t *dt, guint64 classid, guint64 *match_index);
static void parse_config_file(const char *filename);
static void parse_cif_class(const xmlNodePtr base);
static void parse_cif_map(const xmlNodePtr base, wmem_array_t *cif_list);
static void parse_cif_enable(const xmlNodePtr base, vrt_cif_enable_descript_t *en_descript, const char *parent_abbrev);
static vrt_cif_type_t parse_type(xmlChar *str);
static vrt_cif_field_descript_t *parse_field(const xmlNodePtr base, const char *parent_abbrev);
static vrt_cif_info_descript_t *parse_info(const xmlNodePtr base);
static void parse_warnerr_bitmap(const xmlNodePtr base, wmem_map_t *warnerr_bitmap);
static vrt_cif_extension_cam_descript_t* parse_extension_cam(const xmlNodePtr base);
static void parse_record_array(const xmlNodePtr base, vrt_cif_record_array_descript_t *ra_descript, const char *parent_abbrev);
static vrt_cif_record_descript_t* parse_record_enable(const xmlNodePtr base, const char* parent_abbrev);

static void init_record_array_descript(vrt_cif_record_array_descript_t *ptr);
static void init_map_descript_array(vrt_cif_map_descript_t *map_descript, guint count);
static void init_enable_descript_array(vrt_cif_enable_descript_t *en_descript, guint count);

/* functions to build up WS registration structure */
static vrt_cif_map_descript_t *get_map_descript(wmem_array_t *cif_list, guint map_index);
static gboolean add_map_field(vrt_cif_field_descript_t *field, wmem_list_t **list_ptr);

static ftenum_t width_to_enum(guint width, gboolean is_signed, const char *name);
static void build_hf_field(void *v, void *p);  /* list foreach callback */
static void build_hf_class(gpointer k _U_, gpointer v, gpointer p);  /* map foreach callback */
static void build_hf_record(vrt_cif_register_info_index_t *ptr, vrt_cif_record_descript_t *rec);
static void build_hf_array(vrt_cif_register_info_index_t *ptr, vrt_cif_field_descript_t *field);
static void set_default_hf_configuration(vrt_cif_register_info_index_t *head);
static void build_hf_configuration(void);
static void load_and_register_hf_fields(const char* match _U_);
static void deregister_hf_fields(void);
static header_field_info *add_leaf(vrt_cif_register_info_index_t *ptr, gint *pid);
static header_field_info *add_node(vrt_cif_register_info_index_t *ptr, gint *pid, gint *ett);
static void promote_leaf(vrt_cif_register_info_index_t *ptr, gint *ett);

/* functions to parse and display packet */
static int display_unparsed_payload(proto_tree *cif_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, gint nwords);
static void display_cif_field_cb(void *v, void *p);  /* list foreach callback */
static void display_warn_err_mask(tvbuff_t* tvb, proto_tree* tree, int offset, int* pid_list);
static int display_array(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int start_offset, vrt_cif_record_array_descript_t *arr);
static gint dissect_cif(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, wmem_array_t* map_list,
                        int init_offset, wmem_queue_t * field_list, vrt_payload_type_t type);
static int dissect_vrt_cif(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

/* callback functions for wireshark API  */
static void init_dissector(void);
static void cleanup_dissector(void);
static void shutdown_dissector(void);

static void apply_prefs(void);

/*******************************************************************************/
/*******************************************************************************/

/* ws_str calls reqire base to be known, use this function to parse c-style prefixes to find base.
   This should probably be promoted to a general utility function, but for now define it here */
static gboolean str_with_prefix_tou(const gchar* str, const gchar** endptr, guint* cint)
{
  gboolean ret = FALSE;
  *cint = 0;
  if(str != NULL) {
    /* [TODO] ws_str / g_str only provides decimal and hex calls. Since binary and octal are rare,
       we won't go through the effort of implementing the code for them yet */
    if(g_str_has_prefix(str,"0x") || g_str_has_prefix(str,"0X")) {
      ret =  ws_hexstrtou(&str[2], endptr, cint);
    } else if(g_str_has_prefix(str,"0b") || g_str_has_prefix(str,"0B")) {
      report_warning("Parsing of binary literal not implemented (%s)", str);
    } else if((strlen(str) > 1) && (g_str_has_prefix(str,"0") || g_str_has_prefix(str,"0"))) {
      report_warning("Parsing of octal literal not implemented (%s)", str);
    } else {
      /* default to decimal */
      ret = ws_strtou(str, endptr, cint);
    }
  }
  return ret;
}
static gboolean str_with_prefix_tou64(const gchar* str, const gchar** endptr, guint64* cint)
{
  gboolean ret = FALSE;
  *cint = 0;
  if (str != NULL) {
      /* [TODO] ws_str / g_str only provides decimal and hex calls. Since binary and octal are rare,
         we won't go through the effort of implementing the code for them yet */
      if (g_str_has_prefix(str, "0x") || g_str_has_prefix(str, "0X")) {
          ret = ws_hexstrtou64(&str[2], endptr, cint);
      }
      else if (g_str_has_prefix(str, "0b") || g_str_has_prefix(str, "0B")) {
          report_warning("Parsing of binary literal not implemented (%s)", str);
      }
      else if ((strlen(str) > 1) && (g_str_has_prefix(str, "0") || g_str_has_prefix(str, "0"))) {
          report_warning("Parsing of octal literal not implemented (%s)", str);
      }
      else {
          /* default to decimal */
          ret = ws_strtou64(str, endptr, cint);
      }
  }
  return ret;
}

/*******************************************************************************/

static vrt_cif_class_descript_t *find_class_descript(vrt_cif_class_id_map_t *dt, guint64 classid, guint64 *match_index)
{
  guint64 idx = classid;

  /* Walk through list of masks and compare target classid */
  for(guint n = 0; n < wmem_array_get_count(dt->id_map_list); ++n)
  {
    vrt_cif_class_id_index_t *check = wmem_array_index(dt->id_map_list,n);
    if((classid & check->mask) == check->base)
    {
      idx = check->index;
      break;
    }
  }
  if(match_index != NULL) {
    *match_index = idx;
  }
  return (vrt_cif_class_descript_t *) wmem_map_lookup(dt->descript_table, &idx);
}

/* add_leaf(), add_node(), and promote_leaf() operate on the preallocated info structure
   it is important that they not be called more often than the counted number of nodes/leaves */
static header_field_info *add_leaf(vrt_cif_register_info_index_t *ptr, gint *pid)
{
  header_field_info *ret = &(ptr->hf->hfinfo);
  HFILL_INIT(*(ptr->hf));
  ptr->hf->p_id = pid;

//   Check the balance between field counting while parsing config and field setting as we build the tables
//   In particular this may be a problem for ill-formed configuration files
  ++vrt_cif_register_info.hf_count;
  if((ptr->hf) >= &vrt_cif_register_info.hf[vrt_cif_register_info.hf_size]) {
    guint64 idx = ((guint64)ptr->hf - (guint64) vrt_cif_register_info.hf) / sizeof(hf_register_info);
    report_warning("HF Table overflow [%lu]!", idx);
  }

  (ptr->hf)++;
  return ret;
}

static header_field_info *add_node(vrt_cif_register_info_index_t *ptr, gint *pid, gint *ett)
{
  *(ptr->ett) = ett;

//   Check the balance between field counting while parsing config and field setting as we build the tables
//   In particular this may be a problem for ill-formed configuration files
  ++vrt_cif_register_info.ett_count;
  if((ptr->ett) >= &vrt_cif_register_info.ett[vrt_cif_register_info.ett_size]) {
    guint64 idx = ((guint64)ptr->ett - (guint64) vrt_cif_register_info.ett) / sizeof(gint *);
    report_warning("ETT Table overflow[%lu]!", idx);
  }

  (ptr->ett)++;
  return add_leaf(ptr, pid);
}

/* Change a leaf to a node by adding an ett pid */
static void promote_leaf(vrt_cif_register_info_index_t *ptr, gint *ett)
{
  *(ptr->ett) = ett;
  (ptr->ett)++;

//   Check the balance between field counting while parsing config and field setting as we build the tables
//   In particular this may be a problem for ill-formed configuration files
  ++vrt_cif_register_info.ett_count;
  if((ptr->ett) >= &vrt_cif_register_info.ett[vrt_cif_register_info.ett_size]) {
    guint64 idx = ((guint64)ptr->ett - (guint64) vrt_cif_register_info.ett) / sizeof(gint *);
    report_warning("ETT Table overflow[%lu]!", idx);
  }
}

static ftenum_t width_to_enum(guint width, gboolean is_signed, const char *name)
{
  /* align everything to 32-bit words */
  if(width <= 32) return (is_signed?FT_INT32:FT_UINT32);
  if(width <= 64) return (is_signed?FT_INT64:FT_UINT64);
  if(name) {
    report_warning("Field %s: VRT-CIF integer fields larger than 64 are not supported!", name);
  } else {
    report_warning("VRT-CIF integer fields larger than 64 are not supported!");
  }
  return FT_NONE;
}

static void build_hf_record(vrt_cif_register_info_index_t *ptr, vrt_cif_record_descript_t *rec)
{
  header_field_info *hfinfo;
  if(rec->fields != NULL) {
    /* Subtree for section */
    hfinfo = add_node(ptr, &(rec->tree_pid), &(rec->ett_pid));
    hfinfo->name = rec->name;
    hfinfo->abbrev = rec->abbrev;
    hfinfo->type = FT_BYTES;
    hfinfo->display = BASE_NO_DISPLAY_VALUE;
    hfinfo->strings = NULL;
    hfinfo->bitmask = 0;
    hfinfo->blurb = NULL;

    /* Then walk through each field in list to add the subfields */
    wmem_list_foreach(rec->fields, build_hf_field, ptr);
  }
}

static void build_hf_array(vrt_cif_register_info_index_t *ptr, vrt_cif_field_descript_t *field)
{
  vrt_cif_record_array_descript_t *arr = field->array_descript;
  header_field_info *hfinfo;
  wmem_strbuf_t *ws_str;

  /* Top of subtree to hold the array (pid already created in build_field) */
  promote_leaf(ptr, &(arr->field_ett_pid));

  if((arr->hdr_req != NULL) || (arr->hdr_bitmap != 0)) {
    /* create the subtree to hold the header sections */
    hfinfo = add_node(ptr, &(arr->hdr_pid), &(arr->hdr_ett_pid));
    hfinfo->name = "Header";
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, field->abbrev);
    wmem_strbuf_append_printf(ws_str, ".hdr");
    hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
    hfinfo->type = FT_NONE;
    hfinfo->display = BASE_NONE;
    hfinfo->strings = NULL;
    hfinfo->bitmask = 0;
    hfinfo->blurb = NULL;

    /* Required header just gets a subtree for the fields */
    if(arr->hdr_req != NULL) {
      build_hf_record(ptr, arr->hdr_req);
    }
    /* Optional header sections each get a line for the select bit and a subtree for fields */
    if(arr->hdr_bitmap != 0) {
      hfinfo = add_node(ptr, &(arr->hdr_map_pid), &(arr->hdr_map_ett_pid));
      hfinfo->name = "Header Indicators";
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, field->abbrev);
      wmem_strbuf_append_printf(ws_str, ".hdr_sel");
      hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
      hfinfo->type = FT_UINT32;
      hfinfo->display = BASE_HEX;
      hfinfo->strings = NULL;
      hfinfo->bitmask = arr->hdr_bitmap;
      hfinfo->blurb = NULL;

      for(size_t n = 0; n < sizeof(arr->hdr_opt) / sizeof( vrt_cif_record_descript_t *); ++n) {
        if(arr->hdr_opt[n] != NULL) {
          hfinfo = add_leaf(ptr, &(arr->hdr_map_bit_pid[n]));
          hfinfo->name = arr->hdr_opt[n]->name;
          ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, arr->hdr_opt[n]->abbrev);
          wmem_strbuf_append_printf(ws_str, ".en");
          hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
          hfinfo->type = FT_BOOLEAN;
          hfinfo->display = 32;
          hfinfo->strings = NULL;
          hfinfo->bitmask = ((guint64) 1) << n;
          hfinfo->blurb = NULL;
          build_hf_record(ptr, arr->hdr_opt[n]);
        }
      }
    }
  }

  /* create the subtree to hold the record sections */
  if((arr->rec_req != NULL) || (arr->rec_bitmap != 0)) {
    hfinfo = add_node(ptr, &(arr->rec_pid), &(arr->rec_ett_pid));
    hfinfo->name = "Record";
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, field->abbrev);
    wmem_strbuf_append_printf(ws_str, ".rec");
    hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
    hfinfo->type = FT_UINT32;
    hfinfo->display = BASE_DEC;
    hfinfo->strings = NULL;
    hfinfo->bitmask = 0;
    hfinfo->blurb = NULL;

    /* Required record fields just gets a subtree for the fields */
    if(arr->rec_req != NULL) {
      build_hf_record(ptr, arr->rec_req);
    }
    /* Optional record sections each get a line for the select bit and a subtree for fields */
    if(arr->rec_bitmap != 0) {
      hfinfo = add_node(ptr, &(arr->rec_map_pid), &(arr->rec_map_ett_pid));
      hfinfo->name = "Record Indicators";
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, field->abbrev);
      wmem_strbuf_append_printf(ws_str, ".rec_sel");
      hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
      hfinfo->type = FT_UINT32;
      hfinfo->display = BASE_HEX;
      hfinfo->strings = NULL;
      hfinfo->bitmask = arr->rec_bitmap;
      hfinfo->blurb = NULL;

      for(size_t n = 0; n < sizeof(arr->rec_opt) / sizeof( vrt_cif_record_descript_t *); ++n) {
        if(arr->rec_opt[n] != NULL) {
          hfinfo = add_leaf(ptr, &(arr->rec_map_bit_pid[n]));
          hfinfo->name = arr->rec_opt[n]->name;
          ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, arr->rec_opt[n]->abbrev);
          wmem_strbuf_append_printf(ws_str, ".en");
          hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
          hfinfo->type = FT_BOOLEAN;
          hfinfo->display = 32;
          hfinfo->strings = NULL;
          hfinfo->bitmask = ((guint64) 1) << n;
          hfinfo->blurb = NULL;
          build_hf_record(ptr, arr->rec_opt[n]);
        }
      }
    }
  }
}

/* callback for walking field list to populate hf structure */
static void build_hf_field(void *v, void *p)
{
  vrt_cif_register_info_index_t *ptr = (vrt_cif_register_info_index_t *) p;
  vrt_cif_field_descript_t *field = (vrt_cif_field_descript_t *) v;
  header_field_info *hfinfo;

  /* exclude the pseudo types which have special behavior */
  if((field->type == vrt_cif_type_link)) {
      return;
  }

  guint64 bitmask = 0;
  hfinfo = add_leaf(ptr, &field->pid);
  hfinfo->name = field->name;
  hfinfo->abbrev = field->abbrev;
  hfinfo->blurb = field->text;
  switch(field->type) {
    case vrt_cif_type_bool:
      hfinfo->type = FT_BOOLEAN;
      bitmask = ~bitmask >> (64 - field->width);
      bitmask <<= field->offset % 32;
      hfinfo->display = 32; /* offset into buffer is aligned to 32 bit word */
      if (field->unit_strings.singular != NULL) {
          hfinfo->strings = (void*)(&field->unit_strings);
          hfinfo->display |= BASE_UNIT_STRING;
      }
      else {
          hfinfo->strings = NULL;
      }
      hfinfo->strings = NULL;
      break;
    case vrt_cif_type_int:
      hfinfo->type = width_to_enum(field->width, TRUE, field->abbrev);
      bitmask = ~bitmask >> (64 - field->width);
      bitmask <<= field->offset % 32;  
      hfinfo->display = BASE_DEC;
      if (field->unit_strings.singular != NULL) {
        hfinfo->strings = (void*)(&field->unit_strings);
        hfinfo->display |= BASE_UNIT_STRING;
      } else {
        hfinfo->strings = NULL;
      }
      break;
    case vrt_cif_type_uint:
      hfinfo->type = width_to_enum(field->width, FALSE, field->abbrev);
      bitmask = ~bitmask >> (64 - field->width);
      bitmask <<= field->offset % 32;
      hfinfo->display = BASE_DEC;
      if (field->unit_strings.singular != NULL) {
        hfinfo->strings = (void*)(&field->unit_strings);
        hfinfo->display |= BASE_UNIT_STRING;
      }
      else {
        hfinfo->strings = NULL;
      }
      break;
    case vrt_cif_type_hex:
      hfinfo->type = width_to_enum(field->width, FALSE, field->abbrev);
      bitmask = ~bitmask >> (64 - field->width);
      bitmask <<= field->offset % 32;
      hfinfo->display = BASE_HEX;
      hfinfo->strings = NULL;
      break;
    case vrt_cif_type_fixed:
      /* Wireshark does not have a fixed point type, we explicitly convert
         it to a double during dissection (with possible loss of precision */
      hfinfo->type = FT_DOUBLE;
      hfinfo->display = BASE_NONE;
      if (field->unit_strings.singular != NULL) {
        hfinfo->strings = (void*)(&field->unit_strings);
        hfinfo->display |= BASE_UNIT_STRING;
      }
      else {
        hfinfo->strings = NULL;
      }
      break;
    case vrt_cif_type_ufixed:
      /* Wireshark does not have a fixed point type, we convert explicitly convert
         it to a double during dissection (with possible loss of precision */
      hfinfo->type = FT_DOUBLE;
      hfinfo->display = BASE_NONE;
      if (field->unit_strings.singular != NULL) {
        hfinfo->strings = (void*)(&field->unit_strings);
        hfinfo->display |= BASE_UNIT_STRING;
      }
      else {
        hfinfo->strings = NULL;
      }
      break;
    case vrt_cif_type_raw:
      hfinfo->type = FT_BYTES;
      hfinfo->display = BASE_NONE;
      hfinfo->strings = NULL;
      break;
    case vrt_cif_type_dynamic:
      hfinfo->type = FT_BYTES;
      hfinfo->display = BASE_NONE;
      hfinfo->strings = NULL;
      break;
    case vrt_cif_type_string:
      hfinfo->type = FT_STRING;
      hfinfo->display = BASE_NONE;
      hfinfo->strings = NULL;
      break;
    case vrt_cif_type_enum:
      hfinfo->type = width_to_enum(field->width, FALSE, field->abbrev);
      bitmask = ~bitmask >> (64 - field->width);
      bitmask <<= field->offset % 32;
      hfinfo->display = BASE_DEC_HEX | BASE_SPECIAL_VALS;
      hfinfo->strings = VALS(field->enum_strings);
      break;
    case vrt_cif_type_array:
      hfinfo->type = FT_NONE;
      hfinfo->display = BASE_NONE;
      hfinfo->strings = NULL;
      break;
    default:
      hfinfo->type = FT_NONE;
      hfinfo->display = BASE_NONE;
      hfinfo->strings = NULL;
      report_warning("Unrecognized type for field %s!", (field->abbrev ? field->abbrev : ""));
  }
  hfinfo->bitmask = bitmask;

  if(field->type == vrt_cif_type_array) {
    /* walk down the rest of the array hierarchy */
    build_hf_array(ptr, field);
  }
  return;
}

/* callback when walking configuration description table to populate hf stucture*/
static void build_hf_class(gpointer k _U_, gpointer v, gpointer p)
{
  vrt_cif_class_descript_t *class_descript = (vrt_cif_class_descript_t *) v;
  vrt_cif_register_info_index_t *ptr = (vrt_cif_register_info_index_t *) p;
  guint count = wmem_array_get_count(class_descript->cif_list);
  vrt_cif_map_descript_t *map_descript = (vrt_cif_map_descript_t *) wmem_array_get_raw(class_descript->cif_list);
  header_field_info *hfinfo;
  wmem_strbuf_t *ws_str;

  if(class_descript->extension_cam != NULL) {
    vrt_cif_extension_cam_descript_t *extcam = class_descript->extension_cam;
    /* subtree top, then defined fields */
    if((extcam->fields != NULL) || (extcam->info != NULL)) {
      hfinfo = add_node(ptr, &(extcam->pid), &(extcam->ett_pid));
      hfinfo->name = "Extension CAM User Field";
      hfinfo->abbrev = "extcam";
      hfinfo->type = FT_NONE;
      hfinfo->display = BASE_NONE;
      hfinfo->strings = NULL;
      hfinfo->bitmask = 0;
      hfinfo->blurb = "Configuration specific user defined bits of the extension command CAM field";
      wmem_list_foreach(extcam->fields, build_hf_field, p);
    }
  }

  /* walk through the array (each CIF, each enable bit, each field) */
  for(guint n = 0; n < count; ++n,++map_descript) {
    if(map_descript->abbrev == NULL) continue;  /* skip undefined bits */
    // entry for the actual CIF
    hfinfo = add_node(ptr, &(map_descript->pid), &(map_descript->ett_pid));
    hfinfo->name = map_descript->name;
    hfinfo->abbrev = map_descript->abbrev;
    hfinfo->type = FT_UINT32;
    hfinfo->display = BASE_HEX;
    hfinfo->strings = NULL;
    hfinfo->bitmask = map_descript->bitmap;
    hfinfo->blurb = NULL;

    hfinfo = add_node(ptr, &(map_descript->warn_pid), &(map_descript->warn_ett_pid));
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, map_descript->name);
    wmem_strbuf_append_printf(ws_str, " Warnings");
    hfinfo->name = wmem_strbuf_finalize(ws_str);
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, map_descript->abbrev);
    wmem_strbuf_append_printf(ws_str, ".warn");
    hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
    hfinfo->type = FT_UINT32;
    hfinfo->display = BASE_HEX;
    hfinfo->strings = NULL;
    /* A mask of valid bits is defined by the warn/err description structure, but use
       0 here so we can see if any other bits are defined */
    hfinfo->bitmask = 0;
    hfinfo->blurb = NULL;

    hfinfo = add_node(ptr, &(map_descript->err_pid), &(map_descript->err_ett_pid));
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, map_descript->name);
    wmem_strbuf_append_printf(ws_str, " Errors" );
    hfinfo->name = wmem_strbuf_finalize(ws_str);
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, map_descript->abbrev);
    wmem_strbuf_append_printf(ws_str, ".err");
    hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
    hfinfo->type = FT_UINT32;
    hfinfo->display = BASE_HEX;
    hfinfo->strings = NULL;
    hfinfo->bitmask = 0;
    hfinfo->blurb = NULL;
    
    vrt_cif_enable_descript_t *en_descript= &(map_descript->enables[0]);
    for(size_t m = 0; m < sizeof(map_descript->enables) / sizeof(vrt_cif_enable_descript_t); ++m, ++en_descript) {
      /* For each bit in map add a bit entry for the CIF and a top entry for the field */
      if(en_descript->abbrev != NULL) {
        hfinfo = add_leaf(ptr, &(en_descript->bit_pid));
        hfinfo->name = en_descript->name;
        ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->abbrev);
        wmem_strbuf_append_printf(ws_str, ".bit");
        hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
        hfinfo->type = FT_BOOLEAN;
        hfinfo->display = 32;
        hfinfo->strings = NULL;
        hfinfo->bitmask = ((guint64) 1) << m;
        hfinfo->blurb = NULL;

        hfinfo = add_leaf(ptr, &(en_descript->warn_bit_pid));
        hfinfo->name = en_descript->name;
        ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->abbrev);
        wmem_strbuf_append_printf(ws_str, ".bit.warn");
        hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
        hfinfo->type = FT_BOOLEAN;
        hfinfo->display = 32;
        hfinfo->strings = NULL;
        hfinfo->bitmask = ((guint64) 1) << m;
        hfinfo->blurb = NULL;

        hfinfo = add_leaf(ptr, &(en_descript->err_bit_pid));
        hfinfo->name = en_descript->name;
        ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->abbrev);
        wmem_strbuf_append_printf(ws_str, ".bit.err");
        hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
        hfinfo->type = FT_BOOLEAN;
        hfinfo->display = 32;
        hfinfo->strings = NULL;
        hfinfo->bitmask = ((guint64) 1) << m;
        hfinfo->blurb = NULL;

        if((!en_descript->is_link) && (en_descript->fields != NULL)) {
          hfinfo = add_node(ptr, &(en_descript->tree_pid), &(en_descript->ett_pid));
          hfinfo->name = en_descript->name;
          hfinfo->abbrev = en_descript->abbrev;
          hfinfo->type = FT_BYTES;
          hfinfo->display = BASE_NO_DISPLAY_VALUE;
          hfinfo->strings = NULL;
          hfinfo->bitmask = 0;
          hfinfo->blurb = NULL;

          hfinfo = add_node(ptr, &(en_descript->warn_tree_pid), &(en_descript->warn_ett_pid));
          ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->name);
          wmem_strbuf_append_printf(ws_str, " Warnings");
          hfinfo->name = wmem_strbuf_finalize(ws_str);
          ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->abbrev);
          wmem_strbuf_append_printf(ws_str, ".warn");
          hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
          hfinfo->type = FT_UINT32;
          hfinfo->display = BASE_HEX;
          hfinfo->strings = NULL;
          hfinfo->bitmask = 0;
          hfinfo->blurb = NULL;

          hfinfo = add_node(ptr, &(en_descript->err_tree_pid), &(en_descript->err_ett_pid));
          ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->name);
          wmem_strbuf_append_printf(ws_str, " Errors");
          hfinfo->name = wmem_strbuf_finalize(ws_str);
          ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->abbrev);
          wmem_strbuf_append_printf(ws_str, ".err");
          hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
          hfinfo->type = FT_UINT32;
          hfinfo->display = BASE_HEX;
          hfinfo->strings = NULL;
          hfinfo->bitmask = 0;
          hfinfo->blurb = NULL;

          /* Warnings and errors are bitmaps, so we potentially need a display element for each one */
          for(guint64 b = 0; b<32; ++b) {
            const char *name;
            const char *blurb;

            vrt_cif_warnerr_t *we = (vrt_cif_warnerr_t *) wmem_map_lookup(class_descript->warnerr_bitmap, &b);
            if(we != NULL) {
              name = we->name;
              blurb = we->descript;
            } else {
              name = "Undefined Flag Bit";
              blurb = NULL;
            }

            hfinfo = add_leaf(ptr, &(en_descript->warn_tree_array[b]));
            hfinfo->name = name;
            ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->abbrev);
            wmem_strbuf_append_printf(ws_str, ".warn.%ld", b);
            hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
            hfinfo->type = FT_BOOLEAN;
            hfinfo->display = 32;
            hfinfo->strings = NULL;
            hfinfo->bitmask = ((guint64) 1) << b;
            hfinfo->blurb = blurb;

            hfinfo = add_leaf(ptr, &(en_descript->err_tree_array[b]));
            hfinfo->name = name;
            ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, en_descript->abbrev);
            wmem_strbuf_append_printf(ws_str, ".err.%ld", b);
            hfinfo->abbrev = wmem_strbuf_finalize(ws_str);
            hfinfo->type = FT_BOOLEAN;
            hfinfo->display = 32;
            hfinfo->strings = NULL;
            hfinfo->bitmask = ((guint64) 1) << b;
            hfinfo->blurb = blurb;
          }

          /* Then walk through each field in list to add the subfields */
          wmem_list_foreach(en_descript->fields, build_hf_field, p);
        }
      }
    }
  }
}

static void set_default_hf_configuration(vrt_cif_register_info_index_t *head) {
  /*  If new default fields are added, update allocation counts in build_hf_configuration() */
  /* entries */
  header_field_info *hfinfo;

  hfinfo = add_node(head, &hf_vrt_cif_raw, &ett_top);
  hfinfo->name = "Unparsed Payload";
  hfinfo->abbrev = "vrt_cif.payload";
  hfinfo->type = FT_BYTES;
  hfinfo->display = BASE_NONE;
  hfinfo->strings = NULL;
  hfinfo->bitmask = 0x00;
  hfinfo->blurb = NULL;

  hfinfo = add_node(head, &hf_vrt_cif_warn, &ett_warn);
  hfinfo->name = "Warnings";
  hfinfo->abbrev = "vrt_cif.warnings";
  hfinfo->type = FT_NONE;
  hfinfo->display = BASE_NONE;
  hfinfo->strings = NULL;
  hfinfo->bitmask = 0x00;
  hfinfo->blurb = NULL;

  hfinfo = add_node(head, &hf_vrt_cif_err, &ett_err);
  hfinfo->name = "Errors";
  hfinfo->abbrev = "vrt_cif.errors";
  hfinfo->type = FT_NONE;
  hfinfo->display = BASE_NONE;
  hfinfo->strings = NULL;
  hfinfo->bitmask = 0x00;
  hfinfo->blurb = NULL;
}

static void build_hf_configuration(void) {
  /* Allocate enough space to hold all display fields */
  // [NOTE] We count the fields as we add them and rely on this to size the space for the hf structure
  // It is important this is correct, since as we walk the configuration we step the address assuming 
  // there is enough space. If we're wrong we'll overrun the buffer. It might be nice to use a more
  // robust mechanism here.  [a node will step both hf & ett; a leaf just steps hf]

  /* Three (value, warn, err) per CIF, bit of CIF, and field, 
     One per subfield, warn bit, and err bit
     plus one for each static field */
  guint full_count  =  vrt_cif_configuration->node_count +  vrt_cif_configuration->leaf_count + 3;
  /* Three (value, warn, err) per CIF, bit of CIF, and field, 
     plus one for each static subtree  */
  guint sub_count  =  vrt_cif_configuration->node_count + 3;
  if(vrt_cif_register_info.hf != NULL) {  /* hf is used as a proxy for an uninitialized structure */
    // we probably never get here since the whole pool is freed when we parse a new file
    deregister_hf_fields();
    vrt_cif_register_info.hf = (hf_register_info *) wmem_realloc(vrt_cif_cfg_scope, vrt_cif_register_info.hf, sizeof(hf_register_info) * full_count);
    vrt_cif_register_info.ett = (gint **) wmem_realloc(vrt_cif_cfg_scope, vrt_cif_register_info.ett, sizeof(gint *) * sub_count);
  } else {
    vrt_cif_register_info.hf = (hf_register_info *)wmem_alloc(vrt_cif_cfg_scope, sizeof(hf_register_info) * full_count);
    vrt_cif_register_info.ett = (gint **)wmem_alloc(vrt_cif_cfg_scope, sizeof(gint *) * sub_count);
  }
  vrt_cif_register_info.hf_size = full_count;
  vrt_cif_register_info.ett_size = sub_count;
  vrt_cif_register_info_index_t head = { vrt_cif_register_info.hf,  vrt_cif_register_info.ett};

  set_default_hf_configuration(&head);

  // Walk config structure and copy defined fields into new space
  // head is updated in the calls to reflect added elements
  wmem_map_foreach(vrt_cif_configuration->cif_class_table.descript_table, build_hf_class, &head);
  wmem_map_foreach(vrt_cif_configuration->ecif_class_table.descript_table, build_hf_class, &head);
}

static void load_and_register_hf_fields(const char *match _U_)
{
  if(vrt_cif_cfg_scope == NULL) {
    apply_prefs();
  }

  static ei_register_info ei[] = {
    { &ei_proto_note, { "vrt_cif.proto.note.expert", PI_PROTOCOL, PI_NOTE, "Questionable Protocol Behavior", EXPFILL }},
    { &ei_proto_warn, { "vrt_cif.proto.warn.expert", PI_PROTOCOL, PI_WARN, "Protocol Violation (ignored)", EXPFILL }},
    { &ei_proto_err, { "vrt_cif.proto.err.expert", PI_PROTOCOL, PI_ERROR, "Protocol Violation (aborted)", EXPFILL }},
    { &ei_cfg_note, { "vrt_cif.cfg.note.expert", PI_UNDECODED, PI_NOTE, "This packet has special consideration in the dissector", EXPFILL }},
    { &ei_cfg_warn, { "vrt_cif.cfg.warn.expert", PI_UNDECODED, PI_WARN, "Dissector support for this use limited; Packet not fully parsed", EXPFILL }},
    { &ei_cfg_err, { "vrt_cif.cfg.err.expert", PI_MALFORMED, PI_ERROR, "Dissector does not support this use; Packet may be incorrect", EXPFILL }}
  };

  if(vrt_cif_register_info.hf_size != vrt_cif_register_info.hf_count) {
    report_warning("Number of handles allocated does not match number initialized. Check XML (%d, %d)",
                   vrt_cif_register_info.hf_size, vrt_cif_register_info.hf_count);
  }
  proto_register_field_array(proto_vrt_cif, vrt_cif_register_info.hf, vrt_cif_register_info.hf_count);
  if(vrt_cif_register_info.ett_size != vrt_cif_register_info.ett_count) {
    report_warning("Number of subtrees allocated does not match number initialized. Check XML (%d, %d)",
                   vrt_cif_register_info.ett_size, vrt_cif_register_info.ett_count);
  }
  proto_register_subtree_array(vrt_cif_register_info.ett, vrt_cif_register_info.ett_count);
  expert_module_t *expert_vrt_cif = expert_register_protocol(proto_vrt_cif);
  expert_register_field_array(expert_vrt_cif, ei, array_length(ei));
}

static void deregister_hf_fields(void)
{
  /* skip the loop if array was never registered, using the default pid as proxy */
  /* this isn't required as proto_deregister_field() will just return if called with cleared pid */
  if(hf_vrt_cif_raw == -1) return;

  hf_register_info *hf = vrt_cif_register_info.hf;
  for (guint i = 0; i < vrt_cif_register_info.hf_size; ++i) {
    proto_deregister_field(proto_vrt_cif, *(hf->p_id));
    *(hf->p_id) = -1;  // clear it in case we try to deregister again
    
    /* [NOTE] On cleanup, the framework tries to call g_free() on each of the strings in
       the deregistered hf structures. This doesn't play well with the scope allocated buffers,
       so go through and set all strings to NULL to prevent errors later */
    hf->hfinfo.name = NULL;
    hf->hfinfo.abbrev = NULL;
    hf->hfinfo.blurb = NULL;
    hf->hfinfo.type = FT_NONE;
    hf->hfinfo.display = BASE_NONE;
    hf->hfinfo.strings = NULL;
    ++hf;
  }
  // We throw away the ett table and the dynamic nodes will be recreated with an initialized pid, but the
  // static nodes must be cleared explicitly;
  ett_top = -1;
  ett_warn = -1;
  ett_err = -1;
  //vrt_cif_register_info = (const vrt_cif_register_info_t){ NULL, 0, NULL, 0 };
  vrt_cif_register_info.hf = NULL;
  vrt_cif_register_info.hf_size = 0;
  vrt_cif_register_info.ett = NULL;
  vrt_cif_register_info.ett_size = 0;
  vrt_cif_register_info.hf_count = 0;
  vrt_cif_register_info.ett_count = 0;
}

static void init_dissector(void)
{
  /* this is a place holder for the callback */
  ;
}

static void cleanup_dissector(void)
{
  /* this is a place holder for the callback */
  ;
}

static void shutdown_dissector(void)
{
    deregister_hf_fields();
    vrt_cif_cfg_scope = NULL;
    vrt_cif_configuration = NULL;
}

static void apply_prefs(void)
{
  if(vrt_cif_cfg_scope != NULL) {
    /* check if we've already loaded the correct file */
    if(!g_strcmp0(vrt_cif_configuration->filename, (const char *) pref_filename)) return;
    /* release any memory allocated to structures from the old file */
    deregister_hf_fields();
//    wmem_free_all(vrt_cif_cfg_scope);
    vrt_cif_configuration = NULL;
  } else {
//   wmem_file_scope triggers g_assert(allocator->in_scope) on initial call
//    vrt_cif_cfg_scope = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);
    vrt_cif_cfg_scope = wmem_epan_scope();
  }
  parse_config_file((const char *) pref_filename);
  build_hf_configuration();
}

static vrt_cif_configuration_t *vrt_cif_configuration_new(void)
{
  vrt_cif_configuration_t *cfg = wmem_new(vrt_cif_cfg_scope, vrt_cif_configuration_t);
  cfg->cif_class_table.descript_table  = wmem_map_new(vrt_cif_cfg_scope, wmem_int64_hash, g_int64_equal);
  cfg->cif_class_table.id_map_list  = wmem_array_new(vrt_cif_cfg_scope, sizeof(vrt_cif_class_id_index_t));
  cfg->ecif_class_table.descript_table = wmem_map_new(vrt_cif_cfg_scope, wmem_int64_hash, g_int64_equal);
  cfg->ecif_class_table.id_map_list  = wmem_array_new(vrt_cif_cfg_scope, sizeof(vrt_cif_class_id_index_t));
  cfg->node_count = 0;
  cfg->leaf_count = 0;
  cfg->filename = NULL;

  return cfg;
}

static void parse_config_file(const char *filename)
{
  xmlDocPtr  doc = NULL;
  xmlNodePtr root;
  int parse_opt = XML_PARSE_NONET | XML_PARSE_NOBLANKS | XML_PARSE_XINCLUDE | XML_PARSE_NOXINCNODE | XML_PARSE_COMPACT;
  
  /* Old maps are freed automatically? */
  vrt_cif_configuration = vrt_cif_configuration_new();

  if((filename == NULL) || (filename[0] == '\0')) {
    /* report_warning("No configuration file defined"); */
  } else if((doc = xmlReadFile(filename,NULL,parse_opt)) == NULL) {
    report_warning("Can't parse VRT-CIF configuration file \"%s\"", filename);
  } else if(xmlXIncludeProcessFlags(doc, parse_opt) < 0) {
    report_warning("Error parsing VRT-CIF configuration include hierarchy \"%s\"", filename);
  } else if((root = xmlDocGetRootElement(doc)) == NULL) {
    report_warning("VRT-CIF configuration file is empty\"%s\"", filename);
  } else if(xmlStrcmp(root->name, (const xmlChar *) "configuration")) {
  report_warning("VRT-CIF configuration file (%s) root node not as expected (%s)", filename, (root->name ? (const char *) root->name : ""));
  } else {
    /* walk the tree and store the configuration structure */
    for(xmlNodePtr cur = root->xmlChildrenNode; cur != NULL; cur = cur->next) {
      if((!xmlStrcmp(cur->name, (const xmlChar *)"cifClass"))) {
        parse_cif_class(cur);
      }
    }
    if(vrt_cif_configuration->node_count == 0) {
      report_warning("VRT-CIF no fields were parsed from configuration file (%s)! Check Formatting.", filename);
    } else {
      /* If it worked, save the filename so we don't have to reload it every time. This has 
         the implication that wireshark must be restarted if the configuration file changes */
      vrt_cif_configuration->filename = filename;
    }
  }
  if(doc != NULL) {
    xmlFreeDoc(doc);
  }
}

static gboolean add_map_field(vrt_cif_field_descript_t *field, wmem_list_t **list_ptr)
{
  gboolean ret = FALSE;
  if(field != NULL) {
    /* We leave the unused tree pointer set to NULL to save a little memory on sparsely defined
       maps and make the packet parsing faster than checking for an empty tree but that means we 
       have to do an extra check when building the tree */
    if(*list_ptr == NULL) {
      *list_ptr = wmem_list_new(vrt_cif_cfg_scope);
    }
    wmem_list_append(*list_ptr, field);
    ret = TRUE;
  }
  return ret;
}

static void init_record_array_descript(vrt_cif_record_array_descript_t *ptr)
{
  /* structure contains pid fields which must be initialized to -1 rather than 0 */
  ptr->field_ett_pid = -1;

  ptr->hdr_pid = -1;
  ptr->hdr_ett_pid = -1;
  ptr->hdr_map_pid = -1;
  ptr->hdr_map_ett_pid = -1;

  ptr->rec_pid = -1;
  ptr->rec_ett_pid = -1;
  ptr->rec_map_pid = -1;
  ptr->rec_map_ett_pid = -1;
}

static void init_enable_descript_array(vrt_cif_enable_descript_t *en_descript, guint count)
{
  /* structure contains pid fields which must be initialized to -1 rather than 0 */
  /* we could probably cheat here and use a memset across the whole set, but to avoid
     any portability issues, we'll walk through and explicitly set each field */
  vrt_cif_enable_descript_t *ptr = en_descript;
  for(guint n = 0; n < count; ++n) {
    ptr->bit_pid = -1;
    ptr->tree_pid = -1;
    ptr->ett_pid = -1;
    ptr->warn_bit_pid = -1;
    ptr->warn_tree_pid = -1;
    ptr->warn_ett_pid = -1;
    int *pid_ptr = ptr->warn_tree_array;
    for(guint m = 0; m < 32; ++m) {
      *pid_ptr++ = -1;
    }
    ptr->err_bit_pid = -1;
    ptr->err_tree_pid = -1;
    ptr->err_ett_pid = -1;
    pid_ptr = ptr->err_tree_array;
    for(guint m = 0; m < 32; ++m) {
      *pid_ptr++ = -1;
    }
    ptr++;
  }
}

static void init_map_descript_array(vrt_cif_map_descript_t *map_descript, guint count)
{
  vrt_cif_map_descript_t *ptr = map_descript;
  for(guint n = 0; n < count; ++n) {
    ptr->pid = -1;
    ptr->ett_pid = -1;
    ptr->warn_pid = -1;
    ptr->warn_ett_pid = -1;
    ptr->err_pid = -1;
    ptr->err_ett_pid = -1;
    init_enable_descript_array(ptr->enables, 32);
    ptr++;
  }
}

/* Index into the array, growing it if index out of range */
static vrt_cif_map_descript_t *get_map_descript(wmem_array_t *cif_list, guint idx)
{
  guint elem_count = wmem_array_get_count(cif_list);

  if(idx >= elem_count) {
    /* grow array to new index, filling gap with 0 */
    /* The extra allocation feels clunky, but it didn't seem like the API gave another way */
    guint add_count = (idx+1) - elem_count;
    void *temp = wmem_alloc0_array(vrt_cif_cfg_scope, vrt_cif_map_descript_t, add_count); 
    /* structure contains pid fields which must be initialized to -1 rather than 0 */
    init_map_descript_array((vrt_cif_map_descript_t *) temp, add_count);
    wmem_array_append(cif_list, temp, add_count);
    wmem_free(vrt_cif_cfg_scope, temp);     /* ?leave it until the pool is freed? */
  }
  vrt_cif_map_descript_t *ptr = (vrt_cif_map_descript_t *) wmem_array_index(cif_list, idx);
  ptr->index = idx;
  return ptr;
}

static void parse_cif_class(const xmlNodePtr base )
{
  // parse type and id from xml record
  xmlChar *str = xmlGetProp(base, (const xmlChar *)"id");
  guint64 classid;
  if((str == NULL) || (!xmlStrcmp(str, (const xmlChar *)"default"))) {
     classid = default_classid;
  } else {
    str_with_prefix_tou64((const gchar *) str, NULL, &classid);
  }
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"type");
  gboolean extension;
  if((!xmlStrcmp(str, (const xmlChar *)"cif")) || (!xmlStrcmp(str, (const xmlChar *)"standard"))) {
    extension = FALSE;
  } else if((!xmlStrcmp(str, (const xmlChar *)"ecif")) || (!xmlStrcmp(str, (const xmlChar *)"extension"))) {
    extension = TRUE;
  } else {
  report_warning("Unrecognized type of VRT-CIF class: %s. Parsing as extension cif", (str? (const char *)str : "NULL"));
    extension = TRUE;
  }
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar *)"idmask");
  guint64 classid_mask;
  if(str == NULL) {
    classid_mask = ~((guint64) 0);
  } else {
    str_with_prefix_tou64((const gchar *) str, NULL, &classid_mask);
  }
  xmlFree(str);

  vrt_cif_class_id_map_t *dt = (extension?&vrt_cif_configuration->ecif_class_table:&vrt_cif_configuration->cif_class_table);
  vrt_cif_class_descript_t *class_descript;

  /* check if class already in table */
  class_descript = find_class_descript(dt, classid, NULL);

  str = xmlGetProp(base, (const xmlChar *)"alias");
  if(str != NULL) {
    /* The classid uses the configuration defined for the alias; no further
       parsing of this element is done */

    // don't create a new map element; add a new item to the list
    if(class_descript != NULL) {
      report_warning("Attempt to alias defined class 0x%" G_GINT64_MODIFIER "x ignored", classid);
    } else {
      guint64 classid_match;
      if(!xmlStrcmp(str, (const xmlChar *)"default")) {
        classid_match = default_classid;
      } else {
        str_with_prefix_tou64((const gchar *) str, NULL, &classid_match);
      }

      guint64 match_index;
      class_descript = find_class_descript(dt, classid, &match_index);
      if(class_descript == NULL) {
        report_warning("Attempt to alias class 0x%" G_GINT64_MODIFIER "x to undefined class 0x%" G_GINT64_MODIFIER "x ignored", classid, classid_match);
      } else {
        vrt_cif_class_id_index_t idx;
        idx.base = classid & classid_mask;
        idx.mask = classid_mask;
        idx.index = match_index;
        wmem_array_append(dt->id_map_list,&idx,1);  /* append copies structure */
      }
    }
  } else {
    if(class_descript == NULL) {
      vrt_cif_class_id_index_t idx;
      idx.base = classid & classid_mask;
      idx.mask = classid_mask;
      idx.index = idx.base;
      wmem_array_append(dt->id_map_list,&idx,1);  /* append copies structure */

      vrt_cif_class_id_index_t *key = wmem_array_index(dt->id_map_list, wmem_array_get_count(dt->id_map_list)-1);
      class_descript = wmem_new(vrt_cif_cfg_scope, vrt_cif_class_descript_t);
      /* start with 8 slots available to prevent reallocation in most cases */
      class_descript->cif_list = wmem_array_sized_new(vrt_cif_cfg_scope, sizeof(vrt_cif_map_descript_t), 8);
      class_descript->warnerr_bitmap = wmem_map_new(vrt_cif_cfg_scope, wmem_int64_hash, g_int64_equal);
      class_descript->extension_cam = NULL;
      class_descript->info = NULL;
      wmem_map_insert(dt->descript_table, &(key->index), class_descript);
    }
    for(xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
      if((!xmlStrcmp(cur->name, (const xmlChar *)"cifMap"))) {
        parse_cif_map(cur, class_descript->cif_list);
      }
      else if((!xmlStrcmp(cur->name, (const xmlChar *)"warnErrMap"))) {
        parse_warnerr_bitmap(cur, class_descript->warnerr_bitmap);
      }
      else if((!xmlStrcmp(cur->name, (const xmlChar *)"extCam"))) {
        if(class_descript->extension_cam != NULL){
          report_warning("Multiple extension cam definitions for class 0x%" G_GINT64_MODIFIER "x", classid);
        } else {
          class_descript->extension_cam = parse_extension_cam(cur);
        }
      }
      else if((!xmlStrcmp(cur->name, (const xmlChar *)"info"))) {
        if(class_descript->extension_cam != NULL){
          report_warning("Multiple information strings for class 0x%" G_GINT64_MODIFIER "x", classid);
        } else {
          class_descript->info = parse_info(cur);
        }
      }
    }
  }
  xmlFree(str);
}

static void parse_cif_map(const xmlNodePtr base,  wmem_array_t *cif_list)
{
  wmem_strbuf_t *ws_str;
  /* Fetch the ordinal used as index into cif_list */
  guint idx;
  xmlChar *str = xmlGetProp(base, (const xmlChar*)"index");  
  str_with_prefix_tou((const gchar *) str, NULL, &idx);
  xmlFree(str);
  if(xmlHasProp(base, (const xmlChar *)"offset") != NULL) {
    report_warning("cifMap had unexpected offset property. Did you intend to use index?");
  }
  /* get the indexed map; create if required */
  vrt_cif_map_descript_t *map_descript = get_map_descript(cif_list, idx);
  vrt_cif_configuration->node_count += 3;  /* count these as we go for structure allocation later (value, warn & err) */

  str = xmlGetProp(base, (const xmlChar*)"name");
  if(map_descript->name == NULL) {
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
    map_descript->name = wmem_strbuf_finalize(ws_str);
  } else if(g_strcmp0(map_descript->name, (const char *) str)) {
    report_warning("CIF map %s keeping name of previous overlapping map %s", map_descript->name, (str ? (const char *) str : "NULL"));
  }
  xmlFree(str);
  ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, "vrt_cif.cif");
  wmem_strbuf_append_printf(ws_str, "%d", idx);
  map_descript->abbrev = wmem_strbuf_finalize(ws_str);

  for(xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
    if(!xmlStrcmp(cur->name, (const xmlChar*)"cifEnable")) {
      guint pos;
      str = xmlGetProp(cur, (const xmlChar*)"index");
      str_with_prefix_tou((const gchar *) str, NULL, &pos);
      xmlFree(str);
      if (xmlHasProp(cur, (const xmlChar*)"offset") != NULL) {
        report_warning("cifEnable in cifMap %s had unexpected offset property. Did you intend to use index?",
                       (map_descript->name ? map_descript->name : "NULL"));
      }
      if(pos >= 32) {
        report_warning("Ignoring CIF enable bit position %d >= 32 in cifMap %s", pos, (map_descript->name ? map_descript->name : "NULL"));
      } else {
        parse_cif_enable(cur, &map_descript->enables[pos], map_descript->abbrev);
        map_descript->bitmap |= 1 << pos;
      }
    }
    else if((!xmlStrcmp(cur->name, (const xmlChar *)"info"))) {
      map_descript->info = parse_info(cur);
    }
  }
}

static vrt_cif_type_t parse_type(xmlChar *str)
{
  vrt_cif_type_t t;
  if(!(xmlStrcmp(str, (const xmlChar*)"bool"))) {
    t = vrt_cif_type_bool;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"int"))) {
    t = vrt_cif_type_int;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"uint"))) {
    t = vrt_cif_type_uint;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"hex"))) {
    t = vrt_cif_type_hex;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"fixed"))) {
    t = vrt_cif_type_fixed;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"ufixed"))) {
    t = vrt_cif_type_ufixed;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"raw"))) {
    t = vrt_cif_type_raw;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"dynamic"))) {
    t = vrt_cif_type_dynamic;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"string"))) {
    t = vrt_cif_type_string;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"enum"))) {
    t = vrt_cif_type_enum;
  } else if(!(xmlStrcmp(str, (const xmlChar*)"array"))) {
    t = vrt_cif_type_array;
  } else {
    report_warning("Unrecognized field type %s; defaulting to raw", (str ? (const char *) str : "NULL"));
    t = vrt_cif_type_raw;
  }
  return t;
}

static void parse_cif_enable(const xmlNodePtr base, vrt_cif_enable_descript_t *en_descript, const char *parent_abbrev)
{
  wmem_strbuf_t *ws_str;
  xmlChar *str = xmlGetProp(base, (const xmlChar*)"name");
  if(en_descript->name == NULL) {
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
    en_descript->name = wmem_strbuf_finalize(ws_str);
  } else if(g_strcmp0(en_descript->name, (const char *) str)) {
    report_warning("CIF enable %s keeping name of previous overlapping enable %s", (str ? (const char *) str : "NULL"), en_descript->name);
  }
  xmlFree(str);
  str = xmlGetProp(base, (const xmlChar*)"abbrev");
  if(str && *str) {
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, parent_abbrev);
    wmem_strbuf_append_printf(ws_str, ".%s", str);
    char *abbrev = wmem_strbuf_finalize(ws_str);
    if (en_descript->abbrev == NULL) {
      /* new, non-empty string */
      en_descript->abbrev = abbrev;
    } 
    else if (g_strcmp0(en_descript->abbrev, abbrev)) {
      /* conflicting name */
      report_warning("CIF enable %s keeping abbrev of previous overlapping enable %s", (str ? (const char*)str : "NULL"), en_descript->abbrev);
    }
  } else if (en_descript->abbrev == NULL) { 
      /* no string available */
      report_warning("CIF enable %s has an empty abbrev; using name instead", (en_descript->name ? en_descript->name : "NULL"));
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, parent_abbrev);
      wmem_strbuf_append_printf(ws_str, ".%s", (en_descript->name ? en_descript->name : "NULL"));
      en_descript->abbrev = wmem_strbuf_finalize(ws_str);
  }
  xmlFree(str);
  en_descript->is_link = FALSE;

  for(xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
    /* the cifEnable contains either a single cifMap link, or a list of cifFields */
    if(!(xmlStrcmp(cur->name, (const xmlChar*)"cifMap"))) {
      if(en_descript->fields != NULL) {
        /* cifMap cannot be mixed with fields */
        report_warning("A cifMap element cannot be combined with cifFields. Ignoring map in %s", (en_descript->name ? en_descript->name : "NULL"));
        continue;
      }
      vrt_cif_field_descript_t *field = wmem_new0(vrt_cif_cfg_scope, vrt_cif_field_descript_t);
      en_descript->is_link = TRUE;

      field->pid = -1;
      field->type = vrt_cif_type_link;

      str = xmlGetProp(cur, (const xmlChar*)"name");
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
      field->name = wmem_strbuf_finalize(ws_str);
      xmlFree(str);

      str = xmlGetProp(base, (const xmlChar*)"index");
      str_with_prefix_tou((const gchar*)str, NULL, &field->link);
      xmlFree(str);

      add_map_field(field, &en_descript->fields);
      break;
    } 
    else if(!(xmlStrcmp(cur->name, (const xmlChar*)"cifField"))) {
      vrt_cif_field_descript_t *field = parse_field(cur, en_descript->abbrev);
      if(add_map_field(field, &en_descript->fields)) {
        vrt_cif_configuration->leaf_count++;  /* count these as we go for structure allocation later */
      }
    }
    else if((!xmlStrcmp(cur->name, (const xmlChar *)"info"))) {
      en_descript->info = parse_info(cur);
    }
  }

  if(!en_descript->is_link && (en_descript->fields != NULL)) {
    /* account for the field, warning, and error subtrees */
    vrt_cif_configuration->node_count += 3;
    /* Account for the bit header in the value, warning, and error trees
       plus each of the possible 32 bits of warning and error */
    vrt_cif_configuration->leaf_count += 3 + (2*32);
  } else {
    /* we only need the single bit in the value, warn and err trees in this case */
    vrt_cif_configuration->leaf_count += 3;
  }
}

static void parse_warnerr_bitmap(const xmlNodePtr base, wmem_map_t *warnerr_bitmap)
{
  xmlChar *str;
  wmem_strbuf_t *ws_str;

  for(xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
    /* the cifEnable contains either a single cifMap link, or a list of cifFields */
    if(!(xmlStrcmp(cur->name, (const xmlChar*)"bit"))) {
      vrt_cif_warnerr_t *field = wmem_new0(vrt_cif_cfg_scope, vrt_cif_warnerr_t);

      str = xmlGetProp(cur, (const xmlChar*)"name");
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
      field->name = wmem_strbuf_finalize(ws_str);
      xmlFree(str);

      str = xmlGetProp(cur, (const xmlChar*)"descript");
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
      field->descript = wmem_strbuf_finalize(ws_str);
      xmlFree(str);

      guint64 *key_ptr = wmem_new(vrt_cif_cfg_scope, guint64);
      str = xmlGetProp(cur, (const xmlChar*)"index");
      str_with_prefix_tou64((const gchar*)str, NULL, key_ptr);
      wmem_map_insert(warnerr_bitmap,key_ptr, field);

      if (xmlHasProp(cur, (const xmlChar*)"offset") != NULL) {
        report_warning("WarnErrMap field had unexpected offset property. Did you intend to use index?");
      }
    }
  }
}

static vrt_cif_extension_cam_descript_t *parse_extension_cam(const xmlNodePtr base)
{
  vrt_cif_extension_cam_descript_t *extcam;
  extcam = wmem_new0(vrt_cif_cfg_scope, vrt_cif_extension_cam_descript_t);
  extcam->pid = -1;
  extcam->ett_pid = -1;

  xmlChar *str = xmlGetProp(base, (const xmlChar*)"req15");
  if(str) {
    if(!(xmlStrcmp(str, (const xmlChar*)"cif_only"))) {
      extcam->user_req = vrt_payload_cif;
    } else if(!(xmlStrcmp(str, (const xmlChar*)"cif_field"))) {
      extcam->user_req = vrt_payload_cif_field;
    } else {
      /* treat all other cases as further qualified by reqEr/reqWarn flags */
      extcam->user_req = vrt_payload_empty;
    }
  } else {
    extcam->user_req = vrt_payload_undefined;
  }
  xmlFree(str);

  for(xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
    if(!(xmlStrcmp(cur->name, (const xmlChar*)"camField"))) {
      vrt_cif_field_descript_t *field = parse_field(cur, "extCam");
      if(add_map_field(field, &extcam->fields)) {
        vrt_cif_configuration->leaf_count++;  /* count these as we go for structure allocation later */
      }
    }
    else if((!xmlStrcmp(cur->name, (const xmlChar *)"info"))) {
      extcam->info = parse_info(cur);
    }
  }
  if((extcam->fields != NULL) || (extcam->info != NULL)) {
    /* we parsed at least one user defined field */
    vrt_cif_configuration->node_count++;
  }
  return extcam;
}

static vrt_cif_field_descript_t *parse_field(const xmlNodePtr base, const char *parent_abbrev)
{
  vrt_cif_field_descript_t *field = wmem_new0(vrt_cif_cfg_scope, vrt_cif_field_descript_t);

  field->pid = -1;
  xmlChar *str = xmlGetProp(base, (const xmlChar*)"name");
  wmem_strbuf_t *ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
  field->name = wmem_strbuf_finalize(ws_str);
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"descript");
  ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
  field->text = wmem_strbuf_finalize(ws_str);
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"abbrev");
  ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, parent_abbrev);
  if(str && *str) {
  wmem_strbuf_append_printf(ws_str, ".%s", (const char *)str);
  } else {
    report_warning("Field %s.%s has an empty abbrev; using name instead",
                   (parent_abbrev ? parent_abbrev : ""), (field->name ? field->name : ""));
    wmem_strbuf_append_printf(ws_str, ".%s", (field->name ? field->name : ""));
  }
  field->abbrev = wmem_strbuf_finalize(ws_str);
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"offset");
  str_with_prefix_tou((const gchar*)str, NULL, &field->offset);
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"relative");
  guint relative;
  str_with_prefix_tou((const gchar*)str, NULL, &relative);
  field->is_relative = (relative ? 1 : 0);
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"type");
  field->type = parse_type(str);
  xmlFree(str);

  /* read additional properties based on type */
  if(field->type == vrt_cif_type_bool) {
    field->width = 1;
  } else {
    str = xmlGetProp(base, (const xmlChar*)"width");
    str_with_prefix_tou((const gchar*)str, NULL, &field->width);
    xmlFree(str);
  }

  if((field->type == vrt_cif_type_int) || 
     (field->type == vrt_cif_type_uint) || 
     (field->type == vrt_cif_type_fixed) || 
     (field->type == vrt_cif_type_ufixed)) 
  {
    str = xmlGetProp(base, (const xmlChar*)"units");
    if(str && *str) {
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, " ");
      wmem_strbuf_append_printf(ws_str, "%s",(const char *)str);
      field->unit_strings.singular = wmem_strbuf_finalize(ws_str);
      field->unit_strings.plural = NULL;
    } else {
      field->unit_strings.singular = NULL;
      field->unit_strings.plural = NULL;
    }
    xmlFree(str);
  } else {
    field->unit_strings.singular = NULL;
    field->unit_strings.plural = NULL;
  }
  
  if((field->type == vrt_cif_type_fixed) || (field->type == vrt_cif_type_ufixed)) {
    str = xmlGetProp(base, (const xmlChar*)"point");
    if(str && *str) {
      str_with_prefix_tou((const gchar*)str, NULL, &field->point);
    } else {
      field->point = 0;
    }
    xmlFree(str);
    //if(field->point > field->width) {
    //  report_warning("Field %s.%s has point (%d) > width (%d)", (parent_abbrev ? parent_abbrev : ""),
    //      (field->name ? field->name : ""), field->point, field->width);
    //  field->point = field->width;
    //}
    str = xmlGetProp(base, (const xmlChar*)"scale");
    if(str && *str) {
    field->scale = g_ascii_strtod((const gchar *) str, NULL);
    } else {
      field->scale = 1.0;
    }
    xmlFree(str);
  } else {
    field->point = 0;
    field->scale = 1.0;
  }

  if(field->type == vrt_cif_type_enum) {
    /* walk once to count */
    guint count = 0;
    for (xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
      if (xmlStrcmp(cur->name, (const xmlChar*)"enum")) continue;
      ++count;
    }
    field->enum_strings = wmem_alloc_array(vrt_cif_cfg_scope, value_string, count + 1);
    /* and again to fill in the array */
    guint n = 0;
    for (xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
      if (xmlStrcmp(cur->name, (const xmlChar*)"enum")) continue;

      str = xmlGetProp(cur, (const xmlChar*)"key");
      str_with_prefix_tou((const gchar*)str, NULL, &field->enum_strings[n].value);
      xmlFree(str);

      str = xmlGetProp(cur, (const xmlChar*)"value");
      ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
      field->enum_strings[n].strptr = wmem_strbuf_finalize(ws_str);
      xmlFree(str);
      n++;
    }
    /* end list with null entry */
    field->enum_strings[n].value = 0;
    field->enum_strings[n].strptr = NULL;
  } else {
    field->enum_strings = NULL;
  }

  if(field->type == vrt_cif_type_array) {
    field->array_descript = wmem_new0(vrt_cif_cfg_scope, vrt_cif_record_array_descript_t);
    init_record_array_descript(field->array_descript);
    parse_record_array(base, field->array_descript, field->abbrev);
  } else {
    field->array_descript = NULL;
  }

  return field;
}

static vrt_cif_record_descript_t *parse_record_enable(const xmlNodePtr base, const char *parent_abbrev)
{
  vrt_cif_record_descript_t *rec = wmem_new0(vrt_cif_cfg_scope, vrt_cif_record_descript_t);
  rec->tree_pid = -1;
  rec->ett_pid = -1;

  wmem_strbuf_t *ws_str;
  xmlChar *str = xmlGetProp(base, (const xmlChar*)"name");
  ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
  rec->name = wmem_strbuf_finalize(ws_str);
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"abbrev");
  if(str && *str) {
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, parent_abbrev);
    wmem_strbuf_append_printf(ws_str, ".%s", (const char *)str);
    rec->abbrev = wmem_strbuf_finalize(ws_str);
  } else {
    report_warning("Array record %s has an empty abbrev; using name instead", (rec->name ? rec->name : ""));
    ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, parent_abbrev);
    wmem_strbuf_append_printf(ws_str, ".%s", (rec->name ? rec->name : ""));
    rec->abbrev = wmem_strbuf_finalize(ws_str);
  }
  xmlFree(str);

  vrt_cif_configuration->node_count++; /* account for the subtree */

  for(xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
    if(!(xmlStrcmp(cur->name, (const xmlChar*)"cifField"))) {
      vrt_cif_field_descript_t *field = parse_field(cur, rec->abbrev);
      if(add_map_field(field, &rec->fields)) {
        vrt_cif_configuration->leaf_count++;  /* count these as we go for structure allocation later */
      }
    }
    else if((!xmlStrcmp(cur->name, (const xmlChar *)"info"))) {
      rec->info = parse_info(cur);
    }
  }

  return rec;
}

static void parse_record_array(const xmlNodePtr base, vrt_cif_record_array_descript_t *ra_descript, const char *parent_abbrev)
{
  for(xmlNodePtr cur = base->xmlChildrenNode; cur != NULL; cur = cur->next) {
    if(!xmlStrcmp(cur->name, (const xmlChar*)"recordIndex")) {
      xmlChar *str = xmlGetProp(cur, (const xmlChar*)"offset");
      str_with_prefix_tou((const gchar *) str, NULL, &ra_descript->rec_idx_offset);
      xmlFree(str);
      str = xmlGetProp(cur, (const xmlChar*)"width");
      str_with_prefix_tou((const gchar *) str, NULL, &ra_descript->rec_idx_width);
      xmlFree(str);
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar*)"headerEnable")) {
      xmlChar *str = xmlGetProp(cur, (const xmlChar*)"index");
      /* Index attribute mean an optional field; otherwise it is required */
      if(str != NULL) {
        guint pos;
        str_with_prefix_tou((const gchar *) str, NULL, &pos);
        if(pos >= 32) {
          report_warning("Ignoring array header enable bit position %d >= 32 in field %s", pos, parent_abbrev);
        } else if(ra_descript->hdr_opt[pos] != NULL) {
          report_warning("Ignoring duplicate array header enable bit position %d in field %s", pos, parent_abbrev);
        } else {
          ra_descript->hdr_opt[pos] = parse_record_enable(cur, parent_abbrev);
          ra_descript->hdr_bitmap |= 1 << pos;
          vrt_cif_configuration->leaf_count += 1;  /* hdr_map_pid[pos] */
        }
      } else {
        ra_descript->hdr_req = parse_record_enable(cur, parent_abbrev);
      }
      xmlFree(str);
      if (xmlHasProp(cur, (const xmlChar*)"offset") != NULL) {
        report_warning("headerEnable in array field %s had unexpected offset property. Did you intend to use index?",
                       parent_abbrev);
      }
    }
    else if(!xmlStrcmp(cur->name, (const xmlChar*)"recordEnable")) {
      xmlChar *str = xmlGetProp(cur, (const xmlChar*)"index");
      /* Index attribute means an optional field; otherwise it is required */
      if(str != NULL) {
        guint pos;
        str_with_prefix_tou((const gchar *) str, NULL, &pos);
        if(pos >= 32) {
          report_warning("Ignoring array record enable bit position %d >= 32 in field %s", pos, parent_abbrev);
        } else if(ra_descript->rec_opt[pos] != NULL) {
          report_warning("Ignoring duplicate array record enable bit position %d in field %s", pos, parent_abbrev);
        } else {
          ra_descript->rec_opt[pos] = parse_record_enable(cur, parent_abbrev);
          ra_descript->rec_bitmap |= 1 << pos;
          vrt_cif_configuration->leaf_count += 1;  /* rec_map_pid[pos] */
        }
      } else {
        if(ra_descript->rec_req == NULL) {
          ra_descript->rec_req = parse_record_enable(cur, parent_abbrev);
        } else {
          report_warning("Ignoring duplicate required array record enable in field %s", parent_abbrev);
        }
      }
      xmlFree(str);
      if(xmlHasProp(cur, (const xmlChar*)"offset") != NULL) {
        report_warning("recordEnable in array field %s had unexpected offset property. Did you intend to use index?",
                       parent_abbrev);
      }
    }
  }
  /* Account for new nodes, and promote field from a leaf */
  vrt_cif_configuration->node_count++;  /* field  */
  vrt_cif_configuration->leaf_count--;
  if((ra_descript->hdr_req != NULL) || (ra_descript->hdr_bitmap != 0)) vrt_cif_configuration->node_count++; /* hdr */
  if(ra_descript->hdr_bitmap != 0) vrt_cif_configuration->node_count++; /* hdr_map */
  if((ra_descript->rec_req != NULL) || (ra_descript->rec_bitmap != 0)) vrt_cif_configuration->node_count++; /* rec */
  if(ra_descript->rec_bitmap != 0) vrt_cif_configuration->node_count++; /* rec_map */
}

static vrt_cif_info_descript_t *parse_info(const xmlNodePtr base)
{
  vrt_cif_info_descript_t *info = wmem_new0(vrt_cif_cfg_scope, vrt_cif_info_descript_t);

  xmlChar *str = xmlGetProp(base, (const xmlChar*)"level");
  if(!(xmlStrcmp(str, (const xmlChar*)"error"))) {
    info->ei = &ei_cfg_err;
  }
  else if(!(xmlStrcmp(str, (const xmlChar*)"warn"))) {
    info->ei = &ei_cfg_warn;
  } 
  else {
    info->ei = &ei_cfg_note;
  }
  xmlFree(str);

  str = xmlGetProp(base, (const xmlChar*)"string");
  wmem_strbuf_t *ws_str = wmem_strbuf_new(vrt_cif_cfg_scope, str);
  info->text = wmem_strbuf_finalize(ws_str);
  xmlFree(str);

  return info;
}

/* Default fallback function to display remaining payload as raw byte array */
static int display_unparsed_payload(proto_tree *cif_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, gint nwords)
{
  if (nwords > 0) {
    /* The built in display of FT_BYTES in an unprefixed string of the hex values. Pretty it up a little */
    gchar* str = tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, offset, nwords*4, ' ');
    proto_item *ti = proto_tree_add_bytes_format_value(cif_tree, hf_vrt_cif_raw, tvb, offset, nwords*4, NULL, "HEX(%s)", (str?str:""));
    expert_add_info_format(pinfo, ti, &ei_proto_warn, "Unparsed fields remaining");
  }
  return tvb_captured_length(tvb);
}

/* Callback for walking field tree */
static void display_cif_field_cb(void *v, void *p)
{
  vrt_cif_field_display_cb_data_t *ptr = (vrt_cif_field_display_cb_data_t *) p;
  vrt_cif_field_descript_t *field = (vrt_cif_field_descript_t *) v;

  guint offset;
  if(field->is_relative) {
    /* offset is relative to the end of the highest byte parsed */
    offset = (ptr->offset_delta*8) + field->offset;
  } else {
    /* offset is absolute (from start of cif field) */
    offset = field->offset;
  }
  gint top_byte = (offset + field->width + 7) / 8;  /* find upper byte offset */
  if(top_byte > ptr->offset_delta) {
    /* consume the word if all bytes are used */
    ptr->nwords = ptr->nwords - ((top_byte - ptr->offset_delta) /4);
    ptr->offset_delta = top_byte;
  }
  
  /* Fields are all relative to 32-bit words */
  gint pos = ((gint) (offset / 8)) & ~0x3;
  gint blen = 4 + ((gint) (((field->width - (32 - offset % 32)) + 31) / 32) * 4);

  /* Most fields are can be formated with the built in methods specified in the hf list,
     but a few types require special handling */
  if((field->type == vrt_cif_type_fixed) || (field->type == vrt_cif_type_ufixed)) {
    guint64 val;
    if(field->width <= 32) {
      /* grab one raw words */
      val = tvb_get_guint32(ptr->tvb, ptr->offset + pos, ENC_BIG_ENDIAN);
    } else {
      /* grab two raw words */
      val = tvb_get_guint64(ptr->tvb, ptr->offset + pos, ENC_BIG_ENDIAN);
    }
    /* shifting by 64 doesn't work, so check first; fields cannot be > 64 bits */
    if (field->width < 64) {
        val = (val >> (offset & 0x1f)) & ((G_GUINT64_CONSTANT(1) << field->width)-1);
    }
    gdouble v_double;
    if((field->type == vrt_cif_type_fixed) && (val & (G_GUINT64_CONSTANT(1) << (field->width-1)))) {
      /* negative value */
      val = (~val & ((G_GUINT64_CONSTANT(1) << field->width)-1)) + 1;
      v_double = (gdouble) -1.0 * val;
    } else {
      v_double = (gdouble) 1.0 * val;
    }
    v_double /= (G_GUINT64_CONSTANT(1) << field->point);
    v_double *= field->scale;

    /* we could get extra display resolution by converting the integer and fractional parts
       separately, but its probably not worth the effort */
    if(field->width >= 52) {
      expert_add_info_format(ptr->pinfo, ptr->tree, &ei_proto_note, "Fixed point precision greater than double");
    }
    /* [TODO] consider if we can use SI unit scaling i.e. Hz, KHz, MHz, GHz, THz, ... */
    /*        maybe for a fixed set of units (Hz, m, s)? */
    proto_tree_add_double(ptr->tree, field->pid, ptr->tvb, ptr->offset+pos, blen, v_double);
  }
  else if (field->type == vrt_cif_type_raw) {
      /* The built in display of FT_BYTES in an unprefixed string of the hex values. Pretty it up a little */
      gchar* str = tvb_bytes_to_str_punct(wmem_packet_scope(), ptr->tvb, ptr->offset + pos, blen, ' ');
      proto_tree_add_bytes_format_value(ptr->tree, field->pid, ptr->tvb, ptr->offset + pos, blen, NULL, "HEX(%s)", (str?str:""));
  }
  else if (field->type == vrt_cif_type_dynamic) {
      /* The built in FT_UINT_BYTES expects a length field in bytes, but V49 uses words */
      guint32 nwords = tvb_get_guint32(ptr->tvb, ptr->offset + pos, ENC_BIG_ENDIAN);
      gint buf_pos = ptr->offset + pos + 4;  /* elements are word aligned after size */
      if(field->width < 32) {
        /* bit numbering is relative to the 32 bit words */
        nwords = (nwords >> (offset % 32)) & ~(~0ul << field->width);
      }
      /* account for size of variable length fields */
      nwords -= 1;  /* lengh field already accounted for */
      ptr->offset_delta = ptr->offset_delta + (nwords*4);
      ptr->nwords = ptr->nwords - nwords;
      gchar* str = NULL;
      if(nwords > 0) {
        if((buf_pos + (nwords*4)) > tvb_reported_length(ptr->tvb)) {
          /* explicitly check size so we can handle it gracefully */
          expert_add_info_format(ptr->pinfo, ptr->tree, &ei_proto_warn, "Dynamic field length extends beyond packet. Truncating.");
          nwords = (tvb_reported_length(ptr->tvb) - buf_pos) / 4;
        }
        str = tvb_bytes_to_str_punct(wmem_packet_scope(), ptr->tvb, buf_pos, nwords*4, ' ');
      }
      proto_tree_add_bytes_format_value(ptr->tree, field->pid, ptr->tvb, ptr->offset + pos, (nwords+1)*4, NULL, "HEX(%s)", (str?str:""));
  }
  else if (field->type == vrt_cif_type_string) {
      /* The built in FT_UINT_STRING expects a length field in bytes, but V49 uses words */
      guint32 nwords = tvb_get_guint32(ptr->tvb, ptr->offset + pos, ENC_BIG_ENDIAN);
      gint buf_pos = ptr->offset + pos + 4;  /* elements are word aligned after size */
      if (field->width < 32) {
          /* bit numbering is relative to the 32 bit words */
          nwords = (nwords >> (offset % 32)) & ~(~0ul << field->width);
      }
      if ((buf_pos + (nwords * 4)) > tvb_reported_length(ptr->tvb)) {
          /* explicitly check size so we can handle it gracefully */
          expert_add_info_format(ptr->pinfo, ptr->tree, &ei_proto_warn, "String field length extends beyond packet. Truncating.");
          nwords = (tvb_reported_length(ptr->tvb) - buf_pos) / 4;
      }
      /* account for size of variable length fields */
      ptr->offset_delta = ptr->offset_delta + (nwords * 4);
      ptr->nwords = ptr->nwords - nwords;
      /* Note: for strings length does not include the length field */
      gchar* str = NULL;
      if(nwords > 0) {
        str = tvb_get_string_enc(wmem_packet_scope(), ptr->tvb, buf_pos, nwords*4, ENC_UTF_8);
      }
      proto_tree_add_string(ptr->tree, field->pid, ptr->tvb, ptr->offset + pos, (nwords + 1) * 4, (str?str:""));
  }
  else if (field->type == vrt_cif_type_array) {
      /* Unlike string and dynamic, nwords for arrays includes the count */
      guint32 nwords = tvb_get_guint32(ptr->tvb, ptr->offset + pos, ENC_BIG_ENDIAN);
      if(field->width < 32) {
        /* bit numbering is relative to the 32 bit words */
        nwords = (nwords >> (offset % 32)) & ~(~0ul << field->width);
      }
      if((ptr->offset + pos + (nwords*4)) > tvb_reported_length(ptr->tvb)) {
        /* explicitly check size so we can handle it gracefully */
        expert_add_info_format(ptr->pinfo, ptr->tree, &ei_proto_warn, "Array field length extends beyond packet. Truncating.");
        nwords = (tvb_reported_length(ptr->tvb) - (ptr->offset + pos)) / 4;
      }
      proto_item *ti = proto_tree_add_item(ptr->tree, field->pid, ptr->tvb, ptr->offset + pos, nwords*4, ENC_NA);
      proto_tree *subtree = proto_item_add_subtree(ti, field->array_descript->field_ett_pid);

      if(nwords < 3) {
        expert_add_info_format(ptr->pinfo, subtree, &ei_proto_warn, "Misformed or Empty Array. Skipping.");
      } else {
        display_array(ptr->tvb, ptr->pinfo, subtree, ptr->offset + pos, field->array_descript);
      }

      /* account for size of variable length fields */
      nwords -= 1;  /* lengh field already accounted for */
      ptr->offset_delta = ptr->offset_delta + (nwords*4);
      ptr->nwords = ptr->nwords - nwords;

  } else {
    /* All other cases can use the built-in wireshark formatting */
    proto_tree_add_item(ptr->tree, field->pid, ptr->tvb, ptr->offset+pos, blen, ENC_BIG_ENDIAN);
  }


  if(field->info != NULL) {
    /* info associated with specific byte offset */
    proto_tree_add_expert_format(ptr->tree, ptr->pinfo, field->info->ei, ptr->tvb, 
                                 ptr->offset+pos, blen, "%s", (field->info->text ? field->info->text : ""));

    // BASE_ALLOW_ZERO
  }

  return;
}

static void display_warn_err_mask(tvbuff_t *tvb, proto_tree *tree, int offset, int *pid_list)
{
    guint32 fval = tvb_get_ntohl(tvb, offset);
    int idx = 0;
    while(fval) {
      if(fval & 1) {
        proto_tree_add_boolean_format_value(tree, pid_list[idx], tvb, offset, 4, ~0, "%s", "");
      }
      fval >>= 1; ++idx;
    }
}

static int display_array(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int start_offset, vrt_cif_record_array_descript_t *arr)
{
    /* V49.2 Array of records has a defined structure for the configuration fields (sec. 9.3.1)
       0  Total Size of array in words
       1  Header Size(8 bits) | Rec Size(12 bits) | Num Rec(12 bits)
       2  Record Indicator (required)
       3  Header Indicator (optional)
       4  Header (optional)
       *  Records (from end of header)

       The description in the configuration file defined which optional fields will exist in a given array.
       If an optional field is not included, all other fields shift down by 4 bytes

       [NOTE] The defintion of header size in the specification conflicts between the general description and
        specific examples. We assume that header size includes the 3 mandatory words.
    */
    gint max_words = (tvb_reported_length_remaining(tvb, 0)) / 4;
    int riw_offset = start_offset+(2*4);
    int hiw_offset = start_offset+(3*4);
    int offset;

    /* record indicator field is always included even when no optional record fields are defined
       however header indicator field is not, so bump back the starting offset if it is missing */
    if(arr->hdr_bitmap == 0) {
      offset = start_offset + (3*4);
    } else {
      offset = start_offset + (4*4);
    }

    guint nwords = tvb_get_guint32(tvb, start_offset, ENC_BIG_ENDIAN);
    guint total_len = 4 * nwords;
    guint lengths = tvb_get_guint32(tvb, start_offset+4, ENC_BIG_ENDIAN);
    guint n_records = lengths & 0xFFF;
    guint rec_len = 4*((lengths >> 12) & 0xFFF);
    guint hdr_len = 4*((lengths >> 24) & 0xFF);

    if(total_len != hdr_len + (n_records * rec_len)) {
      expert_add_info_format(pinfo, tree, &ei_proto_warn, "Array field lengths are not consistent.");
    }
    if(nwords > (guint) max_words) {
      /* we already displayed a message, so just truncate length here */
      nwords = max_words;
    }
    nwords -= 3;

    /* We have up to 4 basic subtree types directly under the array field
       - Header Indicator  (if any header indicator bits are specified)
       - Record Indicator  (if any record indicator bits are specified)
       - Header (if required header fields or any header indicator bits are specified)
       - 0:N-1 Records
    */

    /* grab the header indicator word and display the set bits */
    wmem_queue_t *hdr_list = wmem_list_new(pinfo->pool); /* (vrt_cif_record_descript_t *) */
    if(arr->hdr_req != NULL) {
      wmem_queue_push(hdr_list, arr->hdr_req);
    }
    if((arr->hdr_bitmap != 0) && (nwords > 0)) {
      guint32 indicator = tvb_get_ntohl(tvb, hiw_offset);
      proto_item *sti = proto_tree_add_uint_format_value(tree, arr->hdr_map_pid, tvb, hiw_offset, 4, indicator, "0x%x", indicator);
      proto_tree *subtree = proto_item_add_subtree(sti, arr->hdr_map_ett_pid);
      nwords -= 1;
      for(int n = ((int)(sizeof(arr->hdr_opt) / sizeof( vrt_cif_record_descript_t *)))-1; n >= 0; --n) {
        /* Display the individual CIF bit */
        if((arr->hdr_opt[n] != NULL) && (indicator & (1<<n))) {
          proto_tree_add_boolean_format_value(subtree, arr->hdr_map_bit_pid[n], tvb, hiw_offset, 4, ~0, "%s", "");
          if(arr->hdr_opt[n]->fields != NULL) {
            wmem_queue_push(hdr_list, arr->hdr_opt[n]);
          }
        }
      }
    }

    /* since we need to walk this multiple times, the queue_t is not suited */
    wmem_list_t *rec_list = wmem_list_new(pinfo->pool); /* (vrt_cif_record_descript_t *) */
    if(arr->rec_req != NULL) {
      wmem_list_append(rec_list, arr->rec_req);
    }
    /* The record indicator is included on all packets, only display it if optional fields are defined
       but add a warning if any undefined bits are set */
    guint32 rec_indicator = tvb_get_ntohl(tvb, riw_offset);
    proto_tree* rif_tree = NULL;
    if(arr->rec_bitmap != 0) {
      proto_item *sti = proto_tree_add_uint_format_value(tree, arr->rec_map_pid, tvb, riw_offset, 4, rec_indicator, "0x%x", rec_indicator);
      rif_tree = proto_item_add_subtree(sti, arr->rec_map_ett_pid);
    }
    for(int n = ((int)(sizeof(arr->rec_opt) / sizeof( vrt_cif_record_descript_t *)))-1; n >= 0; --n) {
      if(rec_indicator & (1<<n)) {
        if(arr->rec_opt[n] != NULL) {
          /* Display the individual CIF bit */
          proto_tree_add_boolean_format_value(rif_tree, arr->rec_map_bit_pid[n], tvb, riw_offset, 4, ~0, "%s", "");
          if(arr->rec_opt[n]->fields != NULL) {
            wmem_list_append(rec_list, arr->rec_opt[n]);
          }
        } else {
          /* Undefined CIF bit set */
          proto_tree_add_expert_format(tree, pinfo, &ei_proto_warn, tvb, riw_offset, 4, "Unexpected bit(%d) of Record CIF set: 0x%x", (int) n, rec_indicator);
        }
      }
    }

    /* subtree for header fields */
    if((wmem_queue_count(hdr_list) > 0) && (nwords > 0)) {
      proto_item *sti = proto_tree_add_item(tree, arr->hdr_pid, tvb, offset, hdr_len, ENC_NA);
      proto_tree *subtree = proto_item_add_subtree(sti, arr->hdr_ett_pid);

      /* walk the header list, but stop early if we run out of header words */
      while((wmem_queue_count(hdr_list) > 0) && (nwords > 0)) {
        vrt_cif_record_descript_t *en = wmem_queue_pop(hdr_list);
        /* add the subtree then walk the fields parsing and adding each one */
        proto_item *fti = proto_tree_add_item(subtree, en->tree_pid, tvb, offset, -1, ENC_NA);
        proto_tree *field_tree = proto_item_add_subtree(fti, en->ett_pid);
        if(en->info != NULL) {
          proto_tree_add_expert_format(field_tree, pinfo, en->info->ei, tvb, offset, 4, "%s", (en->info->text ? en->info->text : ""));
        }
        vrt_cif_field_display_cb_data_t ud;
        ud.pinfo = pinfo;
        ud.tvb = tvb;
        ud.offset = offset;
        ud.nwords = nwords;
        ud.tree = field_tree;
        ud.offset_delta = 0;
        wmem_list_foreach(en->fields, display_cif_field_cb, &ud);
        /* field size aligned to next word boundary */
        gint words_in_field = (ud.offset_delta + 3) / 4;
        proto_item_set_len(fti, words_in_field*4);
        offset += 4 * words_in_field; nwords -= words_in_field;
      }
    }
    wmem_destroy_queue(hdr_list);

    /* loop over parsed number of records */
    gint pos = ((gint) (arr->rec_idx_offset / 8)) & ~0x3;
    if(wmem_list_count(rec_list) > 0) {
      guint32 idx;
      for(guint n = 0; n < n_records; ++n) {
        if(arr->rec_idx_width > 0) {
          if(nwords == 0) {
            expert_add_info_format(pinfo, tree, &ei_proto_warn, "Array record extends beyond field size. Truncating.");
            break;
          }
          /* Index offset relative to start of record */
          idx = tvb_get_guint32(tvb, offset + pos, ENC_BIG_ENDIAN);
          guint32 mask = ~((~0ul)<<arr->rec_idx_width);
          idx = (idx >> (arr->rec_idx_offset % 32)) & mask;
        } else {
          /* use sequence count if no index specified */
          idx = n;
        }
        /* We use 0 to signal variable length record; just highlight the length in this case */
        if(rec_len == 0) {
          rec_len = 4;
        }
        proto_item *sti = proto_tree_add_uint_format_value(tree, arr->rec_pid, tvb, offset, rec_len, idx, "[%d]", idx);
        proto_tree *subtree = proto_item_add_subtree(sti, arr->rec_ett_pid);

        wmem_list_frame_t *f = wmem_list_head(rec_list);
        for(guint m = 0; m <  wmem_list_count(rec_list); ++m) {
          vrt_cif_record_descript_t *en = wmem_list_frame_data(f);
          if(nwords == 0) {
            expert_add_info_format(pinfo, tree, &ei_proto_warn, "Array record extends beyond field size. Truncating.");
            break;
          }
          /* add the subtree then walk the fields parsing and adding each one */
          proto_item *fti = proto_tree_add_item(subtree, en->tree_pid, tvb, offset, 0, ENC_NA);
          proto_tree *field_tree = proto_item_add_subtree(fti, en->ett_pid);
          if(en->info != NULL) {
            proto_tree_add_expert_format(field_tree, pinfo, en->info->ei, tvb, offset, 4, "%s", (en->info->text ? en->info->text : ""));
          }
          vrt_cif_field_display_cb_data_t ud;
          ud.pinfo = pinfo;
          ud.tvb = tvb;
          ud.offset = offset;
          ud.nwords = nwords;
          ud.tree = field_tree;
          ud.offset_delta = 0;
          wmem_list_foreach(en->fields, display_cif_field_cb, &ud);
          /* field size aligned to next word boundary */
          gint words_in_field = (ud.offset_delta + 3) / 4;
          proto_item_set_len(fti, words_in_field*4);
          offset += 4 * words_in_field; nwords -= words_in_field;
          f = wmem_list_frame_next(f);
        }
      }
    }
    wmem_destroy_list(rec_list);
    /* Use the parsed total length to shift overall packet offset regardless of what subfields
       were actually parsed from the array field. */
    return total_len - start_offset;
}

static gint dissect_cif(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, wmem_array_t* map_list, int init_offset, wmem_queue_t * field_list, vrt_payload_type_t type)
{
  gint nwords = 0;
  int offset = init_offset;
  wmem_queue_t *cif_list = wmem_list_new(pinfo->pool);  /* (vrt_cif_map_descript_t *) */

  /* loop until all CIFs parsed */
  wmem_queue_push(cif_list, wmem_array_index(map_list, 0)); /* we always have CIF0 */
  while(wmem_queue_count(cif_list) > 0) {
    vrt_cif_map_descript_t *map_descript = wmem_queue_pop(cif_list);

    /* We want to display with a bit mask, but fetch the value separately to check for undefined bits */
    guint32 cif = tvb_get_ntohl(tvb, offset);
    /* Grab & display the full CIF */
    proto_item* sti;
    proto_tree* subtree;
    if (type == vrt_payload_warn) {
      sti = proto_tree_add_uint_format_value(tree, map_descript->warn_pid, tvb, offset, 4, cif, "0x%x", cif);
      subtree = proto_item_add_subtree(sti, map_descript->warn_ett_pid);
    } else if (type == vrt_payload_err) {
      sti = proto_tree_add_uint_format_value(tree, map_descript->err_pid, tvb, offset, 4, cif, "0x%x", cif);
      subtree = proto_item_add_subtree(sti, map_descript->err_ett_pid);
    } else {
      /* Skip the message if the CIF is enabled, but none of the bits are set. This
         prevents spurious warning/error messages when unused cifs are enabled to
         provide a fixed length header */
      if ((map_descript->info != NULL) && cif) {
        proto_tree_add_expert_format(tree, pinfo, map_descript->info->ei, tvb, offset, 4, "%s",
                                     (map_descript->info->text ? map_descript->info->text : ""));
      }
      sti = proto_tree_add_uint_format_value(tree, map_descript->pid, tvb, offset, 4, cif, "0x%x", cif);
      subtree = proto_item_add_subtree(sti, map_descript->ett_pid);
    }
    
    /* The CIF enable bits are in the opposite order from the CIF fields, so this requires looping twice:
       first 0-31 to build up the complete CIF list, then again, from 31-0 parsing the active fields */
    guint32 mask = 1;
    vrt_cif_enable_descript_t *en_descript = &map_descript->enables[0];
    for (int n = 0; n < 32; ++n) {
      if (cif & mask) {
        if (en_descript->abbrev == NULL) {
          expert_add_info_format(pinfo, sti, &ei_proto_err, "Ignoring undefined CIF%d[%d]; Fields may not be aligned.", map_descript->index, n);
        } else if (en_descript->is_link) {
          /* [NOTE] Assumes CIF selects are defined in order */
          vrt_cif_field_descript_t* f = (vrt_cif_field_descript_t*)wmem_list_frame_data(wmem_list_head(en_descript->fields));
          wmem_queue_push(cif_list, wmem_array_index(map_list, f->link));
        }
      }
      mask <<= 1;
      ++en_descript;
    }
    mask = 1 << 31;
    en_descript = &map_descript->enables[31];
    for(int n = 31; n >= 0; --n) {
      if((cif & mask) && (en_descript->abbrev != NULL)) {
        /* Display the individual CIF bit */
        proto_tree_add_boolean_format_value(subtree, en_descript->bit_pid, tvb, offset, 4, ~0, "%s", "");
        if((!en_descript->is_link) && (en_descript->fields != NULL)) {
          wmem_queue_push(field_list, en_descript);
        }
      }
      mask >>= 1;
      --en_descript;
    }
    /* move to the next word in the buffer */
    offset += 4; nwords++;
  }
  wmem_destroy_queue(cif_list);
  return nwords;
}

static int dissect_vrt_cif(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    int  offset = 0;
    gint nwords;
    vrt_packet_description_t* descript = (vrt_packet_description_t*)(data);

    nwords = (tvb_reported_length_remaining(tvb, 0)) / 4;

    /* Main packet types is already assigned at previous level; append cif specific info here */
    if (descript->is_ack) {
      col_append_str(pinfo->cinfo, COL_INFO, "(ACK)");
    }
    if (descript->has_cid) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "- Map with cid = %#08x:%04x:%04x", descript->oui, descript->info_class_code, descript->packet_class_code);
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, "- Map without cid");
    }

    /* Use a default field as a proxy to make sure field array has been registered */
    if (hf_vrt_cif_raw == -1) {
        load_and_register_hf_fields(NULL);
    }

    if(tree) {
      proto_item* ti = proto_tree_add_item(tree, proto_vrt_cif, tvb, offset, -1, ENC_NA);
      proto_tree* cif_tree = proto_item_add_subtree(ti, ett_top);

      if ((pref_filename == NULL) || (pref_filename[0] == '\0')) {
        expert_add_info_format(pinfo, cif_tree, &ei_proto_warn, "Configuration file not defined");
        return(display_unparsed_payload(cif_tree, pinfo, tvb, offset, nwords));
      }

      /* Select CIF definitions based on packet type and class id */
      vrt_cif_class_id_map_t *dt = NULL;
      if((descript->type == vrt_type_ctx) || (descript->type == vrt_type_cmd)) {
         dt = &vrt_cif_configuration->cif_class_table;
      } else if((descript->type == vrt_type_ectx) || (descript->type == vrt_type_ecmd)) {
         dt = &vrt_cif_configuration->ecif_class_table;
      } else {
        /* this packet doesn't use cifs; just provide the raw payload */
        expert_add_info_format(pinfo, cif_tree, &ei_proto_warn, "Invalid packet type");
        return(display_unparsed_payload(cif_tree, pinfo, tvb, offset, nwords));
      }
      
      guint64 classid;
      if(descript->has_cid) {
        classid = descript->oui;
        classid = (classid << 16) + descript->info_class_code;
        classid = (classid << 16) + descript->packet_class_code;
      } else {
        classid = default_classid;
      }
      vrt_cif_class_descript_t *class_descript;
      while((class_descript = find_class_descript(dt, classid, NULL)) == NULL) {
        if(!pref_class_fallback) {
          expert_add_info_format(pinfo, cif_tree, &ei_proto_note, \
                                 "No definition of class 0x%" G_GINT64_MODIFIER "x available", classid);
        } else {
          expert_add_info_format(pinfo, cif_tree, &ei_proto_note, \
                                 "No definition of class 0x%" G_GINT64_MODIFIER "x available; use default definition", classid);
        }

        if((!pref_class_fallback) || (classid == default_classid)) {
          return(display_unparsed_payload(cif_tree, pinfo, tvb, offset, nwords));
        }
        /* try again with fallback id */
        classid = default_classid;
      }

      if(class_descript->info != NULL) {
        expert_add_info_format(pinfo, cif_tree, class_descript->info->ei, "%s",
                               (class_descript->info->text ? class_descript->info->text : ""));
      }

      /* Parse the type and cam field to determine format of payload */
      vrt_payload_type_t payload_format = vrt_payload_empty;

      if((descript->type == vrt_type_ctx) || (descript->type == vrt_type_ectx)) {
        payload_format = vrt_payload_cif_field;
      } else if((descript->type == vrt_type_cmd) || (descript->type == vrt_type_ecmd)) {
        gboolean ackEr = (descript->cam & (1<<16) ? TRUE : FALSE);
        gboolean ackW  = (descript->cam & (1<<17) ? TRUE : FALSE);
        gboolean ackS  = (descript->cam & (1<<18) ? TRUE : FALSE);
        gboolean ackX  = (descript->cam & (1<<19) ? TRUE : FALSE);
        gboolean ackV  = (descript->cam & (1<<20) ? TRUE : FALSE);
        gboolean ackU  = (descript->cam & (1<<15) ? TRUE : FALSE);  /* user defined ack bit */
        guint32 action = (descript->cam >> 23) & 0x3;

        if(descript->is_ack) {
          gboolean has_type = false; /* ackV, ackX, ackS, and ackU (if defined)) are one-hot encoded*/
          gboolean has_multiple_types = false;
          /* Most cases base payload on ackW/ackEr; override special cases below */
          if((ackW)  && !(ackEr)) {
            payload_format = vrt_payload_warn;
          } else if(!(ackW) && (ackEr)) {
            payload_format = vrt_payload_err;
          } else if((ackW) && (ackEr)) {
            payload_format = vrt_payload_warn_err;
          } else {
            payload_format = vrt_payload_empty;
          }

          if(ackV) {
            has_multiple_types = has_type;
            has_type = true;
          }
          if(ackX) {
            has_multiple_types = has_type;
            has_type = true;
          }
          if(ackS) {
            has_multiple_types = has_type;
            has_type = true;
            /* ackEr and ackW are defined to be 0 in this mode */
            if(ackW || ackEr) {
              expert_add_info_format(pinfo, cif_tree, &ei_proto_warn, "Additional acknowledge flags not allowed with ackS");
            }
            payload_format = vrt_payload_cif_field;
          }
          if(ackU && (class_descript->extension_cam != NULL)) {
            has_multiple_types = has_type;
            has_type = true;
            if((class_descript->extension_cam->user_req == vrt_payload_cif) ||
               (class_descript->extension_cam->user_req == vrt_payload_cif_field)) {
              payload_format = class_descript->extension_cam->user_req;
            }
          }

          if(!has_type || has_multiple_types) {
            expert_add_info_format(pinfo, cif_tree, &ei_proto_warn, "Exactly one acknowledge subtype flag must be set");
            payload_format = vrt_payload_empty;
          }
        } else {  /* Not acknowledge packet */
          if(action == 0) {
            payload_format = vrt_payload_cif;
          } else {
            payload_format = vrt_payload_cif_field;
          }
        }

        /* Display any defined user fields from cam. These are associated with the previously parsed cam
           not the current tvb, but we want to reuse the field processing code, so create a tvbuff from cam.  */
        if(class_descript->extension_cam != NULL) {
          vrt_cif_extension_cam_descript_t *camd = class_descript->extension_cam;
          if((camd->fields != NULL) || (camd->info != NULL)) {
            ti = proto_tree_add_item(cif_tree, camd->pid, tvb, offset, -1, ENC_NA);
            proto_tree *field_tree = proto_item_add_subtree(ti, camd->ett_pid);
            /* we (may) need to flip the bytes so they are in the expected order */
            guint8* cam_buf = wmem_alloc_array(wmem_packet_scope(), guint8, 4);
            cam_buf[3] = descript->cam & 0xFF;
            cam_buf[2] = (descript->cam >> 8) & 0xFF;
            cam_buf[1] = (descript->cam >> 16) & 0xFF;
            cam_buf[0] = (descript->cam >> 24) & 0xFF;
            tvbuff_t *cam_tvb = tvb_new_real_data(cam_buf, 4, 4);

            if(camd->info != NULL) {
              expert_add_info_format(pinfo, field_tree, camd->info->ei, "%s", (camd->info->text ? camd->info->text : ""));
            }
            if(camd->fields != NULL) {
              /* It feels complicated to have to pass all this info to a callback, but there doesn't
                 appear to be another way to walk the tree in the API? */
              vrt_cif_field_display_cb_data_t ud;
              ud.pinfo = pinfo;
              ud.tvb = cam_tvb;
              ud.offset = 0;
              ud.nwords = 1;
              ud.tree = field_tree;
              ud.offset_delta = 0;
              wmem_list_foreach(camd->fields, display_cif_field_cb, &ud);
            }
          }
        }

      }
      /* Parse the indicator fields iteratively building up a list of value fields to parse */
      wmem_queue_t *field_list = wmem_list_new(pinfo->pool); /* (vrt_cif_enable_descript_t *) */
      if((payload_format == vrt_payload_cif) || (payload_format == vrt_payload_cif_field)) {
        gint words_in_cif = dissect_cif(tvb, pinfo, cif_tree, class_descript->cif_list, offset, field_list, vrt_payload_cif);
        offset += 4*words_in_cif; nwords -= words_in_cif;
      }

      wmem_queue_t *warn_list = wmem_list_new(pinfo->pool); /* (vrt_cif_enable_descript_t *) */
      if((payload_format == vrt_payload_warn) || (payload_format == vrt_payload_warn_err)) {
        gint words_in_cif = dissect_cif(tvb, pinfo, cif_tree, class_descript->cif_list, offset, warn_list, vrt_payload_warn);
        offset += 4*words_in_cif; nwords -= words_in_cif;
      }

      wmem_queue_t *err_list = wmem_list_new(pinfo->pool); /* (vrt_cif_enable_descript_t *) */
      if((payload_format == vrt_payload_warn_err) || (payload_format == vrt_payload_err)) {
        gint words_in_cif = dissect_cif(tvb, pinfo, cif_tree, class_descript->cif_list, offset, err_list, vrt_payload_err);
        offset += 4*words_in_cif; nwords -= words_in_cif;
      }
  
      if(payload_format == vrt_payload_cif_field) {
        /* Now if fields have values, loop over each */
        while(wmem_queue_count(field_list) > 0) {
          vrt_cif_enable_descript_t *en = wmem_queue_pop(field_list);
          /* add the subtree then walk the fields parsing and adding each one */
          ti = proto_tree_add_item(cif_tree, en->tree_pid, tvb, offset, -1, ENC_NA);
          proto_tree *field_tree = proto_item_add_subtree(ti, en->ett_pid);

          if(en->info != NULL) {
            proto_tree_add_expert_format(field_tree, pinfo, en->info->ei, tvb, offset, 4, "%s", (en->info->text ? en->info->text : ""));
          }
          /* It feels complicated to have to pass all this info to a callback, but there doesn't
             appear to be another way to walk the tree in the API? */
          vrt_cif_field_display_cb_data_t ud;
          ud.pinfo = pinfo;
          ud.tvb = tvb;
          ud.offset = offset;
          ud.nwords = nwords;
          ud.tree = field_tree;
          ud.offset_delta = 0;
          wmem_list_foreach(en->fields, display_cif_field_cb, &ud);
          /* field size aligned to next word boundary */
          gint words_in_field = (ud.offset_delta + 3) / 4;
          proto_item_set_len(ti, words_in_field*4);
          offset += 4 * words_in_field; nwords -= words_in_field;
        }
      }
      else
      {
        /* without payload to parse, only start a field subtree if it has static information */
        while(wmem_queue_count(field_list) > 0) {
          vrt_cif_enable_descript_t *en = wmem_queue_pop(field_list);
          if(en->info != NULL) {
            ti = proto_tree_add_item(cif_tree, en->tree_pid, tvb, offset, 0, ENC_NA);
            proto_tree *field_tree = proto_item_add_subtree(ti, en->ett_pid);
            proto_tree_add_expert_format(field_tree, pinfo, en->info->ei, tvb, offset, 4, "%s", (en->info->text ? en->info->text : ""));
          }
        }
      }
      wmem_destroy_queue(field_list);
        
      /* Loop over the warning and error lists, ignoring the mapping in the tree using
         the warn/err bit map for the class instead */
      while(wmem_queue_count(warn_list) > 0) {
        vrt_cif_enable_descript_t *en = wmem_queue_pop(warn_list);
        /* add the subtree then walk the fields parsing and adding each one;
            top of subtree has full word including unmapped bits displayed */
        ti = proto_tree_add_item(cif_tree, en->warn_tree_pid, tvb, offset, 4, ENC_NA);
        proto_tree *field_tree = proto_item_add_subtree(ti, en->warn_ett_pid);
        display_warn_err_mask(tvb, field_tree, offset, en->warn_tree_array);
        offset += 4; nwords -= 1;
      }
      wmem_destroy_queue(warn_list);
        
      while(wmem_queue_count(err_list) > 0) {
        vrt_cif_enable_descript_t *en = wmem_queue_pop(err_list);
        /* add the subtree then walk the fields parsing and adding each one;
            top of subtree has full word including unmapped bits displayed */
        ti = proto_tree_add_item(cif_tree, en->err_tree_pid, tvb, offset, 4, ENC_NA);
        proto_tree *field_tree = proto_item_add_subtree(ti, en->err_ett_pid);
        display_warn_err_mask(tvb, field_tree, offset, en->err_tree_array);
        offset += 4; nwords -= 1;
      }
      wmem_destroy_queue(err_list);

      /* dump any remaining payload */
      display_unparsed_payload(cif_tree, pinfo, tvb, offset, nwords);
    }

    return tvb_captured_length(tvb);
}

void proto_register_vrt_cif(void)
{
  proto_vrt_cif = proto_register_protocol ("VITA 49 radio transport protocol context fields", "VITA 49 CIF", "vrt_cif");
  register_dissector("vrt_cif", dissect_vrt_cif, proto_vrt_cif);

  /* We'll do the field registration later, after the configuration file has been parsed */
  proto_register_prefix("vrt_cif", load_and_register_hf_fields);

  /* Group the settings for the subdissector with its parent */
  module_t* cif_subtree = prefs_register_protocol_subtree("VITA 49", proto_vrt_cif, apply_prefs);
  prefs_register_filename_preference(cif_subtree, "cif_filename", 
     "CIF description filename",
     "File describing the format of [Extended] Context Indicator Fields. (may need to restart application)", 
     (const char **) &pref_filename, FALSE);
  prefs_register_bool_preference(cif_subtree, "unknown_class_default", 
     "Fallback to default configuration",
     "If parsed class code has no explicit configuration, use the default configuration instead", 
     &pref_class_fallback);

  register_init_routine( init_dissector );
  register_cleanup_routine( cleanup_dissector );
  register_shutdown_routine( shutdown_dissector );

  // the is_enabled field in the protocol set to 0, so it does not get called as expected....
}

void
proto_reg_handoff_vrt_cif(void)
{
  //dissector_handle_t vrt_handle;
  //vrt_handle = create_dissector_handle(dissect_vrt_cif, proto_vrt_cif);
  create_dissector_handle(dissect_vrt_cif, proto_vrt_cif);
    /* This dissector is explicitly called, so no protocol to register */
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
