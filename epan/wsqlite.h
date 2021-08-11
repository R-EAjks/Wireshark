/* print.h
 * Definitions for printing packet analysis trees.
 *
 * Developer Alexander <dev@alex-mails.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSQLITE_H__
#define __WSQLITE_H__

#include <glib.h>

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/epan_dissect.h>

#include "ws_symbol_export.h"

#include "sqlite/sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define WSQLITE_PARALLEL_COUNT 31
#define WSQLITE_COMMIT_THRESHOLD 50000
#define WSQLITE_CACHE_SIZE 100*1024*1024
#define WSQLITE_PAGE_SIZE 4096

typedef enum
{
  WSQLITE_CT_PACKET,
  WSQLITE_CT_BUFFER,
  WSQLITE_CT_FIELD,
  WSQLITE_CT_DISSECTION_DETAILS
} wsqlite_command_type_t;

typedef struct
{
  guint32 id;
  gdouble timestamp;
  guint32 length;
  guint32 captured_length;
  guint32 interface_id;

} wsqlite_packet_data_t;

typedef struct
{
  guint32 id;
  guint32 packet_id;
  gchar* buffer;
  guint32 length;

} wsqlite_buffer_data_t;

typedef struct
{
  guint32 id;
  gchar* name;
  gchar* display_name;
  guint32 field_type_id;

} wsqlite_field_data_t;

typedef struct
{
  guint32 id;
  guint32 parent_id;
  guint32 field_id;
  guint32 buffer_id;
  guint32 position;
  guint32 length;
  enum ftypes type;
  gint64 integer_value;
  gdouble double_value;
  gchar* string_value;
  gchar* representation;

} wsqlite_dissection_details_data_t;

typedef struct
{
  wsqlite_command_type_t command_type;
  union
  {
    void* data;
    wsqlite_packet_data_t* packet_data;
    wsqlite_buffer_data_t* buffer_data;
    wsqlite_field_data_t* field_data;
    wsqlite_dissection_details_data_t* dissection_details_data;
  } data;

} wsqlite_command_t;

typedef struct
{
  guint32 buffer_id;
  guint32 parent_id;
  guint32 dissection_details_id;
  GHashTable* seen_field_ids;

} wsqlite_id_collection_t;

typedef struct
{
    sqlite3_stmt* insert_string_statement;
    sqlite3_stmt* insert_packet_statement;
    sqlite3_stmt* insert_buffer_statement;
    sqlite3_stmt* insert_field_statement;
    sqlite3_stmt* insert_dissection_details_statement;

} wsqlite_sql_statements_t;

typedef struct
{
  GArray* collect_queue;
  GArray* commit_queue;
  GMutex lock;
  volatile gboolean commit_is_busy;

} wsqlite_command_queue_t;

typedef struct
{
    sqlite3* database;
    wsqlite_command_queue_t command_queue;
    wsqlite_id_collection_t ids;
    wsqlite_sql_statements_t sql_statements;
    GThread* commit_thread;
    gboolean cancel_thread;

} wsqlite_thread_item_t;

typedef struct
{
  guint32 current_index;
  guint32 parallel_count;
  epan_dissect_t* epan_dissect;
  wsqlite_thread_item_t* thread_items;

} wsqlite_callback_args_t;


WS_DLL_PUBLIC gboolean wsqlite_init_callback_args(wsqlite_callback_args_t* callback_args, guint32 parallel_count, gchar* base_file_path);

WS_DLL_PUBLIC void wsqlite_cleanup_callback_args(wsqlite_callback_args_t* callback_args);

WS_DLL_PUBLIC void wsqlite_cleanup_queue(GArray* queue);

WS_DLL_PUBLIC sqlite3* wsqlite_database_open(const gchar* file_name);

WS_DLL_PUBLIC gboolean wsqlite_database_close(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_set_cache_size(sqlite3* wsqlite_database, guint64 cache_size);

WS_DLL_PUBLIC gboolean wsqlite_database_enable_performance_mode(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_create_tables(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_clear_tables(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_create_indexes(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_vacuum(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_write_field_types(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_execute_command(sqlite3* wsqlite_database, gchar* command);

WS_DLL_PUBLIC gboolean wsqlite_execute_command_transaction(sqlite3* wsqlite_database, gchar* command, gboolean use_transaction);

WS_DLL_PUBLIC gboolean wsqlite_commit_command_queue(wsqlite_thread_item_t* thread_item, guint32 threshold, gboolean wait);

WS_DLL_PUBLIC void* wsqlite_commit_thread_function(void* data);

WS_DLL_PUBLIC gchar* wsqlite_get_create_tables_sql();

WS_DLL_PUBLIC gchar* wsqlite_get_clear_tables_sql();

WS_DLL_PUBLIC gchar* wsqlite_get_create_indexes_sql();

WS_DLL_PUBLIC gchar* wsqlite_get_field_types_sql();

WS_DLL_PUBLIC gboolean wsqlite_add_packet_dissection_sql_to_command_queue(wsqlite_callback_args_t* callback_args);

WS_DLL_PUBLIC void wsqlite_add_tree_node_sql_to_command_queue(proto_node* node, gpointer data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* wsqlite.h */
