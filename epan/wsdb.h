/* wsdb.h
 * Routines and types for wsdb (Wireshark Database).
 *
 * Developer Alexander <dev@alex-mails.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSDB_H__
#define __WSDB_H__

#include <glib.h>

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/epan_dissect.h>

#include "ws_symbol_export.h"

#include "sqlite/sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define WSDB_COMMIT_THRESHOLD 10000
#define WSDB_DEFAULT_CACHE_SIZE 150*1024*1024
#define WSDB_DEFAULT_PAGE_SIZE 4096

#define WSDB_FORMAT_VERSION_MAJOR 1
#define WSDB_FORMAT_VERSION_MINOR 0

typedef enum _wsdb_command_type
{
  WSDB_CT_PACKET,
  WSDB_CT_BUFFER,
  WSDB_CT_FIELD,
  WSDB_CT_TREE
} wsdb_command_type_t;

typedef struct _wsdb_packet_data
{
  guint32 id;
  gdouble timestamp;
  guint32 length;
  guint32 interface_id;
  gchar* source;
  gchar* destination;
  gchar* info;
  gchar* protocol;

} wsdb_packet_data_t;

typedef struct _wsdb_buffer_data
{
  guint32 id;
  guint32 packet_id;
  gchar* buffer;
  guint32 length;

} wsdb_buffer_data_t;

typedef struct _wsdb_field_data
{
  guint32 id;
  gchar* name;
  gchar* display_name;
  guint32 field_type_id;

} wsdb_field_data_t;

typedef struct _wsdb_tree_data
{
  guint32 id;
  guint32 parent_id;
  guint32 field_id;
  guint32 packet_id;
  guint32 buffer_id;
  guint32 position;
  guint32 length;
  guint type;
  gint64 integer_value;
  gdouble double_value;
  gchar* string_value;
  gchar* representation;

} wsdb_tree_data_t;

typedef struct _wsdb_command
{
  wsdb_command_type_t command_type;
  union
  {
    void* data;
    wsdb_packet_data_t* packet_data;
    wsdb_buffer_data_t* buffer_data;
    wsdb_field_data_t* field_data;
    wsdb_tree_data_t* tree_data;
  } data;

} wsdb_command_t;

typedef struct _wsdb_id_collection
{
  guint32 parent_id;
  guint32 tree_id;
  guint32 buffer_id;
  GHashTable* seen_buffer_ids;
  GHashTable* seen_field_ids;

} wsdb_id_collection_t;

typedef struct _wsdb_sql_statements
{
    sqlite3_stmt* begin_transaction_statement;
    sqlite3_stmt* commit_transaction_statement;
    sqlite3_stmt* insert_string_statement;
    sqlite3_stmt* insert_packet_statement;
    sqlite3_stmt* insert_buffer_statement;
    sqlite3_stmt* insert_field_statement;
    sqlite3_stmt* insert_tree_statement;

} wsdb_sql_statements_t;

typedef struct _wsdb_queue
{
  GArray* collect_queue;
  GArray* commit_queue;
  GMutex lock;

} wsdb_queue_t;

typedef struct _wsdb_thread_item
{
    sqlite3* database;
    wsdb_queue_t queue;
    wsdb_id_collection_t ids;
    wsdb_sql_statements_t sql_statements;
    GThread* commit_thread;
    volatile gboolean cancel_thread;

} wsdb_thread_item_t;

typedef struct _wsdb_callback_args_t
{
  guint32 current_index;
  guint32 parallel_count;
  epan_dissect_t* epan_dissect;
  wsdb_thread_item_t* thread_items;

} wsdb_callback_args_t;


WS_DLL_PUBLIC gboolean wsdb_init_callback_args(wsdb_callback_args_t* callback_args, guint32 parallel_count, gchar* base_file_path);

WS_DLL_PUBLIC void wsdb_cleanup_callback_args(wsdb_callback_args_t* callback_args);

WS_DLL_PUBLIC void wsdb_cleanup_database(sqlite3* database, wsdb_sql_statements_t* sql_statements);

WS_DLL_PUBLIC void wsdb_cleanup_queue(GArray** queue_pointer);

WS_DLL_PUBLIC sqlite3* wsdb_database_open(const gchar* file_name);

WS_DLL_PUBLIC gboolean wsdb_database_close(sqlite3* database);

WS_DLL_PUBLIC gboolean wsdb_database_set_cache_size(sqlite3* database, guint64 cache_size);

WS_DLL_PUBLIC gboolean wsdb_database_enable_performance_mode(sqlite3* database);

WS_DLL_PUBLIC gboolean wsdb_database_create_tables(sqlite3* database);

WS_DLL_PUBLIC gboolean wsdb_database_clear_tables(sqlite3* database);

WS_DLL_PUBLIC gboolean wsdb_database_create_indexes(sqlite3* database);

WS_DLL_PUBLIC gboolean wsdb_write_field_types(sqlite3* database);

WS_DLL_PUBLIC gboolean wsdb_write_info(sqlite3* database, gint32 parallel_count, guint32 index);

WS_DLL_PUBLIC gboolean wsdb_execute_command(sqlite3* database, gchar* command);

WS_DLL_PUBLIC gboolean wsdb_execute_command_transaction(sqlite3* database, gchar* command, gboolean use_transaction);

WS_DLL_PUBLIC gboolean wsdb_commit_queue(wsdb_thread_item_t* thread_item, guint32 threshold, gboolean wait);

WS_DLL_PUBLIC void* wsdb_commit_thread_function(void* data);

WS_DLL_PUBLIC gboolean wsdb_add_packet_dissection_sql_to_queue(wsdb_callback_args_t* callback_args);

WS_DLL_PUBLIC void wsdb_add_tree_node_sql_to_queue(proto_node* node, gpointer data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* wsdb.h */
