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

#define WSQLITE_WRITE_THRESHOLD 200000
#define WSQLITE_CACHE_SIZE 800*1024*1024
#define WSQLITE_PAGE_SIZE 4096

#define WSQLITE_DEBUG 1

typedef struct {
  sqlite3* wsqlite_database;
  epan_dissect_t* epan_dissect;
  GPtrArray* command_queue;
  GHashTable* seen_fields;
  gint64* last_buffer_id;
  gint64* last_dissection_details_id;
} wsqlite_write_packet_callback_args_t;

typedef struct {
    GPtrArray* command_queue;
    GHashTable* seen_fields;    
    gint64* parent_id;
    gint64* buffer_id;
    gint64* last_dissection_details_id;
} wsqlite_get_tree_node_sql_callback_args_t;

WS_DLL_PUBLIC sqlite3* wsqlite_database_open(const gchar* file_name);

WS_DLL_PUBLIC gboolean wsqlite_database_close(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_set_cache_size(sqlite3* wsqlite_database, guint64 cache_size);

WS_DLL_PUBLIC gboolean wsqlite_database_enable_performance_mode(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_create_tables(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_clear_tables(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_database_create_indexes(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_write_packet_dissection(sqlite3* wsqlite_database, epan_dissect_t* epan_dissect, GHashTable* seen_fields, guint64* last_buffer_id, gint64* last_dissection_details_id);

WS_DLL_PUBLIC gboolean wsqlite_write_field_types(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_execute_command(sqlite3* wsqlite_database, gchar* command);

WS_DLL_PUBLIC gboolean wsqlite_execute_command_transaction(sqlite3* wsqlite_database, gchar* command, gboolean use_transaction);

WS_DLL_PUBLIC gboolean wsqlite_debug_log_command(sqlite3* wsqlite_database, gchar* command);

WS_DLL_PUBLIC gboolean wsqlite_database_vacuum(sqlite3* wsqlite_database);

WS_DLL_PUBLIC gboolean wsqlite_commit_command_queue(sqlite3* wsqlite_database, GPtrArray* command_queue);

WS_DLL_PUBLIC gchar* wsqlite_get_create_tables_sql();

WS_DLL_PUBLIC gchar* wsqlite_get_clear_tables_sql();

WS_DLL_PUBLIC gchar* wsqlite_get_create_indexes_sql();

WS_DLL_PUBLIC gchar* wsqlite_get_field_types_sql();

WS_DLL_PUBLIC gchar* wsqlite_get_field_sql(header_field_info* header_field_info);

WS_DLL_PUBLIC gchar* wsqlite_get_packet_dissection_sql(epan_dissect_t* epan_dissect, GHashTable* seen_fields, gint64* last_buffer_id, gint64* last_dissection_details_id);

WS_DLL_PUBLIC gboolean wsqlite_add_packet_dissection_sql_to_command_queue(epan_dissect_t* epan_dissect, GPtrArray* command_queue, GHashTable* seen_fields, gint64* last_buffer_id, gint64* last_dissection_details_id);

WS_DLL_PUBLIC void wsqlite_add_tree_node_sql_to_command_queue(proto_node* node, gpointer data);

WS_DLL_PUBLIC gchar* wsqlite_join_strings_from_queue(GPtrArray* command_queue);

WS_DLL_PUBLIC gchar* wsqlite_repair_string(gchar* string);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* wsqlite.h */
