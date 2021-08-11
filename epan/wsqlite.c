/* wsqlite.c
 * Routines for Wireshark SQLite (wsqlite) files.
 *
 * Developer Alexander <dev@alex-mails.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/wsqlite.h>

gboolean
wsqlite_init_callback_args(wsqlite_callback_args_t* callback_args, guint32 parallel_count, gchar* base_file_path)
{
    if(callback_args == NULL)
    {
        return FALSE;
    }
    // At least 1 thread is required
    if(parallel_count == 0)
    {
        parallel_count = 1;
    }

    callback_args->parallel_count = parallel_count;
    callback_args->epan_dissect = g_malloc0(sizeof(epan_dissect_t));
    callback_args->thread_items = g_malloc0_n((gsize)parallel_count, sizeof(wsqlite_thread_item_t));

    for(guint32 i = 0; i < parallel_count; i++)
    {
        gchar* file_path = g_strdup_printf("%s_%u.wsqlite", base_file_path, i);
        callback_args->thread_items[i].database = wsqlite_database_open(file_path);
        g_free(file_path);

        if(callback_args->thread_items[i].database == NULL)
        {
            wsqlite_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_string_command = "INSERT OR IGNORE INTO strings(string) VALUES (?);";
        int return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_string_command, -1, &callback_args->thread_items[i].sql_statements.insert_string_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsqlite_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_packet_command = "INSERT INTO packets(id, timestamp, length, captured_length, interface_id) VALUES (?, ?, ?, ?, ?);";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_packet_command, -1, &callback_args->thread_items[i].sql_statements.insert_packet_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsqlite_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_buffer_command = "INSERT INTO buffers(id, packet_id, buffer) VALUES (?, ?, ?);";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_buffer_command, -1, &callback_args->thread_items[i].sql_statements.insert_buffer_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsqlite_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_field_command = "INSERT OR IGNORE INTO fields(id, name, display_name, field_type_id) VALUES (?, ?, ?, ?);";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_field_command, -1, &callback_args->thread_items[i].sql_statements.insert_field_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsqlite_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_dissection_details_command = "INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, integer_value, double_value, string_value_id, representation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, (SELECT id FROM strings WHERE string = ?), (SELECT id FROM strings WHERE string = ?));";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_dissection_details_command, -1, &callback_args->thread_items[i].sql_statements.insert_dissection_details_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsqlite_cleanup_callback_args(callback_args);
            return FALSE;
        }

        callback_args->thread_items[i].command_queue.collect_queue = g_array_new(FALSE, FALSE, sizeof(wsqlite_command_t));
        callback_args->thread_items[i].command_queue.commit_queue = g_array_new(FALSE, FALSE, sizeof(wsqlite_command_t));

        
        g_mutex_init(&callback_args->thread_items[i].command_queue.lock);
        callback_args->thread_items[i].command_queue.commit_is_busy = TRUE;        

        callback_args->thread_items[i].ids.seen_field_ids = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    for (guint32 i = 0; i < parallel_count; i++)
    {
        callback_args->thread_items[i].cancel_thread = FALSE;
        callback_args->thread_items[i].commit_thread = g_thread_new("Commit Thread", wsqlite_commit_thread_function, (void*)&(callback_args->thread_items[i]));

        if (callback_args->thread_items[i].commit_thread == NULL)
        {
            wsqlite_cleanup_callback_args(callback_args);
            return FALSE;
        }
    }

    return TRUE;
}

void
wsqlite_cleanup_callback_args(wsqlite_callback_args_t* callback_args)
{
    if(callback_args == NULL)
    {
        return;
    }

    for (guint32 i = 0; i < callback_args->parallel_count; i++)
    {
        callback_args->thread_items[i].cancel_thread = TRUE;
    }    

    for(guint32 i = 0; i < callback_args->parallel_count; i++)
    {
        sqlite3_finalize(callback_args->thread_items[i].sql_statements.insert_string_statement);
        sqlite3_finalize(callback_args->thread_items[i].sql_statements.insert_packet_statement);
        sqlite3_finalize(callback_args->thread_items[i].sql_statements.insert_buffer_statement);
        sqlite3_finalize(callback_args->thread_items[i].sql_statements.insert_field_statement);
        sqlite3_finalize(callback_args->thread_items[i].sql_statements.insert_dissection_details_statement);

        if (callback_args->thread_items[i].database != NULL)
        {
            wsqlite_database_close(callback_args->thread_items[i].database);
        }

        wsqlite_cleanup_queue(callback_args->thread_items[i].command_queue.collect_queue);
        wsqlite_cleanup_queue(callback_args->thread_items[i].command_queue.commit_queue);

        g_mutex_clear(&callback_args->thread_items[i].command_queue.lock);

        g_hash_table_destroy(callback_args->thread_items[i].ids.seen_field_ids);
    }

    g_free(callback_args->epan_dissect);
    g_free(callback_args->thread_items);

    return;
}

void wsqlite_cleanup_queue(GArray* queue)
{
    if(queue == NULL)
    {
        return;
    }

    for(guint32 i = 0; i < queue->len; i++)
    {
        wsqlite_command_t command = g_array_index(queue, wsqlite_command_t, i);
        if(command.data.data == NULL)
        {
            continue;
        }
        
        if(command.command_type == WSQLITE_CT_BUFFER)
        {
            g_free(command.data.buffer_data->buffer);
        }
        else if (command.command_type == WSQLITE_CT_FIELD)
        {
            g_free(command.data.field_data->name);
            g_free(command.data.field_data->display_name);
        }
        else if(command.command_type == WSQLITE_CT_DISSECTION_DETAILS)
        {
            g_free(command.data.dissection_details_data->string_value);
            g_free(command.data.dissection_details_data->representation);
        }

        g_free(command.data.data);
    }

    g_array_free(queue, TRUE);

    return;
}

sqlite3*
wsqlite_database_open(const gchar* file_name)
{
    sqlite3* wsqlite_database;
    int return_code = 0;

    return_code = sqlite3_open(file_name, &wsqlite_database);

    if (return_code != SQLITE_OK)
    {
        sqlite3_close(wsqlite_database);

        return NULL;
    }

    gboolean wsqlite_result = wsqlite_database_create_tables(wsqlite_database);

    if (wsqlite_result == FALSE)
    {
        sqlite3_close(wsqlite_database);

        return NULL;
    }

    return wsqlite_database;
}

gboolean
wsqlite_database_close(sqlite3* wsqlite_database)
{
    if (wsqlite_database == NULL)
    {
        return FALSE;
    }

    int return_code = sqlite3_close(wsqlite_database);

    if (return_code != SQLITE_OK)
    {
        return FALSE;
    }

    return TRUE;
}

gboolean
wsqlite_database_set_cache_size(sqlite3* wsqlite_database, guint64 cache_size)
{
    if (wsqlite_database == NULL)
    {
        return FALSE;
    }

    guint64 cache_size_in_pages = cache_size / WSQLITE_PAGE_SIZE;

    gchar* command = NULL;
    command = g_strdup_printf("PRAGMA page_size = %u; PRAGMA cache_size = %u;", WSQLITE_PAGE_SIZE, cache_size_in_pages);

    gboolean wsqlite_result = wsqlite_execute_command(wsqlite_database, command);
    
    if (wsqlite_result == FALSE)
    {
        g_free(command);
        return FALSE;
    }

    g_free(command);

    return TRUE;
}


gboolean
wsqlite_database_enable_performance_mode(sqlite3* wsqlite_database)
{
    if (wsqlite_database == NULL)
    {
        return FALSE;
    }

    gchar* command = "PRAGMA journal_mode = OFF;"
                    "PRAGMA synchronous = OFF;"
                    "PRAGMA auto_vacuum = NONE;";

    gboolean wsqlite_result = wsqlite_execute_command_transaction(wsqlite_database, command, FALSE);
    
    if (wsqlite_result == FALSE)
    {
        return FALSE;
    }

    return TRUE;
}

gboolean
wsqlite_database_create_tables(sqlite3* wsqlite_database)
{
    if(wsqlite_database == NULL)
    {
        return FALSE;
    }

    gboolean wsqlite_result = wsqlite_database_clear_tables(wsqlite_database);

    if(wsqlite_result == FALSE)
    {
        return FALSE;
    }

    gchar* command = wsqlite_get_create_tables_sql();

    wsqlite_result = wsqlite_execute_command(wsqlite_database, command);

    return wsqlite_result;
}

gboolean
wsqlite_database_clear_tables(sqlite3* wsqlite_database)
{
    if(wsqlite_database == NULL)
    {
        return FALSE;
    }

    gchar* command = wsqlite_get_clear_tables_sql();

    gboolean wsqlite_result = wsqlite_execute_command(wsqlite_database, command);

    return wsqlite_result;
}

gboolean
wsqlite_database_create_indexes(sqlite3* wsqlite_database)
{
    if(wsqlite_database == NULL)
    {
        return FALSE;
    }

    gchar* command = wsqlite_get_create_indexes_sql();

    gboolean wsqlite_result = wsqlite_execute_command(wsqlite_database, command);

    return wsqlite_result;
}

gboolean
wsqlite_database_vacuum(sqlite3* wsqlite_database)
{
    int sqlite_return_code = 0;
    char* error_message = NULL;

    gchar* command = "VACUUM;";

    sqlite_return_code = sqlite3_exec(wsqlite_database, command, 0, 0, &error_message);

    if (sqlite_return_code != SQLITE_OK)
    {
        sqlite3_free(error_message);
        return FALSE;
    }

    return TRUE;
}

gboolean
wsqlite_write_field_types(sqlite3* wsqlite_database)
{
    if(wsqlite_database == NULL)
    {
        return FALSE;
    }

    gchar* command = wsqlite_get_field_types_sql();

    gboolean wsqlite_result = wsqlite_execute_command(wsqlite_database, command);

    return wsqlite_result;
}

gboolean
wsqlite_execute_command(sqlite3* wsqlite_database, gchar* command)
{
    return wsqlite_execute_command_transaction(wsqlite_database, command, TRUE);
}

gboolean
wsqlite_execute_command_transaction(sqlite3* wsqlite_database, gchar* command, gboolean use_transaction)
{
    int sqlite_return_code = 0;
    char* error_message = NULL;

    if (use_transaction == TRUE)
    {
        sqlite_return_code = sqlite3_exec(wsqlite_database, "BEGIN TRANSACTION;", 0, 0, &error_message);

        if (sqlite_return_code != SQLITE_OK)
        {
            sqlite3_free(error_message);
            return FALSE;
        }
    }

    sqlite_return_code = sqlite3_exec(wsqlite_database, command, 0, 0, &error_message);

    if (sqlite_return_code != SQLITE_OK)
    {
        sqlite3_free(error_message);
        if (use_transaction == TRUE)
        {
            sqlite3_exec(wsqlite_database, "COMMIT TRANSACTION;", 0, 0, NULL);
        }        
        return FALSE;
    }

    if (use_transaction == TRUE)
    {
        sqlite_return_code = sqlite3_exec(wsqlite_database, "COMMIT TRANSACTION;", 0, 0, &error_message);

        if (sqlite_return_code != SQLITE_OK)
        {
            sqlite3_free(error_message);
            return FALSE;
        }
    }    

    return TRUE;
}

gboolean
wsqlite_commit_command_queue(wsqlite_thread_item_t* thread_item, guint32 threshold, gboolean wait)
{
    if(thread_item == NULL)
    {
        return FALSE;
    }

    if (thread_item->command_queue.collect_queue->len >= threshold)
    {
        // Wait until commit queue get available
        while (wait == TRUE && thread_item->command_queue.commit_is_busy == TRUE) { }

        if (thread_item->command_queue.commit_is_busy == FALSE)
        {
            g_mutex_lock(&thread_item->command_queue.lock);

            GArray* temp = thread_item->command_queue.commit_queue;
            thread_item->command_queue.commit_queue = thread_item->command_queue.collect_queue;
            thread_item->command_queue.collect_queue = temp;

            thread_item->command_queue.commit_is_busy = TRUE;

            g_mutex_unlock(&thread_item->command_queue.lock);
        }
    }

    return TRUE;
}

void*
wsqlite_commit_thread_function(void* data)
{
    wsqlite_thread_item_t* thread_item = (wsqlite_thread_item_t*)data;

    while (thread_item->cancel_thread == FALSE)
    {
        if (thread_item->command_queue.commit_is_busy == FALSE)
        {
            continue;
        }

        int return_code = 0;

        return_code = sqlite3_exec(thread_item->database, "BEGIN TRANSACTION;", 0, 0, NULL);

        if (return_code != SQLITE_OK)
        {
            return FALSE;
        }

        for (guint32 i = 0; i < thread_item->command_queue.commit_queue->len; i++)
        {
            wsqlite_command_t command = g_array_index(thread_item->command_queue.commit_queue, wsqlite_command_t, i);
            if (command.data.data == NULL)
            {
                continue;
            }

            if (command.command_type == WSQLITE_CT_PACKET)
            {
                sqlite3_stmt* insert_packet_statement = thread_item->sql_statements.insert_packet_statement;

                return_code = sqlite3_reset(insert_packet_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }
                
                return_code = sqlite3_bind_int64(insert_packet_statement, 1, (sqlite3_int64)command.data.packet_data->id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_double(insert_packet_statement, 2, (double)command.data.packet_data->timestamp);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_packet_statement, 3, (sqlite3_int64)command.data.packet_data->length);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_packet_statement, 4, (sqlite3_int64)command.data.packet_data->captured_length);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_packet_statement, 5, (sqlite3_int64)command.data.packet_data->interface_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_packet_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }
            }
            else if (command.command_type == WSQLITE_CT_BUFFER)
            {
                sqlite3_stmt* insert_buffer_statement = thread_item->sql_statements.insert_buffer_statement;                

                return_code = sqlite3_reset(insert_buffer_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_buffer_statement, 1, (sqlite3_int64)command.data.buffer_data->id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_buffer_statement, 2, (sqlite3_int64)command.data.buffer_data->packet_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_blob64(insert_buffer_statement, 3, command.data.buffer_data->buffer, (sqlite3_int64)command.data.buffer_data->length, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_buffer_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }
            }
            else if (command.command_type == WSQLITE_CT_FIELD)
            {
                sqlite3_stmt* insert_field_statement = thread_item->sql_statements.insert_field_statement;                

                return_code = sqlite3_reset(insert_field_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_field_statement, 1, (sqlite3_int64)command.data.field_data->id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_field_statement, 2, command.data.field_data->name, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_field_statement, 3, command.data.field_data->display_name, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_field_statement, 4, (sqlite3_int64)command.data.field_data->field_type_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_field_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }
            }
            else if (command.command_type == WSQLITE_CT_DISSECTION_DETAILS)
            {
                sqlite3_stmt* insert_string_statement = thread_item->sql_statements.insert_string_statement;                

                return_code = sqlite3_reset(insert_string_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.dissection_details_data->string_value, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_string_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }

                return_code = sqlite3_reset(insert_string_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.dissection_details_data->representation, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_string_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }

                sqlite3_stmt* insert_dissection_details_statement = thread_item->sql_statements.insert_dissection_details_statement;

                return_code = sqlite3_reset(insert_dissection_details_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_dissection_details_statement, 1, (sqlite3_int64)command.data.dissection_details_data->id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_dissection_details_statement, 2, (sqlite3_int64)command.data.dissection_details_data->parent_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_dissection_details_statement, 3, (sqlite3_int64)command.data.dissection_details_data->field_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_dissection_details_statement, 4, (sqlite3_int64)command.data.dissection_details_data->buffer_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_dissection_details_statement, 5, (sqlite3_int64)command.data.dissection_details_data->position);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_dissection_details_statement, 6, (sqlite3_int64)command.data.dissection_details_data->length);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_dissection_details_statement, 7, (sqlite3_int64)command.data.dissection_details_data->integer_value);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_double(insert_dissection_details_statement, 8, (double)command.data.dissection_details_data->double_value);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_dissection_details_statement, 9, command.data.dissection_details_data->string_value, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_dissection_details_statement, 10, command.data.dissection_details_data->representation, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_dissection_details_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }
            }
        }

        return_code = sqlite3_exec(thread_item->database, "COMMIT TRANSACTION;", 0, 0, NULL);

        if (return_code != SQLITE_OK)
        {
            return FALSE;
        }

        wsqlite_cleanup_queue(thread_item->command_queue.commit_queue);
        thread_item->command_queue.commit_queue = g_array_new(FALSE, FALSE, sizeof(wsqlite_command_t));

        g_mutex_lock(&thread_item->command_queue.lock);
        thread_item->command_queue.commit_is_busy = FALSE;
        g_mutex_unlock(&thread_item->command_queue.lock);
    }

    g_thread_exit(NULL);
    return NULL;
}

gchar*
wsqlite_get_create_tables_sql()
{
    gchar* command =
        "CREATE TABLE IF NOT EXISTS debug(id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS strings(id INTEGER PRIMARY KEY AUTOINCREMENT, string TEXT UNIQUE);"
        "CREATE TABLE IF NOT EXISTS info(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS packets(id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, length INTEGER NOT NULL, captured_length INTEGER NOT NULL, interface_id INTEGER)  WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS buffers(id INTEGER PRIMARY KEY AUTOINCREMENT, packet_id INTEGER NOT NULL, buffer BLOB NOT NULL, FOREIGN KEY(packet_id) REFERENCES packets(id));"
        "CREATE TABLE IF NOT EXISTS packet_comments(id INTEGER PRIMARY KEY AUTOINCREMENT, packet_id INTEGER NOT NULL, comment TEXT, FOREIGN KEY(packet_id) REFERENCES packets(id));"
        "CREATE TABLE IF NOT EXISTS field_types(id INTEGER PRIMARY KEY, type TEXT UNIQUE) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS fields(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, field_type_id INTEGER NOT NULL, FOREIGN KEY(field_type_id) REFERENCES field_types(id)) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS dissection_details(id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, field_id INTEGER NOT NULL, buffer_id INTEGER, position INTEGER NOT NULL, length INTEGER NOT NULL, integer_value INTEGER, double_value DOUBLE, string_value_id INTEGER, representation_id INTEGER, FOREIGN KEY(parent_id) REFERENCES dissection_details(id), FOREIGN KEY(field_id) REFERENCES fields(id), FOREIGN KEY(buffer_id) REFERENCES buffers(id), FOREIGN KEY(string_value_id) REFERENCES strings(id), FOREIGN KEY(representation_id) REFERENCES strings(id)) WITHOUT ROWID;"
        ;
    
    return command;
}

gchar*
wsqlite_get_clear_tables_sql()
{
    gchar* command =
        "DROP INDEX IF EXISTS packets_timestamp_idx;"
        "DROP INDEX IF EXISTS dissection_details_parent_id_idx;"
        "DROP INDEX IF EXISTS dissection_details_numeric_value_idx;"
        "DROP INDEX IF EXISTS dissection_details_string_value_id_idx;"

        "DROP TABLE IF EXISTS dissection_details;"
        "DROP TABLE IF EXISTS fields;"
        "DROP TABLE IF EXISTS field_types;"
        "DROP TABLE IF EXISTS packet_comments;"
        "DROP TABLE IF EXISTS buffers;"
        "DROP TABLE IF EXISTS packets;"
        "DROP TABLE IF EXISTS info;"
        "DROP TABLE IF EXISTS strings;"
        "DROP TABLE IF EXISTS debug;"
        ;

    return command;
}

gchar*
wsqlite_get_create_indexes_sql()
{
    gchar* command =
        "CREATE INDEX IF NOT EXISTS packets_timestamp_idx ON packets(timestamp);"
        "CREATE INDEX IF NOT EXISTS dissection_details_parent_id_idx ON dissection_details(parent_id);"
        "CREATE INDEX IF NOT EXISTS dissection_details_numeric_value_idx ON dissection_details(field_id, integer_value, double_value);"
        "CREATE INDEX IF NOT EXISTS dissection_details_string_value_id_idx ON dissection_details(field_id, string_value_id);"
        ;
    
    return command;
}

gchar*
wsqlite_get_field_types_sql()
{
    gchar* result = g_strdup("");

    for (gint i = 0; i < FT_NUM_TYPES; i++)
    {
        gint field_type_id = i;
        const gchar* field_type = ft_strings[i];

        gchar* new_result = g_strdup_printf("%s\nINSERT INTO field_types(id, type) VALUES "
            "(%i, \"%s\");", result, field_type_id, field_type);

        g_free(result);
        result = new_result;
    }
    return result;
}

gboolean
wsqlite_add_packet_dissection_sql_to_command_queue(wsqlite_callback_args_t* callback_args)
{    
    if(callback_args->epan_dissect == NULL)
    {
        return FALSE;
    }

    epan_dissect_t* epan_dissect = callback_args->epan_dissect;

    if(epan_dissect->tvb == NULL)
    {
        return FALSE;
    }

    if(callback_args->thread_items == NULL)
    {
        return FALSE;
    }

    wsqlite_thread_item_t* current_thread_item = NULL;

    while (TRUE)
    {
        // Make the next queue the active one
        callback_args->current_index = (callback_args->current_index + 1) % callback_args->parallel_count;

        current_thread_item = &callback_args->thread_items[callback_args->current_index];

        // There is space in the queue
        if (current_thread_item->command_queue.collect_queue->len < WSQLITE_COMMIT_THRESHOLD)
        {
            break;
        }
        // We can commit the queue
        else if(current_thread_item->command_queue.commit_is_busy == FALSE)
        {
            gboolean wsqlite_result = wsqlite_commit_command_queue(current_thread_item, WSQLITE_COMMIT_THRESHOLD, FALSE);
            if (wsqlite_result == FALSE)
            {
                return FALSE;
            }
        }
    }

    current_thread_item = &callback_args->thread_items[callback_args->current_index];

    // Build packet command
    wsqlite_packet_data_t* packet_data = g_malloc(sizeof(wsqlite_packet_data_t));
    packet_data->id = epan_dissect->pi.num;
    packet_data->timestamp = (gdouble)epan_dissect->pi.abs_ts.secs + (gdouble)epan_dissect->pi.abs_ts.nsecs / 1000000000.0;
    packet_data->length = epan_dissect->pi.fd->pkt_len;
    packet_data->captured_length = tvb_captured_length(epan_dissect->tvb);
    packet_data->interface_id = (epan_dissect->pi.rec->presence_flags & WTAP_HAS_INTERFACE_ID) ? (guint32)epan_dissect->pi.rec->rec_header.packet_header.interface_id : 0;

    wsqlite_command_t packet_command;
    packet_command.command_type = WSQLITE_CT_PACKET;
    packet_command.data.packet_data = packet_data;

    g_array_append_val(current_thread_item->command_queue.collect_queue, packet_command);

    wsqlite_buffer_data_t* buffer_data = g_malloc(sizeof(wsqlite_buffer_data_t));

    gchar* buffer = g_malloc(packet_data->captured_length);
    for (guint32 i = 0; i < packet_data->captured_length; i++)
    {
        if (!tvb_offset_exists(epan_dissect->tvb, i))
        {
            break;
        }
        buffer[i] = tvb_get_guint8(epan_dissect->tvb, i);
    }

    // Get the next buffer id
    current_thread_item->ids.buffer_id++;

    buffer_data->id = current_thread_item->ids.buffer_id;
    buffer_data->packet_id = packet_data->id;
    buffer_data->buffer = buffer;
    buffer_data->length = packet_data->captured_length;

    wsqlite_command_t buffer_command;
    buffer_command.command_type = WSQLITE_CT_BUFFER;
    buffer_command.data.buffer_data = buffer_data;

    g_array_append_val(current_thread_item->command_queue.collect_queue, buffer_command);

    if(epan_dissect->tree == NULL)
    {
        return TRUE;
    }

    // Build tree commands
    proto_tree_children_foreach(epan_dissect->tree, wsqlite_add_tree_node_sql_to_command_queue, callback_args);

    return TRUE;
}

void
wsqlite_add_tree_node_sql_to_command_queue(proto_node* node, gpointer data)
{
    if (data == NULL)
    {
        return;
    }

    wsqlite_callback_args_t* callback_args = (wsqlite_callback_args_t*)data;

    if (callback_args->thread_items == NULL)
    {
        return;
    }

    wsqlite_thread_item_t* current_thread_item = &callback_args->thread_items[callback_args->current_index];

    header_field_info* header_field_info = node->finfo->hfinfo;
    enum ftypes field_type = header_field_info->type;

    if (current_thread_item->ids.seen_field_ids == NULL)
    {
        return;
    }
    gboolean field_is_seen = g_hash_table_contains(current_thread_item->ids.seen_field_ids, GINT_TO_POINTER(header_field_info->id));

    if (field_is_seen == FALSE)
    {
        // Build field command
        wsqlite_field_data_t* field_data = g_malloc(sizeof(wsqlite_field_data_t));
        field_data->id = header_field_info->id;
        field_data->name = g_strdup((gchar*)header_field_info->abbrev);
        field_data->display_name = g_strdup((gchar*)header_field_info->name);
        field_data->field_type_id = (guint32)field_type;

        wsqlite_command_t field_command;
        field_command.command_type = WSQLITE_CT_FIELD;
        field_command.data.field_data = field_data;

        g_array_append_val(current_thread_item->command_queue.collect_queue, field_command);

        g_hash_table_add(current_thread_item->ids.seen_field_ids, GINT_TO_POINTER(header_field_info->id));
    }    

    // Build dissection details command
    wsqlite_dissection_details_data_t* dissection_details_data = g_malloc0(sizeof(wsqlite_dissection_details_data_t));

    // Get the next dissection details id
    current_thread_item->ids.dissection_details_id++;

    dissection_details_data->id = current_thread_item->ids.dissection_details_id;
    dissection_details_data->field_id = header_field_info->id;
    dissection_details_data->parent_id = current_thread_item->ids.parent_id;
    dissection_details_data->type = field_type;
    if(node->finfo->rep->representation != NULL)
    {
        dissection_details_data->representation = g_strdup(node->finfo->rep->representation);
    }
    dissection_details_data->position = (guint32)node->finfo->start;
    dissection_details_data->length = (guint32)node->finfo->length;

    if(field_type == FT_INT8
        || field_type == FT_INT16
        || field_type == FT_INT24
        || field_type == FT_INT32)
    {
        gint32 value = fvalue_get_sinteger(&node->finfo->value);
        dissection_details_data->integer_value = (gint64)value;        
    }
    else if (field_type == FT_CHAR
        || field_type == FT_UINT8
        || field_type == FT_UINT16
        || field_type == FT_UINT24
        || field_type == FT_UINT32
        || field_type == FT_IPXNET
        || field_type == FT_FRAMENUM
        || field_type == FT_IPv4
        || field_type == FT_IEEE_11073_SFLOAT
        || field_type == FT_IEEE_11073_FLOAT)
    {
        guint32 value = fvalue_get_uinteger(&node->finfo->value);
        dissection_details_data->integer_value = (gint64)value;        
    }
    else if (field_type == FT_INT40
        || field_type == FT_INT48
        || field_type == FT_INT56
        || field_type == FT_INT64)
    {
        gint64 value = fvalue_get_sinteger64(&node->finfo->value);
        dissection_details_data->integer_value = value;
    }    
    else if(field_type == FT_UINT40
        || field_type == FT_UINT48
        || field_type == FT_UINT56
        || field_type == FT_UINT64
        || field_type == FT_BOOLEAN
        || field_type == FT_EUI64)
    {
        guint64 value = fvalue_get_uinteger64(&node->finfo->value);
        gdouble msb = (value & 0x8000000000000000) > 0 ? 1.0 : 0.0;
        value = value & 0x7FFFFFFFFFFFFFFF;

        dissection_details_data->integer_value = (gint64)value;
        dissection_details_data->double_value = msb;
    }
    else if (field_type == FT_FLOAT
        || field_type == FT_DOUBLE)
    {
        gdouble value = fvalue_get_floating(&node->finfo->value);
        dissection_details_data->double_value = value;
    }
    else if(field_type == FT_STRING
        || field_type == FT_STRINGZ
        || field_type == FT_STRINGZPAD
        || field_type == FT_STRINGZTRUNC)
    {
        gchar* value = g_strdup(node->finfo->value.value.string);
        dissection_details_data->string_value = value;
    }
    else if(field_type == FT_BYTES
        || field_type == FT_ETHER
        || field_type == FT_IPv6)
    {
        guint32 buffer_length = 0;
        guint8* data_pointer = NULL;

        if (field_type == FT_BYTES
            || field_type == FT_ETHER)
        {
            buffer_length = (guint32)node->finfo->value.value.bytes->len;
            data_pointer = node->finfo->value.value.bytes->data;
        }
        else if(field_type == FT_IPv6)
        {
            buffer_length = 16;
            data_pointer = node->finfo->value.value.ipv6.addr.bytes;
        }

        gchar* value = g_malloc(buffer_length * 2 + 1);
        for (guint32 i = 0; i < buffer_length; i++)
        {
            guint8 current_byte = data_pointer[i];
            guint8 upper_nibble = (current_byte & 0xF0) >> 4;
            guint8 lower_nibble = current_byte & 0x0F;

            value[2 * i] = upper_nibble >= 0x0A ? upper_nibble + 0x41 - 10 : upper_nibble + 0x30;
            value[2 * i + 1] = lower_nibble >= 0x0A ? lower_nibble + 0x41 - 10 : lower_nibble + 0x30;
        }
        value[buffer_length * 2] = '\0';

        dissection_details_data->string_value = value;
    }
    else if (field_type == FT_PROTOCOL)
    {
        gchar* value = g_strdup(node->finfo->value.value.protocol.proto_string);
        dissection_details_data->string_value = value;
    }
    else if (field_type == FT_ABSOLUTE_TIME
        || field_type == FT_RELATIVE_TIME)
    {
        gdouble value = (gdouble)node->finfo->value.value.time.secs + (gdouble)node->finfo->value.value.time.nsecs / 1000000000.0;
        dissection_details_data->double_value = value;
    }
    else if (field_type == FT_GUID)
    {
        e_guid_t guid = node->finfo->value.value.guid;
        gchar* value = g_strdup_printf("08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
            guid.data1, guid.data2, guid.data3,
            guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
            guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]);

        dissection_details_data->string_value = value;
    }
    else // FT_NONE
    {
        // Nothing to do
    }

    wsqlite_command_t dissection_details_command;
    dissection_details_command.command_type = WSQLITE_CT_DISSECTION_DETAILS;
    dissection_details_command.data.dissection_details_data = dissection_details_data;
    g_array_append_val(current_thread_item->command_queue.collect_queue, dissection_details_command);

    // Preserve previous parent id
    guint32 last_parent_id = current_thread_item->ids.parent_id;
    current_thread_item->ids.parent_id = current_thread_item->ids.dissection_details_id;

    proto_tree_children_foreach(node, wsqlite_add_tree_node_sql_to_command_queue, callback_args);

    current_thread_item->ids.parent_id = last_parent_id;
}
