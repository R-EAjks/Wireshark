/* wsdb.c
 * Routines for wsdb (Wireshark Database).
 *
 * Developer Alexander <dev@alex-mails.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/wsdb.h>

gboolean
wsdb_init_callback_args(wsdb_callback_args_t* callback_args, guint32 parallel_count, gchar* base_file_path)
{
    if(callback_args == NULL)
    {
        return FALSE;
    }
    // At least 1 commit thread is required
    if(parallel_count == 0)
    {
        parallel_count = 1;
    }

    callback_args->parallel_count = parallel_count;
    callback_args->epan_dissect = g_malloc0(sizeof(epan_dissect_t));
    callback_args->thread_items = g_malloc0_n((gsize)parallel_count, sizeof(wsdb_thread_item_t));

    for(guint32 i = 0; i < parallel_count; i++)
    {
        gchar* file_path = g_strdup(base_file_path);
        gchar* file_extension_start = g_strrstr(file_path, ".wsdb");
        if (file_extension_start != NULL)
        {
            file_extension_start[0] = '\0';
        }

        gchar* new_file_path = parallel_count > 1 ? g_strdup_printf("%s_%u.wsdb", file_path, i) : g_strdup_printf("%s.wsdb", file_path);
        g_free(file_path);
        file_path = new_file_path;

        callback_args->thread_items[i].database = wsdb_database_open(file_path);
        g_free(file_path);

        if(callback_args->thread_items[i].database == NULL)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        int return_code = 0;

        const gchar* begin_transaction_command = "BEGIN TRANSACTION;";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, begin_transaction_command, -1, &callback_args->thread_items[i].sql_statements.begin_transaction_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* commit_transaction_command = "COMMIT TRANSACTION;";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, commit_transaction_command, -1, &callback_args->thread_items[i].sql_statements.commit_transaction_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_string_command = "INSERT OR IGNORE INTO string(string) VALUES (?);";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_string_command, -1, &callback_args->thread_items[i].sql_statements.insert_string_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_packet_command = "INSERT INTO packet(id, timestamp, length, interface_id, source_string_id, destination_string_id, info_string_id, protocol_string_id) VALUES (?, ?, ?, ?, (SELECT id FROM string WHERE string = ?), (SELECT id FROM string WHERE string = ?), (SELECT id FROM string WHERE string = ?), (SELECT id FROM string WHERE string = ?));";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_packet_command, -1, &callback_args->thread_items[i].sql_statements.insert_packet_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_buffer_command = "INSERT INTO buffer(id, packet_id, buffer) VALUES (?, ?, ?);";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_buffer_command, -1, &callback_args->thread_items[i].sql_statements.insert_buffer_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_field_command = "INSERT OR IGNORE INTO field(id, name, display_name, field_type_id) VALUES (?, ?, ?, ?);";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_field_command, -1, &callback_args->thread_items[i].sql_statements.insert_field_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        const gchar* insert_tree_command = "INSERT INTO tree(id, parent_id, field_id, packet_id, buffer_id, position, length, double_value, integer_value, string_value_string_id, representation_string_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT id FROM string WHERE string = ?), (SELECT id FROM string WHERE string = ?));";
        return_code = sqlite3_prepare_v2(callback_args->thread_items[i].database, insert_tree_command, -1, &callback_args->thread_items[i].sql_statements.insert_tree_statement, NULL);
        if (return_code != SQLITE_OK)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }

        // A preallocated queue 20% bigger than WSDB_COMMIT_THRESHOLD reduces the probability of a resize of the queue
        guint32 reserved_queue_size = (guint32)(1.2 * (double)WSDB_COMMIT_THRESHOLD);
        callback_args->thread_items[i].queue.collect_queue = g_array_sized_new(FALSE, FALSE, sizeof(wsdb_command_t), reserved_queue_size);
        callback_args->thread_items[i].queue.commit_queue = NULL;

        g_mutex_init(&callback_args->thread_items[i].queue.lock);

        callback_args->thread_items[i].ids.seen_buffer_ids = g_hash_table_new(g_direct_hash, g_direct_equal);
        callback_args->thread_items[i].ids.seen_field_ids = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    for (guint32 i = 0; i < parallel_count; i++)
    {
        callback_args->thread_items[i].cancel_thread = FALSE;
        callback_args->thread_items[i].commit_thread = g_thread_new("Commit Thread", wsdb_commit_thread_function, (void*)&(callback_args->thread_items[i]));

        if (callback_args->thread_items[i].commit_thread == NULL)
        {
            wsdb_cleanup_callback_args(callback_args);
            return FALSE;
        }
    }

    return TRUE;
}

void
wsdb_cleanup_callback_args(wsdb_callback_args_t* callback_args)
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
        wsdb_cleanup_database(callback_args->thread_items[i].database, &callback_args->thread_items[i].sql_statements);

        wsdb_cleanup_queue(&callback_args->thread_items[i].queue.collect_queue);
        g_mutex_lock(&callback_args->thread_items[i].queue.lock);
        wsdb_cleanup_queue(&callback_args->thread_items[i].queue.commit_queue);
        g_mutex_unlock(&callback_args->thread_items[i].queue.lock);

        g_mutex_clear(&callback_args->thread_items[i].queue.lock);

        g_hash_table_destroy(callback_args->thread_items[i].ids.seen_buffer_ids);
        g_hash_table_destroy(callback_args->thread_items[i].ids.seen_field_ids);
    }

    g_free(callback_args->epan_dissect);
    g_free(callback_args->thread_items);

    return;
}

void wsdb_cleanup_database(sqlite3* database, wsdb_sql_statements_t* sql_statements)
{
    if (sql_statements != NULL)
    {
        sqlite3_finalize(sql_statements->begin_transaction_statement);
        sqlite3_finalize(sql_statements->commit_transaction_statement);
        sqlite3_finalize(sql_statements->insert_string_statement);
        sqlite3_finalize(sql_statements->insert_packet_statement);
        sqlite3_finalize(sql_statements->insert_buffer_statement);
        sqlite3_finalize(sql_statements->insert_field_statement);
        sqlite3_finalize(sql_statements->insert_tree_statement);
    }

    if (database != NULL)
    {
        wsdb_database_close(database);
    }
}

void wsdb_cleanup_queue(GArray** queue_pointer)
{
    if(queue_pointer == NULL)
    {
        return;
    }

    GArray* queue = queue_pointer[0];

    if(queue == NULL)
    {
        return;
    }

    for(guint32 i = 0; i < queue->len; i++)
    {
        wsdb_command_t command = g_array_index(queue, wsdb_command_t, i);
        if(command.data.data == NULL)
        {
            continue;
        }

        if (command.command_type == WSDB_CT_PACKET)
        {
            g_free(command.data.packet_data->source);
            g_free(command.data.packet_data->destination);
            g_free(command.data.packet_data->info);
            g_free(command.data.packet_data->protocol);
        }
        if(command.command_type == WSDB_CT_BUFFER)
        {
            g_free(command.data.buffer_data->buffer);
        }
        else if (command.command_type == WSDB_CT_FIELD)
        {
            g_free(command.data.field_data->name);
            g_free(command.data.field_data->display_name);
        }
        else if(command.command_type == WSDB_CT_TREE)
        {
            g_free(command.data.tree_data->string_value);
            g_free(command.data.tree_data->representation);
        }

        g_free(command.data.data);
    }

    g_array_free(queue, TRUE);

    queue_pointer[0] = NULL;

    return;
}

sqlite3*
wsdb_database_open(const gchar* file_name)
{
    sqlite3* database;
    int return_code = 0;

    return_code = sqlite3_open(file_name, &database);

    if (return_code != SQLITE_OK)
    {
        sqlite3_close(database);

        return NULL;
    }

    gboolean wsdb_result = wsdb_database_create_tables(database);

    if (wsdb_result == FALSE)
    {
        sqlite3_close(database);

        return NULL;
    }

    return database;
}

gboolean
wsdb_database_close(sqlite3* database)
{
    if (database == NULL)
    {
        return FALSE;
    }

    int return_code = sqlite3_close(database);

    if (return_code != SQLITE_OK)
    {
        return FALSE;
    }

    return TRUE;
}

gboolean
wsdb_database_set_cache_size(sqlite3* database, guint64 cache_size)
{
    if (database == NULL)
    {
        return FALSE;
    }

    guint64 cache_size_in_pages = cache_size / WSDB_DEFAULT_PAGE_SIZE;

    gchar* command = NULL;
    command = g_strdup_printf("PRAGMA page_size = %u; PRAGMA cache_size = %lu;", WSDB_DEFAULT_PAGE_SIZE, cache_size_in_pages);

    gboolean wsdb_result = wsdb_execute_command(database, command);

    g_free(command);

    return wsdb_result;
}


gboolean
wsdb_database_enable_performance_mode(sqlite3* database)
{
    if (database == NULL)
    {
        return FALSE;
    }

    gchar* command = "PRAGMA journal_mode = OFF;"
                    "PRAGMA synchronous = OFF;"
                    "PRAGMA auto_vacuum = NONE;";

    gboolean wsdb_result = wsdb_execute_command_transaction(database, command, FALSE);

    if (wsdb_result == FALSE)
    {
        return FALSE;
    }

    return TRUE;
}

gboolean
wsdb_database_create_tables(sqlite3* database)
{
    if(database == NULL)
    {
        return FALSE;
    }

    gboolean wsdb_result = wsdb_database_clear_tables(database);

    if(wsdb_result == FALSE)
    {
        return FALSE;
    }

    gchar* command =
        "CREATE TABLE IF NOT EXISTS string(id INTEGER PRIMARY KEY AUTOINCREMENT, string TEXT UNIQUE);"
        "CREATE TABLE IF NOT EXISTS info(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS packet(id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, length INTEGER NOT NULL, interface_id INTEGER, source_string_id INTEGER, destination_string_id INTEGER, info_string_id INTEGER, protocol_string_id INTEGER, FOREIGN KEY(source_string_id) REFERENCES string(id), FOREIGN KEY(destination_string_id) REFERENCES string(id), FOREIGN KEY(info_string_id) REFERENCES string(id), FOREIGN KEY(protocol_string_id) REFERENCES string(id)) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS buffer(id INTEGER PRIMARY KEY, packet_id INTEGER NOT NULL, buffer BLOB, FOREIGN KEY(packet_id) REFERENCES packet(id)) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS packet_comment(id INTEGER PRIMARY KEY AUTOINCREMENT, packet_id INTEGER NOT NULL, comment TEXT, FOREIGN KEY(packet_id) REFERENCES packet(id));"
        "CREATE TABLE IF NOT EXISTS field_type(id INTEGER PRIMARY KEY, type TEXT UNIQUE) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS field(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, field_type_id INTEGER NOT NULL, FOREIGN KEY(field_type_id) REFERENCES field_type(id)) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS tree(id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, field_id INTEGER NOT NULL, packet_id INTEGER NOT NULL, buffer_id INTEGER, position INTEGER NOT NULL, length INTEGER NOT NULL, double_value DOUBLE, integer_value INTEGER, string_value_string_id INTEGER, representation_string_id INTEGER, FOREIGN KEY(parent_id) REFERENCES tree(id), FOREIGN KEY(field_id) REFERENCES field(id), FOREIGN KEY(packet_id) REFERENCES packet(id), FOREIGN KEY(buffer_id) REFERENCES buffer(id), FOREIGN KEY(string_value_string_id) REFERENCES string(id), FOREIGN KEY(representation_string_id) REFERENCES string(id)) WITHOUT ROWID;"
        ;

    wsdb_result = wsdb_execute_command(database, command);

    return wsdb_result;
}

gboolean
wsdb_database_clear_tables(sqlite3* database)
{
    if(database == NULL)
    {
        return FALSE;
    }

    gchar* command =
        "DROP INDEX IF EXISTS packet_timestamp_idx;"
        "DROP INDEX IF EXISTS buffer_packet_id_idx;"
        "DROP INDEX IF EXISTS tree_parent_id_idx;"
        "DROP INDEX IF EXISTS tree_packet_id_idx;"
        "DROP INDEX IF EXISTS tree_numeric_value_idx;"
        "DROP INDEX IF EXISTS tree_string_value_id_idx;"

        "DROP TABLE IF EXISTS tree;"
        "DROP TABLE IF EXISTS field;"
        "DROP TABLE IF EXISTS field_type;"
        "DROP TABLE IF EXISTS packet_comment;"
        "DROP TABLE IF EXISTS buffer;"
        "DROP TABLE IF EXISTS packet;"
        "DROP TABLE IF EXISTS info;"
        "DROP TABLE IF EXISTS string;"
        ;

    gboolean wsdb_result = wsdb_execute_command(database, command);

    return wsdb_result;
}

gboolean
wsdb_database_create_indexes(sqlite3* database)
{
    if(database == NULL)
    {
        return FALSE;
    }

    gchar* command =
        "CREATE INDEX IF NOT EXISTS packet_timestamp_idx ON packet(timestamp);"
        "CREATE INDEX IF NOT EXISTS buffer_packet_id_idx ON buffer(packet_id);"
        "CREATE INDEX IF NOT EXISTS tree_parent_id_idx ON tree(parent_id);"
        "CREATE INDEX IF NOT EXISTS tree_packet_id_idx ON tree(packet_id);"
        "CREATE INDEX IF NOT EXISTS tree_numeric_value_idx ON tree(field_id, double_value, integer_value);"
        "CREATE INDEX IF NOT EXISTS tree_string_value_id_idx ON tree(field_id, string_value_string_id);"
        ;

    gboolean wsdb_result = wsdb_execute_command(database, command);

    return wsdb_result;
}

gboolean
wsdb_write_field_types(sqlite3* database)
{
    if(database == NULL)
    {
        return FALSE;
    }

    for (gint i = 0; i < FT_NUM_TYPES; i++)
    {
        gint32 field_type_id = i;
        const gchar* field_type = ftype_name(i);

        gchar* command = g_strdup_printf("INSERT INTO field_type(id, type) VALUES "
            "(%u, \"%s\");", field_type_id, field_type);

        gboolean wsdb_result = wsdb_execute_command(database, command);
        if(wsdb_result == FALSE)
        {
            g_free(command);
            return FALSE;
        }

        g_free(command);
    }

    return TRUE;
}

gboolean
wsdb_write_info(sqlite3* database, gint32 parallel_count, guint32 index)
{
    if (database == NULL)
    {
        return FALSE;
    }

    gchar* command = NULL;
    command = g_strdup_printf("INSERT INTO info (key, value) VALUES "
        "('parallel_count', '%u'), ('index', '%u'), "
        "('wsdb_format_version_major', '%u'), ('wsdb_format_version_minor', '%u'), "
        "('generator', 'Wireshark');", parallel_count, index, WSDB_FORMAT_VERSION_MAJOR, WSDB_FORMAT_VERSION_MINOR);

    gboolean wsdb_result = wsdb_execute_command_transaction(database, command, FALSE);

    g_free(command);

    return wsdb_result;
}

gboolean
wsdb_execute_command(sqlite3* database, gchar* command)
{
    return wsdb_execute_command_transaction(database, command, TRUE);
}

gboolean
wsdb_execute_command_transaction(sqlite3* database, gchar* command, gboolean use_transaction)
{
    int sqlite_return_code = 0;
    char* error_message = NULL;

    if (use_transaction == TRUE)
    {
        sqlite_return_code = sqlite3_exec(database, "BEGIN TRANSACTION;", 0, 0, &error_message);

        if (sqlite_return_code != SQLITE_OK)
        {
            sqlite3_free(error_message);
            return FALSE;
        }
    }

    sqlite_return_code = sqlite3_exec(database, command, 0, 0, &error_message);

    if (sqlite_return_code != SQLITE_OK)
    {
        sqlite3_free(error_message);
        if (use_transaction == TRUE)
        {
            sqlite3_exec(database, "COMMIT TRANSACTION;", 0, 0, NULL);
        }
        return FALSE;
    }

    if (use_transaction == TRUE)
    {
        sqlite_return_code = sqlite3_exec(database, "COMMIT TRANSACTION;", 0, 0, &error_message);

        if (sqlite_return_code != SQLITE_OK)
        {
            sqlite3_free(error_message);
            return FALSE;
        }
    }

    return TRUE;
}

gboolean
wsdb_commit_queue(wsdb_thread_item_t* thread_item, guint32 threshold, gboolean wait)
{
    if(thread_item == NULL)
    {
        return FALSE;
    }

    if (thread_item->queue.collect_queue->len >= threshold)
    {
        // Wait until commit queue gets available
        while (wait == TRUE)
        {
            g_mutex_lock(&thread_item->queue.lock);
            if (thread_item->queue.commit_queue == NULL)
            {
                g_mutex_unlock(&thread_item->queue.lock);
                break;
            }
            g_mutex_unlock(&thread_item->queue.lock);
        }

        g_mutex_lock(&thread_item->queue.lock);
        if (thread_item->queue.commit_queue == NULL)
        {
            thread_item->queue.commit_queue = thread_item->queue.collect_queue;
            // A preallocated queue 20% bigger than WSDB_COMMIT_THRESHOLD reduces the probability of a resize of the queue
            guint32 reserved_queue_size = (guint32)(1.2 * (double)WSDB_COMMIT_THRESHOLD);
            thread_item->queue.collect_queue = g_array_sized_new(FALSE, FALSE, sizeof(wsdb_command_t), reserved_queue_size);

            g_mutex_unlock(&thread_item->queue.lock);
        }
        else
        {
            g_mutex_unlock(&thread_item->queue.lock);
        }
    }

    return TRUE;
}

void*
wsdb_commit_thread_function(void* data)
{
    wsdb_thread_item_t* thread_item = (wsdb_thread_item_t*)data;

    while (thread_item->cancel_thread == FALSE)
    {
        g_mutex_lock(&thread_item->queue.lock);
        if (thread_item->queue.commit_queue == NULL)
        {
            g_mutex_unlock(&thread_item->queue.lock);
            continue;
        }
        else
        {
            g_mutex_unlock(&thread_item->queue.lock);
        }

        int return_code = 0;

        return_code = sqlite3_reset(thread_item->sql_statements.begin_transaction_statement);
        if (return_code != SQLITE_OK)
        {
            continue;
        }

        return_code = sqlite3_step(thread_item->sql_statements.begin_transaction_statement);
        if (return_code != SQLITE_DONE)
        {
            continue;
        }

        for (guint32 i = 0; i < thread_item->queue.commit_queue->len; i++)
        {
            wsdb_command_t command = g_array_index(thread_item->queue.commit_queue, wsdb_command_t, i);
            if (command.data.data == NULL)
            {
                continue;
            }

            if (command.command_type == WSDB_CT_PACKET)
            {
                sqlite3_stmt* insert_string_statement = thread_item->sql_statements.insert_string_statement;

                return_code = sqlite3_reset(insert_string_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.packet_data->source, -1, SQLITE_STATIC);
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

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.packet_data->destination, -1, SQLITE_STATIC);
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

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.packet_data->info, -1, SQLITE_STATIC);
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

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.packet_data->protocol, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_string_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }

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

                return_code = sqlite3_bind_int64(insert_packet_statement, 4, (sqlite3_int64)command.data.packet_data->interface_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_packet_statement, 5, command.data.packet_data->source, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_packet_statement, 6, command.data.packet_data->destination, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_packet_statement, 7, command.data.packet_data->info, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_packet_statement, 8, command.data.packet_data->protocol, -1, SQLITE_STATIC);
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
            else if (command.command_type == WSDB_CT_BUFFER)
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
            else if (command.command_type == WSDB_CT_FIELD)
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
            else if (command.command_type == WSDB_CT_TREE)
            {
                sqlite3_stmt* insert_string_statement = thread_item->sql_statements.insert_string_statement;

                return_code = sqlite3_reset(insert_string_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.tree_data->string_value, -1, SQLITE_STATIC);
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

                return_code = sqlite3_bind_text(insert_string_statement, 1, command.data.tree_data->representation, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_string_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }

                sqlite3_stmt* insert_tree_statement = thread_item->sql_statements.insert_tree_statement;

                return_code = sqlite3_reset(insert_tree_statement);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 1, (sqlite3_int64)command.data.tree_data->id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 2, (sqlite3_int64)command.data.tree_data->parent_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 3, (sqlite3_int64)command.data.tree_data->field_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 4, (sqlite3_int64)command.data.tree_data->packet_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 5, (sqlite3_int64)command.data.tree_data->buffer_id);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 6, (sqlite3_int64)command.data.tree_data->position);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 7, (sqlite3_int64)command.data.tree_data->length);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_double(insert_tree_statement, 8, (double)command.data.tree_data->double_value);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_int64(insert_tree_statement, 9, (sqlite3_int64)command.data.tree_data->integer_value);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_tree_statement, 10, command.data.tree_data->string_value, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_bind_text(insert_tree_statement, 11, command.data.tree_data->representation, -1, SQLITE_STATIC);
                if (return_code != SQLITE_OK)
                {
                    continue;
                }

                return_code = sqlite3_step(insert_tree_statement);
                if (return_code != SQLITE_DONE)
                {
                    continue;
                }
            }
        }

        return_code = sqlite3_reset(thread_item->sql_statements.commit_transaction_statement);
        if (return_code != SQLITE_OK)
        {
            continue;
        }

        return_code = sqlite3_step(thread_item->sql_statements.commit_transaction_statement);
        if (return_code != SQLITE_DONE)
        {
            continue;
        }

        g_mutex_lock(&thread_item->queue.lock);

        wsdb_cleanup_queue(&thread_item->queue.commit_queue);

        g_mutex_unlock(&thread_item->queue.lock);
    }

    // Make sure that everything is written to disk

    sqlite3_db_cacheflush(thread_item->database);

    g_thread_exit(NULL);
    return NULL;
}

gboolean
wsdb_add_packet_dissection_sql_to_queue(wsdb_callback_args_t* callback_args)
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

    wsdb_thread_item_t* current_thread_item = NULL;

    while (TRUE)
    {
        // Make the next queue the active one
        callback_args->current_index = (callback_args->current_index + 1) % callback_args->parallel_count;

        current_thread_item = &callback_args->thread_items[callback_args->current_index];

        // There is space in the queue
        if (current_thread_item->queue.collect_queue->len < WSDB_COMMIT_THRESHOLD)
        {
            break;
        }
        else
        {
            // Try to commit the queue but do not wait
            gboolean wsdb_result = wsdb_commit_queue(current_thread_item, WSDB_COMMIT_THRESHOLD, FALSE);
            if (wsdb_result == FALSE)
            {
                return FALSE;
            }
        }
    }

    current_thread_item = &callback_args->thread_items[callback_args->current_index];

    // Build packet command
    wsdb_packet_data_t* packet_data = g_malloc(sizeof(wsdb_packet_data_t));
    packet_data->id = epan_dissect->pi.num;
    packet_data->timestamp = (gdouble)epan_dissect->pi.abs_ts.secs + (gdouble)epan_dissect->pi.abs_ts.nsecs / 1000000000.0;
    packet_data->length = epan_dissect->pi.fd->pkt_len;
    packet_data->interface_id = (epan_dissect->pi.rec->presence_flags & WTAP_HAS_INTERFACE_ID) ? (guint32)epan_dissect->pi.rec->rec_header.packet_header.interface_id : 0;

    packet_data->source = g_strdup(col_get_text(epan_dissect->pi.cinfo, COL_DEF_SRC));
    packet_data->destination = g_strdup(col_get_text(epan_dissect->pi.cinfo, COL_DEF_DST));
    packet_data->info = g_strdup(col_get_text(epan_dissect->pi.cinfo, COL_INFO));
    packet_data->protocol = g_strdup(col_get_text(epan_dissect->pi.cinfo, COL_PROTOCOL));

    wsdb_command_t packet_command;
    packet_command.command_type = WSDB_CT_PACKET;
    packet_command.data.packet_data = packet_data;

    g_array_append_val(current_thread_item->queue.collect_queue, packet_command);

    if(epan_dissect->tree == NULL)
    {
        return TRUE;
    }

    g_hash_table_remove_all(current_thread_item->ids.seen_buffer_ids);

    // Build tree commands
    proto_tree_children_foreach(epan_dissect->tree, wsdb_add_tree_node_sql_to_queue, callback_args);

    return TRUE;
}

void
wsdb_add_tree_node_sql_to_queue(proto_node* node, gpointer data)
{
    if (data == NULL)
    {
        return;
    }

    wsdb_callback_args_t* callback_args = (wsdb_callback_args_t*)data;

    if (callback_args->thread_items == NULL)
    {
        return;
    }

    wsdb_thread_item_t* current_thread_item = &callback_args->thread_items[callback_args->current_index];

    header_field_info* current_header_field_info = node->finfo->hfinfo;

    gboolean field_is_seen = g_hash_table_contains(current_thread_item->ids.seen_field_ids, GINT_TO_POINTER(current_header_field_info->id));

    if (field_is_seen == FALSE)
    {
        // Build field command
        wsdb_field_data_t* field_data = g_malloc(sizeof(wsdb_field_data_t));
        field_data->id = current_header_field_info->id;
        field_data->name = g_strdup(current_header_field_info->abbrev);
        field_data->display_name = g_strdup(current_header_field_info->name);
        field_data->field_type_id = (guint32)current_header_field_info->type;

        wsdb_command_t field_command;
        field_command.command_type = WSDB_CT_FIELD;
        field_command.data.field_data = field_data;

        g_array_append_val(current_thread_item->queue.collect_queue, field_command);

        g_hash_table_add(current_thread_item->ids.seen_field_ids, GUINT_TO_POINTER(current_header_field_info->id));
    }

    tvbuff_t* current_buffer = node->finfo->ds_tvb;
    guint32 buffer_id = 0;

    gboolean buffer_is_seen = g_hash_table_contains(current_thread_item->ids.seen_buffer_ids, current_buffer);

    if (buffer_is_seen == FALSE && current_buffer != NULL)
    {
        // Build buffer command
        wsdb_buffer_data_t* buffer_data = g_malloc(sizeof(wsdb_buffer_data_t));

        // Get the next buffer id
        current_thread_item->ids.buffer_id++;

        buffer_id = current_thread_item->ids.buffer_id;
        buffer_data->id = current_thread_item->ids.buffer_id;

        buffer_data->packet_id = node->tree_data->pinfo->num;
        buffer_data->length = tvb_captured_length(current_buffer);
        buffer_data->buffer = g_malloc(buffer_data->length);

        for (guint32 i = 0; i < buffer_data->length; i++)
        {
            buffer_data->buffer[i] = tvb_get_guint8(current_buffer, i);
        }

        wsdb_command_t buffer_command;
        buffer_command.command_type = WSDB_CT_BUFFER;
        buffer_command.data.buffer_data = buffer_data;

        g_array_append_val(current_thread_item->queue.collect_queue, buffer_command);

        g_hash_table_insert(current_thread_item->ids.seen_buffer_ids, current_buffer, GUINT_TO_POINTER(buffer_data->id));
    }
    else
    {
        buffer_id = GPOINTER_TO_UINT(g_hash_table_lookup(current_thread_item->ids.seen_buffer_ids, current_buffer));
    }

    // Build dissection details command
    wsdb_tree_data_t* tree_data = g_malloc0(sizeof(wsdb_tree_data_t));

    // Get the next dissection details id
    current_thread_item->ids.tree_id++;

    tree_data->id = current_thread_item->ids.tree_id;
    tree_data->parent_id = current_thread_item->ids.parent_id;
    tree_data->field_id = current_header_field_info->id;
    tree_data->packet_id = node->tree_data->pinfo->num;
    tree_data->buffer_id = buffer_id;
    tree_data->type = (guint32)current_header_field_info->type;
    if(node->finfo->rep->representation != NULL)
    {
        tree_data->representation = g_strdup(node->finfo->rep->representation);
    }
    tree_data->position = (guint32)node->finfo->start;
    tree_data->length = (guint32)node->finfo->length;

    if(current_header_field_info->type == FT_INT8
        || current_header_field_info->type == FT_INT16
        || current_header_field_info->type == FT_INT24
        || current_header_field_info->type == FT_INT32)
    {
        gint32 value = fvalue_get_sinteger(&node->finfo->value);
        tree_data->integer_value = (gint64)value;
    }
    else if (current_header_field_info->type == FT_CHAR
        || current_header_field_info->type == FT_UINT8
        || current_header_field_info->type == FT_UINT16
        || current_header_field_info->type == FT_UINT24
        || current_header_field_info->type == FT_UINT32
        || current_header_field_info->type == FT_FRAMENUM
        || current_header_field_info->type == FT_IPv4)
    {
        guint32 value = fvalue_get_uinteger(&node->finfo->value);
        tree_data->integer_value = (gint64)value;
    }
    else if (current_header_field_info->type == FT_INT40
        || current_header_field_info->type == FT_INT48
        || current_header_field_info->type == FT_INT56
        || current_header_field_info->type == FT_INT64)
    {
        gint64 value = fvalue_get_sinteger64(&node->finfo->value);
        tree_data->integer_value = value;
    }
    else if(current_header_field_info->type == FT_UINT40
        || current_header_field_info->type == FT_UINT48
        || current_header_field_info->type == FT_UINT56
        || current_header_field_info->type == FT_UINT64
        || current_header_field_info->type == FT_EUI64)
    {
        guint64 value = fvalue_get_uinteger64(&node->finfo->value);
        gdouble msb = (value & 0x8000000000000000) > 0 ? 1.0 : 0.0;
        value = value & 0x7FFFFFFFFFFFFFFF;

        tree_data->integer_value = (gint64)value;
        tree_data->double_value = msb;
    }
    else if (current_header_field_info->type == FT_FLOAT
        || current_header_field_info->type == FT_DOUBLE)
    {
        gdouble value = fvalue_get_floating(&node->finfo->value);
        tree_data->double_value = value;
    }
    else if(current_header_field_info->type == FT_BOOLEAN)
    {
        gint64 value = fvalue_get_uinteger64(&node->finfo->value);
        tree_data->integer_value = (gint64)value;
    }
    else if(current_header_field_info->type == FT_STRING
        || current_header_field_info->type == FT_STRINGZ
        || current_header_field_info->type == FT_STRINGZPAD
        || current_header_field_info->type == FT_STRINGZTRUNC)
    {
        gchar* value = g_strdup(node->finfo->value.value.string);
        tree_data->string_value = value;
    }
    else if(current_header_field_info->type == FT_BYTES
        || current_header_field_info->type == FT_ETHER
        || current_header_field_info->type == FT_IPv6)
    {
        guint32 buffer_length = 0;
        guint8* data_pointer = NULL;

        if (current_header_field_info->type == FT_BYTES
            || current_header_field_info->type == FT_ETHER)
        {
            buffer_length = (guint32)node->finfo->value.value.bytes->len;
            data_pointer = node->finfo->value.value.bytes->data;
        }
        else if(current_header_field_info->type == FT_IPv6)
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

        tree_data->string_value = value;
    }
    else if (current_header_field_info->type == FT_PROTOCOL)
    {
        gchar* value = g_strdup(node->finfo->value.value.protocol.proto_string);
        tree_data->string_value = value;
    }
    else if (current_header_field_info->type == FT_ABSOLUTE_TIME
        || current_header_field_info->type == FT_RELATIVE_TIME)
    {
        gdouble value = (gdouble)node->finfo->value.value.time.secs + (gdouble)node->finfo->value.value.time.nsecs / 1000000000.0;
        tree_data->double_value = value;
    }
    else if (current_header_field_info->type == FT_GUID)
    {
        e_guid_t guid = node->finfo->value.value.guid;
        gchar* value = g_strdup_printf("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
            guid.data1, guid.data2, guid.data3,
            guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
            guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]);

        tree_data->string_value = value;
    }
    else // FT_NONE and some others
    {
        // Nothing to do at the moment
    }

    wsdb_command_t tree_command;
    tree_command.command_type = WSDB_CT_TREE;
    tree_command.data.tree_data = tree_data;
    g_array_append_val(current_thread_item->queue.collect_queue, tree_command);

    // Preserve previous parent id
    guint32 last_parent_id = current_thread_item->ids.parent_id;
    current_thread_item->ids.parent_id = current_thread_item->ids.tree_id;

    proto_tree_children_foreach(node, wsdb_add_tree_node_sql_to_queue, callback_args);

    current_thread_item->ids.parent_id = last_parent_id;
}
