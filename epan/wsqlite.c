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
wsqlite_write_packet_dissection(sqlite3* wsqlite_database, epan_dissect_t* epan_dissect, GHashTable* seen_fields, guint64* last_buffer_id, gint64* last_dissection_details_id )
{
    if(wsqlite_database == NULL)
    {
        return FALSE;
    }

    gchar* command = wsqlite_get_packet_dissection_sql(epan_dissect, seen_fields, last_buffer_id, last_dissection_details_id);

    gboolean wsqlite_result = wsqlite_execute_command(wsqlite_database, command);

    return wsqlite_result;
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

#ifdef WSQLITE_DEBUG

    gboolean wsqlite_result = wsqlite_debug_log_command(wsqlite_database, command);
    if (wsqlite_result == FALSE)
    {
        return FALSE;
    }

#endif // WSQLITE_DEBUG

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
wsqlite_debug_log_command(sqlite3* wsqlite_database, gchar* command)
{
    int sqlite_return_code = 0;
    char* error_message = NULL;

    gchar** split = g_strsplit(command, "'", -1);
    gchar* filtered_command = g_strjoinv(" ", split);
    g_strfreev(split);

    gchar* debug_command = NULL;
    debug_command = g_strdup_printf("CREATE TABLE IF NOT EXISTS debug(id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT NUT NULL);"
        "INSERT INTO debug(command) VALUES "
        "('%s');", filtered_command);

    g_free(filtered_command);

    sqlite_return_code = sqlite3_exec(wsqlite_database, debug_command, 0, 0, &error_message);

    if (sqlite_return_code != SQLITE_OK)
    {
        g_free(debug_command);
        sqlite3_free(error_message);
        return FALSE;
    }

    g_free(debug_command);


    return TRUE;
}

gboolean
wsqlite_database_vacuum(sqlite3* wsqlite_database)
{
    int sqlite_return_code = 0;
    char* error_message = NULL;

    gchar* command = "VACUUM;";

#ifdef WSQLITE_DEBUG

    gboolean wsqlite_result = wsqlite_debug_log_command(wsqlite_database, command);
    if (wsqlite_result == FALSE)
    {
        return FALSE;
    }

#endif // WSQLITE_DEBUG

    sqlite_return_code = sqlite3_exec(wsqlite_database, command, 0, 0, &error_message);

    if (sqlite_return_code != SQLITE_OK)
    {
        sqlite3_free(error_message);
        return FALSE;
    }

    return TRUE;
}

gboolean
wsqlite_commit_command_queue(sqlite3* wsqlite_database, GPtrArray* command_queue)
{
    if(wsqlite_database == NULL)
    {
        return FALSE;
    }
    if(command_queue == NULL)
    {
        return FALSE;
    }

    guint command_queue_length = g_ptr_array_len(command_queue);

    if(command_queue_length == 0)
    {
        return TRUE;
    }

    gchar* command = wsqlite_join_strings_from_queue(command_queue);

    if(command == NULL)
    {
        return FALSE;
    }

    gboolean wsqlite_result = wsqlite_execute_command(wsqlite_database, command);

    if(wsqlite_result == FALSE)
    {
        g_free(command);
        return FALSE;
    }

    g_free(command);
    
    return TRUE;
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
    GPtrArray* command_queue = g_ptr_array_new();

    for (gint i = 0; i < FT_NUM_TYPES; i++)
    {
        gint field_type_id = i;
        const gchar* field_type = ft_strings[i];

        gchar* field_type_command = NULL;
        field_type_command = g_strdup_printf("INSERT INTO field_types(id, type) VALUES "
            "(%i, \"%s\");", field_type_id, field_type);

        g_ptr_array_add(command_queue, field_type_command);
    }

    gchar* result = wsqlite_join_strings_from_queue(command_queue);

    g_ptr_array_free(command_queue, TRUE);

    return result;
}

gchar*
wsqlite_get_field_sql(header_field_info* header_field_info)
{
    if(header_field_info == NULL)
    {
        return NULL;
    }

    gint id = header_field_info->id;
    const gchar* name = header_field_info->abbrev;

    gchar* display_name = wsqlite_repair_string((gchar*)header_field_info->name);

    gint field_type_id = (gint)header_field_info->type;

    gchar* field_command = NULL;
    field_command = g_strdup_printf("INSERT INTO fields(id, name, display_name, field_type_id) VALUES "
                                    "(%i, \"%s\", \"%s\", %i);", id, name, display_name, field_type_id);
    
    return field_command;
}


gchar*
wsqlite_get_packet_dissection_sql(epan_dissect_t* epan_dissect, GHashTable* seen_fields, gint64* last_buffer_id, gint64* last_dissection_details_id)
{
    if(epan_dissect == NULL)
    {
        return NULL;
    }

    GPtrArray* command_queue = g_ptr_array_new();

    gboolean wsqlite_result = wsqlite_add_packet_dissection_sql_to_command_queue(epan_dissect, command_queue, seen_fields, last_buffer_id, last_dissection_details_id);
    if(wsqlite_result == FALSE)
    {
        return NULL;
    }

    gchar* result = wsqlite_join_strings_from_queue(command_queue);

    g_ptr_array_free(command_queue, TRUE);

    return result;
}

gboolean
wsqlite_add_packet_dissection_sql_to_command_queue(epan_dissect_t* epan_dissect, GPtrArray* command_queue, GHashTable* seen_fields, gint64* last_buffer_id, gint64* last_dissection_details_id)
{
    if(epan_dissect == NULL)
    {
        return FALSE;
    }

    if(epan_dissect->tvb == NULL)
    {
        return FALSE;
    }

    if(command_queue == NULL)
    {
        return FALSE;
    }

    // Build packet command
    guint32 packet_id = epan_dissect->pi.num;
    gdouble packet_timestamp = (gdouble)epan_dissect->pi.abs_ts.secs + (gdouble)epan_dissect->pi.abs_ts.nsecs / 1000000000.0;
    guint32 packet_length = epan_dissect->pi.fd->pkt_len;
    guint32 packet_captured_length = tvb_captured_length(epan_dissect->tvb);
    guint32 packet_interface_id = 0;
    if (epan_dissect->pi.rec->presence_flags & WTAP_HAS_INTERFACE_ID)
    {
        packet_interface_id = (guint32)(epan_dissect->pi.rec->rec_header.packet_header.interface_id);
    }

    gchar packet_timestamp_string_buffer[64];
    g_ascii_dtostr(packet_timestamp_string_buffer, 64, packet_timestamp);

    gchar* packet_command = NULL;
    packet_command = g_strdup_printf("INSERT INTO packets(id, timestamp, length, captured_length, interface_id) VALUES "
                                    "(%u, %s, %u, %u, %u);", packet_id, packet_timestamp_string_buffer, packet_length, packet_captured_length, packet_interface_id);
    
    g_ptr_array_add(command_queue, packet_command);

    // Build buffer command
    gchar* buffer_string = g_malloc(packet_captured_length * 2 + 1);
    for (guint32 i = 0; i < packet_captured_length; i++)
    {
        if (!tvb_offset_exists(epan_dissect->tvb, i))
        {
            buffer_string[i] = '\0';
            continue;
        }
        guint8 current_byte = tvb_get_guint8(epan_dissect->tvb, i);
        guint8 upper_nibble = (current_byte & 0xF0) >> 4;
        guint8 lower_nibble = current_byte & 0x0F;

        buffer_string[2*i] = upper_nibble >= 0x0A ? upper_nibble + 0x41 - 10: upper_nibble + 0x30;
        buffer_string[2*i + 1] = lower_nibble >= 0x0A ? lower_nibble + 0x41 - 10: lower_nibble + 0x30;
    }
    buffer_string[packet_captured_length * 2] = '\0';

    last_buffer_id[0]++;

    gchar* buffer_command = NULL;
    buffer_command = g_strdup_printf("INSERT INTO buffers(id, packet_id, buffer) VALUES "
                                    "(%i, %u, X'%s');", last_buffer_id[0], packet_id, buffer_string);

    g_free(buffer_string);

    g_ptr_array_add(command_queue, buffer_command);

    if(epan_dissect->tree == NULL)
    {
        return TRUE;
    }

    gint64 parent_id = 0;

    // Build tree commands
    wsqlite_get_tree_node_sql_callback_args_t callback_args;
    callback_args.command_queue = command_queue;
    callback_args.seen_fields = seen_fields;
    callback_args.parent_id = &parent_id;
    callback_args.buffer_id = last_buffer_id;
    callback_args.last_dissection_details_id = last_dissection_details_id;

    proto_tree_children_foreach(epan_dissect->tree, wsqlite_add_tree_node_sql_to_command_queue, &callback_args);

    return TRUE;
}

void
wsqlite_add_tree_node_sql_to_command_queue(proto_node* node, gpointer data)
{
    wsqlite_get_tree_node_sql_callback_args_t* callback_args = (wsqlite_get_tree_node_sql_callback_args_t*)data;
    
    header_field_info* header_field_info = node->finfo->hfinfo;
    enum ftenum field_type = header_field_info->type;
    gchar* representation = wsqlite_repair_string(node->finfo->rep->representation);
    gint32 position = (guint32)node->finfo->start;
    gint32 length = (guint32)node->finfo->length;

    gboolean field_is_seen = g_hash_table_contains(callback_args->seen_fields, GINT_TO_POINTER(header_field_info->id));

    if(field_is_seen == FALSE)
    {
        // build field command
        gchar* field_command = wsqlite_get_field_sql(header_field_info);

        if(field_command == NULL)
        {
            return;
        }

        g_ptr_array_add(callback_args->command_queue, field_command);

        g_hash_table_add(callback_args->seen_fields, GINT_TO_POINTER(header_field_info->id));
    }
    
    callback_args->last_dissection_details_id[0]++;

    if(field_type == FT_INT8
        || field_type == FT_INT16
        || field_type == FT_INT24
        || field_type == FT_INT32)
    {
        gint32 value = fvalue_get_sinteger(&node->finfo->value);
        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, integer_value) VALUES "
                                    "(%i, %i, %i, %i, %i, %i, %i);",
                                    callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value);

        g_ptr_array_add(callback_args->command_queue, command);
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
        guint value = fvalue_get_uinteger(&node->finfo->value);
        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, integer_value, double_value) VALUES "
            "(%i, %i, %i, %i, %i, %i, %u, 0.0);",
            callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value);

        g_ptr_array_add(callback_args->command_queue, command);
    }
    else if (field_type == FT_INT40
        || field_type == FT_INT48
        || field_type == FT_INT56
        || field_type == FT_INT64)
    {
        gint64 value = fvalue_get_sinteger64(&node->finfo->value);
        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, integer_value) VALUES "
            "(%i, %i, %i, %i, %i, %i, %i);",
            callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value);

        g_ptr_array_add(callback_args->command_queue, command);
    }    
    else if(field_type == FT_UINT40
        || field_type == FT_UINT48
        || field_type == FT_UINT56
        || field_type == FT_UINT64
        || field_type == FT_BOOLEAN
        || field_type == FT_EUI64)
    {
        guint64 value = fvalue_get_uinteger64(&node->finfo->value);
        gdouble sign = (value & 0x8000000000000000) > 0 ? 1.0 : 0.0;
        value = value & 0x7FFFFFFFFFFFFFFF;

        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, integer_value, double_value) VALUES "
                                    "(%i, %i, %i, %i, %i, %i, %u, %.0f);",
                                    callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value, sign);

        g_ptr_array_add(callback_args->command_queue, command);
    }
    else if (field_type == FT_FLOAT
        || field_type == FT_DOUBLE)
    {
        gdouble value = fvalue_get_floating(&node->finfo->value);

        gchar value_string_buffer[64];
        g_ascii_dtostr(value_string_buffer, 64, value);

        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, double_value) VALUES "
            "(%i, %i, %i, %i, %i, %i, %s);",
            callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value_string_buffer);

        g_ptr_array_add(callback_args->command_queue, command);
    }
    else if(field_type == FT_STRING
        || field_type == FT_STRINGZ
        || field_type == FT_STRINGZPAD
        || field_type == FT_STRINGZTRUNC)
    {
        gchar* value = wsqlite_repair_string(node->finfo->value.value.string);

        gchar* string_command = NULL;
        string_command = g_strdup_printf("INSERT OR IGNORE INTO strings(string) VALUES (\"%s\");",
            value);

        g_ptr_array_add(callback_args->command_queue, string_command);

        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, string_value_id) VALUES "
                                    "(%i, %i, %i, %i, %i, %i, (SELECT id FROM strings WHERE string = \"%s\"));",
                                    callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value);

        g_free(value);
        g_ptr_array_add(callback_args->command_queue, command);
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

        gchar* string_command = NULL;
        string_command = g_strdup_printf("INSERT OR IGNORE INTO strings(string) VALUES (\"%s\");",
            value);

        g_ptr_array_add(callback_args->command_queue, string_command);

        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, string_value_id) VALUES "
                                    "(%i, %i, %i, %i, %i, %i, (SELECT id FROM strings WHERE string = \"%s\"));",
                                    callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value);

        g_free(value);
        g_ptr_array_add(callback_args->command_queue, command);
    }
    else if (field_type == FT_PROTOCOL)
    {
        gchar* value = wsqlite_repair_string(node->finfo->value.value.protocol.proto_string);

        gchar* string_command = NULL;
        string_command = g_strdup_printf("INSERT OR IGNORE INTO strings(string) VALUES (\"%s\");",
            value);

        g_ptr_array_add(callback_args->command_queue, string_command);

        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, string_value_id) VALUES "
            "(%i, %i, %i, %i, %i, %i, (SELECT id FROM strings WHERE string = \"%s\"));",
            callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value);

        g_free(value);
        g_ptr_array_add(callback_args->command_queue, command);
    }
    else if (field_type == FT_ABSOLUTE_TIME
        || field_type == FT_RELATIVE_TIME)
    {
        gdouble value = (gdouble)node->finfo->value.value.time.secs + (gdouble)node->finfo->value.value.time.nsecs / 1000000000.0;

        gchar value_string_buffer[64];
        g_ascii_dtostr(value_string_buffer, 64, value);


        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, double_value) VALUES "
            "(%i, %i, %i, %i, %i, %i, %s);",
            callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value_string_buffer);

        g_ptr_array_add(callback_args->command_queue, command);
    }
    else if (field_type == FT_GUID)
    {
        e_guid_t guid = node->finfo->value.value.guid;
        gchar* value = g_strdup_printf("08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
            guid.data1, guid.data2, guid.data3,
            guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
            guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]);

        gchar* string_command = NULL;
        string_command = g_strdup_printf("INSERT OR IGNORE INTO strings(string) VALUES (\"%s\");",
            value);

        g_ptr_array_add(callback_args->command_queue, string_command);

        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length, string_value_id) VALUES "
            "(%i, %i, %i, %i, %i, %i, (SELECT id FROM strings WHERE string = \"%s\"));",
            callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length, value);

        g_free(value);
        g_ptr_array_add(callback_args->command_queue, command);
    }
    else // FT_NONE
    {
        gchar* command = NULL;
        command = g_strdup_printf("INSERT INTO dissection_details(id, parent_id, field_id, buffer_id, position, length) VALUES "
                                    "(%i, %i, %i, %i, %i, %i);",
                                    callback_args->last_dissection_details_id[0], callback_args->parent_id[0], header_field_info->id, callback_args->buffer_id[0], position, length);

        g_ptr_array_add(callback_args->command_queue, command);
    }

    if (representation != NULL)
    {
        gchar* string_command = NULL;
        string_command = g_strdup_printf("INSERT OR IGNORE INTO strings(string) VALUES (\"%s\");",
            representation);

        g_ptr_array_add(callback_args->command_queue, string_command);

        gchar* representation_command = NULL;
        representation_command = g_strdup_printf("UPDATE dissection_details SET representation_id = (SELECT id FROM strings WHERE string = \"%s\") WHERE id = %i;",
            representation, callback_args->last_dissection_details_id[0]);

        g_ptr_array_add(callback_args->command_queue, representation_command);
    }

    g_free(representation);

    guint64 last_parent_id = callback_args->parent_id[0];
    callback_args->parent_id[0] = callback_args->last_dissection_details_id[0];
    proto_tree_children_foreach(node, wsqlite_add_tree_node_sql_to_command_queue, callback_args);
    callback_args->parent_id[0] = last_parent_id;
}

gchar*
wsqlite_join_strings_from_queue(GPtrArray* command_queue)
{
    if(command_queue == NULL)
    {
        return NULL;
    }
    guint command_queue_length = g_ptr_array_len(command_queue);

    if(command_queue_length == 0)
    {
        return NULL;
    }

    // g_strjoinv expects a NULL terminated array
    g_ptr_array_add(command_queue, NULL);
    gchar* result = g_strjoinv("\n", (gchar**)command_queue->pdata);

    // remove NULL pointer at the end because g_ptr_array_free would fail otherwise.
    g_ptr_array_remove_index_fast(command_queue, command_queue_length);

    return result;
}

gchar*
wsqlite_repair_string(gchar* string)
{
    if(string == NULL)
    {
        return NULL;
    }
    gchar** splitted_string = g_strsplit(string, "\"", -1);
    gchar* result = g_strjoinv("\"\"", splitted_string);
    g_strfreev(splitted_string);

    return result;
}
