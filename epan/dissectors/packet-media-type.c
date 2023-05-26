/* packet-media-type.c
 * Manage the media_type dissector table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/export_object.h>

#include "packet-media-type.h"

tap_packet_status
media_type_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
	export_object_list_t *object_list = (export_object_list_t *)tapdata;
	const media_eo_t *eo_info = (const media_eo_t *)data;
	export_object_entry_t *entry;

	if(eo_info) { /* We have data waiting for us */
		/* These values will be freed when the Export Object window
		 * is closed. */
		entry = g_new(export_object_entry_t, 1);

		entry->pkt_num = pinfo->num;
		entry->hostname = g_strdup(eo_info->hostname);
		entry->content_type = g_strdup(eo_info->content_type);
		entry->filename = eo_info->filename ? g_path_get_basename(eo_info->filename) : NULL;
		entry->payload_len = tvb_captured_length(eo_info->payload);
		entry->payload_data = (guint8 *)tvb_memdup(NULL, eo_info->payload, 0, entry->payload_len);

		object_list->add_entry(object_list->gui_data, entry);

		return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
	} else {
		return TAP_PACKET_DONT_REDRAW; /* State unchanged - no window updates needed */
	}
}

void
proto_register_media_type(void)
{
	int proto_media_type = proto_register_protocol("Internet media type", "Media Type", "media_type");
	/* This isn't a real protocol, so you can't disable its dissection. */
	proto_set_cant_toggle(proto_media_type);
	/*
	 * Dissectors can register themselves in this table.
	 * It's just "media_type", not "http.content_type", because
	 * it's an Internet media type, used by other protocols as well.
	 *
	 * RFC 6838, 4.2 Naming Requirements:
	 * "Both top-level type and subtype names are case-insensitive."
	 */
	register_dissector_table("media_type", "Internet media type",
	        proto_media_type, FT_STRING, STRING_CASE_INSENSITIVE);

	register_export_object(proto_media_type, media_type_eo_packet, NULL);
}
