/* wstlv.c
 *
 * Routines for handling Wireshark's flavour of Type-Length-Value data.
 * This is the format used by pcapng options and the exported_pdu protocol.
 * (ie, this is *not* for generic TLV data found in whatever protocol.)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

//#include <config.h>

#include "wstlv.h"

#include <string.h>

// Length of item when padded to 32 bits
#define PADDED(x) (((x) + 3) & (~3))

// Length of just the padding
#define PADDING(x) ((((x) + 3) & (~3)) - x)

// Get the list item at the given index. Shorthand. No bounds checking!
#define WSTLV_INDEX(l, i) (g_array_index((l), wstlv_item_t, (i)))

// Size of Type and Length fields (to avoid magic numbers)
#define WSTLV_TL_SIZE 4

void
wstlv_add(wstlv_list *list, guint16 type, guint16 length, gconstpointer data) {
    wstlv_item_t item;

    g_assert(type > 0);
    if (*list == WSTLV_INIT) {
        *list = g_array_new(TRUE, TRUE, sizeof(wstlv_item_t));
    }
    item.type = type;
    item.length = length;
    // Allocate an extra byte with a NULL in case it's holding a string,
    // so its value can be used without having to copy the data when it's not
    // necessary (when it is, see wstlv_item_str() / _gstring()) .
    // This design can be revisited in the future
    item.data = (guint8 *)g_malloc0(length + 1);
    memcpy(item.data, data, length);
    g_array_append_val(*list, item);
}

void
wstlv_clear(wstlv_list *list) {
    if (*list != WSTLV_INIT) {
        guint i;
        wstlv_item_t item;
        for (i = 0; i < (*list)->len; i++) {
            item = WSTLV_INDEX(*list, i);
            g_free(item.data);
        }
        g_array_free(*list, TRUE);
        *list = WSTLV_INIT;
    }
}

void
wstlv_destroy(gpointer data) {
    wstlv_clear((wstlv_list *)&data);
}

void
wstlv_clone(wstlv_list *dest, wstlv_list src) {
    guint i;
    wstlv_item_t item;

    wstlv_clear(dest);

    for(i = 0; i < src->len; i++) {
        item = WSTLV_INDEX(src, i);
        wstlv_add(dest, item.type, item.length, item.data);
    }
}

GSList *
wstlv_search(wstlv_list *list, guint16 type) {
    GSList *ret_val = NULL;
    wstlv_item_t *item;
    guint i;

    if (list == WSTLV_INIT) {
        return NULL;
    }

    for (i = 0; i < wstlv_count(list); i++) {
        item = wstlv_index(list, i);
        if (item->type == type) {
            ret_val = g_slist_prepend(ret_val, item);
        }
    }
    ret_val = g_slist_reverse(ret_val);
    return ret_val;
}

static gint
wstlv_list_compare_internal(gconstpointer a, gconstpointer b, gboolean deep) {
    gint ret_val = 0;
    guint i;
    wstlv_list alist = (wstlv_list) a;
    wstlv_list blist = (wstlv_list) b;
    GCompareFunc cmp_fnc = deep ? wstlv_item_compare_deep : wstlv_item_compare;

    if (wstlv_count(&alist) != wstlv_count(&blist)) {
        return wstlv_count(&alist) - wstlv_count(&blist);
    }
    for (i = 0; i < wstlv_count(&alist); i++) {
        ret_val = cmp_fnc((gconstpointer)&WSTLV_INDEX(alist, i),
                (gconstpointer)&WSTLV_INDEX(blist, i));
        if (ret_val != 0) {
            return ret_val;
        }
    }
    return ret_val;
}

gint
wstlv_list_compare(gconstpointer a, gconstpointer b) {
    return wstlv_list_compare_internal(a, b, FALSE);
}

gint
wstlv_list_compare_deep(gconstpointer a, gconstpointer b) {
    return wstlv_list_compare_internal(a, b, TRUE);
}

wstlv_item_t *
wstlv_index(wstlv_list *list, guint index) {
    if (*list == WSTLV_INIT || index >= (*list)->len) {
        return NULL;
    }
    return &g_array_index(*list, wstlv_item_t, index);
}

gsize
wstlv_size_padded(wstlv_list *list) {
    guint i;
    wstlv_item_t item;
    gsize nbytes = 0;

    if (wstlv_count(list) == 0) {
        return nbytes;
    }
    for(i = 0; i < (*list)->len; i++) {
        item = WSTLV_INDEX(*list, i);
        nbytes += PADDED(item.length) + WSTLV_TL_SIZE;
    }
    return nbytes;
}

guint8
wstlv_item_guint8(wstlv_item_t *item) {
    g_assert(item->length == sizeof(guint8));
    return (guint8)item->data[0];
}

gint8
wstlv_item_gint8(wstlv_item_t *item) {
    g_assert(item->length == sizeof(gint8));
    return (guint8)item->data[0];
}

#define MAKE_CONVERTER(T) \
T \
wstlv_item_ ## T (wstlv_item_t *item) { \
    guint i; \
    union { \
        T ret_val; \
        guint8 data[sizeof(T)]; \
    } converter; \
\
    g_assert(item->length == sizeof(T)); \
    for (i = 0; i < sizeof(T); i++) { \
        converter.data[i] = item->data[i]; \
    } \
    return converter.ret_val; \
}

MAKE_CONVERTER(guint16)
MAKE_CONVERTER(gint16)
MAKE_CONVERTER(guint32)
MAKE_CONVERTER(gint32)
MAKE_CONVERTER(guint64)
MAKE_CONVERTER(gint64)
MAKE_CONVERTER(gfloat)
MAKE_CONVERTER(gdouble)

gchar *
wstlv_item_str(wstlv_item_t *item) {
    return g_strndup((const gchar *)item->data, item->length);
}

GString *
wstlv_item_gstring(wstlv_item_t *item) {
    return g_string_new_len((const gchar *)item->data, item->length);
}

gint
wstlv_item_compare(gconstpointer a, gconstpointer b) {
    wstlv_item_t *itema = (wstlv_item_t *)a;
    wstlv_item_t *itemb = (wstlv_item_t *)b;

    if (itema->type != itemb->type) {
        return itema->type - itemb->type;
    }
    if (itema->length != itemb->length) {
        return itema->length - itemb->length;
    }
    if (itema->data != itemb->data) {
        return (gint)(itema->data - itemb->data);
    }
    return 0;
}

gint
wstlv_item_compare_deep(gconstpointer a, gconstpointer b) {
    wstlv_item_t *itema = (wstlv_item_t *)a;
    wstlv_item_t *itemb = (wstlv_item_t *)b;

    if (itema->type != itemb->type) {
        return itema->type - itemb->type;
    }
    if (itema->length != itemb->length) {
        return itema->length - itemb->length;
    }
    return memcmp(itema->data, itemb->data, itema->length);
}

