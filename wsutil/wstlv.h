/* wstlv.h
 *
 * Routines for handling Wireshark's flavour of Type-Length-Value data.
 * This is the format used by pcapng options and the exported_pdu protocol.
 * (ie, this is *not* for generic TLV data found in whatever protocol.)
 *
 * Types and lengths are presumed to be given in machine byte order.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSTLV_H__
#define __WSTLV_H__

#include <glib.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef GArray* wstlv_list;
typedef guint16 wstlv_type_t;
typedef guint16 wstlv_length_t;

typedef struct wstlv_item_s {
    guint16 type;       // Type identifier; opaque to wstlv.c
    guint16 length;     // Length of data WITHOUT PADDING
    guint8 *data;       // Pointer to data
} wstlv_item_t;

/**
 * @brief Initialization value to use when creating a wstlv.
 * @example
 *      wstlv_list mylist = WSTLV_INIT;
 */
#define WSTLV_INIT NULL


/**
 * @brief Get the number of items in the list.
 * @param [IN] list     Pointer to the `wstlv_list` to count
 * @return guint        The number of items in the list
 * @example
 *      guint n_items = wstlv_count(&mylist);
 */
#define wstlv_count(list) (*(list)==WSTLV_INIT ? (guint)0 : (*(list))->len)

/**
 * @brief Copy a data item into a TLV list, creating the list if necessary.
 * @param [INOUT] list  Pointer to the `wstlv_list` to add to
 * @param [IN] type     The type identifier for the data
 * @param [IN] length   The length of the data in `data`
 * @param [IN] data     The data to be cloned into the TLV
 * @example
 *      wstlv_add(&mylist, 0xF00D, sizeof(guint16), (gconstpointer)&my_number);
 */
WS_DLL_PUBLIC
void wstlv_add(wstlv_list *list, guint16 type, guint16 length, gconstpointer data);

/**
 * @brief Clear a TLV list.
 * @param [INOUT] list  Pointer to the `wstlv_list` to clear
 * @note This function is for concise coding since it takes care of any edge cases.
 * Not suitable as a GDestroyFunc since it takes and modifies a pointer;
 * see wstlv_destroy() for that.
 *
 * @example
 *      wstlv_clear(&mylist);
 */
WS_DLL_PUBLIC
void wstlv_clear(wstlv_list *list);

/**
 * @brief Destroy a TLV list.
 * @param [IN] list  The `wstlv_list` to destroy
 * @note This function is for use as a GDestroyFunc and in other situations
 * when you know the pointer is to a valid structure. You will need to assign
 * WSTLV_INIT to the list afterwards before you can use it again. For a clean
 * API that gracefully handles NULL, see wstlv_clear().
 *
 * @example
 *      GTree * tlv_tree = g_tree_new_full(cmp_func, NULL, NULL, wstlv_destroy);
 */
WS_DLL_PUBLIC
void wstlv_destroy(gpointer data);

/**
 * @brief Perform a deep copy of a TLV list.
 * @param [OUT] dest    Pointer to the new `wstlv_list` to hold the copy
 * @param [IN] src      The existing `wstlv_list` to copy
 * @note Calls wstlv_clear() on dest before copying over it.
 */
WS_DLL_PUBLIC
void wstlv_clone(wstlv_list *dest, wstlv_list src);

/**
 * @brief Create a list of items matching the given type.
 * @param [IN] list     Pointer to the `wstlv_list` to search
 * @param [IN] type     Type to search for
 * @return wstlv_list   The new list with just items of that type
 * @note The result must be freed with g_slist_free() when done.
 */
WS_DLL_PUBLIC
GSList *wstlv_search(wstlv_list *list, guint16 type);

/**
 * @brief Shallow comparison of two TLV lists.
 *        Meant to be able to serve as a GCompareFunc.
 * @param [IN] a        The first wstlv_list
 * @param [IN] b        The second wstlv_list
 * @return gint         whether a </=/> b
 */
WS_DLL_PUBLIC
gint wstlv_list_compare(gconstpointer a, gconstpointer b);

/**
 * @brief Deep comparison of two TLV lists.
 *        Meant to be able to serve as a GCompareFunc.
 * @param [IN] a        The first wstlv_list
 * @param [IN] b        The second wstlv_list
 * @return gint         whether a </=/> b
 */
WS_DLL_PUBLIC
gint wstlv_list_compare_deep(gconstpointer a, gconstpointer b);

/**
 * @brief Get a pointer to an item in the list. Performs bounds checking.
 * @param [IN] list     Pointer to the `wstlv_list` to get
 * @param [IN] index    Index of item to get
 * @return wstlv_item_t* Pointer to the index item, or NULL if there's no such index
 * @note Do not modify the contents of the return value.
 * @example
 *      wstlv_item_t *item = wstlv_index(&mylist, 5);
 */
WS_DLL_PUBLIC
wstlv_item_t *wstlv_index(wstlv_list *list, guint index);

/**
 * @brief Get the size of the TLV list if it were to be written out
 *        with each item padded to 32-bit boundaries.
 *        Does NOT assume an end-of-options tag.
 * @param [IN] list     Pointer to the `wstlv_list`
 * @return gsize        Number of bytes that would be occupied.
 *                      May be 0 if the list is empty.
 */
WS_DLL_PUBLIC
gsize wstlv_size_padded(wstlv_list *list);


/**
 * Get the value of the wstlv_item as the given data type.
 * wstlv.c usually has no idea of what the actual types of the items are
 * that it's storing; its type checking is limited to testing that the
 * item's length matches the data type you're requesting.
 * The data for numeric types is assumed to be stored in machine byte order.
 */
WS_DLL_PUBLIC guint8 wstlv_item_guint8(wstlv_item_t *item);
WS_DLL_PUBLIC gint8 wstlv_item_gint8(wstlv_item_t *item);
WS_DLL_PUBLIC guint16 wstlv_item_guint16(wstlv_item_t *item);
WS_DLL_PUBLIC gint16 wstlv_item_gint16(wstlv_item_t *item);
WS_DLL_PUBLIC guint32 wstlv_item_guint32(wstlv_item_t *item);
WS_DLL_PUBLIC gint32 wstlv_item_gint32(wstlv_item_t *item);
WS_DLL_PUBLIC guint64 wstlv_item_guint64(wstlv_item_t *item);
WS_DLL_PUBLIC gint64 wstlv_item_gint64(wstlv_item_t *item);
WS_DLL_PUBLIC gfloat wstlv_item_gfloat(wstlv_item_t *item);
WS_DLL_PUBLIC gdouble wstlv_item_gdouble(wstlv_item_t *item);

/**
 * The return value of wstlv_item_str() is a copy of the data
 * and you should call g_free() on it when you're done with it
 */
WS_DLL_PUBLIC gchar * wstlv_item_str(wstlv_item_t *item);

/**
 * The return value of wstlv_item_gstring() is a copy of the data
 * and you should call g_string_free() on it when you're done with it
 */
WS_DLL_PUBLIC GString * wstlv_item_gstring(wstlv_item_t *item);

/**
 * @brief Shallow comparison of two TLV items.
 *        Meant to be able to serve as a GCompareFunc.
 * @param [IN] a        The first wstlv_item_t
 * @param [IN] b        The second wstlv_item_t
 * @return gint         whether a </=/> b
 */
WS_DLL_PUBLIC
gint wstlv_item_compare(gconstpointer a, gconstpointer b);

/**
 * @brief Deep comparison of two TLV items.
 *        Meant to be able to serve as a GCompareFunc.
 * @param [IN] a        The first wstlv_item_t
 * @param [IN] b        The second wstlv_item_t
 * @return gint         whether a </=/> b
 */
WS_DLL_PUBLIC
gint wstlv_item_compare_deep(gconstpointer a, gconstpointer b);

/**
 * @brief Getthe size of this TLV item if it were to be written out
 * padded to a 32-bit boundary.
 * @param [IN] item     The wstlv_item_t
 * @return gsize        Number of bytes that would be occupied. May be 0.
 */
#define wstlv_item_size_padded(i) (4+(((i).length + 3) & (~3)))


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __WSTLV_H__ */
