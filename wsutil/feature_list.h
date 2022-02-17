/** @file
 * Declarations of routines for gathering and handling lists of
 * present/absent features
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_FEATURE_LIST_H__
#define __WSUTIL_FEATURE_LIST_H__

#include <glib.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef GList **feature_list;

typedef void(*gather_feature_func)(feature_list l);

WS_DLL_PUBLIC
void with_feature(feature_list l, const char *fmt, ...) G_GNUC_PRINTF(2,3);

WS_DLL_PUBLIC
void without_feature(feature_list l, const char *fmt, ...) G_GNUC_PRINTF(2,3);

WS_DLL_PUBLIC
void sort_features(feature_list l);

WS_DLL_PUBLIC
void free_features(feature_list l);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_FEATURE_LIST_H__ */
