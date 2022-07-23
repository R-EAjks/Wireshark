/* cocoa_bridge.mm
 *
 * This code was taken directly from:
 * https://forum.qt.io/topic/82609/remove-native-mac-menu-items-such-as-show-tab-bar
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/macosx/cocoa_bridge.h>
#include <ui/macosx/macos_compat.h>

#import <Cocoa/Cocoa.h>

void CocoaBridge::cleanOSGeneratedMenuItems()
{
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_12_AND_LATER
    // Remove (don't allow) the "Show Tab Bar" menu item from the "View" menu, if
    // supported

    if ([NSWindow respondsToSelector:@selector(setAllowsAutomaticWindowTabbing:)])
        [NSWindow setAllowsAutomaticWindowTabbing: NO];
#endif

    [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"NSFullScreenMenuItemEverywhere"];

    // Remove (disable) the "Start Dictation..." and "Emoji & Symbols" menu items
    // from the "Edit" menu

    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"NSDisabledDictationMenuItem"];
    [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"NSDisabledCharacterPaletteMenuItem"];
}

/* The following code has been inspired by: https://successfulsoftware.net/2021/03/31/how-to-add-a-dark-theme-to-your-qt-application/ */

bool DarkThemeAvailable()
{
    if (@available(macOS 10.14, *))
        return true;

    return false;
}

bool IsInDarkTheme()
{
    if (DarkThemeAvailable())
    {
        auto appearance = [NSApp.effectiveAppearance bestMatchFromAppearancesWithNames:
                @[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]];
        return [appearance isEqualToString:NSAppearanceNameDarkAqua];
    }

    return false;
}

void SetToDarkTheme()
{
   // https://stackoverflow.com/questions/55925862/how-can-i-set-my-os-x-application-theme-in-code
   if (DarkThemeAvailable())
   {
        [NSApp setAppearance:[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua]];
   }
}

void SetToLightTheme()
{
    // https://stackoverflow.com/questions/55925862/how-can-i-set-my-os-x-application-theme-in-code
    if (DarkThemeAvailable())
    {
        [NSApp setAppearance:[NSAppearance appearanceNamed:NSAppearanceNameAqua]];
    }
}

void SetToAutoTheme()
{
    if (DarkThemeAvailable())
    {
        [NSApp setAppearance:nil];
    }
}