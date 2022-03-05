#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

'''
Go through all user guide help URLs listed in the program
and confirm these are present in the User's Guide souce files.
'''

from re import search
from os import listdir
from sys import exit

userguide_source = "docbook/wsug_src/"
found = {}

with open("ui/help_url.c") as f:
    for line in f:
        if url := search(r"user_guide_url\(\"(.*).html\"\);", line):
            chapter = url.group(1)
            found[chapter] = False

wsug_files = listdir(userguide_source)
adoc_files = [adoc_file for adoc_file in wsug_files if '.adoc' in adoc_file]

for adoc_file in adoc_files:
    with open(userguide_source + adoc_file) as f:
        for line in f:
            if tag := search(r"^\[\#(.*)]", line):
                chapter = tag.group(1)
                if chapter in found:
                    found[chapter] = True

missing = False

for chapter in found:
    if not found[chapter]:
        if not missing:
            print("The following chapters are missing in the User's Guide:")
            missing = True
        print(chapter)

if missing:
    exit(-1)
