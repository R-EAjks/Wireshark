#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import subprocess
import argparse
import signal


# For text colouring/highlighting.
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    ADDED = '\033[45m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


dissectors = [ 'packet-ulgrant.c',
               'packet-l2server.c',
               'packet-dlblock.c',
               'packet-pdcp-uu.c',
               'packet-pdcp-gtpu.c',
               'packet-ip-udp.c',
               'packet-pacs.c',
               'packet-axe-rpc.c',
               'packet-textlogger.c',
               'packet-tlv.c']

def run_check(tool):
    print(bcolors.ADDED + tool + bcolors.ENDC)
    command = './tools/' + tool
    for d in dissectors:
        command += (' --file ' + 'epan/dissectors/' + d)
    os.system(command)


# Run all tests on all of my dissectors.
run_check('check_tfs.py')
run_check('check_typed_item_calls.py')
run_check('check_static.py')
run_check('check_dissector_urls.py')
run_check('check_spelling.py')
