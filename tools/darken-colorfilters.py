#!/usr/bin/env python3
#
# darken-colorfilters.py - Convert the default colorfilters file to one
# that conforms to a dark theme.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2019 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Generate `profiles/Dark Mode/colorfilters` from `colorfilters`.
'''

import io
import os.path
import re
import sys

def main():
    if sys.version_info[0] < 3:
        print("This requires Python 3")
        sys.exit(2)

    this_dir = os.path.dirname(__file__)
    light_cf = os.path.join(this_dir, '..', 'colorfilters')
    dark_cf = os.path.join(this_dir, '..', 'profiles', 'Dark Mode', 'colorfilters')

    # @<filter name>@<filter string>@[<background>][<foreground>]
    rule_re = re.compile('(^[^#].*)\[(\d+),(\d+),(\d+)\]\[(\d+),(\d+),(\d+)\]([\r\n]+)')
    dm_lines = []
    with io.open(light_cf, 'r', encoding='UTF-8') as light_fd:
        for line in light_fd:
            dark_line = None
            m = rule_re.match(line)
            threshold = 12000
            if m:
                rule = m.groups()[0]
                (bg_r, bg_g, bg_b, fg_r, fg_g, fg_b) = [int(chan) for chan in m.groups()[1:7]]
                end = m.groups()[7]
                # The standard light mode foreground color is 4718,10030,11796.
                if fg_r < threshold and fg_g < threshold and fg_b < threshold:
                    dark_line = '{}[{},{},{}][{},{},{}]{}'.format(rule, fg_r, fg_g, fg_b, bg_r, bg_g, bg_b, end)

            if dark_line:
                dm_lines.append(dark_line)
            else:
                dm_lines.append(line)

    with io.open(dark_cf, 'w', encoding='UTF-8') as dark_fd:
        dark_fd.write(''.join(dm_lines))

if __name__ == '__main__':
    main()
