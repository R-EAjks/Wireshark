"""
Detect broken image references in the WSUG and WSDG.

SPDX-License-Identifier: MIT
"""

import os
import os.path
import re
import sys

docbook_root_dir = "docbook"
adoc_extension = ".adoc"
image_regex = r"image::([^\]]+)\["


def check_file(fpath):
    errors = []
    with open(fpath, 'r') as fh:
        fdata = fh.read()
    for match in re.findall(image_regex, fdata):
        image_fpath = os.path.join(docbook_root_dir, match)
        if os.path.isfile(image_fpath):
            continue
        print("%s references image %s which does not exist!" % (fpath, match))
        errors.append((fpath, match))
    return errors


def run_specific_files(fpaths):
    errors = []
    for fpath in fpaths:
        if not (fpath.endswith(adoc_extension)):
            continue
        errors += check_file(fpath)
    return errors


def run_recursive(root_dir):
    errors = []
    for root, dirs, files in os.walk(root_dir):
        fpaths = []
        for fname in files:
            if not (fname.endswith(adoc_extension)):
                continue
            fpath = os.path.join(root, fname)
            fpaths.append(fpath)
        errors += run_specific_files(fpaths)
    return errors


def main():
    if len(sys.argv) == 2:
        root_dir = sys.argv[1]
        errors = run_recursive(root_dir)
    else:
        fpaths = []
        for line in sys.stdin:
            line = line.strip()
            if line:
                fpaths.append(line)
        errors = run_specific_files(fpaths)

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
