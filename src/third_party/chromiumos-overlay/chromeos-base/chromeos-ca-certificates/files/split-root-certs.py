#!/usr/bin/env python3
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Extract individual root cert pem files from bundle.

We expect the bundle is downloaded from https://pki.goog/roots.pem and contains
leading comment lines.

This script reads the specified ROOTS_PEM, parses header comments, and extracts
individual certs into .pem files with human-readable names (based on "Label").
"""

import argparse
import os
import re
import sys


class ExtractedCert:
    """This class represents a cert extracted from a PEM bundle."""

    def __init__(self, lines, prefix=''):
        self.lines = lines
        self.prefix = prefix

    def get_label(self):
        """Find the label for this certification."""
        for line in self.lines:
            if line.startswith('# Label:'):
                m = re.search('# Label: "([^"]+)"', line)
                label = m.group(1)
                return label
        raise ValueError('Could not find label')

    def get_filename(self):
        """Construct path to write to, based on "Label" comment."""
        label_underscores = self.get_label().replace(' ', '_')
        filename = '%s.pem' % label_underscores
        path = os.path.join(self.prefix, filename)
        return path

    def write(self):
        """Write certificate to disk."""
        cert_file = self.get_filename()
        parent_dir = os.path.dirname(cert_file)
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir)
        with open(cert_file, 'w') as f:
            f.writelines(self.lines)


def lex_pem_file(roots_pem):
    """Generator that splits lines from |roots_pem| on cert boundaries."""
    with open(roots_pem) as f:
        lines = f.readlines()

        cert_lines = []
        for line in lines:
            cert_lines.append(line)
            if line.startswith('-----END CERTIFICATE-----'):
                yield cert_lines
                cert_lines = []


def extract_certs(roots_pem, extract_to):
    """Extracts all certs as individual pem files.

    Args:
        roots_pem: Path to bundle file that is a concatenation of certs.
        extract_to: Directory where extracted certs are written. When None,
            extracted certs will not be written to disk.
    """
    for line_list in lex_pem_file(roots_pem):
        cert = ExtractedCert(line_list, prefix=extract_to)
        if extract_to:
            cert.write()


def main(argv):
    """The script entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--roots-pem', help='File containing many certs.',
                        required=True)
    parser.add_argument('--extract-to', default='',
                        help='Where to place extracted certs. If not specified,'
                        ' files will not be written.')
    opts = parser.parse_args(argv)
    extract_certs(opts.roots_pem, opts.extract_to)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
