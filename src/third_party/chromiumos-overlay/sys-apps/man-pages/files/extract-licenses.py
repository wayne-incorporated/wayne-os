#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Extract all the licenses from the man page comments.

Each man page may be licensed under a unique license, so we have to walk each
one and extract the details.
"""

import argparse
import os
from pathlib import Path
import re
import sys
from typing import List, Optional, Tuple, Union


# Extract the license name & text from a section like:
# .\" %%%LICENSE_START(BSD_4_CLAUSE_UCB)
# .\" ...text...
# .\" %%%LICENSE_END
EXTRACT_LICENSE = re.compile(
    r'^[^\n]*%%%LICENSE_START\(([^)]+)\)\n(.*)%%%LICENSE_END$',
    flags=re.MULTILINE | re.DOTALL)


# Licenses that require copyright attribution.
ATTRIBUTION_LICENSES = {
    'BSD_3_CLAUSE_UCB',
    'BSD_4_CLAUSE_UCB',
    'BSD_ONELINE_CDROM',
    'MISC',
    'MIT',
    'PERMISSIVE_MISC',
    'VERBATIM',
    'VERBATIM_ONE_PARA',
    'VERBATIM_PROF',
    'VERBATIM_TWO_PARA',
}

# All licenses we know about.  If a new one shows up, we'll throw an error so
# we're forced to evaluate it.
KNOWN_LICENSES = ATTRIBUTION_LICENSES | {
    'FREELY_REDISTRIBUTABLE',
    'GPL_NOVERSION_ONELINE',
    'GPLv2+',
    'GPLv2+_DOC_FULL',
    'GPLv2+_DOC_MISC',
    'GPLv2+_DOC_ONEPARA',
    'GPLv2_MISC',
    'GPLv2_ONELINE',
    'GPLv2+_SW_3_PARA',
    'GPLv2+_SW_ONEPARA',
    'LDPv1',
    'PUBLIC_DOMAIN',
}


def line_iscomment(line: str) -> bool:
    """Whether |line| is a roff comment."""
    # A variety of possible formats here.  This should get cleaned up in newer
    # versions, but we have to deal with it in current releases.
    # \" ...
    # .\" ...
    # '\" ...
    # .
    # We can't use triple double quotes here because it'll be invalid syntax,
    # so we're forced to use triple single quotes instead.
    # pylint: disable=invalid-triple-quote
    return re.match(r'''^(\.$|[.']?\\")''', line)


def extract_license(page: Path) -> Union[None, Tuple[str, str]]:
    """Extract the license from |page|."""
    with open(page, encoding='utf-8') as fp:
        data = fp.read()

        # Ignore stub pointer files.
        if data.startswith('.so '):
            return None

        # Find the name of the license to do high level checks.
        matches = list(EXTRACT_LICENSE.finditer(data))
        assert matches, f'{page}: unable to find licenses'
        for match in matches:
            name = match.group(1)
            assert name in KNOWN_LICENSES, (
                f'{page}: {name}: unknown license; please update script')

            # We'll yield the entire preceding header to the license.
            if name in ATTRIBUTION_LICENSES:
                # Walk backwards to collect copyrights until we:
                # (1) Hit the start of the file.
                # (2) Hit a non-comment line (as all copyrights are comments).
                # (3) Hit the previous license.
                header = data[0:match.start(0)]
                lines = []
                for line in reversed(header.splitlines()):
                    if not line_iscomment(line) or '%%%LICENSE_' in line:
                        break
                    lines.insert(0, line[3:].strip())
                assert lines, f'{page}: invalid header:\n{header}'
                # Trim a weird leading line pending upstream cleanup.
                if lines[0] == 't':
                    lines.pop(0)
                copyright_text = '\n'.join(lines).strip()

                # Format the license text.
                license_text = ''
                # First remove the different comment styles.
                lines = [x[3:].strip()
                         for x in match.group(2).strip().splitlines()]
                # Then merge sentences.
                for i, line in enumerate(lines):
                    line = line.strip()
                    if i == 0:
                        license_text = line + ' '
                    else:
                        if not line:
                            license_text = license_text.strip() + '\n\n'
                        else:
                            license_text += line + ' '
                license_text = license_text.strip()

                return (license_text, copyright_text)

    # No licenses were found that required attribution.
    return None


def get_parser() -> argparse.ArgumentParser:
    """Get CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-o', '--output', type=Path,
                        help='File to write combined license to.')
    parser.add_argument('-d', '--srcdir', type=Path,
                        default=os.environ.get('S'),
                        help='Source dir to walk (e.g. $S)')
    parser.add_argument('files', nargs='*', default=[],
                        help='Source files (overrides --srcdir)')
    return parser


def main(argv: Optional[List[str]] = None) -> Optional[int]:
    """The main entry point for scripts."""
    parser = get_parser()
    opts = parser.parse_args(argv)

    if not opts.srcdir and not opts.files:
        parser.error('--srcdir is required')
    elif opts.srcdir and opts.files:
        parser.error('--srcdir and files are mutually exclusive')
    elif opts.srcdir:
        if not opts.srcdir.is_dir():
            parser.error(f'{opts.srcdir}: --srcdir is missing or is not a dir')

        files = opts.srcdir.glob('man[0-9]/*.[0-9]')
    else:
        files = [Path(x) for x in opts.files]

    # Merge pages with same licenses into one to avoid duplication.
    licenses = {}
    for file in files:
        result = extract_license(file)
        if result:
            license_text, copyright_text = result
            licenses.setdefault(license_text, []).append(
                (file.name, copyright_text))

    # Then produce the final notice lines.
    lines = []
    for license_text, pages in sorted(licenses.items()):
        for page, copyright_text in pages:
            lines += [page, copyright_text]
        lines += ['', license_text]
        lines += ['-' * 80]
    # Remove the last ~ banner since we don't need it at the end of the file.
    lines.pop()

    # Then write it all out.
    data = '\n'.join(lines).strip() + '\n'
    if opts.output:
        with open(opts.output, 'w', encoding='utf-8') as fp:
            fp.write(data)
    else:
        print(data, end='')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
