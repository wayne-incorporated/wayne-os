#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Parade PS8xxx checksum utility.

Some PS8xxx series TCPCs support support an application firmware update
that can be used instead of needing to update the base firmware. This is
similar to the idea of updating EC-RW while preserving EC-RO.

The application firmware needs a 2-byte checksum placed at the end of
its 64 KB region. This utility is used to 0xff pad the application
firmware and add the checksum.
"""

import argparse
import sys

block_size = 65536
block_offset_xor = block_size - 2
block_offset_sum = block_size - 1

def cksum2(infile):
    """Pad file with 0xff and add checksum."""

    sum_xor = 0
    sum_add = 0
    count = 0

    with open(infile, 'rb') as fh:
        block_fw = bytearray(fh.read())

    fw_len = len(block_fw)

    print('Size of app FW is %d.' % fw_len)

    if fw_len + 2 > block_size:
        print('The input file is too large (%d > %d), '
              'so there is no room to add the 2 byte checksum.\n'
              'Is it already padded to %d bytes?' %
              (fw_len, block_size - 2, block_size))
        return None

    block_ff = bytearray([0xff] * (block_size - fw_len))

    block = block_fw + block_ff

    print('Size of app block is %d.' % len(block))

    for e in block[0:block_offset_xor]:
        sum_xor ^= e
        sum_add += e
        count += 1

    print('Checksum coverage byte count is %d.' % count)

    block[block_offset_xor] = sum_xor
    block[block_offset_sum] = sum_add & 0xff

    print('Checksum XOR is 0x%02x.' % block[block_offset_xor])
    print('Checksum SUM is 0x%02x.' % block[block_offset_sum])

    return block

def main():
    """Main function."""

    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-r', '--read',
                            required=True, help='specify input file')
    arg_parser.add_argument('-w', '--write',
                            required=True, help='specify output file'
                            ' (can be same as input)')

    args = arg_parser.parse_args()
    outfile = args.write
    infile = args.read

    block = cksum2(infile)
    if not block:
        sys.exit(1)

    of = open(outfile, 'wb')
    of.write(block)
    of.close()

if __name__ == '__main__':
    main()
