#!/usr/bin/python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""generate_db is a script for generating the verify_ro database.

usage: generate_db

This script generates a verify_ro_<RLZ CODE>.db file for each supported board.

This file is a hash descriptor database, which consists of Sections for
one or more Chrome OS boards. Each board description Section starts with a
line of 4 characters which is the board ID (the same as the board's RLZ code).

Each board description Section includes variable number of range
descriptor entries, each entry consisting of colon separated fields:

{a|e|g}:{h|d}:base_addr:size[:value[:value[:value...]]]]

Where

 - the first sindgle character field defines the way the range is accessed:
    a - AP flash
    e - EC flash
    g - EC flash requiring gang programming mode
 - the second single character field defines the range type
    h - Cr50 returns the hash of the range
    d - Cr50 returns actual contents of the range (hex dump)
  - the third and and forth fields are base address and size of the range
  - ranges of type 'h' include one or more values for the hash of the range.

Descriptor entries can be split along multiple lines. Each entry is
terminated by an empty line. Board description Section is completed when
another board ID or end of file is encountered.

All values are expressed in hex. Repeating empty lines and lines starting
with '#' are ignored.

Example File excerpt:

ZZAF

a:h:c10000:1000:
9d2108c5b9580f41f0676e32fe49d52157b21cd53267d9d38c5cb8c9b3e07070:
a70f8bb2522f8bf87dc968c44559b489ea62d7fbd4347b385bac134c5e3014d9


This script requires files from google storage.
URLS below in DownloadImages().

This script requires the gbb header gathered from the device
flashrom -r image.bin
flashrom -r -p ec ec.bin

These gathered images then need to be placed in a directory that matches
the DutBoard Entry below.

They are archived in google storage as follows:

gsutil cp -r images/atlas-pvt-11827.46.0/ gs://chromeos-localmirror/verify_ro/images

The current state of this archive looks like this:

moragues@moragues:~$ gsutil ls -r gs://chromeos-localmirror/verify_ro/images
gs://chromeos-localmirror/verify_ro/images/:
gs://chromeos-localmirror/verify_ro/images/

gs://chromeos-localmirror/verify_ro/images/atlas-pvt-11827.46.0/:
gs://chromeos-localmirror/verify_ro/images/atlas-pvt-11827.46.0/ec.bin
gs://chromeos-localmirror/verify_ro/images/atlas-pvt-11827.46.0/image.bin

gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.107.0/:
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.107.0/
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.107.0/README
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.107.0/ec.bin
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.107.0/image.bin

gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.86.0/:
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.86.0/
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.86.0/README
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.86.0/ec.bin
gs://chromeos-localmirror/verify_ro/images/eve-firmware-9584.86.0/image.bin

gs://chromeos-localmirror/verify_ro/images/eve-pvt/:
gs://chromeos-localmirror/verify_ro/images/eve-pvt/
gs://chromeos-localmirror/verify_ro/images/eve-pvt/README
gs://chromeos-localmirror/verify_ro/images/eve-pvt/ec.bin
gs://chromeos-localmirror/verify_ro/images/eve-pvt/image.bin

gs://chromeos-localmirror/verify_ro/images/nocturne-pvt-10984.28.0/:
gs://chromeos-localmirror/verify_ro/images/nocturne-pvt-10984.28.0/
gs://chromeos-localmirror/verify_ro/images/nocturne-pvt-10984.28.0/README
gs://chromeos-localmirror/verify_ro/images/nocturne-pvt-10984.28.0/ec.bin
gs://chromeos-localmirror/verify_ro/images/nocturne-pvt-10984.28.0/image.bin
"""

import argparse
import collections
import hashlib
import os.path
import subprocess
import sys

# DutBoard contains a configuration for a board.
#
# Fields:
#   name: Board Name
#   rlz: Board's RLZ code
#   ap: list names of ap image files to hash
#   ec: list names of ec image files to hash
#   gbb: list names of gbb image files to hash
DutBoard = collections.namedtuple('DutBoard', [
    'name', 'rlz', 'ap', 'ec', 'gbb'])

# FmapSection contains a section from "futility dump_fmap".
#
# Fields:
#   start: int - Starting offset of section
#   size: int - Size of section
#   end: int - Ending offset of section (+1)
FmapSection = collections.namedtuple('FmapSection', ['start', 'size', 'end'])


boards = [
    DutBoard(
        name='Atlas',
        rlz='XWJE',
        ap=['images/atlas-pvt-11827.46.0/image.bin'],
        ec=['images/atlas-pvt-11827.46.0/ec.bin'],
        gbb=['images/atlas-pvt-11827.46.0/image.bin']),
    DutBoard(
        name='Eve',
        rlz='ZZAF',
        ap=['images/eve-firmware-9584.86.0/image.bin',
            'images/eve-firmware-9584.107.0/image.bin'],
        ec=['images/eve-firmware-9584.86.0/ec.bin',
            'images/eve-firmware-9584.107.0/ec.bin'],
        gbb=['images/eve-pvt/image.bin',
             'images/eve-pvt/image.bin']),
    DutBoard(
        name='Nocturne',
        rlz='NBQS',
        ap=['images/nocturne-pvt-10984.28.0/image.bin'],
        ec=['images/nocturne-pvt-10984.28.0/ec.bin'],
        gbb=['images/nocturne-pvt-10984.28.0/image.bin'])]


def DownloadImages():
  """Download images using gsutil.

  If it does not exist, an images folder is created and populated using gsutil.
  """
  if not os.path.isdir('images'):
    print('Downloading Image Files')
    subprocess.call(['gsutil', '-m', 'cp', '-r',
                     'gs://chromeos-localmirror/verify_ro/images', '.'])
    print()
    print()


def ParseFmap(gbb):
  """Parse the GBB images dump_fmap output and generate a dictionary.

  Usage of dictionary:
    fmap_db = parse_fmap(gbb)
    start = fmap_db['RO_FRID_PAD'].start
    size = fmap_db['RO_FRID_PAD'].size
    end = fmap_db['RO_FRID_PAD'].end

  Args:
    gbb: The GBB filename in use.  This is uaually image.bin from the device.

  Returns:
    {str: FmapSection} - A dict mapping section name to FmapSection.
  """
  fmap_db = {}
  lines = subprocess.check_output(
      ['futility', 'dump_fmap', '-p', gbb]).decode().split('\n')
  for entry in lines:
    if entry:
      # split out name, start, end
      name, st, sz = entry.split()
      # place the entries in dictionaries for later use
      fmap_db[name] = FmapSection(
          start=int(st), size=int(sz), end=int(st)+int(sz))
  return fmap_db


def Sect(rlz, outfile):
  """Place a Section seperator in the output file.

  The Section seperator is the RLZ code followed by a blank line

  Args:
    rlz: The RLZ string
    outfile: The current output filename
  """
  outfile.write('{}\n\n'.format(rlz))


def GenerateBoard(name, rlz, ap: list, ec: list, gbb: list):
  """Output a verify_ro_RLZ.db file for a board.

  Args:
    name: Board Name
    rlz: Board's RLZ code
    ap: list of AP binary files to hash
    ec: list of EC binary files to hash
    gbb: list of GBB binary files to hash (finalized image.bin from device)
  """
  if not os.path.isdir('ro_db'):
    subprocess.run(['mkdir', '-p', 'ro_db'])
  filename = 'ro_db/verify_ro_{}.db'.format(rlz)
  outfile = open(filename, 'w')

  outfile.write('# This file was generated by the generate_db script\n')

  outfile.write('# Board name: {}\n'.format(name))
  outfile.write('# RLZ:        {}\n'.format(rlz))
  outfile.write('# AP:         {}\n'.format(ap))
  outfile.write('# EC:         {}\n'.format(ec))
  outfile.write('# GBB:        {}\n'.format(gbb))
  outfile.write('# File Name:  {}\n'.format(filename))
  outfile.write('\n')

  fmap_db = ParseFmap(gbb[0])

  # Constants from gbb_header.h
  gbb_header_hwid_digest_offset = 0x30
  gbb_header_size = 128
  gbb_hwid_size = 256

  Sect(rlz, outfile)

  # AP RO spans the range of 0xc00000..0xffffff.
  #
  # Of that range the VPD RO occupies 0xc00000 to 0xcfffff, and GBB occupies
  # 0xc11000..0xceffff.
  #
  # VPD RO is excluded completely, GBB area of 0xc11000..0xc1ffff is excluded,
  # the rest of the GBB is expected to be uninitialized and is included.

  # Note:  These values are specific to eve and nocturne and may be different
  #        for other systems.

  # SI_BIOS -> WP_RO -> FMAP start 0x00c10000 to RO_FRID_PAD end 0x00c11000
  reg_start = fmap_db['FMAP'].start
  reg_size = fmap_db['RO_FRID_PAD'].end - fmap_db['FMAP'].start
  SplitRegion('a', reg_start, reg_size, reg_size, ap, outfile)

  # Expected to be uninitialized
  SplitRegion('a', 0xc20000, 0x3e0000, 0x10000, ap, outfile)

  Sect(rlz, outfile)

  # EC RO is 32K starting at zero.
  SplitRegion('e', 0, 0x8000, 0x8000, ec, outfile)

  Sect(rlz, outfile)

  # Section for invariant areas of $name GBB.
  # Gbb header up to HWID digest'
  # Structure defined in gbb_header.h
  reg_start = fmap_db['GBB'].start
  reg_size = gbb_header_hwid_digest_offset
  SplitRegion('a', reg_start, reg_size, reg_size, gbb, outfile)

  Sect(rlz, outfile)

  # Skip HWID 32 bytes of hash at offset 0x30, 48 bytes of GBB header padding
  # and 256 bytes allocated for HWID, add GBB Header above HWID space.

  reg_start = fmap_db['GBB'].start + gbb_header_size + gbb_hwid_size

  reg_size = 0x2000
  SplitRegion('a', reg_start, reg_size, reg_size, gbb, outfile)

  # output the footer
  outfile.write('DONE\n\n')


def Dump(blob):
  """Utility function to hex dump a binary blob.

  Args:
    blob: binary blob of data
  """
  print(' '.join('{:02x}'.format(ord(blob))))


def SplitRegion(target, base: int, size: int, step: int, files: list, outfile):
  """Generate hashes for a region of the files.

  Each board description Section includes variable number of range
  descriptor entries, each entry consisting of semicolon separated fields:

  {a|e|g}:{h|d}:base_addr:size[:value[:value[:value...]]]]

  Args:
    target:
      The first sindgle character field defines the way the range is accessed:
      a - AP flash
      e - EC flash
      g - EC flash requiring gang programming mode
    base: base address of the range to hash
    size: total size of the range to hash in bytes
    step: size of each sub range to output as a line
    files: list of input files to hash
    outfile: output ro_db filename
  """
  data = []
  for input_file in files:
    with open(input_file, 'rb') as infile:
      data.append(infile.read())

  if target not in ('a', 'e', 'b'):
    raise ValueError

  offset = 0
  while offset < size:
    if size - offset > step:
      real_step = step
    else:
      real_step = size - offset
    outfile.write('{}:h:{:x}:{:x}'.format(target, base + offset, real_step))
    for blob in data:
      hasher = hashlib.sha256()
      hasher.update(blob[base + offset:base + offset + real_step])
      outfile.write(':\n{}'.format(hasher.hexdigest()))
    outfile.write('\n\n')
    offset += real_step


def main(argv):
  """Main entry point of script.

  Args:
    argv: sys.argv or equivalent

  Returns:
    An argument for sys.exit()
  """
  parser = argparse.ArgumentParser(
      description='Generate a set of veriy_ro database files',
      prog=argv[0])
  parser.parse_args(argv[1:])

  DownloadImages()
  for board in boards:
    print('Name: {}'.format(board.name))
    print('RLZ: {}'.format(board.rlz))
    print('ap: {}'.format(board.ap))
    print('ec: {}'.format(board.ec))
    print('gbb: {}'.format(board.gbb))
    print()
    GenerateBoard(board.name, board.rlz, board.ap, board.ec, board.gbb)


if __name__ == '__main__':
  sys.exit(main(sys.argv))
