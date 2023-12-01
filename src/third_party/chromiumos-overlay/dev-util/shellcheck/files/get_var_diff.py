#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Generates diff of vars from get_vars.py and those existing in Data.hs."""

import itertools
from pathlib import Path
import subprocess

SCRIPT = Path(__file__).resolve()
THIRD_PARTY = SCRIPT.parent.parent.parent.parent.parent

# List of relative directories in which to find the eclasses.
eclass_rel_dirs = (
    THIRD_PARTY / 'chromiumos-overlay' / 'eclass',
    THIRD_PARTY / 'portage-stable' / 'eclass',
    THIRD_PARTY / 'eclass-overlay' / 'eclass',
)

# Runs get_vars.py with the eclass paths and store the output.
cmd = [SCRIPT.with_name('get_vars.py')] + list(
    itertools.chain(*(x.glob('*') for x in eclass_rel_dirs)))
new_output = subprocess.check_output(cmd, encoding='utf-8').splitlines()
new = []
for line in new_output:
  if '--' in line:
    new.append(line.strip())
  elif not line.strip():
    continue
  else:
    new += (line.replace('"', '').replace('\n', '').split(','))

# Reads the Data.hs relevant area and store the lines.
data_hs = THIRD_PARTY / 'shellcheck' / 'src' / 'ShellCheck' / 'Data.hs'
with data_hs.open('r', encoding='utf-8') as fp:
  record = False
  old = []
  for line in fp:
    if line.strip() == '-- autotest.eclass declared incorrectly':
      break
    if line.strip() == '-- generic ebuilds':
      record = True
    if record:
      if '--' in line:
        old.append(line.strip())
      elif not line.strip():
        continue
      else:
        old += line.replace('"', '').replace('\n', '').split(',')

# Cleans up empty bits as a result of parsing difficulties.
new = [x.strip() for x in new if x.strip()]
old = [x.strip() for x in old if x.strip()]

all_eclasses = set()

old_vars = {}
new_vars = {}

current_eclass = ''
for item in old:
  if '--' in item:
    # It's an eclass comment line.
    current_eclass = item[3:]
    all_eclasses.add(current_eclass)
    continue
  else:
    # It's a var, so add it to the dict of the current eclass.
    old_vars.setdefault(current_eclass, []).append(item)
for item in new:
  if '--' in item:
    # It's an eclass comment line.
    current_eclass = item[3:]
    all_eclasses.add(current_eclass)
    continue
  else:
    # It's a var, so add it to the dict of the current eclass.
    new_vars.setdefault(current_eclass, []).append(item)

for eclass in sorted(all_eclasses):
  if eclass in old_vars:
    if eclass not in new_vars:
      # Checks if the entire eclass is removed.
      print(f'{eclass} not present in new variables.')
      for var in old_vars[eclass]:
        print(f'\t-{var}')
      print()
    else:
      # Eclass isn't removed, so check for added or removed vars.
      toprint = '\n'.join(
          [f'\t-{x}' for x in old_vars[eclass] if x not in new_vars[eclass]] +
          [f'\t+{x}' for x in new_vars[eclass] if x not in old_vars[eclass]])
      if toprint:
        print(eclass)
        print(toprint)
  if eclass in new_vars:
    if eclass not in old_vars:
      # Checks if entire eclass is new.
      print(f'{eclass} added in new variables.')
      for var in new_vars[eclass]:
        print(f'\t+{var}')
      print()
