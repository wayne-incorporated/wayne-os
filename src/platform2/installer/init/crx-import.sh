#!/bin/sh
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script handles delayed copying of CRX files into the CRX cache in a
# validated way. This is normally only performed on first boot, and so
# will be a nearly null operation after that.

JOB=$0

# Note these paths are shared with platform/init/chromeos-cleanup-logs.
FROM=/mnt/stateful_partition/unencrypted/import_extensions
TO=/var/cache/external_cache
VALIDATION=/usr/share/import_extensions/validation

if [ ! -d "${TO}" ]; then
  TMPDIR="${TO}.tmp"
  rm -rf "${TMPDIR}"
  mkdir -m 700 "${TMPDIR}"

  # If the source directory exists, and we can validate it... import.
  if [ -d "${FROM}" ]; then
    for val in "${VALIDATION}"/*; do
      # If the import fails, we want to just keep going.
      logger -t "${JOB}" "Performing CRX import for: ${val}"
      encrypted_import "${FROM}" "${val}" "${TMPDIR}" 2>&1 | \
        logger -t "${JOB}"
    done
  else
    logger -t "${JOB}" "CRX Source not present. No import performed."
  fi
  chown -R chronos:chronos "${TMPDIR}"
  mv "${TMPDIR}" "${TO}"
else
  logger -t "${JOB}" "CRX Cache exists. No import performed."
fi

# This .dot file tells the cache manager in Chrome that the import process
# has finished. It should be created, even if we weren't actually able to
# import anything.
touch "${TO}/.initialized"
