#!/bin/sh
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

umask 022
mkdir -p -m 0711 $LOCKBOX_CACHE_DIR
# /sbin/mount-encrypted emits the TPM NVRAM contents, if they exist, to a
# file on tmpfs which is used to authenticate the lockbox during cache
# creation.
if [ -O $LOCKBOX_NVRAM_FILE ]; then
  lockbox-cache --cache=$INSTALL_ATTRS_CACHE \
                --nvram=$LOCKBOX_NVRAM_FILE \
                --lockbox=$INSTALL_ATTRS_FILE
  # There are no other consumers; remove the nvram data
  rm $LOCKBOX_NVRAM_FILE
fi
