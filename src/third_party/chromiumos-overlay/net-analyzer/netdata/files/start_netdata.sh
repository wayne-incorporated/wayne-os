#!/bin/sh
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

LSM_INODE_POLICIES="/sys/kernel/security/chromiumos/inode_security_policies"

UNMOUNT="false"
unmount_security_fs() {
  if [ "${UNMOUNT}" = "true" ]; then
    umount /sys/kernel/security || true
  fi
  trap - EXIT
}

allow_fifo() {
  trap unmount_security_fs EXIT

  if [ ! -e "${LSM_INODE_POLICIES}" ]; then
    mount -n -t securityfs -o nodev,noexec,nosuid securityfs \
      /sys/kernel/security && UNMOUNT="true"
  fi

  if [ -e "${LSM_INODE_POLICIES}" ]; then
    printf "/var/cache/netdata" >"${LSM_INODE_POLICIES}/allow_fifo"
  fi

  unmount_security_fs
}

allow_fifo

systemd-tmpfiles --create --remove /usr/local/lib/tmpfiles.d/on-demand/netdata.conf

exec /usr/local/sbin/netdata \
  -W set global "run as user" netdata \
  -W set global history 3600 \
  "$@"
