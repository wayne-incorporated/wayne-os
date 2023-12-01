#!/bin/bash

# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -x

# Use this script to generate an initial list of syscalls to whitelist with
# seccomp. Note that it will generate two files, each of which ends with the
# PID of the process that ran; you only need to analyze the file with the
# higher PID since the first is the runuser process.

OUTPUT_DIR="$(date --iso-8601=seconds)"
mkdir "${OUTPUT_DIR}"

stop biod || true

if [ "$1" == "--minijail" ]; then
  strace -ff -o "${OUTPUT_DIR}/strace.log"                                     \
  minijail0                                                                    \
    --uts                                                                      \
    -e                                                                         \
    -l                                                                         \
    -N                                                                         \
    -p                                                                         \
    -Kslave                                                                    \
    -v                                                                         \
    --profile minimalistic-mountns                                             \
    -k 'tmpfs,/run,tmpfs,MS_NODEV|MS_NOEXEC|MS_NOSUID,mode=755,size=10M'       \
    -b /run/dbus                                                               \
    -b /run/chromeos-config/v1                                                 \
    -k '/run/daemon-store/biod,/run/daemon-store/biod,none,MS_BIND|MS_REC'     \
    -k 'tmpfs,/var,tmpfs,MS_NODEV|MS_NOEXEC|MS_NOSUID,mode=755,size=10M'       \
    -b /var/log/biod,,1                                                        \
    -b /var/lib/metrics,,1                                                     \
    -b /dev/cros_fp                                                            \
    -b /dev/uinput                                                             \
    -b /sys                                                                    \
    -u biod -g biod                                                            \
    -G                                                                         \
    -c 0                                                                       \
    -n                                                                         \
    -S /usr/share/policy/biod-seccomp.policy                                   \
    -- /usr/bin/biod                                                           \
    --log_dir=/var/log/biod                                                    \
    >/var/log/biod.out 2>&1

  exit 0
fi

strace -ff -o "${OUTPUT_DIR}/strace.log" runuser -u biod -g biod \
    -- /usr/bin/biod --log_dir=/var/log/biod >/var/log/biod.out
