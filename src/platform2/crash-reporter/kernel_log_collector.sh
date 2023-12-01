#!/bin/sh

# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Usage example: "kernel_log_collector.sh XXX YYY"
# This script searches logs in the /var/log/messages which have the keyword XXX.
# And only those logs which are within the last YYY seconds of the latest log
# that has the keyword XXX are printed.

# Kernel log has the possible formats:
# 2013-06-14T16:31:40.514513-07:00 WARNING kernel: [    2.682472] MSG MSG ...
# 2013-06-19T20:38:58.661826+00:00 INFO kernel: [    1.668092] MSG MSG ...

if [ $# -ne 2 ]; then
  echo "Usage: kernel_log_collector.sh <search key> <time duration>" >&2
  exit 1
fi

search_key="$1"
time_duration="$2"
msg_pattern="^[0-9-]*T[0-9:.+-]* [A-Z]* kernel"

die() {
  echo "kernel_log_collector: $*" >&2
  exit 1
}

get_timestamp() {
  timestamp="$(echo "$1" | cut -d " " -f 1)"
  timestamp="$(date -d "${timestamp}" +%s)" || exit $?
  echo "${timestamp}"
}

last_line="$(grep -a "${msg_pattern}" /var/log/messages | \
    grep -- "${search_key}" | tail -n 1)"

if [ -n "${last_line}" ]; then
  if ! allowed_timestamp="$(get_timestamp "${last_line}")"; then
    die "coule not get timestamp from: ${last_line}"
  fi
  : $(( allowed_timestamp -= time_duration ))
  grep -a "${msg_pattern}" /var/log/messages | grep -- "${search_key}" |
      while read -r line; do
        if ! timestamp="$(get_timestamp "${line}")"; then
          die "could not get timestamp from: ${line}"
        fi
        if [ "${timestamp}" -gt "${allowed_timestamp}" ]; then
          echo "${line}"
        fi
      done
fi

echo "END-OF-LOG"

