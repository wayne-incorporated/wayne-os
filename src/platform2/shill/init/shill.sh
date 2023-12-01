#!/bin/sh
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Set logging level and scope if sticky flag exists.
if [ -f /var/cache/modem-utilities/log_shill_verbose3 ]; then
  # Only set SHILL_LOG_LEVEL if no value was set
  if [ -z "${SHILL_LOG_LEVEL}" ]; then
    SHILL_LOG_LEVEL="-3"
  fi
  APPEND_SCOPES="cellular+modem+device+dbus+manager"
  if [ -z "${SHILL_LOG_SCOPES}" ]; then
    SHILL_LOG_SCOPES="${APPEND_SCOPES}"
  else
    SHILL_LOG_SCOPES="${SHILL_LOG_SCOPES}+${APPEND_SCOPES}"
  fi
fi
if [ -z "${SHILL_LOG_LEVEL}" ]; then
  SHILL_LOG_LEVEL=0
fi
set -- "$@" --log-level="${SHILL_LOG_LEVEL}" --log-scopes="${SHILL_LOG_SCOPES}"

if [ -n "${SHILL_LOG_VMODULES}" ]; then
  set -- "$@" --vmodule="${SHILL_LOG_VMODULES}"
fi

if [ -n "${BLOCKED_DEVICES}" ] && [ -n "${SHILL_TEST_DEVICES}" ]; then
  set -- "$@" --devices-blocked="${BLOCKED_DEVICES},${SHILL_TEST_DEVICES}"
elif [ -n "${BLOCKED_DEVICES}" ]; then
  set -- "$@" --devices-blocked="${BLOCKED_DEVICES}"
elif [ -n "${SHILL_TEST_DEVICES}" ]; then
  set -- "$@" --devices-blocked="${SHILL_TEST_DEVICES}"
fi

if [ -n "${ALLOWED_DEVICES}" ]; then
  set -- "$@" --devices-allowed="${ALLOWED_DEVICES}"
fi

# Run shill as shill user/group in a minijail:
#   -G so shill programs can inherit supplementary groups.
#   -n to run shill with no_new_privs.
#   -B 20 to avoid locking SECURE_KEEP_CAPS flag.
#   -c for runtime capabilities:
#     CAP_WAKE_ALARM | CAP_NET_RAW | CAP_NET_ADMIN | CAP_NET_BROADCAST |
#     CAP_NET_BIND_SERVICE | CAP_SETPCAP | CAP_SETUID | CAP_SETGID | CAP_KILL
#   --ambient so child processes can inherit runtime capabilities.
#   -i to lose the dangling minijail0 process.
exec /sbin/minijail0 -u shill -g shill -G -n -B 20 -c 800003de0 --ambient -i \
     -- /usr/bin/shill "$@"
