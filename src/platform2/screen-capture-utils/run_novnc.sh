#!/bin/bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

help() {
  echo "
  run_novnc.sh [--direct] HOST

--direct: Allow connection to the host directly by opening up firewall rules.
" >&2
}

main() {
  local remote_command="kmsvnc & novnc & wait"
  while true; do
    case "${1}" in
      --direct)
        remote_command="\
iptables -I INPUT -p tcp --dport 6080 -j ACCEPT && ${remote_command}"
        shift
        ;;
      --help)
        help
        exit
        ;;
      *)
        break
        ;;
    esac
  done
  local host="${1}"

  if [ -z  "${host}" ]; then
    help
    exit 1
  fi
  ssh -o ExitOnForwardFailure=yes -L 6080:localhost:6080 "${host}" \
    "${remote_command}"
}

main "$@"
