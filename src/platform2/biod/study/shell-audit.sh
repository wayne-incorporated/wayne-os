#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This snippet should be sourced by a bash shell to enable logging
# of all bash commands executed.
# This currently does not differentiate between an interactive or
# non-interactive terminal.
#
# This file can be placed in the system bashrc.d, so that it is
# automatically sourced by all bash shells. On Chrome OS, this is
# /etc/bash/bashrc.d directory.

# Indicate in the log that a new bash shell has been launched.
logger -p local1.info -t bash --id=$$ -- "${USER}: Sourced shell-audit.sh"

# Enable logging of all bash commands moments before being executed.
audit-cmdline-before() {
  # Specific commands are noted as higher priority
  # to make them easier to spot when conducting a privacy audit.
  # One specific example of when this is useful is when checking that a
  # participant was removed from the capture database.
  local pri=info
  local -a cmd_parts
  read -ra cmd_parts <<<"${BASH_COMMAND}"
  case "${cmd_parts[0]}" in
    cp|rm|mv|shred) pri=notice ;;
  esac

  logger -p "local1.${pri}" -t bash --id=$$ -- \
    "${USER}: (${PWD}) ${BASH_COMMAND}"
}
trap audit-cmdline-before DEBUG

# Turn off any possible odd post commands. These can contaminate the log.
PROMPT_COMMAND=
