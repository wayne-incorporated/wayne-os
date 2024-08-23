#!/bin/bash
# Copyright 2009 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Library for setting up remote access and running remote commands.

case ${SCRIPT_NAME} in
cros_show_stacks|update_kernel.sh)
  ;;
*)
  echo "remote_access.sh: This script will be removed by July 2023." >&2
  exit 1
  ;;
esac

DEFAULT_PRIVATE_KEY="${GCLIENT_ROOT}/chromite/ssh_keys/testing_rsa"
PARTNER_PRIVATE_KEY="${GCLIENT_ROOT}/sshkeys/partner_testing_rsa"

DEFINE_string remote "" "remote hostname/IP of running Chromium OS instance"
DEFINE_string private_key "$DEFAULT_PRIVATE_KEY" \
  "Private key of root account on remote host"
DEFINE_integer ssh_port 0 \
  "SSH port of the remote machine running Chromium OS instance"
DEFINE_integer ssh_connect_timeout 30 \
  "SSH connect timeout in seconds"
DEFINE_integer ssh_connection_attempts 4 \
  "SSH connection attempts"
DEFINE_boolean ssh_allow_agent ${FLAGS_FALSE} "Don't block out SSH_AUTH_SOCK"

# Returns true if $1 has at least two colons.
has_two_colons_or_more() {
  # IPv6 addresses have at least two colons while IPv4 addresses and
  # hostnames have none.
  [[ "$1" == *:*:* ]]
}

# Prints $1 enclosed with brackets if it looks like an IPv6 address
# and unchanged otherwise.
brackets_enclosed_if_ipv6() {
  local rem="$1"
  if has_two_colons_or_more "${rem}"; then
    rem="[${rem}]"
  fi
  echo "${rem}"
}

ssh_connect_settings() {
  local for_tool="$1"

  if [[ -n "$SSH_CONNECT_SETTINGS" ]]; then
    # If connection settings were fixed in an environment variable, just return
    # those values.
    echo -n "$SSH_CONNECT_SETTINGS"
  else
    # Otherwise, return the default (or user overridden) settings.
    local settings=(
      "Protocol=2"
      "ConnectTimeout=${FLAGS_ssh_connect_timeout}"
      "ConnectionAttempts=${FLAGS_ssh_connection_attempts}"
      "ServerAliveInterval=10"
      "ServerAliveCountMax=3"
      "StrictHostKeyChecking=no"
      "IdentitiesOnly=yes"
      "IdentityFile=${TMP_PRIVATE_KEY}"
      "UserKnownHostsFile=${TMP_KNOWN_HOSTS}"
      "ControlPath=${TMP_CONTROL_FILE}"
      "ControlMaster=auto"
      "ControlPersist=45"
    )
    if [[ -f "${TMP_PRIVATE_PARTNER_KEY}" ]]; then
      settings+=("IdentityFile=${TMP_PRIVATE_PARTNER_KEY}")
    fi
    printf -- '-o %s ' "${settings[@]}"

    if [[ "${FLAGS_ssh_port}" -ne 0 ]]; then
      if [[ "${for_tool}" == "scp" ]]; then
        printf -- ' -P %d ' "${FLAGS_ssh_port}"
      else
        printf -- ' -p %d ' "${FLAGS_ssh_port}"
      fi
    fi
  fi
}

# Copies $1 to $2 on remote host
remote_cp_to() {
  local scp_rem
  scp_rem="$(brackets_enclosed_if_ipv6 "${FLAGS_remote}")"
  REMOTE_OUT=$(scp $(ssh_connect_settings scp) \
    "$1" "root@${scp_rem}:$2")
  return ${PIPESTATUS[0]}
}

# Raw rsync access to the remote
# Use like: remote_rsync_raw -a /path/from/ root@${FLAGS_remote}:/path/to/
remote_rsync_raw() {
  local reason=0
  rsync -e "ssh $(ssh_connect_settings ssh)" "$@" || reason=$?
  case ${reason} in
    11 )
      # no space left on device, call handle_no_space if implemented
      if command -v handle_no_space >/dev/null; then
        handle_no_space
      fi
      ;;
    * )
      ;;
  esac
  return ${reason}
}

# Copies a list of remote files specified in file $1 to local location
# $2.  Directory paths in $1 are collapsed into $2.
remote_rsync_from() {
  local rsync_rem
  rsync_rem="$(brackets_enclosed_if_ipv6 "${FLAGS_remote}")"
  remote_rsync_raw --no-R --files-from="$1" \
    root@"${rsync_rem}:/" "$2"
}

# Send a directory from $1 to $2 on remote host
#
# Tries to use rsync -a but will fall back to tar if the remote doesn't
# have rsync.  The optional rsync flags are ignored if we fall back to tar.
#
# Use like:
# remote_send_to /build/board/lib/modules/ /lib/modules/ [optional rsync flags]
remote_send_to() {
  local rsync_rem
  if [ ! -d "$1" ]; then
    die "$1 must be a directory"
  fi

  if remote_sh rsync --version >/dev/null 2>&1; then
    rsync_rem="$(brackets_enclosed_if_ipv6 "${FLAGS_remote}")"
    remote_rsync_raw -a "${@:3}" "$1/" root@"${rsync_rem}:$2/"
  else
    tar -C "$1" -cz . | remote_sh tar -C "$2" -xz
  fi
}

_remote_sh() {
  REMOTE_OUT=$(ssh $(ssh_connect_settings ssh) \
    root@$FLAGS_remote "$@")
  return ${PIPESTATUS[0]}
}

# Wrapper for ssh that runs the commmand given by the args on the remote host
# If an ssh error occurs, re-runs the ssh command.
# Output is stored in REMOTE_OUT.
remote_sh() {
  local ssh_status=0
  _remote_sh "$@" || ssh_status=$?
  # 255 indicates an ssh error.
  if [ ${ssh_status} -eq 255 ]; then
    _remote_sh "$@"
  else
    return ${ssh_status}
  fi
}

remote_sh_raw() {
  ssh $(ssh_connect_settings ssh) \
    $EXTRA_REMOTE_SH_ARGS root@$FLAGS_remote "$@"
  return $?
}

remote_sh_allow_changed_host_key() {
  rm -f $TMP_KNOWN_HOSTS
  remote_sh "$@"
}

set_up_remote_access() {
  cp $FLAGS_private_key $TMP_PRIVATE_KEY
  chmod 0400 $TMP_PRIVATE_KEY
  if [[ -f "${PARTNER_PRIVATE_KEY}" ]]; then
      cp "${PARTNER_PRIVATE_KEY}" "${TMP_PRIVATE_PARTNER_KEY}"
      chmod 0400 "${TMP_PRIVATE_PARTNER_KEY}"
  fi

  # Verify the client is reachable before continuing
  local output
  local status=0
  if output=$(remote_sh -n "true" 2>&1); then
    :
  else
    status=$?
    echo "Could not initiate first contact with remote host"
    echo "$output"
  fi
  return $status
}

# Ask the target what board it is
learn_board() {
  [ -n "${FLAGS_board}" ] && return
  remote_sh -n grep CHROMEOS_RELEASE_BOARD /etc/lsb-release
  FLAGS_board=$(echo "${REMOTE_OUT}" | cut -d '=' -f 2)
  if [ -z "${FLAGS_board}" ]; then
    error "Board required"
    exit 1
  fi
  info "Target reports board is ${FLAGS_board}"
}

# Discover partition numbers from the target.
learn_partition_layout() {
  source <(remote_sh_raw cat /usr/sbin/write_gpt.sh)
  load_base_vars
}

# Checks whether a remote device has rebooted successfully.
#
# This uses a rapidly-retried SSH connection, which will wait for at most
# about ten seconds. If the network returns an error (e.g. host unreachable)
# the actual delay may be shorter.
#
# Return values:
#   0: The device has rebooted successfully
#   1: The device has not yet rebooted
#   255: Unable to communicate with the device
_check_if_rebooted() {
  (
    # In my tests SSH seems to be waiting rather longer than would be expected
    # from these parameters. These values produce a ~10 second wait.
    # (in a subshell to avoid clobbering the global settings)
    SSH_CONNECT_SETTINGS="$(sed \
      -e 's/\(ConnectTimeout\)=[0-9]*/\1=2/' \
      -e 's/\(ConnectionAttempts\)=[0-9]*/\1=2/' \
      <<<"$(ssh_connect_settings ssh)")"
    remote_sh_allow_changed_host_key -q -- '[ ! -e /tmp/awaiting_reboot ]'
  )
}

# Triggers a reboot on a remote device and waits for it to complete.
#
# This function will not return until the SSH server on the remote device
# is available after the reboot.
#
remote_reboot() {
  info "Rebooting ${FLAGS_remote}..."
  # 'reboot' is ran in background to make sure the command completes before
  # sshd is terminated.
  remote_sh_raw "touch /tmp/awaiting_reboot; reboot &"
  local start_time=${SECONDS}

  # Wait for five seconds before we start polling
  sleep 5

  # Add a hard timeout of 5 minutes before giving up.
  local timeout=300
  local timeout_expiry=$(( start_time + timeout ))
  while [ ${SECONDS} -lt ${timeout_expiry} ]; do
    # Used to throttle the loop -- see step_remaining_time at the bottom.
    local step_start_time=${SECONDS}

    local status=0
    _check_if_rebooted || status=$?

    local elapsed=$(( SECONDS - start_time ))
    case ${status} in
      0) printf '   %4ds: reboot complete\n' ${elapsed} >&2 ; return 0 ;;
      1) printf '   %4ds: device has not yet shut down\n' ${elapsed} >&2 ;;
      255) printf '   %4ds: can not connect to device\n' ${elapsed} >&2 ;;
      *) die "  internal error" ;;
    esac

    # To keep the loop from spinning too fast, delay until it has taken at
    # least five seconds. When we are actively trying SSH connections this
    # should never happen.
    local step_remaining_time=$(( step_start_time + 5 - SECONDS ))
    if [ ${step_remaining_time} -gt 0 ]; then
      sleep ${step_remaining_time}
   fi
  done
  die_notrace "Reboot has not completed after ${timeout} seconds; giving up."
}

# Called by clients before exiting.
# Part of the remote_access.sh interface but now empty.
cleanup_remote_access() {
  true
}

remote_access_init() {
  TMP_PRIVATE_KEY=$TMP/private_key
  TMP_PRIVATE_PARTNER_KEY="${TMP}/partner_private_key"
  TMP_KNOWN_HOSTS=$TMP/known_hosts
  TMP_CONTROL_FILE="${TMP}/ssh_control-%C"

  if [ -z "$FLAGS_remote" ]; then
    echo "Please specify --remote=<IP-or-hostname> of the Chromium OS instance"
    exit 1
  fi

  # Having SSH_AUTH_SOCK set makes our ssh connections super slow so unset
  # if it's not really needed.
  if [[ ${FLAGS_ssh_allow_agent} -eq ${FLAGS_FALSE} ]]; then
    unset SSH_AUTH_SOCK
  fi

  set_up_remote_access
}
