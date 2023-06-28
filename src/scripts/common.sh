#!/bin/bash
# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# All scripts should die on error unless commands are specifically excepted
# by prefixing with '!' or surrounded by 'set +e' / 'set -e'.

# The number of jobs to pass to tools that can run in parallel (such as make
# and dpkg-buildpackage
if [[ -z ${NUM_JOBS:-} ]]; then
  NUM_JOBS=$(grep -c "^processor" /proc/cpuinfo)
fi
# Ensure that any sub scripts we invoke get the max proc count.
export NUM_JOBS

# Make sure we have the location and name of the calling script, using
# the current value if it is already set.
: ${SCRIPT_LOCATION:=$(dirname "$(readlink -f -- "$0")")}
: ${SCRIPT_NAME:=$(basename -- "$0")}

# Detect whether we're inside a chroot or not
CHROOT_VERSION_FILE=/etc/cros_chroot_version
if [[ -e ${CHROOT_VERSION_FILE} ]]; then
  INSIDE_CHROOT=1
else
  INSIDE_CHROOT=0
fi

# Determine and set up variables needed for fancy color output (if supported).
V_BOLD_RED=
V_BOLD_GREEN=
V_BOLD_YELLOW=
V_VIDOFF=

if [[ -t 1 ]]; then
  # order matters: we want VIDOFF last so that when we trace with `set -x`,
  # our terminal doesn't bleed colors as bash dumps the values of vars.
  V_BOLD_RED=$'\e[1;31m'
  V_BOLD_GREEN=$'\e[1;32m'
  V_BOLD_YELLOW=$'\e[1;33m'
  V_VIDOFF=$'\e[m'
fi

# Turn on bash debug support if available for backtraces.
shopt -s extdebug 2>/dev/null
set +E

# Output a backtrace. Optional parameter allows hiding the last
# frame(s) so functions like "die()" can hide their additional
# frame(s) if they wish.
_dump_trace() {
  # Default = 0 hidden frames: show everything except dump_trace
  # frame itself.
  local hidden_frames=${1:-0}
  local j n p func src line args
  p=${#BASH_ARGV[@]}

  error "$(date)"
  error "$(ps f -o pgid,ppid,pid,etime,cputime,%cpu,command)"

  # Frame 0 is ourselves so it's always suppressed / does not count.
  for (( n = ${#FUNCNAME[@]}; n > hidden_frames; --n )); do
    func=${FUNCNAME[${n} - 1]}
    line=${BASH_LINENO[${n} - 1]}
    args=
    if [[ -z ${BASH_ARGC[${n} -1]} ]]; then
      args='(args unknown, no debug available)'
    else
      for (( j = 0; j < ${BASH_ARGC[${n} -1]}; ++j )); do
        args="${args:+${args} }'${BASH_ARGV[$(( p - j - 1 ))]}'"
      done
      ! (( p -= ${BASH_ARGC[${n} - 1]} ))
    fi
    if [[ ${n} == ${#FUNCNAME[@]} ]]; then
      error "Arguments of $$: ${0##/*} ${args}"
      error "Backtrace:  (most recent call is last)"
    else
      src=${BASH_SOURCE[${n}]##*/}
      curr_func=${FUNCNAME[${n}]}
      error "$(printf ' %s:%s:%s(), called: %s %s ' \
               "${src}" "${line}" "${curr_func}" "${func}" "${args}")"
    fi
  done
}

# Declare these asap so that code below can safely assume they exist.
_message() {
  local prefix
  prefix="$(date +%H:%M:%S) $1"
  shift
  if [[ $# -eq 0 ]]; then
    echo -e "${prefix}${CROS_LOG_PREFIX:-""}:${V_VIDOFF}" >&2
    return
  fi
  (
    # Handle newlines in the message, prefixing each chunk correctly.
    # Do this in a subshell to avoid having to track IFS/set -f state.
    IFS="
"
    set +f
    set -- $*
    IFS=' '
    if [[ $# -eq 0 ]]; then
      # Empty line was requested.
      set -- ''
    fi
    for line in "$@"; do
      echo -e "${prefix}${CROS_LOG_PREFIX:-}: ${line}${V_VIDOFF}" >&2
    done
  )
}

info() {
  _message "${V_BOLD_GREEN}INFO    " "$*"
}

warn() {
  _message "${V_BOLD_YELLOW}WARNING " "$*"
}

error() {
  _message "${V_BOLD_RED}ERROR   " "$*"
}

# Log the command we're about to run, then run it.
# Useful for long running commands that often need debugging from builders.
info_run() {
  info "Running: $*"
  "$@"
}

# For all die functions, they must explicitly force set +eu;
# no reason to have them cause their own crash if we're in the middle
# of reporting an error condition then exiting.
die_err_trap() {
  local result=${1:-$?}
  local command=${2:-${BASH_COMMAND:-command unknown}}
  set +e +u

  if [[ ${result} == "0" ]]; then
    # Let callers simplify by setting us as an EXIT trap handler.
    return 0
  fi

  # Per the message, bash misreports 127 as 1 during err trap sometimes.
  # Note this fact to ensure users don't place too much faith in the
  # exit code in that case.
  set -- "Command '${command}' exited with nonzero code: ${result}"
  if [[ ${result} -eq 1 ]] && [[ -z $(type -t ${command}) ]]; then
    set -- "$@" \
       '(Note bash sometimes misreports "command not found" as exit code 1 '\
'instead of 127)'
  fi
  _dump_trace 1
  error
  error "Command failed:"
  DIE_PREFIX='  '
  die_notrace "$@"
}

# Exit this script due to a failure, outputting a backtrace in the process.
die() {
  set +e +u
  _dump_trace 1
  error
  error "Error was:"
  DIE_PREFIX='  '
  die_notrace "$@"
}

# Exit this script w/out a backtrace.
die_notrace() {
  set +e +u
  if [[ $# -eq 0 ]]; then
    set -- '(no error message given)'
  fi
  local line
  for line in "$@"; do
    error "${DIE_PREFIX}${line}"
  done
  exit 1
}

# Check for a single string in a list of space-separated strings.
# e.g. has "foo" "foo bar baz" is true, but has "f" "foo bar baz" is not.
has() { [[ " ${*:2} " == *" $1 "* ]]; }

# Directory locations inside the dev chroot; try the new default,
# falling back to user specific paths if the upgrade has yet to
# happen.
_user="${USER}"
[[ ${USER} == "root" ]] && _user="${SUDO_USER}"
_CHROOT_TRUNK_DIRS=( "/home/${_user}/trunk" /mnt/host/source )
_DEPOT_TOOLS_DIRS=( "/home/${_user}/depot_tools" /mnt/host/depot_tools )
unset _user

_process_mount_pt() {
  # Given 4 arguments; the root path, the variable to set,
  # the old location, and the new; finally, forcing the upgrade is doable
  # via if a 5th arg is provided.
  # This will then try to migrate the old to new if we can do so right now
  # (else leaving symlinks in place w/in the new), and will set $1 to the
  # new location.
  local base=${1:-/} var=$2 old=$3 new=$4 force=${5:-false}
  local _sudo=$([[ ${USER} != "root" ]] && echo sudo)
  local val=${new}
  if ${force} || [[ -L ${base}/${new} ]] || [[ ! -e ${base}/${new} ]]; then
    # Ok, it's either a symlink or this is the first run.  Upgrade if we can-
    # specifically, if we're outside the chroot and we can rmdir the old.
    # If we cannot rmdir the old, that's due to a mount being bound to that
    # point (even if we can't see it, it's there)- thus fallback to adding
    # compat links.
    if ${force} || ( [[ ${INSIDE_CHROOT} -eq 0 ]] && \
        ${_sudo} rmdir "${base}/${old}" 2>/dev/null ); then
      ${_sudo} rm -f "${base}/${new}" || :
      ${_sudo} mkdir -p "${base}/${new}" "$(dirname "${base}/${old}" )"
      ${_sudo} ln -s "${new}" "${base}/${old}"
    else
      if [[ ! -L ${base}/${new} ]]; then
        # We can't do the upgrade right now; install compatibility links.
        ${_sudo} mkdir -p "$(dirname "${base}/${new}")" "${base}/${old}"
        ${_sudo} ln -s "${old}" "${base}/${new}"
      fi
      val=${old}
    fi
  fi
  eval "${var}=\"${val}\""
}

set_chroot_trunk_dir() {
  # This takes two optional arguments; the first being the path to the chroot
  # base; this is only used by enter_chroot.  The second argument is whether
  # or not to force the new pathways; this is only used by make_chroot.  Passing
  # a non-null value for $2 forces the new paths.
  if [[ ${INSIDE_CHROOT} -eq 0 ]] && [[ -z ${1-} ]]; then
    # Can't do the upgrade, thus skip trying to do so.
    CHROOT_TRUNK_DIR="${_CHROOT_TRUNK_DIRS[1]}"
    DEPOT_TOOLS_DIR="${_DEPOT_TOOLS_DIRS[1]}"
    return
  fi
  _process_mount_pt "${1:-}" CHROOT_TRUNK_DIR "${_CHROOT_TRUNK_DIRS[@]}" \
      ${2:+true}
  _process_mount_pt "${1:-}" DEPOT_TOOLS_DIR "${_DEPOT_TOOLS_DIRS[@]}" \
      ${2:+true}
}

set_chroot_trunk_dir

# Construct a list of possible locations for the source tree.  This list is
# based on various environment variables and globals that may have been set
# by the calling script.
get_gclient_root_list() {
  if [[ ${INSIDE_CHROOT} -eq 1 ]]; then
    echo "${CHROOT_TRUNK_DIR}"
  fi

  if [[ -n ${COMMON_SH:-} ]]; then echo "$(dirname "${COMMON_SH}")/../.."; fi
  if [[ -n ${BASH_SOURCE} ]]; then echo "$(dirname "${BASH_SOURCE}")/../.."; fi
}

# Based on the list of possible source locations we set GCLIENT_ROOT if it is
# not already defined by looking for a src directory in each seach path
# location.  If we do not find a valid looking root we error out.
get_gclient_root() {
  if [[ -n ${GCLIENT_ROOT:-} ]]; then
    return
  fi

  for path in $(get_gclient_root_list); do
    if [[ -d ${path}/src ]]; then
      GCLIENT_ROOT=${path}
      break
    fi
  done

  if [[ -z ${GCLIENT_ROOT} ]]; then
    # Using dash or sh, we don't know where we are.  $0 refers to the calling
    # script, not ourselves, so that doesn't help us.
    echo "Unable to determine location for common.sh.  If you are sourcing"
    echo "common.sh from a script run via dash or sh, you must do it in the"
    echo "following way:"
    echo '  COMMON_SH="$(dirname "$0")/../../scripts/common.sh"'
    echo '  . "${COMMON_SH}"'
    echo "where the first line is the relative path from your script to"
    echo "common.sh."
    exit 1
  fi
}

# Populate the ENVIRONMENT_WHITELIST array.
load_environment_whitelist() {
  set -f
  ENVIRONMENT_WHITELIST=(
    $("${GCLIENT_ROOT}/chromite/scripts/cros_env_whitelist")
  )
  set +f
}

# Find root of source tree
get_gclient_root

# Canonicalize the directories for the root dir and the calling script.
# readlink is part of coreutils and should be present even in a bare chroot.
# This is better than just using
#     FOO="$(cd ${FOO} ; pwd)"
# since that leaves symbolic links intact.
# Note that 'realpath' is equivalent to 'readlink -f'.
SCRIPT_LOCATION=$(readlink -f "${SCRIPT_LOCATION}")
GCLIENT_ROOT=$(readlink -f "${GCLIENT_ROOT}")

# Other directories should always be pathed down from GCLIENT_ROOT.
SRC_ROOT="${GCLIENT_ROOT}/src"
SRC_INTERNAL="${GCLIENT_ROOT}/src-internal"
SCRIPTS_DIR="${SRC_ROOT}/scripts"
BUILD_LIBRARY_DIR="${SCRIPTS_DIR}/build_library"
CHROMITE_BIN="${GCLIENT_ROOT}/chromite/bin"
IMAGES_DIR="${GCLIENT_ROOT}/src/build/images"

# Load shflags
# NOTE: This code snippet is in particular used by the au-generator (which
# stores shflags in ./lib/shflags/) and should not be touched.
if [[ -f ${SCRIPTS_DIR}/lib/shflags/shflags ]]; then
  . "${SCRIPTS_DIR}/lib/shflags/shflags" || die "Couldn't find shflags"
else
  . ./lib/shflags/shflags || die "Couldn't find shflags"
fi

# Our local mirror
DEFAULT_CHROMEOS_SERVER=${CHROMEOS_SERVER:-"http://build.chromium.org/mirror"}

# Upstream mirrors and build suites come in 2 flavors
#   DEV - development chroot, used to build the chromeos image
#   IMG - bootable image, to run on actual hardware

DEFAULT_DEV_MIRROR=${CHROMEOS_DEV_MIRROR:-"${DEFAULT_CHROMEOS_SERVER}/ubuntu"}
DEFAULT_DEV_SUITE=${CHROMEOS_DEV_SUITE:-"karmic"}

DEFAULT_IMG_MIRROR=${CHROMEOS_IMG_MIRROR:-"${DEFAULT_CHROMEOS_SERVER}/ubuntu"}
DEFAULT_IMG_SUITE=${CHROMEOS_IMG_SUITE:-"karmic"}

# Default location for chroot
DEFAULT_CHROOT_DIR=${CHROMEOS_CHROOT_DIR:-"${GCLIENT_ROOT}/chroot"}

# All output files from build should go under ${DEFAULT_BUILD_ROOT}, so that
# they don't pollute the source directory.
DEFAULT_BUILD_ROOT=${CHROMEOS_BUILD_ROOT:-"${SRC_ROOT}/build"}

# Default location for event files
DEFAULT_EVENT_DIR=${DEFAULT_EVENT_DIR:-"${DEFAULT_BUILD_ROOT}/events"}

# Default event file. Format is YYYYDD.HHMM.json
DEFAULT_EVENT_FILE=${DEFAULT_EVENT_FILE:-"${DEFAULT_EVENT_DIR}/$(date +%Y%m%d.%H%M.).json"}

# Sets the default board variable for calling script.
if [[ -f ${GCLIENT_ROOT}/src/scripts/.default_board ]]; then
  DEFAULT_BOARD=$(<"${GCLIENT_ROOT}/src/scripts/.default_board")
  # Check for user typos like whitespace.
  if [[ -n ${DEFAULT_BOARD//[a-zA-Z0-9-_]} ]]; then
    die ".default_board: invalid name detected; please fix:" \
        "'${DEFAULT_BOARD}'"
  fi
fi

# Directory to store built images.  Should be set by sourcing script when used.
BUILD_DIR=

# Path to the verified boot directory where we get signing related keys/scripts.
VBOOT_DIR="${CHROOT_TRUNK_DIR}/src/platform/vboot_reference"
VBOOT_TESTKEYS_DIR="${VBOOT_DIR}/tests/testkeys"
# We load these from the chroot rather than directly from the vboot source repo
# so we work correctly even in a minilayout.
VBOOT_DEVKEYS_DIR="/usr/share/vboot/devkeys"
VBOOT_SIGNING_DIR="/usr/share/vboot/bin"

# Standard filenames
CHROMEOS_BASE_IMAGE_NAME="chromiumos_base_image.bin"
CHROMEOS_IMAGE_NAME="chromiumos_image.bin"
CHROMEOS_DEVELOPER_IMAGE_NAME="chromiumos_image.bin"
CHROMEOS_RECOVERY_IMAGE_NAME="recovery_image.bin"
CHROMEOS_TEST_IMAGE_NAME="chromiumos_test_image.bin"
CHROMEOS_FACTORY_INSTALL_SHIM_NAME="factory_install_shim.bin"
SYSROOT_SETTINGS_FILE="/var/cache/edb/chromeos"

# Install mask for portage ebuilds.  Used by build_image and gmergefs.
# TODO: Is /usr/local/autotest-chrome still used by anyone?
COMMON_INSTALL_MASK="
  *.a
  *.c
  *.cc
  *.cmake
  *.go
  *.la
  *.h
  *.hh
  *.hpp
  *.h++
  *.hxx
  *.proto
  */.keep*
  /build/initramfs
  /build/libexec/tast
  /build/manatee
  /build/rootfs/dlc
  /build/share
  /etc/init.d
  /etc/runlevels
  /etc/selinux/intermediates
  /etc/xinetd.d
  /firmware
  /lib/modules/*/vdso
  /lib/rc
  /opt/google/containers/android/vendor/lib*/pkgconfig
  /opt/google/containers/android/build
  /usr/bin/*-config
  /usr/bin/Xnest
  /usr/bin/Xvfb
  /usr/include
  /usr/lib/cros_rust_registry
  /usr/lib/debug
  /usr/lib/gopath
  /usr/lib*/pkgconfig
  /usr/local/autotest-chrome
  /usr/man
  /usr/share/aclocal
  /usr/share/cups/drv
  /usr/share/doc
  /usr/share/gettext
  /usr/share/gtk-2.0
  /usr/share/gtk-doc
  /usr/share/info
  /usr/share/man
  /usr/share/ppd
  /usr/share/openrc
  /usr/share/pkgconfig
  /usr/share/profiling
  /usr/share/readline
  /usr/src
  "

# Mask for base, dev, and test images (build_image, build_image --test)
DEFAULT_INSTALL_MASK="
  ${COMMON_INSTALL_MASK}
  /boot/config-*
  /boot/System.map-*
  /usr/local/build/autotest
  /lib/modules/*/build
  /lib/modules/*/source
  test_*.ko
  "

# Mask for factory install shim (build_image factory_install)
FACTORY_SHIM_INSTALL_MASK="
  ${DEFAULT_INSTALL_MASK}
  /opt/google/chrome
  /opt/google/containers
  /opt/google/vms
  /usr/lib64/dri
  /usr/lib/dri
  /usr/share/X11
  /usr/share/chromeos-assets/[^i]*
  /usr/share/chromeos-assets/i[^m]*
  /usr/share/fonts
  /usr/share/locale
  /usr/share/mime
  /usr/share/oem
  /usr/share/sounds
  /usr/share/tts
  /usr/share/zoneinfo
  "

# Mask for images without systemd.
SYSTEMD_INSTALL_MASK="
  /lib/systemd/network
  /usr/lib/systemd/system
"

# -----------------------------------------------------------------------------
# Functions

# Enter a chroot and restart the current script if needed
restart_in_chroot_if_needed() {
  # NB:  Pass in ARGV:  restart_in_chroot_if_needed "$@"
  if [[ ${INSIDE_CHROOT} -ne 1 ]]; then
    # Get inside_chroot path for script.
    local chroot_path="$(reinterpret_path_for_chroot "$0")"
    exec "${CHROMITE_BIN}/cros_sdk" -- "${chroot_path}" "$@"
  fi
}

# Fail unless we're inside the chroot.  This guards against messing up your
# workstation.
assert_inside_chroot() {
  if [[ ${INSIDE_CHROOT} -ne 1 ]]; then
    echo "This script must be run inside the chroot.  Run this first:"
    echo "    cros_sdk"
    exit 1
  fi
}

# Fail if we're inside the chroot.  This guards against creating or entering
# nested chroots, among other potential problems.
assert_outside_chroot() {
  if [[ ${INSIDE_CHROOT} -ne 0 ]]; then
    echo "This script must be run outside the chroot."
    exit 1
  fi
}

assert_not_root_user() {
  if [[ ${UID:-$(id -u)} == 0 ]]; then
    echo "This script must be run as a non-root user."
    exit 1
  fi
}

assert_root_user() {
  if [[ ${UID:-$(id -u)} != 0 ]] || [[ ${SUDO_USER:-root} == "root" ]]; then
    die_notrace "This script must be run using sudo from a non-root user."
  fi
}

# Writes stdin to the given file name as root using sudo in overwrite mode.
#
# $1 - The output file name.
sudo_clobber() {
  sudo tee "$1" >/dev/null
}

# Execute multiple commands in a single sudo. Generally will speed things
# up by avoiding multiple calls to `sudo`. If any commands fail, we will
# call die with the failing command. We can handle a max of ~100 commands,
# but hopefully no one will ever try that many at once.
#
# $@ - The commands to execute, one per arg.
sudo_multi() {
  local i cmds

  # Construct the shell code to execute. It'll be of the form:
  # ... && ( ( command ) || exit <command index> ) && ...
  # This way we know which command exited. The exit status of
  # the underlying command is lost, but we never cared about it
  # in the first place (other than it is non zero), so oh well.
  for (( i = 1; i <= $#; ++i )); do
    cmds+=" && ( ( ${!i} ) || exit $(( i + 10 )) )"
  done

  # Execute our constructed shell code.
  sudo -- sh -c ":${cmds[*]}" && i=0 || i=$?

  # See if this failed, and if so, print out the failing command.
  if [[ $i -gt 10 ]]; then
    : $(( i -= 10 ))
    die "sudo_multi failed: ${!i}"
  elif [[ $i -ne 0 ]]; then
    die "sudo_multi failed for unknown reason $i"
  fi
}

# Clears out stale shadow-utils locks in the given target root.
sudo_clear_shadow_locks() {
  info "Clearing shadow utils lockfiles under $1"
  sudo rm -f "$1/etc/"{passwd,group,shadow,gshadow}.lock*
}

# Locate all mounts below a specified directory.
#
# $1 - The root tree.
sub_mounts() {
  # Assume that `mount` outputs a list of mount points in the order
  # that things were mounted (since it always has and hopefully always
  # will).  As such, we have to unmount in reverse order to cleanly
  # unmount submounts (think /dev/pts and /dev).
  awk -v path="$1" -v len="${#1}" \
    '(substr($2, 1, len+1) == path ||
      substr($2, 1, len+1) == (path "/")) { print $2 }' /proc/mounts | \
    tac | \
    sed -e 's/\\040(deleted)$//'
  # Hack(zbehan): If a bind mount's source is mysteriously removed,
  # we'd end up with an orphaned mount with the above string in its name.
  # It can only be seen through /proc/mounts and will stick around even
  # when it should be gone already. crosbug.com/31250
}

# Unmounts a directory, if the unmount fails, warn, and then lazily unmount.
#
# $1 - The path to unmount.
safe_umount_tree() {
  local mount_point="$1"

  local mounts=( $(sub_mounts "${mount_point}") )

  # Silently return if the mount_point was already unmounted.
  if [[ ${#mounts[@]} -eq 0 ]]; then
    return 0
  fi

  # First try to unmount in one shot to speed things up.
  if LC_ALL=C safe_umount -d "${mounts[@]}"; then
      return 0
  fi

  # Well that didn't work, so lazy unmount remaining ones.
  warn "Failed to unmount ${mounts[@]}, these are the processes using the" \
    "mount points."
  sudo fuser -vm "${mount_point}" || true

  warn "Doing a lazy unmount"
  if ! safe_umount -d -l "${mounts[@]}"; then
    mounts=( $(sub_mounts "${mount_point}") )
    die "Failed to lazily unmount ${mounts[@]}"
  fi
}


# Run umount as root.
safe_umount() {
  $([[ ${UID:-$(id -u)} != 0 ]] && echo sudo) umount "$@"
}

# Setup a loopback device for a file and scan for partitions, with retries.
#
# $1 - The file to back the new loopback device.
# $2-$N - Additional arguments to pass to losetup.
loopback_partscan() {
  local lb_dev image="$1"
  shift

  # We set up a binary backoff for adding the partitions. We give 10 attempts
  # each time nth time we fail, backing off by 1<<n. The maximum time then
  # spent sleeping will be sum(2^n) from [0...10] which is 1023 seconds,
  # or ~37 minutes.
  local i partx_out partx_d_out sleep_seconds=1
  for (( i = 0; i <= 10; i++ )); do
    # Flush any dirty pages in the image before we do partx commands.
    info "Running sync -f ${image}"
    sync -f "${image}"

    # This (perhaps) mounts the partitions as well.
    lb_dev=$(sudo losetup --show -f "$@" "${image}")

    # Try to clean the slate by removing any existing parts (best effort).
    partx_d_out=$(sudo partx -v -d "${lb_dev}") || true

    # Try to add the partitions back.
    if ! partx_out=$(sudo partx -v -a "${lb_dev}"); then
      local proc_parts
      warn "Adding partitions with 'partx -v -a ${lb_dev}' failed."
      warn "partx -d output:\n${partx_d_out}"
      warn "partx -a output:\n${partx_out}"
      proc_parts=$(cat /proc/partitions)
      warn "/proc/partitions before detaching loopback:\n ${proc_parts}"
      # Detach the image.
      sudo losetup -d "${lb_dev}" || true
      proc_parts=$(cat /proc/partitions)
      warn "/proc/partitions after detaching loopback:\n ${proc_parts}"
      warn "Sleeping ${sleep_seconds} before trying again."
      sleep "${sleep_seconds}"
      : $(( sleep_seconds <<= 1 ))
    else
      break
    fi
  done

  echo "${lb_dev}"
}

# Detach a loopback device set up earlier.
#
# $1 - The loop device to detach.
# $2-$N - Additional arguments to pass to losetup.
loopback_detach() {
  # Retry the deletes before we detach.  crbug.com/469259
  local i
  for (( i = 0; i < 10; i++ )); do
    if sudo partx -d "$1"; then
      break
    fi
    warn "Sleeping & retrying ..."
    sync
    sleep 1
  done
  sudo losetup --detach "$@"
}

# Sets up symlinks for the developer root. It is necessary to symlink
# usr and local since the developer root is mounted at /usr/local and
# applications expect to be installed under /usr/local/bin, etc.
# This avoids packages installing into /usr/local/usr/local/bin.
# $1 specifies the symlink target for the developer root.
# $2 specifies the symlink target for the var directory.
# $3 specifies the location of the stateful partition.
setup_symlinks_on_root() {
  # Give args better names.
  local dev_image_target=$1
  local var_target=$2
  local dev_image_root="$3/dev_image"

  # Make sure the dev_image dir itself exists.
  if [[ ! -d "${dev_image_root}" ]]; then
    sudo mkdir "${dev_image_root}"
  fi

  # If our var target is actually the standard var, we are cleaning up the
  # symlinks (could also check for /usr/local for the dev_image_target).
  if [[ ${var_target} == "/var" ]]; then
    echo "Cleaning up /usr/local symlinks for ${dev_image_root}"
  else
    echo "Setting up symlinks for /usr/local for ${dev_image_root}"
  fi

  # Set up symlinks that should point to ${dev_image_target}.
  local path
  for path in usr local; do
    if [[ -h ${dev_image_root}/${path} ]]; then
      sudo unlink "${dev_image_root}/${path}"
    elif [[ -e ${dev_image_root}/${path} ]]; then
      die "${dev_image_root}/${path} should be a symlink if exists"
    fi
    sudo ln -s "${dev_image_target}" "${dev_image_root}/${path}"
  done

  # Setup var symlink.
  if [[ -h ${dev_image_root}/var ]]; then
    sudo unlink "${dev_image_root}/var"
  elif [[ -e ${dev_image_root}/var ]]; then
    die "${dev_image_root}/var should be a symlink if it exists"
  fi

  sudo ln -s "${var_target}" "${dev_image_root}/var"
}

# Get current timestamp. Assumes common.sh runs at startup.
start_time=$(date +%s)

# Get time elapsed since start_time in seconds.
_get_elapsed_seconds() {
  local end_time=$(date +%s)
  local elapsed_seconds=$(( end_time - start_time ))
  echo ${elapsed_seconds}
}

# Print time elapsed since start_time.
print_time_elapsed() {
  # Optional first arg to specify elapsed_seconds.  If not given, will
  # recalculate elapsed time to now.  Optional second arg to specify
  # command name associated with elapsed time.
  local elapsed_seconds=${1:-$(_get_elapsed_seconds)}
  local cmd_base=${2:-}

  local minutes=$(( elapsed_seconds / 60 ))
  local seconds=$(( elapsed_seconds % 60 ))

  if [[ -n ${cmd_base} ]]; then
    info "Elapsed time (${cmd_base}): ${minutes}m${seconds}s"
  else
    info "Elapsed time: ${minutes}m${seconds}s"
  fi
}

command_completed() {
  # Call print_elapsed_time regardless.
  local run_time=$(_get_elapsed_seconds)
  local cmd_base=$(basename "$0")
  print_time_elapsed ${run_time} ${cmd_base}
}

# Load configuration files that allow board-specific overrides of default
# functionality to be specified in overlays.
# $1 - File to load.
load_board_specific_script() {
  local file=$1 overlay
  [[ $# -ne 1 ]] && die "load_board_specific_script requires exactly 1 param"
  for overlay in ${BOARD_OVERLAY}; do
    local setup_sh="${overlay}/scripts/${file}"
    if [[ -e ${setup_sh} ]]; then
      source "${setup_sh}"
    fi
  done
}

# Reinterprets path from outside the chroot for use inside.
# Returns "" if "" given.
# $1 - The path to reinterpret.
reinterpret_path_for_chroot() {
  if [[ ${INSIDE_CHROOT} -ne 1 ]]; then
    if [[ -z $1 ]]; then
      echo ""
    else
      local path_abs_path=$(readlink -f "$1")
      local gclient_root_abs_path=$(readlink -f "${GCLIENT_ROOT}")

      # Strip the repository root from the path.
      local relative_path=$(echo ${path_abs_path} \
          | sed "s:${gclient_root_abs_path}/::")

      if [[ ${relative_path} == "${path_abs_path}" ]]; then
        die "Error reinterpreting path.  Path $1 is not within source tree."
      fi

      # Prepend the chroot repository path.
      echo "/mnt/host/source/${relative_path}"
    fi
  else
    # Path is already inside the chroot :).
    echo "$1"
  fi
}

# Echo a list of cross-* ebuilds to exclude from eclean.
get_eclean_exclusions() {
  qlist -IC ^cross-
}

switch_to_strict_mode() {
  # Set up strict execution mode; note that the trap
  # must follow switch_to_strict_mode, else it will have no effect.
  set -e
  trap 'die_err_trap' ERR
  if [[ $# -ne 0 ]]; then
    set "$@"
  fi
}

# TODO: Re-enable this once shflags is set -e safe.
#switch_to_strict_mode
