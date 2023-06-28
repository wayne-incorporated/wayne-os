#!/bin/bash

# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to enter the chroot environment

SCRIPT_ROOT=$(readlink -f $(dirname "$0")/..)
. "${SCRIPT_ROOT}/common.sh" || exit 1

# Script must be run outside the chroot and as root.
assert_outside_chroot
assert_root_user

# Define command line flags
# See http://code.google.com/p/shflags/wiki/Documentation10x
DEFINE_string chroot "$DEFAULT_CHROOT_DIR" \
  "The destination dir for the chroot environment." "d"
DEFINE_string trunk "$GCLIENT_ROOT" \
  "The source trunk to bind mount within the chroot." "s"
DEFINE_string build_number "" \
  "The build-bot build number (when called by buildbot only)." "b"
DEFINE_string chrome_root "" \
  "The root of your chrome browser source. Should contain a 'src' subdir."
DEFINE_string chrome_root_mount "/home/${SUDO_USER}/chrome_root" \
  "The mount point of the chrome broswer source in the chroot."
DEFINE_string cache_dir "" "Directory to use for caching."
DEFINE_string goma_dir "" "Goma installed directory."
DEFINE_string goma_client_json "" "Service account json file for goma."
DEFINE_string reclient_dir "" "Reclient binaries installed directory."
DEFINE_string reproxy_cfg_file "" "Config file for re-client's reproxy."
DEFINE_string working_dir "" \
  "The working directory relative to ${CHROOT_TRUNK_DIR} for the command in \
chroot, must start with '/' if set."

DEFINE_boolean ssh_agent $FLAGS_TRUE "Import ssh agent."
DEFINE_boolean early_make_chroot $FLAGS_FALSE \
  "Internal flag.  If set, the command is run as root without sudo."
DEFINE_boolean verbose $FLAGS_FALSE "Print out actions taken"

# More useful help
FLAGS_HELP="USAGE: $0 [flags] [VAR=value] [-- command [arg1] [arg2] ...]

One or more VAR=value pairs can be specified to export variables into
the chroot environment.  For example:

   $0 FOO=bar BAZ=bel

If [-- command] is present, runs the command inside the chroot,
after changing directory to /${SUDO_USER}/trunk/src/scripts.  Note that neither
the command nor args should include single quotes.  For example:

    $0 -- ./build_platform_packages.sh

Otherwise, provides an interactive shell.
"

CROS_LOG_PREFIX=cros_sdk:enter_chroot
SUDO_HOME=$(eval echo ~${SUDO_USER})

# Version of info from common.sh that only echos if --verbose is set.
debug() {
  if [ $FLAGS_verbose -eq $FLAGS_TRUE ]; then
    info "$*"
  fi
}

# Parse command line flags
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

[ -z "${FLAGS_cache_dir}" ] && \
  die "--cache_dir is required"

# Only now can we die on error.  shflags functions leak non-zero error codes,
# so will die prematurely if 'switch_to_strict_mode' is specified before now.
# TODO: replace shflags with something less error-prone, or contribute a fix.
switch_to_strict_mode

# These config files are to be copied into chroot if they exist in home dir.
# Additionally, git relevant files are copied by setup_git.
FILES_TO_COPY_TO_CHROOT=(
  # Creds used to authenticate with LUCI services.
  .config/chrome_infra/auth/creds.json
  .gdata_cred.txt             # User/password for Google Docs on chromium.org
  .gdata_token                # Auth token for Google Docs on chromium.org
  .goma_client_oauth2_config  # Auth token for Goma
  .inputrc                    # Preserve command line customizations
)
if [[ "${SUDO_USER:-${USER}}" == "chrome-bot" ]]; then
  # Builders still haven't migrated fully to gitcookies.
  # https://crbug.com/1032944
  FILES_TO_COPY_TO_CHROOT+=( .netrc )
fi

INNER_CHROME_ROOT=$FLAGS_chrome_root_mount  # inside chroot
CHROME_ROOT_CONFIG="/var/cache/chrome_root"  # inside chroot
FUSE_DEVICE="/dev/fuse"

# We can't use /var/lock because that might be a symlink to /run/lock outside
# of the chroot.  Or /run on the host system might not exist.
LOCKFILE="${FLAGS_chroot}/.enter_chroot.lock"
MOUNTED_PATH=$(readlink -f "$FLAGS_chroot")

# Reset the depot tools/internal trunk pathways to what they'll
# be w/in the chroot.
set_chroot_trunk_dir "${FLAGS_chroot}"

# Writes stdin to the given file name as the sudo user in overwrite mode.
#
# $@ - The output file names.
user_clobber() {
  install -m644 -o ${SUDO_UID} -g ${SUDO_GID} /dev/stdin "$@"
}

# Copies the specified file owned by the user to the specified location.
# If the copy fails as root (e.g. due to root_squash and NFS), retry the copy
# with the user's account before failing.
user_cp() {
  cp -p "$@" 2>/dev/null || sudo -u ${SUDO_USER} -- cp -p "$@"
}

# Appends stdin to the given file name as the sudo user.
#
# $1 - The output file name.
user_append() {
  cat >> "$1"
  chown ${SUDO_UID}:${SUDO_GID} "$1"
}

# Create the specified directory, along with parents, as the sudo user.
#
# $@ - The directories to create.
user_mkdir() {
  install -o ${SUDO_UID} -g ${SUDO_GID} -d "$@"
}

# Create the specified symlink as the sudo user.
#
# $1 - Link target
# $2 - Link name
user_symlink() {
  ln -sfT "$1" "$2"
  chown -h ${SUDO_UID}:${SUDO_GID} "$2"
}

setup_mount() {
  # If necessary, mount $source in the host FS at $target inside the
  # chroot directory with $mount_args. We don't write to /etc/mtab because
  # these mounts are all contained within an unshare and are therefore
  # inaccessible to other namespaces (e.g. the host desktop system).
  local source="$1"
  local mount_args="-n $2"
  local target="$3"

  local mounted_path="${MOUNTED_PATH}$target"

  case " ${MOUNT_CACHE} " in
  *" ${mounted_path} "*)
    # Already mounted!
    ;;
  *)
    # If it doesn't exist, assume they want a dir.  But don't blindly run
    # it all the time in case they're trying to bind mount a file.
    if [[ ! -e ${mounted_path} ]]; then
      mkdir -p "${mounted_path}"
    fi
    # The args are left unquoted on purpose.
    if [[ -n ${source} ]]; then
      mount ${mount_args} "${source}" "${mounted_path}"
    else
      mount ${mount_args} "${mounted_path}"
    fi
    ;;
  esac
}

copy_ssh_config() {
  # Copy user .ssh/config into the chroot filtering out strings not supported
  # by the chroot ssh. The chroot .ssh directory is passed in as the first
  # parameter.

  # ssh options to filter out. The entire strings containing these substrings
  # will be deleted before copying.
  local bad_options=(
    'UseProxyIf'
    'GSSAPIAuthentication'
    'GSSAPIKeyExchange'
    'ProxyUseFdpass'
  )
  local sshc="${SUDO_HOME}/.ssh/config"
  local chroot_ssh_dir="${1}"
  local filter
  local option

  if ! user_cp "${sshc}" "${chroot_ssh_dir}/config.orig" 2>/dev/null; then
    return # Nothing to copy.
  fi

  for option in "${bad_options[@]}"
  do
    if [ -z "${filter}" ]; then
      filter="${option}"
    else
      filter+="\\|${option}"
    fi
  done

  (
  cat <<EOF
### DO NOT EDIT ###
# File is imported & synced from the copy outside of the SDK.
# Modifications to this version will be lost!
#
# If you want directives to change behavior between inside & outside of the SDK:
#   Match Exec "test -f /etc/cros_chroot_version"

EOF
  sed "/^.*\(${filter}\).*$/d" "${chroot_ssh_dir}/config.orig"
  ) | user_clobber "${chroot_ssh_dir}/config"
}

copy_into_chroot_if_exists() {
  # $1 is file path outside of chroot to copy to path $2 inside chroot.
  if [[ -e "$1" ]]; then
    local dir
    dir=$(dirname "${FLAGS_chroot}/$2")
    if [[ ! -d "${dir}" ]]; then
      user_mkdir "${dir}"
    fi
    user_cp "$1" "${FLAGS_chroot}/$2"
  fi
}

# Usage: promote_api_keys
# This takes care of getting the developer API keys into the chroot where
# chrome can build with them.  It needs to take it from the places a dev
# is likely to put them, and recognize that older chroots may or may not
# have been used since the concept of keys got added, as well as before
# and after the developer deciding to grab their own keys.
promote_api_keys() {
  local destination="${FLAGS_chroot}/home/${SUDO_USER}/.googleapikeys"
  # Don't disturb existing keys.  They could be set differently
  if [[ -s "${destination}" ]]; then
    return 0
  fi
  if [[ -r "${SUDO_HOME}/.googleapikeys" ]]; then
    cp -p "${SUDO_HOME}/.googleapikeys" "${destination}"
    if [[ -s "${destination}" ]] ; then
      info "Copied Google API keys into chroot."
    fi
  elif [[ -r "${SUDO_HOME}/.gyp/include.gypi" ]]; then
    local NAME="('google_(api_key|default_client_(id|secret))')"
    local WS="[[:space:]]*"
    local CONTENTS="('[^\\\\']*')"
    sed -nr -e "/^${WS}${NAME}${WS}[:=]${WS}${CONTENTS}.*/{s//\1: \4,/;p;}" \
         "${SUDO_HOME}/.gyp/include.gypi" | user_clobber "${destination}"
    if [[ -s "${destination}" ]]; then
      info "Put discovered Google API keys into chroot."
    fi
  fi
}

# Sanity check the user's environment locale settings.
check_locale() {
  if [[ "$(locale -k charmap)" != 'charmap="UTF-8"' ]]; then
    error "Your locale appears to not support UTF-8 which is required."
    error "The output from 'locale':"
    locale
    error "The output from 'locale -k LC_CTYPE':"
    locale -k LC_CTYPE
    error "The language env vars:"
    env | grep -E '^(LC_|LANG)'
    if [[ -n "${LC_ALL}" ]]; then
      error "Never set LC_ALL (=${LC_ALL}) in your environment; only set LANG."
    fi
    die_notrace "Please fix your locale settings by setting LANG to UTF-8" \
      "compatible locale and removing any LC_ variable settings."
  fi
}

generate_locales() {
  # Make sure user's requested locales are available
  # http://crosbug.com/19139
  # And make sure en_US{,.UTF-8} are always available as
  # that what buildbot forces internally
  local l locales gen_locales=()

  locales=$(printf '%s\n' en_US en_US.UTF-8 ${LANG} \
    $LC_{ADDRESS,ALL,COLLATE,CTYPE,IDENTIFICATION,MEASUREMENT,MESSAGES} \
    $LC_{MONETARY,NAME,NUMERIC,PAPER,TELEPHONE,TIME} | \
    sort -u | sed '/^C$/d')
  for l in ${locales}; do
    if [[ ${l} == *.* ]]; then
      enc=${l#*.}
    else
      enc="ISO-8859-1"
    fi
    case $(echo ${enc//-} | tr '[:upper:]' '[:lower:]') in
    utf8) enc="UTF-8";;
    esac
    gen_locales+=("${l} ${enc}")
  done
  if [[ ${#gen_locales[@]} -gt 0 ]] ; then
    # Force LC_ALL=C to workaround slow string parsing in bash
    # with long multibyte strings.  Newer setups have this fixed,
    # but locale-gen doesn't need to be run in any locale in the
    # first place, so just go with C to keep it fast.
    # Force jobs=1 to work around locale-gen weirdness where it simultaneously
    # wants to and doesn't want to run multiple jobs (and complains about it).
    # crbug.com/761153
    # Force PATH to the right value inside the SDK in case the host distro has
    # its own incompatible setup.
    chroot "${FLAGS_chroot}" env LC_ALL=C PATH='/bin:/sbin:/usr/bin:/usr/sbin' \
      locale-gen -q -u -j 1 -G "$(printf '%s\n' "${gen_locales[@]}")"
  fi
}

git_config() {
  USER="${SUDO_USER:-${USER}}" \
  HOME="${SUDO_HOME:-${HOME}}" \
  git config "$@"
}

# The --type=path option is new to git-2.18 and not everyone upgrades.
# But not everyone uses the ~ prefix, so try that option if needed.
git_config_path() {
  local out
  out=$(git_config "$@")
  if [[ "${out:0:1}" == "~" ]]; then
    git_config --type path "$@"
  else
    echo "${out}"
  fi
}

setup_git() {
  # Copy .gitconfig into chroot so repo and git can be used from inside.
  # This is required for repo to work since it validates the email address.
  copy_into_chroot_if_exists "${SUDO_HOME}/.gitconfig" \
      "/home/${SUDO_USER}/.gitconfig"
  local -r chroot_gitconfig="${FLAGS_chroot}/home/${SUDO_USER}/.gitconfig"

  # If the user didn't set up their username in their gitconfig, look
  # at the default git settings for the user.
  if ! git config -f "${chroot_gitconfig}" user.email >& /dev/null; then
    local ident=$(cd /; sudo -u ${SUDO_USER} -- git var GIT_COMMITTER_IDENT || \
                  :)
    local ident_name=${ident%% <*}
    local ident_email=${ident%%>*}; ident_email=${ident_email##*<}
    git config -f "${chroot_gitconfig}" --replace-all user.name \
        "${ident_name}" || :
    git config -f "${chroot_gitconfig}" --replace-all user.email \
        "${ident_email}" || :
  fi

  # Copy the gitcookies file, updating the user's gitconfig to point to it.
  local gitcookies
  gitcookies="$(git_config_path --file "${chroot_gitconfig}" \
                  --get http.cookiefile)"
  if [[ $? -ne 0 ]]; then
    # Try the default location anyway.
    gitcookies="${SUDO_HOME}/.gitcookies"
  fi
  copy_into_chroot_if_exists "${gitcookies}" "/home/${SUDO_USER}/.gitcookies"
  local -r chroot_gitcookies="${FLAGS_chroot}/home/${SUDO_USER}/.gitcookies"
  if [[ -e "${chroot_gitcookies}" ]]; then
    git config -f "${chroot_gitconfig}" --replace-all http.cookiefile \
        "/home/${SUDO_USER}/.gitcookies"
  fi
  # This line must be at the end because using `git config` changes ownership of
  # the .gitconfig.
  chown ${SUDO_UID}:${SUDO_GID} "${chroot_gitconfig}"
}

setup_gclient_cache_dir_mount() {
  # Mount "cache_dir" if a glient checkout depends on it.
  # Otherwise, git command inside chroot fails. See https://crbug.com/747349
  local checkout_root="$1"

  if [[ ! -e "${checkout_root}/.gclient" ]]; then
    return 0
  fi

  local cache_dir=$(sed -n -E "s/^ *cache_dir *= *'(.*)'/\1/p" \
                    "${checkout_root}/.gclient")
  if [[ -z "${cache_dir}" ]]; then
    return 0
  fi

  # See if the cache dir exists outside of the chroot.
  if [[ ! -d "${cache_dir}" ]]; then
    # See if it exists inside the chroot (which can happen if the checkout was
    # created in there).
    if [[ ! -d "${FLAGS_chroot}/${cache_dir}" ]]; then
      warn "Gclient cache dir \"${cache_dir}\" is not a directory."
    fi
    return 0
  fi

  setup_mount "${cache_dir}" "--bind" "${cache_dir}"
}

setup_env() {
  (
    flock 200

    # Make the lockfile writable for backwards compatibility.
    chown ${SUDO_UID}:${SUDO_GID} "${LOCKFILE}"

    # Refresh /etc/resolv.conf and /etc/hosts in the chroot.
    install -C -m644 /etc/resolv.conf ${FLAGS_chroot}/etc/resolv.conf
    install -C -m644 /etc/hosts ${FLAGS_chroot}/etc/hosts

    debug "Mounting chroot environment."
    MOUNT_CACHE=$(echo $(awk '{print $2}' /proc/mounts))
    # We shouldn't need access to any /run state, so don't mount it.  Some
    # distros (e.g. Ubuntu) might have /dev/shm symlinked to /run/shm.
    local run_shm="${FLAGS_chroot}/run/shm"
    if [[ ! -d "${run_shm}" ]]; then
      mkdir -p "${run_shm}"
      chmod 1777 "${run_shm}"
    fi

    local run_lock="${FLAGS_chroot}/run/lock"
    if [[ ! -d "${run_lock}" ]]; then
      mkdir -p "${run_lock}"
      chmod 1777 "${run_lock}"
    fi

    # Do this early as it's slow and only needs basic mounts (above).
    generate_locales &

    debug "Setting up referenced repositories if required."
    REFERENCE_DIR=$(git_config_path --file  \
      "${FLAGS_trunk}/.repo/manifests.git/config" \
      repo.reference)
    if [ -n "${REFERENCE_DIR}" ]; then

      ALTERNATES="${FLAGS_trunk}/.repo/alternates"

      # Ensure this directory exists ourselves, and has the correct ownership.
      user_mkdir "${ALTERNATES}"

      unset ALTERNATES

      IFS=$'\n';
      required=( $( sudo -u "${SUDO_USER}" -- \
        "${FLAGS_trunk}/chromite/lib/rewrite_git_alternates" \
        "${FLAGS_trunk}" "${REFERENCE_DIR}" "${CHROOT_TRUNK_DIR}" ) )
      unset IFS

      setup_mount "${FLAGS_trunk}/.repo/chroot/alternates" --bind \
        "${CHROOT_TRUNK_DIR}/.repo/alternates"

      # Note that as we're bringing up each referened repo, we also
      # mount bind an empty directory over its alternates.  This is
      # required to suppress git from tracing through it- we already
      # specify the required alternates for CHROOT_TRUNK_DIR, no point
      # in having git try recursing through each on their own.
      #
      # Finally note that if you're unfamiliar w/ chroot/vfs semantics,
      # the bind is visible only w/in the chroot.
      user_mkdir ${FLAGS_trunk}/.repo/chroot/empty
      position=1
      for x in "${required[@]}"; do
        base="${CHROOT_TRUNK_DIR}/.repo/chroot/external${position}"
        setup_mount "${x}" "--bind" "${base}"
        if [ -e "${x}/.repo/alternates" ]; then
          setup_mount "${FLAGS_trunk}/.repo/chroot/empty" "--bind" \
            "${base}/.repo/alternates"
        fi
        position=$(( ${position} + 1 ))
      done
      unset required position base
    fi
    unset REFERENCE_DIR

    chroot_cache='/var/cache/chromeos-cache'
    debug "Setting up shared cache dir directory."
    user_mkdir "${FLAGS_cache_dir}"/distfiles
    user_mkdir "${FLAGS_chroot}/${chroot_cache}"
    setup_mount "${FLAGS_cache_dir}" "--bind" "${chroot_cache}"
    # TODO(build): remove this as of 12/01/12.
    # Because of how distfiles -> cache_dir was deployed, if this isn't
    # a symlink, we *know* the ondisk pathways aren't compatible- thus
    # fix it now.
    distfiles_path="${FLAGS_chroot}/var/cache/distfiles"
    if [ ! -L "${distfiles_path}" ]; then
      # While we're at it, ensure the var is exported w/in the chroot; it
      # won't exist if distfiles isn't a symlink.
      p="${FLAGS_chroot}/etc/profile.d/chromeos-cachedir.sh"
      rm -rf "${distfiles_path}"
      ln -s chromeos-cache/distfiles "${distfiles_path}"
      mkdir -p -m 775 "${p%/*}"
      echo 'export CHROMEOS_CACHEDIR=${chroot_cache}' > "${p}"
      chmod 0644 "${p}"
    fi

    if [ -d "${SUDO_HOME}/.cidb_creds" ]; then
      setup_mount "${SUDO_HOME}/.cidb_creds" --bind \
        "/home/${SUDO_USER}/.cidb_creds"
    fi

    if [ $FLAGS_ssh_agent -eq $FLAGS_TRUE ]; then
      if [ -n "${SSH_AUTH_SOCK}" -a -d "${SUDO_HOME}/.ssh" ]; then
        local target_ssh="/home/${SUDO_USER}/.ssh"
        TARGET_DIR="${FLAGS_chroot}${target_ssh}"
        user_mkdir "${TARGET_DIR}"

        local known_hosts="${SUDO_HOME}/.ssh/known_hosts"
        if [[ -e ${known_hosts} ]]; then
          # Ensure there is a file to bind mount onto for setup_mount.
          touch "${TARGET_DIR}/known_hosts"
          setup_mount "${known_hosts}" --bind "${target_ssh}/known_hosts"
        fi
        copy_ssh_config "${TARGET_DIR}"
        chown -R ${SUDO_UID}:${SUDO_GID} "${TARGET_DIR}"

        if [ -S "${SSH_AUTH_SOCK}" ]; then
          touch "${FLAGS_chroot}/tmp/ssh-auth-sock"
          setup_mount "${SSH_AUTH_SOCK}" "--bind" "/tmp/ssh-auth-sock"
        fi
      fi
    fi

    if [[ -d "${SUDO_HOME}/.config/chromite" ]]; then
      setup_mount "${SUDO_HOME}/.config/chromite" "--bind" \
        "/home/${SUDO_USER}/.config/chromite"
    fi

    # A reference to the DEPOT_TOOLS path may be passed in by cros_sdk.
    if [ -n "${DEPOT_TOOLS}" ]; then
      debug "Mounting depot_tools"
      setup_mount "${DEPOT_TOOLS}" --bind "${DEPOT_TOOLS_DIR}"
    fi

    if [[ -n "${FLAGS_reclient_dir}" ]]; then
      debug "Mounting re-client"
      setup_mount "${FLAGS_reclient_dir}" --bind "/home/${SUDO_USER}/reclient"
    fi

    if [[ -n "${FLAGS_reproxy_cfg_file}" ]]; then
      debug "Mounting reproxy config file."
      setup_mount "${FLAGS_reproxy_cfg_file}" --bind "/home/${SUDO_USER}/reclient_cfgs/reproxy_chroot.cfg"
    fi

    if [[ -n "${FLAGS_goma_dir}" ]]; then
      debug "Mounting goma"
      # $HOME/goma is the default directory for goma.
      # It is used by goma if GOMA_DIR is not provide.
      setup_mount "${FLAGS_goma_dir}" --bind "/home/${SUDO_USER}/goma"
    fi

    if [[ -n "${FLAGS_goma_client_json}" ]]; then
      debug "Mounting service-account-goma-client.json"
      local dest_path="/creds/service_accounts/service-account-goma-client.json"
      # setup_mount assumes the target is a directory by default.
      # So here, touch the file in advance.
      local mounted_path="${MOUNTED_PATH}${dest_path}"
      mkdir -p "$(dirname "${mounted_path}")"
      touch "${mounted_path}"
      # Note: Original UID:GID and permission should be inherited even after
      # mounting.
      setup_mount "${FLAGS_goma_client_json}" --bind "${dest_path}"
    fi

    # Mount additional directories as specified in .local_mounts file.
    local local_mounts="${FLAGS_trunk}/src/scripts/.local_mounts"
    if [[ -f ${local_mounts} ]]; then
      info "Mounting local folders"
      # format: mount_source
      #      or mount_source mount_point
      #      or # comments
      local mount_source mount_point
      while read mount_source mount_point; do
        if [[ -z ${mount_source} ]]; then
          continue
        fi
        # if only source is assigned, use source as mount point.
        : ${mount_point:=${mount_source}}
        debug "  mounting ${mount_source} on ${mount_point}"
        setup_mount "${mount_source}" "--bind" "${mount_point}"
      done < <(sed -e 's:#.*::' "${local_mounts}")
    fi

    if [[ -n "${FLAGS_chrome_root}" ]]; then
      if ! CHROME_ROOT="$(readlink -f "${FLAGS_chrome_root}")"; then
        die_notrace "${FLAGS_chrome_root} does not exist."
      fi
    fi
    if [ -z "$CHROME_ROOT" ]; then
      CHROME_ROOT="$(cat "${FLAGS_chroot}${CHROME_ROOT_CONFIG}" \
        2>/dev/null || :)"
      CHROME_ROOT_AUTO=1
    fi
    if [[ -n "$CHROME_ROOT" ]]; then
      if [[ ! -d "${CHROME_ROOT}/src" ]]; then
        error "Not mounting chrome source: could not find CHROME_ROOT/src dir."
        error "Full path we tried: ${CHROME_ROOT}/src"
        rm -f "${FLAGS_chroot}${CHROME_ROOT_CONFIG}"
        if [[ ! "$CHROME_ROOT_AUTO" ]]; then
          exit 1
        fi
      else
        debug "Mounting chrome source at: $INNER_CHROME_ROOT"
        echo $CHROME_ROOT > "${FLAGS_chroot}${CHROME_ROOT_CONFIG}"
        setup_mount "$CHROME_ROOT" --bind "$INNER_CHROME_ROOT"
        setup_gclient_cache_dir_mount "$CHROME_ROOT"
      fi
    fi

    # Install fuse module.  Skip modprobe when possible for slight
    # speed increase when initializing the env.
    if [ -c "${FUSE_DEVICE}" ] && ! grep -q fuse /proc/filesystems; then
      modprobe fuse 2> /dev/null ||\
        warn "-- Note: modprobe fuse failed.  gmergefs will not work"
    fi

    # Bind mount the host kernel modules read-only so modprobe can be used
    # inside the chroot for things like usbip-host.
    local modules_dir="/lib/modules"
    if [ -d "${modules_dir}" ]; then
      setup_mount "${modules_dir}" "--bind -o ro" "${modules_dir}"
    fi

    # Fix permissions on ccache tree.  If this is a fresh chroot, then they
    # might not be set up yet.  Or if the user manually `rm -rf`-ed things,
    # we need to reset it.  Otherwise, gcc itself takes care of fixing things
    # on demand, but only when it updates.
    ccache_dir="${FLAGS_chroot}/var/cache/distfiles/ccache"
    if [[ ! -d ${ccache_dir} ]]; then
      mkdir -p -m 2775 "${ccache_dir}"
    fi
    (
      find -H "${ccache_dir}" '(' -type d -a '!' -perm 2775 ')' \
        -exec chmod 2775 {} +
      find -H "${ccache_dir}" -gid 0 -exec chgrp 250 {} +
      # These settings are kept in sync with the gcc ebuild.
      chroot "${FLAGS_chroot}" env CCACHE_DIR=/var/cache/distfiles/ccache \
        CCACHE_UMASK=002 ccache -F 0 -M 11G >/dev/null
    ) &

    # Certain files get copied into the chroot when entering.
    for fn in "${FILES_TO_COPY_TO_CHROOT[@]}"; do
      copy_into_chroot_if_exists "${SUDO_HOME}/${fn}" "/home/${SUDO_USER}/${fn}"
    done

    # Map in credentials account for log-writing access.
    log_cert_dir="/creds/service_accounts/"
    log_cert_file="service-account-chromeos-datastore-writer-prod.json"
    copy_into_chroot_if_exists "${log_cert_dir}${log_cert_file}" \
      "/home/${SUDO_USER}/${log_cert_file}"


    setup_git
    promote_api_keys

    # Fix permissions on shared memory to allow non-root users access to POSIX
    # semaphores. Take special care to only change the permissions on the
    # directory and not all of its contents.
    chmod 1777 "${FLAGS_chroot}/dev/shm"

    # gsutil uses boto config to store settings and credentials. Copy
    # user's own boto file into the chroot if it exists. Also copy it
    # to /root for sudoed invocations.
    chroot_user_boto="${FLAGS_chroot}/home/${SUDO_USER}/.boto"
    chroot_root_boto="${FLAGS_chroot}/root/.boto"
    if [ -f ${SUDO_HOME}/.boto ]; then
      # Pass --remote-destination to overwrite a symlink.
      user_cp "--remove-destination" "${SUDO_HOME}/.boto" "$chroot_user_boto"
      cp "--remove-destination" "$chroot_user_boto" "$chroot_root_boto"
    elif [ -f "/etc/boto.cfg" ]; then
      # For GCE instances, the non-chroot .boto file is not deployed so
      # use the system /etc/boto.cfg if it exists.
      user_cp "--remove-destination" "/etc/boto.cfg" "$chroot_user_boto"
      cp "--remove-destination" "$chroot_user_boto" "$chroot_root_boto"
    fi

    # If user doesn't have a boto file, check if the private overlays
    # are installed and use those credentials.
    boto='src/private-overlays/chromeos-overlay/googlestorage_account.boto'
    if [ -s "${FLAGS_trunk}/${boto}" ]; then
      if [ ! -e "$chroot_user_boto" ]; then
        user_symlink "trunk/${boto}" "$chroot_user_boto"
      fi
      if [ ! -e "$chroot_root_boto" ]; then
        ln -sf "${CHROOT_TRUNK_DIR}/${boto}" "$chroot_root_boto"
      fi
    fi

    # Have found a few chroots where ~/.gsutil is owned by root:root, probably
    # as a result of old gsutil or tools. This causes permission errors when
    # gsutil cp tries to create its cache files, so ensure the user can
    # actually write to their directory.
    gsutil_dir="${FLAGS_chroot}/home/${SUDO_USER}/.gsutil"
    if [ -d "${gsutil_dir}" ]; then
      chown -R ${SUDO_UID}:${SUDO_GID} "${gsutil_dir}"
    fi
  ) 200>>"$LOCKFILE" || die "setup_env failed"
}

# Translate C.UTF-8 into something we support. Remove this when our glibc
# starts supporting C.UTF-8. https://bugzilla.redhat.com/show_bug.cgi?id=902094
for var in LANG \
  LC_{ADDRESS,ALL,COLLATE,CTYPE,IDENTIFICATION,MEASUREMENT,MESSAGES} \
  LC_{MONETARY,NAME,NUMERIC,PAPER,TELEPHONE,TIME}; do
  if [[ ${!var} =~ C\.[Uu][Tt][Ff]-?8 ]]; then
    if [[ ${var} == LC_COLLATE ]]; then
      export LC_COLLATE=C
    else
      export ${var}=en_US.UTF-8
    fi
  fi
done

check_locale
setup_env

CHROOT_PASSTHRU=(
  "BUILDBOT_BUILD=$FLAGS_build_number"
  "CHROMEOS_RELEASE_APPID=${CHROMEOS_RELEASE_APPID:-{DEV-BUILD}}"
  "EXTERNAL_TRUNK_PATH=${FLAGS_trunk}"

  # The default ~/.bash_profile in chroot will cd to $CHROOT_CWD instead of
  # ~/trunk/src/script if that environment variable is set.
  "CHROOT_CWD=${FLAGS_working_dir}"

  # We don't want to auto-update depot_tools inside of the SDK as we manage it.
  "DEPOT_TOOLS_UPDATE=0"
)

# Needs to be set here because setup_env runs in a subshell.
[ -S "${FLAGS_chroot}/tmp/ssh-auth-sock" ] && SSH_AUTH_SOCK=/tmp/ssh-auth-sock

# Add the whitelisted environment variables to CHROOT_PASSTHRU.
load_environment_whitelist
for var in "${ENVIRONMENT_WHITELIST[@]}" ; do
  [ "${!var+set}" = "set" ] && CHROOT_PASSTHRU+=( "${var}=${!var}" )
done

# Set up GIT_PROXY_COMMAND so git:// URLs automatically work behind a proxy.
if [[ -n "${all_proxy}" || -n "${https_proxy}" || -n "${http_proxy}" ]]; then
  CHROOT_PASSTHRU+=(
    "GIT_PROXY_COMMAND=${CHROOT_TRUNK_DIR}/src/scripts/bin/proxy-gw"
  )
fi

# Run command or interactive shell.  Also include the non-chrooted path to
# the source trunk for scripts that may need to print it (e.g.
# build_image.sh).

if [ $FLAGS_early_make_chroot -eq $FLAGS_TRUE ]; then
  cmd=( /bin/bash -l -c 'env "$@"' -- )
elif [ ! -x "${FLAGS_chroot}/usr/bin/sudo" ]; then
  # Complain that sudo is missing.
  error "Failing since the chroot lacks sudo."
  error "Requested enter_chroot command was: $@"
  exit 127
else
  cmd=( sudo -i -u "${SUDO_USER}" )
fi

cmd+=( "${CHROOT_PASSTHRU[@]}" "$@" )
exec chroot "${FLAGS_chroot}" "${cmd[@]}"
