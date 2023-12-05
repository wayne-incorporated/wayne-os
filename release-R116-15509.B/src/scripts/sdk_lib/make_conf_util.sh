# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# When bootstrapping the chroot, only wget is available, and we must
# disable certificate checking.  Once the chroot is fully
# initialized, we can switch to curl, and re-enable the certificate
# checks.  See http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=409938
#
# Usage:
# $1 - 'wget' requests the bootstrap special content; otherwise
#      uses 'curl'.
_make_conf_fetchcommand() {
  local cmd options output_opt resume_opt
  local fileref='\"\${DISTDIR}/\${FILE}\"'
  local uri_ref='\"\${URI}\"'

  if [ "$1" = "wget" ] ; then
    cmd=/usr/bin/wget
    options="-t 5 -T 60 --no-check-certificate --passive-ftp"
    resume_opt="-c"
    output_opt="-O"
  else
    cmd=curl
    options="-f -y 30 --retry 9 -L"
    resume_opt="-C -"
    output_opt="--output"
  fi

  local args="$options $output_opt $fileref $uri_ref"
  echo FETCHCOMMAND=\"$cmd $args\"
  echo RESUMECOMMAND=\"$cmd $resume_opt $args\"
  echo
}

# The default PORTAGE_BINHOST setting selects the preflight
# binhosts.  We override the setting if the build environment
# requests it.
_make_conf_prebuilt() {
  if [[ -n "$IGNORE_PREFLIGHT_BINHOST" ]]; then
    echo 'PORTAGE_BINHOST="$FULL_BINHOST"'
    echo
  fi
}

# Include configuration settings for building private overlay
# packages, if the overlay is present.
#
# N.B.  We explicitly disallow creating content for the private
# overlay during bootstrapping, as it's not currently required,
# and at least a minor nuisance to implement.  Note also that the
# use of an inside-the-chroot path is based on the (currently true)
# assumption that bootstrapping use is outside the chroot, and
# non-bootstrapping use is inside the chroot.
_make_conf_private() {
  if [ "$1" = "wget" ] ; then
    return
  fi

  # If the private overlay dir exists, make sure each sub-piece also exists
  # before we try using it.  Otherwise, simply creating an empty dir will
  # lead to weird build errors.
  local chromeos_overlay="src/private-overlays/chromeos-overlay"
  chromeos_overlay="${CHROOT_TRUNK_DIR}/${chromeos_overlay}"

  if [[ -d "${chromeos_overlay}" ]]; then
    local make_conf="${CHROOT_TRUNK_DIR}/src/third_party/chromiumos-overlay"
    make_conf+="/chromeos/config/make.conf.sdk-chromeos"
    echo "source ${make_conf}"
  fi

  local boto_config="${chromeos_overlay}/googlestorage_account.boto"
  if [[ -e "${boto_config}" ]]; then
    local gs_fetch_binpkg='/mnt/host/source/chromite/bin/gs_fetch_binpkg'
    printf 'FETCHCOMMAND_GS="%s --boto \\"%s\\" \\"%s\\" \\"%s\\""\n' \
      "${gs_fetch_binpkg}" "${boto_config}" \
      '\${URI}' '\${DISTDIR}/\${FILE}'
    echo 'RESUMECOMMAND_GS="${FETCHCOMMAND_GS}"'
  fi

  local chromeos_partner_overlay="src/private-overlays/chromeos-partner-overlay"
  chromeos_partner_overlay="${CHROOT_TRUNK_DIR}/${chromeos_partner_overlay}"

  local overlay
  for overlay in "${chromeos_partner_overlay}" "${chromeos_overlay}"; do
    if [[ -d "${overlay}" ]]; then
      echo "PORTDIR_OVERLAY=\"\$PORTDIR_OVERLAY ${overlay}\""
    fi
  done
}

# Create /etc/make.conf.host_setup according to parameters.
#
# Usage:
# $1 - 'wget' for bootstrapping; 'curl' otherwise.
# $2 - When outside the chroot, path to the chroot.  Empty when
#      inside the chroot.
_create_host_setup() {
  local fetchtype="$1"
  local host_setup="$2/etc/make.conf.host_setup"
  ( echo "# Automatically generated.  EDIT THIS AND BE SORRY."
    echo
    _make_conf_fetchcommand "$fetchtype"
    _make_conf_private "$fetchtype"
    _make_conf_prebuilt
    echo 'MAKEOPTS="-j'${NUM_JOBS}'"' ) | sudo_clobber "$host_setup"
  sudo chmod 644 "$host_setup"
}


# Create /etc/make.conf.host_setup for early bootstrapping of the
# chroot.  This is done early in make_chroot, and the results are
# overwritten later in the process.
#
# Usage:
#   $1 - Path to chroot as seen from outside
create_bootstrap_host_setup() {
  _create_host_setup wget "$@"
}


# Create /etc/make.conf.host_setup for normal usage.
create_host_setup() {
  _create_host_setup curl ''
}
