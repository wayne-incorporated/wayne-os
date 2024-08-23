# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Common library file to be sourced by build_image,
# mod_image_for_test.sh, and mod_image_for_recovery.sh.  This
# file ensures that library source files needed by all the scripts
# are included once, and also takes care of certain bookeeping tasks
# common to all the scripts.

# SCRIPT_ROOT must be set prior to sourcing this file
# shellcheck source=../common.sh
. "${SCRIPT_ROOT}/common.sh" || exit 1

# All scripts using this file must be run inside the chroot.
restart_in_chroot_if_needed "$@"

# shellcheck source=../../platform2/chromeos-common-script/share/chromeos-common.sh
. /usr/share/misc/chromeos-common.sh || exit 1

locate_gpt

should_build_image() {
  # Fast pass back if we should build all incremental images.
  local image_name
  local image_to_build

  for image_name in "$@"; do
    for image_to_build in ${IMAGES_TO_BUILD}; do
      [ "${image_to_build}" = "${image_name}" ] && return 0
    done
  done

  return 1
}

# Returns the pv command if it's available, otherwise plain-old cat. Note that
# this function echoes the command, rather than running it, so it can be used
# as an argument to other commands (like sudo).
pv_cat_cmd() {
  if type -P pv >&/dev/null; then
    # Limit pv's output to 80 columns, for readability.
    local term_cols=$(stty size 2>/dev/null | cut -d' ' -f2)
    if [[ ${term_cols:-0} -gt 80 ]]; then
      echo pv -w 80 -B 4m
    else
      echo pv -B 4m
    fi
  else
    echo cat
  fi
}

# Utility function for creating a copy of an image prior to
# modification from the BUILD_DIR:
#  $1: source filename
#  $2: destination filename
copy_image() {
  local src="${BUILD_DIR}/$1"
  local dst="${BUILD_DIR}/$2"
  if should_build_image $1; then
    echo "Creating $2 from $1..."
    $(pv_cat_cmd) "${src}" >"${dst}" || die "Cannot copy $1 to $2"
  else
    mv "${src}" "${dst}" || die "Cannot move $1 to $2"
  fi
}

# Emerge a custom kernel to the |root|.  The caller is responsible for tweaking
# the build env (e.g. $USE) before calling this.
emerge_custom_kernel() {
  local install_root=$1
  local root=/build/${FLAGS_board}
  local tmp_pkgdir=${root}/custom-packages

  info "Emerging custom kernel into ${install_root}"
  info "Setting PKGDIR=${tmp_pkgdir} to avoid conflicts in ${root}"

  # Clean up any leftover state in custom directories.
  sudo rm -rf "${tmp_pkgdir}"

  # Update chromeos-initramfs to contain the latest binaries from the build
  # tree. This is basically just packaging up already-built binaries from
  # ${root}. We are careful not to muck with the existing prebuilts so that
  # prebuilts can be uploaded in parallel.
  # TODO(davidjames): Implement ABI deps so that chromeos-initramfs will be
  # rebuilt automatically when its dependencies change.
  sudo -E PKGDIR="${tmp_pkgdir}" ${EMERGE_BOARD_CMD} -1 \
    chromeos-base/chromeos-initramfs || die "Cannot emerge chromeos-initramfs"

  # Verify all dependencies of the kernel are installed. This should be a
  # no-op, but it's good to check in case a developer didn't run
  # build_packages.  We need the expand_virtual call to workaround a bug
  # in portage where it only installs the virtual pkg.
  local kernel=$(portageq-${FLAGS_board} expand_virtual ${root} \
                 virtual/linux-sources)
  sudo -E PKGDIR="${tmp_pkgdir}" ${EMERGE_BOARD_CMD} --onlydeps \
    ${kernel} || die "Cannot emerge kernel dependencies"

  # Build the kernel. This uses the standard root so that we can pick up the
  # initramfs from there. But we don't actually install the kernel to the
  # standard root, because that'll muck up the kernel debug symbols there,
  # which we want to upload in parallel.
  sudo -E PKGDIR="${tmp_pkgdir}" ${EMERGE_BOARD_CMD} --buildpkgonly \
    ${kernel} || die "Cannot emerge kernel"

  # Install the custom kernel to the provided install root.
  sudo -E PKGDIR="${tmp_pkgdir}" ${EMERGE_BOARD_CMD} --usepkgonly \
    --root=${install_root} ${kernel} || die "Cannot emerge kernel to root"
}

# Detect the decompression tool to use for |file|.
detect_decompression_tool() {
  local file="$1"

  if [[ "$(od -An -tx1 -N4 "${file}")" == " 28 b5 2f fd" ]]; then
    # Since the Gentoo binpkg has trailing garbage, tell zstd to ignore it.
    echo "zstd -f"
  elif [[ "$(od -An -tx1 -N3 "${file}")" == " 42 5a 68" ]]; then
    echo "lbzip2"
  else
    echo "$1: unknown compression type" >&2
    return 1
  fi
}
