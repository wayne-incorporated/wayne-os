# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-camera.eclass
# @MAINTAINER:
# Chromium OS Camera Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building Chromium package in src/platform2/camera
# @DESCRIPTION:
# Packages in src/platform2/camera are in active development. We want builds
# to be incremental and fast. This centralized the logic needed for this.

inherit multilib

IUSE="
	march_alderlake
	march_armv8
	march_bdver4
	march_corei7
	march_goldmont
	march_silvermont
	march_skylake
	march_tigerlake
	march_tremont
	march_znver1
"

REQUIRED_USE="
	?? ( march_alderlake march_bdver4 march_corei7 march_goldmont march_silvermont march_skylake march_tigerlake march_tremont march_znver1 )
	^^ ( amd64 arm arm64 )
"

# @FUNCTION: cros-camera_dohal
# @USAGE: <source HAL file> <destination HAL file>
# @DESCRIPTION:
# Install the given camera HAL library to /usr/lib/camera_hal or
# /usr/lib64/camera_hal, depending on the architecture and/or platform.
cros-camera_dohal() {
	[[ $# -eq 2 ]] || die "Usage: ${FUNCNAME[0]} <src> <dst>"

	local src=$1
	local dst=$2
	(
		insinto "/usr/$(get_libdir)/camera_hal"
		newins "${src}" "${dst}"
	)
}

# @FUNCTION: cros-camera_generate_conditional_SRC_URI
# @USAGE:
# @DESCRIPTION:
# We build the libraries with different "-march" configuration but the USE flags
# to differentiate the libraries are not mutually exclusive. For example, boards
# with `march_skylake` will also have `amd64`. This function returns conditional
# SRC_URI string like "flag1? ( src1 ) !flag1? ( flag2? ( src2 ) )" from the
# given "flag src" mappings.
cros-camera_generate_conditional_SRC_URI() {
	local -n mappings="$1"
	local flag=""
	local src=""
	local exclude_flags=()
	for mapping in "${mappings[@]}"; do
		read -r flag src <<< "${mapping}"
		if [[ ${#exclude_flags[@]} -ne 0 ]]; then
			printf " !%s? ( " "${exclude_flags[@]}"
		fi
		echo "${flag}? ( ${src} )"
		for _ in "${exclude_flags[@]}"; do
			echo " )"
		done
		exclude_flags+=("${flag}")
	done
}

# @FUNCTION: cros-camera_generate_auto_framing_package_SRC_URI
# @USAGE:
# @DESCRIPTION:
# Generate SRC_URI for auto framing package by PV.
cros-camera_generate_auto_framing_package_SRC_URI() {
	local pv="$1"
	local prefix="gs://chromeos-localmirror/distfiles/chromeos-camera-libautoframing"
	local suffix="${pv}.tar.zst"
	# Skip the check for this variable since it's indirectly referenced in
	# cros-camera_generate_conditional_SRC_URI (local -n).
	# shellcheck disable=SC2034
	local auto_framing_flag_src_mappings=(
		"amd64 ${prefix}-x86_64-${suffix}"
	)
	cros-camera_generate_conditional_SRC_URI auto_framing_flag_src_mappings
}

# @FUNCTION: cros-camera_generate_document_scanning_package_SRC_URI
# @USAGE:
# @DESCRIPTION:
# Generate SRC_URI for document scanning package by PV.
cros-camera_generate_document_scanning_package_SRC_URI() {
	local pv="$1"
	local prefix="gs://chromeos-localmirror/distfiles/chromeos-document-scanning-lib"
	local suffix="${pv}.tar.zst"
	# Skip the check for this variable since it's indirectly referenced in
	# cros-camera_generate_conditional_SRC_URI (local -n).
	# shellcheck disable=SC2034
	local document_scanning_flag_src_mappings=(
		"march_alderlake ${prefix}-x86_64-alderlake-${suffix}"
		"march_armv8 ${prefix}-armv7-armv8-${suffix}"
		"march_bdver4 ${prefix}-x86_64-bdver4-${suffix}"
		"march_corei7 ${prefix}-x86_64-corei7-${suffix}"
		"march_goldmont ${prefix}-x86_64-goldmont-${suffix}"
		"march_silvermont ${prefix}-x86_64-silvermont-${suffix}"
		"march_skylake ${prefix}-x86_64-skylake-${suffix}"
		"march_tigerlake ${prefix}-x86_64-tigerlake-${suffix}"
		"march_tremont ${prefix}-x86_64-tremont-${suffix}"
		"march_znver1 ${prefix}-x86_64-znver1-${suffix}"
		"amd64 ${prefix}-x86_64-${suffix}"
		"arm ${prefix}-armv7-${suffix}"
		"arm64 ${prefix}-arm-${suffix}"
	)
	cros-camera_generate_conditional_SRC_URI document_scanning_flag_src_mappings
}

# @FUNCTION: cros-camera_generate_facessd_package_SRC_URI
# @USAGE:
# @DESCRIPTION:
# Generate SRC_URI for facessd package by PV.
cros-camera_generate_facessd_package_SRC_URI() {
	local pv="$1"
	local prefix="gs://chromeos-localmirror/distfiles/chromeos-facessd-lib"
	local suffix="${pv}.tar.zst"
	# Skip the check for this variable since it's indirectly referenced in
	# cros-camera_generate_conditional_SRC_URI (local -n).
	# shellcheck disable=SC2034
	local facessd_flag_src_mappings=(
		"march_alderlake ${prefix}-x86_64-alderlake-${suffix}"
		"march_armv8 ${prefix}-armv7-armv8-${suffix}"
		"march_bdver4 ${prefix}-x86_64-bdver4-${suffix}"
		"march_corei7 ${prefix}-x86_64-corei7-${suffix}"
		"march_goldmont ${prefix}-x86_64-goldmont-${suffix}"
		"march_silvermont ${prefix}-x86_64-silvermont-${suffix}"
		"march_skylake ${prefix}-x86_64-skylake-${suffix}"
		"march_tigerlake ${prefix}-x86_64-tigerlake-${suffix}"
		"march_tremont ${prefix}-x86_64-tremont-${suffix}"
		"march_znver1 ${prefix}-x86_64-znver1-${suffix}"
		"amd64 ${prefix}-x86_64-${suffix}"
		"arm ${prefix}-armv7-${suffix}"
		"arm64 ${prefix}-arm-${suffix}"
	)
	cros-camera_generate_conditional_SRC_URI facessd_flag_src_mappings
}

# @FUNCTION: cros-camera_generate_gcam_package_SRC_URI
# @USAGE:
# @DESCRIPTION:
# Generate SRC_URI for gcam package by PV.
cros-camera_generate_gcam_package_SRC_URI() {
	local pv="$1"
	local prefix="gs://chromeos-localmirror/distfiles/chromeos-camera-libgcam"
	local suffix="${pv}.tar.zst"
	# Skip the check for this variable since it's indirectly referenced in
	# cros-camera_generate_conditional_SRC_URI (local -n).
	# shellcheck disable=SC2034
	local gcam_flag_src_mappings=(
		"march_alderlake ${prefix}-x86_64-alderlake-${suffix}"
		"march_skylake ${prefix}-x86_64-skylake-${suffix}"
	)
	cros-camera_generate_conditional_SRC_URI gcam_flag_src_mappings
}

# @FUNCTION: cros-camera_generate_portrait_mode_package_SRC_URI
# @USAGE:
# @DESCRIPTION:
# Generate SRC_URI for portrait mode package by PV.
cros-camera_generate_portrait_mode_package_SRC_URI() {
	local pv="$1"
	local prefix="gs://chromeos-localmirror/distfiles/portrait-processor-lib"
	local suffix="${pv}.tar.zst"
	# Skip the check for this variable since it's indirectly referenced in
	# cros-camera_generate_conditional_SRC_URI (local -n).
	# shellcheck disable=SC2034
	local portrait_mode_flag_src_mappings=(
		"amd64 ${prefix}-x86_64-${suffix}"
		"arm ${prefix}-armv7-${suffix}"
	)
	cros-camera_generate_conditional_SRC_URI portrait_mode_flag_src_mappings
}
