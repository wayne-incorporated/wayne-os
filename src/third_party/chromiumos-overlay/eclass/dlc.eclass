# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @MAINTAINER:
# Chromium OS System Services Team
# @AUTHOR
# The ChromiumOS Authors <chromium-os-dev@chromium.org>
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new
# @BLURB: Helper eclass for building DLC packages.
# @DESCRIPTION:
# Handles building the DLC image and metadata files and dropping them into
# locations where they can be picked up by the build process and hosted on
# Omaha, respectively.

if [[ -z "${_ECLASS_DLC}" ]]; then
_ECLASS_DLC="1"

inherit cros-constants

# Check for EAPI 7+.
case "${EAPI:-0}" in
[0123456]) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

DLC_BUILD_DIR="build/rootfs/dlc"
DLC_BUILD_DIR_SCALED="build/rootfs/dlc-scaled"

# @ECLASS-VARIABLE: DLC_PREALLOC_BLOCKS
# @DEFAULT_UNSET
# @REQUIRED
# @DESCRIPTION:
# The number of blocks to preallocate for each of the the DLC A/B partitions.
# Block size is 4 KiB.

# Other optional DLC ECLASS-VARAIBLES

# @ECLASS-VARIABLE: DLC_NAME
# @DEFAULT_UNSET
# @REQUIRED
# @DESCRIPTION:
# The name of the DLC to show on the UI.
: "${DLC_NAME:=${PN}}"

# @ECLASS-VARIABLE: DLC_DESCRIPTION
# @DESCRIPTION:
# A human readable description for DLC.

# @ECLASS-VARIABLE: DLC_ID
# @DESCRIPTION:
# Unique ID for the DLC among all DLCs. Needed to generate metadata for
# imageloader. Used in creating directories for the image file and metadata. It
# cannot contain '_' or '/'.
: "${DLC_ID:=${PN}}"

# @ECLASS-VARIABLE: DLC_PACKAGE
# @DESCRIPTION:
# Unique ID for the package in the DLC. Each DLC can have multiple
# packages. Needed to generate metadata for imageloader. Used in creating
# directories for the image file and metadata. It cannot contain '_' or '/'.
: "${DLC_PACKAGE:=package}"

# @ECLASS-VARIABLE: DLC_VERSION
# @DESCRIPTION:
# Version of the DLC being built.
: "${DLC_VERSION:=${PVR}}"

# @ECLASS-VARIABLE: DLC_FS_TYPE
# @DEFAULT UNSET
# @DESCRIPTION:
# Specify the type of filesystem for the DLC image. Currently we only support
# squashfs.

# @ECLASS-VARIABLE: DLC_PRELOAD
# @DESCRIPTION:
# Determines whether to preload the DLC for test images. A boolean must be
# passed in.
: "${DLC_PRELOAD:="false"}"

# @ECLASS-VARIABLE: DLC_FACTORY_INSTALL
# @DESCRIPTION:
# Determines whether to factory install the DLC into FSI. A boolean must be
# passed in. (Please consult @chromeos-core-services team before using this)
: "${DLC_FACTORY_INSTALL:="false"}"

# @ECLASS-VARIABLE: DLC_ENABLED
# @DESCRIPTION:
# Determines whether the package will be a DLC package or regular package.
# By default, the package is a DLC package and the files will be installed in
# ${DLC_BUILD_DIR[_SCALED]}/${DLC_ID}/${DLC_PACKAGE}/root, but if the variable is
# set to "false", all the functions will ignore the path suffix and everything
# that would have been installed inside the DLC, gets installed in the rootfs.
: "${DLC_ENABLED:="true"}"

# @ECLASS-VARIABLE: DLC_MOUNT_FILE_REQUIRED
# @DESCRIPTION:
# By default, DLC mount points should be retrieved from the DBUS install method.
# Places where DBus isn't accessible, use this flag to generate a file holding
# the mount point as an indirect method of retrieving the DLC mount point.
: "${DLC_MOUNT_FILE_REQUIRED:="false"}"

# @ECLASS-VARIABLE: DLC_RESERVED
# @DESCRIPTION:
# Determines whether to always eagerly reserve space for the DLC on disk.
# This should only be used by DLCs which always requires space on the device.
# (Please consult @chromeos-core-services team before using this)
: "${DLC_RESERVED:="false"}"

# @ECLASS-VARIABLE: DLC_CRITICAL_UPDATE
# @DESCRIPTION:
# Determines whether to always update the DLC with the OS atomically.
# (Please consult @chromeos-core-services team before using this)
: "${DLC_CRITICAL_UPDATE:="false"}"

# @ECLASS-VARIABLE: DLC_LOADPIN_VERITY_DIGEST
# @DESCRIPTION:
# Add DLC as part of trusted verity digest by the kernel.
# (Please consult @chromeos-core-services team before using this)
: "${DLC_LOADPIN_VERITY_DIGEST:="false"}"

# @ECLASS-VARIABLE: DLC_SCALED
# @DESCRIPTION:
# DLC will be fed through scaling design.
# (Please consult @chromeos-core-services team before using this)
: "${DLC_SCALED:="false"}"

# @ECLASS-VARIABLE: DLC_POWERWASH_SAFE
# @DESCRIPTION:
# DLC will be powerwash safe. (Only on LVM supported devices)
# In order for a DLC to be powerwash safe, it must go through build time reviews
# to be allowlisted.
# (Please consult @chromeos-core-services team before using this)
: "${DLC_POWERWASH_SAFE:="false"}"

# @FUNCTION: dlc_add_path
# @USAGE: <path to add the DLC prefix to>
# @RETURN:
# Adds the DLC path prefix to the argument based on the value of |DLC_ENABLED|
# and returns that value.
dlc_add_path() {
	[[ $# -eq 1 ]] || die "${FUNCNAME[0]}: takes one argument"
	local input_path="$1"
	if [[ "${DLC_ENABLED}" != "true" ]]; then
		echo "/${input_path}"
	else
		[[ -z "${DLC_ID}" ]] && die "DLC_ID undefined"
		[[ -z "${DLC_PACKAGE}" ]] && die "DLC_PACKAGE undefined"
		if [[ "${DLC_SCALED}" == "true" ]]; then
			echo "/${DLC_BUILD_DIR_SCALED}/${DLC_ID}/${DLC_PACKAGE}/root/${input_path}"
		else
			echo "/${DLC_BUILD_DIR}/${DLC_ID}/${DLC_PACKAGE}/root/${input_path}"
		fi
	fi
}

# @FUNCTION: dlc_src_install
# @DESCRIPTION:
# Installs DLC files into
# /build/${BOARD}/${DLC_BUILD_DIR}/${DLC_ID}/${DLC_PACKAGE}/root.
dlc_src_install() {
	[[ "${DLC_ENABLED}" =~ ^(true|false)$ ]] || die "Invalid DLC_ENABLED value"
	if [[ "${DLC_ENABLED}" != "true" ]]; then
		return
	fi

	# Required.
	[[ -z "${DLC_NAME}" ]] && die "DLC_NAME undefined"
	[[ -z "${DLC_PREALLOC_BLOCKS}" ]] && die "DLC_PREALLOC_BLOCKS undefined"

	# Optional, but error if derived default values are empty.
	: "${DLC_DESCRIPTION:=${DESCRIPTION}}"
	[[ -z "${DLC_DESCRIPTION}" ]] && die "DLC_DESCRIPTION undefined"
	[[ -z "${DLC_ID}" ]] && die "DLC_ID undefined"
	[[ -z "${DLC_PACKAGE}" ]] && die "DLC_PACKAGE undefined"
	[[ -z "${DLC_VERSION}" ]] && die "DLC_VERSION undefined"
	[[ "${DLC_PRELOAD}" =~ ^(true|false)$ ]] || die "Invalid DLC_PRELOAD value"
	[[ "${DLC_FACTORY_INSTALL}" =~ ^(true|false)$ ]] || die "Invalid DLC_FACTORY_INSTALLvalue"
	[[ "${DLC_MOUNT_FILE_REQUIRED}" =~ ^(true|false)$ ]] \
		|| die "Invalid DLC_MOUNT_FILE_REQUIRED value"
	[[ "${DLC_RESERVED}" =~ ^(true|false)$ ]] \
		|| die "Invalid DLC_RESERVED value"
	[[ "${DLC_CRITICAL_UPDATE}" =~ ^(true|false)$ ]] \
		|| die "Invalid DLC_CRITICAL_UPDATE value"
	[[ "${DLC_LOADPIN_VERITY_DIGEST}" =~ ^(true|false)$ ]] \
		|| die "Invalid DLC_LOADPIN_VERITY_DIGEST value"
	[[ "${DLC_SCALED}" =~ ^(true|false)$ ]] \
		|| die "Invalid DLC_SCALED value"

	local args=(
		--install-root-dir="${D}"
		--pre-allocated-blocks="${DLC_PREALLOC_BLOCKS}"
		--version="${DLC_VERSION}"
		--id="${DLC_ID}"
		--package="${DLC_PACKAGE}"
		--name="${DLC_NAME}"
		--description="${DLC_DESCRIPTION}"
		--fullnamerev="${CATEGORY}/${PF}"
		--build-package
	)

	if [[ -n "${DLC_FS_TYPE}" ]]; then
		args+=( --fs-type="${DLC_FS_TYPE}" )
	fi

	if [[ "${DLC_PRELOAD}" == "true" ]]; then
		args+=( --preload )
	fi

	if [[ "${DLC_FACTORY_INSTALL}" == "true" ]]; then
		args+=( --factory-install )
	fi

	if [[ "${DLC_MOUNT_FILE_REQUIRED}" == "true" ]]; then
		args+=( --mount-file-required )
	fi

	if [[ "${DLC_RESERVED}" == "true" ]]; then
		args+=( --reserved )
	fi

	if [[ "${DLC_CRITICAL_UPDATE}" == "true" ]]; then
		args+=( --critical-update )
	fi

	if [[ "${DLC_LOADPIN_VERITY_DIGEST}" == "true" ]]; then
		args+=( --loadpin-verity-digest )
	fi

	if [[ "${DLC_SCALED}" == "true" ]]; then
		args+=( --scaled )
	fi

	if [[ "${DLC_POWERWASH_SAFE}" == "true" ]]; then
		args+=( --powerwash-safe )
	fi

	"${CHROMITE_BIN_DIR}"/build_dlc "${args[@]}" \
		|| die "build_dlc failed."
}

EXPORT_FUNCTIONS src_install

fi
