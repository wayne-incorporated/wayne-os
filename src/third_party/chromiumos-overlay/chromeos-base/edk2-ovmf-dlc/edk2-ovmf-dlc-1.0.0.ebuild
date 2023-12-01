# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This package wraps UEFI FW as a DLC.

EAPI=7

inherit dlc

DESCRIPTION="UEFI FW packaged as a DLC"
SRC_URI=""

# This DLC bundles files from edk2-ovmf-crosvm, so we use its LICENSE settings.
# Licenses that require attribution (see chromite/licensing/) are manually
# merged into the custom LICENSE.edk2-ovmf-dlc since the tools can't
# automatically scan the edk2-ovmf-crosvm source tree here. This must be
# updated whenever edk2-ovmf-crosvm's licenses change.
LICENSE="openssl LICENSE.edk2-ovmf-dlc"
SLOT="0"
KEYWORDS="*"
S="${WORKDIR}"
DEPEND="sys-firmware/edk2-ovmf-crosvm"

IUSE="dlc"
REQUIRED_USE="dlc"

# Currently BIOS image is 3.7MB. Reserve 3.7MB + space for growth.
# 1MiB = 256 x 4KiB blocks
DLC_PREALLOC_BLOCKS="$((4 * 256))"

DLC_PRELOAD=true

DLC_NAME="edk2-ovmf-dlc"

LOCAL_ENV_DLC_PATH="/opt"
LOCAL_ENV_FW_IMAGE_PATH="${SYSROOT}/build/share/edk2-ovmf-crosvm/CROSVM_CODE.fd"

src_install() {
	# Setup DLC paths.
	into "$(dlc_add_path "${LOCAL_ENV_DLC_PATH}")"
	insinto "$(dlc_add_path "${LOCAL_ENV_DLC_PATH}")"
	exeinto "$(dlc_add_path "${LOCAL_ENV_DLC_PATH}")"
	doins "${LOCAL_ENV_FW_IMAGE_PATH}"
	dlc_src_install
}
