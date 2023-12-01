# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This is the DLC packs the shared libraries used by assistant in chrome.

EAPI=7

inherit cros-workon dlc

# No git repo for this so use empty-project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Assistant DLC"
SRC_URI=""

# V2 of libassistant.so will be downloaded and packed.
DEPEND="
	chromeos-base/chromeos-chrome:=[chrome_internal]
"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
S="${WORKDIR}"

# libassistant_v2.so is ~21MB.
# Account for growth:
# 40MB / 4KB block size = 10240 blocks.
DLC_PREALLOC_BLOCKS="10240"
DLC_NAME="Assistant DLC"
# Tast tests run against libassistant.so
DLC_PRELOAD=true

# Enabled scaled design.
DLC_SCALED=true

CHROME_DIR=/opt/google/chrome
LIBASSISTANT_DIR="${SYSROOT}/build/share/libassistant"

# Don't need to unpack anything.
# Also suppresses messages related to unpacking unrecognized formats.
src_unpack() {
	:
}

src_install() {
	exeinto "$(dlc_add_path ${CHROME_DIR})"
	doexe "${LIBASSISTANT_DIR}/libassistant_v2.so"
	dlc_src_install
}
