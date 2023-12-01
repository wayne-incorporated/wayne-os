# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="modem logging blobs from fibocom"

LICENSE="BSD-Fibocom"
SLOT="0"
KEYWORDS="*"
IUSE=""

MIRROR_PATH="gs://chromeos-localmirror/distfiles"
SRC_URI="${MIRROR_PATH}/fibocomtools-${PV}.tar.xz"

S=${WORKDIR}
CAPTURE_TOOL_DIR="fibocomtools/Tool/CAPTURE_TOOL"
INSTALL_DIR="/opt/fibocom"

src_install() {
	insinto "${INSTALL_DIR}"
	doins -r "${WORKDIR}/fibocomtools"
	fperms 0755 "${INSTALL_DIR}/${CAPTURE_TOOL_DIR}/COMMON/bin/ccom"
	fperms 0755 "${INSTALL_DIR}/${CAPTURE_TOOL_DIR}/GL850/bin/tlog"
	fperms 0755 "${INSTALL_DIR}/${CAPTURE_TOOL_DIR}/NL668/bin/diaggrabpro"
}
