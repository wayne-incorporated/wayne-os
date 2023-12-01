# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/pkg/sftp v${PV}"

CROS_GO_PACKAGES=(
	"github.com/pkg/sftp"
	"github.com/pkg/sftp/internal/encoding/ssh/filexfer"
)

inherit cros-go

DESCRIPTION="The sftp package provides support for file system operations on remote ssh servers using the SFTP subsystem. "
HOMEPAGE="https://github.com/pkg/sftp"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/crypto
	dev-go/go-sys
	dev-go/kr-fs
	dev-go/testify
"
RDEPEND=""
