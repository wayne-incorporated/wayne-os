# Copyright 2023 ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE="github.com/google/go-tpm v${PV}"

CROS_GO_PACKAGES=(
	"github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

inherit cros-go

DESCRIPTION="This is a go library for working with TPM devices, that is encoding and decoding binary commands."
HOMEPAGE="https://github.com/google/go-tpm"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/go-sys"
RDEPEND=""
