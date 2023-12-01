# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/spf13/afero v${PV}"

CROS_GO_PACKAGES=(
	"github.com/spf13/afero"
	"github.com/spf13/afero/mem"
	"github.com/spf13/afero/gcsfs"
)

# temp workaround to allow circular afero -> gcp-storage -> afero
# when migrating to modules mode this can be dropped because
# the upstream Go modules system supports circular deps
CROS_GO_SKIP_DEP_CHECK="1"

inherit cros-go

DESCRIPTION="A FileSystem Abstraction System for Go"
HOMEPAGE="https://github.com/spf13/afero"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/crypto
	dev-go/gapi
	dev-go/oauth2
	dev-go/sftp
	dev-go/text
"
RDEPEND=""
