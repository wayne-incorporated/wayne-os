# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# pick mod at the current head of release-branch.go1.17
# commit 49f84bccfd3469cb3095201f7855641bcc8eb49a (tag: v0.5.1, origin/release-branch.go1.17)
CROS_GO_SOURCE="go.googlesource.com/mod:golang.org/x/mod v${PV}"

CROS_GO_PACKAGES=(
	"golang.org/x/mod/module"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/internal/lazyregexp"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="packages for writing tools that work directly with Go module mechanics"
HOMEPAGE="https://golang.org/x/mod"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/crypto
	dev-go/xerrors
	dev-go/yaml:3
"
RDEPEND="${DEPEND}"
