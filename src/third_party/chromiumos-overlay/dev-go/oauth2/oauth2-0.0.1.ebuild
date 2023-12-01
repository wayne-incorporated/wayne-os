# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/oauth2:golang.org/x/oauth2 b44042a4b9c12aec471902e0287a912bcb3ac1db"

CROS_GO_PACKAGES=(
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
	"golang.org/x/oauth2/jwt"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/google/internal/externalaccount"
)

CROS_GO_TEST=(
	"golang.org/x/oauth2"
	#Flaky: "golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
	"golang.org/x/oauth2/jwt"
	"golang.org/x/oauth2/google"
)

inherit cros-go

DESCRIPTION="Go packages for oauth2"
HOMEPAGE="https://golang.org/x/oauth2"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/gcp-compute
	dev-go/cmp
	dev-go/net
	dev-go/appengine
"
RDEPEND="${DEPEND}"
