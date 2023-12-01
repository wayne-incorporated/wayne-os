# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/golang/appengine:google.golang.org/appengine v${PV}"

CROS_GO_PACKAGES=(
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/internal"
	"google.golang.org/appengine/internal/app_identity"
	"google.golang.org/appengine/internal/base"
	"google.golang.org/appengine/internal/datastore"
	"google.golang.org/appengine/internal/log"
	"google.golang.org/appengine/internal/modules"
	"google.golang.org/appengine/internal/remote_api"
	"google.golang.org/appengine/internal/socket"
	"google.golang.org/appengine/internal/urlfetch"
	"google.golang.org/appengine/datastore/internal/cloudkey"
	"google.golang.org/appengine/datastore/internal/cloudpb"
	"google.golang.org/appengine/socket"
	"google.golang.org/appengine/urlfetch"
)

inherit cros-go

DESCRIPTION="Go APIs for interacting with App Engine."
HOMEPAGE="https://github.com/golang/appengine"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	dev-go/net
	dev-go/protobuf-legacy-api
	dev-go/text
"
RDEPEND="${DEPEND}"
