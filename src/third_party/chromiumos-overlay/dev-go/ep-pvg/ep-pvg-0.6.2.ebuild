# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/gcp* packages are all built from this repo.  They should
# be updated together.
CROS_GO_SOURCE="github.com/envoyproxy/protoc-gen-validate:github.com/envoyproxy/protoc-gen-validate v${PV}"

CROS_GO_PACKAGES=(
	"github.com/envoyproxy/protoc-gen-validate/validate"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Protoc plugin to generate polyglot message validators"
HOMEPAGE="https://github.com/envoyproxy/go-control-plane/protoc-gen-validate"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks"

DEPEND="
	dev-go/afero
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	dev-go/strcase
"
RDEPEND="${DEPEND}"
