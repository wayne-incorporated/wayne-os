# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/googleapis/enterprise-certificate-proxy v${PV}"

CROS_GO_PACKAGES=(
	"github.com/googleapis/enterprise-certificate-proxy/client/..."
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Google Proxies for Enterprise Certificates"
HOMEPAGE="github.com/googleapis/enterprise-certificate-proxy"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"
