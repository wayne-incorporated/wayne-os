# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/golang/groupcache 0c9617f2e0990bd8a5f8bb87fd1535575d2e3e2c"

CROS_GO_PACKAGES=(
	"github.com/golang/groupcache/lru"
)

CROS_GO_TEST=(
	"github.com/golang/groupcache"
)

inherit cros-go

DESCRIPTION="Distributed caching and cache-filling library"
HOMEPAGE="https://github.com/golang/groupcache"
SRC_URI="$(cros-go_src_uri)"

LICENSE="FTL"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks"

DEPEND=""
RDEPEND=""
