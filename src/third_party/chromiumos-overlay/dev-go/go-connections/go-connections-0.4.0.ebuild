# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# this revision is a bit newer than the 0.4.0 tagged released commit, it is the
# original revision used before the CrOS Go modules conversion, to avoid breakages
# bt future upgrades should use the tagged release commits
CROS_GO_SOURCE="github.com/docker/go-connections 88e5af338bb1e6c7f51b69cc1864249d1e8f4786"

CROS_GO_PACKAGES=(
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-connections/sockets"
	"github.com/docker/go-connections/tlsconfig"
)

inherit cros-go

DESCRIPTION="Utility package to work with network connections"
HOMEPAGE="https://github.com/docker/go-connections"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND="dev-go/errors"
RDEPEND="!<=dev-go/docker-20.10.8-r1"
