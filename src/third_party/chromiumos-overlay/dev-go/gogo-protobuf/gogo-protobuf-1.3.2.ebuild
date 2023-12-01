# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# this revision is a bit newer than the 1.3.2 tagged released commit, it is the
# original revision used before the CrOS Go modules conversion, to avoid breakages
# bt future upgrades should use the tagged release commits
CROS_GO_SOURCE="github.com/gogo/protobuf 226206f39bd7276e88ec684ea0028c18ec2c91ae"

CROS_GO_PACKAGES=(
	"github.com/gogo/protobuf/proto"
)

inherit cros-go

DESCRIPTION="Protocol Buffers for Go with Gadgets."
HOMEPAGE="https://github.com/gogo/protobuf"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND="
	dev-go/errcheck
	dev-go/go-tools
"
RDEPEND="!<=dev-go/docker-20.10.8-r1"
