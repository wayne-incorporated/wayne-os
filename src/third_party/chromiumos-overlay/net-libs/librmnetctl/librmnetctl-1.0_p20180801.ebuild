# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

inherit cros-sanitizers toolchain-funcs

DESCRIPTION="Userspace interface to RmNet driver"
HOMEPAGE="https://source.codeaurora.org/quic/lc/chromiumos/third_party/librmnetctl"
GIT_SHA1="916d3a45539cea163dbb9c6be8b3b94692401df8"

# The source package is a snapshot of commit ${GIT_SHA1} on the LC.UM.1.0
# branch of the upstream repository at
# https://source.codeaurora.org/quic/lc/chromiumos/third_party/librmnetctl
# and created as follows:
#
#   git clone https://source.codeaurora.org/quic/lc/chromiumos/third_party/librmnetctl -b LC.UM.1.0
#   cd librmnetctl
#   git archive --format=tar.gz -9 -o librmnetctl-1.0_p"$(date +%Y%m%d)".tar.gz \
#       --prefix="${GIT_SHA1}"/ "${GIT_SHA1}"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="asan"

S="${WORKDIR}/${PN}-${GIT_SHA1}"

src_prepare() {
	default
}

src_configure() {
	sanitizers-setup-env
}

src_install() {
	emake prefix="${ED}/usr" libdir="\$(prefix)/$(get_libdir)" install
}
