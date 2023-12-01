# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# No git repo for this so use empty-project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Rootfs lacros for all architectures"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
S="${WORKDIR}"

# All runtime dependencies should already be part of
# chromeos-base/chromeos-chrome, the ones that aren't will be handled in
# crbug.com/1199441.
RDEPEND="chromeos-base/chromeos-chrome"
DEPEND=""

if [[ ${PV} != 9999 ]]; then
	ORIG_URI="gs://chrome-unsigned/desktop-5c0tCh"
	SRC_URI="
		amd64? (
			${ORIG_URI}/${PV}/lacros64/lacros_compressed_zstd.squash -> ${PN}-amd64-squash-zstd-${PV}
			${ORIG_URI}/${PV}/lacros64/metadata.json -> ${PN}-amd64-metadata-${PV}
		)
		arm? (
			${ORIG_URI}/${PV}/lacros-arm32/lacros_compressed_zstd.squash -> ${PN}-arm-squash-zstd-${PV}
			${ORIG_URI}/${PV}/lacros-arm32/metadata.json -> ${PN}-arm-metadata-${PV}
		)
		arm64? (
			${ORIG_URI}/${PV}/lacros-arm64/lacros_compressed_zstd.squash -> ${PN}-arm64-squash-zstd-${PV}
			${ORIG_URI}/${PV}/lacros-arm64/metadata.json -> ${PN}-arm64-metadata-${PV}
		)
	"
fi

# Don't need to unpack anything.
# Also suppresses messages related to unpacking unrecognized formats.
src_unpack() {
	:
}

src_install() {
	insinto /opt/google/lacros
	newins "${DISTDIR}/${PN}-${ARCH}-squash-zstd-${PV}" lacros.squash
	newins "${DISTDIR}/${PN}-${ARCH}-metadata-${PV}" metadata.json

	# Upstart configuration
	insinto /etc/init
	doins "${FILESDIR}/lacros-mounter.conf"
	doins "${FILESDIR}/lacros-unmounter.conf"

	# D-Bus configuration
	insinto /etc/dbus-1/system.d
	doins "${FILESDIR}/Lacros.conf"
}
