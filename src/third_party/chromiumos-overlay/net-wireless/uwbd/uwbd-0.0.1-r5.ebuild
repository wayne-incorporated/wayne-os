# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT="52d1cd3ac41f7e1e4747bb2c95cd073daf22d5ae"
CROS_WORKON_TREE="bce9bb66d8c0eef7f757f9ac2219438b397c5889"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_DESTDIR="${S}"
CROS_WORKON_SUBTREE="uwbd"
CROS_WORKON_INCREMENTAL_BUILD=1

inherit cros-workon cros-rust user

DESCRIPTION="The UWB D-Bus daemon"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/uwbd"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"
IUSE="uwbd_client"

BDEPEND="dev-libs/protobuf"
DEPEND="
	cros_host? ( dev-libs/protobuf:= )
	dev-rust/third-party-crates-src:=
	dev-rust/chromeos-dbus-bindings:=
	dev-rust/libchromeos:=
	net-wireless/uwb_core:=
"
RDEPEND="${DEPEND}"

pkg_preinst() {
	# Create user and group for uwbd
	enewuser "uwbd"
	enewgroup "uwbd"
}

src_install() {
	# Install the uwbd binary.
	dobin "$(cros-rust_get_build_dir)/uwbd"
	if use uwbd_client; then
		dobin "$(cros-rust_get_build_dir)/uwbd_client"
	fi

	# Install the DBus config.
	insinto /etc/dbus-1/system.d
	doins dbus/org.chromium.uwbd.conf

	# Install the upstart config.
	insinto /etc/init
	doins upstart/uwbd.conf

	# Install the seccomp filter.
	insinto /usr/share/policy
	doins upstart/seccomp/uwbd-seccomp.policy
}
