# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="91ac10a0ccfcd551da72b79264b79938fbabedd2"
CROS_WORKON_TREE="4a9fa5274fe8685137e6d13fdf030e36e87c925d"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_DESTDIR="${S}"
CROS_WORKON_SUBTREE="crosh"

inherit cros-workon cros-rust

DESCRIPTION="Chrome OS developer command-line shell"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/crosh/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"
IUSE=""

COMMON_DEPEND="
	chromeos-base/vboot_reference:=
	sys-apps/dbus
"

DEPEND="${COMMON_DEPEND}
	dev-rust/third-party-crates-src:=
	dev-rust/libchromeos:=
	dev-rust/system_api:=
	>dev-rust/tlsdate_dbus-0.24.52-r8:=
	sys-apps/dbus:=
"
RDEPEND="${COMMON_DEPEND}
	app-admin/sudo
	net-misc/iputils
	net-misc/openssh
	net-wireless/iw
	sys-apps/net-tools
"

src_test() {
	./run_tests.sh || die

	local args=()
	# (b/197637613) reduce the number of futex calls to reduce the risk of a hang
	# when running inside qemu.
	if ! cros_rust_is_direct_exec; then
		args+=( -- --test-threads=1 )
	fi

	cros-rust_src_test "${args[@]}"
}

src_install() {
	dobin "$(cros-rust_get_build_dir)/crosh"
	newbin crosh crosh.sh
	dobin network_diag
	local d="/usr/share/crosh"
	insinto "${d}/dev.d"
	doins dev.d/*.sh
	insinto "${d}/removable.d"
	doins removable.d/*.sh
}
