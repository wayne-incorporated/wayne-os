# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
# We don't use CROS_WORKON_OUTOFTREE_BUILD here since project's Cargo.toml is
# using "provided by ebuild" macro which supported by cros-rust.
CROS_WORKON_SUBTREE="shadercached"

inherit cros-workon cros-rust user

DESCRIPTION="Shader cache management daemon"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/shadercached/"

LICENSE="BSD-Google"
SLOT="0/${PVR}"
KEYWORDS="~*"

DEPEND="
	dev-rust/third-party-crates-src:=
	dev-rust/system_api:=
	dev-rust/libchromeos:=
	sys-apps/dbus:=
"
RDEPEND="sys-apps/dbus:="

src_install() {
	dobin "$(cros-rust_get_build_dir)/shadercached"

	# create a directory in /etc so that /run/daemon-store is created and mounted
	# by cryptohome
	local daemon_store="/etc/daemon-store/shadercached"
	dodir "${daemon_store}"
	fperms 0750 "${daemon_store}"
	fowners shadercached:shadercached "${daemon_store}"

	# D-Bus configuration.
	insinto /etc/dbus-1/system.d
	doins dbus/org.chromium.ShaderCache.conf

	# Init configuration
	insinto /etc/init
	doins init/shadercached.conf

	# Minijail configuration.
	insinto /usr/share/minijail
	doins minijail/shadercached.conf
}

pkg_setup() {
	# enewuser/group has to be done in pkg_setup() instead of pkg_preinst() since
	# src_install() needs shadercached user and group
	enewuser shadercached
	enewgroup shadercached
	cros-workon_pkg_setup
}
