# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="85984bf86609d49522802e77684a327c847f8dd3"
CROS_WORKON_TREE="2b1750cb25c048b5c9c1dba061349abd52c5c012"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_SUBTREE="cronista"

inherit user cros-workon cros-rust

DESCRIPTION="Authenticated storage daemon."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/cronista/"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="manatee"

BDEPEND="dev-libs/protobuf"
RDEPEND="sys-apps/dbus"
DEPEND="
	cros_host? ( dev-libs/protobuf:= )
	dev-rust/third-party-crates-src:=
	chromeos-base/crosvm-base:=
	chromeos-base/libsirenia:=
	dev-rust/libchromeos:=
	dev-libs/openssl:0=
"

pkg_setup() {
	enewuser cronista
	enewgroup cronista
	cros-rust_pkg_setup
}

src_install() {
	local build_dir="$(cros-rust_get_build_dir)"
	dobin "${build_dir}/cronista"

	local daemon_store="/etc/daemon-store/cronista"
	dodir "${daemon_store}"
	fperms 0700 "${daemon_store}"
	fowners cronista:cronista "${daemon_store}"

	if use manatee ;  then
		insinto /etc/init
		doins upstart/cronista.conf
	fi
}
