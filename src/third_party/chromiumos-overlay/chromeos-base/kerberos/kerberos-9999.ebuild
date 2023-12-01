# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
# TODO(b/187784160): Avoid directly including headers from other packages.
CROS_WORKON_SUBTREE="common-mk kerberos libpasswordprovider metrics .gn"

PLATFORM_SUBDIR="kerberos"

inherit cros-workon platform user

DESCRIPTION="Requests and manages Kerberos tickets to enable Kerberos SSO"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/kerberos/"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="asan fuzzer"

COMMON_DEPEND="
	app-crypt/mit-krb5:=
	chromeos-base/libbrillo:=[asan?,fuzzer?]
	chromeos-base/libpasswordprovider:=
	>=chromeos-base/metrics-0.0.1-r3152:=
	chromeos-base/minijail:=
	dev-libs/protobuf:=
	sys-apps/dbus:=
"
RDEPEND="${COMMON_DEPEND}"
DEPEND="
	${COMMON_DEPEND}
	chromeos-base/protofiles:=
	chromeos-base/session_manager-client:=
	chromeos-base/system_api:=[fuzzer?]
"

pkg_setup() {
	# Has to be done in pkg_setup() instead of pkg_preinst() since
	# src_install() needs kerberosd.
	enewuser kerberosd
	enewgroup kerberosd
	enewuser kerberosd-exec
	enewgroup kerberosd-exec
	cros-workon_pkg_setup
}

src_install() {
	platform_src_install

	# Create daemon store folder prototype, see
	# https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md#securely-mounting-cryptohome-daemon-store-folders
	local daemon_store="/etc/daemon-store/kerberosd"
	dodir "${daemon_store}"
	fperms 0770 "${daemon_store}"
	fowners kerberosd:kerberosd "${daemon_store}"

	# fuzzer_component_id is unknown/unlisted
	platform_fuzzer_install "${S}/OWNERS" "${OUT}"/config_parser_fuzzer \
		--dict "${S}"/config_parser_fuzzer.dict || die
}

platform_pkg_test() {
	platform test_all
}
