# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="b2d13b15353ff1bfc98f9713a7475bc1a326fdd2"
CROS_WORKON_TREE=("87ad1186bfc1f34a7c4b189f85791d0856febe36" "a0d8550678a1ed2a4ab62782049032a024bf40df" "05b3aedc9b0aca52205aae464767be201f5b6da2" "ffeac33c1fdeef5126592b3e76f125ec2a06e8a6" "77dd6b1964b41d55712d47784d71c3daf139930c" "a3e7069a974eff03c6ec1151b879c333985c9e89" "f8294a653aecfb61077b1f91d79f13365b6549bd" "3a7df68f70c7d697449fd6a965342139eb4dce18" "dc3c9db3d984574e13865d725f505035d6cac081" "433baf0de74de8f33b68fd0bec974e95440ecd74")
CROS_RUST_SUBDIR="system_api"

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR} authpolicy/dbus_bindings cryptohome/dbus_bindings debugd/dbus_bindings dlcservice/dbus_adaptors login_manager/dbus_bindings shill/dbus_bindings power_manager/dbus_bindings vm_tools/dbus_bindings vtpm"

inherit cros-workon cros-rust

DESCRIPTION="Chrome OS system API D-Bus bindings for Rust."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/system_api/"

LICENSE="BSD-Google"
SLOT="0/${PVR}"
KEYWORDS="*"

BDEPEND="dev-libs/protobuf"
DEPEND="
	cros_host? ( dev-libs/protobuf:= )
	dev-rust/third-party-crates-src:=
	dev-rust/chromeos-dbus-bindings:=
	sys-apps/dbus:=
"
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}
	!chromeos-base/system_api-rust
"

src_install() {
	# We don't want the build.rs to get packaged with the crate. Otherwise
	# we will try and regenerate the bindings.
	rm build.rs || die "Cannot remove build.rs"

	cros-rust_src_install
}
