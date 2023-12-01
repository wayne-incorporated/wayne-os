# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "cd857fe2b5ecdbe73201e3881c114ccb50ba7a8a" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_GO_PACKAGES=(
	"chromiumos/wilco_dtc/..."
)

CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk diagnostics/grpc .gn"

PLATFORM_SUBDIR="diagnostics/grpc"

WANT_LIBCHROME="no"
WANT_LIBBRILLO="no"
inherit cros-go cros-workon platform

DESCRIPTION="Chrome OS Wilco DTC proto/gRPC API"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/diagnostics/grpc"
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	dev-libs/protobuf:=
	dev-go/protobuf-legacy-api:=
	net-libs/grpc:=
"
DEPEND="
	${RDEPEND}
	dev-go/protobuf
	dev-go/grpc
"

src_unpack() {
	platform_src_unpack
	CROS_GO_WORKSPACE="${OUT}/gen/go"
}

src_install() {
	platform_src_install

	insinto /usr/"$(get_libdir)"/pkgconfig
	doins wilco_dtc_grpc_protos.pc

	insinto /usr/include/wilco_dtc/proto_bindings
	doins "${OUT}"/gen/include/*.h

	dolib.a "${OUT}"/*.a

	cros-go_src_install
}
