# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cmake-utils

DESCRIPTION="Library to randomly mutate protobuffers."
HOMEPAGE="https://github.com/google/libprotobuf-mutator"
SRC_URI="https://github.com/google/${PN}/archive/${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="msan +static-libs"
RESTRICT="test"

DEPEND="dev-libs/protobuf:="
RDEPEND="${DEPEND}"
BDEPEND="${DEPEND}"

PATCHES=( "${FILESDIR}/fix-msan.patch" )

src_configure() {
	local mycmakeargs=(
		-DTHREADS_PTHREAD_ARG=-pthread
		-DBUILD_SHARED_LIBS:BOOL=$(usex static-libs OFF ON)
	)

	cmake-utils_src_configure
}

src_compile() {
	cmake-utils_src_make protobuf-mutator protobuf-mutator-libfuzzer
}

src_install() {
	local inst_dir="/usr/include/libprotobuf-mutator"
	insinto "${inst_dir}/port"
	doins port/*.h
	insinto "${inst_dir}/src"
	doins src/*.h
	insinto "${inst_dir}/src/libfuzzer"
	doins src/libfuzzer/*.h

	insinto /usr/share/pkgconfig
	doins "${FILESDIR}/${PN}.pc"

	local base_lib="${BUILD_DIR}/src/libprotobuf-mutator"
	local fuzzer_lib="${BUILD_DIR}/src/libfuzzer/libprotobuf-mutator-libfuzzer"
	if use static-libs; then
		dolib.a "${base_lib}.a"
		dolib.a "${fuzzer_lib}.a"
	else
		dolib.so "${base_lib}.so"
		dolib.so "${fuzzer_lib}.so"
	fi
}
