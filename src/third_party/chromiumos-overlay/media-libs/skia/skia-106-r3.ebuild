# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-common.mk ninja-utils python-any-r1 toolchain-funcs

DESCRIPTION="Skia: The 2D Graphics Library"
HOMEPAGE="https://github.com/google/skia"

# The latest skia milestone when this ebuild is created.
# https://github.com/google/skia/blob/main/include/core/SkMilestone.h
GIT_SHA1="52aecbec6fb24f9cf0491563674906a9a43170da"

SRC_URI="https://github.com/google/skia/archive/${GIT_SHA1}.tar.gz -> ${P}.tar.gz"
S="${WORKDIR}/${PN}-${GIT_SHA1}"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	virtual/opengles:=
	media-libs/freetype:2=
"
DEPEND="
	x11-drivers/opengles-headers:=
	${RDEPEND}
	${PYTHON_DEPS}
"

src_prepare() {
	default

	# change the include path of skia from include/ to skia/
	find experimental/ include/ modules/ src/ third_party/ \
		'(' -name '*.h' -o -name '*.cpp' -o -name '*.c' ')' \
		-exec sed -i 's|#include "include/|#include "skia/|g' {} + || die
	mv include/ skia/ || die
}

src_configure() {
	python_setup
	tc-export AR CC CXX

	local gn_flags=(
		ar=\""${AR}"\"
		cc=\""${CC}"\"
		cxx=\""${CXX}"\"
		is_component_build=true
		is_official_build=true
		skia_build_fuzzers=false
		skia_enable_gpu=true
		skia_enable_graphite=false
		skia_enable_particles=false
		skia_enable_pdf=false
		skia_enable_precompile=false
		skia_enable_skottie=false
		skia_enable_skshaper=false
		skia_gl_standard=\"gles\"
		skia_system_freetype2_include_path=\""${EROOT}/usr/include/freetype2"\"
		skia_use_egl=true
		skia_use_expat=false
		skia_use_fontconfig=false
		skia_use_freetype=true
		skia_use_harfbuzz=false
		skia_use_icu=false
		skia_use_libfuzzer_defaults=false
		skia_use_libgifcodec=false
		skia_use_libheif=false
		skia_use_libjpeg_turbo_encode=false
		skia_use_libjpeg_turbo_decode=false
		skia_use_libpng_decode=false
		skia_use_libpng_encode=false
		skia_use_libwebp_decode=false
		skia_use_libwebp_encode=false
		skia_use_perfetto=false
		skia_use_piex=false
		skia_use_x11=false
		skia_use_xps=false
		skia_use_zlib=false
	)

	if use x86; then
		gn_flags+=( target_cpu=\"x86\" )
	elif use amd64; then
		gn_flags+=( target_cpu=\"x64\" )
	elif use arm; then
		gn_flags+=( target_cpu=\"arm\")
	elif use arm64; then
		gn_flags+=( target_cpu=\"arm64\" )
	else
		die "Unknown arch ${ARCH}"
	fi


	passflags() {
		local flags parsed
		IFS=" " read -r -a flags <<< "${1}"
		parsed="[$(printf '"%s", ' "${flags[@]}")]"
		gn_flags+=( extra_"${2}""=""${parsed}" )
	}
	passflags "${CXXFLAGS}" cflags_cc
	passflags "${LDFLAGS}" ldflags
	passflags "${CFLAGS}" cflags_c

	local gn_flags_str="${gn_flags[*]}"
	set -- gn gen --args="${gn_flags_str% }" out || die
	echo "$@"
	"$@" || die
}

src_compile() {
	eninja -C out
}

src_install() {
	dolib.so out/*.so

	insinto "/usr/include/skia"
	doins -r skia modules

	insinto "/usr/$(get_libdir)/pkgconfig"
	sed -e "s:@LIB@:$(get_libdir):g" -e "s:@PV@:${PV}:g" \
		"${FILESDIR}"/skia.pc.in | newins - skia.pc
}
