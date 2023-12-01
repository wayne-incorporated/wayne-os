# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit meson cros-fuzzer cros-sanitizers

DESCRIPTION="eSCL and WSD SANE backend"
HOMEPAGE="https://github.com/alexpevzner/sane-airscan"
LICENSE="GPL-2"
SLOT="0/${PVR}"
KEYWORDS="*"
IUSE="fuzzer"

COMMON_DEPEND="
	dev-libs/libxml2:=
	media-gfx/sane-backends:=
	media-libs/libjpeg-turbo:=
	media-libs/libpng:=
	net-dns/avahi:=
	net-libs/libsoup:=
"
DEPEND="${COMMON_DEPEND}"
RDEPEND="${COMMON_DEPEND}"

# SHA-1 or tag will both work.
GIT_REF="0.99.27"
SRC_URI="https://github.com/alexpevzner/sane-airscan/archive/${GIT_REF}.tar.gz -> ${PN}-${GIT_REF}.tar.gz"
S="${WORKDIR}/${PN}-${GIT_REF}"

FUZZERS=(
	"fuzzer-query"
	"fuzzer-uri"
	"fuzzer-xml"
)

PATCHES=(
	"${FILESDIR}/${PN}-0.9.20-noasan.patch"
)

src_configure() {
	sanitizers-setup-env || die
	meson_src_configure
}

src_compile() {
	if use fuzzer; then
		meson_src_compile "${FUZZERS[@]}"
	else
		meson_src_compile
	fi
	# Generates a copy of airscan.conf with the lines after the debug tag uncommented.
	sed -e '/^#*\[debug\]/,$s/^#*//' < "${FILESDIR}/airscan.conf" > "${BUILD_DIR}/airscan-debug.conf"
}

src_install() {
	if ! use fuzzer; then
		dobin "${BUILD_DIR}/airscan-discover"

		exeinto "/usr/$(get_libdir)/sane"
		doexe "${BUILD_DIR}/libsane-airscan.so.1"

		insinto "/etc/sane.d"
		newins "${FILESDIR}/airscan.conf" "airscan.conf"

		insinto "/usr/share/sane"
		newins "${BUILD_DIR}/airscan-debug.conf" "airscan-debug.conf"

		insinto "/etc/sane.d/dll.d"
		newins "${S}/dll.conf" "airscan.conf"
	fi

	# Safe to call even if the fuzzer isn't built because this won't do
	# anything unless we have USE=fuzzer.
	for fuzzer in "${FUZZERS[@]}"; do
		# Rename fuzzers before install because the upstream target
		# names ended up being different from our naming scheme.
		local compat_name="airscan_${fuzzer#fuzzer-}_fuzzer"
		mv "${BUILD_DIR}/${fuzzer}" "${BUILD_DIR}/${compat_name}"
		local fuzzer_component_id="860616"
		fuzzer_install "${FILESDIR}/fuzzers.owners" \
			"${BUILD_DIR}/${compat_name}" \
			--comp "${fuzzer_component_id}"
	done

	# Include sane-airscan/airscan.h in header
	mkdir "${BUILD_DIR}/sane-airscan"
	cp "${S}/airscan.h" "${BUILD_DIR}/sane-airscan"
	doheader -r "${BUILD_DIR}/sane-airscan"
}
