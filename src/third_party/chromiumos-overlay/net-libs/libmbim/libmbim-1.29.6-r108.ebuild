# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6
CROS_WORKON_COMMIT="b5b171fab4ab9dc68a81aed499c09e7a7541cdc6"
CROS_WORKON_TREE="5f7c00922960f05580691a76f8cae8f3d44c23ef"
CROS_WORKON_PROJECT="chromiumos/third_party/libmbim"

inherit meson cros-sanitizers cros-workon udev cros-fuzzer cros-sanitizers

DESCRIPTION="MBIM modem protocol helper library"
HOMEPAGE="http://cgit.freedesktop.org/libmbim/"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="-asan doc static-libs fuzzer"

RDEPEND=">=dev-libs/glib-2.36
	virtual/libgudev"

DEPEND="${RDEPEND}
	doc? ( dev-util/gtk-doc )
	virtual/pkgconfig"

src_configure() {
	sanitizers-setup-env

	append-cppflags -DMBIM_DISABLE_DEPRECATED

	local emesonargs=(
		--prefix='/usr'
		-Dmbim_username='modem'
		-Dlibexecdir='/usr/libexec'
		-Dudevdir='/lib/udev'
		-Dintrospection=false
		-Dman=false
		-Dbash_completion=false
		$(meson_use fuzzer)
	)
	meson_src_configure
}

src_install() {
	meson_src_install

	if use fuzzer; then
		local fuzzer_build_path="${BUILD_DIR}/src/libmbim-glib/test"
		cp "${fuzzer_build_path}/test-message-fuzzer" \
			"${fuzzer_build_path}/test-mbim-message-fuzzer" || die

		# ChromeOS/Platform/Connectivity/Cellular
		local fuzzer_component_id="167157"
		fuzzer_install "${S}/OWNERS" \
			"${fuzzer_build_path}/test-mbim-message-fuzzer" \
			--comp "${fuzzer_component_id}"
	fi
}
