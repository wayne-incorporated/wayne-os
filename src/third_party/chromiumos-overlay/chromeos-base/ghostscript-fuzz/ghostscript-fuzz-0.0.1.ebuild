# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-fuzzer cros-sanitizers flag-o-matic

DESCRIPTION="Fuzzer for Ghostscript"
HOMEPAGE="http://www.chromium.org/"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="asan fuzzer"

COMMON_DEPEND="app-text/ghostscript-gpl:=[fuzzer]"
RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}"

# We really don't want to be building this otherwise.
REQUIRED_USE="fuzzer"

S="${WORKDIR}"

src_prepare() {
	default
	cp "${FILESDIR}"/* .
}

src_configure() {
	sanitizers-setup-env || die
	fuzzer-setup-binary || die
	export LDFLAGS+=" -lgs"
}

src_compile() {
	emake gstoraster_fuzzer
}

src_install() {
	local fuzzer_component_id="167231"
	fuzzer_install "${S}"/OWNERS gstoraster_fuzzer \
		--comp "${fuzzer_component_id}" \
		--options "${S}/gstoraster_fuzzer.options"
}
