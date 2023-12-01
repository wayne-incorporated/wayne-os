# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="5"

inherit eutils toolchain-funcs

DESCRIPTION="Infineon TPM firmware updater"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="BSD-Infineon LICENSE.infineon-firmware-updater-TCG"
SLOT="0"
KEYWORDS="*"
IUSE="tpm_slb9655_v4_31"

DEPEND="test? ( dev-util/shunit2 )"

RDEPEND="
	dev-libs/openssl:0=
	tpm_slb9655_v4_31? ( chromeos-base/ec-utils )
"

DEPEND="${RDEPEND}"

S="${WORKDIR}"

src_prepare() {
	epatch "${FILESDIR}"/makefile-fixes.patch
	epatch "${FILESDIR}"/unlimited-log-file-size.patch
	epatch "${FILESDIR}"/dry-run-option.patch
	epatch "${FILESDIR}"/change_default_password.patch
	epatch "${FILESDIR}"/retry-send-on-ebusy.patch
	epatch "${FILESDIR}"/ignore-error-on-complete-option.patch
	epatch "${FILESDIR}"/update-type-ownerauth.patch
	epatch "${FILESDIR}"/openssl-1.1.patch
	epatch "${FILESDIR}"/wno-error.patch
}

src_configure() {
	# Disable -Wstrict-prototypes, b/230345382.
	append-flags -Wno-strict-prototypes
	tc-export AR CC
}

src_compile() {
	emake -C TPMFactoryUpd
}

src_test() {
	"${FILESDIR}"/tpm-firmware-updater-test || die
}

src_install() {
	newsbin TPMFactoryUpd/TPMFactoryUpd infineon-firmware-updater
	dosbin "${FILESDIR}"/tpm-firmware-updater
	dosbin "${FILESDIR}"/tpm-firmware-locate-update
	dosbin "${FILESDIR}"/tpm-firmware-update-cleanup

	insinto /etc/init
	doins "${FILESDIR}"/tpm-firmware-check.conf
	doins "${FILESDIR}"/tpm-firmware-update.conf
	doins "${FILESDIR}"/send-tpm-firmware-update-metrics.conf
	exeinto /usr/share/cros/init
	doexe "${FILESDIR}"/tpm-firmware-check.sh
	doexe "${FILESDIR}"/tpm-firmware-update.sh
	doexe "${FILESDIR}"/tpm-firmware-update-factory.sh
}
