# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Chrome OS restricted set of certificates"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/docs/+/HEAD/ca_certs.md"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}

src_compile() {
	"${FILESDIR}/split-root-certs.py" \
		--extract-to "${S}" \
		--roots-pem "${FILESDIR}/roots.pem" \
		|| die "Couldn't extract certs from roots.pem"
}

src_install() {
	CA_CERT_DIR=/usr/share/chromeos-ca-certificates
	insinto "${CA_CERT_DIR}"
	doins *.pem
	c_rehash "${D}/${CA_CERT_DIR}"
}
