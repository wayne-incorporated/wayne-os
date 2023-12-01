# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# 6ba98ff60144f60aba589b4d6121689528fbae76 is the current version as of Nov 12, 2019.
# ACVPTool in this version supports the algorithms needed by cr50 for FIPS testing.
CROS_GO_SOURCE="boringssl.googlesource.com/boringssl 6ba98ff60144f60aba589b4d6121689528fbae76"

CROS_GO_PACKAGES=(
	"boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool/acvp"
	"boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool/subprocess"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="A tool for speaking to the NIST ACVP server."
HOMEPAGE="https://boringssl.googlesource.com/boringssl/+/master/util/fipstools/acvp/acvptool/"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google SSLeay"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
