# Copyright 2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="583d14842cb0af67b4aa1840efd8a116bf125030"
CROS_WORKON_TREE="5f948aa7213ed5e2faed7bacbc944f8358919e46"
CROS_WORKON_PROJECT="chromiumos/platform/feature-management"
CROS_WORKON_LOCALNAME="platform/feature-management"

CROS_WORKON_INCREMENTAL_BUILD=1

inherit cros-workon

DESCRIPTION="Public Feature data"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/feature-management"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="feature_management feature_management_bsp"

# Only a DEPEND, since this package only install file needed for compiling
# libsegmentation.
DEPEND="
	feature_management? ( chromeos-base/feature-management-private:= )
	feature_management_bsp? ( chromeos-base/feature-management-bsp:= )
"

src_prepare() {
	# Install private starlak file, if any.
	if use feature_management; then
		find "${SYSROOT}/build/share/feature-management/private" -name "*.star" \
				-exec cp -t "${S}" {} \+ || die
	fi
	default
}

src_compile() {
	emake V=1
}

src_install() {
	insinto "/usr/include/libsegmentation"
	doins "${S}/generated/libsegmentation_pb.h"
	insinto "/build/share/libsegmentation"
	doins -r "${S}/proto"
}
