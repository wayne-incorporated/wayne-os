# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit cros-binary

DESCRIPTION="RFIM Policy for Intel(R) Dynamic Platform & Thermal Framework"

LICENSE="LICENSE.intel-dptf-private"
SLOT="0"
KEYWORDS="*"
S="${WORKDIR}"

CROS_BINARY_URI="dptf/DptfPolicyRfim-${PV}.tbz2"

# chipset-kbl binary can be used for all Intel platform.
cros-binary_add_gs_uri bcs-chipset-kbl-private chipset-kbl-private \
	"${CROS_BINARY_URI}"

src_install() {
	# Install DPTF policy add-on library.
	dolib.so DptfPolicyRfim.so
	dolib.so upe_wifi.so
}
