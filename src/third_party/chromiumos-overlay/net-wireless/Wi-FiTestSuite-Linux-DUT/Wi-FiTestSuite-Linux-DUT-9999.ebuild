# Copyright 2020 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

CROS_WORKON_PROJECT="chromiumos/third_party/Wi-FiTestSuite-Linux-DUT"
CROS_WORKON_LOCALNAME="Wi-FiTestSuite-Linux-DUT"

inherit cros-workon

DESCRIPTION="A DUT controller for Wi-Fi Alliance's Certification Test Suite"
HOMEPAGE="https://github.com/Wi-FiTestSuite/Wi-FiTestSuite-Linux-DUT"

LICENSE="ISC"
SLOT="0"
KEYWORDS="~*"
IUSE=""

src_compile() {
	emake V=1
}

src_install() {
	exeinto /usr/local/bin
	doexe dut/wfa_dut
	doexe ca/wfa_ca
	doexe shbin/*
	exeinto /usr/local/libexe/wfa
	doexe scripts/*
}
