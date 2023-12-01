# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="ADL-N Acoustic Echo Cancellation params for on/off respectively"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-nissa-${PV}.tar.bz2"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-nissa-${PV}

src_install() {
	insinto /opt/google/rtc_audio_processing/
	doins ./*.bin
}
