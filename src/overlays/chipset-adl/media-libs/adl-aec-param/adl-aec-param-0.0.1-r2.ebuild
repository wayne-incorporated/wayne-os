# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Alder Lake Acoustic Noise Cancellation params for on/off respectively"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-brya-${PV}.tar.bz2"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* x86 amd64"

S=${WORKDIR}/${PN}-brya-${PV}

src_install() {
	insinto /opt/google/rtc_audio_processing/
	doins AEC_On.bin
	doins AEC_Off.bin
}
