# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

CROS_WORKON_COMMIT="64edf0b872d4f2c8f21bb018c014f05b980d2f89"
CROS_WORKON_TREE="d613a987f8265b4c2f35dde9d07f6f026398532a"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_PROJECT="chromiumos/platform/audiotest"
CROS_WORKON_LOCALNAME="platform/audiotest"

inherit cros-sanitizers cros-workon cros-common.mk

DESCRIPTION="Audio test tools"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/audiotest"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="-asan"

RDEPEND="media-libs/alsa-lib
	media-sound/adhd"
DEPEND="${RDEPEND}"

src_configure() {
	export WITH_CRAS=true
	sanitizers-setup-env
	cros-common.mk_src_configure
	append-lfs-flags
}

src_test() {
	pushd script || die
	python3 -m unittest cyclic_bench_unittest || die
	popd > /dev/null || die
}

src_install() {
	# Install built tools
	pushd "${OUT:?OUT directory is not defined}" >/dev/null || die
	dobin src/alsa_api_test
	dobin alsa_conformance_test/alsa_conformance_test
	dobin src/alsa_helpers
	dobin src/audiofuntest
	dobin src/cras_api_test
	dobin loopback_latency/loopback_latency
	dobin script/alsa_conformance_test.py
	dobin script/cyclic_bench.py
	dobin script/audio_analysis.py
	dobin script/audio_data.py
	dobin script/audio_quality_measurement.py
	dobin script/check_recorded_frequency.py
	popd >/dev/null || die
}
