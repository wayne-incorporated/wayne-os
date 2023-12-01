# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v3
#
# Web port of the Google text-to-speech engine.

EAPI=6

DESCRIPTION="Google text-to-speech engine"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

# Files in /usr/share/chromeos-assets/speech_synthesis/ moved from
# chromeos-base/common-assets.
RDEPEND="!<chromeos-base/common-assets-0.0.2-r123"

S="${WORKDIR}"

src_install() {
	local tts_path=/usr/share/chromeos-assets/speech_synthesis
	mkdir -p "patts" || die

	if use amd64 ; then
		cp "libchrometts_x86_64.so" "patts/libchrometts.so" || die
	elif use arm64 ; then
		cp "libchrometts_arm64.so" "patts/libchrometts.so" || die
	elif use arm ; then
		cp "libchrometts_armv7.so" "patts/libchrometts.so" || die
	else
		ewarn "Text-to-speech unsupported on this architecture."
		return
	fi

	cp ./*.{css,html,js,json,png,svg,zvoice} "patts/" || die

	chmod 644 patts/* || die
	chmod 755 patts/libchrometts.so || die

	# Create and install a squashfs file.
	mksquashfs "patts" "patts.squash" 			-all-root \
		-noappend -no-recovery -no-exports -exit-on-error -comp zstd \
		-Xcompression-level 22 -b 1M -root-mode 0755 -no-progress || die

	keepdir "${tts_path}"/patts
	insinto "${tts_path}"
	doins "patts.squash"

	# Install an Upstart script that mount and unmount the squash file when
	# system-services start and stop.
	insinto "/etc/init"
	doins "googletts.conf"
}
