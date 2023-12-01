# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This ebuild simply makes the latest HPS firmware binaries available
# on the ChromeOS test image. These firmware binaries are unsigned.

EAPI=7

# We depend on hps-firmware2 to ensure that a new image is
# copied if source code has changed
CROS_WORKON_PROJECT="chromiumos/platform/hps-firmware"
CROS_WORKON_LOCALNAME="platform/hps-firmware2"

inherit cros-workon

DESCRIPTION="Chrome OS Unsigned HPS firmware for testing"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/hps-firmware/+/HEAD"

# For more details about the license, please refer to b/194344208#comment10.
LICENSE="BSD-Google BSD-2 Apache-2.0 MIT 0BSD BSD ISC"
KEYWORDS="~*"
SLOT="0"

DEPEND="
	chromeos-base/hps-firmware
"

src_unpack() {
	# Fetch unsigned images from /firmware/hps
	mkdir -p "${S}"
	FROM_DIR="${ESYSROOT}/firmware/hps/"
	cp "${FROM_DIR}/mcu_stage1.bin" "${S}"
	cp "${FROM_DIR}/manifest.txt" "${S}"
	cp "${FROM_DIR}/fpga_bitstream.bin" "${S}"
	cp "${FROM_DIR}/fpga_application.bin" "${S}"
}

src_compile() {
	# Nothing to compile
	:
}

src_install() {
	# Much of the logic here copied from hps-firmware-images.ebuild

	# Generate a single combined LICENSE file from all applicable license texts,
	# so that the Chrome OS license scanner can find it.
	cat <<-EOF > LICENSE
	HPS firmware source code is available under the Apache License 2.0.
	HPS firmware binaries also incorporate source code from several
	other projects under other licenses:
	EOF
	cat licenses/third-party/* >> LICENSE

	# Extract stage1 version (currently this is just the first 4 bytes of the
	# stage1 signature).
	python3 -c "with open('mcu_stage1.bin', 'rb') as f:
		f.seek(20);
		print(int.from_bytes(f.read(4), 'big'))" \
		>mcu_stage1.version.txt || die

	# Compress firmware images to save space. hpsd will decompress these on the fly.
	# hpsd limits decompression memory to 20MiB. xz(1) explains:
	# "The settings used when compressing a file determine the memory
	# requirements of the decompressor.  Typically the decompressor needs
	# 5 % to 20 % of the amount of memory that the compressor needed when
	# creating the file." Thus we apply a limit of 80MiB when compressing.
	xz -9 --memlimit-compress=80MiB \
		fpga_application.bin \
		fpga_bitstream.bin \
		mcu_stage1.bin

	insinto "/usr/lib/firmware/hps/latest"
	doins "${S}/fpga_application.bin.xz"
	doins "${S}/fpga_bitstream.bin.xz"
	doins "${S}/mcu_stage1.bin.xz"
	doins "${S}/mcu_stage1.version.txt"
	doins "${S}/manifest.txt"
}
