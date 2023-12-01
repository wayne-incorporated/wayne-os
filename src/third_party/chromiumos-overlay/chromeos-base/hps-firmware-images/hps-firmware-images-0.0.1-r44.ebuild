# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="7da2ddb1a418232fa0711ed09725ffb1bf56953c"
CROS_WORKON_TREE="f84c9e58f975d7284c7bad8db4fe363d3ab28cbb"
CROS_WORKON_PROJECT="chromiumos/platform/hps-firmware-images"
CROS_WORKON_LOCALNAME="platform/hps-firmware-images"

inherit cros-workon

DESCRIPTION="Chrome OS HPS firmware"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/hps-firmware-images/+/HEAD"

# For more details about the license, please refer to b/194344208#comment10.
LICENSE="BSD-Google BSD-2 Apache-2.0 MIT 0BSD BSD ISC"
KEYWORDS="*"

# before signing firmware files were installed from this source ebuild
RDEPEND="
	!<chromeos-base/hps-firmware-0.1.0-r296
"

src_install() {
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
	python3 -c "with open('firmware-signed/mcu_stage1.bin', 'rb') as f:
		f.seek(20);
		print(int.from_bytes(f.read(4), 'big'))" \
		>firmware-signed/mcu_stage1.version.txt || die

	# Compress firmware images to save space. hpsd will decompress these on the fly.
	# hpsd limits decompression memory to 20MiB. xz(1) explains:
	# "The settings used when compressing a file determine the memory
	# requirements of the decompressor.  Typically the decompressor needs
	# 5 % to 20 % of the amount of memory that the compressor needed when
	# creating the file." Thus we apply a limit of 80MiB when compressing.
	xz -9 --memlimit-compress=80MiB \
		firmware-signed/fpga_application.bin \
		firmware-signed/fpga_bitstream.bin \
		firmware-signed/mcu_stage1.bin

	insinto "/usr/lib/firmware/hps"
	doins "${S}/firmware-signed/fpga_application.bin.xz"
	doins "${S}/firmware-signed/fpga_bitstream.bin.xz"
	doins "${S}/firmware-signed/mcu_stage1.bin.xz"
	doins "${S}/firmware-signed/mcu_stage1.version.txt"
	doins "${S}/firmware-signed/manifest.txt"
}
