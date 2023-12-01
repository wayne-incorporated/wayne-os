# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Generate and install some files of various sizes to test image
size calculations."
HOMEPAGE="https://chromium.googlesource.com/"
SRC_URI=""
LICENSE="BSD-Google"
KEYWORDS="*"
IUSE=""


src_compile() {
	echo "a" > a-1byte.txt
	dd if=/dev/zero of="512-1-512.txt" bs=512 count=1
	dd if=/dev/zero of="512-2-1024.txt" bs=512 count=2
	dd if=/dev/zero of="512-4-2048.txt" bs=512 count=4
	dd if=/dev/zero of="512-6-3072.txt" bs=512 count=6
	dd if=/dev/zero of="512-8-4096.txt" bs=512 count=8
	dd if=/dev/zero of="4096-1-4096.txt" bs=4096 count=1
	dd if=/dev/zero of="4096-2-8192.txt" bs=4096 count=2
	dd if=/dev/zero of="4096-4-16384.txt" bs=4096 count=4
	dd if=/dev/zero of="4096-6-24576.txt" bs=4096 count=6
	dd if=/dev/zero of="4096-8-32768.txt" bs=4096 count=8
}

src_install() {
	dodir /etc/size-test
	insinto /etc/size-test
	doins "a-1byte.txt"
	doins "512-1-512.txt"
	doins "512-2-1024.txt"
	doins "512-4-2048.txt"
	doins "512-6-3072.txt"
	doins "512-8-4096.txt"
	doins "4096-1-4096.txt"
	doins "4096-2-8192.txt"
	doins "4096-4-16384.txt"
	doins "4096-6-24576.txt"
	doins "4096-8-32768.txt"
}
