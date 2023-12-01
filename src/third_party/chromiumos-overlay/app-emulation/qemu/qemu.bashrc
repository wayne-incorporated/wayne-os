# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_post_src_install_lddtree() {
	# Vars that Gentoo provides, but shellcheck doesn't understand.
	: "${D:=}"
	: "${SYSROOT:=}"

	# Create a package we can use outside the SDK.
	# Only do this for the few tools we use for chromite.lib.vm.
	local prog progs=( qemu-img qemu-system-aarch64 qemu-system-x86_64 )
	/mnt/host/source/chromite/bin/lddtree \
		--copy-to "${D}/usr/libexec/qemu" \
		--libdir /lib \
		--bindir /bin \
		--generate-wrappers \
		"${progs[@]/#/${D}/usr/bin/}" || die
	# glibc dynamically loads these based on /etc/nsswich.conf, so we have
	# to copy them over manually.
	cp "${SYSROOT}/$(get_libdir)/libnss_"{compat,db,dns,files}.so.2 \
		"${D}/usr/libexec/qemu/lib/" || die
	# No need to duplicate this in the package itself.
	for prog in "${progs[@]}"; do
		dosym ../../../bin/"${prog}" /usr/libexec/qemu/bin/"${prog}".elf
	done
	# QEMU searches for its bios files relative to itself.  Add a symlink so it
	# can find the installed bios files under /usr/share/qemu/.
	dosym ../../share/qemu /usr/libexec/qemu/pc-bios
	dosym ../../share /usr/libexec/qemu/share
}
