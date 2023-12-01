# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT=(
	"breakpad/breakpad"
	"linux-syscall-support"
)
CROS_WORKON_LOCALNAME=(
	"third_party/breakpad"
	"third_party/breakpad/src/third_party/lss"
)
CROS_WORKON_DESTDIR=(
	"${S}"
	"${S}/src/third_party/lss"
)

inherit cros-arm64 cros-i686 cros-workon cros-sanitizers flag-o-matic multiprocessing

DESCRIPTION="Google crash reporting"
HOMEPAGE="https://chromium.googlesource.com/breakpad/breakpad"
SRC_URI=""

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="-alltests cros_host rustc-demangle test"

COMMON_DEPEND="
	rustc-demangle? ( dev-rust/rustc-demangle-capi )
	net-misc/curl:=
"
RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}
	test? (
		dev-cpp/gtest:=
	)
"

src_prepare() {
	default
	find "${S}" -type f -exec touch -r "${S}"/configure {} +
}

src_configure() {
	sanitizers-setup-env

	# -fno-sanitize=alignment since this package interprets ELF binaries
	# directly, which often involves `reinterpret_cast`s on `ptr+offset`
	# pairs that make no attempt to guarantee alignment.
	append-flags -g -fno-sanitize=alignment

	# Disable flaky tests by default.  Do it here because the CPPFLAGS
	# are recorded at configure time and not read on the fly.
	# http://crbug.com/359999
	use alltests && append-cppflags -DENABLE_FLAKY_TESTS

	multijob_init

	mkdir build
	pushd build >/dev/null || die
	ECONF_SOURCE=${S} multijob_child_init econf --enable-system-test-libs \
		$(use_enable rustc-demangle system-rustc-demangle) \
		--bindir="$(usex cros_host /usr/bin /usr/local/bin)"
	popd >/dev/null || die

	if use cros_host || use_i686; then
		# The mindump code is still wordsize specific.  Needs to be redone
		# like https://chromium.googlesource.com/breakpad/breakpad/+/4116671cbff9e99fbd834a1b2cdd174226b78c7c
		einfo "Configuring 32-bit build"
		mkdir work32
		pushd work32 >/dev/null || die
		use cros_host && append-flags "-m32"
		use_i686 && push_i686_env
		ECONF_SOURCE=${S} multijob_child_init econf
		use_i686 && pop_i686_env
		use cros_host && filter-flags "-m32"
		popd >/dev/null || die
	fi

	if use_arm64; then
		# The mindump code is still wordsize specific.  Needs to be redone
		# like https://chromium.googlesource.com/breakpad/breakpad/+/4116671cbff9e99fbd834a1b2cdd174226b78c7c
		einfo "Configuring 64-bit build"
		mkdir work64
		pushd work64 >/dev/null || die
		use_arm64 && push_arm64_env
		ECONF_SOURCE=${S} multijob_child_init econf
		use_arm64 && pop_arm64_env
		popd >/dev/null || die
	fi

	multijob_finish
}

src_compile() {
	emake -C build

	if use cros_host; then
		einfo "Building 32-bit tools"
		emake -C work32 \
			src/tools/linux/md2core/minidump-2-core
	fi

	if use_i686; then
		einfo "Building 32-bit library"
		push_i686_env
		emake -C work32 src/client/linux/libbreakpad_client.a
		pop_i686_env
	fi

	if use_arm64; then
		einfo "Building 64-bit library"
		push_arm64_env
		emake -C work64 src/client/linux/libbreakpad_client.a
		pop_arm64_env
	fi
}

src_test() {
	if ! use x86 && ! use amd64 ; then
		einfo Skipping unit tests on non-x86 platform
		return
	fi
	# VERBOSE controls the test log output.
	emake -C build VERBOSE=1 check
}

src_install() {
	emake -C build DESTDIR="${D}" install

	# TODO(https://crbug.com/google-breakpad/890): Don't build dump_syms for
	# !cros_host rather than remove it after the fact. dump_syms depends on
	# rustc-demangle which triggers the LFS bad-API-use detector through a
	# libc::mmap call from Rust.
	if ! use cros_host; then
		rm "${D}/usr/local/bin/dump_syms" || die
	fi

	# Move core2md to the rootfs. It's not only for tests but also used on
	# shipped devices.
	dodir /usr/bin
	if ! use cros_host; then
		mv "${D}/usr/local/bin/core2md" "${D}/usr/bin/core2md" || die
	fi

	insinto /usr/include/google-breakpad/client/linux/handler
	doins src/client/linux/handler/*.h
	insinto /usr/include/google-breakpad/client/linux/crash_generation
	doins src/client/linux/crash_generation/*.h
	insinto /usr/include/google-breakpad/common/linux
	doins src/common/linux/*.h
	insinto /usr/include/google-breakpad/processor
	doins src/processor/*.h

	if use cros_host; then
		newbin work32/src/tools/linux/md2core/minidump-2-core \
		       minidump-2-core.32
	fi

	if use_i686; then
		push_i686_env
		dolib.a work32/src/client/linux/libbreakpad_client.a
		pop_i686_env
	fi

	if use_arm64; then
		push_arm64_env
		dolib.a work64/src/client/linux/libbreakpad_client.a
		pop_arm64_env
	fi

	# shellcheck disable=SC2016 # we don't want `${libdir}` to expand below.
	find "${ED}/usr" -name breakpad-client.pc \
		-exec sed -i '/^Libs:/s/-L${libdir} //g' {} + || die
}
