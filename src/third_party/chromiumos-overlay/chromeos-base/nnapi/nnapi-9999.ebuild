# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-constants

CROS_WORKON_MANUAL_UPREV="1"

CROS_WORKON_PROJECT=(
	"chromiumos/platform2"
	"aosp/platform/frameworks/native"
	"aosp/platform/system/core/libcutils"
	"aosp/platform/system/core/libutils"
	"aosp/platform/system/libbase"
	"aosp/platform/system/libfmq"
	"aosp/platform/system/libhidl"
	"aosp/platform/system/logging"
)
CROS_WORKON_REPO=(
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_HOST_URL}"
)
CROS_WORKON_LOCALNAME=(
	"platform2"
	"aosp/frameworks/native"
	"aosp/system/core/libcutils"
	"aosp/system/core/libutils"
	"aosp/system/libbase"
	"aosp/system/libfmq"
	"aosp/system/libhidl"
	"aosp/system/logging"
)
CROS_WORKON_DESTDIR=(
	"${S}/platform2"
	"${S}/platform2/aosp/frameworks/native"
	"${S}/platform2/aosp/system/core/libcutils"
	"${S}/platform2/aosp/system/core/libutils"
	"${S}/platform2/aosp/system/libbase"
	"${S}/platform2/aosp/system/libfmq"
	"${S}/platform2/aosp/system/libhidl"
	"${S}/platform2/aosp/system/logging"
)
CROS_WORKON_SUBTREE=(
	"common-mk nnapi .gn"
	""
	""
	""
	""
	""
	""
	""
)
CROS_WORKON_EGIT_BRANCH=(
	"main"
	"master"
	"master"
	"master"
	"master"
	"master"
	"master"
	"master"
)

PLATFORM_SUBDIR="nnapi"

inherit cros-workon platform

DESCRIPTION="Chrome OS support utils for Android Neural Network API"
HOMEPAGE="https://developer.android.com/ndk/guides/neuralnetworks"

LICENSE="BSD-Google  Apache-2.0"
KEYWORDS="~*"
IUSE=""

RDEPEND="
"

DEPEND="
	${RDEPEND}
"

PATCHES=(
	"${FILESDIR}/00001-libbase-fix-stderr-logging.patch"
	"${FILESDIR}/00002-libhidl-callstack.patch"
	"${FILESDIR}/00003-libutils-callstack.patch"
	"${FILESDIR}/00004-libfmq-page-size.patch"
	"${FILESDIR}/00005-libcutils-ashmemtests.patch"
	"${FILESDIR}/00006-libhidl-cast-interface.patch"
	"${FILESDIR}/00007-libbase-get-property-from-envvar.patch"
	"${FILESDIR}/00008-libutils-memory-leak.patch"
	"${FILESDIR}/00009-libutils-timer-cast.patch"
	"${FILESDIR}/00010-libutils-clock-test.patch"
	"${FILESDIR}/00011-libutils-lightrefbase.patch"
)

src_prepare() {
	# The workdir is platform2/nnapi - we need to pop up one level in the stack
	# to apply our patches.
	pushd .. || exit
	eapply -p2 "${FILESDIR}/00001-libbase-fix-stderr-logging.patch"
	eapply -p2 "${FILESDIR}/00002-libhidl-callstack.patch"
	eapply -p2 "${FILESDIR}/00003-libutils-callstack.patch"
	eapply -p2 "${FILESDIR}/00004-libfmq-page-size.patch"
	eapply -p2 "${FILESDIR}/00005-libcutils-ashmemtests.patch"
	eapply -p2 "${FILESDIR}/00006-libhidl-cast-interface.patch"
	eapply -p2 "${FILESDIR}/00007-libbase-get-property-from-envvar.patch"
	eapply -p2 "${FILESDIR}/00008-libutils-memory-leak.patch"
	eapply -p2 "${FILESDIR}/00009-libutils-timer-cast.patch"
	eapply -p2 "${FILESDIR}/00010-libutils-clock-test.patch"
	eapply -p2 "${FILESDIR}/00011-libutils-lightrefbase.patch"
	popd || exit

	eapply_user
}

src_install() {
	platform_src_install

	einfo "Installing Android headers."
	insinto /usr/include/aosp
	doins -r includes/*
	doins -r ../aosp/frameworks/native/libs/arect/include/*
	doins -r ../aosp/frameworks/native/libs/nativewindow/include/*
	doins -r ../aosp/system/core/libcutils/include/*
	doins -r ../aosp/system/core/libutils/include/*
	doins -r ../aosp/system/libbase/include/*
	doins -r ../aosp/system/libfmq/include/*
	doins -r ../aosp/system/libfmq/base/*
	doins -r ../aosp/system/libhidl/base/include/*
	doins -r ../aosp/system/libhidl/libhidlmemory/include/*
	doins -r ../aosp/system/logging/liblog/include/*
	# Selectively install one off headers
	insinto /usr/include/aosp/android
	doins ../aosp/frameworks/native/include/android/sharedmem.h

	einfo "Installing the shared library."
	dolib.so "${OUT}/lib/libnnapi-support.so"

	insinto "/usr/$(get_libdir)/pkgconfig"
	doins "${OUT}/obj/nnapi/libnnapi-support.pc"
}

platform_pkg_test() {
	local tests=(
		base cutils fmq hidl hwbuf log utils native
	)

	# When running in qemu, these tests freeze the emulator when hitting
	# EventFlag::wake from libfmq. The error printed is:
	# Error in event flag wake attempt: Function not implemented
	# This is a known issue, see:
	# https://chromium.googlesource.com/chromiumos/docs/+/master/testing/running_unit_tests.md#caveats
	local qemu_gtest_excl_filter="-"
	qemu_gtest_excl_filter+="BlockingReadWrites.SmallInputTest1:"

	local gtest_excl_filter="-"
	if use asan; then
		# The sharedbuffer tests deliberately allocate too much memory:
		# AddressSanitizer: requested allocation size 0xfffffffffffffffe
		# We can't use allocator_may_return_null=1 as it prints a warning that the
		# toolchain considers an error.
		gtest_excl_filter+="SharedBufferTest.alloc_null:"
		gtest_excl_filter+="SharedBufferTest.alloc_big:"
		gtest_excl_filter+="SharedBufferTest.alloc_max:"
		gtest_excl_filter+="SharedBufferTest.editResize_null:"
		gtest_excl_filter+="SharedBufferTest.editResize_death:"

		# These tests expects an exit before the memory is cleaned up,
		# so asan picks this up as a leak, but it's intentional.
		gtest_excl_filter+="StrongPointer*.AssertStrongRefExists:"
		gtest_excl_filter+="RefBase.AssertWeakRefExistsDeath:"

		# ForkSafe leaves some threads running which results in warning printed:
		# ==26==Running thread 23 was not suspended. False leaks are possible.
		# Toolchain considers anything in the asan output as an error.
		gtest_excl_filter+="logging.ForkSafe:"

		# The queue created in this test cannot be deleted without crashing in
		# the hidl library. lsan_suppressions doesn't work due to the lack of
		# /usr/bin/llvm-symbolizer, so just exclude the test.
		gtest_excl_filter+="BadQueueConfig.QueueSizeTooLarge:"
	fi

	local test_target
	for test_target in "${tests[@]}"; do
		platform_test "run" "${OUT}/lib${test_target}_testrunner" "0" "${gtest_excl_filter}" "${qemu_gtest_excl_filter}"
	done
}
