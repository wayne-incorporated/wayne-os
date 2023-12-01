# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="8fe1e61da2c337014406dbdae855347609dbc94c"
CROS_WORKON_TREE="8f3d94a1d989307b9bf37aa247d122f9a58a5f94"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_LOCALNAME="platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1

# Run tests in multiple processes to speed up execution.
# shellcheck disable=SC2034
CROS_RUST_TEST_MULTIPROCESS=yes

# We don't use CROS_WORKON_OUTOFTREE_BUILD here since crosvm/Cargo.toml is
# using "# ignored by ebuild" macro which supported by cros-rust.

inherit cros-rust cros-sanitizers cros-workon user

DESCRIPTION="Utility for running VMs on Chrome OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/"

# 'Apache-2.0' and 'BSD-vmm_vhost' are for third_party/vmm_vhost.
LICENSE="BSD-Google Apache-2.0 BSD-vmm_vhost"
KEYWORDS="*"
IUSE="test cros-debug crosvm-gpu crosvm-swap -crosvm-trace-marker -crosvm-plugin +crosvm-power-monitor-powerd +crosvm-video-decoder +crosvm-video-encoder -crosvm-video-ffmpeg +crosvm-video-libvda -crosvm-video-vaapi +crosvm-wl-dmabuf tpm2 android-vm-master android-vm-tm arcvm_gce_l1"

BDEPEND="dev-libs/protobuf"
COMMON_DEPEND="
	sys-apps/dtc:=
	sys-libs/libcap:=
	crosvm-video-ffmpeg? ( media-video/ffmpeg )
	crosvm-video-libvda? ( chromeos-base/libvda )
	crosvm-video-vaapi? ( x11-libs/libva )
	chromeos-base/minijail:=
	dev-libs/wayland:=
	crosvm-gpu? (
		media-libs/virglrenderer:=
	)
	crosvm-wl-dmabuf? ( media-libs/minigbm:= )
	dev-rust/libchromeos:=
"

RDEPEND="${COMMON_DEPEND}
	!chromeos-base/crosvm-bin
	crosvm-power-monitor-powerd? ( sys-apps/dbus )
	tpm2? ( sys-apps/dbus )
"

DEPEND="${COMMON_DEPEND}
	cros_host? ( dev-libs/protobuf:= )
	dev-rust/third-party-crates-src:=
	dev-libs/wayland-protocols:=
	dev-rust/minijail:=
	dev-rust/p9:=
	dev-rust/system_api:=
	media-sound/cras-client:=
	sys-apps/dbus:=
	tpm2? (
		chromeos-base/tpm2:=
		chromeos-base/trunks:=
	)
	crosvm-power-monitor-powerd? (
		chromeos-base/system_api
	)
"

pkg_setup() {
	cros-rust_pkg_setup
}

src_unpack() {
	# Unpack both the project and dependency source code
	cros-workon_src_unpack
	cros-rust_src_unpack
}

src_prepare() {
	cros_optimize_package_for_speed
	cros-rust_src_prepare

	if use arcvm_gce_l1; then
		eapply "${FILESDIR}"/0001-betty-arcvm-Loose-mprotect-mmap-for-software-renderi.patch
	fi

	default
}

src_configure() {
	cros-rust_src_configure

	# Change the path used for the minijail pivot root from /var/empty.
	# See: https://crbug.com/934513
	export DEFAULT_PIVOT_ROOT="/mnt/empty"
}

src_compile() {
	export CROSVM_BUILD_VARIANT="chromeos"

	local features=(
		"audio"
		"balloon"
		"config-file"
		"qcow"
		"registered_events"
		"usb"
		$(usex crosvm-gpu gpu "")
		$(usex crosvm-gpu virgl_renderer "")
		$(usex crosvm-gpu virgl_renderer_next "")
		$(usex crosvm-plugin plugin "")
		$(usex crosvm-power-monitor-powerd power-monitor-powerd "")
		$(usex crosvm-swap swap "")
		$(usex crosvm-trace-marker trace_marker "")
		$(usex crosvm-video-decoder video-decoder "")
		$(usex crosvm-video-encoder video-encoder "")
		$(usex crosvm-video-libvda libvda "")
		$(usex crosvm-video-ffmpeg ffmpeg "")
		$(usex crosvm-video-vaapi vaapi "")
		$(usex crosvm-wl-dmabuf wl-dmabuf "")
		$(usex tpm2 tpm "")
		$(usex cros-debug gdb "")
		chromeos
		$(usex android-vm-master composite-disk "")
		$(usex android-vm-tm composite-disk "")
	)

	local crosvm_control_features=(
		"registered_events"
	)

	# Remove other versions of crosvm_control so the header installation
	# only picks up the most recently built version.
	# TODO(b/188858559) Remove this once the header is installed directly by cargo
	rm -rf "$(cros-rust_get_build_dir)/build/crosvm_control-*" || die "failed to remove old crosvm_control packages"

	# Build crosvm binary
	ecargo_build -v --no-default-features --features="${features[*]}" || die "crosvm cargo build failed"

	# Build additional crates
	ecargo_build -v -p qcow_utils || die "qcow_utils cargo build failed"
	ecargo_build -v --features="${crosvm_control_features[*]}" -p crosvm_control || die "crosvm_control cargo build failed"
}

src_test() {
	export CROSVM_BUILD_VARIANT="chromeos"

	local test_opts=(
		--verbose
		--workspace
		--features chromeos

		# Run only unit tests (tests in --lib and --bins). These are safe to run in any environment,
		# including the portage sandbox. Integration and e2e tests of crosvm are run upstream.
		--lib --bins

		# The swap crate requires userfaultfd, which does not compile on ChromeOS.
		--exclude swap
		# Disable VAAPI testing as it would require us to depend on libva.
		--exclude libva
	)
	use tpm2 || test_opts+=(--exclude tpm2 --exclude tpm2-sys)
	use crosvm-video-ffmpeg || test_opts+=(--exclude ffmpeg)
	use crosvm-video-libvda || test_opts+=(--exclude libvda)

	local skip_tests=(
		# To skip a test, add its name as it shows up in the test results. Example:
		# --skip "test_integration::simple_kvm"
	)

	ecargo_test "${test_opts[@]}" -- "${skip_tests[@]}" || die "cargo test failed"
}

src_install() {
	# cargo doesn't know how to install cross-compiled binaries.  It will
	# always install native binaries for the host system.  Manually install
	# crosvm instead.
	local build_dir="$(cros-rust_get_build_dir)"
	dobin "${build_dir}/crosvm"

	# Install qcow utils library, header, and pkgconfig files.
	dolib.so "${build_dir}/deps/libqcow_utils.so"

	local include_dir="/usr/include/crosvm"

	"${S}"/qcow_utils/platform2_preinstall.sh "${PV}" "${include_dir}" \
		"${WORKDIR}"
	insinto "/usr/$(get_libdir)/pkgconfig"
	doins "${WORKDIR}/libqcow_utils.pc"

	insinto "${include_dir}"
	doins "${S}"/qcow_utils/src/qcow_utils.h

	# Install crosvm_control header and library.
	# Note: Old versions of the crosvm_control package are deleted at the
	# beginning of the compile step, so this doins will only pick up the
	# most recently built crosvm_control.h.
	# TODO(b/188858559) Install the header directly from cargo using --out-dir once the feature is stable
	doins "${build_dir}"/build/crosvm_control-*/out/crosvm_control.h
	dolib.so "${build_dir}/deps/libcrosvm_control.so"

	# Install plugin library, when requested.
	if use crosvm-plugin; then
		insinto "${include_dir}"
		doins "${S}/crosvm_plugin/crosvm.h"
		dolib.so "${build_dir}/deps/libcrosvm_plugin.so"
	fi
}

pkg_preinst() {
	enewuser "crosvm"
	enewgroup "crosvm"

	cros-rust_pkg_preinst
}
