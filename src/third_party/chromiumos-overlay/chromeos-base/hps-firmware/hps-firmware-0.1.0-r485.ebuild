# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="33c57b0b565801a8c0d98f39b0b3e67f57956d24"
CROS_WORKON_TREE="13477ebcf3b7b02073d85be8e6f03fcff3df550c"
CROS_WORKON_PROJECT="chromiumos/platform/hps-firmware"
CROS_WORKON_LOCALNAME="platform/hps-firmware2"
CROS_WORKON_USE_VCSID=1
PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon cros-rust toolchain-funcs python-any-r1

DESCRIPTION="HPS firmware and tooling"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/hps-firmware"

LICENSE="BSD-Google"
KEYWORDS="*"

BDEPEND="
	chromeos-base/hps-sign-rom
	dev-embedded/hps-sdk
	dev-rust/svd2rust:=
	sci-electronics/amaranth
	>=sci-electronics/nextpnr-0.1_p20220210
	sci-electronics/prjoxide
	sci-electronics/yosys
	sci-electronics/yosys-f4pga-plugins
	$(python_gen_any_dep '
		sci-electronics/litespi[${PYTHON_USEDEP}]
		sci-electronics/litex[${PYTHON_USEDEP}]
		sci-electronics/pythondata-cpu-vexriscv[${PYTHON_USEDEP}]
	')
"

python_check_deps() {
	has_version -b "sci-electronics/litespi[${PYTHON_USEDEP}]" &&
		has_version -b "sci-electronics/litex[${PYTHON_USEDEP}]" &&
		has_version -b "sci-electronics/pythondata-cpu-vexriscv[${PYTHON_USEDEP}]"
}

DEPEND="
	dev-rust/third-party-crates-src:=
	dev-embedded/libftdi:=
	virtual/libusb:1
"

# /usr/lib/firmware/hps/fpga_bitstream.bin and
# /usr/lib/firmware/hps/fpga_application.bin
# moved from hps-firmware-images to here
RDEPEND="
	!<chromeos-base/hps-firmware-images-0.0.1-r17
"

src_unpack() {
	cros-workon_src_unpack
	cros-rust_src_unpack
}

src_prepare() {
	# Not using cros-rust_src_prepare because it wrongly assumes Cargo.toml is
	# in the root of ${S} and we don't need its manipulations anyway.

	# config.toml is intended for use when running `cargo` directly but would
	# mess with the ebuild if we didn't delete it.
	rm -f rust/.cargo/config.toml

	default
}

src_configure() {
	# Use Python helper modules from CFU-Playground. These are developed
	# upstream but are intimately tied to the HPS accelerator code.
	export PYTHONPATH="${S}/third_party/python/CFU-Playground"

	# Use Rust and GCC from hps-sdk, since the main Chrome OS compilers
	# do not yet support RISC-V.
	export PATH="/opt/hps-sdk/bin:${PATH}"

	# CROS_BASE_RUSTFLAGS are for the AP, they are not applicable to
	# HPS firmware, which is cross-compiled for STM32
	unset CROS_BASE_RUSTFLAGS
	cros-rust_configure_cargo

	# Override some unwanted rustflags configured by cros-rust_configure_cargo.
	# For our Cortex-M0 target, we need "fat" LTO and opt-level=z (smallest) to
	# make everything small enough to fit. Debug assertions and
	# integer overflow checks introduce panicking paths into the firmware,
	# which bloats the size of the images with extra strings in .rodata.
	# TODO(dcallagh): tidy this up properly in cros-rust.eclass.
	# CROS_BASE_RUSTFLAGS are the same problem.
	# asan and ubsan are also the same problem.
	# shellcheck disable=SC2154 # ECARGO_HOME is defined in cros-rust.eclass
	cat <<- EOF >> "${ECARGO_HOME}/config"
	[target.'cfg(all(target_arch = "arm", target_os = "none"))']
	rustflags = [
		"-Clto=yes",
		"-Copt-level=z",
		"-Coverflow-checks=off",
		"-Cdebug-assertions=off",
		"-Ccodegen-units=1",
	]
	EOF

	# cros-rust_update_cargo_lock tries to handle Cargo.lock but it assumes
	# there is only one Cargo.lock in the root of the source tree, which is not
	# true for hps-firmware. For now just delete the ones we have.
	rm rust/Cargo.lock rust/mcu/Cargo.lock rust/riscv/Cargo.lock
}

src_compile() {
	# Build FPGA bitstream
	einfo "Building FPGA bitstream"
	python -m soc.hps_soc --no-compile-software || die

	# Build FPGA application
	einfo "Building FPGA application"
	(
		cd rust/riscv/fpga_rom || die
		ecargo build --release
	)
	# shellcheck disable=SC2154 # CARGO_TARGET_DIR is defined in cros-rust.eclass
	llvm-objcopy -O binary \
		"${CARGO_TARGET_DIR}/riscv32i-unknown-none-elf/release/fpga_rom" \
		"${S}/build/hps_platform/fpga_rom.bin" || die

	# Build MCU firmware
	for crate in stage0 stage1_app ; do (
		einfo "Building MCU firmware ${crate}"
		cd rust/mcu/${crate} || die
		HPS_SPI_BIT="${S}/build/hps_platform/gateware/hps_platform.bit" \
			HPS_SPI_BIN="${S}/build/hps_platform/fpga_rom.bin" \
			ecargo build \
			--target="thumbv6m-none-eabi" \
			--release
		einfo "Flattening MCU firmware image ${crate}"
		# shellcheck disable=SC2154 # CARGO_TARGET_DIR is defined in cros-rust.eclass
		llvm-objcopy -O binary \
			"${CARGO_TARGET_DIR}/thumbv6m-none-eabi/release/${crate}" \
			"${CARGO_TARGET_DIR}/thumbv6m-none-eabi/release/${crate}.bin" || die
	) done

	# Sign MCU stage1 firmware with dev key
	# shellcheck disable=SC2154 # CARGO_TARGET_DIR is defined in cros-rust.eclass
	hps-sign-rom \
		--input "${CARGO_TARGET_DIR}/thumbv6m-none-eabi/release/stage1_app.bin" \
		--output "${CARGO_TARGET_DIR}/thumbv6m-none-eabi/release/stage1_app.bin.signed" \
		--use-insecure-dev-key \
		|| die
}

src_test() {
	einfo "Running gateware unit tests"
	python -m unittest discover -v || die

	einfo "Running Rust tests"
	cd rust || die
	RUST_BACKTRACE=1 ecargo_test
}

src_install() {
	# Extract stage1 version (currently this is just the first 4 bytes of the
	# stage1 signature).
	# shellcheck disable=SC2154 # CARGO_TARGET_DIR is defined in cros-rust.eclass
	python3 -c "with open('${CARGO_TARGET_DIR}/thumbv6m-none-eabi/release/stage1_app.bin.signed', 'rb') as f:
		f.seek(20);
		print(int.from_bytes(f.read(4), 'big'))" \
		>mcu_stage1.version.txt || die

	# install build metadata for use by:
	# https://source.corp.google.com/chromeos_internal/src/platform/tast-tests-private/src/chromiumos/tast/local/bundles/crosint/hps/fpga_gateware_stats.go
	insinto "/usr/lib/firmware/hps"
	doins build/hps_platform/gateware/hps_platform_build.metadata

	# Generate and install the build manifest.
	# shellcheck disable=SC2154 # VCSID is supplied by cros-workon.eclass
	echo "${VCSID}" > manifest.txt
	cat models/manifest.txt >> manifest.txt

	# install into /firmware as part of signing process
	# signed release firmware is installed by hps-firmware-images ebuild
	insinto "/firmware/hps"
	# shellcheck disable=SC2154 # CARGO_TARGET_DIR is defined in cros-rust.eclass
	newins "${CARGO_TARGET_DIR}/thumbv6m-none-eabi/release/stage0.bin" "mcu_stage0.bin"
	newins "${CARGO_TARGET_DIR}/thumbv6m-none-eabi/release/stage1_app.bin.signed" "mcu_stage1.bin"
	doins mcu_stage1.version.txt
	doins manifest.txt
	newins build/hps_platform/gateware/hps_platform.bit fpga_bitstream.bin
	newins build/hps_platform/fpga_rom.bin fpga_application.bin
}
