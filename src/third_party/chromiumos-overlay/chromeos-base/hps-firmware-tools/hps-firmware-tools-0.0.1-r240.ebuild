# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="33c57b0b565801a8c0d98f39b0b3e67f57956d24"
CROS_WORKON_TREE="13477ebcf3b7b02073d85be8e6f03fcff3df550c"
CROS_WORKON_PROJECT="chromiumos/platform/hps-firmware"
CROS_WORKON_LOCALNAME="platform/hps-firmware2"
PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon cros-rust python-any-r1

DESCRIPTION="HPS firmware tools for development and testing"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/hps-firmware"

LICENSE="BSD-Google"
KEYWORDS="*"

BDEPEND="
	dev-embedded/hps-sdk
	dev-rust/svd2rust:=
	>=sci-electronics/nextpnr-0.1_p20220210
	sci-electronics/nmigen
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

# host tools used to live in hps-firmware
# hps-factory used to live in hps-firmware-images
RDEPEND="
	!<chromeos-base/hps-firmware-0.1.0-r244
	!<chromeos-base/hps-firmware-images-0.0.1-r28
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

	# Use Rust from hps-sdk, since the main Chrome OS Rust compiler
	# does not yet support RISC-V.
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
	# hps-factory needs an FPGA bitstream.
	einfo "Building FPGA bitstream"
	python -m soc.hps_soc || die

	for tool in hps-factory hps-mon hps-util ; do (
		cd rust/${tool} || die
		einfo "Building ${tool}"
		ecargo_build
	) done
}

src_test() {
	# The hps-firmware ebuild runs all unit tests (including for host tools),
	# nothing more to do here.
	:
}

src_install() {
	dobin "$(cros-rust_get_build_dir)/hps-factory"
	dobin "$(cros-rust_get_build_dir)/hps-mon"
	dobin "$(cros-rust_get_build_dir)/hps-util"
}
