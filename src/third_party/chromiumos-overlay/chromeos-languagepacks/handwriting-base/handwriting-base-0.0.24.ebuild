# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit dlc

# This ebuild is referring to the same resource as package:
# src/third_party/chromiumos-overlay/dev-libs/libhandwriting/
# We keep two ebuilds while we migrate from nacl to Language Packs.

DESCRIPTION="Handwriting Library used by Language Pack for ChromiumOS"

SRC_URI="
	amd64? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_amd64-${PV}.tar.gz )
	march_alderlake? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_silvermont-${PV}.tar.gz )
	march_goldmont? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_goldmont-${PV}.tar.gz )
	march_silvermont? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_silvermont-${PV}.tar.gz )
	march_skylake? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_silvermont-${PV}.tar.gz )
	march_tremont? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_silvermont-${PV}.tar.gz )
	arm? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_arm32-${PV}.tar.gz )
	arm64? ( gs://chromeos-localmirror/distfiles/libhandwriting_chromeos_arm64-${PV}.tar.gz )
"

RESTRICT="mirror"

LICENSE="BSD-Google Apache-2.0 MPL-2.0 icu-58"
SLOT="0"
KEYWORDS="*"

IUSE="
	ondevice_handwriting
	ondevice_handwriting_dlc
	amd64
	arm
	arm64
	dlc
	march_alderlake
	march_goldmont
	march_silvermont
	march_skylake
	march_tremont
"

# At most one march flag is required. Exactly one of the archs is required.
REQUIRED_USE="
	?? ( march_alderlake march_goldmont march_silvermont march_skylake march_tremont )
	^^ ( amd64 arm arm64 )
	ondevice_handwriting
"

S="${WORKDIR}"

# Allocate DLC_PREALLOC_BLOCKS * 4KiB = 30MB.
DLC_PREALLOC_BLOCKS="7500"
# Preload DLC data on test images.
DLC_PRELOAD=true

# Enable scaled design.
DLC_SCALED=true

src_unpack() {
	# Unpack the arch/microarch-relevant package.
	local suffix=""
	if use march_goldmont; then
		suffix="goldmont"
	elif use march_alderlake \
		|| use march_silvermont \
		|| use march_skylake \
		|| use march_tremont; then
		suffix="silvermont"
	elif use amd64; then
		suffix="amd64"
	elif use arm; then
		suffix="arm32"
	elif use arm64; then
		suffix="arm64"
	else
		die "Unsupported architecture ${ARCH}"
	fi

	unpack "libhandwriting_chromeos_${suffix}-${PV}.tar.gz"
}

src_install() {
	# Setup DLC paths. We don't need any subdirectory inside the DLC path.
	insinto "$(dlc_add_path /)"

	# Install the shared library.
	insopts -m0755
	newins "libhandwriting.so" "libhandwriting.so"
	insopts -m0644

	# This command packages the files into a DLC.
	dlc_src_install
}
