# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="553e6b821ca0556f985b7294822ad51bbd98202c"
CROS_WORKON_TREE="496671b0eebaba3a0acfaa1a277f49d49119fb8f"
CROS_WORKON_PROJECT="chromiumos/platform/graphics"
CROS_WORKON_LOCALNAME="platform/graphics"
CROS_WORKON_SUBTREE="src/fossilize"

inherit cros-constants cros-workon

DESCRIPTION="Fossilize in a hermetic environment."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/graphics/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
VIDEO_CARDS="
	intel radeon
"
# $VIDEO_CARDS might include multiple values here.
# shellcheck disable=SC2086
IUSE="$(printf 'video_cards_%s ' ${VIDEO_CARDS})"

DEPEND="
	dev-util/vulkan-tools
	media-libs/fossilize:=
"

src_unpack() {
	cros-workon_src_unpack
	S+="/${CROS_WORKON_SUBTREE}"
}

src_install() {
	# Copy the binaries and their dependencies.
	local tools=(
		"/usr/bin/vulkaninfo"
		"/usr/bin/fossilize-replay"
	)
	local wrapper_args=()
	if use video_cards_intel; then
		wrapper_args+=(
			"--wrapper-preload"
			"/lib/libintel_noop_drm_shim.so"
		)
	fi
	"${CHROMITE_BIN_DIR}"/lddtree --root="${SYSROOT}" --bindir=/bin \
		--libdir=/lib --generate-wrappers \
		--copy-non-elfs \
		"${wrapper_args[@]}" \
		--copy-to-tree="${WORKDIR}"/pkg/ \
		"${tools[@]}" || die

	# Copy the vulkan libraries that are dlopen()d and LD_PRELOADed.
	local dlopen_libs=(
		"/usr/$(get_libdir)/libvulkan.so"
	)
	local icd_base="share/vulkan/icd.d"
	local icd_files=()
	if use video_cards_intel; then
		dlopen_libs+=(
			"/usr/$(get_libdir)/libintel_noop_drm_shim.so"
			"/usr/$(get_libdir)/libvulkan_intel.so"
		)
		icd_files+=(
			"${icd_base}/intel_icd.x86_64.json"
		)
	fi
	if use video_cards_radeon; then
		dlopen_libs+=(
			"/usr/$(get_libdir)/libvulkan_radeon.so"
		)
		icd_files+=(
			"${icd_base}/radeon_icd.x86_64.json"
		)
	fi
	mapfile -t dlopen_libs \
		< <("${CHROMITE_BIN_DIR}"/lddtree --root="${SYSROOT}" --list \
		"${dlopen_libs[@]}") || die
	cp -aL "${dlopen_libs[@]}" "${WORKDIR}"/pkg/lib/ || die

	# Modify the icd paths to be relative.
	mkdir -p "${WORKDIR}/pkg/share/vulkan/icd.d" || die
	local icd
	for icd in "${icd_files[@]}"; do
		sed -e "s:/usr/$(get_libdir):../../../lib:" \
			"${SYSROOT}/usr/${icd}" > "${WORKDIR}/pkg/${icd}" || die
	done

	# Install everything.
	insinto /build/opt/google/fossilize
	insopts -m0755
	doins -r "${WORKDIR}"/pkg/*

	if use video_cards_intel; then
		doins intel*shim
	fi
	if use video_cards_radeon; then
		doins radeon*shim
	fi
}
