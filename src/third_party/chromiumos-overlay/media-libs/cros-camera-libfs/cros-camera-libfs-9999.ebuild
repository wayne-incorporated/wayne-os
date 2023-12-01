# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_SUBTREE=".gn camera/build camera/libfs common-mk"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="camera/libfs"

inherit cros-camera cros-workon platform unpacker

DESCRIPTION="Camera Libraries File System which installs the prebuilt libraries."

IUSE="
	camera_feature_auto_framing
	camera_feature_face_detection
	camera_feature_hdrnet
	camera_feature_portrait_mode
	ondevice_document_scanner
	ondevice_document_scanner_dlc
"

REQUIRED_USE="
	?? ( ondevice_document_scanner ondevice_document_scanner_dlc )
"

PACKAGE_AUTO_FRAMING_PV="2022.09.06"
PACKAGE_DOCUMENT_SCANNING_PV="1.0.0"
PACKAGE_FACESSD_PV="2021.10.27"
PACKAGE_GCAM_PV="2023.01.11"
PACKAGE_PORTRAIT_MODE_PV="2023.03.14"

SRC_URI="
		camera_feature_auto_framing? (
				$(cros-camera_generate_auto_framing_package_SRC_URI ${PACKAGE_AUTO_FRAMING_PV})
		)
		$(cros-camera_generate_facessd_package_SRC_URI ${PACKAGE_FACESSD_PV})
		camera_feature_hdrnet? (
				$(cros-camera_generate_gcam_package_SRC_URI ${PACKAGE_GCAM_PV})
		)
		camera_feature_portrait_mode? (
				$(cros-camera_generate_portrait_mode_package_SRC_URI ${PACKAGE_PORTRAIT_MODE_PV})
		)
		$(cros-camera_generate_document_scanning_package_SRC_URI ${PACKAGE_DOCUMENT_SCANNING_PV})
"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"

RDEPEND="
	!media-libs/cros-camera-document-scanning
	!media-libs/cros-camera-effect-portrait-mode
	!media-libs/cros-camera-facessd
	!media-libs/cros-camera-libautoframing
	!media-libs/cros-camera-libgcam
"

src_unpack() {
	unpacker
	platform_src_unpack
	# Override unpacked data by files/* for local development.
	if [[ "${PV}" == "9999" ]]; then
		cp -fpr "${FILESDIR}"/* "${WORKDIR}" || die
	fi
}

install_lib() {
	local lib_src_path="$1"
	local so_files_path="$2"
	shift 2

	local lib_name=$(basename "${lib_src_path}")

	if [[ "${lib_name}" != *".so" ]]; then
		die "${lib_name} does not end with \".so\", which is required for a shared library."
	fi

	# For building binary, but won't be installed into the image.
	chmod 755 "${lib_src_path}"
	insinto /build/share/cros_camera
	doins "${lib_src_path}"

	# Put into the squashfs image without debug symbols.
	$(tc-getSTRIP) -s "${lib_src_path}" -o "${so_files_path}/${lib_name}" || die
}

src_install() {
	platform_src_install

	insinto /etc/init
	doins init/cros-camera-libfs.conf

	local so_files_path="${WORKDIR}/camera_libs"
	mkdir -p "${so_files_path}"

	local camera_g3_libs_path="${WORKDIR}/g3_libs.squash"

	# Move the required .so into the folder to prepare for compression.
	if use camera_feature_auto_framing; then
		install_lib "${WORKDIR}/libautoframing_cros.so" "${so_files_path}"
	fi
	if use ondevice_document_scanner; then
		install_lib "${WORKDIR}/libdocumentscanner.so" "${so_files_path}"
	fi
	install_lib "${WORKDIR}/libfacessd_cros.so" "${so_files_path}"
	if use camera_feature_hdrnet && (use march_skylake || use march_alderlake); then
		install_lib "${WORKDIR}/libgcam_cros.so" "${so_files_path}"
	fi
	if use camera_feature_portrait_mode; then
		install_lib "${WORKDIR}/libportrait_cros.so" "${so_files_path}"
	fi

	# Compress the .so files to a single .squash file and install it.
	mksquashfs "${so_files_path}" "${camera_g3_libs_path}" \
			-all-root -noappend -no-recovery -no-exports -exit-on-error \
			-no-progress -4k-align \
			-b 1M \
			-root-mode 0755
	insinto /usr/share/cros-camera
	doins "${camera_g3_libs_path}"
	keepdir /usr/share/cros-camera/libfs

	# For Document Scanning
	insinto /usr/include/chromeos/libdocumentscanner/
	doins "${WORKDIR}"/document_scanner.h

	insinto /usr/include/cros-camera
	doins "${WORKDIR}"/*.h

	# Install model file and anchor file
	insinto /usr/share/cros-camera/ml_models
	doins "${WORKDIR}"/*.pb "${WORKDIR}"/*.tflite
}
