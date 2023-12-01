# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Install media profiles on ARC++"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
DEPEND="!chromeos-base/arc-media-profiles-default"
S="${WORKDIR}"

src_install() {
	insinto /etc/camera/
	doins "${FILESDIR}/media_profiles.xml"

	dobin "${FILESDIR}/generate_camera_profile"

	# /etc/media_profiles.xml in container is a symbolic link to vendor image.
	# In order to change profile at runtime, we have to install the file
	# into /oem partition. Create a symbolic link in vendor image to redirect
	# profiles correctly.
	dosym /oem/etc/media_profiles.xml \
		/opt/google/containers/android/vendor/etc/media_profiles.xml
}
