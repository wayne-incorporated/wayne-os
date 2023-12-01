# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# The tarball contains the static linked dex2oat binary executable. It is
# produced by Android build server and copied from the url below.
# gs://android-build-chromeos/builds/git_nyc-mr1-arc-linux-static_build_tools/4254306/9522bf7036721fd1cb8074f1a457e860a111924dc320d19975d81e6163fcd7f6/dex2oatds
#
# A functionally similar binary can be created from AOSP source tree with
# command below:
#     ART_BUILD_HOST_STATIC=true ART_BUILD_HOST_NDEBUG=true mmma art/dex2oat
# We do not build it from source because of size and complexity of pulling
# down a big portion of AOSP source tree.
#
# For P, the binary was copied from:
# https://android-build.googleplex.com/builds/submitted/9067970/sdk_cheets_x86_64-userdebug/latest
# For RVC, the binary is build from rvc-arc-dev art commit
# 337cf0aa8a455479ca0bcb53a484fd9046c06a91 mmma art/
#
# CAUTION: DO NOT attempt to update/replace existing tarballs under
# gs://chromeos-localmirror/distfiles/. Always follow the following instructions
# if a new tarball is required:
#
# 1. Download the existing tarball from SRC_URI and extract contents
#    (${P} is package name + version e.g. dex2oatds-0.0.2)
# 2. Add/replace binaries that requires an update
# 3. Bump the ebuild version number (e.g. 0.0.2 -> 0.0.3) by renaming the file,
#    also update symlinks
# 4. Repack binaries: `tar jcvf ${P}.tbz2 <files>`, where ${P} contains the
#    **NEW** version number (all ${P} below refers to the new version)
# 5. Copy the new tarball to gs://chromeos-localmirror/distfiles/${P}.tbz2
#    **MAKE SURE NOT TO OVERWRITE ANY EXISTING FILES**
# 6. Set public permissions: `gsutil acl ch -g allUsers:READER
#    gs://chromeos-localmirror/distfiles/${P}.tbz2`
# 7. Under chroot, run `ebuild ${P}-r1.ebuild manifest` to update Manifest
# 8. Run `sudo emerge sys-devel/dex2oatds` to make sure the new version installs
# 9. Commit all changes and send CL for review.

EAPI="7"

DESCRIPTION="Ebuild which pulls in binaries of dex2oatds"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

src_install() {
	dobin dex2oatds
	dobin dex2oatds-pi
	dobin dex2oats-rvc
}
