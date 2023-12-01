# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# The tarball contains the aapt binary executable. It is taken from the Android
# build server for ARC NYC branch and for 4551453 build.
# gs://chromeos-arc-images/builds/git_nyc-mr1-arc-linux-static_sdk_tools/4551453/aapt
# This tool does not change frequently. If you need update it then download the
# binaries for the latest build, upload the new version to chromeos-localmirror
# https://pantheon.corp.google.com/storage/browser/chromeos-localmirror/distfiles
# and update the current version and manifest.

EAPI="5"

DESCRIPTION="Ebuild which pulls in binaries of aapt"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

src_install() {
	dobin aapt
}
