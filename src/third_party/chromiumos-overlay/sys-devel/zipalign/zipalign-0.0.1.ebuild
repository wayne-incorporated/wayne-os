# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# The tarball contains the zipalign binary executable
# (https://developer.android.com/studio/command-line/zipalign). It does not
# change frequently, but if it needs updating, copy the `zipalign` file from
# gs://chromeos-arc-images/builds/git_nyc-mr1-arc-linux-static_sdk_tools/{r},
# where {r} is the latest revision number. Upload this to chromeos-localmirror
# https://pantheon.corp.google.com/storage/browser/chromeos-localmirror/distfiles
# and update the current version and manifest. Further updates should update
# ${PV} to match {r}.

EAPI="7"

DESCRIPTION="An optimisation tool for Android APK files. It aligns uncompressed
data on 4-byte boundaries. This results in a reduction of RAM consumed when the
APK is running."
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="-* amd64"
IUSE=""

S="${WORKDIR}"

src_install() {
	dobin zipalign
}
