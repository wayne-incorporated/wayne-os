# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="Virtual for editor"

SLOT="0"
KEYWORDS="*"
LICENSE="metapackage"

# The editors we offer in our overlays.
RDEPEND="|| (
	app-editors/nano
	app-editors/neatvi
	app-editors/qemacs
	app-editors/vim
)"
