# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="Common factory resoureces shared between some projects. For
example, projects based on same chipset, projects with similar features
(jetstream, CfM)."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

#
# WARNING: Nothing should be added to this ebuild.  This ebuild is overriden
# in most of the board specific overlays, or will be.
#
