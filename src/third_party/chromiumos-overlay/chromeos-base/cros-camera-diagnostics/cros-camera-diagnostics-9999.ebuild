# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_SUBTREE=".gn camera/build camera/common camera/include camera/mojo camera/diagnostics common-mk mojo_service_manager"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="camera/diagnostics"

inherit cros-camera cros-workon platform

DESCRIPTION="ChromeOS camera diagnostics service."

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

RDEPEND="
	chromeos-base/libbrillo:=
	chromeos-base/mojo_service_manager:="

DEPEND="${RDEPEND}"
