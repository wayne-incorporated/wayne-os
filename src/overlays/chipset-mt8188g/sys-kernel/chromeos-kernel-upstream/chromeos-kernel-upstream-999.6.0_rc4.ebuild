# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="7325af371b816783aa51a1a243fa0295d0592775"
CROS_WORKON_TREE="f9c8c14783afe4b4bef958ee74c39a623e272f03"
CROS_WORKON_PROJECT="chromiumos/third_party/kernel"
# TODO: Fix it when the official CrOS kernel branch is created.
CROS_WORKON_LOCALNAME="kernel/upstream"
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon cros-kernel2

HOMEPAGE="https://www.chromium.org/chromium-os/chromiumos-design-docs/chromium-os-kernel"
# TODO: Fix it when the official CrOS kernel branch is created.
DESCRIPTION="Chrome OS Linux Kernel experimental 6.0-rc4 with Geralt private patches."
KEYWORDS="*"
