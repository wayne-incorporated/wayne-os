# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="TFLite models and supporting assets used for testing ML & NNAPI."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/refs/heads/main/ml_benchmark/model_zoo/"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

SRC_URI="gs://chromeos-localmirror/distfiles/ml-test-assets-${PV}.tar.xz"

S="${WORKDIR}"

src_install() {
	insinto "/usr/local/share/ml-test-assets"
	doins -r ./*
}
