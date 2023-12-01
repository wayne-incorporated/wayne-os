# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_GO_SOURCE="github.com/pierrec/lz4 v${PV}"
CROS_GO_PACKAGES=(
	"github.com/pierrec/lz4"
	"github.com/pierrec/lz4/internal/lz4block"
	"github.com/pierrec/lz4/internal/lz4errors"
	"github.com/pierrec/lz4/internal/lz4stream"
	"github.com/pierrec/lz4/internal/xxh32"
)

inherit cros-go

DESCRIPTION="LZ4 compression and decompression in pure Go"
HOMEPAGE="https://github.com/pierrec/lz4"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
