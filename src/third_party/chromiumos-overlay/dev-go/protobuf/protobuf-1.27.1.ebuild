# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/protocolbuffers/protobuf-go:google.golang.org/protobuf v${PV}"
)

CROS_GO_PACKAGES=(
	"google.golang.org/protobuf/cmd/protoc-gen-go/internal_gengo"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/encoding/..."
	"google.golang.org/protobuf/internal/descfmt"
	"google.golang.org/protobuf/internal/descopts"
	"google.golang.org/protobuf/internal/detrand"
	"google.golang.org/protobuf/internal/encoding/..."
	"google.golang.org/protobuf/internal/errors"
	"google.golang.org/protobuf/internal/filedesc"
	"google.golang.org/protobuf/internal/filetype"
	"google.golang.org/protobuf/internal/flags"
	"google.golang.org/protobuf/internal/genid"
	"google.golang.org/protobuf/internal/impl"
	"google.golang.org/protobuf/internal/msgfmt"
	"google.golang.org/protobuf/internal/order"
	"google.golang.org/protobuf/internal/pragma"
	"google.golang.org/protobuf/internal/protobuild"
	"google.golang.org/protobuf/internal/protolegacy"
	"google.golang.org/protobuf/internal/set"
	"google.golang.org/protobuf/internal/strs"
	"google.golang.org/protobuf/internal/testprotos/..."
	"google.golang.org/protobuf/internal/version"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/..."
	"google.golang.org/protobuf/runtime/..."
	"google.golang.org/protobuf/testing/..."
	"google.golang.org/protobuf/types/..."
)

inherit cros-go

DESCRIPTION="Go support for Google's protocol buffers"
HOMEPAGE="https://github.com/protocolbuffers/protobuf-go"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="dev-go/cmp
	test? ( dev-go/sync )"
RDEPEND=""
