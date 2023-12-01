# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/golang/protobuf v1.5.2"
)

CROS_GO_PACKAGES=(
	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/internal/gengogrpc"
	"github.com/golang/protobuf/internal/testprotos/proto2_proto"
	"github.com/golang/protobuf/internal/testprotos/proto3_proto"
	"github.com/golang/protobuf/internal/testprotos/jsonpb_proto"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/ptypes/..."
)

CROS_GO_BINARIES=(
	"github.com/golang/protobuf/protoc-gen-go"
)

inherit cros-go

DESCRIPTION="Legacy Go API support for Google's protocol buffers"
HOMEPAGE="https://github.com/golang/protobuf"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/protobuf
	test? ( dev-go/sync )
"
RDEPEND="
	dev-go/protobuf
"
