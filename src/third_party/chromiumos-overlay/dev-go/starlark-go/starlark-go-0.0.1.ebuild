# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/google/starlark-go:go.starlark.net 87f333178d5942de51b193111d6f636c79833ea5"
)

CROS_GO_BINARIES=(
	"go.starlark.net/cmd/starlark/starlark.go"
)

CROS_GO_PACKAGES=(
	"go.starlark.net/lib/proto"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/internal/compile"
	"go.starlark.net/internal/spell"
	"go.starlark.net/resolve"
	"go.starlark.net/syntax"
)

inherit cros-go

DESCRIPTION="Go impl of the starlark config language"
HOMEPAGE="https://github.com/google/starlark-go"
SRC_URI="$(cros-go_src_uri)"
RESTRICT="binchecks strip"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND="
	dev-go/cmp
	dev-go/go-sys
	dev-go/logex
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	dev-go/readline
	dev-go/test
	dev-go/xerrors
"

RDEPEND=""
