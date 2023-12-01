# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/protocolbuffers/txtpbfmt 6b0cb7827ab2684011788e72d1d05226b8588f89"

CROS_GO_PACKAGES=(
	"github.com/protocolbuffers/txtpbfmt/ast"
	"github.com/protocolbuffers/txtpbfmt/parser"
	"github.com/protocolbuffers/txtpbfmt/unquote"
)

inherit cros-go

DESCRIPTION="Parses, edits and formats text proto files in a way that preserves comments."
HOMEPAGE="https://github.com/protocolbuffers/txtpbfmt"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	dev-go/glog
	dev-go/wordwrap
"
RDEPEND="${DEPEND}"
