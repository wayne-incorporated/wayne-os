# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"chromium.googlesource.com/infra/luci/luci-go:go.chromium.org/luci f21543fed307ddf4ed3c9ceb09afbfb52b680d54"
	"github.com/danjacques/gofslock 6e321f4509c8589652ac83307e867969aa1f6cde"
	"github.com/mitchellh/go-homedir af06845cf3004701891bf4fdb884bfe4920b3727"
)

CROS_GO_PACKAGES=(
	"github.com/danjacques/gofslock/fslock"
	"github.com/mitchellh/go-homedir"
	"go.chromium.org/luci/auth"
	"go.chromium.org/luci/server/auth/delegation/messages"
	"go.chromium.org/luci/auth/identity"
	"go.chromium.org/luci/auth/integration/localauth/rpcs"
	"go.chromium.org/luci/auth/internal"
	"go.chromium.org/luci/cipd/api/cipd/v1"
	"go.chromium.org/luci/cipd/client/cipd"
	"go.chromium.org/luci/cipd/client/cipd/configpb"
	"go.chromium.org/luci/cipd/client/cipd/deployer"
	"go.chromium.org/luci/cipd/client/cipd/digests"
	"go.chromium.org/luci/cipd/client/cipd/ensure"
	"go.chromium.org/luci/cipd/client/cipd/fs"
	"go.chromium.org/luci/cipd/client/cipd/internal"
	"go.chromium.org/luci/cipd/client/cipd/internal/messages"
	"go.chromium.org/luci/cipd/client/cipd/internal/retry"
	"go.chromium.org/luci/cipd/client/cipd/pkg"
	"go.chromium.org/luci/cipd/client/cipd/platform"
	"go.chromium.org/luci/cipd/client/cipd/plugin"
	"go.chromium.org/luci/cipd/client/cipd/plugin/host"
	"go.chromium.org/luci/cipd/client/cipd/plugin/plugins"
	"go.chromium.org/luci/cipd/client/cipd/plugin/plugins/admission"
	"go.chromium.org/luci/cipd/client/cipd/plugin/protocol"
	"go.chromium.org/luci/cipd/client/cipd/reader"
	"go.chromium.org/luci/cipd/client/cipd/template"
	"go.chromium.org/luci/cipd/client/cipd/ui"
	"go.chromium.org/luci/cipd/common"
	"go.chromium.org/luci/cipd/common/cipderr"
	"go.chromium.org/luci/cipd/version"
	"go.chromium.org/luci/hardcoded/chromeinfra"
	"go.chromium.org/luci/lucictx"
	"go.chromium.org/luci/tokenserver/api"
	"go.chromium.org/luci/tokenserver/api/minter/v1"
)

inherit cros-go

DESCRIPTION="Go CIPD client package."
HOMEPAGE="https://chromium.googlesource.com/infra/luci/luci-go/+/refs/heads/main/cipd"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="dev-go/luci-go-common"
RDEPEND="${DEPEND}"
