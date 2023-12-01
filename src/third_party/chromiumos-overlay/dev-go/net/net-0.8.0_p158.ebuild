# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/net:golang.org/x/net 4f30a5c0130f199e0dfd54e9de49f9367cabf1ad"

CROS_GO_PACKAGES=(
	"golang.org/x/net/bpf"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/icmp"
	"golang.org/x/net/idna"
	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"
	"golang.org/x/net/internal/socks"
	"golang.org/x/net/internal/timeseries"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/net/netutil"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/net/trace"
	"golang.org/x/net/websocket"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Go supplementary network libraries"
HOMEPAGE="https://golang.org/x/net"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/term
	dev-go/text
	dev-go/go-sys
"
RDEPEND="dev-go/text"
