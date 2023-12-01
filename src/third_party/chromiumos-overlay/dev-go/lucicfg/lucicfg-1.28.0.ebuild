# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# To determine the latest version, run the following for each architecture:
# $ cipd resolve infra/tools/luci/lucicfg/linux-${ARCH} -version latest

DESCRIPTION="Dialect of the starlark-go CLI for compiling starlark configs"
HOMEPAGE="https://chromium.googlesource.com/infra/luci/luci-go/+/main/lucicfg/"
SRC_URI="
	amd64? ( cipd://infra/tools/luci/lucicfg/linux-amd64:nbdhAt7xHlGWTn7NyfAyWtiSxEMMrCnc7sOYYRDQovwC -> ${P}-amd64.zip )
	x86?   ( cipd://infra/tools/luci/lucicfg/linux-386:Eov5Nt9D63ImjwNzuvPNoUNmgYC3ClsAZC7yw-gXQy8C -> ${P}-x86.zip )
	arm64? ( cipd://infra/tools/luci/lucicfg/linux-arm64:5g-Q10_7W8V73fPnEi3JRry2Ntnz14w9x__4SnDUZaAC -> ${P}-arm64.zip )
	arm?   ( cipd://infra/tools/luci/lucicfg/linux-armv6l:UAPY457UUGKjqe5OPjTtGbzxUGbc_4TXojhsHFnYTsUC -> ${P}-arm.zip )
"
RESTRICT="mirror"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="amd64 x86 arm arm64"
IUSE=""

S="${WORKDIR}"

src_install() {
	dobin lucicfg
}
