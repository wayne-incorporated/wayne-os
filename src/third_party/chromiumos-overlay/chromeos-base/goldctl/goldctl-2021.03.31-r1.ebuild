# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# When the time comes to roll to a new version, run the following for each architecture:
# $ cipd resolve skia/tools/goldctl/linux-${ARCH} -version latest
# Latest as of 2021-03-31
SRC_URI="
	amd64? ( cipd://skia/tools/goldctl/linux-amd64:0ov3TUTdHjrpXdmomZUYhtozjUPAOWj5pFnLb_wSN3cC  -> ${P}-amd64.zip )
	x86?   ( cipd://skia/tools/goldctl/linux-386:lSVGG0WGcohimf9T2UCs35aMvQ4T8-cfZ84hZEZfrLsC    -> ${P}-x86.zip )
	arm64? ( cipd://skia/tools/goldctl/linux-arm64:NphODeY7HYsq6sZxzXGhwKkVtuoXWQkJT0rsVuzuwsIC  -> ${P}-arm64.zip )
	arm?   ( cipd://skia/tools/goldctl/linux-armv6l:R5kIju7TxEtjEaSnw9Q0coLcVVcCeIm0p5VQM2ka00oC -> ${P}-arm.zip )
"

DESCRIPTION="This command-line tool lets clients upload images to gold"
HOMEPAGE="https://skia.googlesource.com/buildbot/+/HEAD/gold-client/"
RESTRICT="mirror"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

src_install() {
	if [[ ! -e "goldctl" ]]; then
		cat > "goldctl" <<EOF
#!/bin/sh

echo "Goldctl binary is not supported on the architecture ${ARCH}." >&2
exit 1

EOF
	fi
	dobin goldctl
}
