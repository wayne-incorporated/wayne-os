# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="c0f640a6e09ef090019cdba154cd56eaa3fe7d22"
CROS_WORKON_TREE=("61fd92fe419f1ae1f1b06d0b1aea96666291c443" "329be361fe0ba49a07d8643ca4c5a68061624273" "12dab00deb75cafd6dc7e5c07ef89ec110cbab77" "60cd015ce801b2171ba7c7a0cf0f2abe87336862" "4cf2099d3a9c62b341396691239e55b9c4c4a928" "4a8a3d2135b93784093c7f4c5d2a54b921930145" "901c3cf860debda9a673974c9dc0263b1525a7e6")
CROS_WORKON_PROJECT="apps/libapps"
CROS_WORKON_LOCALNAME="third_party/libapps"
CROS_WORKON_SUBTREE="libdot hterm nassh ssh_client terminal wasi-js-bindings wassh"

inherit cros-workon

DESCRIPTION="The Chromium OS Shell extension (the HTML/JS rendering part)"
HOMEPAGE="https://chromium.googlesource.com/apps/libapps/+/master/nassh/doc/chromeos-crosh.md"
# These are kept in sync with libdot.py settings.
FONTS_HASHES=(
	# Current one.
	d6dc5eaf459abd058cd3aef1e25963fde893f9d87f5f55f340431697ce4b3506
	# Next one.
)
NODE_HASHES=(
	# Current one.
	14.15.4/b2e40ddbac04d05baafbb007f203c6663c9d4ca9
	# Next one.
	16.13.0/ab9544e24e752d3d17f335fb7b2055062e582d11
)
NPM_HASHES=(
	# Current one.
	a98c76bf5c11b1fa8caadcdda9c4945d5436b619e3b41868adf91f739b7ec06f
	# Next one.
	c6c3b74a64a72cc695c658527d2cb837199347897081b86e69c602870b3c77d5
)
PLUGIN_VERSIONS=(
	# Current one.
	0.50
	# Next one.
	0.52
)
SRC_URI="
	$(printf 'https://storage.googleapis.com/chromium-nodejs/%s ' "${NODE_HASHES[@]}")
	$(printf 'https://storage.googleapis.com/chromeos-localmirror/secureshell/distfiles/fonts-%s.tar.xz ' \
		"${FONTS_HASHES[@]}")
	$(printf 'https://storage.googleapis.com/chromeos-localmirror/secureshell/distfiles/node_modules-%s.tar.xz ' \
		"${NPM_HASHES[@]}")
	$(printf 'https://storage.googleapis.com/chromeos-localmirror/secureshell/releases/%s.tar.xz ' \
		"${PLUGIN_VERSIONS[@]}")
"

# The archives above live on Google maintained sites.
RESTRICT="mirror"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"
IUSE=""

RDEPEND="!<chromeos-base/common-assets-0.0.2"

e() {
	echo "$@"
	"$@" || die
}

src_compile() {
	export VCSID="${CROS_WORKON_COMMIT:-${PF}}"
	e ./nassh/bin/mkdist --crosh-only
}

src_install() {
	local dir="/usr/share/chromeos-assets/crosh_builtin"
	dodir "${dir}"
	unzip -d "${D}${dir}" nassh/dist/crosh.zip || die
	local pnacl="${D}${dir}/plugin/pnacl"
	if ! use arm && ! use arm64; then
		rm "${pnacl}/ssh_client_nl_arm.nexe"* || die
	fi
	if ! use x86 ; then
		rm "${pnacl}/ssh_client_nl_x86_32.nexe"* || die
	fi
	if ! use amd64 ; then
		rm "${pnacl}/ssh_client_nl_x86_64.nexe"* || die
	fi
}
