# Copyright 1999-2018 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/third_party/shellcheck"
CROS_WORKON_LOCALNAME="shellcheck"
CROS_WORKON_EGIT_BRANCH="chromeos-0.7"
CROS_WORKON_DESTDIR="${S}"

CABAL_FILE="${S}/ShellCheck.cabal"
CABAL_LIVE_VERSION=true  # Avoid automatic SRC_URI from haskell-cabal.eclass.

CABAL_FEATURES="profile haddock hoogle hscolour test-suite"
CABAL_EXTRA_CONFIGURE_FLAGS="--disable-executable-dynamic
	--disable-shared
	--ghc-option=-optl-static
"

inherit cros-workon haskell-cabal

DESCRIPTION="Shell script analysis tool"
HOMEPAGE="https://www.shellcheck.net/"

LICENSE="GPL-3"
SLOT="0/${PV}"
KEYWORDS="~*"
IUSE=""

DEPEND=">=dev-haskell/aeson-1.4.0:=[profile?] <dev-haskell/aeson-2.2:=[profile?]
	>=dev-haskell/diff-0.4.0:=[profile?] <dev-haskell/diff-0.5:=[profile?]
	>=dev-haskell/mtl-2.2.1:=[profile?]
	>=dev-haskell/parsec-3.0:=[profile?]
	>=dev-haskell/quickcheck-2.14.2:2=[template-haskell,profile?]
	<dev-haskell/quickcheck-2.15:2=[profile?]
	>=dev-haskell/regex-tdfa-1.2.0:=[profile?]
	<dev-haskell/regex-tdfa-1.4:=[profile?]
	dev-haskell/semigroups:=[profile?]
	>=dev-lang/ghc-8.10.1:=
	>=dev-haskell/cabal-3.0.0.0
	dev-libs/gmp[static-libs]
	dev-libs/libffi[static-libs]
"

src_install() {
	cabal_src_install
	# TODO(crbug.com/1000756): Add support for manpage build process (requires pandoc)
	doman "${FILESDIR}/${PN}.1"
}
