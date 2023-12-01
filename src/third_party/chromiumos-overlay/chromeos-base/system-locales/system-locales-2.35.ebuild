# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Note: Chrome itself does not use or care about system locales.  It has ICU
# baked in to handle all i18n issues.  These system locales are for all the
# other packages that might have need of a UTF-8 clean input, including for
# devs who launch shells.
#
# We only generate en_US.UTF-8 currently as our "neutral" locale.  When glibc
# finally ships C.UTF-8, we can switch over to that.
# https://sourceware.org/glibc/wiki/Proposals/C.UTF-8

EAPI="7"

inherit toolchain-funcs multilib

DESCRIPTION="Some system locales when apps need more than C (not for apps using ICU for i18n)"
HOMEPAGE="http://dev.chromium.org/"
SRC_URI=""

# The source locale files come from glibc, and the FSF specifically disclaims
# any and all copyright to them.
LICENSE="public-domain"
SLOT="0"
KEYWORDS="*"
IUSE=""

# The locale files change across glibc versions, so make sure we stay in sync
# with them.  Pinning the version here forces us to revbump it when we update
# the glibc version.
DEPEND="~sys-libs/glibc-${PV}"
RDEPEND="${DEPEND}"

S="${WORKDIR}"

e() {
	echo "$@"
	"$@" || die
}

src_compile() {
	local args=(
		# Many locales contain warnings that we don't care about and we can't
		# really fix here.
		--force

		# Select the right output format for the target.
		"--$(tc-endian)-endian"
	)

	mkdir -p usr/lib/locale
	e localedef --prefix="${PWD}" "${args[@]}" \
		--charmap=UTF-8 --inputfile=en_US \
		en_US.UTF-8 || die &
	e localedef --prefix="${PWD}" "${args[@]}" \
		--charmap=UTF-8 --inputfile=C \
		C.UTF-8 || die &
	wait
}

src_install() {
	insinto /usr/lib/locale
	doins usr/lib/locale/locale-archive
}
