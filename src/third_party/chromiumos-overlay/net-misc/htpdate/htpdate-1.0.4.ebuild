# Copyright 1999-2009 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit toolchain-funcs

DESCRIPTION="Synchronize local workstation with time offered by remote webservers"
HOMEPAGE="http://www.clevervest.com/htp/"
SRC_URI="http://www.clevervest.com/htp/archive/c/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

PATCHES=(
	"${FILESDIR}/${P}-waitforvalidhttpresp.patch"
	"${FILESDIR}/${P}-errorcheckhttpresp.patch"
	"${FILESDIR}/${P}-checkagainstbuildtime.patch"
	"${FILESDIR}/${P}-oob_date_read.patch"
	"${FILESDIR}/${P}-errorsarentsuccess.patch"
	"${FILESDIR}/${P}-64bit_limits.patch"
	"${FILESDIR}/${P}-relative_path.patch"
	"${FILESDIR}/${P}-all_headers.patch"
)

src_unpack() {
	unpack ${A}
	cd "${S}" || die
	unpack ./htpdate.8.gz || die
}

src_compile() {
	# Provide timestamp of when this was built, in number of seconds since
	# 01 Jan 1970 in UTC time.
	local stamp=$(date -u +%s)
	# Set it back one day to avoid dealing with time zones.
	local date_opt="-DBUILD_TIME_UTC=$(( stamp - 86400 ))"
	emake CFLAGS="-Wall ${date_opt} ${CFLAGS} ${CPPFLAGS} ${LDFLAGS}" CC="$(tc-getCC)"
}

src_install() {
	dosbin htpdate
	doman htpdate.8
	dodoc README Changelog
}
