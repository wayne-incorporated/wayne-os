# Copyright 1999-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
PYTHON_REQ_USE="threads(+),xml(+)"

inherit cros-fuzzer cros-sanitizers autotools python-single-r1 readme.gentoo-r1 udev

DESCRIPTION="HP Linux Imaging and Printing - Print, scan, fax drivers and service tools"
HOMEPAGE="https://developers.hp.com/hp-linux-imaging-and-printing"
SRC_URI="mirror://sourceforge/hplip/${P}.tar.gz
		https://dev.gentoo.org/~billie/distfiles/${PN}-3.22.6-patches-1.tar.xz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"

IUSE="asan fuzzer doc fax +hpcups hpijs kde libnotify -libusb0 minimal parport policykit qt5 scanner +snmp static-ppds X"

COMMON_DEPEND="
	net-print/cups
	sys-apps/dbus
	virtual/jpeg:0
	hpijs? ( net-print/cups-filters[foomatic] )
	!minimal? (
		!libusb0? ( virtual/libusb:1 )
		libusb0? ( virtual/libusb:0 )
		scanner? ( media-gfx/sane-backends )
		snmp? (
			dev-libs/openssl:0=
			net-analyzer/net-snmp:=
			net-dns/avahi[dbus,python,${PYTHON_SINGLE_USEDEP}]
		)
	)
"
BDEPEND="
	virtual/pkgconfig
"
DEPEND="
	${COMMON_DEPEND}
	${PYTHON_DEPS}
"
RDEPEND="
	${COMMON_DEPEND}
	app-text/ghostscript-gpl
	!minimal? (
		$(python_gen_cond_dep '>=dev-python/dbus-python-1.2.0-r1[${PYTHON_USEDEP}]')
		$(python_gen_cond_dep 'dev-python/pygobject:2[${PYTHON_USEDEP}]' 'python2*')
		$(python_gen_cond_dep 'dev-python/pygobject:3[${PYTHON_USEDEP}]' 'python3*')
		fax? ( $(python_gen_cond_dep 'dev-python/reportlab[${PYTHON_USEDEP}]') )
		kernel_linux? ( virtual/udev )
		qt5? (
			$(python_gen_cond_dep \
				'>=dev-python/PyQt5-5.5.1[dbus,gui,widgets,${PYTHON_USEDEP}]')
			libnotify? ( $(python_gen_cond_dep 'dev-python/notify2[${PYTHON_USEDEP}]') )
		)
		scanner? (
			$(python_gen_cond_dep '>=dev-python/reportlab-3.2[${PYTHON_USEDEP}]')
			$(python_gen_cond_dep '>=dev-python/pillow-3.1.1[${PYTHON_USEDEP}]')
			X? (
				|| (
					kde? ( kde-misc/skanlite )
					media-gfx/xsane
					media-gfx/sane-frontends
				)
			)
		)
	)
	policykit? ( sys-auth/polkit )
"

REQUIRED_USE="${PYTHON_REQUIRED_USE}"

PATCHES=(
	"${WORKDIR}/patches"
	"${FILESDIR}/${PN}-3.21.8-disable-create-ppd.patch"
	"${FILESDIR}/${PN}-3.19.6-ignore-prebuilt-shared-objects.patch"
	"${FILESDIR}/${PN}-3.19.6-fix-uninitialized-variable.patch"
	"${FILESDIR}/${PN}-3.19.6-fix-pixel-color-overflow.patch"
	"${FILESDIR}/${PN}-3.21.8-disable-python.patch"
	"${FILESDIR}/${PN}-3.21.8-fix-unpack-bits.patch"
	"${FILESDIR}/${PN}-3.21.8-fix-cupsbytesperline.patch"
	"${FILESDIR}/${PN}-3.21.8-fix-buffer-overflow-in-halftoner.patch"
	"${FILESDIR}/${PN}-3.21.8-fix-tempbuffer-size-in-halftoner.patch"
	"${FILESDIR}/${PN}-3.21.8-fix-bad-header-read.patch"
	"${FILESDIR}/${PN}-3.22.6-gccver.patch"
	"${FILESDIR}/${PN}-3.22.6-fix-ub-pointer-overflow.patch"
)

#DISABLE_AUTOFORMATTING="yes"
DOC_CONTENTS="
For more information on setting up your printer please take
a look at the hplip section of the gentoo printing guide:
https://wiki.gentoo.org/wiki/Printing

Any user who wants to print must be in the lp group.
"

pkg_setup() {
	python-single-r1_pkg_setup

	use scanner && ! use X && einfo "You need USE=X for the scanner GUI."

	if use minimal ; then
		einfo "Installing driver portions only, make sure you know what you are doing."
		einfo "Depending on the USE flags set for hpcups or hpijs the appropiate driver"
		einfo "is installed. If both USE flags are set hpijs overrides hpcups."
	fi

	if ! use hpcups && ! use hpijs ; then
		einfo "Installing neither hpcups (USE=-hpcups) nor hpijs (USE=-hpijs) driver,"
		einfo "which is probably not what you want."
		einfo "You will almost certainly not be able to print."
	fi
}

src_prepare() {
	default

	if use fuzzer ; then
		eapply "${FILESDIR}/${PN}-3.21.8-fuzz.patch"
		cp "${FILESDIR}"/{hpcups,hpps}_fuzzer.cc "${FILESDIR}"/stdin_util.{h,cc} .
	fi

	python_fix_shebang .

	# Make desktop files follow the specification
	# Gentoo bug: https://bugs.gentoo.org/show_bug.cgi?id=443680
	# Upstream bug: https://bugs.launchpad.net/hplip/+bug/1080324
	sed -i -e '/^Categories=/s/Application;//' \
		-e '/^Encoding=.*/d' hplip.desktop.in || die
	sed -i -e '/^Categories=/s/Application;//' \
		-e '/^Version=.*/d' \
		-e '/^Comment=.*/d' hplip-systray.desktop.in || die

	# Force recognition of Gentoo distro by hp-check
	sed -i \
		-e "s:file('/etc/issue', 'r').read():'Gentoo':" \
		installer/core_install.py || die

	# Forcibly delete prebuilt shared objects that the Chrome OS
	# build prefers not to rely upon.
	rm -r "${S}/prnt/plugins" || die

	eautoreconf
}

src_configure() {
	if use fuzzer ; then
		fuzzer-setup-env || die
	fi

	local drv_build=()
	local minimal_build=()

	sanitizers-setup-env
	append-lfs-flags

	if use hpcups ; then
		drv_build+=("$(use_enable hpcups hpcups-install)")
		if use static-ppds ; then
			drv_build+=( --enable-cups-ppd-install )
			drv_build+=( --disable-cups-drv-install )
		else
			drv_build+=( --enable-cups-drv-install )
			drv_build+=( --disable-cups-ppd-install )
		fi
	else
		drv_build+=( --disable-hpcups-install )
		drv_build+=( --disable-cups-drv-install )
		drv_build+=( --disable-cups-ppd-install )
	fi

	if use hpijs ; then
		drv_build+=(" $(use_enable hpijs hpijs-install)")
		if use static-ppds ; then
			drv_build+=( --enable-foomatic-ppd-install )
			drv_build+=( --disable-foomatic-drv-install )
		else
			drv_build+=( --enable-foomatic-drv-install )
			drv_build+=( --disable-foomatic-ppd-install )
		fi
	else
		drv_build+=( --disable-hpijs-install )
		drv_build+=( --disable-foomatic-drv-install )
		drv_build+=( --disable-foomatic-ppd-install )
	fi

	if use minimal ; then
		if use hpijs ; then
			minimal_build+=( --enable-hpijs-only-build )
		else
			minimal_build+=( --disable-hpijs-only-build )
		fi
		if use hpcups ; then
			minimal_build+=( --enable-hpcups-only-build )
		else
			minimal_build+=( --disable-hpcups-only-build )
		fi
		minimal_build+=( --disable-fax-build )
		minimal_build+=( --disable-network-build )
		minimal_build+=( --disable-scan-build )
		minimal_build+=( --disable-gui-build )
	else
		if use fax ; then
			minimal_build+=( --enable-fax-build )
		else
			minimal_build+=( --disable-fax-build )
		fi
		if use snmp ; then
			minimal_build+=( --enable-network-build )
		else
			minimal_build+=( --disable-network-build )
		fi
		if use scanner ; then
			minimal_build+=( --enable-scan-build )
		else
			minimal_build+=( --disable-scan-build )
		fi
		if use qt5 ; then
			minimal_build+=( --enable-qt5 )
			minimal_build+=( --enable-gui-build )
		else
			minimal_build+=( --disable-gui-build )
			minimal_build+=( --disable-qt5 )
		fi
	fi

	local cups_config="${SYSROOT}/usr/bin/cups-config"
	# disable class driver for now
	econf \
		--enable-class-driver \
		--disable-cups11-build \
		--disable-foomatic-rip-hplip-install \
		--disable-imageProcessor-build \
		--disable-lite-build \
		--disable-run-create-ppd \
		--disable-shadow-build \
		--disable-qt3 \
		--disable-qt4 \
		--disable-udev_sysfs_rules \
		--with-cupsbackenddir="$("${cups_config}" --serverbin)"/backend \
		--with-cupsfilterdir="$("${cups_config}" --serverbin)"/filter \
		--with-docdir=/usr/share/doc/${PF} \
		--with-htmldir=/usr/share/doc/${PF}/html \
		--enable-hpps-install \
		$(use_enable !minimal dbus-build) \
		--disable-network-build \
		"${drv_build[@]}" \
		"${minimal_build[@]}" \
		$(use_enable doc doc-build) \
		$(use_enable libusb0 libusb01_build) \
		$(use_enable parport pp-build) \
		$(use_enable policykit)

	# hpijs ppds are created at configure time but are not installed (3.17.11)

	# Use system foomatic-rip for hpijs driver instead of foomatic-rip-hplip
	# The hpcups driver does not use foomatic-rip
	#local i
	#for i in ppd/hpijs/*.ppd.gz ; do
	#	rm -f ${i}.temp || die
	#	gunzip -c ${i} | sed 's/foomatic-rip-hplip/foomatic-rip/g' | \
	#		gzip > ${i}.temp || die
	#	mv ${i}.temp ${i} || die
	#done
}

src_install() {
	# Only install the hpps and hpcups filters.
	exeinto /usr/libexec/cups/filter
	doexe hpps
	doexe hpcups

	readme.gentoo_create_doc

	if use fuzzer ; then
		insinto /usr/share/cups/model
		doins "${FILESDIR}"/hpcups.ppd
		local fuzzer_component_id="167231"
		fuzzer_install "${FILESDIR}"/OWNERS hpcups_fuzzer --comp "${fuzzer_component_id}"
		fuzzer_install "${FILESDIR}"/OWNERS hpps_fuzzer --comp "${fuzzer_component_id}"
	fi
}

pkg_postinst() {
	readme.gentoo_print_elog
}
