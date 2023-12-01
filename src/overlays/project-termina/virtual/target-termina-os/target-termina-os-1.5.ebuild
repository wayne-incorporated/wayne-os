# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Packages for the Termina base image"
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE="vm-containers"

RDEPEND="
	app-arch/bzip2
	app-arch/gzip
	app-arch/tar
	app-arch/xz-utils
	vm-containers? (
		chromeos-base/termina_container_tools
		chromeos-base/tremplin
	)
	chromeos-base/chromeos-bsp-termina
	chromeos-base/mcastd
	chromeos-base/minijail
	chromeos-base/ndproxyd
	chromeos-base/termina-chrony-config
	chromeos-base/vm_guest_tools
	sys-apps/iproute2
	sys-auth/pambase
	sys-fs/btrfs-progs
	virtual/chromeos-bsp
	virtual/implicit-system
	virtual/linux-sources
"

DEPEND="
	${RDEPEND}
"
