# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of packages required for the Chromium OS Printing subsystem"
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

IUSE="internal postscript"

RDEPEND="
	chromeos-base/ippusb_bridge
	chromeos-base/lexmark-fax-pnh
	chromeos-base/print_tools
	net-print/cups
	net-print/cups-filters
	net-print/dymo-cups-drivers
	net-print/epson-inkjet-printer-escpr
	net-print/pwgtocanonij
	net-print/starcupsdrv
	internal? (
		net-print/fuji-xerox-printing-license
		net-print/fujifilm-printing-license
		net-print/konica-minolta-printing-license
		net-print/nec-printing-license
		net-print/xerox-printing-license
	)
	postscript? ( net-print/hplip )
"
