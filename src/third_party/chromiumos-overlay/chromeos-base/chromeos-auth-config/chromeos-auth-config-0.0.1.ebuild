# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit pam

DESCRIPTION="ChromiumOS-specific configuration files for pambase"
HOMEPAGE="http://www.chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND="sys-auth/pambase"
RDEPEND="${DEPEND}
	chromeos-base/vboot_reference"

S="${WORKDIR}"

src_install() {
	# Chrome OS: sudo and vt2 are important for system debugging both in
	# developer mode and during development.  These two stanzas allow sudo and
	# login auth as user chronos under the following conditions:
	#
	# 1. password-less access:
	# - system in developer mode
	# - there is no passwd.devmode file
	# - there is no system-wide password set above.
	# 2. System-wide (/etc/shadow) password access:
	# - image has a baked in password above
	# 3. Developer mode password access
	# - user creates a passwd.devmode file with "chronos:CRYPTED_PASSWORD"
	# 4. System-wide (/etc/shadow) password access set by modifying /etc/shadow:
	# - Cases #1 and #2 will apply but failure will fall through to the
	#   inserted password.
	insinto /etc/pam.d
	doins "${FILESDIR}/chromeos-auth"

	newpamd "${FILESDIR}"/include-chromeos-auth sudo
	pamd_mimic system-auth sudo auth account session

	newpamd "${FILESDIR}"/include-chromeos-auth sudo-i
	pamd_mimic system-auth sudo-i auth account session

	newpamd "${FILESDIR}"/include-chromeos-auth login
	pamd_mimic system-local-login login auth account password session

	dosbin "${FILESDIR}/is_developer_end_user"
}
