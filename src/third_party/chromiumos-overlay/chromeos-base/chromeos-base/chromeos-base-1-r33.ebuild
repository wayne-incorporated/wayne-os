# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon user udev tmpfiles

DESCRIPTION="ChromeOS specific system setup"
HOMEPAGE="https://dev.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="chromeless_tty cros_embedded cros_host pam uefi vtconsole kernel-4_4"

# We need to make sure timezone-data is merged before us.
# See pkg_setup below as well as http://crosbug.com/27413
# and friends.
# Similarly, we have to make sure bash is merged before us.
# We don't need dash because only bash modifies ROOT duing
# pkg_* stages, and depending on dash would disable a little
# bit of possible parallelism.
# See https://crbug.com/220728 for more details.
DEPEND=">=sys-apps/baselayout-2
	!<sys-apps/baselayout-2.0.1-r227
	!<sys-libs/timezone-data-2011d
	!<=app-admin/sudo-1.8.2
	!<sys-apps/mawk-1.3.4
	!<app-shells/bash-4.1
	!<app-shells/dash-0.5.5
	!<net-misc/openssh-5.2_p1-r8
	app-shells/bash
	!cros_host? (
		!pam? (
			!app-admin/sudo
		)
		!app-misc/editor-wrapper
		cros_embedded? (
			app-shells/dash
		)
		sys-libs/timezone-data
	)
	acct-user/chronos
	acct-group/chronos"
RDEPEND="${DEPEND}"

# The user that all user-facing processes will run as.
SHARED_USER_NAME="chronos"

# Adds a "daemon"-type user/group pair.
add_daemon_user() {
	local username="$1"
	local uid="$2"
	enewuser "${username}" "${uid}"
	enewgroup "${username}" "${uid}"
}

pkg_setup() {
	if ! use cros_host ; then
		# The sys-libs/timezone-data package installs a default /etc/localtime
		# file automatically, so scrub that if it's a regular file.
		local etc_tz="${ROOT}etc/localtime"
		[[ -L ${etc_tz} ]] || rm -f "${etc_tz}"
	fi

	# Standard system users/groups. Allow them to get default IDs.
	add_daemon_user "root"
	add_daemon_user "bin"
	add_daemon_user "daemon"
	enewgroup "sys"
	add_daemon_user "adm"
	enewgroup "tty"
	enewgroup "disk"
	add_daemon_user "lp"
	enewgroup "mem"
	enewgroup "kmem"
	enewgroup "wheel"
	enewgroup "floppy"
	add_daemon_user "news"
	add_daemon_user "uucp"
	enewgroup "console"
	enewgroup "audio"
	enewgroup "cdrom"
	enewgroup "tape"
	enewgroup "video"
	enewgroup "cdrw"
	enewgroup "usb"
	enewgroup "users"
	add_daemon_user "portage"
	enewgroup "utmp"
	enewgroup "nogroup"
	add_daemon_user "nobody"
	enewgroup "uinput"
}

pkg_preinst() {
	# Create users and groups that are used by system daemons at runtime.
	# Users and groups that are also needed at build time should be
	# created in pkg_setup instead.
	add_daemon_user "input"      # For /dev/input/event access
	enewgroup "i2c"              # For I2C device node access.
	enewgroup "hidraw"           # For hidraw device node access.
	enewgroup "drm_dp_aux"       # For drm_dp_aux device node access.
	enewgroup "password-viewers" # For access to the user's password
	enewgroup "serial"           # For owning access to serial devices.
	enewgroup "tun"              # For access to /dev/net/tun.

	# Add a chronos-access group to provide non-chronos users,
	# mostly system daemons running as a non-chronos user, group permissions
	# to access files/directories owned by chronos.
	local system_access_user="chronos-access"
	local system_access_id="1001"

	add_daemon_user "${system_access_user}" "${system_access_id}"

	# Some default directories. These are created here rather than at
	# install because some of them may already exist and have mounts.
	local x
	for x in /dev /home /media /run /mnt/empty \
		/mnt/stateful_partition /proc /root /sys /var/lock; do
		[[ -d "${ROOT}/${x}" ]] && continue
		install -d --mode=0755 --owner=root --group=root "${ROOT}/${x}"
	done

	# Create mount point for the EFI System Partition.
	if ! use cros_host && use uefi; then
		install -d --mode=0755 --owner=root --group=root "${ROOT}/efi"
	fi
}

src_install() {
	insinto /etc
	doins "${FILESDIR}"/issue

	insinto /etc/sysctl.d
	doins "${FILESDIR}"/00-sysctl.conf "${FILESDIR}"/10-fs-flush.conf.ac_only

	insinto /etc/profile.d
	doins "${FILESDIR}"/xauthority.sh

	insinto /etc/avahi
	doins "${FILESDIR}"/avahi-daemon.conf

	insinto /etc/modprobe.d
	doins "${FILESDIR}"/modprobe.d/*.conf

	# 01editor is currently using /usr/bin/vi, which is available on both
	# cros_host and DUT. Please update this when default editor is changed.
	insinto /etc/env.d
	doins "${FILESDIR}/01editor"

	# target-specific fun
	if ! use cros_host ; then
		dodir /bin /usr/bin

		# Install all the udev rules.
		udev_dorules "${FILESDIR}"/udev-rules/*.rules
		use vtconsole && udev_dorules "${FILESDIR}"/60-X-tty1-tty2-group-rw.rules

		# Install all the tmpfiles.d configs.
		dotmpfiles "${FILESDIR}/tmpfiles.d"/*.conf

		# b/212196481 : only chromeos kernels v4.14 (and newer) r8152 driver
		# have support for RTL8153C and RTL8153D. Older kernels should
		# continue using the "default" driver (cdc_ether or cdc_ncm).
		# For v4.14 and newer kernels, we can enable WOL functionality even
		# if the product doesn't officially support WOL. The goal is consistent
		# behavior for all other driver features across those platforms.
		#
		# Revert this change once we stop building/shipping those kernels.
		if use kernel-4_4 ; then
			rm -f "${D}"/lib/udev/rules.d/??-usb-rtl_nic-net.rules
		fi

		# Symlink /etc/localtime to something on the stateful
		# partition. At runtime, the system will take care of
		# initializing the path in /var.
		dosym /var/lib/timezone/localtime /etc/localtime
		# We use mawk in the target boards, not gawk.
		dosym mawk /usr/bin/awk

		# We want dash as our main shell.
		dosym dash /bin/sh

		# Avoid the wrapper and just link to the only editor we have.
		dodir /usr/libexec
		dosym /usr/bin/$(usex cros_embedded vi vim) /usr/libexec/editor
		dosym /bin/more /usr/libexec/pager

		# Install our custom ssh config settings.
		insinto /etc/ssh
		doins "${FILESDIR}"/ssh{,d}_config
		fperms 600 /etc/ssh/sshd_config

		if ! use pam ; then
			dobin "${FILESDIR}"/sudo
			sed -i -e '/^UsePAM/d' "${D}"/etc/ssh/sshd_config || die
		fi

		# Custom login shell snippets.
		insinto /etc/profile.d
		doins "${FILESDIR}"/cursor.sh

		insinto /etc/bash/bashrc.d
		doins "${FILESDIR}"/01-prompt.sh
	fi

	# Some daemons and utilities access the mounts through /etc/mtab.
	dosym /proc/mounts /etc/mtab

	insinto /etc/sudoers.d
	echo "${SHARED_USER_NAME} ALL=(ALL) ALL" > 95_cros_base
	insopts -m 440
	doins 95_cros_base
}
