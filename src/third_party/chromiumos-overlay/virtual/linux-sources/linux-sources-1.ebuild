# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cros-kernel-versions

DESCRIPTION="Chrome OS Kernel virtual package"
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

# shellcheck disable=SC2154
IUSE="${!CHROMEOS_KERNELS[*]}"
# exactly one of foo, bar, or baz must be set, but not several
REQUIRED_USE="^^ ( ${!CHROMEOS_KERNELS[*]} )"

# shellcheck disable=SC2154
RDEPEND="
	$(for v in "${!CHROMEOS_KERNELS[@]}"; do echo  "${v}? (  sys-kernel/${CHROMEOS_KERNELS[${v}]} )"; done)
"

# Add blockers so when migrating between USE flags, the old version gets
# unmerged automatically.
# shellcheck disable=SC2154
RDEPEND+="
	$(for v in "${!CHROMEOS_KERNELS[@]}"; do echo "!${v}? ( !sys-kernel/${CHROMEOS_KERNELS[${v}]} )"; done)
"

# Default to the latest kernel if none has been selected.
# TODO: This defaulting does not work. Fix or remove.
RDEPEND_DEFAULT="sys-kernel/chromeos-kernel-5_4"
# Here be dragons!
RDEPEND+="
	$(printf '!%s? ( ' "${!CHROMEOS_KERNELS[@]}")
	${RDEPEND_DEFAULT}
	$(printf '%0.s) ' "${!CHROMEOS_KERNELS[@]}")
"
