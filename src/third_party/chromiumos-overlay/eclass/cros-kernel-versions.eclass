# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-kernel-version.eclass
# @DESCRIPTION:
# A utility eclass for Chromium OS kernel version handling. In particular, it
# provides the names for kernel packages and IUSE flag names.

if [[ -z ${_CROS_KERNEL_VERSION_ECLASS} ]]; then
_CROS_KERNEL_VERSION_ECLASS=1

# Check for EAPI 5+
case "${EAPI:-0}" in
0|1|2|3|4) die "Unsupported EAPI=${EAPI:-0} (too old) for ${ECLASS}." ;;
5|6|7) ;;
esac

# CHROMEOS_KERNELS maps IUSE flag names to kernel package names.
declare -g -A CHROMEOS_KERNELS=(
	[kernel-4_4]=chromeos-kernel-4_4
	[kernel-4_14]=chromeos-kernel-4_14
	[kernel-4_19]=chromeos-kernel-4_19
	[kernel-5_4]=chromeos-kernel-5_4
	[kernel-5_10]=chromeos-kernel-5_10
	[kernel-5_15]=chromeos-kernel-5_15
	[kernel-6_1]=chromeos-kernel-6_1
	[kernel-experimental]=chromeos-kernel-experimental
	[kernel-next]=chromeos-kernel-next
	[kernel-upstream]=chromeos-kernel-upstream
	[kernel-upstream-mainline]=upstream-kernel-mainline
	[kernel-upstream-next]=upstream-kernel-next
)

# Add blockers so when switching between kernels packages, the old package gets
# unmerged automatically. Add blockers only for kernels in CHROMEOS_KERNELS.
if [[ ${CATEGORY} == "sys-kernel" ]] && has "${PN}" "${CHROMEOS_KERNELS[@]}"; then
	RDEPEND+="
		$(for v in "${CHROMEOS_KERNELS[@]}"; do [[ ${PN} == "${v}" ]] || echo "!sys-kernel/${v}"; done)
	"
fi

fi
