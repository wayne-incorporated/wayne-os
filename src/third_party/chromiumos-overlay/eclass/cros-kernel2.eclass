# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
#
# Shellcheck doesn't understand our CONFIG_FRAMGMENTS expansion.
# shellcheck disable=SC2034

# When you change this eclass, please update
# sys-kernel/chromeos-kernel-*/*/files/revision_bump files to cause package
# rebuilds, working around https://issuetracker.google.com/201299127.
#
# The content of revision_bump files does not matter, as long as it changes.

# Check for EAPI 7+.
case "${EAPI:-0}" in
0|1|2|3|4|5|6) die "Unsupported EAPI=${EAPI:-0} (too old) for ${ECLASS}" ;;
7) ;;
esac

# Since we use CHROMEOS_KERNEL_CONFIG, CHROMEOS_KERNEL_SPLITCONFIG, and
# CHROMEOS_DTBS here, it is not safe to reuse the kernel prebuilts across
# different boards. Inherit the cros-board eclass to make sure that doesn't
# happen.
inherit binutils-funcs cros-board cros-kernel-versions estack toolchain-funcs

HOMEPAGE="http://www.chromium.org/"
LICENSE="GPL-2"
SLOT="0"

DEPEND="sys-kernel/linux-firmware
	factory_netboot_ramfs? ( chromeos-base/chromeos-initramfs[factory_netboot_ramfs] )
	factory_shim_ramfs? ( chromeos-base/chromeos-initramfs[factory_shim_ramfs] )
	minios_ramfs? ( chromeos-base/chromeos-initramfs[minios_ramfs] )
	recovery_ramfs? ( chromeos-base/chromeos-initramfs[recovery_ramfs] )
	builtin_fw_mali_g57? ( virtual/opengles )
	builtin_fw_t210_bpmp? ( sys-kernel/tegra_bpmp-t210 )
	builtin_fw_t210_nouveau? ( sys-kernel/nouveau-firmware )
	builtin_fw_x86_adl_ucode? ( sys-firmware/brya-kernel-ucode )
	builtin_fw_x86_adln_ucode? ( sys-firmware/adln-ucode-firmware-private )
	builtin_fw_x86_amd_ucode? ( sys-kernel/linux-firmware[linux_firmware_amd_ucode] )
	builtin_fw_x86_aml_ucode? ( chromeos-base/aml-ucode-firmware-private )
	builtin_fw_x86_apl_ucode? ( chromeos-base/apl-ucode-firmware-private )
	builtin_fw_x86_bdw_ucode? ( chromeos-base/bdw-ucode-firmware-private )
	builtin_fw_x86_bsw_ucode? ( chromeos-base/bsw-ucode-firmware-private )
	builtin_fw_x86_byt_ucode? ( chromeos-base/byt-ucode-firmware-private )
	builtin_fw_x86_cml_ucode? ( chromeos-base/cml-ucode-firmware-private )
	builtin_fw_x86_glk_ucode? ( chromeos-base/glk-ucode-firmware-private )
	builtin_fw_x86_intel_ucode? ( sys-firmware/intel-ucode-firmware )
	builtin_fw_x86_jsl_ucode? ( chromeos-base/jsl-ucode-firmware-private )
	builtin_fw_x86_kbl_ucode? ( chromeos-base/kbl-ucode-firmware-private )
	builtin_fw_x86_mdn_ucode? ( sys-firmware/mdn-ucode-firmware-private )
	builtin_fw_x86_mtl_ucode? ( sys-firmware/mtl-ucode-firmware-private )
	builtin_fw_x86_rpl_ucode? ( sys-firmware/brya-kernel-ucode )
	builtin_fw_x86_skl_ucode? ( chromeos-base/skl-ucode-firmware-private )
	builtin_fw_x86_tgl_ucode? ( chromeos-base/tgl-ucode-firmware-private )
	builtin_fw_x86_whl_ucode? ( chromeos-base/whl-ucode-firmware-private )
"

CHROMEOS_KERNEL_FAMILY_VALUES=(
	arcvm
	chromeos
	termina
)

CHROMEOS_KERNEL_FAMILY_FLAGS=(
	"${CHROMEOS_KERNEL_FAMILY_VALUES[@]/#/chromeos_kernel_family_}"
)

IUSE="
	apply_patches
	-asan
	buildtest
	${CHROMEOS_KERNEL_FAMILY_FLAGS[*]}
	+clang
	-compilation_database
	-device_tree
	dt_choose_all
	+dt_compression
	+fit_compression_kernel_lz4
	fit_compression_kernel_lzma
	firmware_install
	frozen_gcc
	hibernate
	-kernel_sources
	kernel_warning_level_1
	kernel_warning_level_2
	kernel_warning_level_3
	+lld
	+llvm_ias
	nfc
	-wifi_testbed_ap
	-boot_dts_device_tree
	-nowerror
	-ppp
	-binder
	-selinux_develop
	-transparent_hugepage
	tpm2
	-kernel_afdo
	-kernel_afdo_verify
	-kern_arm_afdo
	+vdso32
	-criu
	-docker
	-lxc
	sparse
	disable_kernel_fragments
	-kfuzz
"
REQUIRED_USE="
	^^ ( ${CHROMEOS_KERNEL_FAMILY_FLAGS[*]} )
	compilation_database? ( clang )
	?? ( fit_compression_kernel_lz4 fit_compression_kernel_lzma )
	frozen_gcc? ( !clang )
	kern_arm_afdo? ( kernel_afdo )
	lld? ( clang )
	llvm_ias? ( clang )
"
STRIP_MASK="
	/lib/modules/*/kernel/*
	/usr/lib/debug/*
	/usr/src/*
"

# SRC_URI requires RESTRICT="mirror". We specify AutoFDO profiles in SRC_URI
# so that ebuild can fetch it for us.
# binchecks is restricted because the kernel does not use all the same build
# flags we want for userland (crbug/1061666).
RESTRICT="binchecks mirror"
SRC_URI=""

KERNEL_VERSION="${PN#chromeos-kernel-}"
KERNEL_VERSION="${KERNEL_VERSION/_/.}"

# Specifying AutoFDO profiles in SRC_URI and let ebuild fetch it for us.
# Prefer the frozen version of afdo profiles if set.
AFDO_VERSION=${AFDO_FROZEN_PROFILE_VERSION:-${AFDO_PROFILE_VERSION}}
ARM_AFDO_VERSION=${ARM_AFDO_FROZEN_PROFILE_VERSION:-${ARM_AFDO_PROFILE_VERSION}}

GS_PREFIX="gs://chromeos-prebuilt/afdo-job/cwp/kernel"
if [[ -n "${AFDO_VERSION}" ]]; then
	# Set AFDO_LOCATION if not already set.
	: "${AFDO_LOCATION:="${GS_PREFIX}/amd64/${KERNEL_VERSION}"}"
	AFDO_GCOV="${PN}-${AFDO_VERSION}.gcov"
	AFDO_GCOV_EXTBINARY="${AFDO_GCOV}.extbinary.afdo"
	SRC_URI+=" kernel_afdo? (
		${AFDO_LOCATION}/${AFDO_VERSION}.gcov.xz -> ${AFDO_GCOV}.xz
	)"
fi
if [[ -n "${ARM_AFDO_VERSION}" ]]; then
	: "${ARM_AFDO_LOCATION:="${GS_PREFIX}/arm/${KERNEL_VERSION}"}"
	ARM_AFDO_GCOV="${PN}-${ARM_AFDO_VERSION}.gcov"
	ARM_AFDO_GCOV_EXTBINARY="${ARM_AFDO_GCOV}.extbinary.afdo"
	SRC_URI+=" kern_arm_afdo? (
		${ARM_AFDO_LOCATION}/${ARM_AFDO_VERSION}.gcov.xz -> ${ARM_AFDO_GCOV}.xz
	)"
fi

apply_private_patches() {
	eshopts_push -s nullglob
	local patches=( "${FILESDIR}"/*.patch )
	eshopts_pop
	[[ ${#patches[@]} -gt 0 ]] && eapply "${patches[@]}"
}

# Ignore files under /lib/modules/ as we like to install vdso objects in there.
MULTILIB_STRICT_EXEMPT+="|modules"

# Build out-of-tree and incremental by default, but allow an ebuild inheriting
# this eclass to explicitly build in-tree.
: "${CROS_WORKON_OUTOFTREE_BUILD:=1}"
: "${CROS_WORKON_INCREMENTAL_BUILD:=1}"

# Config fragments selected by USE flags. _config fragments are mandatory,
# _config_disable fragments are optional and will be appended to kernel config
# if use flag is not set.
# ...fragments will have the following variables substitutions
# applied later (needs to be done later since these values
# aren't reliable when used in a global context like this):
#   %ROOT% => ${SYSROOT}
#
# A NOTE about config fragments and when they should be used...
#
# In general config fragments should be avoided.
# - They tend to get crufty and obsolete as the kernel moves forward and
#   nothing validates that they still make sense.
# - It's non-obvious when someone is working with the kernel that extra
#   configs were turned on with a fragment.
#
# Fragments should really only be for:
# - Debug options that a developer might turn on when building the kernel
#   themselves.
# - Debug options that a builder might turn on for producing a debug build
#   with extra testing (options that we don't want enabled for production).
# - Options enabling risky features that are only enabled for non-production
#   boards that otherwise share the same kernel as production boards.
# - Options needed for building the recovery image kernel. This kernel shares
#   the same kernel config as the normal kernel but needs a few extra kernel
#   options that we _don't_ want turned on for the normal kernel.
#
# If a feature is safe for production it should simply be turned on in the main
# kernel config even if only a subset of boards need that feature turned on.

CONFIG_FRAGMENTS=(
	acpi_ac
	acpi_debug
	allocator_slab
	apex
	aurora
	binder
	blkdevram
	bpf_extras
	builtin_driver_amdgpu
	ca0132
	criu
	cros_ec_mec
	debug
	debugobjects
	devdebug
	diskswap
	dmadebug
	dm_snapshot
	docker
	drm_dp_aux_chardev
	dwc2_dual_role
	dyndebug
	ec2_guest_net
	eve_bt_hacks
	eve_wifi_etsi
	factory_netboot_ramfs
	factory_shim_ramfs
	failslab
	fbconsole
	goldfish
	hibernate
	highmem
	hypervisor_guest
	i2cdev
	iioservice
	irqsoff_tracer
	iscsi
	livepatch
	lockdown
	lxc
	kasan
	kcfi
	kcov
	kcsan
	kernel_compress_xz
	kexec_file
	kgdb
	kmemleak
	kvm
	kvm_invept_global
	kvm_host
	kvm_nested
	kvm_virt_suspend_time
	lockdebug
	lockstat
	lpss_uart
	mbim
	memory_debug
	minios_ramfs
	module_sign
	nfc
	nfs
	nowerror
	pageowner
	pca954x
	pcserial
	pkvm
	plan9
	ppp
	preempt_tracer
	pvrdebug
	qmi
	realtekpstor
	recovery_ramfs
	samsung_serial
	sched_tracer
	selinux_develop
	socketmon
	systemtap
	tpm
	transparent_hugepage
	ubsan
	usb_gadget
	usb_gadget_acm
	usb_gadget_audio
	usb_gadget_ncm
	usbip
	vfat
	virtio_balloon
	vivid
	vkms
	vlan
	vtpm_proxy
	vmware_guest
	vtconsole
	wifi_testbed_ap
	wifi_diag
	x32
	xen_guest
	vpu_driver
)

acpi_ac_desc="Enable ACPI AC"
acpi_ac_config="
CONFIG_ACPI_AC=y
"
acpi_ac_config_disable="
# CONFIG_ACPI_AC is not set
"
acpi_debug_desc="Enable ACPI DEBUG"
acpi_debug_config="
CONFIG_ACPI_DEBUG=y
"

allocator_slab_desc="Turn on SLAB allocator"
allocator_slab_config="
CONFIG_SLAB=y
# CONFIG_SLUB is not set
"

apex_desc="Apex chip kernel driver"
apex_config="
CONFIG_STAGING_GASKET_FRAMEWORK=m
CONFIG_STAGING_APEX_DRIVER=m
"

aurora_desc="Aurora experiment support"
aurora_config="
CONFIG_INTEL_IOMMU_SCALABLE_MODE_DEFAULT_ON=y
CONFIG_INTEL_IOMMU_SVM=y
CONFIG_IOMMU_DEFAULT_PASSTHROUGH=y
CONFIG_IRQ_REMAP=y
CONFIG_VFIO=m
CONFIG_VFIO_PCI=m
CONFIG_VMD=y
CONFIG_PCI_IOV=y
CONFIG_PCI_PF_STUB=m
CONFIG_PCI_STUB=m
"

binder_desc="binder IPC"
binder_config="
CONFIG_ANDROID=y
CONFIG_ANDROID_BINDER_IPC=y
"

blkdevram_desc="ram block device"
blkdevram_config="
CONFIG_BLK_DEV_RAM=y
CONFIG_BLK_DEV_RAM_COUNT=16
CONFIG_BLK_DEV_RAM_SIZE=16384
"

bpf_extras_desc="Enable BPF extras. Relocation information and LSM hooks."
bpf_extras_config="
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_LSM=y
"

builtin_driver_amdgpu_desc="DRM driver for AMD GPUs"
builtin_driver_amdgpu_config="
CONFIG_DRM_AMDGPU=y
"
ca0132_desc="CA0132 ALSA codec"
ca0132_config="
CONFIG_SND_HDA_CODEC_CA0132=y
CONFIG_SND_HDA_DSP_LOADER=y
"

criu_desc="Flags required if you wish to use the criu python library"
criu_config="
CONFIG_CHECKPOINT_RESTORE=y
CONFIG_EPOLL=y
CONFIG_EVENTFD=y
CONFIG_FHANDLE=y
CONFIG_IA32_EMULATION=y
CONFIG_INET_DIAG=y
CONFIG_INET_UDP_DIAG=y
CONFIG_INOTIFY_USER=y
CONFIG_NAMESPACES=y
CONFIG_NETLINK_DIAG=y
CONFIG_PACKET_DIAG=y
CONFIG_PID_NS=y
CONFIG_UNIX_DIAG=y
"

cros_ec_mec_desc="LPC Support for Microchip Embedded Controller"
cros_ec_mec_config="
CONFIG_MFD_CROS_EC_LPC_MEC=y
CONFIG_CROS_EC_LPC_MEC=y
"

debugobjects_desc="Enable kernel debug objects debugging"
debugobjects_config="
CONFIG_DEBUG_OBJECTS=y
CONFIG_DEBUG_OBJECTS_SELFTEST=y
CONFIG_DEBUG_OBJECTS_FREE=y
CONFIG_DEBUG_OBJECTS_TIMERS=y
CONFIG_DEBUG_OBJECTS_WORK=y
CONFIG_DEBUG_OBJECTS_RCU_HEAD=y
CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER=y
"

# devdebug configuration options should impose no or little runtime
# overhead while providing useful information for developers.
devdebug_desc="Miscellaneous developer debugging options"
devdebug_config="
CONFIG_ARM_PTDUMP=y
CONFIG_ARM_PTDUMP_DEBUGFS=y
CONFIG_ARM64_PTDUMP_DEBUGFS=y
CONFIG_PTDUMP_DEBUGFS=y
CONFIG_BLK_DEBUG_FS=y
CONFIG_DEBUG_DEVRES=y
CONFIG_DEBUG_WX=y
CONFIG_GENERIC_IRQ_DEBUGFS=y
CONFIG_IRQ_DOMAIN_DEBUG=y
CONFIG_INIT_STACK_ALL_PATTERN=y
"

diskswap_desc="Enable swap file"
diskswap_config="
CONFIG_CRYPTO_LZO=y
CONFIG_DISK_BASED_SWAP=y
CONFIG_FRONTSWAP=y
CONFIG_LZO_COMPRESS=y
CONFIG_Z3FOLD=y
CONFIG_ZBUD=y
CONFIG_ZPOOL=y
CONFIG_ZSWAP=y
"

dmadebug_desc="Enable DMA debugging"
dmadebug_config="
CONFIG_DEBUG_SG=y
CONFIG_DMA_API_DEBUG=y
"

dm_snapshot_desc="Snapshot device mapper target"
dm_snapshot_config="
CONFIG_BLK_DEV_DM=y
CONFIG_DM_SNAPSHOT=m
"

drm_dp_aux_chardev_desc="DisplayPort DP AUX driver support"
drm_dp_aux_chardev_config="
CONFIG_DRM_DP_AUX_CHARDEV=y
"

dwc2_dual_role_desc="Dual Role support for DesignWare USB2.0 controller"
dwc2_dual_role_config="
CONFIG_USB_DWC2_DUAL_ROLE=y
"

dyndebug_desc="Enable Dynamic Debug"
dyndebug_config="
CONFIG_DYNAMIC_DEBUG=y
"

ec2_guest_net_desc="Amazon EC2 Enhanced Networking drivers"
ec2_guest_net_config="
CONFIG_NET_VENDOR_AMAZON=y
CONFIG_ENA_ETHERNET=y
CONFIG_NET_VENDOR_INTEL=y
CONFIG_IXGBEVF=y
"

eve_bt_hacks_desc="Enable Bluetooth Hacks for Eve"
eve_bt_hacks_config="
CONFIG_BT_EVE_HACKS=y
"

eve_wifi_etsi_desc="Eve-specific workaround for ETSI"
eve_wifi_etsi_config="
CONFIG_EVE_ETSI_WORKAROUND=y
"

failslab_desc="Enable fault injection"
failslab_config="
CONFIG_FAILSLAB=y
CONFIG_FAULT_INJECTION=y
CONFIG_FAULT_INJECTION_DEBUG_FS=y
"

fbconsole_desc="framebuffer console"
fbconsole_config="
CONFIG_FRAMEBUFFER_CONSOLE=y
"
fbconsole_config_disable="
# CONFIG_FRAMEBUFFER_CONSOLE is not set
"

goldfish_dec="Goldfish virtual hardware platform"
goldfish_config="
CONFIG_GOLDFISH=y
CONFIG_GOLDFISH_BUS=y
CONFIG_GOLDFISH_PIPE=y
CONFIG_KEYBOARD_GOLDFISH_EVENTS=y
"

hibernate_desc="Enable hibernation (aka suspend-to-disk)"
hibernate_config="
CONFIG_HIBERNATION=y
"

highmem_desc="highmem"
highmem_config="
CONFIG_HIGHMEM64G=y
"

hypervisor_guest_desc="Support running under a hypervisor"
hypervisor_guest_config="
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_KVM_GUEST=y
CONFIG_VIRTIO_VSOCKETS=m
CONFIG_VIRTIO_IOMMU=m
CONFIG_ACPI_VIOT=y
CONFIG_PCI_COIOMMU=y
CONFIG_COIOMMU=y
CONFIG_IOMMU_BOUNCE_BUFFERS=y
"

i2cdev_desc="I2C device interface"
i2cdev_config="
CONFIG_I2C_CHARDEV=y
"

iioservice_desc="Enable IIO service"
iioservice_config="
# CONFIG_IIO_CROS_EC_SENSORS_RING is not set
"

irqsoff_tracer_desc="irqsoff tracer"
irqsoff_tracer_config="
CONFIG_IRQSOFF_TRACER=y
"

iscsi_desc="iSCSI initiator and target drivers"
iscsi_config="
CONFIG_SCSI_LOWLEVEL=y
CONFIG_ISCSI_TCP=m
CONFIG_CONFIGFS_FS=m
CONFIG_TARGET_CORE=m
CONFIG_ISCSI_TARGET=m
CONFIG_TCM_IBLOCK=m
CONFIG_TCM_FILEIO=m
CONFIG_TCM_PSCSI=m
"

kasan_desc="Enable KASAN"
kasan_config="
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_TEST_KASAN=m
CONFIG_FRAME_WARN=0
CONFIG_FORTIFY_SOURCE=n
CONFIG_LOCALVERSION=\"-kasan\"
# CONFIG_KFENCE is not set
"

kcfi_desc="Enable kcfi (for 6.1 and later)"
kcfi_config="
CONFIG_CFI_CLANG=y
"

kcov_desc="Enable kcov"
kcov_config="
CONFIG_KCOV=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
# CONFIG_RANDOMIZE_BASE is not set
"

kcsan_desc="Enable KCSAN"
# KCSAN reports of unknown origin are too frequent and not very useful for now.
kcsan_config="
CONFIG_KCSAN=y
CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n
CONFIG_FRAME_WARN=0
"

kernel_compress_xz_desc="Compresss kernel image with XZ"
kernel_compress_xz_config="
# CONFIG_KERNEL_GZIP is not set
# CONFIG_KERNEL_BZIP2 is not set
# CONFIG_KERNEL_LZMA is not set
# CONFIG_KERNEL_LZO is not set
# CONFIG_KERNEL_LZ4 is not set
CONFIG_KERNEL_XZ=y
"

kexec_file_desc="Enable CONFIG_KEXEC_FILE"
kexec_file_config="
CONFIG_CRASH_CORE=y
CONFIG_KEXEC_CORE=y
# CONFIG_KEXEC is not set
CONFIG_KEXEC_FILE=y
# CONFIG_KEXEC_VERIFY_SIG is not set
"

kgdb_desc="Enable kgdb"
kgdb_config="
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_FRAME_POINTER=y
CONFIG_GDB_SCRIPTS=y
CONFIG_KGDB=y
CONFIG_KGDB_KDB=y
CONFIG_PANIC_TIMEOUT=0
CONFIG_PROC_KCORE=y
# CONFIG_RANDOMIZE_BASE is not set
# CONFIG_WATCHDOG is not set
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=1
"""
# kgdb over serial port depends on CONFIG_HW_CONSOLE which depends on CONFIG_VT
REQUIRED_USE+=" kgdb? ( vtconsole )"

kmemleak_desc="Enable kmemleak"
kmemleak_config="
CONFIG_DEBUG_KMEMLEAK=y
CONFIG_DEBUG_KMEMLEAK_EARLY_LOG_SIZE=16384
CONFIG_DEBUG_KMEMLEAK_TEST=m
"

lockstat_desc="Lock usage statistics"
lockstat_config="
CONFIG_LOCK_STAT=y
"

lockdebug_desc="Additional lock debug settings"
lockdebug_config="
CONFIG_DEBUG_RT_MUTEXES=y
CONFIG_DEBUG_SPINLOCK=y
CONFIG_DEBUG_MUTEXES=y
CONFIG_PROVE_RCU=y
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_LOCALVERSION=\"-lockdep\"
${lockstat_config}
"
lockdebug_config_disable="
# CONFIG_DEBUG_RT_MUTEXES is not set
# CONFIG_DEBUG_SPINLOCK is not set
# CONFIG_DEBUG_MUTEXES is not set
# CONFIG_PROVE_RCU is not set
# CONFIG_PROVE_LOCKING is not set
# CONFIG_DEBUG_ATOMIC_SLEEP is not set
# CONFIG_LOCALVERSION is not set
# CONFIG_LOCK_STAT is not set
"

lpss_uart_desc="Enable Intel LPSS UART serial ports"
lpss_uart_config="
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_DMA=y
CONFIG_SERIAL_8250_DW=y
CONFIG_SERIAL_8250_LPSS=y
"

nfc_desc="Enable NFC support"
nfc_config="
CONFIG_NFC=m
CONFIG_NFC_HCI=m
CONFIG_NFC_LLCP=y
CONFIG_NFC_NCI=m
CONFIG_NFC_PN533=m
CONFIG_NFC_PN544=m
CONFIG_NFC_PN544_I2C=m
CONFIG_NFC_SHDLC=y
"

pageowner_desc="Enable pageowner kernel memory tracking"
pageowner_config="
CONFIG_PAGE_OWNER=y
CONFIG_DEBUG_KERNEL=y
"

pvrdebug_desc="PowerVR Rogue debugging"
pvrdebug_config="
CONFIG_DRM_POWERVR_ROGUE_DEBUG=y
"

tpm_desc="TPM support"
tpm_config="
CONFIG_TCG_TPM=y
CONFIG_TCG_TIS=y
"

vtpm_proxy_desc="vTPM proxy support"
vtpm_proxy_config="
CONFIG_TCG_VTPM_PROXY=y
"

# initramfs compression is done by the chromeos-initramfs package build
# and kernel build can ingest the compressed image as it is.
recovery_ramfs_desc="Initramfs for recovery image"
recovery_ramfs_config='
CONFIG_INITRAMFS_SOURCE="%ROOT%/var/lib/initramfs/recovery_ramfs.cpio"
CONFIG_INITRAMFS_COMPRESSION_NONE=y
'

# TODO(b/251448197): remove CONFIG_SECURITY_CHROMIUMOS=n when the long-term
# solution is landed.
factory_netboot_ramfs_desc="Initramfs for factory netboot installer"
factory_netboot_ramfs_config='
CONFIG_INITRAMFS_SOURCE="%ROOT%/var/lib/initramfs/factory_netboot_ramfs.cpio"
CONFIG_INITRAMFS_COMPRESSION_NONE=y
CONFIG_SECURITY_CHROMIUMOS=n
'

# TODO(b/251448197): remove CONFIG_SECURITY_CHROMIUMOS=n when the long-term
# solution is landed.
factory_shim_ramfs_desc="Initramfs for factory installer shim"
factory_shim_ramfs_config='
CONFIG_INITRAMFS_SOURCE="%ROOT%/var/lib/initramfs/factory_shim_ramfs.cpio"
CONFIG_INITRAMFS_COMPRESSION_NONE=y
CONFIG_SECURITY_CHROMIUMOS=n
'

minios_ramfs_desc="Initramfs for minios image"
minios_ramfs_config='
CONFIG_INITRAMFS_SOURCE="%ROOT%/var/lib/initramfs/minios_ramfs.cpio"
CONFIG_INITRAMFS_COMPRESSION_NONE=y
'

vfat_desc="vfat"
vfat_config="
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_ISO8859_1=y
CONFIG_FAT_FS=y
CONFIG_VFAT_FS=y
"

kvm_desc="KVM"
kvm_config="
CONFIG_HAVE_KVM=y
CONFIG_HAVE_KVM_IRQCHIP=y
CONFIG_HAVE_KVM_EVENTFD=y
CONFIG_KVM_APIC_ARCHITECTURE=y
CONFIG_KVM_MMIO=y
CONFIG_KVM_ASYNC_PF=y
CONFIG_KVM=m
CONFIG_KVM_INTEL=m
# CONFIG_KVM_AMD is not set
# CONFIG_KVM_MMU_AUDIT is not set
CONFIG_VIRTIO=m
CONFIG_VIRTIO_BLK=m
CONFIG_VIRTIO_NET=m
CONFIG_VIRTIO_CONSOLE=m
CONFIG_VIRTIO_RING=m
CONFIG_VIRTIO_PCI=m
CONFIG_VIRTUALIZATION=y
"

kvm_invept_global_desc="Workaround for b/188008861"
kvm_invept_global_config="
CONFIG_KVM_INVEPT_GLOBAL=y
"

kvm_host_desc="Support running virtual machines with KVM"
kvm_host_config="
CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT=y
CONFIG_HAVE_KVM_EVENTFD=y
CONFIG_HAVE_KVM_IRQCHIP=y
CONFIG_HAVE_KVM_IRQFD=y
CONFIG_HAVE_KVM_IRQ_ROUTING=y
CONFIG_HAVE_KVM_MSI=y
CONFIG_KVM=y
# CONFIG_KVM_MMU_AUDIT is not set
# CONFIG_KVM_APIC_ARCHITECTURE is not set
# CONFIG_KVM_ASYNC_PF is not set
CONFIG_KVM_AMD=y
CONFIG_KVM_INTEL=y
CONFIG_KVM_MMIO=y
CONFIG_VSOCKETS=m
CONFIG_VHOST_VSOCK=m
CONFIG_VIRTUALIZATION=y
CONFIG_KVM_ARM_HOST=y
CONFIG_KVM_HETEROGENEOUS_RT=y
"

kvm_nested_desc="Support running nested VMs"
kvm_nested_config="
CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT=y
CONFIG_HAVE_KVM_EVENTFD=y
CONFIG_HAVE_KVM_IRQCHIP=y
CONFIG_HAVE_KVM_IRQFD=y
CONFIG_HAVE_KVM_IRQ_ROUTING=y
CONFIG_HAVE_KVM_MSI=y
CONFIG_KVM=y
# CONFIG_KVM_MMU_AUDIT is not set
# CONFIG_KVM_APIC_ARCHITECTURE is not set
# CONFIG_KVM_ASYNC_PF is not set
CONFIG_KVM_AMD=y
CONFIG_KVM_INTEL=y
CONFIG_KVM_MMIO=y
"

kvm_virt_suspend_time_desc="Support KVM virtual suspend time injection"
kvm_virt_suspend_time_config="
CONFIG_KVM_VIRT_SUSPEND_TIMING=y
"

# TODO(benchan): Remove the 'mbim' use flag and unconditionally enable the
# CDC MBIM driver once Chromium OS fully supports MBIM.
mbim_desc="CDC MBIM driver"
mbim_config="
CONFIG_USB_NET_CDC_MBIM=m
"

memory_debug_desc="Memory debugging"
memory_debug_config="
CONFIG_DEBUG_MEMORY_INIT=y
CONFIG_DEBUG_PAGEALLOC=y
CONFIG_DEBUG_PER_CPU_MAPS=y
CONFIG_DEBUG_STACKOVERFLOW=y
CONFIG_DEBUG_VM=y
CONFIG_DEBUG_VM_PGFLAGS=y
CONFIG_DEBUG_VM_RB=y
CONFIG_DEBUG_VM_VMACACHE=y
CONFIG_DEBUG_VIRTUAL=y
CONFIG_PAGE_OWNER=y
CONFIG_PAGE_POISONING=y
"

module_sign_desc="Enable kernel module signing and signature verification"
module_sign_config='
CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE is not set
CONFIG_MODULE_SIG_ALL=y
# CONFIG_MODULE_SIG_SHA1 is not set
# CONFIG_MODULE_SIG_SHA224 is not set
CONFIG_MODULE_SIG_SHA256=y
# CONFIG_MODULE_SIG_SHA384 is not set
# CONFIG_MODULE_SIG_SHA512 is not set
CONFIG_MODULE_SIG_HASH="sha256"
CONFIG_ASN1=y
CONFIG_CRYPTO_AKCIPHER=y
CONFIG_CRYPTO_RSA=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
# CONFIG_PKCS7_TEST_KEY is not set
# CONFIG_SIGNED_PE_FILE_VERIFICATION is not set
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS="certs/trusted_key.pem"
# CONFIG_SYSTEM_EXTRA_CERTIFICATE is not set
CONFIG_SECONDARY_TRUSTED_KEYRING=y
CONFIG_CLZ_TAB=y
CONFIG_MPILIB=y
CONFIG_OID_REGISTRY=y
'

livepatch_desc="kernel livepatching"
livepatch_config='
CONFIG_LIVEPATCH=y
CONFIG_KALLSYMS_ALL=y
'

lockdown_desc="Enable kernel lockdown module"
lockdown_config='
CONFIG_SECURITY_LOCKDOWN_LSM=y
# CONFIG_SECURITY_LOCKDOWN_LSM_EARLY is not set
CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y
# CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY is not set
# CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY is not set
'

nfs_desc="NFS"
nfs_config="
CONFIG_USB_NET_AX8817X=y
CONFIG_DNOTIFY=y
CONFIG_DNS_RESOLVER=y
CONFIG_LOCKD=y
CONFIG_LOCKD_V4=y
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NFSD=m
CONFIG_NFSD_V3=y
CONFIG_NFSD_V4=y
CONFIG_NFS_COMMON=y
CONFIG_NFS_FS=y
CONFIG_NFS_USE_KERNEL_DNS=y
CONFIG_NFS_V3=y
CONFIG_NFS_V4=y
CONFIG_ROOT_NFS=y
CONFIG_RPCSEC_GSS_KRB5=y
CONFIG_SUNRPC=y
CONFIG_SUNRPC_GSS=y
CONFIG_USB_USBNET=y
CONFIG_IP_PNP=y
CONFIG_IP_PNP_DHCP=y
"

pca954x_desc="PCA954x I2C mux"
pca954x_config="
CONFIG_I2C_MUX_PCA954x=m
"

pcserial_desc="PC serial"
pcserial_config="
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_DW=y
CONFIG_SERIAL_8250_PCI=y
CONFIG_SERIAL_EARLYCON=y
CONFIG_PARPORT=y
CONFIG_PARPORT_PC=y
CONFIG_PARPORT_SERIAL=y
"

pkvm_desc="pKVM support"
pkvm_config="
CONFIG_PKVM_INTEL=y
CONFIG_PKVM_INTEL_DEBUG=y
CONFIG_PCI_PASID=y
CONFIG_IOMMU_DEFAULT_PASSTHROUGH=y
"

plan9_desc="Plan 9 protocol support"
plan9_config="
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
CONFIG_9P_FS_SECURITY=y
"

# NB: CONFIG_PPP must be built-in, because it provides the /dev/ppp alias
# (MODULE_ALIAS_CHARDEV()), which otherwise doesn't play nicely with our udev
# rules to change its permissions. See also: b/166388882 and crbug.com/864474.
ppp_desc="PPPoE and ppp support"
ppp_config="
CONFIG_PPPOE=m
CONFIG_PPP=y
CONFIG_PPP_BSDCOMP=m
CONFIG_PPP_DEFLATE=m
CONFIG_PPP_MPPE=m
CONFIG_PPP_SYNC_TTY=m
"

preempt_tracer_desc="preemption off tracer"
preempt_tracer_config="
CONFIG_PREEMPT_TRACER=y
"

qmi_desc="QMI WWAN driver"
qmi_config="
CONFIG_USB_NET_QMI_WWAN=m
"

realtekpstor_desc="Realtek PCI card reader"
realtekpstor_config="
CONFIG_RTS_PSTOR=m
"

samsung_serial_desc="Samsung serialport"
samsung_serial_config="
CONFIG_SERIAL_SAMSUNG=y
CONFIG_SERIAL_SAMSUNG_CONSOLE=y
"

sched_tracer_desc="scheduling latency tracer"
sched_tracer_config="
CONFIG_SCHED_TRACER=y
"

selinux_develop_desc="SELinux developer mode"
selinux_develop_config="
# CONFIG_SECURITY_SELINUX_PERMISSIVE_DONTAUDIT is not set
"

socketmon_desc="INET socket monitoring interface (for iproute2 ss)"
socketmon_config="
CONFIG_INET_DIAG=y
CONFIG_INET_TCP_DIAG=y
CONFIG_INET_UDP_DIAG=y
"

systemtap_desc="systemtap support"
systemtap_config="
CONFIG_KPROBES=y
CONFIG_DEBUG_INFO=y
"

ubsan_desc="Enable UBSAN"
ubsan_config="
CONFIG_UBSAN=y
CONFIG_UBSAN_SANITIZE_ALL=y
CONFIG_TEST_UBSAN=m
CONFIG_FORTIFY_SOURCE=n
"

usb_gadget_desc="USB gadget support with ConfigFS/FunctionFS"
usb_gadget_config="
CONFIG_USB_CONFIGFS=m
CONFIG_USB_CONFIGFS_F_FS=y
CONFIG_USB_FUNCTIONFS=m
CONFIG_USB_GADGET=y
"

usb_gadget_acm_desc="USB ACM gadget support"
usb_gadget_acm_config="
CONFIG_USB_CONFIGFS_ACM=y
"

usb_gadget_audio_desc="USB Audio gadget support"
usb_gadget_audio_config="
CONFIG_USB_CONFIGFS_F_UAC1=y
CONFIG_USB_CONFIGFS_F_UAC2=y
"

usb_gadget_ncm_desc="USB NCM gadget support"
usb_gadget_ncm_config="
CONFIG_USB_CONFIGFS_NCM=y
"

usbip_desc="Virtual USB support"
usbip_config="
CONFIG_USBIP_CORE=m
CONFIG_USBIP_HOST=m
CONFIG_USBIP_VHCI_HCD=m
"

virtio_balloon_desc="Balloon driver support kvm guests"
virtio_balloon_config="
CONFIG_MEMORY_BALLOON=y
CONFIG_BALLOON_COMPACTION=y
CONFIG_VIRTIO_BALLOON=m
"

vivid_desc="Virtual Video Test Driver"
vivid_config="
CONFIG_MEDIA_TEST_SUPPORT=y
CONFIG_V4L_TEST_DRIVERS=y
CONFIG_VIDEO_VIVID=m
CONFIG_VIDEO_VIVID_MAX_DEVS=64
"

vkms_desc="Virtual KMS (Kernel Mode Setting)"
vkms_config="
CONFIG_DRM_VKMS=m
"

vkms_config_disable="
# CONFIG_DRM_VKMS is not set
"

vlan_desc="802.1Q VLAN"
vlan_config="
CONFIG_VLAN_8021Q=m
"

vmware_guest_desc="Support running under VMware hypervisor"
vmware_guest_config="
CONFIG_VMWARE_BALLOON=y
CONFIG_VMWARE_PVSCSI=y
CONFIG_VMWARE_VMCI=y
CONFIG_VMWARE_VMCI_VSOCKETS=y
CONFIG_VMXNET3=y
"

wifi_testbed_ap_desc="Defer Atheros Wifi EEPROM regulatory"
wifi_testbed_ap_warning="
Don't use the wifi_testbed_ap flag unless you know what you are doing!
An image built with this flag set must never be run outside a
sealed RF chamber!
"
wifi_testbed_ap_config="
CONFIG_ATH_DEFER_EEPROM_REGULATORY=y
CONFIG_BRIDGE=y
CONFIG_MAC80211_BEACON_FOOTER=y
"

wifi_diag_desc="mac80211 WiFi diagnostic support"
wifi_diag_config="
CONFIG_MAC80211_WIFI_DIAG=y
"

x32_desc="x32 ABI support"
x32_config="
CONFIG_X86_X32=y
"

xen_guest_desc="Support running under Xen hypervisor"
xen_guest_config="
CONFIG_XEN=y
CONFIG_XEN_PV=y
CONFIG_XEN_PV_SMP=y
CONFIG_XEN_DOM0=y
CONFIG_XEN_PVHVM=y
CONFIG_XEN_PVHVM_SMP=y
CONFIG_XEN_512GB=y
CONFIG_XEN_SAVE_RESTORE=y
CONFIG_XEN_PVH=y
CONFIG_PCI_XEN=y
CONFIG_XEN_PCIDEV_FRONTEND=y
CONFIG_XEN_BLKDEV_FRONTEND=y
CONFIG_XEN_BLKDEV_BACKEND=m
CONFIG_XEN_SCSI_FRONTEND=m
CONFIG_XEN_NETDEV_FRONTEND=y
CONFIG_XEN_NETDEV_BACKEND=m
CONFIG_INPUT_XEN_KBDDEV_FRONTEND=y
CONFIG_HVC_XEN=y
CONFIG_HVC_XEN_FRONTEND=y
CONFIG_TCG_XEN=m
CONFIG_XEN_DEV_EVTCHN=m
CONFIG_XEN_BACKEND=y
CONFIG_XENFS=m
CONFIG_XEN_COMPAT_XENFS=y
CONFIG_XEN_SYS_HYPERVISOR=y
CONFIG_XEN_XENBUS_FRONTEND=y
CONFIG_XEN_GNTDEV=m
CONFIG_XEN_GRANT_DEV_ALLOC=m
CONFIG_SWIOTLB_XEN=y
CONFIG_XEN_TMEM=m
CONFIG_XEN_PCIDEV_BACKEND=m
CONFIG_XEN_PRIVCMD=m
CONFIG_XEN_HAVE_PVMMU=y
CONFIG_XEN_EFI=y
CONFIG_XEN_AUTO_XLATE=y
CONFIG_XEN_ACPI=y
CONFIG_XEN_HAVE_VPMU=y
"

vtconsole_desc="VT console"
vtconsole_config="
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
"
vtconsole_config_disable="
# CONFIG_VT is not set
# CONFIG_VT_CONSOLE is not set
"

nowerror_desc="Don't build with -Werror (warnings aren't fatal)."
nowerror_config="
# CONFIG_ERROR_ON_WARNING is not set
# CONFIG_WERROR is not set
"

docker_desc="Docker Support (Linux Containers)"
docker_config="
# Generic flag requirements generated from the
# ebuild file.
CONFIG_BLK_CGROUP=y
CONFIG_BLK_DEV_THROTTLING=y
CONFIG_BRIDGE=y
CONFIG_BRIDGE_NETFILTER=y
CONFIG_CFQ_GROUP_IOSCHED=y
CONFIG_CFS_BANDWIDTH=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CGROUP_NET_PRIO=y
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_SCHED=y
CONFIG_CPUSETS=y
CONFIG_CRYPTO=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_GCM=y
CONFIG_CRYPTO_GHASH=y
CONFIG_CRYPTO_SEQIV=y
CONFIG_DUMMY=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_IOSCHED_CFQ=y
CONFIG_IPC_NS=y
CONFIG_IPVLAN=y
CONFIG_IP_NF_FILTER=y
CONFIG_IP_NF_NAT=y
CONFIG_IP_NF_TARGET_MASQUERADE=y
CONFIG_IP_VS=y
CONFIG_IP_VS_NFCT=y
CONFIG_IP_VS_PROTO_TCP=y
CONFIG_IP_VS_PROTO_UDP=y
CONFIG_IP_VS_RR=y
CONFIG_KEYS=y
CONFIG_MACVLAN=y
CONFIG_MEMCG=y
CONFIG_MEMCG_SWAP=y
CONFIG_MEMCG_SWAP_ENABLED=y
CONFIG_NAMESPACES=y
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
CONFIG_NETFILTER_XT_MATCH_IPVS=y
CONFIG_NET_CLS_CGROUP=y
CONFIG_NET_NS=y
CONFIG_NF_NAT=y
CONFIG_NF_NAT_IPV4=y
CONFIG_NF_NAT_NEEDED=y
CONFIG_OVERLAY_FS=y
CONFIG_PID_NS=y
CONFIG_POSIX_MQUEUE=y
CONFIG_RT_GROUP_SCHED=y
CONFIG_SECCOMP=y
CONFIG_USER_NS=y
CONFIG_UTS_NS=y
CONFIG_VETH=y
CONFIG_VXLAN=y
CONFIG_XFRM_ALGO=y
CONFIG_XFRM_USER=y
CONFIG_CGROUP_HUGETLB=y

# These are all required for chromeos
# On advice of yuzhao@, crash in __mod_node_page_state
CONFIG_KSTALED=n
# See crbug.com/1955013
CONFIG_SECURITY_CHROMIUMOS_NO_SYMLINK_MOUNT=n
# See crbug.com/1050405
CONFIG_INIT_STACK_ALL=n
"

lxc_desc="LXC Support (Linux Containers)"
lxc_config="
CONFIG_CGROUP_DEVICE=y
CONFIG_CPUSETS=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_RESOURCE_COUNTERS=y
CONFIG_DEVPTS_MULTIPLE_INSTANCES=y
CONFIG_MACVLAN=y
CONFIG_POSIX_MQUEUE=y
CONFIG_BRIDGE_NETFILTER=y
CONFIG_NETFILTER_XT_TARGET_CHECKSUM=y
CONFIG_NETFILTER_XT_MATCH_COMMENT=y
"

transparent_hugepage_desc="Transparent Hugepage Support"
transparent_hugepage_config="
CONFIG_ARM_LPAE=y
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_TRANSPARENT_HUGEPAGE_MADVISE=y
"

# We blast in all the debug options we can under this use flag so we can catch
# as many kernel bugs as possible in testing. Developers can choose to use
# this option too, but they should expect performance to be degraded, unlike
# the devdebug use flag. Since the kernel binary in gzip may be too large to
# fit into a typical 16MB partition, we also switch to xz compression.
debug_desc="All the debug options to catch kernel bugs in testing configurations"
debug_config="
${debugobjects_config}
${devdebug_config}
${dmadebug_config}
${dyndebug_config}
${kasan_config}
${kernel_compress_xz_config}
${lockdebug_config}
${memory_debug_config}
CONFIG_DEBUG_LIST=y
CONFIG_DEBUG_PREEMPT=y
CONFIG_DEBUG_STACK_USAGE=y
CONFIG_SCHED_STACK_END_CHECK=y
CONFIG_WQ_WATCHDOG=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_HARDENED_USERCOPY_FALLBACK=y
CONFIG_HARDENED_USERCOPY_PAGESPAN=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_DEBUG_PI_LIST=y
CONFIG_REFCOUNT_FULL=y
CONFIG_DEBUG_KOBJECT_RELEASE=y
"

vpu_driver_desc="Driver for Intel VPU"
vpu_driver_config="
CONFIG_DRM_ACCEL_IVPU=m
"

# Firmware binaries selected by USE flags.  Selected firmware binaries will
# be built into the kernel using CONFIG_EXTRA_FIRMWARE.

FIRMWARE_BINARIES=(
	builtin_fw_amdgpu_carrizo
	builtin_fw_amdgpu_gc_10_3_7
	builtin_fw_amdgpu_gc_11_0_1
	builtin_fw_amdgpu_green_sardine
	builtin_fw_amdgpu_picasso
	builtin_fw_amdgpu_raven2
	builtin_fw_amdgpu_renoir
	builtin_fw_amdgpu_stoney
	builtin_fw_amdgpu_yellow_carp
	builtin_fw_guc_adl
	builtin_fw_guc_adl_kernelnext
	builtin_fw_guc_adln
	builtin_fw_guc_g9
	builtin_fw_guc_jsl
	builtin_fw_guc_tgl
	builtin_fw_huc_adl
	builtin_fw_huc_adl_kernelnext
	builtin_fw_huc_adln
	builtin_fw_huc_g9
	builtin_fw_huc_jsl
	builtin_fw_huc_tgl
	builtin_fw_mali_g57
	builtin_fw_t124_xusb
	builtin_fw_t210_bpmp
	builtin_fw_t210_nouveau
	builtin_fw_t210_xusb
	builtin_fw_vega12
	builtin_fw_x86_adl_ucode
	builtin_fw_x86_adln_ucode
	builtin_fw_x86_amd_ucode
	builtin_fw_x86_aml_ucode
	builtin_fw_x86_apl_ucode
	builtin_fw_x86_bdw_ucode
	builtin_fw_x86_bsw_ucode
	builtin_fw_x86_byt_ucode
	builtin_fw_x86_cml_ucode
	builtin_fw_x86_glk_ucode
	builtin_fw_x86_intel_ucode
	builtin_fw_x86_jsl_ucode
	builtin_fw_x86_kbl_ucode
	builtin_fw_x86_mdn_ucode
	builtin_fw_x86_mtl_ucode
	builtin_fw_x86_rpl_ucode
	builtin_fw_x86_skl_ucode
	builtin_fw_x86_tgl_ucode
	builtin_fw_x86_whl_ucode
)

builtin_fw_amdgpu_carrizo_desc="Firmware for AMD Carizzo"
builtin_fw_amdgpu_carrizo_files=(
	amdgpu/carrizo_ce.bin
	amdgpu/carrizo_me.bin
	amdgpu/carrizo_mec.bin
	amdgpu/carrizo_mec2.bin
	amdgpu/carrizo_pfp.bin
	amdgpu/carrizo_rlc.bin
	amdgpu/carrizo_sdma.bin
	amdgpu/carrizo_sdma1.bin
	amdgpu/carrizo_uvd.bin
	amdgpu/carrizo_vce.bin
)

builtin_fw_amdgpu_gc_10_3_7_desc="Firmware for AMD GC 10.3.7"
builtin_fw_amdgpu_gc_10_3_7_files=(
	amdgpu/dcn_3_1_6_dmcub.bin
	amdgpu/gc_10_3_7_ce.bin
	amdgpu/gc_10_3_7_me.bin
	amdgpu/gc_10_3_7_mec2.bin
	amdgpu/gc_10_3_7_mec.bin
	amdgpu/gc_10_3_7_pfp.bin
	amdgpu/gc_10_3_7_rlc.bin
	amdgpu/psp_13_0_8_asd.bin
	amdgpu/psp_13_0_8_ta.bin
	amdgpu/psp_13_0_8_toc.bin
	amdgpu/sdma_5_2_7.bin
	amdgpu/yellow_carp_vcn.bin
)

builtin_fw_amdgpu_gc_11_0_1_desc="Firmware for AMD GC 11.0.1"
builtin_fw_amdgpu_gc_11_0_1_files=(
	amdgpu/dcn_3_1_4_dmcub.bin
	amdgpu/gc_11_0_1_imu.bin
	amdgpu/gc_11_0_1_me.bin
	amdgpu/gc_11_0_1_mec.bin
	amdgpu/gc_11_0_1_mes.bin
	amdgpu/gc_11_0_1_mes1.bin
	amdgpu/gc_11_0_1_pfp.bin
	amdgpu/gc_11_0_1_rlc.bin
	amdgpu/psp_13_0_4_ta.bin
	amdgpu/psp_13_0_4_toc.bin
	amdgpu/sdma_6_0_1.bin
	amdgpu/vcn_4_0_2.bin
)

builtin_fw_amdgpu_green_sardine_desc="Firmware for AMD Green Sardine"
builtin_fw_amdgpu_green_sardine_files=(
	amdgpu/green_sardine_asd.bin
	amdgpu/green_sardine_ce.bin
	amdgpu/green_sardine_dmcub.bin
	amdgpu/green_sardine_me.bin
	amdgpu/green_sardine_mec2.bin
	amdgpu/green_sardine_mec.bin
	amdgpu/green_sardine_pfp.bin
	amdgpu/green_sardine_rlc.bin
	amdgpu/green_sardine_sdma.bin
	amdgpu/green_sardine_ta.bin
	amdgpu/green_sardine_vcn.bin
)

builtin_fw_amdgpu_picasso_desc="Firmware for AMD Picasso"
builtin_fw_amdgpu_picasso_files=(
	amdgpu/picasso_asd.bin
	amdgpu/picasso_ce.bin
	amdgpu/picasso_gpu_info.bin
	amdgpu/picasso_me.bin
	amdgpu/picasso_mec2.bin
	amdgpu/picasso_mec.bin
	amdgpu/picasso_pfp.bin
	amdgpu/picasso_rlc_am4.bin
	amdgpu/picasso_rlc.bin
	amdgpu/picasso_sdma.bin
	amdgpu/picasso_vcn.bin
	amdgpu/picasso_ta.bin
)

builtin_fw_amdgpu_raven2_desc="Firmware for AMD Raven 2"
builtin_fw_amdgpu_raven2_files=(
	amdgpu/raven_dmcu.bin
	amdgpu/raven2_asd.bin
	amdgpu/raven2_ce.bin
	amdgpu/raven2_gpu_info.bin
	amdgpu/raven2_me.bin
	amdgpu/raven2_mec.bin
	amdgpu/raven2_mec2.bin
	amdgpu/raven2_pfp.bin
	amdgpu/raven2_rlc.bin
	amdgpu/raven2_sdma.bin
	amdgpu/raven2_vcn.bin
	amdgpu/raven2_ta.bin
)

builtin_fw_amdgpu_renoir_desc="Firmware for AMD Renoir"
builtin_fw_amdgpu_renoir_files=(
	amdgpu/renoir_asd.bin
	amdgpu/renoir_ce.bin
	amdgpu/renoir_dmcub.bin
	amdgpu/renoir_gpu_info.bin
	amdgpu/renoir_me.bin
	amdgpu/renoir_mec2.bin
	amdgpu/renoir_mec.bin
	amdgpu/renoir_pfp.bin
	amdgpu/renoir_rlc.bin
	amdgpu/renoir_sdma.bin
	amdgpu/renoir_ta.bin
	amdgpu/renoir_vcn.bin
)

builtin_fw_amdgpu_stoney_desc="Firmware for AMD Stoney"
builtin_fw_amdgpu_stoney_files=(
	amdgpu/stoney_ce.bin
	amdgpu/stoney_me.bin
	amdgpu/stoney_mec.bin
	amdgpu/stoney_pfp.bin
	amdgpu/stoney_rlc.bin
	amdgpu/stoney_sdma.bin
	amdgpu/stoney_uvd.bin
	amdgpu/stoney_vce.bin
)

builtin_fw_amdgpu_yellow_carp_desc="Firmware for AMD Yellow Carp"
builtin_fw_amdgpu_yellow_carp_files=(
	amdgpu/yellow_carp_asd.bin
	amdgpu/yellow_carp_ce.bin
	amdgpu/yellow_carp_dmcub.bin
	amdgpu/yellow_carp_me.bin
	amdgpu/yellow_carp_mec2.bin
	amdgpu/yellow_carp_mec.bin
	amdgpu/yellow_carp_pfp.bin
	amdgpu/yellow_carp_rlc.bin
	amdgpu/yellow_carp_sdma.bin
	amdgpu/yellow_carp_ta.bin
	amdgpu/yellow_carp_toc.bin
	amdgpu/yellow_carp_vcn.bin
)

builtin_fw_guc_adl_desc="GuC Firmware for ADL"
builtin_fw_guc_adl_files=(
	i915/tgl_guc_49.0.1.bin
	i915/adlp_guc_62.0.3.bin
	i915/adlp_guc_69.0.3.bin
	i915/adlp_guc_70.1.1.bin
	i915/adlp_guc_70.bin
)

builtin_fw_guc_adl_kernelnext_desc="GuC Firmware for ADL Kernelnext"
builtin_fw_guc_adl_kernelnext_files=(
	i915/adlp_guc_69.0.3.bin
	i915/adlp_guc_70.1.1.bin
	i915/adlp_guc_70.bin
)

builtin_fw_guc_adln_desc="GuC Firmware for ADL-N"
builtin_fw_guc_adln_files=(
	i915/tgl_guc_70.bin
)

builtin_fw_guc_g9_desc="GuC Firmware for Gen9"
builtin_fw_guc_g9_files=(
	i915/kbl_guc_ver9_39.bin
)

builtin_fw_guc_jsl_desc="GuC Firmware for JSL"
builtin_fw_guc_jsl_files=(
	i915/ehl_guc_49.0.1.bin
	i915/ehl_guc_70.1.1.bin
)

builtin_fw_guc_tgl_desc="GuC Firmware for TGL"
builtin_fw_guc_tgl_files=(
	i915/tgl_guc_49.0.1.bin
	i915/tgl_guc_70.1.1.bin
	i915/tgl_guc_70.bin
)

builtin_fw_huc_adl_desc="HuC Firmware for ADL"
builtin_fw_huc_adl_files=(
	i915/tgl_huc_7.9.3.bin
)

builtin_fw_huc_adl_kernelnext_desc="HuC Firmware for ADL Kernelnext"
builtin_fw_huc_adl_kernelnext_files=(
	i915/tgl_huc_7.9.3.bin
)

builtin_fw_huc_adln_desc="HuC Firmware for ADL-N"
builtin_fw_huc_adln_files=(
	i915/tgl_huc_7.9.3.bin
)

builtin_fw_huc_g9_desc="HuC Firmware for Gen9"
builtin_fw_huc_g9_files=(
	i915/kbl_huc_ver02_00_1810.bin
)

builtin_fw_huc_jsl_desc="HuC Firmware for JSL"
builtin_fw_huc_jsl_files=(
	i915/ehl_huc_9.0.0.bin
)

builtin_fw_huc_tgl_desc="HuC Firmware for TGL"
builtin_fw_huc_tgl_files=(
	i915/tgl_huc_7.5.0.bin
	i915/tgl_huc_7.9.3.bin
)

builtin_fw_mali_g57_desc="Workaround Firmware for Mali-G57"
builtin_fw_mali_g57_files=(
	valhall-1691526.wa
)

builtin_fw_t124_xusb_desc="Tegra124 XHCI controller"
builtin_fw_t124_xusb_files=(
	nvidia/tegra124/xusb.bin
)

builtin_fw_t210_bpmp_desc="Tegra210 BPMP"
builtin_fw_t210_bpmp_files=(
	nvidia/tegra210/bpmp.bin
)

builtin_fw_t210_nouveau_desc="Tegra210 Nouveau GPU"
builtin_fw_t210_nouveau_files=(
	nouveau/acr_ucode.bin
	nouveau/fecs.bin
	nouveau/fecs_sig.bin
	nouveau/gpmu_ucode_desc.bin
	nouveau/gpmu_ucode_image.bin
	nouveau/nv12b_bundle
	nouveau/nv12b_fuc409c
	nouveau/nv12b_fuc409d
	nouveau/nv12b_fuc41ac
	nouveau/nv12b_fuc41ad
	nouveau/nv12b_method
	nouveau/nv12b_sw_ctx
	nouveau/nv12b_sw_nonctx
	nouveau/pmu_bl.bin
	nouveau/pmu_sig.bin
)

builtin_fw_t210_xusb_desc="Tegra210 XHCI controller"
builtin_fw_t210_xusb_files=(
	nvidia/tegra210/xusb.bin
)

builtin_fw_vega12_desc="Firmware for AMD VEGA12"
builtin_fw_vega12_files=(
	amdgpu/vega12_asd.bin
	amdgpu/vega12_ce.bin
	amdgpu/vega12_gpu_info.bin
	amdgpu/vega12_me.bin
	amdgpu/vega12_mec2.bin
	amdgpu/vega12_mec.bin
	amdgpu/vega12_pfp.bin
	amdgpu/vega12_rlc.bin
	amdgpu/vega12_sdma1.bin
	amdgpu/vega12_sdma.bin
	amdgpu/vega12_smc.bin
	amdgpu/vega12_sos.bin
	amdgpu/vega12_uvd.bin
	amdgpu/vega12_vce.bin
)

builtin_fw_x86_amd_ucode_desc="AMD ucode for all chips"
builtin_fw_x86_amd_ucode_files=(
	amd-ucode/microcode_amd.bin
	amd-ucode/microcode_amd_fam15h.bin
	amd-ucode/microcode_amd_fam16h.bin
	amd-ucode/microcode_amd_fam17h.bin
	amd-ucode/microcode_amd_fam19h.bin
)

builtin_fw_x86_intel_ucode_desc="Intel ucode for all chips"
builtin_fw_x86_intel_ucode_files=(
	intel-ucode/06-03-02
	intel-ucode/06-05-00
	intel-ucode/06-05-01
	intel-ucode/06-05-02
	intel-ucode/06-05-03
	intel-ucode/06-06-00
	intel-ucode/06-06-05
	intel-ucode/06-06-0a
	intel-ucode/06-06-0d
	intel-ucode/06-07-01
	intel-ucode/06-07-02
	intel-ucode/06-07-03
	intel-ucode/06-08-01
	intel-ucode/06-08-03
	intel-ucode/06-08-06
	intel-ucode/06-08-0a
	intel-ucode/06-09-05
	intel-ucode/06-0a-00
	intel-ucode/06-0a-01
	intel-ucode/06-0b-01
	intel-ucode/06-0b-04
	intel-ucode/06-0d-06
	intel-ucode/06-0e-08
	intel-ucode/06-0e-0c
	intel-ucode/06-0f-02
	intel-ucode/06-0f-06
	intel-ucode/06-0f-07
	intel-ucode/06-0f-0a
	intel-ucode/06-0f-0b
	intel-ucode/06-0f-0d
	intel-ucode/06-16-01
	intel-ucode/06-17-06
	intel-ucode/06-17-07
	intel-ucode/06-17-0a
	intel-ucode/06-1a-04
	intel-ucode/06-1a-05
	intel-ucode/06-1c-02
	intel-ucode/06-1c-0a
	intel-ucode/06-1d-01
	intel-ucode/06-1e-05
	intel-ucode/06-25-02
	intel-ucode/06-25-05
	intel-ucode/06-26-01
	intel-ucode/06-2a-07
	intel-ucode/06-2c-02
	intel-ucode/06-2d-06
	intel-ucode/06-2d-07
	intel-ucode/06-2e-06
	intel-ucode/06-2f-02
	intel-ucode/06-37-08
	intel-ucode/06-37-09
	intel-ucode/06-3a-09
	intel-ucode/06-3c-03
	intel-ucode/06-3d-04
	intel-ucode/06-3e-04
	intel-ucode/06-3e-06
	intel-ucode/06-3e-07
	intel-ucode/06-3f-02
	intel-ucode/06-3f-04
	intel-ucode/06-45-01
	intel-ucode/06-46-01
	intel-ucode/06-47-01
	intel-ucode/06-4c-03
	intel-ucode/06-4c-04
	intel-ucode/06-4d-08
	intel-ucode/06-4e-03
	intel-ucode/06-55-03
	intel-ucode/06-55-04
	intel-ucode/06-55-05
	intel-ucode/06-55-06
	intel-ucode/06-55-07
	intel-ucode/06-55-0b
	intel-ucode/06-56-02
	intel-ucode/06-56-03
	intel-ucode/06-56-04
	intel-ucode/06-56-05
	intel-ucode/06-5c-02
	intel-ucode/06-5c-09
	intel-ucode/06-5c-0a
	intel-ucode/06-5e-03
	intel-ucode/06-5f-01
	intel-ucode/06-66-03
	intel-ucode/06-6a-05
	intel-ucode/06-6a-06
	intel-ucode/06-6c-01
	intel-ucode/06-7a-01
	intel-ucode/06-7a-08
	intel-ucode/06-7e-05
	intel-ucode/06-8a-01
	intel-ucode/06-8c-01
	intel-ucode/06-8c-02
	intel-ucode/06-8d-01
	intel-ucode/06-8e-09
	intel-ucode/06-8e-0a
	intel-ucode/06-8e-0b
	intel-ucode/06-8e-0c
	intel-ucode/06-8f-04
	intel-ucode/06-8f-05
	intel-ucode/06-8f-06
	intel-ucode/06-8f-07
	intel-ucode/06-8f-08
	intel-ucode/06-96-01
	intel-ucode/06-97-02
	intel-ucode/06-97-05
	intel-ucode/06-9a-03
	intel-ucode/06-9a-04
	intel-ucode/06-9c-00
	intel-ucode/06-9e-09
	intel-ucode/06-9e-0a
	intel-ucode/06-9e-0b
	intel-ucode/06-9e-0c
	intel-ucode/06-9e-0d
	intel-ucode/06-a5-02
	intel-ucode/06-a5-03
	intel-ucode/06-a5-05
	intel-ucode/06-a6-00
	intel-ucode/06-a6-01
	intel-ucode/06-a7-01
	intel-ucode/06-b7-01
	intel-ucode/06-ba-02
	intel-ucode/06-ba-03
	intel-ucode/06-be-00
	intel-ucode/06-bf-02
	intel-ucode/06-bf-05
	intel-ucode/0f-00-07
	intel-ucode/0f-00-0a
	intel-ucode/0f-01-02
	intel-ucode/0f-02-04
	intel-ucode/0f-02-05
	intel-ucode/0f-02-06
	intel-ucode/0f-02-07
	intel-ucode/0f-02-09
	intel-ucode/0f-03-02
	intel-ucode/0f-03-03
	intel-ucode/0f-03-04
	intel-ucode/0f-04-01
	intel-ucode/0f-04-03
	intel-ucode/0f-04-04
	intel-ucode/0f-04-07
	intel-ucode/0f-04-08
	intel-ucode/0f-04-09
	intel-ucode/0f-04-0a
	intel-ucode/0f-06-02
	intel-ucode/0f-06-04
	intel-ucode/0f-06-05
	intel-ucode/0f-06-08
)

builtin_fw_x86_adl_ucode_desc="Intel ucode for ADL"
builtin_fw_x86_adl_ucode_files=(
	intel-ucode/06-9a-03
	intel-ucode/06-9a-04
)

builtin_fw_x86_adln_ucode_desc="Intel ucode for ADL-N"
builtin_fw_x86_adln_ucode_files=(
	intel-ucode/06-be-00
)

builtin_fw_x86_aml_ucode_desc="Intel ucode for AML"
builtin_fw_x86_aml_ucode_files=(
	intel-ucode/06-8e-09
	intel-ucode/06-8e-0c
)

builtin_fw_x86_apl_ucode_desc="Intel ucode for APL"
builtin_fw_x86_apl_ucode_files=(
	intel-ucode/06-5c-09
)

builtin_fw_x86_bdw_ucode_desc="Intel ucode for BDW"
builtin_fw_x86_bdw_ucode_files=(
	intel-ucode/06-3d-04
)

builtin_fw_x86_bsw_ucode_desc="Intel ucode for BSW"
builtin_fw_x86_bsw_ucode_files=(
	intel-ucode/06-4c-03
	intel-ucode/06-4c-04
)

builtin_fw_x86_byt_ucode_desc="Intel ucode for BYT"
builtin_fw_x86_byt_ucode_files=(
	intel-ucode/06-37-08
)

builtin_fw_x86_cml_ucode_desc="Intel ucode for CML"
builtin_fw_x86_cml_ucode_files=(
	intel-ucode/06-8e-0c
	intel-ucode/06-9e-0d
	intel-ucode/06-a6-00
)

builtin_fw_x86_glk_ucode_desc="Intel ucode for GLK"
builtin_fw_x86_glk_ucode_files=(
	intel-ucode/06-7a-01
	intel-ucode/06-7a-08
)

builtin_fw_x86_jsl_ucode_desc="Intel ucode for JSL"
builtin_fw_x86_jsl_ucode_files=(
	intel-ucode/06-9c-00
)

builtin_fw_x86_kbl_ucode_desc="Intel ucode for KBL"
builtin_fw_x86_kbl_ucode_files=(
	intel-ucode/06-8e-09
	intel-ucode/06-8e-0a
)

builtin_fw_x86_mdn_ucode_desc="AMD ucode for Mendocino"
builtin_fw_x86_mdn_ucode_files=(
	amd-ucode/microcode_amd_fam17h.bin
)

builtin_fw_x86_mtl_ucode_desc="Intel ucode for MTL"
builtin_fw_x86_mtl_ucode_files=(
	intel-ucode/06-aa-01
	intel-ucode/06-aa-02
)

builtin_fw_x86_rpl_ucode_desc="Intel ucode for RPL"
builtin_fw_x86_rpl_ucode_files=(
	intel-ucode/06-ba-02
	intel-ucode/06-ba-03
)

builtin_fw_x86_skl_ucode_desc="Intel ucode for SKL"
builtin_fw_x86_skl_ucode_files=(
	intel-ucode/06-4e-03
)

builtin_fw_x86_tgl_ucode_desc="Intel ucode for TGL"
builtin_fw_x86_tgl_ucode_files=(
	intel-ucode/06-8c-00
	intel-ucode/06-8c-01
)

builtin_fw_x86_whl_ucode_desc="Intel ucode for WHL"
builtin_fw_x86_whl_ucode_files=(
	intel-ucode/06-8e-0b
	intel-ucode/06-8e-0c
)

extra_fw_config="
CONFIG_EXTRA_FIRMWARE=\"%FW%\"
CONFIG_EXTRA_FIRMWARE_DIR=\"%ROOT%/lib/firmware\"
"

# Add all config and firmware fragments as off by default
IUSE="${IUSE} ${CONFIG_FRAGMENTS[*]} ${FIRMWARE_BINARIES[*]}"
REQUIRED_USE+="
	?? (
		factory_netboot_ramfs
		factory_shim_ramfs
		minios_ramfs
		recovery_ramfs
	)
	factory_netboot_ramfs? ( i2cdev )
	factory_shim_ramfs? ( i2cdev )
	recovery_ramfs? ( i2cdev )
	factory_netboot_ramfs? ( || ( tpm tpm2 ) )
	factory_shim_ramfs? ( || ( tpm tpm2 ) )
	recovery_ramfs? ( || ( tpm tpm2 ) )
"

# Get the CHROMEOS_KERNEL_FAMILY from the use flags(chromeos_kernel_family_*).
_get_kernel_family() {
	local i
	for i in "${!CHROMEOS_KERNEL_FAMILY_FLAGS[@]}"; do
		if use "${CHROMEOS_KERNEL_FAMILY_FLAGS[${i}]}"; then
			echo "${CHROMEOS_KERNEL_FAMILY_VALUES[${i}]}"
			return
		fi
	done

	die "chromeos kernel family use flag not defined!"
}

# If an overlay has eclass overrides, but doesn't actually override this
# eclass, we'll have ECLASSDIR pointing to the active overlay's
# eclass/ dir, but this eclass is still in the main chromiumos tree.  So
# add a check to locate the cros-kernel/ regardless of what's going on.
ECLASSDIR_LOCAL=${BASH_SOURCE[0]%/*}
eclass_dir() {
	# shellcheck disable=SC2154
	local d="${ECLASSDIR}/cros-kernel"
	if [[ ! -d ${d} ]] ; then
		d="${ECLASSDIR_LOCAL}/cros-kernel"
	fi
	echo "${d}"
}

# @FUNCTION: kernelrelease
# @DESCRIPTION:
# Returns the current compiled kernel version.
# Note: Only valid after src_configure has finished running.
kernelrelease() {
	# Try to fastpath figure out the kernel release since calling
	# kmake is slow.  The idea here is that if we happen to be
	# running this function at the end of the install phase then
	# there will be a binary that was created with the kernel
	# version as a suffix.  We can look at that to figure out the
	# version.
	#
	# NOTE: it's safe to always call this function because ${D}
	# isn't something that is kept between incremental builds, IOW
	# it's not like $(cros-workon_get_build_dir).  That means that
	# if ${D}/boot/vmlinuz-* exists it must be the right one.

	local kernel_bins=("${D}"/boot/vmlinuz-*)
	local version

	if [[ ${#kernel_bins[@]} -eq 1 ]]; then
		version="${kernel_bins[0]##${D}/boot/vmlinuz-}"
	fi
	if [[ -z "${version}" || "${version}" == '*' ]]; then
		version="$(kmake -s --no-print-directory kernelrelease)"
	fi

	echo "${version}"
}

# @FUNCTION: cc_option
# @DESCRIPTION:
# Return 0 if ${CC} supports all provided options, 1 otherwise.
# test-flags-CC tests each flag individually and returns the
# supported flags, which is not what we need here.
cc_option() {
	local t="$(test-flags-CC "$@")"
	[[ "${t}" == "$*" ]]
}

# @FUNCTION: install_kernel_sources
# @DESCRIPTION:
# Installs the kernel sources into ${D}/usr/src/${P} and fixes symlinks.
# The package must have already installed a directory under ${D}/lib/modules.
install_kernel_sources() {
	local version=$(kernelrelease)
	local dest_modules_dir=lib/modules/${version}
	local dest_source_dir=usr/src/${P}
	local dest_build_dir=${dest_source_dir}/build

	# Fix symlinks in lib/modules
	ln -sfvT "../../../${dest_build_dir}" \
	   "${D}/${dest_modules_dir}/build" || die
	ln -sfvT "../../../${dest_source_dir}" \
	   "${D}/${dest_modules_dir}/source" || die

	einfo "Installing kernel source tree"
	dodir "${dest_source_dir}"
	local f
	for f in "${S}"/*; do
		[[ "${f}" == "${S}/build" ]] && continue
		cp -pPR "${f}" "${D}/${dest_source_dir}" ||
			die "Failed to copy kernel source tree"
	done

	dosym "${P}" "/usr/src/linux"

	einfo "Installing kernel build tree"
	dodir "${dest_build_dir}"
	cp -pPR "$(cros-workon_get_build_dir)"/. "${D}/${dest_build_dir}" || die

	# Modify Makefile to use the ROOT environment variable if defined.
	# This path needs to be absolute so that the build directory will
	# still work if copied elsewhere.
	sed -i -e "s@${S}@\$(ROOT)/${dest_source_dir}@" \
		"${D}/${dest_build_dir}/Makefile" || die
}

get_build_cfg() {
	echo "$(cros-workon_get_build_dir)/.config"
}

# Get architecture to be used for
# - "<arch>_defconfig" if there is no splitconfig
# - "chromiumos-<arch>" if CHROMEOS_KERNEL_SPLITCONFIG is not defined
get_build_arch() {
	if [[ "${ARCH}" == "arm"  ||  "${ARCH}" == "arm64" ]]; then
		# shellcheck disable=SC2154
		case "${CHROMEOS_KERNEL_SPLITCONFIG}" in
			*exynos*)
				echo "exynos5"
				;;
			*mediatek*)
				echo "mediatek"
				;;
			*qualcomm*)
				echo "qualcomm"
				;;
			*rockchip64*)
				echo "rockchip64"
				;;
			*rockchip*)
				echo "rockchip"
				;;
			*tegra*)
				echo "tegra"
				;;
			*)
				echo "${ARCH}"
				;;
		esac
	elif [[ "${ARCH}" == "x86" ]]; then
		case "${CHROMEOS_KERNEL_SPLITCONFIG}" in
			*i386*)
				echo "i386"
				;;
			*x86_64*)
				echo "x86_64"
				;;
			*)
				echo "x86"
				;;
		esac
	elif [[ "${ARCH}" == "amd64" ]]; then
		echo "x86_64"
	elif [[ "${ARCH}" == "mips" ]]; then
		case "${CHROMEOS_KERNEL_SPLITCONFIG}" in
			*pistachio*)
				echo "pistachio"
				;;
			*)
				echo "maltasmvp"
				;;
		esac
	else
		tc-arch-kernel
	fi
}

# @FUNCTION: cros_chkconfig_present
# @USAGE: <option to check config for>
# @DESCRIPTION:
# Returns success of the provided option is present in the build config.
cros_chkconfig_present() {
	local config=$1
	grep -q "^CONFIG_$1=[ym]$" "$(get_build_cfg)"
}

cros-kernel2_pkg_setup() {
	cros-workon_pkg_setup
}

# @FUNCTION: _cros-kernel2_get_fit_compression
# @USAGE:
# @DESCRIPTION:
# Returns what compression algorithm the kernel uses in the FIT
# image. Currently only applicable for arm64 since on all other
# kernels we use the zImage which is created/compressed by the kernel
# build itself; returns "none" when not applicable.
_cros-kernel2_get_fit_compression() {
	local kernel_arch=${CHROMEOS_KERNEL_ARCH:-$(tc-arch-kernel)}

	if [[ "${kernel_arch}" != "arm64" ]]; then
		echo none
	elif use fit_compression_kernel_lz4; then
		echo lz4
	elif use fit_compression_kernel_lzma; then
		echo lzma
	else
		echo none
	fi
}

# @FUNCTION: _cros-kernel2_get_fit_kernel_path
# @USAGE:
# @DESCRIPTION:
# Returns the releative path to the (uncompressed) kernel we'll put in the fit
# image.
_cros-kernel2_get_fit_kernel_path() {
	local kernel_arch=${CHROMEOS_KERNEL_ARCH:-$(tc-arch-kernel)}

	case ${kernel_arch} in
		arm64)
			echo "arch/${kernel_arch}/boot/Image"
			;;
		mips)
			echo "vmlinuz.bin"
			;;
		*)
			echo "arch/${kernel_arch}/boot/zImage"
			;;
	esac
}

# @FUNCTION: _cros-kernel2_get_fit_compressed_kernel_path
# @USAGE:
# @DESCRIPTION:
# Returns the releative path to the compressed kernel we'll put in the fit
# image; if we're using a compression of "none" this will just return the
# path of the uncompressed kernel.
_cros-kernel2_get_compressed_path() {
	local uncompressed_path="$(_cros-kernel2_get_fit_kernel_path)"
	local compression="$(_cros-kernel2_get_fit_compression)"

	if [[ "${compression}" == "none" ]]; then
		echo "${uncompressed_path}"
	else
		echo "${uncompressed_path}.${compression}"
	fi
}

# @FUNCTION: _cros-kernel2_compress_fit_kernel
# @USAGE: <kernel_dir>
# @DESCRIPTION:
# Compresses the kernel with the algorithm selected by current USE flags. If
# no compression algorithm this does nothing.
_cros-kernel2_compress_fit_kernel() {
	local kernel_dir=${1}
	local kernel_path="${kernel_dir}/$(_cros-kernel2_get_fit_kernel_path)"
	local compr_path="${kernel_dir}/$(_cros-kernel2_get_compressed_path)"
	local compression="$(_cros-kernel2_get_fit_compression)"

	case "${compression}" in
		lz4)
			lz4 -20 -z -f "${kernel_path}" "${compr_path}" || die
			;;
		lzma)
			lzma -9 -z -f -k "${kernel_path}" || die
			;;
	esac
}

# @FUNCTION: _cros-kernel2_get_compat
# @USAGE: <dtb file>
# @DESCRIPTION:
# Returns the list of compatible strings extracted from a given .dtb file, in
# the format required to re-insert it in a new property of an its-script.
_cros-kernel2_get_compat() {
	local dtb="$1"
	local result=""
	local s

	for s in $(fdtget "${dtb}" / compatible); do
		result+="\"${s}\","
	done

	printf "%s" "${result%,}"
}

# @FUNCTION: _cros-kernel2_emit_its_script
# @USAGE: <output file> <kernel_dir> <device trees>
# @DESCRIPTION:
# Emits the its script used to build the u-boot fitImage kernel binary
# that contains the kernel as well as device trees used when booting
# it.
_cros-kernel2_emit_its_script() {
	local compat=()
	local kernel_arch=${CHROMEOS_KERNEL_ARCH:-$(tc-arch-kernel)}
	local fit_compression_fdt="none"
	local fit_compression_kernel
	local kernel_bin_path
	local iter=1
	local its_out=${1}
	shift
	local kernel_dir=${1}
	shift

	fit_compression_kernel="$(_cros-kernel2_get_fit_compression)"
	kernel_bin_path="${kernel_dir}/$(_cros-kernel2_get_compressed_path)"

	cat > "${its_out}" <<-EOF || die
	/dts-v1/;

	/ {
		description = "Chrome OS kernel image with one or more FDT blobs";
		#address-cells = <1>;

		images {
			kernel@1 {
				data = /incbin/("${kernel_bin_path}");
				type = "kernel_noload";
				arch = "${kernel_arch}";
				os = "linux";
				compression = "${fit_compression_kernel}";
				load = <0>;
				entry = <0>;
			};
	EOF

	local dtb
	for dtb in "$@" ; do
		compat[${iter}]=$(_cros-kernel2_get_compat "${dtb}")
		if use dt_compression; then
			# Compress all DTBs in parallel (only needed after this function).
			lz4 -20 -z -f "${dtb}" "${dtb}.lz4" || die &
			dtb="${dtb}.lz4"
			fit_compression_fdt="lz4"
		fi
		cat >> "${its_out}" <<-EOF || die
			fdt@${iter} {
				description = "$(basename "${dtb}")";
				data = /incbin/("${dtb}");
				type = "flat_dt";
				arch = "${kernel_arch}";
				compression = "${fit_compression_fdt}";
				hash@1 {
					algo = "sha1";
				};
			};
		EOF
		((++iter))
	done

	cat <<-EOF >>"${its_out}"
		};
		configurations {
	EOF

	local i
	for i in $(seq 1 $((iter-1))) ; do
		cat >> "${its_out}" <<-EOF || die
			conf@${i} {
				kernel = "kernel@1";
				fdt = "fdt@${i}";
				compatible = ${compat[${i}]};
			};
		EOF
	done

	echo "	};" >> "${its_out}"
	echo "};" >> "${its_out}"

	# Wait for DTB compression to finish.
	wait
}

kmake() {
	# Allow override of kernel arch.
	local kernel_arch=${CHROMEOS_KERNEL_ARCH:-$(tc-arch-kernel)}

	# Support 64bit kernels w/32bit userlands.
	local cross=${CHOST}
	local cross_compat
	local CC_COMPAT
	local LD_COMPAT
	case ${ARCH}:${kernel_arch} in
		x86:x86_64)
			cross="x86_64-cros-linux-gnu"
			;;
		arm:arm64)
			cross="aarch64-cros-linux-gnu"
			;;
	esac

	# Support generating 32-bit VDSO on arm64 kernels
	if use vdso32 && [[ "${kernel_arch}" == "arm64" ]]; then
		cross_compat="armv7a-cros-linux-gnueabihf-"
		CC_COMPAT="armv7a-cros-linux-gnueabihf-clang"
		LD_COMPAT="ld.lld"
	fi

	# Assemble with LLVM's integrated assembler on x86_64 and aarch64
	if use llvm_ias; then
		export LLVM_IAS=1
	fi

	if [[ "${CHOST}" != "${cross}" ]]; then
		unset CC CXX LD STRIP OBJCOPY NM AR
	fi

	tc-export_build_env BUILD_{CC,CXX,LD,PKG_CONFIG}
	CHOST=${cross} tc-export CC CXX LD STRIP OBJCOPY NM AR
	if use clang; then
		STRIP=llvm-strip
		OBJCOPY=llvm-objcopy
		NM=llvm-nm
		AR=llvm-ar
		CHOST=${cross} clang-setup-env
	fi
	# Use ld.lld instead of ${cross}-ld.lld, ${cross}-ld.lld has userspace
	# specific options. Linux kernel already specifies the type by "-m <type>".
	# It also matches upstream (https://github.com/ClangBuiltLinux) and
	# Android usage.
	local linker=$(usex lld "ld.lld" "${cross}-ld.bfd")

	# Linux kernel can't be built with gold linker. Explicitly use bfd linker
	# when invoked through compiler and LLD is not used.
	local linker_arg=""
	if ! use lld; then
		linker_arg="-fuse-ld=bfd"
	fi

	# BUILD_CC, BUILD_CXX come from an eclass that shellcheck won't see.
	# shellcheck disable=SC2154
	set -- \
		LD="${linker}" \
		LD_COMPAT="${LD_COMPAT}" \
		OBJCOPY="${OBJCOPY}" \
		REAL_STRIP="${STRIP}" \
		STRIP="${STRIP}" \
		NM="${NM}" \
		AR="${AR}" \
		CC="${CC} ${linker_arg}" \
		CC_COMPAT="${CC_COMPAT}" \
		CXX="${CXX} ${linker_arg}" \
		HOSTCC="${BUILD_CC}" \
		HOSTCXX="${BUILD_CXX}" \
		HOSTPKG_CONFIG="${BUILD_PKG_CONFIG}" \
		HOSTLD="${BUILD_LD}" \
		CLANG_CROSS_FLAGS="--target=${cross}" \
		"$@"

	# The kernel Makefile allows this optionally set from the environment,
	# so we do too.
	# shellcheck disable=SC2154,SC2153
	local kcflags="${KCFLAGS}"
	local afdo_filename afdo_option
	if use clang; then
		afdo_filename="${WORKDIR}/${AFDO_GCOV_EXTBINARY}"
		afdo_option="profile-sample-use"
	else
		afdo_filename="${WORKDIR}/${AFDO_GCOV}"
		afdo_option="auto-profile"
	fi
	use kernel_afdo && kcflags+=" -f${afdo_option}=${afdo_filename}"

	local indirect_branch_options_v1=(
		"-mindirect-branch=thunk"
		"-mindirect-branch-loop=pause"
		"-fno-jump-tables"
	)
	local indirect_branch_options_v2=(
		"-mindirect-branch=thunk"
		"-mindirect-branch-register"
	)

	# Indirect branch options only available for Intel GCC and clang.
	if use x86 || use amd64; then
		# The kernel will set required compiler options if it supports
		# the RETPOLINE configuration option and it is enabled.
		# Otherwise set supported compiler options here to get a basic
		# level of protection.
		if ! cros_chkconfig_present RETPOLINE; then
			if use clang; then
				kcflags+=" $(test-flags-CC -mretpoline)"
			else
				if cc_option "${indirect_branch_options_v1[@]}"; then
					kcflags+=" ${indirect_branch_options_v1[*]}"
				elif cc_option "${indirect_branch_options_v2[@]}"; then
					kcflags+=" ${indirect_branch_options_v2[*]}"
				fi
			fi
		fi
	fi

	# LLVM needs this to parse perf.data.
	# See AutoFDO README for details: https://github.com/google/autofdo
	use clang && kcflags+=" -fdebug-info-for-profiling "

	# The kernel doesn't use CFLAGS and doesn't expect it to be passed
	# in.  Let's be explicit that it won't do anything by unsetting CFLAGS.
	#
	# In general the kernel manages its own tools flags and doesn't expect
	# someone external to pass flags in unless those flags have been
	# very specifically tailored to interact well with the kernel Makefiles.
	# In that case we pass in flags with KCFLAGS which is documented to be
	# not a full set of flags but as "additional" flags. In general the
	# kernel Makefiles carefully adjust their flags in various
	# sub-directories to get the needed result.  The kernel has CONFIG_
	# options for adjusting compiler flags and self-adjusts itself
	# depending on whether it detects clang or not.
	#
	# In the same spirit, let's also unset LDFLAGS.  While (in some cases)
	# the kernel will build upon LDFLAGS passed in from the environment it
	# makes sense to just let the kernel be like we do for the rest of the
	# flags.
	unset CFLAGS
	unset LDFLAGS

	local kernel_warning_level=""
	if use kernel_warning_level_1; then
		kernel_warning_level+=1
	fi
	if use kernel_warning_level_2; then
		kernel_warning_level+=2
	fi
	if use kernel_warning_level_3; then
		kernel_warning_level+=3
	fi
	if [[ -n "${kernel_warning_level}" ]]; then
		kernel_warning_level="W=${kernel_warning_level}"
	fi

	local sparse=""
	if use sparse; then
		sparse="C=1"
	fi

	ARCH=${kernel_arch} \
		CROSS_COMPILE="${cross}-" \
		CROSS_COMPILE_COMPAT="${cross_compat}" \
		KCFLAGS="${kcflags}" \
		emake \
		V="${VERBOSE:-0}" \
		O="$(cros-workon_get_build_dir)" \
		${kernel_warning_level} \
		${sparse} \
		"$@"
}

cros-kernel2_src_unpack() {
	# Force in-tree builds if private patches may have to be applied.
	if [[ "${PV}" != "9999" ]] || use apply_patches; then
		CROS_WORKON_OUTOFTREE_BUILD=0
	fi

	cros-workon_src_unpack
	if use kern_arm_afdo; then
		# Use the Arm profile version.
		AFDO_VERSION="${ARM_AFDO_VERSION}"
		AFDO_GCOV="${ARM_AFDO_GCOV}"
		AFDO_GCOV_EXTBINARY="${ARM_AFDO_GCOV_EXTBINARY}"
	fi
	if use kernel_afdo && [[ -z "${AFDO_VERSION}" ]]; then
		if use kern_arm_afdo; then
			PROF_VER="ARM_AFDO_PROFILE_VERSION"
			AFDO_FLAG="kern_arm_afdo"
		else
			PROF_VER="AFDO_PROFILE_VERSION"
			AFDO_FLAG="kernel_afdo"
		fi
		eerror "${PROF_VER} is required in .ebuild by ${AFDO_FLAG}."
		die
	fi

	pushd "${WORKDIR}" >/dev/null || die
	if use kernel_afdo; then
		unpack "${AFDO_GCOV}.xz"

		# Compressed binary profiles are lazily loaded, so they save a
		# meaningful amount of CPU and memory per clang invocation. They're
		# only available with clang.
		if use clang; then
			llvm-profdata merge \
				-sample \
				--extbinary \
				-output="${AFDO_GCOV_EXTBINARY}" \
				"${AFDO_GCOV}" || die
		fi
	fi
	popd >/dev/null || die
}

cros-kernel2_src_prepare() {
	if [[ "${PV}" != "9999" ]] || use apply_patches; then
		apply_private_patches
	fi
	if ! use clang; then
		if use frozen_gcc; then
			cros_use_frozen_gcc
		else
			cros_use_gcc
		fi
	fi

	# Allow use of GNU tools for configs not using llvm tools.
	if ! use lld || ! use llvm_ias; then
		cros_allow_gnu_build_tools
	fi

	if [[ ${CROS_WORKON_INCREMENTAL_BUILD} != "1" ]]; then
		mkdir -p "$(cros-workon_get_build_dir)"
	fi

	default
}

cros-kernel2_src_configure() {
	# The kernel controls its own optimization settings, so this would be a nop
	# if we were to run it. Leave it here anyway as a grep-friendly marker.
	# cros_optimize_package_for_speed

	# Use a single or split kernel config as specified in the board or variant
	# make.conf overlay. Default to the arch specific split config if an
	# overlay or variant does not set either CHROMEOS_KERNEL_CONFIG or
	# CHROMEOS_KERNEL_SPLITCONFIG. CHROMEOS_KERNEL_CONFIG is set relative
	# to the root of the kernel source tree.
	local config
	local cfgarch="$(get_build_arch)"
	local build_cfg="$(get_build_cfg)"

	if use frozen_gcc; then
		unset LD_PRELOAD
		export SANDBOX_ON=0
	fi

	if use buildtest; then
		local kernel_arch=${CHROMEOS_KERNEL_ARCH:-$(tc-arch-kernel)}
		kmake allmodconfig
		case ${kernel_arch} in
			arm)
				# Big endian builds fail with endianness mismatch errors.
				# See crbug.com/772028 for details.
				sed -i -e 's/CONFIG_CPU_BIG_ENDIAN=y/# CONFIG_CPU_BIG_ENDIAN is not set/' "${build_cfg}"
				;;
		esac
		# Disable CONFIG_FORTIFY_SOURCE for buildtest.  See b/265129193.
		sed -i -e 's/CONFIG_FORTIFY_SOURCE=y/# CONFIG_FORTIFY_SOURCE is not set/' "${build_cfg}"
		kmake olddefconfig
		return 0
	fi

	if [ -n "${CHROMEOS_KERNEL_CONFIG}" ]; then
		case ${CHROMEOS_KERNEL_CONFIG} in
			/*)
				config="${CHROMEOS_KERNEL_CONFIG}"
				;;
			*)
				config="${S}/${CHROMEOS_KERNEL_CONFIG}"
				;;
		esac
	else
		config=${CHROMEOS_KERNEL_SPLITCONFIG:-"chromiumos-${cfgarch}"}
	fi

	elog "Using kernel config: ${config}"

	if [ -n "${CHROMEOS_KERNEL_CONFIG}" ]; then
		cp -f "${config}" "${build_cfg}" || die
	else
		if [ -e chromeos/scripts/prepareconfig ] ; then
			local kernel_family=$(_get_kernel_family)
			einfo "Using family: ${kernel_family}"
			CHROMEOS_KERNEL_FAMILY="${kernel_family}" chromeos/scripts/prepareconfig \
				"${config}" "${build_cfg}" || die
		else
			config="$(eclass_dir)/${cfgarch}_defconfig"
			ewarn "Can't prepareconfig, falling back to default " \
				"${config}"
			cp "${config}" "${build_cfg}" || die
			# Allow usage of GNU binutils in this case. It mostly happens in a
			# developer local build where they are using the ebuild to build
			# kernel with any upstream kernel hash.
			cros_allow_gnu_build_tools
		fi
	fi

	if ! use disable_kernel_fragments; then
		local fragment
		for fragment in "${CONFIG_FRAGMENTS[@]}"; do
			local config="${fragment}_config"
			local status

			if [[ ${!config+set} != "set" ]]; then
				die "'${fragment}' listed in CONFIG_FRAGMENTS, but ${config} is not set up"
			fi

			if use "${fragment}"; then
				status="enabling"
			else
				config="${fragment}_config_disable"
				status="disabling"
				if [[ -z "${!config}" ]]; then
					continue
				fi
			fi

			local msg="${fragment}_desc"
			elog "   - ${status} ${!msg} config"
			local warning="${fragment}_warning"
			local warning_msg="${!warning}"
			if [[ -n "${warning_msg}" ]] ; then
				ewarn "${warning_msg}"
			fi

			echo "${!config//%ROOT%/${SYSROOT}}" >> "${build_cfg}" || die
		done
	fi

	local -a builtin_fw
	for fragment in "${FIRMWARE_BINARIES[@]}"; do
		local files="${fragment}_files[@]"

		if [[ ${!files+set} != "set" ]]; then
			die "'${fragment}' listed in FIRMWARE_BINARIES, but ${files} is not set up"
		fi

		if use "${fragment}"; then
			local msg="${fragment}_desc"
			elog "   - Embedding ${!msg} firmware"
			builtin_fw+=( "${!files}" )
		fi
	done

	if [[ ${#builtin_fw[@]} -gt 0 ]]; then
		echo "${extra_fw_config}" | \
			sed -e "s|%ROOT%|${SYSROOT}|g" -e "s|%FW%|${builtin_fw[*]}|g" \
			>> "${build_cfg}" || die
	fi

	# If the old config is unchanged restore it.  This allows us to keep
	# the old timestamp which will avoid regenerating stuff that hasn't
	# actually changed.  Note that we compare against the non-normalized
	# config to avoid an extra call to "kmake olddefconfig" in the common
	# case.
	#
	# If the old config changed, we'll normalize the new one and stash
	# both the non-normalized and normalized versions for next time.

	local old_config="$(cros-workon_get_build_dir)/cros-old-config"
	local old_defconfig="$(cros-workon_get_build_dir)/cros-old-defconfig"
	local old_hash="$(cros-workon_get_build_dir)/cros-old-hash"

	if [[ -e "${old_config}" && -e "${old_defconfig}" && \
		-e "${old_hash}" && \
		"$(git rev-parse HEAD 2>/dev/null)" == $(<"${old_hash}") ]] && \
		cmp -s "${build_cfg}" "${old_config}"; then
		cp -a "${old_defconfig}" "${build_cfg}" || die
	else
		cp -a "${build_cfg}" "${old_config}" || die

		# Use default for options not explicitly set in splitconfig.
		kmake olddefconfig

		cp -a "${build_cfg}" "${old_defconfig}" || die

		# This is not fatal and happens if source is not a git tree
		git rev-parse HEAD >"${old_hash}" 2>/dev/null
	fi
}

# @FUNCTION: get_dtb_name
# @USAGE: <dtb_dir>
# @DESCRIPTION:
# Get the name(s) of the device tree binary file(s) to include.

get_dtb_name() {
	local dtb_dir=${1}
	local dtb_glob="*.dtb"
	local result

	if ! use dt_choose_all && [[ -n "${CHROMEOS_DTBS}" ]]; then
		dtb_glob="${CHROMEOS_DTBS}"
	fi

	# Add sort to stabilize the dtb ordering.
	result="$(find "${dtb_dir}" -name "${dtb_glob}" | LC_COLLATE=C sort)"

	if [[ -z "${result}" ]]; then
		die "Found no dtb files matching glob ${dtb_glob} in ${dtb_dir}"
	fi

	echo "${result}"
}

gen_compilation_database() {
	local build_dir="$(cros-workon_get_build_dir)"
	local src_dir="${build_dir}/source"
	local db_chroot="${build_dir}/compile_commands_chroot.json"
	local script="gen_compile_commands.py"

	# gen_compile_commands.py has been moved into scripts/clang-tools/
	# since v5.9 kernel.
	if [[ -f "${src_dir}/scripts/${script}" ]]; then
		"${src_dir}/scripts/${script}" \
			-d "${build_dir}" -o "${db_chroot}" || die
	elif [[ -f "${src_dir}/scripts/clang-tools/${script}" ]]; then
		"${src_dir}/scripts/clang-tools/${script}" \
			-d "${build_dir}" -o "${db_chroot}" || die
	else
		die "Cannot find ${script}"
	fi

	# Make relative include paths absolute.
	sed -i -e "s:-I\./:-I${build_dir}/:g" "${db_chroot}" || die

	# shellcheck disable=SC2154
	local ext_chroot_path="${EXTERNAL_TRUNK_PATH}/chroot"
	local in_chroot_path="$(readlink -f "${src_dir}")"
	local ext_src_path="${EXTERNAL_TRUNK_PATH}/${in_chroot_path#/mnt/host/source/}"

	# Generate non-chroot version of the DB with the following
	# changes:
	#
	# 1. translate file and directory paths
	# 2. call clang directly instead of using CrOS wrappers
	# 3. use standard clang target triples
	# 4. remove a few compiler options that might not be available
	#    in the potentially older clang version outside the chroot
	#
	sed -E -e "s:/mnt/host/source/:${EXTERNAL_TRUNK_PATH}/:g" \
		-e "s:\"${src_dir}:\"${ext_src_path}:g" \
		-e "s:-I/build/:-I${ext_chroot_path}/build/:g" \
		-e "s:\"/build/:\"${ext_chroot_path}/build/:g" \
		-e "s:-isystem /:-isystem ${ext_chroot_path}/:g" \
		\
		-e "s:[a-z0-9_]+-(cros|pc)-linux-gnu([a-z]*)?-clang:clang:g" \
		\
		-e "s:([a-z0-9_]+)-cros-linux-gnu:\1-linux-gnu:g" \
		\
		-e "s:-fdebug-info-for-profiling::g" \
		-e "s:-mretpoline::g" \
		-e "s:-mretpoline-external-thunk::g" \
		-e "s:-mfentry::g" \
		\
		"${db_chroot}" \
		> "${build_dir}/compile_commands_no_chroot.json" || or die

	echo \
"compile_commands_*.json are compilation databases for the Linux kernel. The
files can be used by tools that support the commonly used JSON compilation
database format.

To use the compilation database with an IDE or other tools outside of the
chroot create a symlink named 'compile_commands.json' in the kernel source
directory (outside of the chroot) to compile_commands_no_chroot.json." \
		> "${build_dir}/compile_commands.txt" || die
}

_cros-kernel2_compile() {
	local build_targets
	local kernel_arch=${CHROMEOS_KERNEL_ARCH:-$(tc-arch-kernel)}
	case ${kernel_arch} in
		arm)
			if use device_tree; then
				build_targets=( "zImage" "dtbs" )
			else
				build_targets=( "uImage" )
			fi
			use boot_dts_device_tree && build_targets+=( "dtbs" )
			;;
		arm64)
			build_targets=(
				"Image" "dtbs"
			)
			;;
		mips)
			build_targets=(
				vmlinuz.bin
			)
			use device_tree && build_targets+=( "dtbs" )
			;;
		*)
			build_targets=(
				all
			)
			;;
	esac

	cros_chkconfig_present MODULES && build_targets+=( "modules" )

	# Some older kernels don't have a scripts_gdb target, so we want this
	# to be an empty array, not an array with an empty string in it.
	# shellcheck disable=SC2207
	use kgdb && build_targets+=( $(sed -nE 's/^(scripts_gdb):.*$/\1/p' Makefile) )

	# If a .dts file is deleted from the source code it won't disappear
	# from the output in the next incremental build.  Nuke all dtbs so we
	# don't include stale files.  We use 'find' to handle old and new
	# locations (see comments in install below).
	local arch_dir="$(cros-workon_get_build_dir)/arch"
	[[ -d "${arch_dir}" ]] && find "${arch_dir}" -name '*.dtb' -delete

	kmake -k "${build_targets[@]}"

	if use compilation_database; then
		gen_compilation_database
	fi
}

cros-kernel2_src_compile() {
	local old_config="$(cros-workon_get_build_dir)/cros-old-config"
	local old_defconfig="$(cros-workon_get_build_dir)/cros-old-defconfig"
	local build_cfg="$(get_build_cfg)"
	# (b/206056057) Disable SANDBOX and LD_PRELOAD for frozen gcc.
	if use frozen_gcc; then
		unset LD_PRELOAD
		export SANDBOX_ON=0
	fi

	# Some users of cros-kernel2 touch the config after
	# cros-kernel2_src_configure finishes.  Detect that and remove
	# the old configs we were saving to speed up the next
	# incremental build.  These users of cros-kernel2 will be
	# slower but they will still work OK.
	if ! cmp -s "${build_cfg}" "${old_defconfig}"; then
		ewarn "Slowing build speed because ebuild touched config."
		rm -f "${old_config}" "${old_defconfig}" || die
	fi

	_cros-kernel2_compile

	# If Kconfig files have changed since we last did a compile then the
	# .config file that we passed in the kernel might not have been in
	# perfect form.  In general we only generate / make defconfig in
	# cros-kernel2_src_configure() if we see that our config changed (we
	# don't detect Kconfig changes).
	#
	# It's _probably_ fine that we just built the kernel like this because
	# the kernel detects this case, falls into a slow path, and then
	# noisily does a defconfig.  However, there is a very small chance that
	# the results here will be unexpected.  Specifically if you're jumping
	# between very different kernels and you're using an underspecified
	# config (like the fallback config), it's possible the results will be
	# wrong.  AKA if you start with the raw config, then make a defconfig
	# with kernel A, then use that defconfig w/ kernel B to generate a new
	# defconfig, you could end up with a different result than if you
	# sent the raw config straight to kernel B.
	#
	# Let's be paranoid and keep things safe.  We'll detect if we got
	# it wrong and in that case compile the kernel a 2nd time.

	# Check if defconfig is different after the kernel build finished.
	if [[ -e "${old_defconfig}" ]] && \
		! cmp -s "${build_cfg}" "${old_defconfig}"; then
		# We'll stash what the kernel came up with as a defconfig.
		cp -a "${build_cfg}" "${old_defconfig}" || die

		# Re-create a new defconfig from the stashed raw config.
		cp -a "${old_config}" "${build_cfg}" || die
		kmake olddefconfig

		# If the newly generated defconfig is different from what
		# the kernel came up with then do a recompile.
		if ! cmp -s "${build_cfg}" "${old_defconfig}"; then
			ewarn "Detected Kconfig change; redo with olddefconfig"

			cp -a "${build_cfg}" "${old_defconfig}" || die
			_cros-kernel2_compile
		fi
	fi
}

# @FUNCTION: cros-kernel2_src_install
# @USAGE: [install_prefix]
# @DESCRIPTION:
# install the kernel to the system at ${D}${install_prefix}.
cros-kernel2_src_install() {
	if use firmware_install; then
		die "The firmware_install USE flag is dead."
	fi

	if use buildtest ; then
		ewarn "Skipping install for buildtest"
		return 0
	fi

	local install_prefix=${1}
	local install_dir="${D}${install_prefix}"

	if use kernel_sources && [[ -n "${install_prefix}" ]]; then
		die "The install_prefix option is not supported with USE kernel_sources flag."
	fi

	dodir "${install_prefix}/boot"
	kmake INSTALL_MOD_PATH="${install_dir}" INSTALL_PATH="${install_dir}/boot" install

	if use device_tree; then
		_cros-kernel2_compress_fit_kernel \
			"$(cros-workon_get_build_dir)" &
	fi

	local version=$(kernelrelease)

	if cros_chkconfig_present MODULES; then
		kmake INSTALL_MOD_PATH="${install_dir}" INSTALL_MOD_STRIP="magic" \
			STRIP="$(eclass_dir)/strip_splitdebug" \
			modules_install
		dostrip -x "${install_prefix}/lib/modules/${version}/kernel/" \
			"${install_prefix}/usr/lib/debug/lib/modules/"
	fi

	local kernel_arch=${CHROMEOS_KERNEL_ARCH:-$(tc-arch-kernel)}
	local kernel_bin="${install_dir}/boot/vmlinuz-${version}"

	# We might have compressed in background; wait for it now.
	wait

	if use arm || use arm64 || use mips; then
		local kernel_dir="$(cros-workon_get_build_dir)"
		local boot_dir="${kernel_dir}/arch/${kernel_arch}/boot"
		local zimage_bin="${install_dir}/boot/zImage-${version}"
		local image_bin="${install_dir}/boot/Image-${version}"
		local dtb_dir="${boot_dir}"

		# Newer kernels (after linux-next 12/3/12) put dtbs in the dts
		# dir.  Use that if we we find no dtbs directly in boot_dir.
		# Note that we try boot_dir first since the newer kernel will
		# actually rm ${boot_dir}/*.dtb so we'll have no stale files.
		if ! ls "${dtb_dir}"/*.dtb &> /dev/null; then
			dtb_dir="${boot_dir}/dts"
		fi

		if use device_tree; then
			local its_script="${kernel_dir}/its_script"
			# get_dtb_name() produces a line-separated list, and we *want* to
			# split on whitespace for _cros-kernel2_emit_its_script(). These
			# are simple filenames, so this should be OK.
			# shellcheck disable=SC2046
			_cros-kernel2_emit_its_script "${its_script}" \
				"${kernel_dir}" $(get_dtb_name "${dtb_dir}")
			mkimage -D "-I dts -O dtb -p 2048" -f "${its_script}" \
				"${kernel_bin}" || die
		elif [[ "${kernel_arch}" == "arm" ]]; then
			cp "${boot_dir}/uImage" "${kernel_bin}" || die
			if use boot_dts_device_tree; then
				# For boards where the device tree .dtb file is stored
				# under /boot/dts, loaded into memory, and then
				# passed on the 'bootm' command line, make sure they're
				# all installed.
				#
				# We install more .dtb files than we need, but it's
				# less work than a hard-coded list that gets out of
				# date.
				#
				# TODO(jrbarnette):  Really, this should use a
				# FIT image, same as other boards.
				insinto "${install_prefix}/boot/dts"
				doins "${dtb_dir}"/*.dtb
			fi
		fi
		case ${kernel_arch} in
			arm)
				cp -a "${boot_dir}/zImage" "${zimage_bin}" || die
				;;
			arm64)
				cp -a "${boot_dir}/Image" "${image_bin}" || die
				;;
		esac
	fi
	if use arm || use arm64 || use mips; then
		pushd "$(dirname "${kernel_bin}")" >/dev/null || die
		case ${kernel_arch} in
			arm)
				ln -sf "$(basename "${zimage_bin}")" zImage || die
				;;
		esac
		popd >/dev/null || die
	fi
	if [ ! -e "${install_dir}/boot/vmlinuz" ]; then
		ln -sf "vmlinuz-${version}" "${install_dir}/boot/vmlinuz" || die
	fi

	# Check the size of kernel image and issue warning when image size is near
	# the limit. For netboot initramfs, we don't care about kernel
	# size limit as the image is downloaded over network.
	local kernel_image_size=$(stat -c '%s' -L "${install_dir}"/boot/vmlinuz)
	einfo "Kernel image size is ${kernel_image_size} bytes."

	# Install uncompressed kernel for debugging purposes.
	insinto "${install_prefix}/usr/lib/debug/boot"
	newins "$(cros-workon_get_build_dir)/vmlinux" vmlinux.debug
	dostrip -x "${install_prefix}/usr/lib/debug/boot/vmlinux.debug" \
		"${install_prefix}/usr/src/"
	# Be nice to scripts expecting vmlinux.
	ln -s vmlinux.debug "${install_dir}/usr/lib/debug/boot/vmlinux" || die

	if use kgdb && [[ -d "$(cros-workon_get_build_dir)/scripts/gdb" ]]; then
		insinto "${install_prefix}/usr/lib/debug/boot/"
		doins "$(readlink -f \
			"$(cros-workon_get_build_dir)/vmlinux-gdb.py")"
		# Match vmlinux symlink to vmlinux.debug.
		ln -s vmlinux-gdb.py \
			"${install_dir}"/usr/lib/debug/boot/vmlinux.debug-gdb.py || die
		mkdir "${install_dir}"/usr/lib/debug/boot/scripts || die
		rsync -rKLp --chmod=a+r \
			--include='*/' --include='*.py' --exclude='*' \
			"$(cros-workon_get_build_dir)/scripts/gdb/" \
			"${install_dir}"/usr/lib/debug/boot/scripts/gdb || die
	fi

	# Also install the vdso shared ELFs for crash reporting.
	# We use slightly funky filenames so as to better integrate with
	# debugging processes (crash reporter/gdb/etc...).  The basename
	# will be the SONAME (what the runtime process sees), but since
	# that is not unique among all inputs, we also install into a dir
	# with the original filename.  e.g. we will install:
	#  /lib/modules/3.8.11/vdso/vdso32-syscall.so/linux-gate.so
	if use x86 || use amd64; then
		local vdso_dir d f soname
		vdso_dir="$(cros-workon_get_build_dir)/arch/x86/vdso"
		if [[ ! -d ${vdso_dir} ]]; then
			# Use new path with newer (>= v4.2-rc1) kernels
			vdso_dir="$(cros-workon_get_build_dir)/arch/x86/entry/vdso"
		fi
		[[ -d ${vdso_dir} ]] || die "could not find x86 vDSO dir"

		# Use the debug versions (.so.dbg) so portage can run splitdebug on them.
		for f in "${vdso_dir}"/vdso*.so.dbg; do
			d="${install_prefix}/lib/modules/${version}/vdso/${f##*/}"

			exeinto "${d}"
			newexe "${f}" "linux-gate.so"

			soname=$(scanelf -qF'%S#f' "${f}")
			dosym "linux-gate.so" "${d}/${soname}"
		done
	elif [[ "${kernel_arch}" == "arm64" ]]; then
		local vdso_dir d f soname
		vdso_dir="$(cros-workon_get_build_dir)/arch/arm64/kernel/vdso"
		[[ -d ${vdso_dir} ]] || die "could not find arm64 vDSO dir"

		# Use the debug versions (.so.dbg) so portage can run splitdebug on them.
		for f in "${vdso_dir}"*/vdso*.so.dbg; do
			d="${install_prefix}/lib/modules/${version}/vdso${f#*vdso}"
			d="${d%/*}"

			exeinto "${d}"
			newexe "${f}" "linux-gate.so"

			soname=$(scanelf -qF'%S#f' "${f}")
			dosym "linux-gate.so" "${d}/${soname}"
		done
	fi

	if use kernel_sources; then
		install_kernel_sources
	else
		dosym "$(cros-workon_get_build_dir)" "${install_prefix}/usr/src/linux"
	fi

	if use compilation_database; then
		insinto "${install_prefix}/build/kernel"
		einfo "Installing kernel compilation databases.
To use the compilation database with an IDE or other tools outside of the
chroot create a symlink named 'compile_commands.json' in the kernel source
directory (outside of the chroot) to compile_commands_no_chroot.json."
		doins "$(cros-workon_get_build_dir)"/compile_commands_*.json
		doins "$(cros-workon_get_build_dir)"/compile_commands.txt
	fi

	if use kernel_afdo_verify; then
		# Deliver the profile we just verified.  The upload artifacts
		# step in the builder will collect the (now verified) AFDO
		# profile from here.
		insinto "${install_prefix}/usr/lib/debug/boot"
		doins "${DISTDIR}/${AFDO_GCOV}.xz"
	fi
}

EXPORT_FUNCTIONS pkg_setup src_unpack src_prepare src_configure src_compile src_install
