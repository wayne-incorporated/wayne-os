# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Change this version number when any change is made to patches/files under
# edk2 and an auto-revbump is required.
# VERSION=REVBUMP-0.0.3

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/edk2"
CROS_WORKON_LOCALNAME="edk2"

inherit cros-workon coreboot-sdk multiprocessing

DESCRIPTION="EDK II firmware development environment for the UEFI and PI specifications."
HOMEPAGE="https://github.com/tianocore/edk2"

LICENSE="BSD"
KEYWORDS="~*"
IUSE="fwserial"

BDEPEND="dev-embedded/coreboot-sdk:="
RDEPEND=""
DEPEND=""

SRC_URI="https://www.openssl.org/source/openssl-1.1.0e.tar.gz"

PATCHES=(
	"${FILESDIR}/00_BaseTools_Scripts.patch"
	"${FILESDIR}/01_CorebootPayloadPkg_pcinoenum.patch"
	"${FILESDIR}/02_CorebootPayloadPkg_bds.patch"
	"${FILESDIR}/03_Library_EndofDXE.patch"
	"${FILESDIR}/04_CorebootPayloadPkg_addps2.patch"
	"${FILESDIR}/06_CorebootPayloadPkg_keep_cb_table.patch"
	"${FILESDIR}/07_apics.patch"
	"${FILESDIR}/08_nvme.patch"
	"${FILESDIR}/09_nomask_8259.patch"
	"${FILESDIR}/10_eMMC.patch"
	"${FILESDIR}/11_parallel_BaseTools.patch"
	"${FILESDIR}/12_vrt.patch"
	"${FILESDIR}/13_smmstore.patch"
	"${FILESDIR}/14_Basetools_pie.patch"
	"${FILESDIR}/15_SdMMcPciHcDxe_Bayhub.patch"
	"${FILESDIR}/16_SATA_channelcount.patch"
	"${FILESDIR}/17_CorebootModulePkg_noscien.patch"
	"${FILESDIR}/18_BaseTools-LzmaCompress-Fix-possible-uninitialized-va.patch"
	"${FILESDIR}/19_BaseTools-Lzma-Update-LZMA-SDK-version-to-18.05.patch"
	"${FILESDIR}/20_BaseTools-LzmaCompress-Fix-GCC-warning-misleading-in.patch"
)

BUILDTYPE=DEBUG # DEBUG or RELEASE

src_unpack() {
	cros-workon_src_unpack

	unpack "openssl-1.1.0e.tar.gz"
	mv openssl-1.1.0e ${S}/CryptoPkg/Library/OpensslLib/openssl || die "moving openssl into place failed"
}

src_prepare() {
	if ! use fwserial; then
		PATCHES+=("${FILESDIR}/05_CorebootPayloadPkg_noserial.patch")
	fi
	default
}

src_compile() {
	. ./edksetup.sh
	cat /opt/coreboot-sdk/share/edk2config/tools_def.txt \
		>> Conf/tools_def.txt
	( cd BaseTools/Source/C && emake ARCH=X64 )
	export COREBOOT_SDK_PREFIX_arm COREBOOT_SDK_PREFIX_arm64 COREBOOT_SDK_PREFIX_x86_32 COREBOOT_SDK_PREFIX_x86_64
	build -t COREBOOT -a IA32 -a X64 -b ${BUILDTYPE} -n $(makeopts_jobs) \
			-p CorebootPayloadPkg/CorebootPayloadPkgIa32X64.dsc
}

src_install() {
	insinto /firmware/tianocore
	doins "Build/CorebootPayloadPkgX64/${BUILDTYPE}_COREBOOT/FV/UEFIPAYLOAD.fd"
}
