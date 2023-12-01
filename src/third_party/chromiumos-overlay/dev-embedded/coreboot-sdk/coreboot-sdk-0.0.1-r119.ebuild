# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="84ad2ff679a5d6dfbaff1ca02b8f00135f083776"
CROS_WORKON_TREE="23b3929c8398195ad452b9eadcab4c5ec2b60041"
CROS_WORKON_PROJECT="chromiumos/third_party/coreboot"
CROS_WORKON_LOCALNAME="coreboot"
CROS_WORKON_SUBTREE="util/crossgcc"

inherit cros-workon flag-o-matic multiprocessing

DESCRIPTION="upstream coreboot's compiler suite"
HOMEPAGE="https://www.coreboot.org"
LICENSE="GPL-3 LGPL-3"
KEYWORDS="*"

# URIs taken from buildgcc -u
# Needs to be synced with changes in the coreboot repo,
# then pruned to the minimum required set (eg. no gdb, python, expat, llvm)
CROSSGCC_URIS="
https://ftpmirror.gnu.org/gmp/gmp-6.2.1.tar.xz
https://ftpmirror.gnu.org/mpfr/mpfr-4.1.0.tar.xz
https://ftpmirror.gnu.org/mpc/mpc-1.2.1.tar.gz
https://ftpmirror.gnu.org/gcc/gcc-11.2.0/gcc-11.2.0.tar.xz
https://ftpmirror.gnu.org/binutils/binutils-2.37.tar.xz
https://acpica.org/sites/acpica/files/acpica-unix2-20220331.tar.gz
"

SRC_URI="
${CROSSGCC_URIS}
http://mirrors.cdn.adacore.com/art/591c6d80c7a447af2deed1d7 -> gnat-gpl-2017-x86_64-linux-bin.tar.gz
"

buildgcc_failed() {
	local arch="$1"

	cat $(ls */.failed | sed "s,\.failed,build.log,")
	die "building the compiler for ${arch} failed"
}

src_prepare() {
	eapply_user

	mkdir util/crossgcc/tarballs
	ln -s "${DISTDIR}"/* util/crossgcc/tarballs/
	unpack gnat-gpl-2017-x86_64-linux-bin.tar.gz
	# buildgcc uses 'cc' to find gnat1 so it needs to find the gnat-gpl
	# compiler under that name
	ln -s gcc gnat-gpl-2017-x86_64-linux-bin/bin/cc
	# Add a gcc patch to make it builds with glibc 2.26.
	cp "${FILESDIR}/${PN}-gcc-ucontext.patch" "${S}/util/crossgcc/patches/gcc-6.3.0_ucontext.patch"
	# Enable default support for RV32IAFC multilib target
	cp "${FILESDIR}/${PN}-rv32iafc.patch" "${S}/util/crossgcc/patches/gcc-11.2.0_rv32iafc.patch"
}

src_compile() {
	# We're bootstrapping with an old compiler whose
	# linker isn't happy about this flag.
	filter-ldflags "-Wl,--icf=all"

	cd util/crossgcc || die "couldn't enter crossgcc tree"

	./buildgcc -d /opt/coreboot-sdk -D "${S}/out" -P iasl -t -j "$(makeopts_jobs)" \
	|| buildgcc_failed "ACPI"

	# To bootstrap the Ada build, an Ada compiler needs to be available. To
	# make sure it interacts well with the C/C++ parts of the compiler,
	# buildgcc asks gcc for the Ada compiler's path using the compiler's
	# -print-prog-name option which only deals with programs from the very
	# same compiler distribution, so make sure we use the right one.
	export PATH="${S}"/gnat-gpl-2017-x86_64-linux-bin/bin:"${PATH}"
	export CC=gcc CXX=g++

	local buildgcc_opts=(-j "$(makeopts_jobs)" -l "c,c++,ada" -t)

	# Build bootstrap compiler to get a reliable compiler base no matter how
	# versions diverged, but keep it separately, since we only need it
	# during this build and not in the chroot.
	./buildgcc -B -d "${S}"/bootstrap "${buildgcc_opts[@]}" \
		|| buildgcc_failed "cros_sdk (bootstrap)"

	export PATH="${S}/bootstrap/bin:${PATH}"

	local architectures=(
		i386-elf
		x86_64-elf
		arm-eabi
		aarch64-elf
		nds32le-elf
		riscv-elf
	)

	local arch
	for arch in "${architectures[@]}"; do
		./buildgcc -d /opt/coreboot-sdk -D "${S}/out" -p "${arch}" \
			"${buildgcc_opts[@]}" \
		|| buildgcc_failed "${arch}"
	done

	rm -f "${S}"/out/opt/coreboot-sdk/lib/lib*.{la,a}
}

src_install() {
	local files

	dodir /opt
	cp -a out/opt/coreboot-sdk "${D}"/opt/coreboot-sdk || die

	readarray -t files < <(find "${D}" -name '*.[ao]' -printf "/%P\n")
	dostrip -x "${files[@]}"
}
