# Copyright 1999-2014 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/sys-devel/gcc/gcc-4.4.3-r3.ebuild,v 1.1 2010/06/19 01:53:09 zorry Exp $

EAPI="7"

PATCH_VER="6"
PATCH_DEV=${PATCH_DEV:-slyfox}

inherit eutils binutils-funcs

DESCRIPTION="The GNU Compiler Collection.  Includes C/C++, java compilers, pie+ssp extensions, Haj Ten Brugge runtime bounds checking. This Compiler is based off of Crosstoolv14."

LICENSE="GPL-3 LGPL-3 libgcc FDL-1.2"
KEYWORDS="*"

RDEPEND=">=sys-libs/zlib-1.1.4
	>=sys-devel/gcc-config-1.6
	virtual/libiconv
	>=dev-libs/gmp-4.3.2
	>=dev-libs/mpc-0.8.1
	>=dev-libs/mpfr-2.4.2
	graphite? (
		>=dev-libs/cloog-0.18.0
		>=dev-libs/isl-0.11.1
	)"
DEPEND="${RDEPEND}
	test? (
		>=dev-util/dejagnu-1.4.4
		>=sys-devel/autogen-5.5.4
	)
	>=sys-apps/texinfo-4.8
	>=sys-devel/bison-1.875"
PDEPEND=">=sys-devel/gcc-config-2.3"
# Go is required for the toolchain wrappers.
BDEPEND="
	dev-lang/go
	${CATEGORY}/binutils
"

RESTRICT="strip"

IUSE="cet gcc_repo gcj git_gcc go graphite gtk hardened hardfp llvm_libgcc mounted_gcc multilib
	nls cxx openmp test tests +thumb upstream_gcc vanilla vtable_verify +wrapper_ccache"

is_crosscompile() { [[ ${CHOST} != "${CTARGET}" ]] ; }

export CTARGET=${CTARGET:-${CHOST}}
if [[ ${CTARGET} = "${CHOST}" ]] ; then
	if [[ ${CATEGORY/cross-} != "${CATEGORY}" ]] ; then
		export CTARGET=${CATEGORY/cross-}
	fi
fi

GCC_PV=${TOOLCHAIN_GCC_PV:-${PV}}
GCC_PVR=${GCC_PV}
[[ ${PR} != "r0" ]] && GCC_PVR=${GCC_PVR}-${PR}

# GCC_RELEASE_VER must always match 'gcc/BASE-VER' value.
# It's an internal representation of gcc version used for:
# - versioned paths on disk
# - 'gcc -dumpversion' output. Must always match <digit>.<digit>.<digit>.
GCC_RELEASE_VER=$(ver_cut 1-3 "${GCC_PV}")

GCC_BRANCH_VER=$(ver_cut 1-2 "${GCC_PV}")

# Ideally this variable should allow for custom gentoo versioning
# of binary and gcc-config names not directly tied to upstream
# versioning. In practive it's hard to untangle from gcc/BASE-VER
# (GCC_RELEASE_VER) value.
GCC_CONFIG_VER=${GCC_RELEASE_VER}

PREFIX=${TOOLCHAIN_PREFIX:-${EPREFIX}/usr}

LIBPATH=${TOOLCHAIN_LIBPATH:-${PREFIX}/lib/gcc/${CTARGET}/${GCC_CONFIG_VER}}
INCLUDEPATH=${TOOLCHAIN_INCLUDEPATH:-${LIBPATH}/include}

if is_crosscompile ; then
	BINPATH=${TOOLCHAIN_BINPATH:-${PREFIX}/${CHOST}/${CTARGET}/gcc-bin/${GCC_CONFIG_VER}}
else
	BINPATH=${TOOLCHAIN_BINPATH:-${PREFIX}/${CTARGET}/gcc-bin/${GCC_CONFIG_VER}}
fi

DATAPATH=${TOOLCHAIN_DATAPATH:-${PREFIX}/share/gcc-data/${CTARGET}/${GCC_CONFIG_VER}}

# Dont install in /usr/include/g++-v3/, but in gcc internal directory.
# We will handle /usr/include/g++-v3/ with gcc-config ...
STDCXX_INCDIR=${TOOLCHAIN_STDCXX_INCDIR:-${LIBPATH}/include/g++-v${GCC_BRANCH_VER/\.*/}}

SLOT="${CTARGET}"

SRC_URI="mirror://gnu/gcc/gcc-${PV}/gcc-${PV}.tar.xz
	https://dev.gentoo.org/~${PATCH_DEV}/distfiles/gcc-${GCC_RELEASE_VER}-patches-${PATCH_VER}.tar.bz2"

PATCHES=(
	"${FILESDIR}/0001-Fix-emutls.c-to-not-leak-pthread-keys.patch"
)

S="${WORKDIR}/gcc-${PV}"
MY_BUILDDIR="${WORKDIR}/build-${CTARGET}"

src_prepare() {
	einfo "Applying Gentoo GCC patches"
	eapply "${WORKDIR}/patch"

	# Apply things from PATCHES and user dirs
	default
}

src_configure() {
	if [[ -f ${MY_BUILDDIR}/Makefile ]]; then
		ewarn "Skipping configure due to existing build output"
		return
	fi

	# We need to enable `cros_allow_gnu_build_tools` because the ./configure
	# script will probe for `${CTARGET}-gcc`. If we have the wrappers then
	# it kills the processes. We could set GCC_FOR_TARGET=/bin/false, but I'm
	# not sure we actually need the hack. In a chroot without gcc installed,
	# then the ./configure will set GCC_FOR_TARGET to `gcc`, but it sets
	# has_gcc_for_target=false so it won't get used.
	cros_allow_gnu_build_tools

	if is_crosscompile; then
		# Cross GCC builds do not like LD being set, it will find correct LD to use.
		# TODO: We might be able to set LD_FOR_TARGET instead.
		unset LD BUILD_LD
	fi

	local gcc_langs="c"
	use cxx && gcc_langs+=",c++"
	use go && gcc_langs+=",go"

	# Set configuration based on path variables
	local confgcc=(
		--prefix="${PREFIX}"
		--bindir="${BINPATH}"
		--datadir="${DATAPATH}"
		--includedir="${INCLUDEPATH}"
		--with-gxx-include-dir="${STDCXX_INCDIR}"
		--mandir="${DATAPATH}/man"
		--infodir="${DATAPATH}/info"
		--with-python-dir="${DATAPATH#${PREFIX}}/python"

		--build="${CBUILD}"
		--host="${CHOST}"
		--target="${CTARGET}"
		--enable-languages="${gcc_langs}"
		--enable-__cxa_atexit
		--disable-canonical-system-headers
		--enable-checking=release
		--enable-linker-build-id
		--enable-wchar

		--with-bugurl='https://bugs.chromium.org'

		$(use_enable go libatomic)
		$(use_enable multilib)
		$(use_enable openmp libgomp)

		# Disable libs we don't care about.
		--disable-libcilkrts
		--disable-libitm
		--disable-libcc1
		--disable-libmudflap
		--disable-libquadmath
		--disable-libssp
		--disable-libsanitizer

		# Enable frame pointer by default for all the boards.
		# originally only enabled for i686 for chromium-os:23321.
		--enable-frame-pointer

		# Allow user to opt into CET. Ideally this should be auto-enabled
		# based on binutils config via the default --enable-cet=auto but it
		# does not alawys work and binutils has its own problems for which it
		# added its own cet use flag, so also add it here to be safe and explicit.
		$(use_enable cet)
	)

	if use vtable_verify; then
		confgcc+=(
			--enable-cxx-flags="-Wl,-L../libsupc++/.libs"
			--enable-vtable-verify
		)
	fi

	# Make PIE (position independent executable) default for Cross-compiler
	# Linux/GNU	builds.
	if [[ "${CTARGET}" == *linux-gnu* ]]; then
		confgcc+=( --enable-default-pie )
	fi

	# Handle target-specific options.
	case ${CTARGET} in
	arm*)	#264534
		local arm_arch="${CTARGET%%-*}"
		# Only do this if arm_arch is armv*
		if [[ ${arm_arch} == armv* ]]; then
			# Convert armv7{a,r,m} to armv7-{a,r,m}
			[[ ${arm_arch} == armv7? ]] && arm_arch=${arm_arch/7/7-}
			# Remove endian ('l' / 'eb')
			[[ ${arm_arch} == *l ]] && arm_arch=${arm_arch%l}
			[[ ${arm_arch} == *eb ]] && arm_arch=${arm_arch%eb}

			confgcc+=(
				--with-arch="${arm_arch}"
				--disable-esp
			)
		fi
		if use hardfp; then
			confgcc+=( --with-float=hard )
			case ${CTARGET} in
				armv6*) confgcc+=( --with-fpu=vfp ) ;;
				armv7a*) confgcc+=( --with-fpu=vfpv3 ) ;;
				armv7m*) confgcc+=( --with-fpu=vfpv2 ) ;;
			esac
		fi
		use thumb && confgcc+=( --with-mode=thumb )
		;;
	i?86*)
		# Hardened is enabled for x86, but disabled for ARM.
		confgcc+=(
			--enable-esp
			--with-arch=atom
			--with-tune=atom
		)
		;;
	x86_64*-gnux32)
		confgcc+=( --with-abi=x32 --with-multilib-list=mx32 )
		;;
	esac

	# Handle ABI-specific options.
	local needed_libc="glibc"
	if [[ "${CTARGET}" == *-eabi || "${CTARGET}" == *-elf ]]; then
		confgcc+=( --with-newlib )
		needed_libc="newlib"
	fi

	if is_crosscompile; then
		confgcc+=( --enable-poison-system-directories )
		if [[ -n ${needed_libc} ]]; then
			if ! has_version "${CATEGORY}/${needed_libc}"; then
				confgcc+=( --disable-shared --disable-threads --without-headers )
			elif has_version "${CATEGORY}/${needed_libc}[crosscompile_opts_headers-only]"; then
				confgcc+=( --disable-shared --with-sysroot=/usr/"${CTARGET}" )
			else
				confgcc+=( --with-sysroot=/usr/"${CTARGET}" )
			fi
		fi
	else
		confgcc+=( --enable-shared --enable-threads=posix )
	fi

	# Finally add the user options (if any).
	confgcc+=( "${EXTRA_ECONF}" )

	# Build in a separate build tree
	mkdir -p "${MY_BUILDDIR}" || die
	cd "${MY_BUILDDIR}" || die

	# and now to do the actual configuration
	addwrite /dev/zero
	echo "Running this:"
	echo "${S}"/configure "${confgcc[@]}"
	"${S}"/configure "${confgcc[@]}" || die
}

src_compile() {
	cd "${MY_BUILDDIR}" || die
	GCC_CFLAGS="$(portageq envvar CFLAGS)"
	TARGET_FLAGS=""
	TARGET_GO_FLAGS=""

	if use hardened ; then
		TARGET_FLAGS="${TARGET_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2"
	fi

	EXTRA_CFLAGS_FOR_TARGET="${TARGET_FLAGS}"
	EXTRA_CXXFLAGS_FOR_TARGET="${TARGET_FLAGS}"

	if use vtable_verify ; then
		EXTRA_CXXFLAGS_FOR_TARGET+=" -fvtable-verify=std"
	fi

	# libgo on arm must be compiled with -marm. Go's panic/recover functionality
	# is broken in thumb mode.
	if [[ ${CTARGET} == arm* ]]; then
		TARGET_GO_FLAGS="${TARGET_GO_FLAGS} -marm"
	fi
	EXTRA_GOCFLAGS_FOR_TARGET="${TARGET_GO_FLAGS}"

	# Do not link libgcc with gold. That is known to fail on internal linker
	# errors. See crosbug.com/16719
	local LD_NON_GOLD=$(get_binutils_path_ld "${CTARGET}")/ld

	emake CFLAGS="${GCC_CFLAGS}" \
		LDFLAGS="-Wl,-O1" \
		STAGE1_CFLAGS="-O2 -pipe" \
		BOOT_CFLAGS="-O2" \
		CFLAGS_FOR_TARGET="$(get_make_var CFLAGS_FOR_TARGET) ${EXTRA_CFLAGS_FOR_TARGET}" \
		CXXFLAGS_FOR_TARGET="$(get_make_var CXXFLAGS_FOR_TARGET) ${EXTRA_CXXFLAGS_FOR_TARGET}" \
		GOCFLAGS_FOR_TARGET="$(get_make_var GOCFLAGS_FOR_TARGET) ${EXTRA_GOCFLAGS_FOR_TARGET}" \
		LD_FOR_TARGET="${LD_NON_GOLD}" \
		all
}

# Logic copied from Gentoo's toolchain.eclass.
toolchain_src_install() {
	# These should be symlinks
	dodir /usr/bin
	cd "${D}${BINPATH}" || die
	for x in cpp gcc g++ c++ gcov g77 gcj gcjh gfortran gccgo ; do
		# For some reason, g77 gets made instead of ${CTARGET}-g77...
		# this should take care of that
		[[ -f ${x} ]] && mv ${x} "${CTARGET}-${x}"

		if [[ -f ${CTARGET}-${x} ]] ; then
			if ! is_crosscompile ; then
				ln -sf "${CTARGET}-${x}" ${x}
				dosym "${BINPATH}/${CTARGET}-${x}" \
					/usr/bin/"${x}-${GCC_CONFIG_VER}"
			fi

			# Create version-ed symlinks
			dosym "${BINPATH}/${CTARGET}-${x}" \
				"/usr/bin/${CTARGET}-${x}-${GCC_CONFIG_VER}"
		fi

		if [[ -f "${CTARGET}-${x}-${GCC_CONFIG_VER}" ]] ; then
			rm -f "${CTARGET}-${x}-${GCC_CONFIG_VER}"
			ln -sf "${CTARGET}-${x}" "${CTARGET}-${x}-${GCC_CONFIG_VER}"
		fi
	done
}

src_install() {
	cd "${MY_BUILDDIR}" || die

	# Don't allow symlinks in private gcc include dir as this can break the build
	find gcc/include*/ -type l -delete

	S="${MY_BUILDDIR}" emake DESTDIR="${D}" install || die

	find "${D}" -name libiberty.a -exec rm -f "{}" \;

	# Punt some tools which are really only useful while building gcc
	find "${ED}" -name install-tools -prune -type d -exec rm -rf "{}" \;
	# Move the libraries to the proper location
	gcc_movelibs

	# Move pretty-printers to gdb datadir to shut ldconfig up
	gcc_move_pretty_printers

	dodir /etc/env.d/gcc
	insinto /etc/env.d/gcc

	local LDPATH=${LIBPATH}
	for SUBDIR in 32 64 ; do
		if [[ -d ${D}/${LDPATH}/${SUBDIR} ]]
		then
			LDPATH="${LDPATH}:${LDPATH}/${SUBDIR}"
		fi
	done

	cat <<-EOF > env.d
LDPATH="${LDPATH}"
MANPATH="${DATAPATH}/man"
INFOPATH="${DATAPATH}/info"
STDCXX_INCDIR="${STDCXX_INCDIR##*/}"
CTARGET=${CTARGET}
GCC_PATH="${BINPATH}"
GCC_VER="${GCC_RELEASE_VER}"
EOF
	newins env.d "$(get_gcc_config_file)"
	cd - || die

	toolchain_src_install

	cd "${D}${BINPATH}" || die

	# For wrapper build argument only, not actually used in gcc wrappers.
	local use_llvm_next=false

	if is_crosscompile ; then
		local sysroot_wrapper_file_prefix
		local sysroot_wrapper_config
		if use hardened
		then
			sysroot_wrapper_file_prefix=sysroot_wrapper.hardened
			sysroot_wrapper_config=cros.hardened
		else
			sysroot_wrapper_file_prefix=sysroot_wrapper
			sysroot_wrapper_config=cros.nonhardened
		fi

		exeinto "${BINPATH}"
		cat "${FILESDIR}/bisect_driver.py" > \
			"${D}${BINPATH}/bisect_driver.py" || die

		# Note: We are always producing both versions, with and without ccache,
		# so we can replace the behavior of the wrapper without rebuilding it.
		# Used e.g. in chromite/scripts/cros_setup_toolchains.py to disable the
		# ccache for simplechrome toolchains.
		local ccache_suffixes=(noccache ccache)
		local ccache_option_values=(false true)
		for ccache_index in {0,1}; do
			local ccache_suffix="${ccache_suffixes[${ccache_index}]}"
			local ccache_option="${ccache_option_values[${ccache_index}]}"
			# Build new golang wrapper
			GO111MODULE=off "${FILESDIR}/compiler_wrapper/build.py" --config="${sysroot_wrapper_config}" \
				--use_ccache="${ccache_option}" \
				--use_llvm_next="${use_llvm_next}" \
				--output_file="${D}${BINPATH}/${sysroot_wrapper_file_prefix}.${ccache_suffix}" || die
		done

		local use_ccache_index
		use_ccache_index="$(usex wrapper_ccache 1 0)"
		local sysroot_wrapper_file="${sysroot_wrapper_file_prefix}.${ccache_suffixes[${use_ccache_index}]}"

		for x in cpp c++ g++ gcc; do
			if [[ -f "${CTARGET}-${x}" ]]; then
				mv "${CTARGET}-${x}" "${CTARGET}-${x}.real"
				dosym "${sysroot_wrapper_file}" "${BINPATH}/${CTARGET}-${x}" || die
			fi
		done
		if use go; then
			local wrapper="sysroot_wrapper.gccgo"
			doexe "${FILESDIR}/${wrapper}" || die
			mv "${CTARGET}-gccgo" "${CTARGET}-gccgo.real" || die
			dosym "${wrapper}" "${BINPATH}/${CTARGET}-gccgo" || die
		fi
	else
		local sysroot_wrapper_file=host_wrapper

		exeinto "${BINPATH}"

		GO111MODULE=off "${FILESDIR}/compiler_wrapper/build.py" --config=cros.host --use_ccache=false \
			--use_llvm_next="${use_llvm_next}" \
			--output_file="${D}${BINPATH}/${sysroot_wrapper_file}" || die

		for x in cpp c++ g++ gcc; do
			if [[ -f "${CTARGET}-${x}" ]]; then
				mv "${CTARGET}-${x}" "${CTARGET}-${x}.real"
				dosym "${sysroot_wrapper_file}" "${BINPATH}/${CTARGET}-${x}" || die
			fi
			if [[ -f "${x}" ]]; then
				ln "${CTARGET}-${x}.real" "${x}.real" || die
				rm "${x}" || die
				dosym "${sysroot_wrapper_file}" "${BINPATH}/${x}" || die
				# Add a cc.real symlink that points to gcc.real, https://crbug.com/1090449
				if [[ "${x}" == "gcc" ]]; then
					dosym "${x}.real" "${BINPATH}/cc.real"
				fi
			fi
		done
	fi

	if use tests
	then
		TEST_INSTALL_DIR="usr/local/dejagnu/gcc"
		dodir ${TEST_INSTALL_DIR}
		cd "${D}/${TEST_INSTALL_DIR}" || die
		tar -czf "tests.tar.gz" "${WORKDIR}"
	fi
}

pkg_postinst() {
	gcc-config "$(get_gcc_config_file)"
	if [[ "${CTARGET}" == "${CHOST}" ]]; then
		# Point cc and cpp to clang based tools instead of gcc.
		ln -sf "clang_cc_wrapper" "/usr/bin/cc"
		ln -sf "clang-cpp" "/usr/bin/cpp"
	fi
}

pkg_postrm() {
	if is_crosscompile ; then
		if [[ -z $(ls "${ROOT}/etc/env.d/gcc/${CTARGET}*" 2>/dev/null) ]] ; then
			rm -f "${ROOT}/etc/env.d/gcc/config-${CTARGET}"
			rm -f "${ROOT}/etc/env.d/??gcc-${CTARGET}"
			rm -f "${ROOT}/usr/bin/${CTARGET}-{gcc,{g,c}++}{,32,64}"
		fi
	fi
}

get_gcc_config_file() {
	echo "${CTARGET}-${PV}"
}

# Grab a variable from the build system (taken from linux-info.eclass)
get_make_var() {
	local var=$1 makefile=${2:-${MY_BUILDDIR}/Makefile}
	echo -e "e:\\n\\t@echo \$(${var})\\ninclude ${makefile}" | \
		r=${makefile%/*} emake --no-print-directory -s -f - 2>/dev/null
}
XGCC() { get_make_var GCC_FOR_TARGET ; }

gcc_move_pretty_printers() {
	local py gdbdir=/usr/share/gdb/auto-load${LIBPATH}
	pushd "${D}${LIBPATH}" >/dev/null || die
	while IFS= read -r -d '' py; do
		local multidir=${py%/*}
		insinto "${gdbdir}/${multidir}"
		sed -i "/^libdir =/s:=.*:= '${LIBPATH}/${multidir}':" "${py}" || die #348128
		doins "${py}" || die
		rm "${py}" || die
	done <   <(find . -name '*-gdb.py' -print0)
	popd >/dev/null || die
}

# Move around the libs to the right location.  For some reason,
# when installing gcc, it dumps internal libraries into /usr/lib
# instead of the private gcc lib path
gcc_movelibs() {
	# For all the libs that are built for CTARGET, move them into the
	# compiler-specific CTARGET internal dir.
	local x multiarg removedirs=""
	for multiarg in $($(XGCC) -print-multi-lib) ; do
		multiarg=${multiarg#*;}
		multiarg=${multiarg//@/ -}

		# disable overzealous shellcheck because multiarg can be empty and passing
		# "" as an argument modifies the behaviour of xgcc breaking install paths.
		# shellcheck disable=SC2086
		local OS_MULTIDIR=$($(XGCC) ${multiarg} --print-multi-os-directory)
		# shellcheck disable=SC2086
		local MULTIDIR=$($(XGCC) ${multiarg} --print-multi-directory)
		local TODIR="${D}${LIBPATH}"/${MULTIDIR}
		local FROMDIR=

		[[ -d ${TODIR} ]] || mkdir -p "${TODIR}"

		for FROMDIR in \
			"${LIBPATH}"/${OS_MULTIDIR} \
			"${LIBPATH}"/../${MULTIDIR} \
			"${PREFIX}"/lib/${OS_MULTIDIR} \
			"${PREFIX}"/${CTARGET}/lib/${OS_MULTIDIR}
		do
			removedirs="${removedirs} ${FROMDIR}"
			FROMDIR=${D}${FROMDIR}
			if [[ ${FROMDIR} != "${TODIR}" && -d ${FROMDIR} ]] ; then
				find "${FROMDIR}" -maxdepth 1 ! -type d -exec \
					mv -ft "${TODIR}" {} +
			fi
		done
		fix_libtool_libdir_paths "${LIBPATH}/${MULTIDIR}"

		# SLOT up libgcj.pc if it's available (and let gcc-config worry about links)
		FROMDIR="${PREFIX}/lib/${OS_MULTIDIR}"
		for x in "${D}${FROMDIR}"/pkgconfig/libgcj*.pc ; do
			[[ -f ${x} ]] || continue
			sed -i "/^libdir=/s:=.*:=${LIBPATH}/${MULTIDIR}:" "${x}" || die
			mv "${x}" "${D}${FROMDIR}/pkgconfig/libgcj-${GCC_PV}.pc" || die
		done
	done

	# We remove directories separately to avoid this case:
	#	mv SRC/lib/../lib/*.o DEST
	#	rmdir SRC/lib/../lib/
	#	mv SRC/lib/../lib32/*.o DEST  # Bork
	for FROMDIR in ${removedirs} ; do
		rmdir "${D}${FROMDIR}" >& /dev/null
	done
	find -depth "${ED}" -type d -exec rmdir {} + >& /dev/null

	# We remove all instances of the GCC-installed libgcc, since we will be
	# installing compiler-rt and libunwind in its place.
	#
	# We'd like to remove libgcc.a, but this is required to build glibc, and
	# that causes complications. libgcc_eh.a also can't be removed yet, due
	# to it defining `__gcc_personality_v0`, which is a compiler-rt thing on
	# the LLVM side. We'll be able to remove both nce we can remove libgcc.a,
	# since this remnant of GCC's libgcc is confusing the system. Alternatively,
	# once we get a true LLVM runtimes build happening, we should be able to
	# remove libgcc_eh.a.
	if use llvm_libgcc; then
		rm -f "${D}${LIBPATH}"/libgcc_s* || die
	fi
}

# make sure the libtool archives have libdir set to where they actually
# -are-, and not where they -used- to be.  also, any dependencies we have
# on our own .la files need to be updated.
fix_libtool_libdir_paths() {
	local libpath="$1"

	pushd "${D}" >/dev/null || die

	pushd "./${libpath}" >/dev/null || die
	local dir="${PWD#${D%/}}"
	local allarchives=$(echo *.la)
	allarchives="\(${allarchives// /\\|}\)"
	popd >/dev/null || die

	# The libdir might not have any .la files. #548782
	find "./${dir}" -maxdepth 1 -name '*.la' \
		-exec sed -i -e "/^libdir=/s:=.*:='${dir}':" {} + || die
	# Would be nice to combine these, but -maxdepth can not be specified
	# on sub-expressions.
	find "./${PREFIX}"/lib* -maxdepth 3 -name '*.la' \
		-exec sed -i -e "/^dependency_libs=/s:/[^ ]*/${allarchives}:${libpath}/\1:g" {} + || die
	find "./${dir}/" -maxdepth 1 -name '*.la' \
		-exec sed -i -e "/^dependency_libs=/s:/[^ ]*/${allarchives}:${libpath}/\1:g" {} + || die

	popd >/dev/null || die
}
