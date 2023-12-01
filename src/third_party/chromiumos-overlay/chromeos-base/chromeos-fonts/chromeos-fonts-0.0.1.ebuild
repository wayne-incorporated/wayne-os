# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-constants

DESCRIPTION="Chrome OS Fonts (meta package)"
HOMEPAGE="http://src.chromium.org"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="cros_host extra_japanese_fonts internal"

# List of font packages used in Chromium OS.  This list is separate
# so that it can be shared between the host in
# chromeos-base/hard-host-depends and the target in
# chromeos-base/chromeos.
#
# The glibc requirement is a bit funky.  For target boards, we make sure it is
# installed before any other package (by way of setup_board), but for the sdk
# board, we don't have that toolchain-specific tweak.  So we end up installing
# these in parallel and the chroot logic for font generation fails.  We can
# drop this when we stop executing the helper in the $ROOT via `chroot` and/or
# `qemu` (e.g. when we do `ROOT=/build/amd64-host/ emerge chromeos-fonts`).
#
# The gcc-libs requirement is a similar situation.  Ultimately this comes down
# to fixing http://crbug.com/205424.
DEPEND="
	internal? (
		chromeos-base/monotype-fonts:=
		>=chromeos-base/google-sans-fonts-3.0.0:=
	)
	media-fonts/croscorefonts:=
	media-fonts/crosextrafonts:=
	media-fonts/crosextrafonts-carlito:=
	media-fonts/noto-cjk:=
	media-fonts/notofonts:=
	media-fonts/ko-nanumfonts:=
	media-fonts/lohitfonts-cros:=
	media-fonts/robotofonts:=
	media-fonts/tibt-jomolhari:=
	media-libs/fontconfig:=
	!cros_host? ( sys-libs/gcc-libs:= )
	cros_host? ( sys-libs/glibc:= )
	extra_japanese_fonts? (
		media-fonts/ipaex
		media-fonts/morisawa-ud-fonts
	)
	"
RDEPEND="${DEPEND}"

S=${WORKDIR}

emptydir() {
	[[ -z "$(find "$1" -mindepth 1 -maxdepth 1)" ]]
}

# When cross-compiling, the generated font caches need to be compatible with
# the architecture on which they will be used, so we run the target fc-cache
# through platform2_test.py (and QEMU).
generate_font_cache() {
	local fonts_path="${WORKDIR}/usr/share/fonts"

	# Because this can be a lot of data, we link instead of copying. Hard
	# links may run into /proc/sys/fs/protected_hardlinks limitations on
	# some systems, so we use symbolic links. Symlinks need to be relative,
	# to work in and out of a sysroot-relative view of the filesystem.
	local sysroot_fonts="${SYSROOT}/usr/share/fonts"
	# Mirror the directory structure.
	find "${sysroot_fonts}" -mindepth 1 -type d -printf "${fonts_path}/%P\0" | \
		xargs -0 mkdir -p || die
	# Create relative symlinks to all the fonts.
	find "${sysroot_fonts}" -type f -not -name .uuid -printf '%P\0' | \
		xargs -0 -I'{}' ln -sr "${sysroot_fonts}"/{} "${fonts_path}"/{} \
		|| die

	# Copy the fontconfig configurations over too.
	mkdir -p "${WORKDIR}/etc/fonts" || die
	rsync -a "${SYSROOT}/etc/fonts/" "${WORKDIR}/etc/fonts/" || die

	# .uuid files need to exist when fc-cache is run, otherwise fc-cache
	# will try to generate them itself.
	local fontname
	while read -r -d $'\0' fontname; do
		# Old builds could leave empty (except for .uuid) directories.
		if emptydir "${fonts_path}/${fontname}"; then
			rmdir -v "${fonts_path}/${fontname}" || die
			continue
		fi
		uuidgen --sha1 -n @dns -N "$(usev cros_host)${fontname}" > \
			"${fonts_path}/${fontname}"/.uuid || die
	done < <(find "${fonts_path}" -depth -mindepth 1 -type d -printf '%P\0')

	# Per https://reproducible-builds.org/specs/source-date-epoch/, this
	# should be the last modification time of the source (date +%s). In
	# practice, we just need it to be older than the timestamp of anyone
	# building this package, and greater than 0 (fontconfig ignores 0
	# values).
	local TIMESTAMP=1
	if [[ "${ARCH}" == "amd64" ]]; then
		# Special-case for amd64: the target ISA may not match our
		# build host (so we can't run natively;
		# https://crbug.com/856686), and we may not have QEMU support
		# for the full ISA either. Just run the SDK binary instead.
		SOURCE_DATE_EPOCH="${TIMESTAMP}" \
			/usr/bin/fc-cache -f -v --sysroot "${WORKDIR}" || die
	else
		"${CHROOT_SOURCE_ROOT}"/src/platform2/common-mk/platform2_test.py \
			--env SOURCE_DATE_EPOCH="${TIMESTAMP}" \
			--sysroot "${SYSROOT}" \
			-- /usr/bin/fc-cache -f -v \
			--sysroot "${WORKDIR/#${SYSROOT}/}" || die
	fi
}

src_compile() {
	generate_font_cache
}

src_install() {
	insinto /usr/share/cache/fontconfig
	doins "${WORKDIR}"/usr/share/cache/fontconfig/*

	# .uuid files are also needed for the target package.
	local fontname
	while read -r -d $'\0' fontname; do
		insinto "/usr/share/fonts/${fontname}"
		doins "${WORKDIR}/usr/share/fonts/${fontname}/.uuid"
	done < <(find "${WORKDIR}"/usr/share/fonts/ -mindepth 1 -type d -printf '%P\0')
}
