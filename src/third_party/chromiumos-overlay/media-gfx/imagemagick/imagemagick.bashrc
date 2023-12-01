# When we install imagemagick into dev/test images, it goes into
# /usr/local.  It uses config files and libltdl at runtime which
# means it normally expects files in /etc and /usr/lib but they
# are now in /usr/local/etc and /usr/local/lib.  So set the prefix
# to /usr/local so it works in those images.
cros_pre_src_configure_imagemagick_local() {
	if [[ $(cros_target) != "cros_host" ]]; then
		EXTRA_ECONF+="
			--prefix=/usr/local
			--libdir=/usr/local/$(get_libdir)
			--sysconfdir=/usr/local/etc
		"

		# Argument hack since we are installing to /usr/local
		find() {
			local args=( -maxdepth 1 -name "*.la" -delete )
			if [[ "$*" == "${ED}/usr/$(get_libdir)/ ${args[*]}" ]]; then
				set -- "${ED}/usr/local/$(get_libdir)/" "${args[@]}"
			fi
			$(type -P find) "$@"
		}
	fi
}

# Enable C++ exceptions.
cros_pre_src_prepare_enable_cxx_exceptions() {
	cros_enable_cxx_exceptions
}

# Force install to use -j1 since it can flake.
# http://crbug.com/216751
cros_pre_src_install_imagemagick_single_install() {
	MAKEOPTS+=" -j1"
}

# When installing a binpkg, we externally set INSTALL_MASK/etc...
# to kill all *.la files.  This would break imagemagick because it
# uses libltdl which utilizes libtool linker scripts (.la) to locate
# modules at runtime.  So save all of the .la files in a tarball and
# unpack them ourselves later on :x.

LA_TARBALL="share/${PN}/la-files.tar.zst"

cros_post_src_install_imagemagick_save_la() {
	pushd "${ED}"/usr/local >/dev/null
	mkdir -p "share/${PN}"
	tar -Izstdmt -cf ${LA_TARBALL} $(find -name '*.la')
	popd >/dev/null
}

cros_post_pkg_prerm_imagemagick_cleanup_la() {
	pushd "${EROOT}"/usr/local >/dev/null
	rm -f $(tar tf ${LA_TARBALL})
	popd >/dev/null
}

cros_post_pkg_postinst_imagemagick_restore_la() {
	pushd "${EROOT}"/usr/local >/dev/null
	tar xf ${LA_TARBALL}
	popd >/dev/null
}
