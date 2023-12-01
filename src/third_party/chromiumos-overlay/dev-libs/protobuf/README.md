The newest version of dev-libs/protobuf lives in portage stable, and a
ChromeOS-specific protobuf.bashrc file is used to mask out protoc related
files since they are not needed on build targets (just the SDK).

libprotobuf is used by some externally built files, so when upgrading
libprotobuf it is often necessary to keep the .so files around from the
previous version with any non-conflicting symlinks until the externally built
files are rebuilt against the newer libprotobuf.

Here is an excerpt from an ebuild that only installs the necessary libraries:

```
SLOT="PITA/30"

...

multilib_src_compile() {
	emake -C "src" libprotobuf-lite.la libprotobuf.la libprotoc.la
}

multilib_src_install() {
	DESTDIR="${ED}" emake -C "src" install-libLTLIBRARIES
	libtool --finish "${ED}/usr/lib64" || die

	# Remove
	# * .la files
	# * libprotoc which isn't needed.
	# * top level .so symlinks
	find "${ED}" \( -iname '*.la' -or -iname 'libprotoc.*' -or -iname 'libprotoc.*' -or -iname '*.so' \) -delete || die
}
```
