This package resides here because the ebuild file deviates from the upstream
version. This is done so we can configure the correct data directory for vim on
ChromeOS dev and test images. The default data directory for vim and vim-core is
`/usr/share/...` whereas the installation directory for dev and test images is
`/use/local/share/...`. This causes issues as vim is not able to locate the
artifact files on dev and test images.

When upreving vim and vim-core please remember to add the following line in the
`src_configure()` function, and append `cros_host` to the list of `IUSE` flags
at the top of the ebuild.
`! use cros_host && myconf+=( --datadir=/usr/local/share )`

For more information see b/249339147
