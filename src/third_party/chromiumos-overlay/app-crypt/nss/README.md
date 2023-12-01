app-crypt/nss ebuild notes

This ebuild only installs util binaries from the NSS library such as
`certutil`. Those binaries are installed on test images to facilitate
Tast tests and to provide other utilities.

The Chrome OS nss ebuild carries the following modifications vs. upstream:

* nss-3.38-shlibsign-path-pollution.patch
* nss-3.44-prefer-writable-tokens-for-trust.patch
* nss-3.68.2-nss-ld-fixup.patch

This is in sync with dev-libs/nss to make sure builds are consistent.
