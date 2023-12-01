dev-libs/nss ebuild notes

The ChromeOS nss ebuild carries the following modifications vs. upstream:

* nss-3.38-shlibsign-path-pollution.patch
* nss-3.44-prefer-writable-tokens-for-trust.patch
* nss-3.68.2-nss-ld-fixup.patch

Those patches can be removed once the upstream has adopted them. Otherwise check
with the package owners and patch authors if there are any patch failures.

In ChromeOS images, util binaries from this package are not installed by
turning off USE flags 'utils'. And the util binaries are installed through
a separate package`app-crypt/nss`.
