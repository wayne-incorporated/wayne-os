This package makes use of cros-workon eclass to maintain a -9999 and a release
version of the ebuild file.

In addition, there is a -9998.ebuild version that points directly to the
upstream repository hosted in GitHub. This version is masked on the base
profile (and hence on every other profile that inherits from base) so that it
cannot be used to build any image. The -9998 version is then unmasked on a
specific profile (e.g., fwupd-upstream) for the amd64-generic board and it is
used for continuous integration testing that is executed periodically by an
informational builder.
