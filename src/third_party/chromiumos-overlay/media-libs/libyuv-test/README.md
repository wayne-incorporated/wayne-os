# `libyuv-test` package

This package contains a `libyuv` build for testing purposes; concretely it
builds and deploys the `libyuv_unittest` binary. This binary is exercised from,
at least, the `video.PlatformLibYUVPerftest.*` Tast tests (see
[tinyurl.com/cros-gfx-video](https://tinyurl.com/cros-gfx-video)).

The canonical (public) reference for this package's source can be found at
https://chromium.googlesource.com/libyuv/libyuv.

## How to uprev `libyuv-test`

The ebuild in this folder follows the Chromium version number; this is specified
on `libyuv`'s [README.chromium]
(https://chromium.googlesource.com/libyuv/libyuv/+/HEAD/README.chromium)
file.

ChromeOS keeps package sources in specific [archive mirrors]
(https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md);
the uprev target version source has to be uploaded to this mirror by hand by a
developer, following [these instructions]
(https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md#Getting-files-onto-localmirror).

Said package source has to be downloaded from the `libyuv` repository by looking
up in the [README.chromium file history]
(https://chromium.googlesource.com/libyuv/libyuv/+log/refs/heads/main/README.chromium)
the commit associated to the target Chromium numbering update. This `tar.gz`
has to be downloaded, renamed to `libyuv-${PACKAGE_VERSION}` and uploaded
to the mirror.

For example the version was updated to `1840` in commit
`65e7c9d5706a77d1949da59bfcb0817c252ef8d6`; the `tar.gz` file can be downloaded
at
https://chromium.googlesource.com/libyuv/libyuv/+archive/65e7c9d5706a77d1949da59bfcb0817c252ef8d6.tar.gz.

Before uploading a ChromeOS CL, the manifest also needs to be updated, e.g. by
running `ebuild-$BOARD libyuv-test-${PACAKGE_VERSION}.ebuild manifest`.

## `libyuv` package

A sibling `libyuv` package exists in the same `media-libs` package category
[here]
(https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/chromiumos-overlay/media-libs/libyuv/);
this is used for OS-level camera functionality. Although both `libyuv-test` and
`libyuv` are independent, is a good idea to uprev them at the same time. Refer
to that package ``README.md` for instructions.
