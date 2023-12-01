Effects Stream Manipulator Tests
================

This package installs the `cros_effects_sm_tests` executable into a ChromeOS image.

This package depends on test assets stored in
[Google3](https://source.corp.google.com/piper///depot/google3/chromeos/test_assets).
For changes to this data to be reflected in this package some manual steps need to be
followed.

Uprev Instructions
==================

Upload the release
------------------
1. Ensure `gsutil` is in your path: `export PATH=$PATH:~/chromiumos/chromite/scripts`.
1. Change dir to `cd /google/src/head/depot/google3/chromeos/test_assets/`.
1. Run the `./upload_data.sh` script.
1. The script will package the latest set of data stored in `cros_effects_tests_assets`,
label it with the next version number and upload it to Google storage.

Uprev the ebuild
----------------
1. Navigate to the cros-camera-effects-sm-tests ebuild location at:
`src/third_party/chromiumos-overlay/media-libs/cros-camera-effects-sm-tests`.
1. Inside the 9999 ebuild, increment the last number of the `SRC_URI` field with a value
of the form `ml-core-cros_effects_test_assets-0.0.2.tar.xz`. E.g. In this case it should be
updated to `ml-core-cros_effects_test_assets-0.0.3.tar.xz`.
1. Update the manifest with `ebuild cros-camera-effects-sm-tests-0.0.xx.ebuild manifest`
1. You're done! Create a CL with the commit note below and get it reviewed.

```
cros-camera-effects-sm-tests: uprev to 0.0.3

Uprev cros-camera-effects-sm-tests test assets

BUG=<BUG>
TEST=Tests pass when run locally
```
