# Chrome OS ML Service: How to upgrade the libhandwriting library

This page explains how to upgrade the handwriting recognition library. The doc
assumes that you have already obtained a new release
"libhandwriting-0.0.3.tar.gz" and want to upgrade to it from
"libhandwriting-0.0.2.tar.gz".

When there is no need to update the code in ml-service, the steps are as
follows,

1. (Just like the
[first step of publishing ML models](publish_and_use_model.md#upload-model))
Upload the newly released tarball to
https://storage.googleapis.com/chromeos-localmirror/distfiles/ following the
instruction [here][update-localmirror]. Reminder: do NOT delete the old release.

2. Submit a CL to rename the ebuild file from "libhandwriting-0.0.2-rN.ebuild"
("N" denotes the existing revision number) to the new version, i.e.,
"libhandwriting-0.0.3-r1.ebuild" (revision number should start from 1). Remember
to update the Manifest file too (you can run
```
ebuild "/home/${USER}/trunk/src/third_party/chromiumos-overlay/dev-libs/libhandwriting/libhandwriting-0.0.3-r1.ebuild" manifest
```
to generate the manifest file in the chroot).

When the code in ml-service also needs update, you can submit the ml-serivce
CL with the CL in Step 2 above together using [cq-depend].


[cq-depend]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/contributing.md#cq-depend
[update-localmirror]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md#Updating-localmirror-localmirror_private
