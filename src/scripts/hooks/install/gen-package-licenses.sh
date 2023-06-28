#!/bin/bash
# Copyright 2014 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

generate_licensing()
{
  local PKG="${CATEGORY}/${PF}"

  # This expands to something like
  # /build/x86-alex/tmp/portage/dev-util/libc-bench-0.0.1-r6
  # Run FEATURES='noclean' emerge-x86-alex libc-bench to prevent having the
  # directory cleaned up if you are debugging.
  einfo "Generating license for ${PKG} in ${PORTAGE_BUILDDIR}"
  /mnt/host/source/chromite/licensing/ebuild_license_hook \
      --builddir "${PORTAGE_BUILDDIR}" || die "
Failed Generating Licensing for ${PKG}
Note that many/most open source licenses require that you distribute the license
with the code, therefore you should fix this instead of overridding this check.

Note too that you need to bundle the license with binary packages too, even
if they are not part of ChromeOS proper since all packages are available as
prebuilts to anyone and therefore must include a license.

If you need help resolving the licensing error you just got, please have a
look at
https://dev.chromium.org/chromium-os/licensing/licensing-for-chromiumos-package-owners
"
}

generate_licensing
