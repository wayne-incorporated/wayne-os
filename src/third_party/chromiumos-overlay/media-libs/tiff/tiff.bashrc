# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO(crbug.com/738401): Remove tiff2pdf from the INSTALL_MASK once
# CVE-2017-9935 is fixed.

tiff_mask="
  /usr/bin/tiff2pdf
  /usr/bin/pal2rgb
"
INSTALL_MASK+=" ${tiff_mask}"
PKG_INSTALL_MASK+=" ${tiff_mask}"
unset tiff_mask
