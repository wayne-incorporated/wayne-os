# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Enable memcmp for Chrome OS.
export ac_cv_func_memcmp_working=yes

# Don't install any binaries since only the libraries are used.
openldap_mask="
  /usr/bin
"
PKG_INSTALL_MASK+=" ${openldap_mask}"
INSTALL_MASK+=" ${openldap_mask}"
unset openldap_mask
