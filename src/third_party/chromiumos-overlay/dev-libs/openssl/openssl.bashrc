# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# These OpenSSL programs are for debugging only and should not be required in
# the image. CA.pl and tsget also require perl, which is normally not available
# in the image.
if [[ $(cros_target) != "cros_host" ]]; then
  openssl_mask="
    /etc/ssl/misc/CA.pl
    /etc/ssl/misc/CA.sh
    /etc/ssl/misc/c_hash
    /etc/ssl/misc/c_info
    /etc/ssl/misc/c_issuer
    /etc/ssl/misc/c_name
    /etc/ssl/misc/tsget
  "
  PKG_INSTALL_MASK+=" ${openssl_mask}"
  INSTALL_MASK+=" ${openssl_mask}"
  unset openssl_mask
fi
