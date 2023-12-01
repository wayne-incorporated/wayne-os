# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Additional variables needed for cross compile on Chrome OS.
export krb5_cv_attr_constructor_destructor=yes,yes
export ac_cv_func_regcomp=yes
export ac_cv_printf_positional=yes

# Remove unwanted binaries from the image. In particular ksu
# can't be part of the image due to suid capabilities.
krb5_mask="
  /usr/sbin
  /usr/bin/k5srvutil
  /usr/bin/kadmin
  /usr/bin/ksu
  /usr/bin/kswitch
  /usr/bin/ktutil
  /usr/bin/kvno
  /usr/bin/sclient
  /usr/bin/sim_client
  /usr/bin/uuclient
"
PKG_INSTALL_MASK+=" ${krb5_mask}"
INSTALL_MASK+=" ${krb5_mask}"
unset krb5_mask
