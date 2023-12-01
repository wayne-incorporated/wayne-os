# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# /etc/rsyslog.chromeos only uses immark.so, imuxsock.so and imklog.so.
# All the /usr/lib*/rsyslog/lm*.so are not plugins, but runtime modules.
rsyslog_mask="
  /etc/rsyslog.d/50-default.conf

  /usr/lib*/rsyslog/imdiag.so
  /usr/lib*/rsyslog/imfile.so
  /usr/lib*/rsyslog/impstats.so
  /usr/lib*/rsyslog/imptcp.so
  /usr/lib*/rsyslog/imtcp.so
  /usr/lib*/rsyslog/imudp.so
  /usr/lib*/rsyslog/ommail.so
  /usr/lib*/rsyslog/omprog.so
  /usr/lib*/rsyslog/omruleset.so
  /usr/lib*/rsyslog/omstdout.so
  /usr/lib*/rsyslog/omtesting.so
  /usr/lib*/rsyslog/omuxsock.so
  /usr/lib*/rsyslog/pmaixforwardedfrom.so
  /usr/lib*/rsyslog/pmciscoios.so
  /usr/lib*/rsyslog/pmcisconames.so
  /usr/lib*/rsyslog/pmlastmsg.so
  /usr/lib*/rsyslog/pmsnare.so
"

PKG_INSTALL_MASK+=" ${rsyslog_mask}"
INSTALL_MASK+=" ${rsyslog_mask}"
