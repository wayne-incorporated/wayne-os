#!/bin/sh
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

bootstat shill-start

# Double check to make sure shill related paths have been created with the
# intended ownership and permissions. These paths should already have been
# handled during boot, but check them again.
systemd-tmpfiles --create --remove --clean /usr/lib/tmpfiles.d/shill.conf
systemd-tmpfiles --create --remove --clean /usr/lib/tmpfiles.d/dhcpcd.conf

# tmpfiles.d does not handle chown/chmod -R because of unsafe ownership
# transitions.
(
  # Log any cases where the old behavior actually results in a change,
  # for /run paths until we are sure these are not needed.
  chown -c -R shill:shill /run/shill

  chown -c -R vpn:vpn \
    /run/ipsec \
    /run/l2tpipsec_vpn \
    /run/xl2tpd \
    /run/wireguard

  chown -c -R dhcp:dhcp /run/dhcpcd
) | logger -p err -t "shill-pre-start"

chown -R shill:shill \
  /var/cache/shill \
  /var/lib/shill/metrics

chown -R dhcp:dhcp /var/lib/dhcpcd
chmod -R u+rwX,g+rwX,o+rX /var/lib/dhcpcd
