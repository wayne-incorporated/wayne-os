// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_NETLINK_FD_H_
#define SHILL_NET_NETLINK_FD_H_

namespace shill {

class Sockets;

// Keep this large enough to avoid overflows on IPv6 SNM routing update spikes
constexpr int kNetlinkReceiveBufferSize = 512 * 1024;

int OpenNetlinkSocketFD(Sockets* sockets,
                        int netlink_family,
                        int netlink_groups_mask);

}  // namespace shill

#endif  // SHILL_NET_NETLINK_FD_H_
