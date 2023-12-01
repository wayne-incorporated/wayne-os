// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/netlink_fd.h"

#include <linux/netlink.h>
#include <sys/socket.h>

#include <base/logging.h>

#include "shill/net/sockets.h"

namespace shill {

int OpenNetlinkSocketFD(Sockets* sockets,
                        int netlink_family,
                        int netlink_groups_mask) {
  int sockfd =
      sockets->Socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, netlink_family);
  if (sockfd < 0) {
    PLOG(ERROR) << "Failed to open netlink socket for family "
                << netlink_family;
    return Sockets::kInvalidFileDescriptor;
  }

  if (sockets->SetReceiveBuffer(sockfd, kNetlinkReceiveBufferSize))
    PLOG(WARNING) << "Failed to increase receive buffer size to "
                  << kNetlinkReceiveBufferSize << "b";

  struct sockaddr_nl addr;
  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = netlink_groups_mask;

  if (sockets->Bind(sockfd, reinterpret_cast<struct sockaddr*>(&addr),
                    sizeof(addr)) < 0) {
    PLOG(ERROR) << "Netlink socket bind failed for family " << netlink_family;
    sockets->Close(sockfd);
    return Sockets::kInvalidFileDescriptor;
  }

  return sockfd;
}

}  // namespace shill
