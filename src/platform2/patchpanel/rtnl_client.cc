// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/rtnl_client.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>

#include <algorithm>
#include <utility>

#include <base/logging.h>

namespace patchpanel {
namespace {

template <typename Address, unsigned char ip_family>
std::map<Address, MacAddress> GetNeighborMacTable(
    const base::ScopedFD& rtnl_fd, const std::optional<int>& ifindex) {
  sockaddr_nl kernel;
  memset(&kernel, 0, sizeof(kernel));
  kernel.nl_family = AF_NETLINK;

  struct nl_req {
    nlmsghdr hdr;
    rtgenmsg gen;
  } req;
  memset(&req, 0, sizeof(nl_req));
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(rtgenmsg));
  req.hdr.nlmsg_type = RTM_GETNEIGH;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = 1;
  req.gen.rtgen_family = ip_family;

  iovec io_req;
  memset(&io_req, 0, sizeof(io_req));
  io_req.iov_base = &req;
  io_req.iov_len = req.hdr.nlmsg_len;

  msghdr rtnl_req;
  memset(&rtnl_req, 0, sizeof(rtnl_req));
  rtnl_req.msg_name = &kernel;
  rtnl_req.msg_namelen = sizeof(kernel);
  rtnl_req.msg_iov = &io_req;
  rtnl_req.msg_iovlen = 1;

  if (sendmsg(rtnl_fd.get(), &rtnl_req, 0) < 0) {
    PLOG(ERROR) << "sendmsg() failed on rtnetlink socket";
    return {};
  }

  static constexpr size_t kRtnlReplyBufferSize = 32768;
  char reply_buffer[kRtnlReplyBufferSize];

  iovec io_reply;
  memset(&io_reply, 0, sizeof(io_reply));
  io_reply.iov_base = reply_buffer;
  io_reply.iov_len = kRtnlReplyBufferSize;

  msghdr rtnl_reply;
  memset(&rtnl_reply, 0, sizeof(rtnl_reply));
  rtnl_reply.msg_name = &kernel;
  rtnl_reply.msg_namelen = sizeof(kernel);
  rtnl_reply.msg_iov = &io_reply;
  rtnl_reply.msg_iovlen = 1;

  bool done = false;
  std::map<Address, MacAddress> ret;
  while (!done) {
    ssize_t len = recvmsg(rtnl_fd.get(), &rtnl_reply, 0);
    if (len < 0) {
      PLOG(ERROR) << "recvmsg() failed on rtnetlink socket";
      return ret;
    }

    for (nlmsghdr* msg_ptr = reinterpret_cast<nlmsghdr*>(reply_buffer);
         NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len)) {
      switch (msg_ptr->nlmsg_type) {
        case NLMSG_DONE:
          done = true;
          break;
        case RTM_NEWNEIGH: {
          std::optional<Address> addr;
          std::optional<MacAddress> mac_addr;

          size_t rt_attr_len = RTM_PAYLOAD(msg_ptr);
          ndmsg* nd_msg = reinterpret_cast<ndmsg*>(NLMSG_DATA(msg_ptr));
          // Filter out the special IPs that get resolved into MAC without
          // sending an ARP/NDP packet.
          if (nd_msg->ndm_state & NUD_NOARP) {
            continue;
          }
          // Filter out the IPs from different network interfaces.
          if (ifindex && nd_msg->ndm_ifindex != *ifindex) {
            continue;
          }

          rtattr* rt_attr = reinterpret_cast<rtattr*>(RTM_RTA(nd_msg));
          for (; RTA_OK(rt_attr, rt_attr_len);
               rt_attr = RTA_NEXT(rt_attr, rt_attr_len)) {
            if (rt_attr->rta_type == NDA_DST) {
              addr = Address::CreateFromBytes(
                  reinterpret_cast<const char*>(RTA_DATA(rt_attr)),
                  Address::kAddressLength);
            } else if (rt_attr->rta_type == NDA_LLADDR) {
              mac_addr = MacAddress();
              std::copy_n(reinterpret_cast<const uint8_t*>(RTA_DATA(rt_attr)),
                          ETHER_ADDR_LEN, mac_addr->begin());
            }
          }

          if (addr && mac_addr) {
            ret[*addr] = *mac_addr;
          }
          break;
        }
        default: {
          LOG(WARNING) << "received unexpected rtnetlink message type "
                       << msg_ptr->nlmsg_type << ", length "
                       << msg_ptr->nlmsg_len;
          break;
        }
      }
    }
  }

  return ret;
}

}  // namespace

// static
std::unique_ptr<RTNLClient> RTNLClient::Create() {
  base::ScopedFD rtnl_fd(
      socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
  if (!rtnl_fd.is_valid()) {
    PLOG(ERROR) << "socket() failed for rtnetlink socket";
    return nullptr;
  }

  sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;

  if (bind(rtnl_fd.get(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
    PLOG(ERROR) << "bind() failed on rtnetlink socket";
    return nullptr;
  }

  return std::unique_ptr<RTNLClient>(new RTNLClient(std::move(rtnl_fd)));
}

RTNLClient::RTNLClient(base::ScopedFD rtnl_fd) : rtnl_fd_(std::move(rtnl_fd)) {}
RTNLClient::~RTNLClient() = default;

std::map<net_base::IPv4Address, MacAddress> RTNLClient::GetIPv4NeighborMacTable(
    const std::optional<int>& ifindex) const {
  return GetNeighborMacTable<net_base::IPv4Address, AF_INET>(rtnl_fd_, ifindex);
}

std::map<net_base::IPv6Address, MacAddress> RTNLClient::GetIPv6NeighborMacTable(
    const std::optional<int>& ifindex) const {
  return GetNeighborMacTable<net_base::IPv6Address, AF_INET6>(rtnl_fd_,
                                                              ifindex);
}

}  // namespace patchpanel
