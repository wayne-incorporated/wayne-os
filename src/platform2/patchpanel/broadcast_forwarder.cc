// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/broadcast_forwarder.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <shill/net/rtnl_handler.h>

#include "patchpanel/net_util.h"
#include "patchpanel/socket.h"

namespace {

constexpr net_base::IPv4Address kBcastAddr(255, 255, 255, 255);
constexpr int kBufSize = 4096;
constexpr uint16_t kIpFragOffsetMask = 0x1FFF;
// Broadcast forwarder will not forward system ports (0 - 1023).
constexpr uint16_t kMinValidPort = 1024;

// SetBcastSockFilter filters out packets by only accepting (all conditions
// must be fulfilled):
// - UDP protocol,
// - Destination address equals to 255.255.255.255 or |bcast_addr|,
// - Source and destination port is not a system port (>= 1024).
bool SetBcastSockFilter(int fd, const net_base::IPv4Address& bcast_addr) {
  sock_filter kBcastFwdBpfInstructions[] = {
      // Load IP protocol value.
      BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsetof(iphdr, protocol)),
      // Check if equals UDP, if not, then goto return 0.
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 8),
      // Load IP destination address.
      BPF_STMT(BPF_LD | BPF_W | BPF_IND, offsetof(iphdr, daddr)),
      // Check if it is a broadcast address.
      // All 1s.
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(kBcastAddr.ToInAddr().s_addr),
               1, 0),
      // Current interface broadcast address.
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(bcast_addr.ToInAddr().s_addr),
               0, 5),
      // Move index to start of UDP header.
      BPF_STMT(BPF_LDX | BPF_IMM, sizeof(iphdr)),
      // Load UDP source port.
      BPF_STMT(BPF_LD | BPF_H | BPF_IND, offsetof(udphdr, uh_sport)),
      // Check if it is a valid source port (>= 1024).
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, kMinValidPort, 0, 2),
      // Load UDP destination port.
      BPF_STMT(BPF_LD | BPF_H | BPF_IND, offsetof(udphdr, uh_dport)),
      // Check if it is a valid destination port (>= 1024).
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, kMinValidPort, 1, 0),
      // Return 0.
      BPF_STMT(BPF_RET | BPF_K, 0),
      // Return MAX.
      BPF_STMT(BPF_RET | BPF_K, IP_MAXPACKET),
  };
  sock_fprog kBcastFwdBpfProgram = {
      .len = sizeof(kBcastFwdBpfInstructions) / sizeof(sock_filter),
      .filter = kBcastFwdBpfInstructions};

  if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &kBcastFwdBpfProgram,
                 sizeof(kBcastFwdBpfProgram)) != 0) {
    PLOG(ERROR)
        << "setsockopt(SO_ATTACH_FILTER) failed for broadcast forwarder";
    return false;
  }
  return true;
}

void Ioctl(int fd,
           const std::string& ifname,
           unsigned int cmd,
           struct ifreq* ifr) {
  if (ifname.empty()) {
    LOG(WARNING) << "Empty interface name";
    return;
  }

  memset(ifr, 0, sizeof(struct ifreq));
  strncpy(ifr->ifr_name, ifname.c_str(), IFNAMSIZ);
  if (ioctl(fd, cmd, ifr) < 0) {
    // Ignore EADDRNOTAVAIL: IPv4 was not provisioned.
    if (errno != EADDRNOTAVAIL) {
      PLOG(ERROR) << "ioctl call failed for " << ifname;
    }
  }
}

net_base::IPv4Address GetIfreqAddr(const struct ifreq& ifr) {
  return net_base::IPv4Address(
      reinterpret_cast<const struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr);
}

net_base::IPv4Address GetIfreqBroadaddr(const struct ifreq& ifr) {
  return net_base::IPv4Address(
      reinterpret_cast<const struct sockaddr_in*>(&ifr.ifr_broadaddr)
          ->sin_addr);
}

net_base::IPv4Address GetIfreqNetmask(const struct ifreq& ifr) {
  return net_base::IPv4Address(
      reinterpret_cast<const struct sockaddr_in*>(&ifr.ifr_netmask)->sin_addr);
}

}  // namespace

namespace patchpanel {

std::unique_ptr<BroadcastForwarder::Socket> BroadcastForwarder::CreateSocket(
    base::ScopedFD fd,
    const net_base::IPv4Address& addr,
    const net_base::IPv4Address& broadaddr,
    const net_base::IPv4Address& netmask) {
  auto socket = std::make_unique<Socket>();
  socket->watcher = base::FileDescriptorWatcher::WatchReadable(
      fd.get(),
      base::BindRepeating(&BroadcastForwarder::OnFileCanReadWithoutBlocking,
                          base::Unretained(this), fd.get()));
  socket->fd = std::move(fd);
  socket->addr = addr;
  socket->broadaddr = broadaddr;
  socket->netmask = netmask;
  return socket;
}

BroadcastForwarder::BroadcastForwarder(const std::string& dev_ifname)
    : dev_ifname_(dev_ifname) {}

void BroadcastForwarder::Init() {
  addr_listener_ = std::make_unique<shill::RTNLListener>(
      shill::RTNLHandler::kRequestAddr,
      base::BindRepeating(&BroadcastForwarder::AddrMsgHandler,
                          weak_factory_.GetWeakPtr()));
  shill::RTNLHandler::GetInstance()->Start(RTMGRP_IPV4_IFADDR);
}

void BroadcastForwarder::AddrMsgHandler(const shill::RTNLMessage& msg) {
  if (!msg.HasAttribute(IFA_LABEL)) {
    LOG(ERROR) << "Address event message does not have IFA_LABEL";
    return;
  }

  if (msg.mode() != shill::RTNLMessage::kModeAdd)
    return;

  shill::ByteString b(msg.GetAttribute(IFA_LABEL).GetSubstring(0, IFNAMSIZ));
  std::string ifname(b.GetConstCString(), b.GetLength());
  if (ifname != dev_ifname_)
    return;

  // Interface address is added.
  if (msg.HasAttribute(IFA_ADDRESS)) {
    shill::ByteString b(msg.GetAttribute(IFA_ADDRESS));
    const auto addr =
        net_base::IPv4Address::CreateFromBytes(b.GetConstData(), b.GetLength());
    if (!addr) {
      LOG(WARNING) << "Expected IFA_ADDRESS length "
                   << net_base::IPv4Address::kAddressLength << " but got "
                   << b.GetLength();
      return;
    }
    dev_socket_->addr = *addr;
  }

  // Broadcast address is added.
  if (msg.HasAttribute(IFA_BROADCAST)) {
    shill::ByteString b(msg.GetAttribute(IFA_BROADCAST));
    const auto broadaddr =
        net_base::IPv4Address::CreateFromBytes(b.GetConstData(), b.GetLength());
    if (!broadaddr) {
      LOG(WARNING) << "Expected IFA_BROADCAST length "
                   << net_base::IPv4Address::kAddressLength << " but got "
                   << b.GetLength();
      return;
    }
    dev_socket_->broadaddr = *broadaddr;

    base::ScopedFD dev_fd(BindRaw(dev_ifname_));
    if (!dev_fd.is_valid()) {
      LOG(WARNING) << "Could not bind socket on " << dev_ifname_;
      return;
    }
    dev_socket_ = CreateSocket(std::move(dev_fd), dev_socket_->addr,
                               dev_socket_->broadaddr, /*netmask=*/{});
  }
}

base::ScopedFD BroadcastForwarder::Bind(const std::string& ifname,
                                        uint16_t port) {
  base::ScopedFD fd(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "socket() failed for broadcast forwarder on " << ifname
                << " for port: " << port;
    return base::ScopedFD();
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ);
  if (setsockopt(fd.get(), SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
    PLOG(ERROR) << "setsockopt(SOL_SOCKET) failed for broadcast forwarder on "
                << ifname << " for port: " << port;
    return base::ScopedFD();
  }

  int on = 1;
  if (setsockopt(fd.get(), SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
    PLOG(ERROR) << "setsockopt(SO_BROADCAST) failed for broadcast forwarder on "
                << ifname << " for: " << port;
    return base::ScopedFD();
  }

  if (setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    PLOG(ERROR) << "setsockopt(SO_REUSEADDR) failed for broadcast forwarder on "
                << ifname << " for: " << port;
    return base::ScopedFD();
  }

  struct sockaddr_in bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(port);

  if (bind(fd.get(), (const struct sockaddr*)&bind_addr, sizeof(bind_addr)) <
      0) {
    PLOG(ERROR) << "bind(" << port << ") failed for broadcast forwarder on "
                << ifname << " for: " << port;
    return base::ScopedFD();
  }

  return fd;
}

base::ScopedFD BroadcastForwarder::BindRaw(const std::string& ifname) {
  base::ScopedFD fd(
      socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "socket() failed for raw socket";
    return base::ScopedFD();
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ);
  if (ioctl(fd.get(), SIOCGIFINDEX, &ifr) < 0) {
    PLOG(ERROR) << "SIOCGIFINDEX failed for " << ifname;
    return base::ScopedFD();
  }

  struct sockaddr_ll bindaddr;
  memset(&bindaddr, 0, sizeof(bindaddr));
  bindaddr.sll_family = AF_PACKET;
  bindaddr.sll_protocol = htons(ETH_P_IP);
  bindaddr.sll_ifindex = ifr.ifr_ifindex;

  if (bind(fd.get(), (const struct sockaddr*)&bindaddr, sizeof(bindaddr)) < 0) {
    PLOG(ERROR) << "bind() failed for broadcast forwarder on " << ifname;
    return base::ScopedFD();
  }

  Ioctl(fd.get(), ifname, SIOCGIFBRDADDR, &ifr);
  const auto bcast_addr = GetIfreqBroadaddr(ifr);

  if (!SetBcastSockFilter(fd.get(), bcast_addr)) {
    return base::ScopedFD();
  }

  return fd;
}

bool BroadcastForwarder::AddGuest(const std::string& br_ifname) {
  if (br_sockets_.find(br_ifname) != br_sockets_.end()) {
    LOG(WARNING) << "Forwarding is already started between " << dev_ifname_
                 << " and " << br_ifname;
    return false;
  }

  base::ScopedFD br_fd(BindRaw(br_ifname));
  if (!br_fd.is_valid()) {
    LOG(WARNING) << "Could not bind socket on " << br_ifname;
    return false;
  }

  struct ifreq ifr;
  Ioctl(br_fd.get(), br_ifname, SIOCGIFADDR, &ifr);
  const auto br_addr = GetIfreqAddr(ifr);
  Ioctl(br_fd.get(), br_ifname, SIOCGIFBRDADDR, &ifr);
  const auto br_broadaddr = GetIfreqBroadaddr(ifr);
  Ioctl(br_fd.get(), br_ifname, SIOCGIFNETMASK, &ifr);
  const auto br_netmask = GetIfreqNetmask(ifr);

  std::unique_ptr<Socket> br_socket =
      CreateSocket(std::move(br_fd), br_addr, br_broadaddr, br_netmask);

  br_sockets_.emplace(br_ifname, std::move(br_socket));

  // Broadcast forwarder is not started yet.
  if (dev_socket_ == nullptr) {
    base::ScopedFD dev_fd(BindRaw(dev_ifname_));
    if (!dev_fd.is_valid()) {
      LOG(WARNING) << "Could not bind socket on " << dev_ifname_;
      br_sockets_.clear();
      return false;
    }

    Ioctl(dev_fd.get(), dev_ifname_, SIOCGIFADDR, &ifr);
    const auto dev_addr = GetIfreqAddr(ifr);
    Ioctl(dev_fd.get(), dev_ifname_, SIOCGIFBRDADDR, &ifr);
    const auto dev_broadaddr = GetIfreqBroadaddr(ifr);

    dev_socket_ = CreateSocket(std::move(dev_fd), dev_addr, dev_broadaddr,
                               /*netmask=*/{});
  }
  return true;
}

void BroadcastForwarder::RemoveGuest(const std::string& br_ifname) {
  const auto& socket = br_sockets_.find(br_ifname);
  if (socket == br_sockets_.end()) {
    LOG(WARNING) << "Forwarding is not started between " << dev_ifname_
                 << " and " << br_ifname;
    return;
  }
  br_sockets_.erase(socket);
}

void BroadcastForwarder::OnFileCanReadWithoutBlocking(int fd) {
  alignas(4) uint8_t buffer[kBufSize];
  uint8_t* data = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);

  sockaddr_ll dst_addr;
  struct iovec iov = {
      .iov_base = buffer,
      .iov_len = kBufSize,
  };
  msghdr hdr = {
      .msg_name = &dst_addr,
      .msg_namelen = sizeof(dst_addr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = nullptr,
      .msg_controllen = 0,
      .msg_flags = 0,
  };

  ssize_t msg_len = ReceiveMessage(fd, &hdr);
  if (msg_len < 0) {
    // Ignore ENETDOWN: this can happen if the interface is not yet configured.
    if (errno != ENETDOWN) {
      PLOG(WARNING) << "recvmsg() failed";
    }
    return;
  }

  // These headers are taken directly from the buffer and is 4 bytes aligned.
  struct iphdr* ip_hdr = (struct iphdr*)(buffer);
  struct udphdr* udp_hdr = (struct udphdr*)(buffer + sizeof(struct iphdr));

  // Check that the IP header and UDP header have been filled.
  if (msg_len < sizeof(struct iphdr) + sizeof(struct udphdr))
    return;

  // Drop fragmented packets.
  if ((ntohs(ip_hdr->frag_off) & (kIpFragOffsetMask | IP_MF)) != 0)
    return;

  // Store the length of the message data without its headers.
  if (ntohs(udp_hdr->len) < sizeof(struct udphdr)) {
    return;
  }
  size_t len = ntohs(udp_hdr->len) - sizeof(struct udphdr);

  // Validate message data length.
  if (len + sizeof(struct udphdr) + sizeof(struct iphdr) > msg_len) {
    return;
  }

  struct sockaddr_in fromaddr = {0};
  fromaddr.sin_family = AF_INET;
  fromaddr.sin_port = udp_hdr->uh_sport;
  fromaddr.sin_addr.s_addr = ip_hdr->saddr;

  struct sockaddr_in dst = {0};
  dst.sin_family = AF_INET;
  dst.sin_port = udp_hdr->uh_dport;
  dst.sin_addr.s_addr = ip_hdr->daddr;

  // Forward ingress traffic to guests.
  if (fd == dev_socket_->fd.get()) {
    // Prevent looped back broadcast packets to be forwarded.
    if (net_base::IPv4Address(fromaddr.sin_addr) == dev_socket_->addr)
      return;

    SendToGuests(buffer, len, dst);
    return;
  }

  for (auto const& socket : br_sockets_) {
    if (fd != socket.second->fd.get())
      continue;

    // Prevent looped back broadcast packets to be forwarded.
    if (net_base::IPv4Address(fromaddr.sin_addr) == socket.second->addr)
      return;

    // We are spoofing packets source IP to be the actual sender source IP.
    // Prevent looped back broadcast packets by not forwarding anything from
    // outside the interface netmask.
    if ((fromaddr.sin_addr.s_addr & socket.second->netmask.ToInAddr().s_addr) !=
        (socket.second->addr.ToInAddr().s_addr &
         socket.second->netmask.ToInAddr().s_addr))
      return;

    // Forward egress traffic from one guest to outside network.
    SendToNetwork(ntohs(fromaddr.sin_port), data, len, dst);
  }
}

bool BroadcastForwarder::SendToNetwork(uint16_t src_port,
                                       const void* data,
                                       size_t len,
                                       const struct sockaddr_in& dst) {
  base::ScopedFD temp_fd(Bind(dev_ifname_, src_port));
  if (!temp_fd.is_valid()) {
    LOG(WARNING) << "Could not bind socket on " << dev_ifname_ << " for port "
                 << src_port;
    return false;
  }

  struct sockaddr_in dev_dst = {0};
  memcpy(&dev_dst, &dst, sizeof(sockaddr_in));

  if (net_base::IPv4Address(dev_dst.sin_addr) != kBcastAddr)
    dev_dst.sin_addr = dev_socket_->broadaddr.ToInAddr();

  if (SendTo(temp_fd.get(), data, len, &dev_dst) < 0) {
    // Ignore ENETDOWN: this can happen if the interface is not yet configured.
    if (errno != ENETDOWN) {
      PLOG(WARNING) << "sendto() failed";
    }
    return false;
  }
  return true;
}

bool BroadcastForwarder::SendToGuests(const void* ip_pkt,
                                      size_t len,
                                      const struct sockaddr_in& dst) {
  bool success = true;

  base::ScopedFD raw(socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_UDP));
  if (!raw.is_valid()) {
    PLOG(ERROR) << "socket() failed for raw socket";
    return false;
  }

  int on = 1;
  if (setsockopt(raw.get(), IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    PLOG(ERROR) << "setsockopt(IP_HDRINCL) failed";
    return false;
  }
  if (setsockopt(raw.get(), SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
    PLOG(ERROR) << "setsockopt(SO_BROADCAST) failed";
    return false;
  }

  // Copy IP packet received by the lan interface and only change its
  // destination address.
  alignas(4) uint8_t buffer[kBufSize];
  memset(buffer, 0, kBufSize);
  memcpy(buffer, reinterpret_cast<const uint8_t*>(ip_pkt),
         sizeof(iphdr) + sizeof(udphdr) + len);

  // These headers are taken directly from the buffer and is 4 bytes aligned.
  struct iphdr* ip_hdr = (struct iphdr*)buffer;
  struct udphdr* udp_hdr = (struct udphdr*)(buffer + sizeof(struct iphdr));

  ip_hdr->check = 0;
  udp_hdr->check = 0;

  struct sockaddr_in br_dst = {0};
  memcpy(&br_dst, &dst, sizeof(struct sockaddr_in));

  for (auto const& socket : br_sockets_) {
    // Set destination address.
    if (net_base::IPv4Address(br_dst.sin_addr) != kBcastAddr) {
      br_dst.sin_addr = socket.second->broadaddr.ToInAddr();
      ip_hdr->daddr = socket.second->broadaddr.ToInAddr().s_addr;
      ip_hdr->check = Ipv4Checksum(ip_hdr);
    }
    udp_hdr->check =
        Udpv4Checksum(buffer, sizeof(iphdr) + sizeof(udphdr) + len);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, socket.first.c_str(), IFNAMSIZ);
    if (setsockopt(raw.get(), SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
      PLOG(ERROR) << "setsockopt(SOL_SOCKET) failed for broadcast forwarder on "
                  << socket.first;
      continue;
    }

    // Use already created broadcast fd.
    if (SendTo(raw.get(), buffer,
               sizeof(struct iphdr) + sizeof(struct udphdr) + len,
               &br_dst) < 0) {
      PLOG(WARNING) << "sendto failed";
      success = false;
    }
  }
  return success;
}

ssize_t BroadcastForwarder::ReceiveMessage(int fd, struct msghdr* msg) {
  return recvmsg(fd, msg, 0);
}

ssize_t BroadcastForwarder::SendTo(int fd,
                                   const void* buffer,
                                   size_t buffer_len,
                                   const struct sockaddr_in* dst_addr) {
  return sendto(fd, buffer, buffer_len, 0,
                reinterpret_cast<const struct sockaddr*>(dst_addr),
                sizeof(*dst_addr));
}

}  // namespace patchpanel
