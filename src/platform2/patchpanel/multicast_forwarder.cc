// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/multicast_forwarder.h"

#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "patchpanel/dns/dns_protocol.h"
#include "patchpanel/dns/dns_response.h"
#include "patchpanel/net_util.h"
#include "patchpanel/socket.h"
#include "patchpanel/system.h"

namespace {

const int kBufSize = 1536;

// Returns the IPv4 address assigned to the interface on which the given socket
// is bound. Or returns INADDR_ANY if the interface has no IPv4 address.
struct in_addr GetInterfaceIp(int fd, const std::string& ifname) {
  if (ifname.empty()) {
    LOG(WARNING) << "Empty interface name";
    return {0};
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ);
  if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
    // Ignore EADDRNOTAVAIL: IPv4 was not provisioned.
    if (errno != EADDRNOTAVAIL) {
      PLOG(ERROR) << "SIOCGIFADDR failed for " << ifname;
    }
    return {0};
  }

  struct sockaddr_in* if_addr =
      reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
  return if_addr->sin_addr;
}

// Fills sockaddr_storage values.
void SetSockaddr(struct sockaddr_storage* saddr_storage,
                 sa_family_t sa_family,
                 uint16_t port,
                 const char* addr) {
  struct sockaddr* saddr = reinterpret_cast<sockaddr*>(saddr_storage);
  if (sa_family == AF_INET) {
    struct sockaddr_in* saddr4 = reinterpret_cast<struct sockaddr_in*>(saddr);
    saddr4->sin_family = AF_INET;
    saddr4->sin_port = htons(port);
    if (addr)
      memcpy(&saddr4->sin_addr, addr, sizeof(struct in_addr));
    return;
  }
  if (sa_family == AF_INET6) {
    struct sockaddr_in6* saddr6 = reinterpret_cast<sockaddr_in6*>(saddr);
    saddr6->sin6_family = AF_INET6;
    saddr6->sin6_port = htons(port);
    if (addr)
      memcpy(&saddr6->sin6_addr, addr, sizeof(struct in6_addr));
    return;
  }
  LOG(ERROR) << "Invalid socket family " << sa_family;
}

}  // namespace

namespace patchpanel {

std::unique_ptr<MulticastForwarder::Socket> MulticastForwarder::CreateSocket(
    base::ScopedFD fd, sa_family_t sa_family) {
  auto socket = std::make_unique<Socket>();
  socket->watcher = base::FileDescriptorWatcher::WatchReadable(
      fd.get(),
      base::BindRepeating(&MulticastForwarder::OnFileCanReadWithoutBlocking,
                          base::Unretained(this), fd.get(), sa_family));
  socket->fd = std::move(fd);
  return socket;
}

MulticastForwarder::MulticastForwarder(const std::string& lan_ifname,
                                       const net_base::IPv4Address& mcast_addr,
                                       const net_base::IPv6Address& mcast_addr6,
                                       uint16_t port)
    : lan_ifname_(lan_ifname),
      port_(port),
      mcast_addr_(mcast_addr),
      mcast_addr6_(mcast_addr6) {}

void MulticastForwarder::Init() {
  base::ScopedFD lan_fd(Bind(AF_INET, lan_ifname_));
  if (lan_fd.is_valid()) {
    lan_socket_.emplace(AF_INET, CreateSocket(std::move(lan_fd), AF_INET));
  } else {
    LOG(WARNING) << "Could not bind socket on " << lan_ifname_ << " for "
                 << mcast_addr_ << ":" << port_;
  }

  base::ScopedFD lan_fd6(Bind(AF_INET6, lan_ifname_));
  if (lan_fd6.is_valid()) {
    lan_socket_.emplace(AF_INET6, CreateSocket(std::move(lan_fd6), AF_INET6));
  } else {
    LOG(WARNING) << "Could not bind socket on " << lan_ifname_ << " for "
                 << mcast_addr6_ << ":" << port_;
  }
}

base::ScopedFD MulticastForwarder::Bind(sa_family_t sa_family,
                                        const std::string& ifname) {
  const std::string mcast_addr =
      (sa_family == AF_INET) ? mcast_addr_.ToString() : mcast_addr6_.ToString();

  base::ScopedFD fd(socket(sa_family, SOCK_DGRAM, 0));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "socket() failed on " << ifname << " for " << mcast_addr
                << ":" << port_;
    return base::ScopedFD();
  }

  // The socket needs to be bound to INADDR_ANY rather than a specific
  // interface, or it will not receive multicast traffic.  Therefore
  // we use SO_BINDTODEVICE to force TX from this interface, and
  // specify the interface address in IP_ADD_MEMBERSHIP to control RX.
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ);
  if (setsockopt(fd.get(), SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr))) {
    PLOG(ERROR) << "setsockopt(SO_BINDTODEVICE) failed on " << ifname << " for "
                << mcast_addr << ":" << port_;
    return base::ScopedFD();
  }

  System system;
  int ifindex = system.IfNametoindex(ifname);
  if (ifindex == 0) {
    PLOG(ERROR) << "Could not obtain interface index of " << ifname << " for "
                << mcast_addr << ":" << port_;
    return base::ScopedFD();
  }

  int level, optname;
  if (sa_family == AF_INET) {
    struct ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_multiaddr = mcast_addr_.ToInAddr();
    mreqn.imr_address.s_addr = htonl(INADDR_ANY);
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd.get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn,
                   sizeof(mreqn)) < 0) {
      PLOG(ERROR) << "Can't add IPv4 multicast membership for on " << ifname
                  << " for " << mcast_addr_ << ":" << port_;
      return base::ScopedFD();
    }

    level = IPPROTO_IP;
    optname = IP_MULTICAST_LOOP;
  } else if (sa_family == AF_INET6) {
    struct ipv6_mreq mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.ipv6mr_multiaddr = mcast_addr6_.ToIn6Addr();
    mreqn.ipv6mr_interface = static_cast<uint32_t>(ifindex);
    if (setsockopt(fd.get(), IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreqn,
                   sizeof(mreqn)) < 0) {
      PLOG(ERROR) << "Can't add IPv6 multicast membership on " << ifname
                  << " for " << mcast_addr6_ << ":" << port_;
      return base::ScopedFD();
    }

    level = IPPROTO_IPV6;
    optname = IPV6_MULTICAST_LOOP;
  } else {
    return base::ScopedFD();
  }

  int off = 0;
  if (setsockopt(fd.get(), level, optname, &off, sizeof(off))) {
    PLOG(ERROR) << "setsockopt(IP_MULTICAST_LOOP) failed on " << ifname
                << " for " << mcast_addr << ":" << port_;
    return base::ScopedFD();
  }

  int on = 1;
  if (setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    PLOG(ERROR) << "setsockopt(SO_REUSEADDR) failed on " << ifname << " for "
                << mcast_addr << ":" << port_;
    return base::ScopedFD();
  }

  struct sockaddr_storage bind_addr = {0};
  SetSockaddr(&bind_addr, sa_family, port_, nullptr);

  if (bind(fd.get(), (const struct sockaddr*)&bind_addr,
           sizeof(struct sockaddr_storage)) < 0) {
    PLOG(ERROR) << "bind(" << port_ << ") failed for on " << ifname << " for "
                << mcast_addr << ":" << port_;
    return base::ScopedFD();
  }

  return fd;
}

bool MulticastForwarder::AddGuest(const std::string& int_ifname) {
  if (int_sockets_.find(std::make_pair(AF_INET, int_ifname)) !=
          int_sockets_.end() ||
      int_sockets_.find(std::make_pair(AF_INET6, int_ifname)) !=
          int_sockets_.end()) {
    LOG(WARNING) << "Forwarding is already started between " << lan_ifname_
                 << " and " << int_ifname;
    return false;
  }

  bool success = false;

  // Set up IPv4 multicast forwarder.
  base::ScopedFD int_fd4(Bind(AF_INET, int_ifname));
  if (int_fd4.is_valid()) {
    int_fds_.emplace(std::make_pair(AF_INET, int_fd4.get()));

    int_sockets_.emplace(std::make_pair(AF_INET, int_ifname),
                         CreateSocket(std::move(int_fd4), AF_INET));

    success = true;
    LOG(INFO) << "Started IPv4 forwarding between " << lan_ifname_ << " and "
              << int_ifname << " for " << mcast_addr_ << ":" << port_;
  } else {
    LOG(WARNING) << "Could not bind socket on " << int_ifname << " for "
                 << mcast_addr_ << ":" << port_;
  }

  // Set up IPv6 multicast forwarder.
  base::ScopedFD int_fd6(Bind(AF_INET6, int_ifname));
  if (int_fd6.is_valid()) {
    int_fds_.emplace(std::make_pair(AF_INET6, int_fd6.get()));
    int_sockets_.emplace(std::make_pair(AF_INET6, int_ifname),
                         CreateSocket(std::move(int_fd6), AF_INET6));

    success = true;
    LOG(INFO) << "Started IPv6 forwarding between " << lan_ifname_ << " and "
              << int_ifname << " for " << mcast_addr6_ << ":" << port_;
  } else {
    LOG(WARNING) << "Could not bind socket on " << int_ifname << " for "
                 << mcast_addr6_ << ":" << port_;
  }

  return success;
}

void MulticastForwarder::RemoveGuest(const std::string& int_ifname) {
  const auto& socket4 = int_sockets_.find(std::make_pair(AF_INET, int_ifname));
  if (socket4 != int_sockets_.end()) {
    int_fds_.erase(std::make_pair(AF_INET, socket4->second->fd.get()));
    int_sockets_.erase(socket4);
  } else {
    LOG(WARNING) << "IPv4 forwarding is not started between " << lan_ifname_
                 << " and " << int_ifname;
  }

  const auto& socket6 = int_sockets_.find(std::make_pair(AF_INET6, int_ifname));
  if (socket6 != int_sockets_.end()) {
    int_fds_.erase(std::make_pair(AF_INET6, socket6->second->fd.get()));
    int_sockets_.erase(socket6);
  } else {
    LOG(WARNING) << "IPv6 forwarding is not started between " << lan_ifname_
                 << " and " << int_ifname;
  }
}

void MulticastForwarder::OnFileCanReadWithoutBlocking(int fd,
                                                      sa_family_t sa_family) {
  CHECK(sa_family == AF_INET || sa_family == AF_INET6);

  char data[kBufSize];

  struct sockaddr_storage fromaddr_storage = {0};
  struct sockaddr* fromaddr =
      reinterpret_cast<struct sockaddr*>(&fromaddr_storage);

  socklen_t addrlen = sizeof(struct sockaddr_storage);

  ssize_t r = Receive(fd, data, kBufSize, fromaddr, &addrlen);
  if (r < 0) {
    // Ignore ENETDOWN: this can happen if the interface is not yet configured
    if (errno != ENETDOWN) {
      PLOG(WARNING) << "recvfrom failed";
    }
    return;
  }
  size_t len = static_cast<size_t>(r);

  socklen_t expectlen = sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                             : sizeof(struct sockaddr_in6);
  if (addrlen != expectlen) {
    LOG(WARNING) << "recvfrom failed: src addr length was " << addrlen
                 << " but expected " << expectlen;
    return;
  }

  struct sockaddr_storage dst_storage = {0};
  struct sockaddr* dst = reinterpret_cast<struct sockaddr*>(&dst_storage);
  uint16_t src_port;

  if (sa_family == AF_INET) {
    const struct sockaddr_in* addr4 =
        reinterpret_cast<const struct sockaddr_in*>(fromaddr);
    src_port = ntohs(addr4->sin_port);
  } else if (sa_family == AF_INET6) {
    const struct sockaddr_in6* addr6 =
        reinterpret_cast<const struct sockaddr_in6*>(fromaddr);
    src_port = ntohs(addr6->sin6_port);
  }
  const auto mcast_in_addr = mcast_addr_.ToInAddr();
  const auto mcast_in6_addr = mcast_addr6_.ToIn6Addr();
  SetSockaddr(&dst_storage, sa_family, port_,
              sa_family == AF_INET
                  ? reinterpret_cast<const char*>(&mcast_in_addr)
                  : reinterpret_cast<const char*>(&mcast_in6_addr));

  // Forward ingress traffic to all guests.
  const auto& lan_socket = lan_socket_.find(sa_family);
  if ((lan_socket != lan_socket_.end() && fd == lan_socket->second->fd.get())) {
    SendToGuests(data, len, dst, addrlen);
    return;
  }

  const auto& int_fd = int_fds_.find(std::make_pair(sa_family, fd));
  if (int_fd == int_fds_.end() || lan_socket == lan_socket_.end())
    return;

  // Forward egress traffic from one guest to all other guests.
  // No IP translation is required as other guests can route to each other
  // behind the SNAT setup.
  SendToGuests(data, len, dst, addrlen, fd);

  // On mDNS, sending to physical network requires translating any IPv4
  // address specific to the guest and not visible to the physical network.
  if (sa_family == AF_INET && port_ == kMdnsPort) {
    // TODO(b/132574450) The replacement address should instead be specified
    // as an input argument, based on the properties of the network
    // currently connected on |lan_ifname_|.
    const struct in_addr lan_ip =
        GetInterfaceIp(lan_socket->second->fd.get(), lan_ifname_);
    if (lan_ip.s_addr == htonl(INADDR_ANY)) {
      // When the physical interface has no IPv4 address, IPv4 is not
      // provisioned and there is no point in trying to forward traffic in
      // either direction.
      return;
    }
    TranslateMdnsIp(
        lan_ip, reinterpret_cast<const struct sockaddr_in*>(fromaddr)->sin_addr,
        data, len);
  }

  // Forward egress traffic from one guest to outside network.
  SendTo(src_port, data, len, dst, addrlen);
}

bool MulticastForwarder::SendTo(uint16_t src_port,
                                const void* data,
                                size_t len,
                                const struct sockaddr* dst,
                                socklen_t dst_len) {
  if (src_port == port_) {
    int lan_fd = lan_socket_.find(dst->sa_family)->second->fd.get();
    if (sendto(lan_fd, data, len, 0, dst, dst_len) < 0) {
      // Ignore ENETDOWN: this can happen if the interface is not yet configured
      if (errno != ENETDOWN) {
        PLOG(WARNING) << "sendto " << *dst << " on " << lan_ifname_
                      << " from port " << src_port << " failed";
      }
      return false;
    }
    return true;
  }

  patchpanel::Socket temp_socket(dst->sa_family, SOCK_DGRAM);
  if (!temp_socket.is_valid()) {
    PLOG(ERROR) << "Failed to create UDP socket to forward to " << *dst;
    return false;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, lan_ifname_.c_str(), IFNAMSIZ);
  if (setsockopt(temp_socket.fd(), SOL_SOCKET, SO_BINDTODEVICE, &ifr,
                 sizeof(ifr))) {
    PLOG(ERROR) << "setsockopt(SO_BINDTODEVICE) failed";
    return false;
  }

  int level, optname;
  struct sockaddr_storage bind_addr_storage = {0};
  struct sockaddr* bind_addr = reinterpret_cast<sockaddr*>(&bind_addr_storage);
  if (dst->sa_family == AF_INET) {
    level = IPPROTO_IP;
    optname = IP_MULTICAST_LOOP;
  } else if (dst->sa_family == AF_INET6) {
    level = IPPROTO_IPV6;
    optname = IPV6_MULTICAST_LOOP;
  } else {
    LOG(ERROR) << "Unexpected sa_family " << dst->sa_family;
    return false;
  }
  SetSockaddr(&bind_addr_storage, dst->sa_family, src_port, nullptr);

  int flag = 0;
  if (setsockopt(temp_socket.fd(), level, optname, &flag, sizeof(flag))) {
    PLOG(ERROR) << "setsockopt(IP_MULTICAST_LOOP) failed";
    return false;
  }

  flag = 1;
  if (setsockopt(temp_socket.fd(), SOL_SOCKET, SO_REUSEADDR, &flag,
                 sizeof(flag))) {
    PLOG(ERROR) << "setsockopt(SO_REUSEADDR) failed";
    return false;
  }

  if (!temp_socket.Bind(bind_addr, sizeof(struct sockaddr_storage))) {
    PLOG(ERROR) << "Failed to bind to " << bind_addr_storage;
    return false;
  }

  if (temp_socket.SendTo(data, len, dst, dst_len) < 0) {
    // Ignore ENETDOWN: this can happen if the interface is not yet configured
    if (errno != ENETDOWN) {
      PLOG(WARNING) << "sendto " << *dst << " on " << lan_ifname_
                    << " from port " << src_port << " failed";
    }
    return false;
  }
  return true;
}

bool MulticastForwarder::SendToGuests(const void* data,
                                      size_t len,
                                      const struct sockaddr* dst,
                                      socklen_t dst_len,
                                      int ignore_fd) {
  bool success = true;
  for (const auto& socket : int_sockets_) {
    if (socket.first.first != dst->sa_family)
      continue;
    int fd = socket.second->fd.get();
    if (fd == ignore_fd)
      continue;

    // Use already created multicast fd.
    if (sendto(fd, data, len, 0, dst, dst_len) < 0) {
      PLOG(WARNING) << "sendto " << socket.first.second << " failed";
      success = false;
    }
  }
  return success;
}

// static
void MulticastForwarder::TranslateMdnsIp(const struct in_addr& lan_ip,
                                         const struct in_addr& guest_ip,
                                         char* data,
                                         size_t len) {
  if (guest_ip.s_addr == htonl(INADDR_ANY)) {
    return;
  }

  // Make sure this is a valid, successful DNS response from the Android
  // host.
  if (len > dns_protocol::kMaxUDPSize || len <= 0) {
    return;
  }

  DnsResponse resp;
  memcpy(resp.io_buffer()->data(), data, len);
  if (!resp.InitParseWithoutQuery(len) ||
      !(resp.flags() & dns_protocol::kFlagResponse) ||
      resp.rcode() != dns_protocol::kRcodeNOERROR) {
    return;
  }

  // Check all A records for the internal IP, and replace it with |lan_ip|
  // if it is found.
  DnsRecordParser parser = resp.Parser();
  while (!parser.AtEnd()) {
    const size_t ipv4_addr_len = sizeof(lan_ip.s_addr);

    DnsResourceRecord record;
    if (!parser.ReadRecord(&record)) {
      break;
    }
    if (record.type == dns_protocol::kTypeA &&
        record.rdata.size() == ipv4_addr_len) {
      struct in_addr rr_ip;
      memcpy(&rr_ip, record.rdata.data(), ipv4_addr_len);
      if (guest_ip.s_addr == rr_ip.s_addr) {
        // HACK: This is able to calculate the (variable) offset of the IPv4
        // address inside the resource record by assuming that the
        // StringPiece returns a pointer inside the io_buffer.  It works
        // today, but future libchrome changes might break it.
        // |record|'s data is a pointer into |resp|'s data therefore it is safe
        // to assume that subtraction is a positive number and cast it to size_t
        size_t ip_offset =
            static_cast<size_t>(record.rdata.data() - resp.io_buffer()->data());
        CHECK(ip_offset <= len - ipv4_addr_len);
        memcpy(&data[ip_offset], &lan_ip.s_addr, ipv4_addr_len);
      }
    }
  }
}

ssize_t MulticastForwarder::Receive(int fd,
                                    char* buffer,
                                    size_t buffer_size,
                                    struct sockaddr* src_addr,
                                    socklen_t* addrlen) {
  return recvfrom(fd, buffer, buffer_size, 0, src_addr, addrlen);
}
}  // namespace patchpanel
