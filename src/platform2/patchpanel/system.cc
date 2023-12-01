// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/system.h"

#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <base/files/scoped_file.h>
#include <base/logging.h>

#include "patchpanel/net_util.h"

namespace patchpanel {

namespace {

// /proc/sys/ paths and fragments used for System::SysNetSet
// Defines the local port range that is used by TCP and UDP traffic to choose
// the local port (IPv4 and IPv6).
constexpr const char kSysNetIPLocalPortRangePath[] =
    "/proc/sys/net/ipv4/ip_local_port_range";
// Enables/Disables IPv4 forwarding between interfaces.
constexpr const char kSysNetIPv4ForwardingPath[] =
    "/proc/sys/net/ipv4/ip_forward";
// /proc/sys path for controlling connection tracking helper modules
constexpr const char kSysNetConntrackHelperPath[] =
    "/proc/sys/net/netfilter/nf_conntrack_helper";
// Enables/Disables IPv6.
constexpr const char kSysNetDisableIPv6Path[] =
    "/proc/sys/net/ipv6/conf/all/disable_ipv6";
// Prefix for IPv4 interface configuration.
constexpr const char kSysNetIPv4ConfPrefix[] = "/proc/sys/net/ipv4/conf/";
// Suffix for allowing localhost as a source or destination when routing IPv4.
constexpr const char kSysNetIPv4RouteLocalnetSuffix[] = "/route_localnet";
// Enables/Disables IPv6 forwarding between interfaces.
constexpr const char kSysNetIPv6ForwardingPath[] =
    "/proc/sys/net/ipv6/conf/all/forwarding";
// Prefix for IPv6 interface configuration.
constexpr const char kSysNetIPv6ConfPrefix[] = "/proc/sys/net/ipv6/conf/";
// Suffix for accepting Router Advertisements on an interface and
// autoconfiguring it with IPv6 parameters.
constexpr const char kSysNetIPv6AcceptRaSuffix[] = "/accept_ra";
// Enables/Disables IPv6 cross-inteface NDP response.
constexpr const char kSysNetIPv6ProxyNDPPath[] =
    "/proc/sys/net/ipv6/conf/all/proxy_ndp";

constexpr char kTunDev[] = "/dev/net/tun";
}  // namespace

int System::Ioctl(int fd, ioctl_req_t request, const char* argp) {
  return ioctl(fd, request, argp);
}

int System::Ioctl(int fd, ioctl_req_t request, uint64_t arg) {
  return Ioctl(fd, request, reinterpret_cast<const char*>(arg));
}

int System::Ioctl(int fd, ioctl_req_t request, struct ifreq* ifr) {
  return Ioctl(fd, request, reinterpret_cast<const char*>(ifr));
}

int System::Ioctl(int fd, ioctl_req_t request, struct rtentry* route) {
  return Ioctl(fd, request, reinterpret_cast<const char*>(route));
}

int System::SocketPair(int domain, int type, int protocol, int sv[2]) {
  return socketpair(domain, type, protocol, sv);
}

pid_t System::WaitPid(pid_t pid, int* wstatus, int options) {
  return waitpid(pid, wstatus, options);
}

base::ScopedFD System::OpenTunDev() {
  return base::ScopedFD(open(kTunDev, O_RDWR | O_NONBLOCK));
}

bool System::SysNetSet(SysNet target,
                       const std::string& content,
                       const std::string& iface) {
  std::string path;
  switch (target) {
    case SysNet::kIPv4Forward:
      return Write(kSysNetIPv4ForwardingPath, content);
    case SysNet::kIPLocalPortRange:
      return Write(kSysNetIPLocalPortRangePath, content);
    case SysNet::kIPv4RouteLocalnet:
      if (iface.empty()) {
        LOG(ERROR) << "IPv4LocalPortRange requires a valid interface";
        return false;
      }
      return Write(
          kSysNetIPv4ConfPrefix + iface + kSysNetIPv4RouteLocalnetSuffix,
          content);
    case SysNet::kIPv6Forward:
      return Write(kSysNetIPv6ForwardingPath, content);
    case SysNet::kIPv6AcceptRA:
      if (iface.empty()) {
        LOG(ERROR) << "IPv6AcceptRA requires a valid interface";
        return false;
      }
      return Write(kSysNetIPv6ConfPrefix + iface + kSysNetIPv6AcceptRaSuffix,
                   content);
    case SysNet::kConntrackHelper:
      return Write(kSysNetConntrackHelperPath, content);
    case SysNet::kIPv6Disable:
      return Write(kSysNetDisableIPv6Path, content);
    case SysNet::kIPv6ProxyNDP:
      return Write(kSysNetIPv6ProxyNDPPath, content);
  }
}

int System::IfNametoindex(const char* ifname) {
  uint32_t ifindex = if_nametoindex(ifname);
  if (ifindex > INT_MAX) {
    errno = EINVAL;
    return 0;
  }
  return static_cast<int>(ifindex);
}

int System::IfNametoindex(const std::string& ifname) {
  return IfNametoindex(ifname.c_str());
}

char* System::IfIndextoname(int ifindex, char* ifname) {
  if (ifindex < 0) {
    errno = EINVAL;
    return nullptr;
  }
  return if_indextoname(static_cast<uint32_t>(ifindex), ifname);
}

std::string System::IfIndextoname(int ifindex) {
  char ifname[IFNAMSIZ] = {};
  IfIndextoname(ifindex, ifname);
  return ifname;
}

// static
bool System::Write(const std::string& path, const std::string& content) {
  base::ScopedFD fd(open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << path;
    return false;
  }

  if (write(fd.get(), content.c_str(), content.size()) != content.size()) {
    PLOG(ERROR) << "Failed to write \"" << content << "\" to " << path;
    return false;
  }

  return true;
}

}  // namespace patchpanel
