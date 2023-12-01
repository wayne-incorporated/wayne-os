// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_FAKE_SYSTEM_H_
#define PATCHPANEL_FAKE_SYSTEM_H_

#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>

#include <string>
#include <utility>
#include <vector>

#include <base/files/scoped_file.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "patchpanel/system.h"

namespace patchpanel {
class FakeSystem : public System {
 public:
  FakeSystem() = default;
  ~FakeSystem() = default;

  // Capture Ioctls operations and arguments. Always succeeds.
  int Ioctl(int fd, ioctl_req_t request, const char* argp) override {
    ioctl_reqs.push_back(request);
    switch (request) {
      case SIOCBRADDBR:
      case SIOCBRDELBR: {
        ioctl_ifreq_args.push_back({std::string(argp), {}});
        break;
      }
      case SIOCBRADDIF:
      case TUNSETIFF:
      case SIOCSIFADDR:
      case SIOCSIFNETMASK:
      case SIOCSIFHWADDR:
      case SIOCGIFFLAGS:
      case SIOCSIFFLAGS: {
        struct ifreq ifr;
        memcpy(&ifr, argp, sizeof(ifr));
        ioctl_ifreq_args.push_back({std::string(ifr.ifr_name), ifr});
        break;
      }
      case SIOCADDRT:
      case SIOCDELRT: {
        struct rtentry route;
        memcpy(&route, argp, sizeof(route));
        ioctl_rtentry_args.push_back({"", route});
        // Copy the string pointed by rtentry.rt_dev because Add/DeleteIPv4Route
        // pass this value to ioctl() on the stack.
        if (route.rt_dev) {
          auto& cap = ioctl_rtentry_args.back();
          cap.first = std::string(route.rt_dev);
          cap.second.rt_dev = const_cast<char*>(cap.first.c_str());
        }
        break;
      }
      case TUNSETPERSIST:
      case TUNSETOWNER: {
        // ioctl_u32_args.push_back(static_cast<uint32_t>(argp));
        break;
      }
    }
    return 0;
  }

  base::ScopedFD OpenTunDev() override {
    return base::ScopedFD(open("/dev/null", O_RDONLY | O_CLOEXEC));
  }

  MOCK_METHOD(int, SocketPair, (int, int, int, int[2]), (override));
  MOCK_METHOD3(SysNetSet,
               bool(SysNet target,
                    const std::string& content,
                    const std::string& iface));
  MOCK_METHOD1(IfNametoindex, int(const std::string& ifname));
  MOCK_METHOD1(IfIndextoname, std::string(int ifindex));

  std::vector<ioctl_req_t> ioctl_reqs;
  std::vector<std::pair<std::string, struct rtentry>> ioctl_rtentry_args;
  std::vector<std::pair<std::string, struct ifreq>> ioctl_ifreq_args;
  std::vector<uint32_t> ioctl_u32_args;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_FAKE_SYSTEM_H_
