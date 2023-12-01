// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <net/if.h>

#include <set>
#include <string>

#include <base/logging.h>
#include <base/notreached.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "permission_broker/port_tracker.h"

namespace permission_broker {

class FakePortTracker : public PortTracker {
 public:
  FakePortTracker() : PortTracker(nullptr), next_fd_{1} {}
  FakePortTracker(const FakePortTracker&) = delete;
  FakePortTracker& operator=(const FakePortTracker&) = delete;
  ~FakePortTracker() override = default;

  bool ModifyPortRule(patchpanel::Client::FirewallRequestOperation,
                      const PortRule& rule) override {
    return true;
  }
  int AddLifelineFd(int dbus_fd) override { return next_fd_++; }
  bool DeleteLifelineFd(int fd) override { return true; }

 private:
  int next_fd_;
};

// Helper struct for keeping track of randomly generated request.
struct FuzzRequest {
  PortTracker::PortRuleType type;
  patchpanel::Client::FirewallRequestProtocol proto;
  uint16_t port;
  std::string ifname;
};

// Implements a total order for FuzzRequest to insert them in std::set.
bool operator<(const FuzzRequest& lhs, const FuzzRequest& rhs) {
  if (lhs.type != rhs.type) {
    return lhs.type < rhs.type;
  }
  if (lhs.proto != rhs.proto) {
    return lhs.proto < rhs.proto;
  }
  if (lhs.port != rhs.port) {
    return lhs.port < rhs.port;
  }
  return lhs.ifname < rhs.ifname;
}

struct FuzzRequest MakeRandomRequest(FuzzedDataProvider& provider) {
  return {
      .type = provider.ConsumeEnum<PortTracker::PortRuleType>(),
      .proto = provider.ConsumeBool()
                   ? patchpanel::Client::FirewallRequestProtocol::kTcp
                   : patchpanel::Client::FirewallRequestProtocol::kUdp,
      .port = provider.ConsumeIntegral<uint16_t>(),
      .ifname = provider.ConsumeRandomLengthString(IFNAMSIZ - 1),
  };
}

bool AddRule(FuzzedDataProvider& provider,
             FakePortTracker& port_tracker,
             const FuzzRequest& request) {
  int dbus_fd = provider.ConsumeIntegral<int>();
  switch (request.type) {
    case PortTracker::kUnknownRule:
      // Ignore random rule generated with this default type value.
      return false;
    case PortTracker::kAccessRule:
      if (request.proto == patchpanel::Client::FirewallRequestProtocol::kTcp) {
        return port_tracker.AllowTcpPortAccess(request.port, request.ifname,
                                               dbus_fd);
      } else {
        return port_tracker.AllowUdpPortAccess(request.port, request.ifname,
                                               dbus_fd);
      }
    case PortTracker::kLockdownRule:
      if (request.proto == patchpanel::Client::FirewallRequestProtocol::kUdp) {
        // Invalid lockdown rule request, ignore.
        return false;
      }
      return port_tracker.LockDownLoopbackTcpPort(request.port, dbus_fd);
    case PortTracker::kForwardingRule: {
      struct in_addr ip_addr = {.s_addr = provider.ConsumeIntegral<uint32_t>()};
      char buffer[INET_ADDRSTRLEN];
      memset(buffer, 0, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &ip_addr, buffer, INET_ADDRSTRLEN);
      std::string dst_ip = buffer;
      uint16_t dst_port = provider.ConsumeIntegral<uint16_t>();
      if (request.proto == patchpanel::Client::FirewallRequestProtocol::kTcp) {
        return port_tracker.StartTcpPortForwarding(request.port, request.ifname,
                                                   dst_ip, dst_port, dbus_fd);
      } else {
        return port_tracker.StartUdpPortForwarding(request.port, request.ifname,
                                                   dst_ip, dst_port, dbus_fd);
      }
    }
    default:
      NOTREACHED();
      return false;
  }
}

bool RemoveRule(FakePortTracker& port_tracker, const FuzzRequest& request) {
  switch (request.type) {
    case PortTracker::kUnknownRule:
      // Ignore random rule generated with this default type value.
      return false;
    case PortTracker::kAccessRule:
      if (request.proto == patchpanel::Client::FirewallRequestProtocol::kTcp) {
        return port_tracker.RevokeTcpPortAccess(request.port, request.ifname);
      } else {
        return port_tracker.RevokeUdpPortAccess(request.port, request.ifname);
      }
    case PortTracker::kLockdownRule:
      if (request.proto == patchpanel::Client::FirewallRequestProtocol::kUdp) {
        // Invalid lockdown rule request, ignore.
        return false;
      }
      return port_tracker.ReleaseLoopbackTcpPort(request.port);
    case PortTracker::kForwardingRule:
      if (request.proto == patchpanel::Client::FirewallRequestProtocol::kTcp) {
        return port_tracker.StopTcpPortForwarding(request.port, request.ifname);
      } else {
        return port_tracker.StopUdpPortForwarding(request.port, request.ifname);
      }
    default:
      NOTREACHED();
      return false;
  }
}
}  // namespace permission_broker

struct Environment {
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  permission_broker::FakePortTracker port_tracker;
  std::set<permission_broker::FuzzRequest> existing_rules;
  FuzzedDataProvider provider(data, size);

  while (provider.remaining_bytes() > 0) {
    float p = provider.ConsumeProbability<float>();
    if (p < 0.05) {
      // Try removing a non-existing rule 5% of the time.
      while (provider.remaining_bytes() > 0) {
        permission_broker::FuzzRequest r =
            permission_broker::MakeRandomRequest(provider);
        if (existing_rules.find(r) != existing_rules.end()) {
          // Collision with existing rule, retry.
          continue;
        }
        if (RemoveRule(port_tracker, r)) {
          // RemoveRule should fail.
          return -1;
        }
        break;
      }
    } else if (p < 0.10 && !existing_rules.empty()) {
      // Try re-adding an existing rule another 5% of the time.
      auto it = std::begin(existing_rules);
      std::advance(it, provider.ConsumeIntegralInRange<int>(
                           0, existing_rules.size() - 1));
      if (AddRule(provider, port_tracker, *it)) {
        // AddRule should fail.
        return -1;
      }
    } else if (p < existing_rules.size() / 100) {
      // Otherwise either generate a new rule or delete an existing rule.
      // Deletion attempts are more likely the more rules already exist.
      auto it = std::begin(existing_rules);
      std::advance(it, provider.ConsumeIntegralInRange<int>(
                           0, existing_rules.size() - 1));
      if (!RemoveRule(port_tracker, *it)) {
        // RemoveRule should succeed.
        return -1;
      }
      existing_rules.erase(it);
    } else {
      permission_broker::FuzzRequest r =
          permission_broker::MakeRandomRequest(provider);
      // Ignore invalid requests.
      if (AddRule(provider, port_tracker, r)) {
        existing_rules.insert(r);
      }
    }
  }

  return 0;
}
