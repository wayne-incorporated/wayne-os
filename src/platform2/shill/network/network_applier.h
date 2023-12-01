// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_NETWORK_APPLIER_H_
#define SHILL_NETWORK_NETWORK_APPLIER_H_

#include <memory>

#include <base/no_destructor.h>

#include "shill/ipconfig.h"
#include "shill/network/network_priority.h"
#include "shill/resolver.h"

namespace shill {

// A singleton class that provide stateless API for Networks to apply their
// configurations into kernel netdevice, routing table, routing policy table,
// and other components implementing network stack.
class NetworkApplier {
 public:
  virtual ~NetworkApplier();

  // Singleton accessor.
  static NetworkApplier* GetInstance();

  // Helper factory function for test code with dependency injection.
  static std::unique_ptr<NetworkApplier> CreateForTesting(Resolver* resolver);

  // Apply the DNS configuration by writing into /etc/resolv.conf.
  // TODO(b/259354228): dnsproxy will take the ownership of resolv.conf file
  // after b/207657239 is resolved.
  // TODO(b/269401899): Use NetworkConfig as parameter.
  void ApplyDNS(NetworkPriority priority,
                const IPConfig::Properties* ipv4_properties,
                const IPConfig::Properties* ipv6_properties);

 protected:
  NetworkApplier();
  NetworkApplier(const NetworkApplier&) = delete;
  NetworkApplier& operator=(const NetworkApplier&) = delete;

 private:
  friend class base::NoDestructor<NetworkApplier>;

  // Cache singleton pointers for performance and test purposes.
  Resolver* resolver_;
};

}  // namespace shill

#endif  // SHILL_NETWORK_NETWORK_APPLIER_H_
