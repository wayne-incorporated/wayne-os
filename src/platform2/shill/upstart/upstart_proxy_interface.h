// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_UPSTART_UPSTART_PROXY_INTERFACE_H_
#define SHILL_UPSTART_UPSTART_PROXY_INTERFACE_H_

#include <string>
#include <vector>

namespace shill {

// This class provides access for sending events to upstart.
// Call ProxyFactory::CreateUpstartProxy() to create an instance of this
// proxy.
class UpstartProxyInterface {
 public:
  virtual ~UpstartProxyInterface() = default;

  // Sends a request to upstart to propagate an event.
  virtual void EmitEvent(const std::string& name,
                         const std::vector<std::string>& env,
                         bool wait) = 0;
};

}  // namespace shill

#endif  // SHILL_UPSTART_UPSTART_PROXY_INTERFACE_H_
