// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MM1_SIM_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_MM1_SIM_PROXY_INTERFACE_H_

#include <string>

#include "shill/callbacks.h"

namespace shill {
namespace mm1 {

// These are the methods that a org.freedesktop.ModemManager1.Sim
// proxy must support. The interface is provided so that it can be
// mocked in tests. All calls are made asynchronously. Call completion
// is signalled via the callbacks passed to the methods.
class SimProxyInterface {
 public:
  virtual ~SimProxyInterface() = default;

  virtual void SendPin(const std::string& pin, ResultCallback callback) = 0;
  virtual void SendPuk(const std::string& puk,
                       const std::string& pin,
                       ResultCallback callback) = 0;
  virtual void EnablePin(const std::string& pin,
                         const bool enabled,
                         ResultCallback callback) = 0;
  virtual void ChangePin(const std::string& old_pin,
                         const std::string& new_pin,
                         ResultCallback callback) = 0;
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MM1_SIM_PROXY_INTERFACE_H_
