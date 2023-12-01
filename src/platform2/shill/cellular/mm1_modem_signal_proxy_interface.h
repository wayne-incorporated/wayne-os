// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MM1_MODEM_SIGNAL_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_MM1_MODEM_SIGNAL_PROXY_INTERFACE_H_

#include <string>

#include "shill/callbacks.h"

namespace shill {
class Error;

namespace mm1 {

// These are the methods that a
// org.freedesktop.ModemManager1.Modem.Signal proxy must support.
// The interface is provided so that it can be mocked in tests.
// All calls are made asynchronously. Call completion is signalled via
// the callbacks passed to the methods.
class ModemSignalProxyInterface {
 public:
  virtual ~ModemSignalProxyInterface() = default;

  virtual void Setup(const int rate,
                     Error* error,
                     ResultCallback callback,
                     int timeout) = 0;

  virtual void SetupThresholds(const KeyValueStore& settings,
                               Error* error,
                               ResultCallback callback,
                               int timeout) = 0;
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MM1_MODEM_SIGNAL_PROXY_INTERFACE_H_
