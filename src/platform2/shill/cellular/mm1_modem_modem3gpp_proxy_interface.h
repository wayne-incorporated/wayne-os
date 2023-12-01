// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MM1_MODEM_MODEM3GPP_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_MM1_MODEM_MODEM3GPP_PROXY_INTERFACE_H_

#include <string>

#include "shill/callbacks.h"

namespace shill {
class Error;

namespace mm1 {

// These are the methods that a
// org.freedesktop.ModemManager1.Modem.Modem3gpp proxy must support.
// The interface is provided so that it can be mocked in tests.
// All calls are made asynchronously. Call completion is signalled via
// the callbacks passed to the methods.
class ModemModem3gppProxyInterface {
 public:
  virtual ~ModemModem3gppProxyInterface() = default;

  virtual void Register(const std::string& operator_id,
                        ResultCallback callback) = 0;
  virtual void Scan(KeyValueStoresCallback callback) = 0;
  virtual void SetInitialEpsBearerSettings(const KeyValueStore& properties,
                                           ResultCallback callback) = 0;
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MM1_MODEM_MODEM3GPP_PROXY_INTERFACE_H_
