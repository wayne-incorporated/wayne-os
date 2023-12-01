// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MM1_MODEM_SIMPLE_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_MM1_MODEM_SIMPLE_PROXY_INTERFACE_H_

#include <string>

#include "shill/callbacks.h"
#include "shill/store/key_value_store.h"

namespace shill {
class Error;

namespace mm1 {

// These are the methods that a
// org.freedesktop.ModemManager1.Modem.Simple proxy must support.  The
// interface is provided so that it can be mocked in tests.  All calls
// are made asynchronously. Call completion is signalled via the callbacks
// passed to the methods.
class ModemSimpleProxyInterface {
 public:
  virtual ~ModemSimpleProxyInterface() = default;

  virtual void Connect(const KeyValueStore& properties,
                       RpcIdentifierCallback callback,
                       int timeout) = 0;
  virtual void Disconnect(const RpcIdentifier& bearer,
                          ResultCallback callback,
                          int timeout) = 0;
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MM1_MODEM_SIMPLE_PROXY_INTERFACE_H_
