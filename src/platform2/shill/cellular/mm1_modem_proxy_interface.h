// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MM1_MODEM_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_MM1_MODEM_PROXY_INTERFACE_H_

#include <string>
#include <vector>

#include "shill/callbacks.h"

namespace shill {
class Error;

namespace mm1 {

using ModemStateChangedSignalCallback =
    base::RepeatingCallback<void(int32_t, int32_t, uint32_t)>;

// These are the methods that a org.freedesktop.ModemManager1.Modem
// proxy must support. The interface is provided so that it can be
// mocked in tests. All calls are made asynchronously. Call completion
// is signalled via the callbacks passed to the methods.
class ModemProxyInterface {
 public:
  virtual ~ModemProxyInterface() = default;

  virtual void Enable(bool enable, ResultCallback callback, int timeout) = 0;
  virtual void CreateBearer(const KeyValueStore& properties,
                            RpcIdentifierCallback callback,
                            int timeout) = 0;
  virtual void DeleteBearer(const RpcIdentifier& bearer,
                            ResultCallback callback,
                            int timeout) = 0;
  virtual void Reset(ResultCallback callback, int timeout) = 0;
  virtual void FactoryReset(const std::string& code,
                            ResultCallback callback,
                            int timeout) = 0;
  virtual void SetCurrentCapabilities(uint32_t capabilities,
                                      ResultCallback callback,
                                      int timeout) = 0;
  virtual void SetCurrentModes(uint32_t allowed_modes,
                               uint32_t preferred_mode,
                               ResultCallback callback,
                               int timeout) = 0;
  virtual void SetCurrentBands(const std::vector<uint32_t>& bands,
                               ResultCallback callback,
                               int timeout) = 0;
  virtual void SetPrimarySimSlot(uint32_t slot,
                                 ResultCallback callback,
                                 int timeout) = 0;
  virtual void Command(const std::string& cmd,
                       uint32_t user_timeout,
                       StringCallback callback,
                       int timeout) = 0;
  virtual void SetPowerState(uint32_t power_state,
                             ResultCallback callback,
                             int timeout) = 0;

  virtual void set_state_changed_callback(
      const ModemStateChangedSignalCallback& callback) = 0;
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MM1_MODEM_PROXY_INTERFACE_H_
