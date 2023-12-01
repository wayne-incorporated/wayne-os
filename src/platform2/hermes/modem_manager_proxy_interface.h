// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MODEM_MANAGER_PROXY_INTERFACE_H_
#define HERMES_MODEM_MANAGER_PROXY_INTERFACE_H_

#include <string>

#include "hermes/hermes_common.h"

namespace hermes {

class ModemManagerProxyInterface {
 public:
  // cb is executed when a new modem appears on DBus. Executed only once.
  virtual void RegisterModemAppearedCallback(base::OnceClosure cb) = 0;
  // If MM has exported a DBus object, executes cb immediately. If not,
  // waits for MM to export a DBus object.
  virtual void WaitForModem(base::OnceClosure cb) = 0;

  virtual std::string GetMbimPort() const = 0;

  virtual void ScheduleUninhibit(base::TimeDelta timeout) = 0;
  virtual void WaitForModemAndInhibit(ResultCallback cb) = 0;
  virtual ~ModemManagerProxyInterface() = default;
};
}  // namespace hermes

#endif  // HERMES_MODEM_MANAGER_PROXY_INTERFACE_H_
