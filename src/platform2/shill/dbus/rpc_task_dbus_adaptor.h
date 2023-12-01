// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_RPC_TASK_DBUS_ADAPTOR_H_
#define SHILL_DBUS_RPC_TASK_DBUS_ADAPTOR_H_

#include <map>
#include <string>

#include "dbus_bindings/org.chromium.flimflam.Task.h"
#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_adaptor.h"

namespace shill {

class RpcTask;

// Subclass of DBusAdaptor for RpcTask objects. There is a 1:1 mapping between
// RpcTask and RpcTaskDBusAdaptor instances. Furthermore, the RpcTask
// owns the RpcTaskDBusAdaptor and manages its lifetime, so we're OK
// with RpcTaskDBusAdaptor having a bare pointer to its owner task.
class RpcTaskDBusAdaptor : public org::chromium::flimflam::TaskAdaptor,
                           public org::chromium::flimflam::TaskInterface,
                           public DBusAdaptor,
                           public RpcTaskAdaptorInterface {
 public:
  static const char kPath[];

  RpcTaskDBusAdaptor(const scoped_refptr<dbus::Bus>& bus, RpcTask* task);
  RpcTaskDBusAdaptor(const RpcTaskDBusAdaptor&) = delete;
  RpcTaskDBusAdaptor& operator=(const RpcTaskDBusAdaptor&) = delete;

  ~RpcTaskDBusAdaptor() override;

  // Implementation of RpcTaskAdaptorInterface.
  const RpcIdentifier& GetRpcIdentifier() const override;
  const RpcIdentifier& GetRpcConnectionIdentifier() const override;

  // Implementation of TaskAdaptor
  bool getsec(brillo::ErrorPtr* error,
              std::string* user,
              std::string* password) override;
  bool notify(brillo::ErrorPtr* error,
              const std::string& reason,
              const std::map<std::string, std::string>& dict) override;

 private:
  RpcTask* task_;
  const RpcIdentifier connection_name_;
};

}  // namespace shill

#endif  // SHILL_DBUS_RPC_TASK_DBUS_ADAPTOR_H_
