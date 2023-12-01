// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/shims/task_proxy.h"

#include <base/logging.h>

namespace shill {

namespace shims {

TaskProxy::TaskProxy(scoped_refptr<dbus::Bus> bus,
                     const std::string& path,
                     const std::string& service)
    : proxy_(bus, dbus::ObjectPath(path)) {}

TaskProxy::~TaskProxy() = default;

void TaskProxy::Notify(const std::string& reason,
                       const std::map<std::string, std::string>& dict) {
  LOG(INFO) << __func__ << "(" << reason << ", argcount: " << dict.size()
            << ")";
  brillo::ErrorPtr error;
  if (!proxy_.notify(reason, dict, &error)) {
    LOG(ERROR) << "DBus error: " << error->GetCode() << ": "
               << error->GetMessage();
  }
}

bool TaskProxy::GetSecret(std::string* username, std::string* password) {
  LOG(INFO) << __func__;
  brillo::ErrorPtr error;
  if (!proxy_.getsec(username, password, &error)) {
    LOG(ERROR) << "DBus error: " << error->GetCode() << ": "
               << error->GetMessage();
    return false;
  }
  return true;
}

}  // namespace shims

}  // namespace shill
