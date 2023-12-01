// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MANAGER_DBUS_ADAPTOR_H_
#define HERMES_MANAGER_DBUS_ADAPTOR_H_

#include "hermes/adaptor_interfaces.h"

namespace hermes {

class Manager;

class ManagerDBusAdaptor : public org::chromium::Hermes::ManagerInterface,
                           public ManagerAdaptorInterface {
 public:
  explicit ManagerDBusAdaptor(Manager* /*manager*/);
  ManagerDBusAdaptor(const ManagerDBusAdaptor&) = delete;
  ManagerDBusAdaptor& operator=(const ManagerDBusAdaptor&) = delete;

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
};

}  // namespace hermes

#endif  // HERMES_MANAGER_DBUS_ADAPTOR_H_
