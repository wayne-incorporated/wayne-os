// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/manager_dbus_adaptor.h"
#include "hermes/context.h"

namespace hermes {

ManagerDBusAdaptor::ManagerDBusAdaptor(Manager* /*manager*/)
    : ManagerAdaptorInterface(this),
      dbus_object_(nullptr,
                   Context::Get()->bus(),
                   org::chromium::Hermes::ManagerAdaptor::GetObjectPath()) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAndBlock();
}

}  // namespace hermes
