// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_SERVER_H_
#define DISCOD_SERVER_H_

#include <memory>

#include <base/memory/ref_counted.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/bus.h>

#include "discod/control_loop.h"
#include "discod/dbus_adaptors/org.chromium.Discod.h"

namespace discod {

class Server : public org::chromium::DiscodAdaptor,
               public org::chromium::DiscodInterface {
 public:
  Server(scoped_refptr<dbus::Bus> bus,
         std::unique_ptr<ControlLoop> control_loop);
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;
  ~Server() override;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  void EnableWriteBoost() override;

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
  std::unique_ptr<ControlLoop> control_loop_;
};

}  // namespace discod

#endif  // DISCOD_SERVER_H_
