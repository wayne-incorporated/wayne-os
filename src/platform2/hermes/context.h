// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_CONTEXT_H_
#define HERMES_CONTEXT_H_

#include <base/check.h>
#include <base/files/file_path.h>
#include <dbus/bus.h>
#include <google-lpa/lpa/core/lpa.h>

#include "hermes/adaptor_factory_interface.h"
#include "hermes/modem_control_interface.h"

namespace hermes {

class Executor;

// Top-level context singleton for access to common context like google-lpa Lpa
// instance and D-Bus bus.
//
// This should be the sole implicit dependency for classes in Hermes.
class Context {
 public:
  // Initializes Context singleton. Must only be invoked once, and must be
  // invoked prior to clients calling Get().
  static void Initialize(const scoped_refptr<dbus::Bus>& bus,
                         lpa::core::Lpa* lpa,
                         Executor* executor,
                         AdaptorFactoryInterface* adaptor_factory,
                         ModemControlInterface* modem_control,
                         base::FilePath fw_path);
  // Returns initialized Context singleton. Initialize() must have been invoked
  // prior to calls to this.
  static Context* Get() {
    CHECK(context_);
    return context_;
  }

  const scoped_refptr<dbus::Bus>& bus() { return bus_; }
  lpa::core::Lpa* lpa() { return lpa_; }
  Executor* executor() { return executor_; }
  AdaptorFactoryInterface* adaptor_factory() { return adaptor_factory_; }
  ModemControlInterface* modem_control() { return modem_control_; }
  base::FilePath fw_path_;
  bool dbus_ongoing_ = false;

 private:
  Context(const scoped_refptr<dbus::Bus>& bus,
          lpa::core::Lpa* lpa,
          Executor* executor,
          AdaptorFactoryInterface* adaptor_factory,
          ModemControlInterface* modem_control,
          base::FilePath fw_path);
  Context(const Context&) = delete;
  Context& operator=(const Context&) = delete;

  static Context* context_;

  scoped_refptr<dbus::Bus> bus_;
  lpa::core::Lpa* lpa_;
  Executor* executor_;
  AdaptorFactoryInterface* adaptor_factory_;
  ModemControlInterface* modem_control_;
};

}  // namespace hermes

#endif  // HERMES_CONTEXT_H_
