// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "hermes/context.h"

#include <base/check.h>

namespace hermes {

// static
Context* Context::context_ = nullptr;

// static
void Context::Initialize(const scoped_refptr<dbus::Bus>& bus,
                         lpa::core::Lpa* lpa,
                         Executor* executor,
                         AdaptorFactoryInterface* adaptor_factory,
                         ModemControlInterface* modem_control,
                         base::FilePath fw_path) {
  CHECK(!context_);
  context_ = new Context(bus, lpa, executor, adaptor_factory, modem_control,
                         std::move(fw_path));
}

Context::Context(const scoped_refptr<dbus::Bus>& bus,
                 lpa::core::Lpa* lpa,
                 Executor* executor,
                 AdaptorFactoryInterface* adaptor_factory,
                 ModemControlInterface* modem_control,
                 base::FilePath fw_path)
    : fw_path_(std::move(fw_path)),
      bus_(bus),
      lpa_(lpa),
      executor_(executor),
      adaptor_factory_(adaptor_factory),
      modem_control_(modem_control) {}

}  // namespace hermes
