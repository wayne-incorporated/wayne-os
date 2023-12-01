// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "runtime_probe/system/context_factory_impl.h"
#include "runtime_probe/system/helper_invoker_direct_impl.h"

namespace runtime_probe {
ContextFactoryImpl::ContextFactoryImpl() {
  CHECK(SetupDBusServices()) << "Cannot setup dbus service";

  helper_invoker_ = std::make_unique<HelperInvokerDirectImpl>();
}

}  // namespace runtime_probe
