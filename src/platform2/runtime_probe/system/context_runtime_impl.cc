// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/check.h>

#include "runtime_probe/system/context_runtime_impl.h"
#include "runtime_probe/system/helper_invoker_debugd_impl.h"

namespace runtime_probe {
ContextRuntimeImpl::ContextRuntimeImpl() {
  CHECK(SetupDBusServices()) << "Cannot setup dbus service";

  helper_invoker_ = std::make_unique<HelperInvokerDebugdImpl>();
}

}  // namespace runtime_probe
