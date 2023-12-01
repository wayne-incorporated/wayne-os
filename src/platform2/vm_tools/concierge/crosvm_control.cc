// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/crosvm_control.h"

#include <utility>

#include <absl/base/call_once.h>

#include "vm_tools/concierge/crosvm_control_impl.h"

namespace vm_tools::concierge {
namespace {
absl::once_flag g_instance_init;
std::unique_ptr<CrosvmControl> g_instance;
}  // namespace

CrosvmControl* CrosvmControl::Get() {
  absl::call_once(g_instance_init, []() {
    if (!g_instance) {
      CrosvmControlImpl::Init();
    }
  });

  return g_instance.get();
}

void CrosvmControl::Reset() {
  g_instance.reset();
}

void CrosvmControl::SetInstance(std::unique_ptr<CrosvmControl> instance) {
  g_instance = std::move(instance);
}

}  // namespace vm_tools::concierge
