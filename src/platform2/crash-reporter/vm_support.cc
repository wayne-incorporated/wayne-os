// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/vm_support.h"

#include "base/files/file_path.h"
#include "base/no_destructor.h"

#if USE_KVM_GUEST
#include "crash-reporter/vm_support_proper.h"
#endif  // USE_KVM_GUEST

namespace {

VmSupport* g_vm_support_test_override = nullptr;

}  // namespace

VmSupport::~VmSupport() = default;

// static
void VmSupport::SetForTesting(VmSupport* vm_support) {
  g_vm_support_test_override = vm_support;
}

// static
VmSupport* VmSupport::Get() {
  if (g_vm_support_test_override != nullptr) {
    return g_vm_support_test_override;
  }
#if USE_KVM_GUEST
  static base::NoDestructor<VmSupportProper> instance;
  return instance.get();
#else
  return nullptr;
#endif  // USE_KVM_GUEST
}
