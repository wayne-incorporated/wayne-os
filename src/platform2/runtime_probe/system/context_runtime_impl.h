// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_CONTEXT_RUNTIME_IMPL_H_
#define RUNTIME_PROBE_SYSTEM_CONTEXT_RUNTIME_IMPL_H_

#include "runtime_probe/system/context_impl.h"

namespace runtime_probe {

class ContextRuntimeImpl : public ContextImpl {
 public:
  ContextRuntimeImpl();
  ~ContextRuntimeImpl() override = default;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_CONTEXT_RUNTIME_IMPL_H_
