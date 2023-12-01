// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/global_context.h"

#include <optional>

#include <base/check.h>
#include <base/logging.h>
#include <vboot/crossystem.h>

namespace imageloader {

// static
GlobalContext* GlobalContext::g_ctx_ = nullptr;

// static
GlobalContext* GlobalContext::Current() {
  CHECK(g_ctx_ != nullptr) << "The GlobalContext has not been set yet!";
  return g_ctx_;
}

void GlobalContext::SetAsCurrent() {
  g_ctx_ = this;
}

bool GlobalContext::IsOfficialBuild() const {
  // TODO(ahassani): Save this value in an `std::optional` instance so we don't
  // have to query this several times during the runtime.
  return VbGetSystemPropertyInt("debug_build") == 0;
}

}  // namespace imageloader
