// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/overalls/overalls_singleton.h"

namespace hwsec {
namespace overalls {

Overalls* OverallsSingleton::overalls_ = nullptr;

Overalls* OverallsSingleton::GetInstance() {
  if (overalls_ == nullptr) {
    overalls_ = new Overalls();
  }
  return overalls_;
}

Overalls* OverallsSingleton::SetInstance(Overalls* ins) {
  Overalls* old_instance = GetInstance();
  overalls_ = ins;
  return old_instance;
}

}  // namespace overalls
}  // namespace hwsec
