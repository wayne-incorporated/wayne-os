// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/regen_mitigator.h"

#include "login_manager/session_manager_service.h"

#include <base/check.h>

namespace login_manager {

RegenMitigator::RegenMitigator(KeyGenerator* generator)
    : generator_(generator) {
  DCHECK(generator_);
}

RegenMitigator::~RegenMitigator() {}

bool RegenMitigator::Mitigate(const std::string& ownername,
                              const base::Optional<base::FilePath>& ns_path) {
  return mitigating_ = generator_->Start(ownername, ns_path);
}

bool RegenMitigator::Mitigating() {
  return mitigating_;
}

}  // namespace login_manager
