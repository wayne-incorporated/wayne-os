// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/lvm/dlc_lvm_creator.h"

#include <memory>

#include "dlcservice/dlc_interface.h"
#include "dlcservice/lvm/dlc_lvm.h"

namespace dlcservice {

std::unique_ptr<DlcInterface> DlcLvmCreator::Create(const DlcId& id) {
  return std::make_unique<DlcLvm>(id);
}

}  // namespace dlcservice
