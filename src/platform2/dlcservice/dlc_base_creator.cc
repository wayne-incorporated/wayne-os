// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/dlc_base_creator.h"

#include <memory>

#include "dlcservice/dlc_base.h"
#include "dlcservice/dlc_interface.h"

namespace dlcservice {

std::unique_ptr<DlcInterface> DlcBaseCreator::Create(const DlcId& id) {
  return std::make_unique<DlcBase>(id);
}

}  // namespace dlcservice
