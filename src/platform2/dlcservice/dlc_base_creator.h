// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_DLC_BASE_CREATOR_H_
#define DLCSERVICE_DLC_BASE_CREATOR_H_

#include <memory>

#include "dlcservice/dlc_creator_interface.h"
#include "dlcservice/dlc_interface.h"

namespace dlcservice {

class DlcBaseCreator : public DlcCreatorInterface {
 public:
  DlcBaseCreator() = default;
  ~DlcBaseCreator() = default;

  DlcBaseCreator(const DlcBaseCreator&) = delete;
  DlcBaseCreator& operator=(const DlcBaseCreator&) = delete;

  std::unique_ptr<DlcInterface> Create(const DlcId&) override;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_DLC_BASE_CREATOR_H_
