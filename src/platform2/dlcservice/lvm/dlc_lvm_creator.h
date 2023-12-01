// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_LVM_DLC_LVM_CREATOR_H_
#define DLCSERVICE_LVM_DLC_LVM_CREATOR_H_

#include <memory>

#include "dlcservice/dlc_creator_interface.h"
#include "dlcservice/dlc_interface.h"

namespace dlcservice {

class DlcLvmCreator : public DlcCreatorInterface {
 public:
  DlcLvmCreator() = default;
  ~DlcLvmCreator() = default;

  DlcLvmCreator(const DlcLvmCreator&) = delete;
  DlcLvmCreator& operator=(const DlcLvmCreator&) = delete;

  std::unique_ptr<DlcInterface> Create(const DlcId&) override;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_LVM_DLC_LVM_CREATOR_H_
