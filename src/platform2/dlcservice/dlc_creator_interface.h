// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_DLC_CREATOR_INTERFACE_H_
#define DLCSERVICE_DLC_CREATOR_INTERFACE_H_

#include <memory>

#include "dlcservice/dlc_interface.h"
#include "dlcservice/types.h"

namespace dlcservice {

class DlcCreatorInterface {
 public:
  DlcCreatorInterface() = default;
  virtual ~DlcCreatorInterface() = default;

  DlcCreatorInterface(const DlcCreatorInterface&) = delete;
  DlcCreatorInterface& operator=(const DlcCreatorInterface&) = delete;

  // Generic creation method.
  virtual std::unique_ptr<DlcInterface> Create(const DlcId&) = 0;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_DLC_CREATOR_INTERFACE_H_
