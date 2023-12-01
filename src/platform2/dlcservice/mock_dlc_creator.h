// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_MOCK_DLC_CREATOR_H_
#define DLCSERVICE_MOCK_DLC_CREATOR_H_

#include <memory>

#include "dlcservice/dlc_creator_interface.h"
#include "dlcservice/dlc_interface.h"
#include "dlcservice/types.h"

namespace dlcservice {

class MockDlcCreator : public DlcCreatorInterface {
 public:
  MockDlcCreator() = default;

  MockDlcCreator(const MockDlcCreator&) = delete;
  MockDlcCreator& operator=(const MockDlcCreator&) = delete;

  MOCK_METHOD(std::unique_ptr<DlcInterface>,
              Create,
              (const DlcId&),
              (override));
};

}  // namespace dlcservice

#endif  // DLCSERVICE_MOCK_DLC_CREATOR_H_
