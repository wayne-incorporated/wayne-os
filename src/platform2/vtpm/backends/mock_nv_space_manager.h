// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_MOCK_NV_SPACE_MANAGER_H_
#define VTPM_BACKENDS_MOCK_NV_SPACE_MANAGER_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/nv_space_manager.h"

namespace vtpm {

class MockNvSpaceManager : public NvSpaceManager {
 public:
  virtual ~MockNvSpaceManager() = default;

  MOCK_METHOD(trunks::TPM_RC,
              Read,
              (trunks::TPM_NV_INDEX, const std::string&, std::string&),
              (override));

  MOCK_METHOD(trunks::TPM_RC,
              GetDataSize,
              (trunks::TPM_NV_INDEX, trunks::UINT16&),
              (override));

  MOCK_METHOD(trunks::TPM_RC,
              GetAttributes,
              (trunks::TPM_NV_INDEX, trunks::TPMA_NV&),
              (override));

  MOCK_METHOD(trunks::TPM_RC,
              GetNameAlgorithm,
              (trunks::TPM_NV_INDEX, trunks::TPMI_ALG_HASH&),
              (override));

  MOCK_METHOD(trunks::TPM_RC,
              ListHandles,
              (std::vector<trunks::TPM_HANDLE>&),
              (override));
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_MOCK_NV_SPACE_MANAGER_H_
