// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_TPM_NVRAM_INTERFACE_H_
#define TPM_MANAGER_SERVER_MOCK_TPM_NVRAM_INTERFACE_H_

#include <gmock/gmock.h>

#include "tpm_manager/server/tpm_nvram_interface.h"

namespace tpm_manager {

class MockTpmNvramInterface : public TpmNvramInterface {
 public:
  MockTpmNvramInterface();
  ~MockTpmNvramInterface() override;

  MOCK_METHOD(void,
              DefineSpace,
              (const DefineSpaceRequest&, DefineSpaceCallback),
              (override));
  MOCK_METHOD(void,
              DestroySpace,
              (const DestroySpaceRequest&, DestroySpaceCallback),
              (override));
  MOCK_METHOD(void,
              WriteSpace,
              (const WriteSpaceRequest&, WriteSpaceCallback),
              (override));
  MOCK_METHOD(void,
              ReadSpace,
              (const ReadSpaceRequest&, ReadSpaceCallback),
              (override));
  MOCK_METHOD(void,
              LockSpace,
              (const LockSpaceRequest&, LockSpaceCallback),
              (override));
  MOCK_METHOD(void,
              ListSpaces,
              (const ListSpacesRequest&, ListSpacesCallback),
              (override));
  MOCK_METHOD(void,
              GetSpaceInfo,
              (const GetSpaceInfoRequest&, GetSpaceInfoCallback),
              (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_TPM_NVRAM_INTERFACE_H_
