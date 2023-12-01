// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_TPM_NVRAM_H_
#define TPM_MANAGER_SERVER_MOCK_TPM_NVRAM_H_

#include "tpm_manager/server/tpm_nvram.h"

#include <map>
#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace tpm_manager {

struct NvSpace {
  std::string data;
  bool read_locked;
  bool write_locked;
  std::vector<NvramSpaceAttribute> attributes;
  std::string authorization_value;
  NvramSpacePolicy policy;
};

class MockTpmNvram : public TpmNvram {
 public:
  MockTpmNvram();
  ~MockTpmNvram() override;

  MOCK_METHOD(NvramResult,
              DefineSpace,
              (uint32_t,
               size_t,
               const std::vector<NvramSpaceAttribute>&,
               const std::string&,
               NvramSpacePolicy),
              (override));
  MOCK_METHOD(NvramResult, DestroySpace, (uint32_t), (override));
  MOCK_METHOD(NvramResult,
              WriteSpace,
              (uint32_t, const std::string&, const std::string&),
              (override));
  MOCK_METHOD(NvramResult,
              ReadSpace,
              (uint32_t, std::string*, const std::string&),
              (override));
  MOCK_METHOD(NvramResult,
              LockSpace,
              (uint32_t, bool, bool, const std::string&),
              (override));
  MOCK_METHOD(NvramResult, ListSpaces, (std::vector<uint32_t>*), (override));
  MOCK_METHOD(NvramResult,
              GetSpaceInfo,
              (uint32_t,
               uint32_t*,
               bool*,
               bool*,
               std::vector<NvramSpaceAttribute>*,
               NvramSpacePolicy*),
              (override));
  MOCK_METHOD(void, PrunePolicies, (), (override));

 private:
  NvramResult FakeDefineSpace(
      uint32_t index,
      size_t size,
      const std::vector<NvramSpaceAttribute>& attributes,
      const std::string& authorization_value,
      NvramSpacePolicy policy);
  NvramResult FakeDestroySpace(uint32_t index);
  NvramResult FakeWriteSpace(uint32_t index,
                             const std::string& data,
                             const std::string& authorization_value);
  NvramResult FakeReadSpace(uint32_t index,
                            std::string* data,
                            const std::string& authorization_value);
  NvramResult FakeLockSpace(uint32_t index,
                            bool lock_read,
                            bool lock_write,
                            const std::string& authorization_value);
  NvramResult FakeListSpaces(std::vector<uint32_t>* index_list);
  NvramResult FakeGetSpaceInfo(uint32_t index,
                               uint32_t* size,
                               bool* is_read_locked,
                               bool* is_write_locked,
                               std::vector<NvramSpaceAttribute>* attributes,
                               NvramSpacePolicy* policy);

  std::map<uint32_t, NvSpace> nvram_map_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_TPM_NVRAM_H_
