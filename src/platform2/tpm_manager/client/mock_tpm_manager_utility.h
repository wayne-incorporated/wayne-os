// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_CLIENT_MOCK_TPM_MANAGER_UTILITY_H_
#define TPM_MANAGER_CLIENT_MOCK_TPM_MANAGER_UTILITY_H_

#include "tpm_manager/client/tpm_manager_utility.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace tpm_manager {

class TPM_MANAGER_EXPORT MockTpmManagerUtility : public TpmManagerUtility {
 public:
  MockTpmManagerUtility() {
    using ::testing::_;
    using ::testing::Return;
    ON_CALL(*this, Initialize()).WillByDefault(Return(true));
    ON_CALL(*this, TakeOwnership()).WillByDefault(Return(true));
    ON_CALL(*this, GetTpmStatus(_, _, _)).WillByDefault(Return(true));
    ON_CALL(*this, GetTpmNonsensitiveStatus(_, _, _, _))
        .WillByDefault(Return(true));
    ON_CALL(*this, GetVersionInfo(_, _, _, _, _, _))
        .WillByDefault(Return(true));
    ON_CALL(*this, RemoveOwnerDependency(_)).WillByDefault(Return(true));
    ON_CALL(*this, ClearStoredOwnerPassword()).WillByDefault(Return(true));
    ON_CALL(*this, GetDictionaryAttackInfo(_, _, _, _))
        .WillByDefault(Return(true));
    ON_CALL(*this, ResetDictionaryAttackLock()).WillByDefault(Return(true));
    ON_CALL(*this, DefineSpace(_, _, _, _, _)).WillByDefault(Return(true));
    ON_CALL(*this, DestroySpace(_)).WillByDefault(Return(true));
    ON_CALL(*this, WriteSpace(_, _, _)).WillByDefault(Return(true));
    ON_CALL(*this, ReadSpace(_, _, _)).WillByDefault(Return(true));
    ON_CALL(*this, ListSpaces(_)).WillByDefault(Return(true));
    ON_CALL(*this, GetSpaceInfo(_, _, _, _, _)).WillByDefault(Return(true));
    ON_CALL(*this, LockSpace(_)).WillByDefault(Return(true));
    ON_CALL(*this, GetOwnershipTakenSignalStatus(_, _, _))
        .WillByDefault(Return(true));
  }
  ~MockTpmManagerUtility() override = default;

  MOCK_METHOD(bool, Initialize, (), (override));
  MOCK_METHOD(bool, TakeOwnership, (), (override));
  MOCK_METHOD(bool, GetTpmStatus, (bool*, bool*, LocalData*), (override));
  MOCK_METHOD(bool,
              GetTpmNonsensitiveStatus,
              (bool*, bool*, bool*, bool*),
              (override));
  MOCK_METHOD(
      bool,
      GetVersionInfo,
      (uint32_t*, uint64_t*, uint32_t*, uint32_t*, uint64_t*, std::string*),
      (override));
  MOCK_METHOD(bool, RemoveOwnerDependency, (const std::string&), (override));
  MOCK_METHOD(bool, ClearStoredOwnerPassword, (), (override));
  MOCK_METHOD(bool,
              GetDictionaryAttackInfo,
              (int*, int*, bool*, int*),
              (override));
  MOCK_METHOD(bool, ResetDictionaryAttackLock, (), (override));
  MOCK_METHOD(bool,
              DefineSpace,
              (uint32_t, size_t, bool, bool, bool),
              (override));
  MOCK_METHOD(bool, DestroySpace, (uint32_t), (override));
  MOCK_METHOD(bool,
              WriteSpace,
              (uint32_t, const std::string&, bool),
              (override));
  MOCK_METHOD(bool, ReadSpace, (uint32_t, bool, std::string*), (override));
  MOCK_METHOD(bool, ListSpaces, (std::vector<uint32_t>*), (override));
  MOCK_METHOD(
      bool,
      GetSpaceInfo,
      (uint32_t, uint32_t*, bool*, bool*, std::vector<NvramSpaceAttribute>*),
      (override));
  MOCK_METHOD(bool, LockSpace, (uint32_t), (override));
  MOCK_METHOD(bool,
              GetOwnershipTakenSignalStatus,
              (bool*, bool*, LocalData*),
              (override));
  MOCK_METHOD(void, AddOwnershipCallback, (OwnershipCallback), (override));
  MOCK_METHOD(void,
              OnOwnershipTaken,
              (const OwnershipTakenSignal&),
              (override));
  MOCK_METHOD(void,
              OnSignalConnected,
              (const std::string&, const std::string&, bool),
              (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_CLIENT_MOCK_TPM_MANAGER_UTILITY_H_
