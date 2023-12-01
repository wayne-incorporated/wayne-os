// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>
#include <trunks/mock_tpm_utility.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using tpm_manager::NvramResult;
using tpm_manager::NvramSpaceAttribute;
using tpm_manager::TpmManagerStatus;

namespace {
constexpr uint32_t kFwmpIndex = 0x100a;
constexpr uint32_t kInstallAttributesIndex =
    USE_TPM_DYNAMIC ? 0x9da5b0 : 0x800004;
constexpr uint32_t kEnterpriseRollbackIndex = 0x100e;
}  // namespace

namespace hwsec {

using BackendStorageTpm2Test = BackendTpm2TestBase;

TEST_F(BackendStorageTpm2Test, IsReady) {
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kInstallAttributesIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(10);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PERSISTENT_WRITE_LOCK);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  tpm_manager::RemoveOwnerDependencyReply remove_reply;
  remove_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              RemoveOwnerDependency(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(remove_reply), Return(true)));

  auto result = backend_->GetStorageTpm2().IsReady(Space::kInstallAttributes);
  ASSERT_OK(result);
  EXPECT_FALSE(result->preparable);
  EXPECT_TRUE(result->readable);
  EXPECT_TRUE(result->writable);
}

TEST_F(BackendStorageTpm2Test, IsReadyPreparable) {
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kInstallAttributesIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(10);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(true);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  auto result = backend_->GetStorageTpm2().IsReady(Space::kInstallAttributes);
  ASSERT_OK(result);
  EXPECT_TRUE(result->preparable);
  EXPECT_TRUE(result->destroyable);
}

TEST_F(BackendStorageTpm2Test, IsReadyNotAvailable) {
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kInstallAttributesIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(10);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(true);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(false);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  EXPECT_THAT(backend_->GetStorageTpm2().IsReady(Space::kInstallAttributes),
              NotOk());
}

TEST_F(BackendStorageTpm2Test, Prepare) {
  const uint32_t kFakeSize = 32;
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kInstallAttributesIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(10);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(true);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PERSISTENT_WRITE_LOCK);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  tpm_manager::DestroySpaceReply destroy_reply;
  destroy_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), DestroySpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(destroy_reply), Return(true)));

  tpm_manager::DefineSpaceReply define_reply;
  define_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), DefineSpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(define_reply), Return(true)));

  tpm_manager::RemoveOwnerDependencyReply remove_reply;
  remove_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              RemoveOwnerDependency(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(remove_reply), Return(true)));

  EXPECT_THAT(
      backend_->GetStorageTpm2().Prepare(Space::kInstallAttributes, kFakeSize),
      IsOk());
}

TEST_F(BackendStorageTpm2Test, PrepareNotAvailable) {
  const uint32_t kFakeSize = 32;
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  auto result = backend_->GetStorageTpm2().Prepare(
      Space::kPlatformFirmwareManagementParameters, kFakeSize);
  ASSERT_NOT_OK(result);
}

TEST_F(BackendStorageTpm2Test, PrepareReady) {
  constexpr unsigned char kNormalModePCRBytes[] = {
      0x89, 0xEA, 0xF3, 0x51, 0x34, 0xB4, 0xB3, 0xC6, 0x49, 0xF4, 0x4C,
      0x0C, 0x76, 0x5B, 0x96, 0xAE, 0xAB, 0x8B, 0xB3, 0x4E, 0xE8, 0x3C,
      0xC7, 0xA6, 0x83, 0xC4, 0xE5, 0x3D, 0x15, 0x81, 0xC8, 0xC7};

  const std::string kNormalModePCR(std::begin(kNormalModePCRBytes),
                                   std::end(kNormalModePCRBytes));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNormalModePCR),
                      Return(trunks::TPM_RC_SUCCESS)));

  const uint32_t kFakeSize = 32;
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kFwmpIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(kFakeSize);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_CREATE);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_OWNER_WRITE);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_READ_AUTHORIZATION);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_READ);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  EXPECT_THAT(backend_->GetStorageTpm2().Prepare(
                  Space::kPlatformFirmwareManagementParameters, kFakeSize),
              IsOk());
}

TEST_F(BackendStorageTpm2Test, Load) {
  const uint32_t kFakeSize = 32;
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kFwmpIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(kFakeSize);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PERSISTENT_WRITE_LOCK);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_READ);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(false);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  const std::string kFakeData = "fake_data";

  tpm_manager::ReadSpaceReply read_reply;
  read_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  read_reply.set_data(kFakeData);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ReadSpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(read_reply), Return(true)));

  EXPECT_THAT(
      backend_->GetStorageTpm2().Load(Space::kFirmwareManagementParameters),
      IsOkAndHolds(brillo::BlobFromString(kFakeData)));
}

TEST_F(BackendStorageTpm2Test, Store) {
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kInstallAttributesIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(10);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PERSISTENT_WRITE_LOCK);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(false);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  const std::string kFakeData = "fake_data";

  tpm_manager::WriteSpaceReply write_reply;
  write_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), WriteSpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(write_reply), Return(true)));

  tpm_manager::LockSpaceReply lock_reply;
  lock_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), LockSpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(lock_reply), Return(true)));

  EXPECT_THAT(backend_->GetStorageTpm2().Store(
                  Space::kInstallAttributes, brillo::BlobFromString(kFakeData)),
              IsOk());
}

TEST_F(BackendStorageTpm2Test, Lock) {
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(10);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_READ_AUTHORIZATION);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_BOOT_WRITE_LOCK);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_WRITE_AUTHORIZATION);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::LockSpaceReply lock_reply;
  lock_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), LockSpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(lock_reply), Return(true)));

  EXPECT_THAT(backend_->GetStorageTpm2().Lock(Space::kBootlockbox,
                                              Backend::Storage::LockOptions{
                                                  .read_lock = false,
                                                  .write_lock = true,
                                              }),
              IsOk());
}

TEST_F(BackendStorageTpm2Test, LockNoOp) {
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(10);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(true);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_READ_AUTHORIZATION);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_BOOT_WRITE_LOCK);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_WRITE_AUTHORIZATION);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::LockSpaceReply lock_reply;
  lock_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  // Space is already locked as requested, so no need to send the LockSpace
  // command again.
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), LockSpace).Times(0);

  EXPECT_THAT(backend_->GetStorageTpm2().Lock(Space::kBootlockbox,
                                              Backend::Storage::LockOptions{
                                                  .read_lock = false,
                                                  .write_lock = true,
                                              }),
              IsOk());
}

TEST_F(BackendStorageTpm2Test, EnterpriseRollbackReady) {
  const uint32_t kFakeSize = 32;
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kEnterpriseRollbackIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(kFakeSize);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_CREATE);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_READ_AUTHORIZATION);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_WRITE_AUTHORIZATION);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(false);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  auto result = backend_->GetStorageTpm2().IsReady(Space::kEnterpriseRollback);
  ASSERT_OK(result);
  EXPECT_TRUE(result->readable);
  EXPECT_TRUE(result->writable);
}

TEST_F(BackendStorageTpm2Test, EnterpriseRollbackNotReady) {
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  EXPECT_THAT(backend_->GetStorageTpm2().IsReady(Space::kEnterpriseRollback),
              NotOk());
}

TEST_F(BackendStorageTpm2Test, FWMPPreparableNormalMode) {
  constexpr unsigned char kNormalModePCRBytes[] = {
      0x89, 0xEA, 0xF3, 0x51, 0x34, 0xB4, 0xB3, 0xC6, 0x49, 0xF4, 0x4C,
      0x0C, 0x76, 0x5B, 0x96, 0xAE, 0xAB, 0x8B, 0xB3, 0x4E, 0xE8, 0x3C,
      0xC7, 0xA6, 0x83, 0xC4, 0xE5, 0x3D, 0x15, 0x81, 0xC8, 0xC7};

  const std::string kNormalModePCR(std::begin(kNormalModePCRBytes),
                                   std::end(kNormalModePCRBytes));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNormalModePCR),
                      Return(trunks::TPM_RC_SUCCESS)));

  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  auto result =
      backend_->GetStorageTpm2().IsReady(Space::kFirmwareManagementParameters);
  ASSERT_OK(result);
  EXPECT_TRUE(result->preparable);
  EXPECT_TRUE(result->destroyable);
}

TEST_F(BackendStorageTpm2Test, FWMPNotPreparableWrongMode) {
  const std::string kUnexpectedModePCR(SHA256_DIGEST_LENGTH, 'X');

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kUnexpectedModePCR),
                      Return(trunks::TPM_RC_SUCCESS)));

  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  auto result =
      backend_->GetStorageTpm2().IsReady(Space::kFirmwareManagementParameters);
  ASSERT_OK(result);
  EXPECT_FALSE(result->preparable);
  EXPECT_FALSE(result->readable);
  EXPECT_FALSE(result->writable);
  EXPECT_FALSE(result->destroyable);
}

TEST_F(BackendStorageTpm2Test, FWMPWritableDevMode) {
  constexpr unsigned char kDevModePCRBytes[] = {
      0x23, 0xE1, 0x4D, 0xD9, 0xBB, 0x51, 0xA5, 0x0E, 0x16, 0x91, 0x1F,
      0x7E, 0x11, 0xDF, 0x1E, 0x1A, 0xAF, 0x0B, 0x17, 0x13, 0x4D, 0xC7,
      0x39, 0xC5, 0x65, 0x36, 0x07, 0xA1, 0xEC, 0x8D, 0xD3, 0x7A};

  const std::string kDevModePCR(std::begin(kDevModePCRBytes),
                                std::end(kDevModePCRBytes));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kDevModePCR), Return(trunks::TPM_RC_SUCCESS)));

  const uint32_t kFakeSize = 32;
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kFwmpIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(kFakeSize);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_CREATE);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_OWNER_WRITE);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_READ_AUTHORIZATION);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_READ);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  auto result = backend_->GetStorageTpm2().IsReady(
      Space::kPlatformFirmwareManagementParameters);
  ASSERT_OK(result);
  EXPECT_TRUE(result->readable);
  EXPECT_TRUE(result->writable);
}

TEST_F(BackendStorageTpm2Test, FWMPNotWritableWrongMode) {
  const std::string kUnexpectedModePCR(SHA256_DIGEST_LENGTH, 'X');

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kUnexpectedModePCR),
                      Return(trunks::TPM_RC_SUCCESS)));

  const uint32_t kFakeSize = 32;
  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kFwmpIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(kFakeSize);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_CREATE);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_OWNER_WRITE);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_READ_AUTHORIZATION);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_READ);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  auto result = backend_->GetStorageTpm2().IsReady(
      Space::kPlatformFirmwareManagementParameters);
  ASSERT_OK(result);
  EXPECT_TRUE(result->readable);
  EXPECT_FALSE(result->writable);
}

TEST_F(BackendStorageTpm2Test, DestroyModifiableFWMP) {
  constexpr unsigned char kNormalModePCRBytes[] = {
      0x89, 0xEA, 0xF3, 0x51, 0x34, 0xB4, 0xB3, 0xC6, 0x49, 0xF4, 0x4C,
      0x0C, 0x76, 0x5B, 0x96, 0xAE, 0xAB, 0x8B, 0xB3, 0x4E, 0xE8, 0x3C,
      0xC7, 0xA6, 0x83, 0xC4, 0xE5, 0x3D, 0x15, 0x81, 0xC8, 0xC7};

  const std::string kNormalModePCR(std::begin(kNormalModePCRBytes),
                                   std::end(kNormalModePCRBytes));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNormalModePCR),
                      Return(trunks::TPM_RC_SUCCESS)));

  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kFwmpIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  const uint32_t kFakeSize = 32;
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(kFakeSize);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PERSISTENT_WRITE_LOCK);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_READ);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  tpm_manager::DestroySpaceReply destroy_reply;
  destroy_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), DestroySpace(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(destroy_reply), Return(true)));

  EXPECT_THAT(
      backend_->GetStorageTpm2().Destroy(Space::kFirmwareManagementParameters),
      IsOk());
}

TEST_F(BackendStorageTpm2Test, DestroyUnmodifiableFWMP) {
  const std::string kUnexpectedModePCR(SHA256_DIGEST_LENGTH, 'X');

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kUnexpectedModePCR),
                      Return(trunks::TPM_RC_SUCCESS)));

  tpm_manager::ListSpacesReply list_reply;
  list_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  list_reply.add_index_list(kFwmpIndex);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), ListSpaces(_, _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(list_reply), Return(true)));

  const uint32_t kFakeSize = 32;
  tpm_manager::GetSpaceInfoReply info_reply;
  info_reply.set_result(NvramResult::NVRAM_RESULT_SUCCESS);
  info_reply.set_size(kFakeSize);
  info_reply.set_is_read_locked(false);
  info_reply.set_is_write_locked(false);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PERSISTENT_WRITE_LOCK);
  info_reply.add_attributes(NvramSpaceAttribute::NVRAM_PLATFORM_READ);
  EXPECT_CALL(proxy_->GetMockTpmNvramProxy(), GetSpaceInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(info_reply), Return(true)));

  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;
  status_reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
  status_reply.set_is_enabled(true);
  status_reply.set_is_owned(true);
  status_reply.set_is_owner_password_present(true);
  EXPECT_CALL(proxy_->GetMockTpmManagerProxy(),
              GetTpmNonsensitiveStatus(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(status_reply), Return(true)));

  EXPECT_THAT(
      backend_->GetStorageTpm2().Destroy(Space::kFirmwareManagementParameters),
      NotOk());
}

}  // namespace hwsec
