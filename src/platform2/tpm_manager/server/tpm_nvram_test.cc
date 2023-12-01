// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm_nvram_impl.h"

#include <libhwsec/test_utils/tpm1/test_fixture.h>
#include <cstdint>

#include "tpm_manager/common/typedefs.h"
#include "tpm_manager/server/mock_local_data_store.h"
#include "tpm_manager/server/mock_openssl_crypto_util.h"
#include "tpm_manager/server/mock_tpm_status.h"

namespace tpm_manager {

namespace {

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Pointee;
using testing::Return;
using testing::SetArgPointee;
using testing::SetArrayArgument;

constexpr TSS_HCONTEXT kFakeContext = 99999;
constexpr TSS_HTPM kFakeTpm = 66666;

// Sadly, trousers doesn't have Trspi_LoadBlob_NV_DATA_PUBLIC, so we need this
// function.
std::vector<uint8_t> Serialize_TPM_NV_DATA_PUBLIC(TPM_NV_DATA_PUBLIC* data) {
  uint64_t offset = 0;
  Trspi_LoadBlob_UINT16(&offset, data->tag, nullptr);
  // trousers doesn't have Trspi_LoadBlob_NV_INDEX
  Trspi_LoadBlob_UINT32(&offset, data->nvIndex, nullptr);
  Trspi_LoadBlob_PCR_INFO_SHORT(&offset, nullptr, &data->pcrInfoRead);
  Trspi_LoadBlob_PCR_INFO_SHORT(&offset, nullptr, &data->pcrInfoWrite);
  // trousers doesn't have Trspi_LoadBlob_NV_ATTRIBUTES
  Trspi_LoadBlob_UINT16(&offset, data->permission.tag, nullptr);
  Trspi_LoadBlob_UINT32(&offset, data->permission.attributes, nullptr);
  Trspi_LoadBlob_BYTE(&offset, data->bReadSTClear, nullptr);
  Trspi_LoadBlob_BYTE(&offset, data->bWriteSTClear, nullptr);
  Trspi_LoadBlob_BYTE(&offset, data->bWriteDefine, nullptr);
  Trspi_LoadBlob_UINT32(&offset, data->dataSize, nullptr);
  std::vector<uint8_t> result(offset);
  uint8_t* buffer = result.data();
  offset = 0;
  Trspi_LoadBlob_UINT16(&offset, data->tag, buffer);
  // trousers doesn't have Trspi_LoadBlob_NV_INDEX
  Trspi_LoadBlob_UINT32(&offset, data->nvIndex, buffer);
  Trspi_LoadBlob_PCR_INFO_SHORT(&offset, buffer, &data->pcrInfoRead);
  Trspi_LoadBlob_PCR_INFO_SHORT(&offset, buffer, &data->pcrInfoWrite);
  // trousers doesn't have Trspi_LoadBlob_NV_ATTRIBUTES
  Trspi_LoadBlob_UINT16(&offset, data->permission.tag, buffer);
  Trspi_LoadBlob_UINT32(&offset, data->permission.attributes, buffer);
  Trspi_LoadBlob_BYTE(&offset, data->bReadSTClear, buffer);
  Trspi_LoadBlob_BYTE(&offset, data->bWriteSTClear, buffer);
  Trspi_LoadBlob_BYTE(&offset, data->bWriteDefine, buffer);
  Trspi_LoadBlob_UINT32(&offset, data->dataSize, buffer);
  return result;
}

MATCHER_P(UstrEq, str, "") {
  std::string arg_str(reinterpret_cast<char*>(arg), str.length());
  return arg_str == str;
}

}  // namespace

class TpmNvramTest : public ::hwsec::Tpm1HwsecTest {
 public:
  TpmNvramTest()
      : tpm_nvram_(&mock_data_store_),
        fake_local_data_(mock_data_store_.GetMutableFakeData()) {
    ON_CALL_OVERALLS(Ospi_Context_Create(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(kFakeContext), Return(TSS_SUCCESS)));
    ON_CALL_OVERALLS(Ospi_Context_GetTpmObject(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(kFakeTpm), Return(TSS_SUCCESS)));
  }
  ~TpmNvramTest() override = default;

 protected:
  NiceMock<MockLocalDataStore> mock_data_store_;
  TpmNvramImpl tpm_nvram_;
  // Holds a reference of the internal |LocalData| of |mock_data_store_|.
  LocalData& fake_local_data_;
};

TEST_F(TpmNvramTest, DefineSpaceSuccess) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x87;
  constexpr size_t kSize = 0x20;
  const std::vector<NvramSpaceAttribute> attributes;
  const std::string authorization_value;
  NvramSpacePolicy policy = NVRAM_POLICY_NONE;
  constexpr TSS_HNVSTORE kNvKandle = 52;

  EXPECT_CALL_OVERALLS(
      Ospi_Context_CreateObject(kFakeContext, TSS_OBJECT_TYPE_NV, 0, _))
      .WillOnce(DoAll(SetArgPointee<3>(kNvKandle), Return(TSS_SUCCESS)));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_DATASIZE, 0, kSize))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_PERMISSIONS, 0, 0))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_NV_DefineSpace(kNvKandle, 0, 0))
      .WillOnce(Return(TSS_SUCCESS));

  EXPECT_EQ(tpm_nvram_.DefineSpace(kIndex, kSize, attributes,
                                   authorization_value, policy),
            NVRAM_RESULT_SUCCESS);
}

TEST_F(TpmNvramTest, DefineSpaceFail) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x87;
  constexpr size_t kSize = 0x20;
  const std::vector<NvramSpaceAttribute> attributes;
  const std::string authorization_value;
  NvramSpacePolicy policy = NVRAM_POLICY_NONE;

  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(_, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(_, TSS_TSPATTRIB_NV_DATASIZE, 0, kSize))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(_, TSS_TSPATTRIB_NV_PERMISSIONS, 0, 0))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_NV_DefineSpace(_, _, _))
      .WillOnce(Return(TPM_E_AUTHFAIL));

  EXPECT_EQ(tpm_nvram_.DefineSpace(kIndex, kSize, attributes,
                                   authorization_value, policy),
            NVRAM_RESULT_ACCESS_DENIED);
}

TEST_F(TpmNvramTest, DefineSpaceNoOwnerPassword) {
  constexpr uint32_t kIndex = 0x87;
  constexpr size_t kSize = 0x20;
  const std::vector<NvramSpaceAttribute> attributes;
  const std::string authorization_value;
  NvramSpacePolicy policy = NVRAM_POLICY_NONE;

  EXPECT_EQ(tpm_nvram_.DefineSpace(kIndex, kSize, attributes,
                                   authorization_value, policy),
            NVRAM_RESULT_OPERATION_DISABLED);
}

TEST_F(TpmNvramTest, DefineSpaceSetPCR0) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x87;
  constexpr size_t kSize = 0x20;
  const std::vector<NvramSpaceAttribute> attributes;
  const std::string authorization_value;
  NvramSpacePolicy policy = NVRAM_POLICY_PCR0;

  constexpr unsigned int kTpmBootPCR = 0;
  constexpr unsigned int kTpmPCRLocality = 1;
  constexpr int kPcrLen = 32;
  constexpr char kFakePcr0[] = "01234567890123456789012345678901";
  constexpr TSS_HNVSTORE kNvKandle = 1725;
  constexpr TSS_HPCRS kPcrKandle = 9527;

  EXPECT_CALL_OVERALLS(
      Ospi_Context_CreateObject(kFakeContext, TSS_OBJECT_TYPE_NV, 0, _))
      .WillOnce(DoAll(SetArgPointee<3>(kNvKandle), Return(TSS_SUCCESS)));
  EXPECT_CALL_OVERALLS(Ospi_Context_CreateObject(kFakeContext,
                                                 TSS_OBJECT_TYPE_PCRS,
                                                 TSS_PCRS_STRUCT_INFO_SHORT, _))
      .WillOnce(DoAll(SetArgPointee<3>(kPcrKandle), Return(TSS_SUCCESS)));

  // ScopedTssMemory should free this pcr0.
  uint8_t* pcr0 = new uint8_t[kPcrLen];
  memcpy(pcr0, kFakePcr0, kPcrLen);

  EXPECT_CALL_OVERALLS(Ospi_TPM_PcrRead(kFakeTpm, kTpmBootPCR, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kPcrLen), SetArgPointee<3>(pcr0),
                      Return(TSS_SUCCESS)));
  EXPECT_CALL_OVERALLS(
      Ospi_PcrComposite_SetPcrValue(kPcrKandle, kTpmBootPCR, kPcrLen, pcr0))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_PcrComposite_SetPcrLocality(kPcrKandle, kTpmPCRLocality))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_DATASIZE, 0, kSize))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_PERMISSIONS, 0, 0))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_NV_DefineSpace(kNvKandle, kPcrKandle, kPcrKandle))
      .WillOnce(Return(TSS_SUCCESS));

  EXPECT_EQ(tpm_nvram_.DefineSpace(kIndex, kSize, attributes,
                                   authorization_value, policy),
            NVRAM_RESULT_SUCCESS);
}

TEST_F(TpmNvramTest, DefineSpaceAttributes) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x23;
  constexpr size_t kSize = 0x30;
  const std::vector<NvramSpaceAttribute> attributes{
      NVRAM_PERSISTENT_WRITE_LOCK, NVRAM_BOOT_WRITE_LOCK, NVRAM_OWNER_WRITE};
  const std::string authorization_value;
  NvramSpacePolicy policy = NVRAM_POLICY_NONE;

  constexpr TSS_HNVSTORE kNvKandle = 5491;
  EXPECT_CALL_OVERALLS(
      Ospi_Context_CreateObject(kFakeContext, TSS_OBJECT_TYPE_NV, 0, _))
      .WillOnce(DoAll(SetArgPointee<3>(kNvKandle), Return(TSS_SUCCESS)));

  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_DATASIZE, 0, kSize))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_PERMISSIONS, 0,
                           TPM_NV_PER_WRITEDEFINE | TPM_NV_PER_WRITE_STCLEAR |
                               TPM_NV_PER_OWNERWRITE))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_NV_DefineSpace(kNvKandle, 0, 0))
      .WillOnce(Return(TSS_SUCCESS));

  EXPECT_EQ(tpm_nvram_.DefineSpace(kIndex, kSize, attributes,
                                   authorization_value, policy),
            NVRAM_RESULT_SUCCESS);
}

TEST_F(TpmNvramTest, DefineSpaceAuthAttributes) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x92;
  constexpr size_t kSize = 16;
  const std::vector<NvramSpaceAttribute> attributes{NVRAM_READ_AUTHORIZATION};
  const std::string authorization_value = "NF@ONsafsfF)A@N";
  NvramSpacePolicy policy = NVRAM_POLICY_NONE;

  constexpr TSS_HPOLICY kTpmUsagePolicy = 9321;
  EXPECT_CALL_OVERALLS(Ospi_GetPolicyObject(kFakeTpm, TSS_POLICY_USAGE, _))
      .WillOnce(DoAll(SetArgPointee<2>(kTpmUsagePolicy), Return(TSS_SUCCESS)));
  EXPECT_CALL_OVERALLS(
      Ospi_Policy_SetSecret(kTpmUsagePolicy, TSS_SECRET_MODE_PLAIN,
                            owner_password.size(), UstrEq(owner_password)))
      .WillOnce(Return(TSS_SUCCESS));

  constexpr TSS_HNVSTORE kNvKandle = 12345;
  EXPECT_CALL_OVERALLS(
      Ospi_Context_CreateObject(kFakeContext, TSS_OBJECT_TYPE_NV, 0, _))
      .WillOnce(DoAll(SetArgPointee<3>(kNvKandle), Return(TSS_SUCCESS)));

  constexpr TSS_HPOLICY kPolicyKandle = 54321;
  EXPECT_CALL_OVERALLS(Ospi_Context_CreateObject(kFakeContext,
                                                 TSS_OBJECT_TYPE_POLICY,
                                                 TSS_POLICY_USAGE, _))
      .WillOnce(DoAll(SetArgPointee<3>(kPolicyKandle), Return(TSS_SUCCESS)));

  EXPECT_CALL_OVERALLS(Ospi_Policy_SetSecret(kPolicyKandle,
                                             TSS_SECRET_MODE_PLAIN,
                                             authorization_value.size(),
                                             UstrEq(authorization_value)))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_Policy_AssignToObject(kPolicyKandle, kNvKandle))
      .WillOnce(Return(TSS_SUCCESS));

  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_DATASIZE, 0, kSize))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_SetAttribUint32(kNvKandle,
                                            TSS_TSPATTRIB_NV_PERMISSIONS, 0,
                                            TPM_NV_PER_AUTHREAD))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_NV_DefineSpace(kNvKandle, _, _))
      .WillOnce(Return(TSS_SUCCESS));

  EXPECT_EQ(tpm_nvram_.DefineSpace(kIndex, kSize, attributes,
                                   authorization_value, policy),
            NVRAM_RESULT_SUCCESS);
}

TEST_F(TpmNvramTest, GetSpaceInfoAllNull) {
  constexpr uint32_t kIndex = 0x8012334;
  TPM_NV_DATA_PUBLIC info{
      .nvIndex = kIndex,
  };
  std::vector<uint8_t> serialize_info = Serialize_TPM_NV_DATA_PUBLIC(&info);

  // ScopedTssMemory should free this nv_data_info.
  uint8_t* nv_data_info = new uint8_t[serialize_info.size()];
  memcpy(nv_data_info, serialize_info.data(), serialize_info.size());

  EXPECT_CALL_OVERALLS(Ospi_TPM_GetCapability(kFakeTpm, TSS_TPMCAP_NV_INDEX,
                                              sizeof(kIndex), Pointee(kIndex),
                                              _, _))
      .WillOnce(DoAll(SetArgPointee<4>(serialize_info.size()),
                      SetArgPointee<5>(nv_data_info), Return(TSS_SUCCESS)));

  EXPECT_EQ(tpm_nvram_.GetSpaceInfo(kIndex, nullptr, nullptr, nullptr, nullptr,
                                    nullptr),
            NVRAM_RESULT_SUCCESS);
}

TEST_F(TpmNvramTest, GetSpaceInfoData) {
  constexpr uint32_t kIndex = 0x8013450;
  constexpr uint32_t kSize = 0x123;
  constexpr bool kIsReadLocked = false;
  constexpr bool kIsWriteLocked = true;
  const std::vector<NvramSpaceAttribute> kAttributes = {
      NVRAM_BOOT_WRITE_LOCK, NVRAM_BOOT_READ_LOCK, NVRAM_READ_AUTHORIZATION,
      NVRAM_PLATFORM_WRITE, NVRAM_OWNER_READ};
  constexpr NvramSpacePolicy kPolicy = NVRAM_POLICY_PCR0;

  std::vector<uint8_t> pcrSelect = {1};

  TPM_NV_DATA_PUBLIC info{
      .nvIndex = kIndex,
      .pcrInfoWrite =
          TPM_PCR_INFO_SHORT{
              .pcrSelection =
                  TPM_PCR_SELECTION{
                      .sizeOfSelect = 1,
                      .pcrSelect = pcrSelect.data(),
                  },
          },
      .permission =
          TPM_NV_ATTRIBUTES{
              .attributes = TPM_NV_PER_AUTHREAD | TPM_NV_PER_PPWRITE |
                            TPM_NV_PER_OWNERREAD | TPM_NV_PER_WRITE_STCLEAR |
                            TPM_NV_PER_READ_STCLEAR,
          },
      .bReadSTClear = kIsReadLocked,
      .bWriteSTClear = kIsWriteLocked,
      .bWriteDefine = false,
      .dataSize = kSize,
  };
  std::vector<uint8_t> serialize_info = Serialize_TPM_NV_DATA_PUBLIC(&info);

  // ScopedTssMemory should free this nv_data_info.
  uint8_t* nv_data_info = new uint8_t[serialize_info.size()];
  memcpy(nv_data_info, serialize_info.data(), serialize_info.size());

  EXPECT_CALL_OVERALLS(Ospi_TPM_GetCapability(kFakeTpm, TSS_TPMCAP_NV_INDEX,
                                              sizeof(kIndex), Pointee(kIndex),
                                              _, _))
      .WillOnce(DoAll(SetArgPointee<4>(serialize_info.size()),
                      SetArgPointee<5>(nv_data_info), Return(TSS_SUCCESS)));

  uint32_t size;
  bool is_read_locked;
  bool is_write_locked;
  std::vector<NvramSpaceAttribute> attributes;
  NvramSpacePolicy policy;
  EXPECT_EQ(tpm_nvram_.GetSpaceInfo(kIndex, &size, &is_read_locked,
                                    &is_write_locked, &attributes, &policy),
            NVRAM_RESULT_SUCCESS);
  EXPECT_EQ(size, kSize);
  EXPECT_EQ(is_read_locked, kIsReadLocked);
  EXPECT_EQ(is_write_locked, kIsWriteLocked);
  EXPECT_EQ(attributes, kAttributes);
  EXPECT_EQ(policy, kPolicy);
}

TEST_F(TpmNvramTest, GetSpaceInfoFail) {
  constexpr uint32_t kIndex = 0x80178924;
  EXPECT_CALL_OVERALLS(Ospi_TPM_GetCapability(kFakeTpm, TSS_TPMCAP_NV_INDEX,
                                              sizeof(kIndex), Pointee(kIndex),
                                              _, _))
      .WillOnce(DoAll(Return(TPM_E_AREA_LOCKED)));

  EXPECT_EQ(tpm_nvram_.GetSpaceInfo(kIndex, nullptr, nullptr, nullptr, nullptr,
                                    nullptr),
            NVRAM_RESULT_OPERATION_DISABLED);
}

TEST_F(TpmNvramTest, DestroySpaceSuccess) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x56;

  TPM_NV_DATA_PUBLIC info{
      .nvIndex = kIndex,
  };
  std::vector<uint8_t> serialize_info = Serialize_TPM_NV_DATA_PUBLIC(&info);

  // ScopedTssMemory should free this nv_data_info.
  uint8_t* nv_data_info = new uint8_t[serialize_info.size()];
  memcpy(nv_data_info, serialize_info.data(), serialize_info.size());

  EXPECT_CALL_OVERALLS(Ospi_TPM_GetCapability(kFakeTpm, TSS_TPMCAP_NV_INDEX,
                                              sizeof(kIndex), Pointee(kIndex),
                                              _, _))
      .WillOnce(DoAll(SetArgPointee<4>(serialize_info.size()),
                      SetArgPointee<5>(nv_data_info), Return(TSS_SUCCESS)));

  constexpr TSS_HNVSTORE kNvKandle = 23413;
  EXPECT_CALL_OVERALLS(
      Ospi_Context_CreateObject(kFakeContext, TSS_OBJECT_TYPE_NV, 0, _))
      .WillOnce(DoAll(SetArgPointee<3>(kNvKandle), Return(TSS_SUCCESS)));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_NV_ReleaseSpace(kNvKandle))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_EQ(tpm_nvram_.DestroySpace(kIndex), NVRAM_RESULT_SUCCESS);
}

TEST_F(TpmNvramTest, DestroySpaceNotExist) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x56;

  EXPECT_CALL_OVERALLS(Ospi_TPM_GetCapability(kFakeTpm, TSS_TPMCAP_NV_INDEX,
                                              sizeof(kIndex), Pointee(kIndex),
                                              _, _))
      .WillOnce(DoAll(Return(TPM_E_BADINDEX)));

  EXPECT_CALL_OVERALLS(
      Ospi_Context_CreateObject(kFakeContext, TSS_OBJECT_TYPE_NV, 0, _))
      .Times(0);
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(_, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .Times(0);
  EXPECT_CALL_OVERALLS(Ospi_NV_ReleaseSpace(_)).Times(0);
  EXPECT_EQ(tpm_nvram_.DestroySpace(kIndex), NVRAM_RESULT_SUCCESS);
}

TEST_F(TpmNvramTest, DestroySpaceFail) {
  std::string owner_password = "owner";
  fake_local_data_.set_owner_password(owner_password);
  constexpr uint32_t kIndex = 0x1247123;

  TPM_NV_DATA_PUBLIC info{
      .nvIndex = kIndex,
  };
  std::vector<uint8_t> serialize_info = Serialize_TPM_NV_DATA_PUBLIC(&info);

  // ScopedTssMemory should free this nv_data_info.
  uint8_t* nv_data_info = new uint8_t[serialize_info.size()];
  memcpy(nv_data_info, serialize_info.data(), serialize_info.size());

  EXPECT_CALL_OVERALLS(Ospi_TPM_GetCapability(kFakeTpm, TSS_TPMCAP_NV_INDEX,
                                              sizeof(kIndex), Pointee(kIndex),
                                              _, _))
      .WillOnce(DoAll(SetArgPointee<4>(serialize_info.size()),
                      SetArgPointee<5>(nv_data_info), Return(TSS_SUCCESS)));

  constexpr TSS_HNVSTORE kNvKandle = 342;
  EXPECT_CALL_OVERALLS(
      Ospi_Context_CreateObject(kFakeContext, TSS_OBJECT_TYPE_NV, 0, _))
      .WillOnce(DoAll(SetArgPointee<3>(kNvKandle), Return(TSS_SUCCESS)));
  EXPECT_CALL_OVERALLS(
      Ospi_SetAttribUint32(kNvKandle, TSS_TSPATTRIB_NV_INDEX, 0, kIndex))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_CALL_OVERALLS(Ospi_NV_ReleaseSpace(kNvKandle))
      .WillOnce(Return(TSS_E_NV_AREA_NOT_EXIST));
  EXPECT_EQ(tpm_nvram_.DestroySpace(kIndex), NVRAM_RESULT_DEVICE_ERROR);
}

TEST_F(TpmNvramTest, DestroySpaceNoOwnerPassword) {
  constexpr uint32_t kIndex = 0x5222;

  EXPECT_EQ(tpm_nvram_.DestroySpace(kIndex), NVRAM_RESULT_OPERATION_DISABLED);
}

}  // namespace tpm_manager
