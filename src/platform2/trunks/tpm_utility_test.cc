// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iterator>

#include <base/check_op.h>
#include <base/strings/string_number_conversions.h>
#include <crypto/sha2.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/aes.h>

#include "trunks/cr50_headers/ap_ro_status.h"
#include "trunks/error_codes.h"
#include "trunks/hmac_authorization_delegate.h"
#include "trunks/mock_authorization_delegate.h"
#include "trunks/mock_blob_parser.h"
#include "trunks/mock_command_transceiver.h"
#include "trunks/mock_hmac_session.h"
#include "trunks/mock_policy_session.h"
#include "trunks/mock_tpm.h"
#include "trunks/mock_tpm_cache.h"
#include "trunks/mock_tpm_state.h"
#include "trunks/tpm_constants.h"
#include "trunks/tpm_utility.h"
#include "trunks/tpm_utility_impl.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace {

// GSC Vendor ID ("CROS").
const uint32_t kVendorIdGsc = 0x43524f53;

// Returns the total number of bits set in the first |size| elements from
// |array|.
int CountSetBits(const uint8_t* array, size_t size) {
  int res = 0;
  for (size_t i = 0; i < size; ++i) {
    for (int bit_position = 0; bit_position < 8; ++bit_position) {
      if ((array[i] & (1 << bit_position)) != 0) {
        ++res;
      }
    }
  }
  return res;
}

trunks::TPM2B_PUBLIC MakeTpm2bPublic() {
  trunks::TPM2B_PUBLIC tpm2b_public;
  tpm2b_public.size = sizeof(trunks::TPMT_PUBLIC);
  trunks::TPMT_PUBLIC& tpmt_public = tpm2b_public.public_area;
  memset(&tpmt_public, 0, sizeof(trunks::TPMT_PUBLIC));
  return tpm2b_public;
}

trunks::TPM2B_PUBLIC MakeEmptyTpm2bPublic() {
  trunks::TPM2B_PUBLIC tpm2b_public;
  tpm2b_public.size = 0;
  // Intentionally not initializing |tpm2b_public.public_area| as a size of zero
  // indicates that |public_area| is not meant to be read.
  return tpm2b_public;
}

std::string HexDecode(const std::string hex) {
  std::vector<uint8_t> output;
  CHECK(base::HexStringToBytes(hex, &output));
  return std::string(reinterpret_cast<char*>(output.data()), output.size());
}

}  // namespace

namespace trunks {

// A test fixture for TpmUtility tests.
class TpmUtilityTest : public testing::Test {
 public:
  TpmUtilityTest() : mock_tpm_(&mock_transceiver_), utility_(factory_) {}
  ~TpmUtilityTest() override {}
  void SetUp() override {
    factory_.set_blob_parser(&mock_blob_parser_);
    factory_.set_tpm_state(&mock_tpm_state_);
    factory_.set_tpm(&mock_tpm_);
    factory_.set_tpm_cache(&mock_tpm_cache_);
    factory_.set_hmac_session(&mock_hmac_session_);
    factory_.set_trial_session(&mock_trial_session_);
    ON_CALL(mock_tpm_, NV_ReadPublicSync(_, _, _, _, _))
        .WillByDefault(Return(TPM_RC_FAILURE));
  }

  TPM_RC ComputeKeyName(const TPMT_PUBLIC& public_area,
                        std::string* object_name) {
    return utility_.ComputeKeyName(public_area, object_name);
  }

  TPM_RC SetKnownOwnerPassword(const std::string& owner_password) {
    return utility_.SetKnownOwnerPassword(owner_password);
  }

  TPM_RC CreateStorageRootKeys(const std::string& owner_password) {
    return utility_.CreateStorageRootKeys(owner_password);
  }

  TPM_RC CreatePersistentSaltingKey(const std::string& owner_password) {
    return utility_.CreatePersistentSaltingKey(owner_password);
  }

  void SetExistingKeyHandleExpectation(TPM_HANDLE handle) {
    TPMS_CAPABILITY_DATA capability_data = {};
    TPML_HANDLE& handles = capability_data.data.handles;
    handles.count = 1;
    handles.handle[0] = handle;
    EXPECT_CALL(mock_tpm_,
                GetCapabilitySync(TPM_CAP_HANDLES, handle, _, _, _, _))
        .WillRepeatedly(
            DoAll(SetArgPointee<4>(capability_data), Return(TPM_RC_SUCCESS)));
  }

  void PopulatePCRSelection(bool has_sha1_pcrs,
                            bool make_sha1_bank_empty,
                            bool has_sha256_pcrs,
                            TPML_PCR_SELECTION* pcrs) {
    memset(pcrs, 0, sizeof(TPML_PCR_SELECTION));
    // By convention fill SHA-256 first. This is a bit brittle because order is
    // not important but it simplifies comparison to memcmp.
    if (has_sha256_pcrs) {
      pcrs->pcr_selections[pcrs->count].hash = TPM_ALG_SHA256;
      pcrs->pcr_selections[pcrs->count].sizeof_select = PCR_SELECT_MIN;
      for (int i = 0; i < PCR_SELECT_MIN; ++i) {
        pcrs->pcr_selections[pcrs->count].pcr_select[i] = 0xff;
      }
      ++pcrs->count;
    }
    if (has_sha1_pcrs) {
      pcrs->pcr_selections[pcrs->count].hash = TPM_ALG_SHA1;
      if (make_sha1_bank_empty) {
        pcrs->pcr_selections[pcrs->count].sizeof_select = PCR_SELECT_MAX;
      } else {
        pcrs->pcr_selections[pcrs->count].sizeof_select = PCR_SELECT_MIN;
        for (int i = 0; i < PCR_SELECT_MIN; ++i) {
          pcrs->pcr_selections[pcrs->count].pcr_select[i] = 0xff;
        }
      }
      ++pcrs->count;
    }
  }

  void DecryptTPM_SENSITIVE(TPM2B_DATA encryption_key,
                            TPM2B_PUBLIC public_data,
                            TPM2B_PRIVATE private_data,
                            TPM2B_SENSITIVE* sensitive_data) {
    EXPECT_NE(sensitive_data, nullptr);

    EXPECT_EQ(encryption_key.size, kAesKeySize);
    AES_KEY key;
    AES_set_encrypt_key(encryption_key.buffer, kAesKeySize * 8, &key);
    unsigned char iv[MAX_AES_BLOCK_SIZE_BYTES] = {0};
    int iv_in = 0;
    std::string unencrypted_private(private_data.size, 0);
    AES_cfb128_encrypt(
        reinterpret_cast<const unsigned char*>(private_data.buffer),
        reinterpret_cast<unsigned char*>(std::data(unencrypted_private)),
        private_data.size, &key, iv, &iv_in, AES_DECRYPT);
    TPM2B_DIGEST inner_integrity;
    EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPM2B_DIGEST(&unencrypted_private,
                                                 &inner_integrity, nullptr));
    std::string object_name;
    EXPECT_EQ(TPM_RC_SUCCESS,
              ComputeKeyName(public_data.public_area, &object_name));
    std::string integrity_value =
        crypto::SHA256HashString(unencrypted_private + object_name);
    EXPECT_EQ(integrity_value.size(), inner_integrity.size);
    EXPECT_EQ(0, memcmp(inner_integrity.buffer, integrity_value.data(),
                        inner_integrity.size));

    EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPM2B_SENSITIVE(&unencrypted_private,
                                                    sensitive_data, nullptr));
    EXPECT_TRUE(unencrypted_private.empty());
  }

  void SetExistingPCRSExpectation(bool has_sha1_pcrs, bool has_sha256_pcrs) {
    TPMS_CAPABILITY_DATA capability_data = {};
    TPML_PCR_SELECTION& pcrs = capability_data.data.assigned_pcr;
    PopulatePCRSelection(has_sha1_pcrs, false, has_sha256_pcrs, &pcrs);
    EXPECT_CALL(mock_tpm_, GetCapabilitySync(TPM_CAP_PCRS, _, _, _, _, _))
        .WillRepeatedly(
            DoAll(SetArgPointee<4>(capability_data), Return(TPM_RC_SUCCESS)));
  }

  void SetGsc(bool is_gsc) {
    EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_SUCCESS));
    uint32_t vendor_id = is_gsc ? kVendorIdGsc : 1;
    EXPECT_CALL(mock_tpm_state_, GetTpmProperty(TPM_PT_MANUFACTURER, _))
        .WillOnce(DoAll(SetArgPointee<1>(vendor_id), Return(true)));
  }

  TPM_RC TpmUtilityGetRsuDeviceIdInternal(std::string* rsu_device_id) {
    return utility_.GetRsuDeviceIdInternal(rsu_device_id);
  }

 protected:
  const TPM2B_PUBLIC kTpm2bPublic = MakeTpm2bPublic();
  const TPM2B_PUBLIC kEmptyTpm2bPublic = MakeEmptyTpm2bPublic();

  TrunksFactoryForTest factory_;
  NiceMock<MockCommandTransceiver> mock_transceiver_;
  NiceMock<MockBlobParser> mock_blob_parser_;
  NiceMock<MockTpmState> mock_tpm_state_;
  NiceMock<MockTpm> mock_tpm_;
  NiceMock<MockTpmCache> mock_tpm_cache_;
  NiceMock<MockAuthorizationDelegate> mock_authorization_delegate_;
  NiceMock<MockHmacSession> mock_hmac_session_;
  NiceMock<MockPolicySession> mock_trial_session_;
  TpmUtilityImpl utility_;
};

class NVTpmUtilityTest : public TpmUtilityTest {
 protected:
  // Constants with some valid NVRAM data.
  const uint32_t kNvIndex = 53;
  const uint32_t kNvTpmIndex = NV_INDEX_FIRST + kNvIndex;
  const TPMI_ALG_HASH kNvNameAlg = TPM_ALG_SHA256;
  const TPMA_NV kNvAttributes = TPMA_NV_WRITEDEFINE;
  const uint16_t kNvDataSize = 256;
  const std::string kNvData = std::string(kNvDataSize, 'z');
  const TPM2B_NV_PUBLIC kTpm2bNvPublic = MakeTpm2bNvPublic();
  const TPM2B_NV_PUBLIC kEmptyTpm2bNvPublic = MakeEmptyTpm2bNvPublic();
  const TPM2B_MAX_NV_BUFFER kTpm2bMaxNvBuffer = MakeTpm2bMaxNvBuffer();
  // Constants with invalid NVRAM data, for use in negative tests.
  const uint32_t kNvBadIndex = 1 << 29;

  NVTpmUtilityTest() = default;
  ~NVTpmUtilityTest() = default;

  void SetNVRAMMap(uint32_t index, const TPMS_NV_PUBLIC& public_area) {
    utility_.nvram_public_area_map_[index] = public_area;
  }

  TPM_RC GetNVRAMMap(uint32_t index, TPMS_NV_PUBLIC* public_area) const {
    auto it = utility_.nvram_public_area_map_.find(index);
    if (it == utility_.nvram_public_area_map_.end())
      return TPM_RC_FAILURE;
    *public_area = it->second;
    return TPM_RC_SUCCESS;
  }

  TPM2B_MAX_NV_BUFFER MakeTpm2bMaxNvBufferWithData(
      const std::string& data) const {
    CHECK_LE(kNvDataSize, MAX_NV_BUFFER_SIZE);
    TPM2B_MAX_NV_BUFFER tpm2b_max_nv_buffer;
    tpm2b_max_nv_buffer.size = data.size();
    memcpy(tpm2b_max_nv_buffer.buffer, data.data(), data.size());
    return tpm2b_max_nv_buffer;
  }

 private:
  TPM2B_NV_PUBLIC MakeTpm2bNvPublic() const {
    TPM2B_NV_PUBLIC tpm2b_nv_public;
    tpm2b_nv_public.size = sizeof(TPMS_NV_PUBLIC);
    TPMS_NV_PUBLIC& tpms_nv_public = tpm2b_nv_public.nv_public;
    memset(&tpms_nv_public, 0, sizeof(TPMS_NV_PUBLIC));
    tpms_nv_public.nv_index = kNvTpmIndex;
    tpms_nv_public.name_alg = kNvNameAlg;
    tpms_nv_public.attributes = kNvAttributes;
    tpms_nv_public.data_size = kNvDataSize;
    return tpm2b_nv_public;
  }

  TPM2B_NV_PUBLIC MakeEmptyTpm2bNvPublic() const {
    TPM2B_NV_PUBLIC tpm2b_nv_public;
    tpm2b_nv_public.size = 0;
    // Intentionally not zeroing the TPMS_NV_PUBLIC sub-structure - it should
    // not be read by the tested code.
    return tpm2b_nv_public;
  }

  TPM2B_MAX_NV_BUFFER MakeTpm2bMaxNvBuffer() const {
    return MakeTpm2bMaxNvBufferWithData(kNvData);
  }
};

TEST_F(TpmUtilityTest, StartupSuccess) {
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.Startup());
}

TEST_F(TpmUtilityTest, StartupAlreadyStarted) {
  EXPECT_CALL(mock_tpm_, StartupSync(_, _))
      .WillRepeatedly(Return(TPM_RC_INITIALIZE));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.Startup());
}

TEST_F(TpmUtilityTest, StartupFailure) {
  EXPECT_CALL(mock_tpm_, StartupSync(_, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.Startup());
}

TEST_F(TpmUtilityTest, StartupSelfTestFailure) {
  EXPECT_CALL(mock_tpm_, SelfTestSync(_, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.Startup());
}

TEST_F(TpmUtilityTest, ClearSuccess) {
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.Clear());
}

TEST_F(TpmUtilityTest, ClearAfterBadInit) {
  EXPECT_CALL(mock_tpm_, ClearSync(_, _, _))
      .WillOnce(Return(TPM_RC_AUTH_MISSING))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.Clear());
}

TEST_F(TpmUtilityTest, ClearFail) {
  EXPECT_CALL(mock_tpm_, ClearSync(_, _, _)).WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.Clear());
}

TEST_F(TpmUtilityTest, ShutdownTest) {
  EXPECT_CALL(mock_tpm_, ShutdownSync(TPM_SU_CLEAR, _));
  utility_.Shutdown();
}

TEST_F(TpmUtilityTest, InitializeTpmAlreadyInit) {
  SetExistingPCRSExpectation(false, true);
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.InitializeTpm());
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.InitializeTpm());
}

TEST_F(TpmUtilityTest, InitializeTpmSuccess) {
  SetExistingPCRSExpectation(false, true);
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.InitializeTpm());
}

TEST_F(TpmUtilityTest, InitializeTpmBadAuth) {
  SetExistingPCRSExpectation(false, true);
  // Reject attempts to set platform auth.
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_PLATFORM, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.InitializeTpm());
}

TEST_F(TpmUtilityTest, InitializeTpmDisablePHFails) {
  SetExistingPCRSExpectation(false, true);
  // Reject attempts to disable the platform hierarchy.
  EXPECT_CALL(mock_tpm_, HierarchyControlSync(_, _, TPM_RH_PLATFORM, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.InitializeTpm());
}

TEST_F(TpmUtilityTest, AllocatePCRFromNone) {
  SetExistingPCRSExpectation(false, false);
  TPML_PCR_SELECTION new_pcr_allocation;
  EXPECT_CALL(mock_tpm_, PCR_AllocateSync(TPM_RH_PLATFORM, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&new_pcr_allocation), SetArgPointee<3>(YES),
                      Return(TPM_RC_SUCCESS)));
  ASSERT_EQ(TPM_RC_SUCCESS, utility_.AllocatePCR(""));
  ASSERT_EQ(1u, new_pcr_allocation.count);
  TPML_PCR_SELECTION expected_pcr_allocation;
  PopulatePCRSelection(false, false, true, &expected_pcr_allocation);
  ASSERT_EQ(expected_pcr_allocation.count, new_pcr_allocation.count);
  ASSERT_EQ(0,
            memcmp(expected_pcr_allocation.pcr_selections,
                   new_pcr_allocation.pcr_selections,
                   sizeof(TPMS_PCR_SELECTION) * expected_pcr_allocation.count));
}

TEST_F(TpmUtilityTest, AllocatePCRFromSHA1Only) {
  SetExistingPCRSExpectation(true, false);
  TPML_PCR_SELECTION new_pcr_allocation;
  EXPECT_CALL(mock_tpm_, PCR_AllocateSync(TPM_RH_PLATFORM, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&new_pcr_allocation), SetArgPointee<3>(YES),
                      Return(TPM_RC_SUCCESS)));
  ASSERT_EQ(TPM_RC_SUCCESS, utility_.AllocatePCR(""));
  ASSERT_EQ(2u, new_pcr_allocation.count);
  TPML_PCR_SELECTION expected_pcr_allocation;
  PopulatePCRSelection(true, true, true, &expected_pcr_allocation);
  ASSERT_EQ(expected_pcr_allocation.count, new_pcr_allocation.count);
  ASSERT_EQ(0,
            memcmp(expected_pcr_allocation.pcr_selections,
                   new_pcr_allocation.pcr_selections,
                   sizeof(TPMS_PCR_SELECTION) * expected_pcr_allocation.count));
}

TEST_F(TpmUtilityTest, AllocatePCRFromSHA1AndSHA256) {
  SetExistingPCRSExpectation(true, true);
  TPML_PCR_SELECTION new_pcr_allocation;
  EXPECT_CALL(mock_tpm_, PCR_AllocateSync(TPM_RH_PLATFORM, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&new_pcr_allocation), SetArgPointee<3>(YES),
                      Return(TPM_RC_SUCCESS)));
  ASSERT_EQ(TPM_RC_SUCCESS, utility_.AllocatePCR(""));
  ASSERT_EQ(1u, new_pcr_allocation.count);
  TPML_PCR_SELECTION expected_pcr_allocation;
  PopulatePCRSelection(true, true, false, &expected_pcr_allocation);
  ASSERT_EQ(expected_pcr_allocation.count, new_pcr_allocation.count);
  ASSERT_EQ(0,
            memcmp(expected_pcr_allocation.pcr_selections,
                   new_pcr_allocation.pcr_selections,
                   sizeof(TPMS_PCR_SELECTION) * expected_pcr_allocation.count));
}

TEST_F(TpmUtilityTest, AllocatePCRFromSHA256Only) {
  SetExistingPCRSExpectation(false, true);
  EXPECT_CALL(mock_tpm_, PCR_AllocateSync(TPM_RH_PLATFORM, _, _, _, _, _, _, _))
      .Times(0);
  ASSERT_EQ(TPM_RC_SUCCESS, utility_.AllocatePCR(""));
}

TEST_F(TpmUtilityTest, AllocatePCRCommandFailure) {
  SetExistingPCRSExpectation(false, false);
  EXPECT_CALL(mock_tpm_, PCR_AllocateSync(_, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.AllocatePCR(""));
}

TEST_F(TpmUtilityTest, AllocatePCRTpmFailure) {
  SetExistingPCRSExpectation(false, false);
  EXPECT_CALL(mock_tpm_, PCR_AllocateSync(_, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(NO), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.AllocatePCR(""));
}

TEST_F(TpmUtilityTest, PrepareForOwnershipSuccess) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_OWNER, _, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.PrepareForOwnership());
}

TEST_F(TpmUtilityTest, PrepareForOwnershipFailure) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_OWNER, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.PrepareForOwnership());
}

TEST_F(TpmUtilityTest, PrepareForOwnershipAlreadyOwned) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet()).WillOnce(Return(true));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(_, _, _, _)).Times(0);
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.PrepareForOwnership());
}

TEST_F(TpmUtilityTest, TakeOwnershipSuccess) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsEndorsementPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsLockoutPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, TakeOwnershipOwnershipDone) {
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, TakeOwnershipBadSession) {
  EXPECT_CALL(mock_hmac_session_, StartUnboundSession(true, true))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, TakeOwnershipFailure) {
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_OWNER, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, ChangeOwnerPasswordEndorsementDone) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsLockoutPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, ChangeOwnerPasswordLockoutDone) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsEndorsementPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, ChangeOwnerPasswordEndorsementLockoutDone) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, ChangeOwnerPasswordEndorsementFail) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsEndorsementPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(_, _, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_ENDORSEMENT, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, ChangeOwnerPasswordLockoutFailure) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsEndorsementPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsLockoutPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(_, _, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_LOCKOUT, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.TakeOwnership("owner", "endorsement", "lockout"));
}

TEST_F(TpmUtilityTest, StirRandomSuccess) {
  std::string entropy_data(
      "large test data large test data large test data is that enough?");
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.StirRandom(entropy_data, &mock_authorization_delegate_));
}

TEST_F(TpmUtilityTest, StirRandomFails) {
  std::string entropy_data("test data");
  EXPECT_CALL(mock_tpm_, StirRandomSync(_, nullptr))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.StirRandom(entropy_data, nullptr));
}

TEST_F(TpmUtilityTest, GenerateRandomSuccess) {
  // This number is larger than the max bytes the GetRandom call can return.
  // Therefore we expect software to make multiple calls to fill this many
  // bytes.
  size_t num_bytes = 72;
  std::string random_data;
  TPM2B_DIGEST large_random;
  large_random.size = 32;
  TPM2B_DIGEST small_random;
  small_random.size = 8;
  EXPECT_CALL(mock_tpm_, GetRandomSync(_, _, &mock_authorization_delegate_))
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(large_random), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, GetRandomSync(8, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SetArgPointee<1>(small_random), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.GenerateRandom(num_bytes, &mock_authorization_delegate_,
                                    &random_data));
  EXPECT_EQ(num_bytes, random_data.size());
}

TEST_F(TpmUtilityTest, GenerateRandomFails) {
  size_t num_bytes = 5;
  std::string random_data;
  EXPECT_CALL(mock_tpm_, GetRandomSync(_, _, nullptr))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.GenerateRandom(num_bytes, nullptr, &random_data));
}

TEST_F(TpmUtilityTest, ExtendPCRSuccess) {
  TPM_HANDLE pcr_handle = HR_PCR + 1;
  TPML_DIGEST_VALUES digests;
  EXPECT_CALL(mock_tpm_,
              PCR_ExtendSync(pcr_handle, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&digests), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.ExtendPCR(1, "test digest",
                                               &mock_authorization_delegate_));
  EXPECT_EQ(1u, digests.count);
  EXPECT_EQ(TPM_ALG_SHA256, digests.digests[0].hash_alg);
  std::string hash_string = crypto::SHA256HashString("test digest");
  EXPECT_EQ(0, memcmp(hash_string.data(), digests.digests[0].digest.sha256,
                      crypto::kSHA256Length));
}

TEST_F(TpmUtilityTest, ExtendPCRFail) {
  int pcr_index = 0;
  TPM_HANDLE pcr_handle = HR_PCR + pcr_index;
  EXPECT_CALL(mock_tpm_, PCR_ExtendSync(pcr_handle, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.ExtendPCR(pcr_index, "test digest", nullptr));
}

TEST_F(TpmUtilityTest, ExtendPCRBadParam) {
  EXPECT_EQ(TPM_RC_FAILURE, utility_.ExtendPCR(-1, "test digest", nullptr));
}

TEST_F(TpmUtilityTest, ReadPCRSuccess) {
  // The |pcr_index| is chosen to match the structure for |pcr_select|.
  // If you change |pcr_index|, remember to change |pcr_select|.
  int pcr_index = 1;
  std::string pcr_value;
  TPML_PCR_SELECTION pcr_select;
  pcr_select.count = 1;
  pcr_select.pcr_selections[0].hash = TPM_ALG_SHA256;
  pcr_select.pcr_selections[0].sizeof_select = 1;
  pcr_select.pcr_selections[0].pcr_select[0] = 2;
  TPML_DIGEST pcr_values;
  pcr_values.count = 1;
  pcr_values.digests[0].size = 5;
  EXPECT_CALL(mock_tpm_, PCR_ReadSync(_, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(pcr_select),
                      SetArgPointee<3>(pcr_values), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.ReadPCR(pcr_index, &pcr_value));
}

TEST_F(TpmUtilityTest, ReadPCRFail) {
  std::string pcr_value;
  EXPECT_CALL(mock_tpm_, PCR_ReadSync(_, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.ReadPCR(1, &pcr_value));
}

TEST_F(TpmUtilityTest, ReadPCRBadReturn) {
  std::string pcr_value;
  EXPECT_EQ(TPM_RC_FAILURE, utility_.ReadPCR(1, &pcr_value));
}

TEST_F(TpmUtilityTest, GetKeyPublicAreaFailureEmptyData) {
  TPM_HANDLE key_handle = 42;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(kEmptyTpm2bPublic), Return(TPM_RC_SUCCESS)));
  TPMT_PUBLIC tpmt_public;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.GetKeyPublicArea(key_handle, &tpmt_public));
}

TEST_F(TpmUtilityTest, AsymmetricEncryptSuccess) {
  TPM_HANDLE key_handle = 42;
  std::string plaintext;
  std::string output_ciphertext("ciphertext");
  std::string ciphertext;
  TPM2B_PUBLIC_KEY_RSA out_message =
      Make_TPM2B_PUBLIC_KEY_RSA(output_ciphertext);
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_EncryptSync(key_handle, _, _, _, _, _,
                                         &mock_authorization_delegate_))
      .WillOnce(DoAll(SetArgPointee<5>(out_message), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.AsymmetricEncrypt(key_handle, TPM_ALG_NULL, TPM_ALG_NULL,
                                       plaintext, &mock_authorization_delegate_,
                                       &ciphertext));
  EXPECT_EQ(0, ciphertext.compare(output_ciphertext));
}

TEST_F(TpmUtilityTest, AsymmetricEncryptFail) {
  TPM_HANDLE key_handle = 42;
  std::string plaintext;
  std::string ciphertext;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_EncryptSync(key_handle, _, _, _, _, _, nullptr))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.AsymmetricEncrypt(key_handle, TPM_ALG_NULL, TPM_ALG_NULL,
                                       plaintext, nullptr, &ciphertext));
}

TEST_F(TpmUtilityTest, AsymmetricEncryptBadParams) {
  TPM_HANDLE key_handle = TPM_RH_FIRST;
  std::string plaintext;
  std::string ciphertext;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt | kRestricted;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, nullptr))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.AsymmetricEncrypt(key_handle, TPM_ALG_RSAES, TPM_ALG_NULL,
                                       plaintext, nullptr, &ciphertext));
}

TEST_F(TpmUtilityTest, AsymmetricEncryptNullSchemeForward) {
  TPM_HANDLE key_handle = 42;
  std::string plaintext;
  std::string output_ciphertext("ciphertext");
  std::string ciphertext;
  TPM2B_PUBLIC_KEY_RSA out_message =
      Make_TPM2B_PUBLIC_KEY_RSA(output_ciphertext);
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  TPMT_RSA_DECRYPT scheme;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_EncryptSync(key_handle, _, _, _, _, _, nullptr))
      .WillOnce(DoAll(SetArgPointee<5>(out_message), SaveArg<3>(&scheme),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.AsymmetricEncrypt(key_handle, TPM_ALG_NULL, TPM_ALG_NULL,
                                       plaintext, nullptr, &ciphertext));
  EXPECT_EQ(scheme.scheme, TPM_ALG_OAEP);
  EXPECT_EQ(scheme.details.oaep.hash_alg, TPM_ALG_SHA256);
}

TEST_F(TpmUtilityTest, AsymmetricEncryptSchemeForward) {
  TPM_HANDLE key_handle = 42;
  std::string plaintext;
  std::string output_ciphertext("ciphertext");
  std::string ciphertext;
  TPM2B_PUBLIC_KEY_RSA out_message =
      Make_TPM2B_PUBLIC_KEY_RSA(output_ciphertext);
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  TPMT_RSA_DECRYPT scheme;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_EncryptSync(key_handle, _, _, _, _, _, nullptr))
      .WillOnce(DoAll(SetArgPointee<5>(out_message), SaveArg<3>(&scheme),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.AsymmetricEncrypt(key_handle, TPM_ALG_RSAES, TPM_ALG_NULL,
                                       plaintext, nullptr, &ciphertext));
  EXPECT_EQ(scheme.scheme, TPM_ALG_RSAES);
}

TEST_F(TpmUtilityTest, AsymmetricDecryptSuccess) {
  TPM_HANDLE key_handle = 42;
  std::string plaintext;
  std::string output_plaintext("plaintext");
  std::string ciphertext;
  std::string password("password");
  TPM2B_PUBLIC_KEY_RSA out_message =
      Make_TPM2B_PUBLIC_KEY_RSA(output_plaintext);
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_DecryptSync(key_handle, _, _, _, _, _,
                                         &mock_authorization_delegate_))
      .WillOnce(DoAll(SetArgPointee<5>(out_message), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.AsymmetricDecrypt(
                key_handle, TPM_ALG_NULL, TPM_ALG_NULL, ciphertext,
                &mock_authorization_delegate_, &plaintext));
  EXPECT_EQ(0, plaintext.compare(output_plaintext));
}

TEST_F(TpmUtilityTest, AsymmetricDecryptFail) {
  TPM_HANDLE key_handle = 42;
  std::string key_name;
  std::string plaintext;
  std::string ciphertext;
  std::string password;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_DecryptSync(key_handle, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.AsymmetricDecrypt(
                key_handle, TPM_ALG_NULL, TPM_ALG_NULL, ciphertext,
                &mock_authorization_delegate_, &plaintext));
}

TEST_F(TpmUtilityTest, AsymmetricDecryptBadParams) {
  TPM_HANDLE key_handle = TPM_RH_FIRST;
  std::string plaintext;
  std::string ciphertext;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt | kRestricted;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.AsymmetricDecrypt(
                key_handle, TPM_ALG_RSAES, TPM_ALG_NULL, ciphertext,
                &mock_authorization_delegate_, &plaintext));
}

TEST_F(TpmUtilityTest, AsymmetricDecryptBadSession) {
  TPM_HANDLE key_handle = TPM_RH_FIRST;
  std::string key_name;
  std::string plaintext;
  std::string ciphertext;
  std::string password;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.AsymmetricDecrypt(key_handle, TPM_ALG_RSAES, TPM_ALG_NULL,
                                       ciphertext, nullptr, &plaintext));
}

TEST_F(TpmUtilityTest, AsymmetricDecryptNullHashAlgorithmForward) {
  TPM_HANDLE key_handle = 42;
  std::string plaintext;
  std::string output_plaintext("plaintext");
  std::string ciphertext;
  std::string password;
  TPM2B_PUBLIC_KEY_RSA out_message =
      Make_TPM2B_PUBLIC_KEY_RSA(output_plaintext);
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  TPMT_RSA_DECRYPT scheme;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_DecryptSync(key_handle, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(out_message), SaveArg<3>(&scheme),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.AsymmetricDecrypt(
                key_handle, TPM_ALG_OAEP, TPM_ALG_NULL, ciphertext,
                &mock_authorization_delegate_, &plaintext));
  EXPECT_EQ(scheme.scheme, TPM_ALG_OAEP);
  EXPECT_EQ(scheme.details.oaep.hash_alg, TPM_ALG_SHA256);
}

TEST_F(TpmUtilityTest, AsymmetricDecryptSchemeForward) {
  TPM_HANDLE key_handle = 42;
  std::string plaintext;
  std::string output_plaintext("plaintext");
  std::string ciphertext;
  std::string password;
  TPM2B_PUBLIC_KEY_RSA out_message =
      Make_TPM2B_PUBLIC_KEY_RSA(output_plaintext);
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  TPMT_RSA_DECRYPT scheme;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, RSA_DecryptSync(key_handle, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(out_message), SaveArg<3>(&scheme),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.AsymmetricDecrypt(
                key_handle, TPM_ALG_RSAES, TPM_ALG_NULL, ciphertext,
                &mock_authorization_delegate_, &plaintext));
  EXPECT_EQ(scheme.scheme, TPM_ALG_RSAES);
}

TEST_F(TpmUtilityTest, ECDHZGenSuccess) {
  TPM_HANDLE key_handle = 4231;
  trunks::TPMS_ECC_POINT ecc_point;
  std::string x = HexDecode(
      "4d389be4b2542a71fff17e1ac8105077b8fcfe2c565fa202d07f386f576eb564");
  std::string y = HexDecode(
      "4491a3ac1cf9166a60d906ed06a5b1a2f29ca223b81064ca8b08f8bac68dd875");
  ecc_point.x = trunks::Make_TPM2B_ECC_PARAMETER(x);
  ecc_point.y = trunks::Make_TPM2B_ECC_PARAMETER(y);

  trunks::TPM2B_ECC_POINT in_point = trunks::Make_TPM2B_ECC_POINT(ecc_point);
  trunks::TPM2B_ECC_POINT z_point;

  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_ECC;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              ECDH_ZGenSync(key_handle, _, _, _, &mock_authorization_delegate_))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.ECDHZGen(key_handle, in_point,
                              &mock_authorization_delegate_, &z_point));
}

TEST_F(TpmUtilityTest, ECDHZGenFail) {
  TPM_HANDLE key_handle = 4231;
  trunks::TPMS_ECC_POINT ecc_point;
  trunks::TPM2B_ECC_POINT in_point = trunks::Make_TPM2B_ECC_POINT(ecc_point);
  trunks::TPM2B_ECC_POINT z_point;

  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_ECC;
  public_area.public_area.object_attributes = kDecrypt;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              ECDH_ZGenSync(key_handle, _, _, _, &mock_authorization_delegate_))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.ECDHZGen(key_handle, in_point,
                              &mock_authorization_delegate_, &z_point));
}

TEST_F(TpmUtilityTest, ECDHZGenBadParams) {
  TPM_HANDLE key_handle = 4231;
  trunks::TPMS_ECC_POINT ecc_point;
  trunks::TPM2B_ECC_POINT in_point = trunks::Make_TPM2B_ECC_POINT(ecc_point);
  trunks::TPM2B_ECC_POINT z_point;

  std::string plaintext;
  std::string output_plaintext("plaintext");
  std::string ciphertext;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_ECC;
  public_area.public_area.object_attributes = kDecrypt | kRestricted;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.ECDHZGen(key_handle, in_point,
                              &mock_authorization_delegate_, &z_point));
}

TEST_F(TpmUtilityTest, ECDHZGenBadSession) {
  TPM_HANDLE key_handle = TPM_RH_FIRST;
  trunks::TPM2B_ECC_POINT in_point;
  trunks::TPM2B_ECC_POINT z_point;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.ECDHZGen(key_handle, in_point, nullptr, &z_point));
}

TEST_F(TpmUtilityTest, SignRsaSuccess) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  constexpr char kSignatureOutput[] = "hi";

  TPMT_SIGNATURE signature_out;
  signature_out.signature.rsassa.sig =
      Make_TPM2B_PUBLIC_KEY_RSA(kSignatureOutput);
  EXPECT_CALL(mock_tpm_, SignSync(key_handle, _, _, _, _, _,
                                  &mock_authorization_delegate_))
      .WillOnce(DoAll(SetArgPointee<5>(signature_out), Return(TPM_RC_SUCCESS)));

  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));

  std::string signature;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
  EXPECT_EQ(signature, kSignatureOutput);
}

TEST_F(TpmUtilityTest, SignEcdsaSuccess) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');

  TPMT_SIGNATURE signature_out;
  signature_out.signature.ecdsa.signature_r = Make_TPM2B_ECC_PARAMETER("ab");
  signature_out.signature.ecdsa.signature_r = Make_TPM2B_ECC_PARAMETER("cd");
  signature_out.signature.ecdsa.hash = TPM_ALG_SHA256;
  EXPECT_CALL(mock_tpm_, SignSync(key_handle, _, _, _, _, _,
                                  &mock_authorization_delegate_))
      .WillOnce(DoAll(SetArgPointee<5>(signature_out), Return(TPM_RC_SUCCESS)));

  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_ECC;
  public_area.public_area.object_attributes = kSign;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.ecc.x.size = 0;
  public_area.public_area.unique.ecc.y.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));

  std::string signature;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_ECDSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));

  std::string expected_signature;
  Serialize_TPMT_SIGNATURE(signature_out, &expected_signature);
  EXPECT_EQ(signature, expected_signature);
}

TEST_F(TpmUtilityTest, SignFail) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, SignSync(key_handle, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
}

TEST_F(TpmUtilityTest, SignInputLength) {
  TPM_HANDLE key_handle = 42;
  constexpr int kLimitOfDigestSize = sizeof(TPMU_HA);
  std::string digest(kLimitOfDigestSize, 'a');
  std::string too_long_digest = digest + "a";

  TPMT_SIGNATURE signature_out;
  signature_out.signature.rsassa.sig.size = 0;
  EXPECT_CALL(mock_tpm_, SignSync(key_handle, _, _, _, _, _,
                                  &mock_authorization_delegate_))
      .WillRepeatedly(
          DoAll(SetArgPointee<5>(signature_out), Return(TPM_RC_SUCCESS)));

  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));

  std::string signature;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          false /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256,
                          too_long_digest, false /* generate_hash */,
                          &mock_authorization_delegate_, &signature));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256,
                          too_long_digest, true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
}

TEST_F(TpmUtilityTest, SignBadWithRestrictedKey) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign | kRestricted;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
}

TEST_F(TpmUtilityTest, SignBadAuthorizationSession) {
  TPM_HANDLE key_handle = TPM_RH_FIRST;
  std::string password;
  std::string digest(32, 'a');
  std::string signature;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */, nullptr, &signature));
}

TEST_F(TpmUtilityTest, SignBadWithNonSigningKey) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kDecrypt;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
}

TEST_F(TpmUtilityTest, SignBadSchemeTypeNotMatchedWithKeyType) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.object_attributes = kSign;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));

  // Sign RSA scheme with ECC key
  public_area.public_area.type = TPM_ALG_ECC;
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.Sign(key_handle, TPM_ALG_RSAPSS, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));

  // Sign ECC scheme with RSA key
  public_area.public_area.type = TPM_ALG_RSA;
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.Sign(key_handle, TPM_ALG_ECDSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
}

TEST_F(TpmUtilityTest, SignBadWithBadKeyHandle) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_FAILURE)));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.Sign(key_handle, TPM_ALG_RSASSA, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
}

TEST_F(TpmUtilityTest, SignBadSigningSchemeType) {
  TPM_HANDLE key_handle = 0;
  std::string password;
  std::string digest(32, 'a');
  std::string signature;
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.Sign(key_handle, TPM_ALG_AES, TPM_ALG_NULL, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
}

TEST_F(TpmUtilityTest, SignNullSchemeForward) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  TPMT_SIGNATURE signature_out;
  signature_out.signature.rsassa.sig.size = 0;
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPMT_SIG_SCHEME scheme;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, SignSync(key_handle, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(signature_out), SaveArg<3>(&scheme),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_NULL, TPM_ALG_SHA256, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
  EXPECT_EQ(scheme.scheme, TPM_ALG_RSASSA);
  EXPECT_EQ(scheme.details.rsassa.hash_alg, TPM_ALG_SHA256);
}

TEST_F(TpmUtilityTest, SignRSASSAWithNullAlgorithm) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(32, 'a');
  TPMT_SIGNATURE signature_out;
  signature_out.signature.rsassa.sig.size = 0;
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPMT_SIG_SCHEME scheme;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, SignSync(key_handle, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(signature_out), SaveArg<3>(&scheme),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_NULL, TPM_ALG_NULL, digest,
                          false /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
  EXPECT_EQ(scheme.scheme, TPM_ALG_RSASSA);
  EXPECT_EQ(scheme.details.rsassa.hash_alg, TPM_ALG_NULL);
}

TEST_F(TpmUtilityTest, SignSchemeForward) {
  TPM_HANDLE key_handle = 42;
  std::string password;
  std::string digest(64, 'a');
  TPMT_SIGNATURE signature_out;
  signature_out.signature.rsassa.sig.size = 0;
  std::string signature;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPMT_SIG_SCHEME scheme;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.object_attributes = kSign;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, SignSync(key_handle, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(signature_out), SaveArg<3>(&scheme),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.Sign(key_handle, TPM_ALG_RSAPSS, TPM_ALG_SHA1, digest,
                          true /* generate_hash */,
                          &mock_authorization_delegate_, &signature));
  EXPECT_EQ(scheme.scheme, TPM_ALG_RSAPSS);
  EXPECT_EQ(scheme.details.rsapss.hash_alg, TPM_ALG_SHA1);
}

TEST_F(TpmUtilityTest, CertifyCreationSuccess) {
  TPM_HANDLE key_handle = 42;
  std::string creation_blob;
  EXPECT_CALL(mock_tpm_, CertifyCreationSyncShort(TPM_RH_NULL, key_handle, _, _,
                                                  _, _, _, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CertifyCreation(key_handle, creation_blob));
}

TEST_F(TpmUtilityTest, CertifyCreationParserError) {
  TPM_HANDLE key_handle = 42;
  std::string creation_blob;
  EXPECT_CALL(mock_blob_parser_, ParseCreationBlob(creation_blob, _, _, _))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.CertifyCreation(key_handle, creation_blob));
}

TEST_F(TpmUtilityTest, CertifyCreationFailure) {
  TPM_HANDLE key_handle = 42;
  std::string creation_blob;
  EXPECT_CALL(mock_tpm_, CertifyCreationSyncShort(TPM_RH_NULL, key_handle, _, _,
                                                  _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.CertifyCreation(key_handle, creation_blob));
}

TEST_F(TpmUtilityTest, ChangeAuthDataSuccess) {
  TPM_HANDLE key_handle = 1;
  std::string new_password;
  std::string key_blob;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.ChangeKeyAuthorizationData(
                                key_handle, new_password,
                                &mock_authorization_delegate_, &key_blob));
}

TEST_F(TpmUtilityTest, ChangeAuthDataKeyNameFail) {
  TPM_HANDLE key_handle = 1;
  std::string old_password;
  std::string new_password;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(key_handle, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.ChangeKeyAuthorizationData(
                                key_handle, new_password,
                                &mock_authorization_delegate_, nullptr));
}

TEST_F(TpmUtilityTest, ChangeAuthDataFailure) {
  TPM_HANDLE key_handle = 1;
  std::string new_password;
  EXPECT_CALL(mock_tpm_, ObjectChangeAuthSync(key_handle, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.ChangeKeyAuthorizationData(
                                key_handle, new_password,
                                &mock_authorization_delegate_, nullptr));
}

TEST_F(TpmUtilityTest, ChangeAuthDataParserFail) {
  TPM_HANDLE key_handle = 1;
  std::string new_password;
  std::string key_blob;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  public_area.public_area.type = TPM_ALG_RSA;
  public_area.public_area.auth_policy.size = 0;
  public_area.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_blob_parser_, SerializeKeyBlob(_, _, &key_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(
      SAPI_RC_BAD_TCTI_STRUCTURE,
      utility_.ChangeKeyAuthorizationData(
          key_handle, new_password, &mock_authorization_delegate_, &key_blob));
}

TEST_F(TpmUtilityTest, ImportRSAKeySuccess) {
  uint32_t public_exponent = 0x10001;
  std::string modulus(256, 'a');
  std::string prime_factor(128, 'b');
  std::string password("password");
  std::string key_blob;
  TPM2B_DATA encryption_key;
  TPM2B_PUBLIC public_data = kTpm2bPublic;
  TPM2B_PRIVATE private_data;
  EXPECT_CALL(mock_tpm_, ImportSync(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&encryption_key), SaveArg<3>(&public_data),
                      SaveArg<4>(&private_data), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(
      TPM_RC_SUCCESS,
      utility_.ImportRSAKey(TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                            modulus, public_exponent, prime_factor, password,
                            &mock_authorization_delegate_, &key_blob));

  // Validate that the public area was properly constructed.
  EXPECT_EQ(public_data.public_area.parameters.rsa_detail.key_bits,
            modulus.size() * 8);
  EXPECT_EQ(public_data.public_area.parameters.rsa_detail.exponent,
            public_exponent);
  EXPECT_EQ(public_data.public_area.unique.rsa.size, modulus.size());
  EXPECT_EQ(0, memcmp(public_data.public_area.unique.rsa.buffer, modulus.data(),
                      modulus.size()));

  // Validate the private struct construction.
  TPM2B_SENSITIVE sensitive_data;
  DecryptTPM_SENSITIVE(encryption_key, public_data, private_data,
                       &sensitive_data);

  EXPECT_EQ(sensitive_data.sensitive_area.auth_value.size, password.size());
  EXPECT_EQ(0, memcmp(sensitive_data.sensitive_area.auth_value.buffer,
                      password.data(), password.size()));
  EXPECT_EQ(sensitive_data.sensitive_area.sensitive.rsa.size,
            prime_factor.size());
  EXPECT_EQ(0, memcmp(sensitive_data.sensitive_area.sensitive.rsa.buffer,
                      prime_factor.data(), prime_factor.size()));
}

TEST_F(TpmUtilityTest, ImportRSAKeySuccessWithNoBlob) {
  uint32_t public_exponent = 0x10001;
  std::string modulus(256, 'a');
  std::string prime_factor(128, 'b');
  std::string password;
  EXPECT_EQ(
      TPM_RC_SUCCESS,
      utility_.ImportRSAKey(TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                            modulus, public_exponent, prime_factor, password,
                            &mock_authorization_delegate_, nullptr));
}

TEST_F(TpmUtilityTest, ImportRSAKeyParentNameFail) {
  uint32_t public_exponent = 0x10001;
  std::string modulus(256, 'a');
  std::string prime_factor(128, 'b');
  std::string password;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(
      TPM_RC_FAILURE,
      utility_.ImportRSAKey(TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                            modulus, public_exponent, prime_factor, password,
                            &mock_authorization_delegate_, nullptr));
}

TEST_F(TpmUtilityTest, ImportRSAKeyFail) {
  std::string modulus;
  std::string prime_factor;
  std::string password;
  EXPECT_CALL(mock_tpm_, ImportSync(_, _, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.ImportRSAKey(TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                                  modulus, 0x10001, prime_factor, password,
                                  &mock_authorization_delegate_, nullptr));
}

TEST_F(TpmUtilityTest, ImportRSAKeyParserFail) {
  std::string modulus;
  std::string prime_factor;
  std::string password;
  std::string key_blob;
  EXPECT_CALL(mock_blob_parser_, SerializeKeyBlob(_, _, &key_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.ImportRSAKey(TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                                  modulus, 0x10001, prime_factor, password,
                                  &mock_authorization_delegate_, &key_blob));
}

TEST_F(TpmUtilityTest, ImportEccKeySuccess) {
  TPM2B_DATA encryption_key;
  TPM2B_PUBLIC public_data = kTpm2bPublic;
  TPM2B_PRIVATE private_data;
  EXPECT_CALL(mock_tpm_, ImportSync(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&encryption_key), SaveArg<3>(&public_data),
                      SaveArg<4>(&private_data), Return(TPM_RC_SUCCESS)));

  constexpr TPMI_ECC_CURVE curve_id = TPM_ECC_NIST_P256;
  const std::string public_point_x("public_point_x");
  const std::string public_point_y("public_point_y");
  const std::string private_value("private");
  const std::string password("password");
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.ImportECCKey(TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                                  curve_id, public_point_x, public_point_y,
                                  private_value, password,
                                  &mock_authorization_delegate_, &key_blob));

  // Validate that the public area was properly constructed.
  EXPECT_EQ(public_data.public_area.type, TPM_ALG_ECC);
  EXPECT_EQ(public_data.public_area.parameters.ecc_detail.curve_id, curve_id);
  EXPECT_EQ(public_data.public_area.parameters.ecc_detail.kdf.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_data.public_area.parameters.ecc_detail.scheme.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_data.public_area.unique.ecc.x.size, public_point_x.size());
  EXPECT_EQ(memcmp(public_data.public_area.unique.ecc.x.buffer,
                   public_point_x.data(), public_point_x.size()),
            0);
  EXPECT_EQ(public_data.public_area.unique.ecc.y.size, public_point_y.size());
  EXPECT_EQ(memcmp(public_data.public_area.unique.ecc.y.buffer,
                   public_point_y.data(), public_point_y.size()),
            0);

  // Validate the private struct construction.
  TPM2B_SENSITIVE sensitive_data;
  DecryptTPM_SENSITIVE(encryption_key, public_data, private_data,
                       &sensitive_data);

  EXPECT_EQ(sensitive_data.sensitive_area.auth_value.size, password.size());
  EXPECT_EQ(memcmp(sensitive_data.sensitive_area.auth_value.buffer,
                   password.data(), password.size()),
            0);
  EXPECT_EQ(sensitive_data.sensitive_area.sensitive.ecc.size,
            private_value.size());
  EXPECT_EQ(memcmp(sensitive_data.sensitive_area.sensitive.ecc.buffer,
                   private_value.data(), private_value.size()),
            0);
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairSuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPML_PCR_SELECTION creation_pcrs;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), SaveArg<3>(&creation_pcrs),
                      Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string creation_blob;
  uint32_t creation_pcr = 12;
  EXPECT_EQ(
      TPM_RC_SUCCESS,
      utility_.CreateRSAKeyPair(
          TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey, 2048, 0x10001,
          "password", "", false, std::vector<uint32_t>({creation_pcr}),
          &mock_authorization_delegate_, &key_blob, &creation_blob));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.rsa_detail.scheme.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(1u, creation_pcrs.count);
  EXPECT_EQ(TPM_ALG_SHA256, creation_pcrs.pcr_selections[0].hash);
  EXPECT_EQ(PCR_SELECT_MIN, creation_pcrs.pcr_selections[0].sizeof_select);
  EXPECT_EQ(1u << (creation_pcr % 8),
            creation_pcrs.pcr_selections[0].pcr_select[creation_pcr / 8]);
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairMultiplePCRSuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPML_PCR_SELECTION creation_pcrs;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), SaveArg<3>(&creation_pcrs),
                      Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string creation_blob;
  std::vector<uint32_t> creation_pcr_indexes({0, 2});
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRSAKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey, 2048,
                0x10001, "password", "", false, creation_pcr_indexes,
                &mock_authorization_delegate_, &key_blob, &creation_blob));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.rsa_detail.scheme.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(1u, creation_pcrs.count);
  TPMS_PCR_SELECTION pcr_selection = creation_pcrs.pcr_selections[0];
  EXPECT_EQ(TPM_ALG_SHA256, pcr_selection.hash);
  EXPECT_EQ(PCR_SELECT_MIN, pcr_selection.sizeof_select);
  EXPECT_EQ(creation_pcr_indexes.size(),
            CountSetBits(pcr_selection.pcr_select, PCR_SELECT_MIN));
  for (uint32_t pcr_index : creation_pcr_indexes) {
    uint8_t creation_pcr_index = pcr_index / 8;
    uint8_t creation_pcr_mask = 1u << (pcr_index % 8);
    EXPECT_EQ(creation_pcr_mask,
              creation_pcr_mask & pcr_selection.pcr_select[creation_pcr_index]);
  }
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairDecryptKeySuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRSAKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, 2048, 0x10001,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, 0u);
  EXPECT_EQ(public_area.public_area.parameters.rsa_detail.scheme.scheme,
            TPM_ALG_NULL);
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairSignKeySuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPM2B_SENSITIVE_CREATE sensitive_create;
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, GetTpmProperty(TPM_PT_MANUFACTURER, _))
      .WillOnce(DoAll(SetArgPointee<1>(kVendorIdGsc), Return(true)));
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&sensitive_create), SaveArg<2>(&public_area),
                      Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string policy_digest(32, 'a');
  std::string key_auth("password");
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRSAKeyPair(TpmUtility::AsymmetricKeyUsage::kSignKey,
                                      2048, 0x10001, key_auth, policy_digest,
                                      true /* use_only_policy_authorization */,
                                      std::vector<uint32_t>(),
                                      &mock_authorization_delegate_, &key_blob,
                                      nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy,
            kAdminWithPolicy);
  EXPECT_EQ(public_area.public_area.parameters.rsa_detail.scheme.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_area.public_area.parameters.rsa_detail.key_bits, 2048);
  EXPECT_EQ(public_area.public_area.parameters.rsa_detail.exponent, 0x10001u);
  EXPECT_EQ(public_area.public_area.auth_policy.size, policy_digest.size());
  EXPECT_EQ(0, memcmp(public_area.public_area.auth_policy.buffer,
                      policy_digest.data(), policy_digest.size()));
  EXPECT_EQ(sensitive_create.sensitive.user_auth.size, key_auth.size());
  EXPECT_EQ(0, memcmp(sensitive_create.sensitive.user_auth.buffer,
                      key_auth.data(), key_auth.size()));
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairSignKeySuccessNoPaddingOnlyAlg) {
  // Unknown vendor - no padding-only alg support expected for TPM.
  uint32_t vendor_id = 0xaabbccdd;
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, GetTpmProperty(TPM_PT_MANUFACTURER, _))
      .WillOnce(DoAll(SetArgPointee<1>(vendor_id), Return(true)));
  EXPECT_CALL(mock_tpm_, CreateSyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string policy_digest(32, 'a');
  std::string key_auth("password");
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRSAKeyPair(TpmUtility::AsymmetricKeyUsage::kSignKey,
                                      2048, 0x10001, key_auth, policy_digest,
                                      true /* use_only_policy_authorization */,
                                      std::vector<uint32_t>(),
                                      &mock_authorization_delegate_, &key_blob,
                                      nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairBadDelegate) {
  std::string key_blob;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.CreateRSAKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, 2048, 0x10001,
                "password", "", false, std::vector<uint32_t>(), nullptr,
                &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairFailure) {
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, GetTpmProperty(TPM_PT_MANUFACTURER, _))
      .WillOnce(DoAll(SetArgPointee<1>(kVendorIdGsc), Return(true)));
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.CreateRSAKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, 2048, 0x10001,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairKeyParserFail) {
  std::string key_blob;
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, GetTpmProperty(TPM_PT_MANUFACTURER, _))
      .WillOnce(DoAll(SetArgPointee<1>(kVendorIdGsc), Return(true)));
  EXPECT_CALL(mock_blob_parser_, SerializeKeyBlob(_, _, &key_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.CreateRSAKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, 2048, 0x10001,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateRSAKeyPairCreationParserFail) {
  std::string creation_blob;
  std::string key_blob;
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, GetTpmProperty(TPM_PT_MANUFACTURER, _))
      .WillOnce(DoAll(SetArgPointee<1>(kVendorIdGsc), Return(true)));
  EXPECT_CALL(mock_blob_parser_, SerializeCreationBlob(_, _, _, &creation_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.CreateRSAKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, 2048, 0x10001,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, &creation_blob));
}

TEST_F(TpmUtilityTest, CreateECCKeyPairSuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPM2B_SENSITIVE_CREATE sensitive_create;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&sensitive_create), SaveArg<2>(&public_area),
                      Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string creation_blob;
  std::string key_auth("password");
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey,
                TPM_ECC_NIST_P256, key_auth, "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, &creation_blob));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.curve_id,
            TPM_ECC_NIST_P256);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.kdf.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.scheme.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(sensitive_create.sensitive.user_auth.size, key_auth.size());
  EXPECT_EQ(0, memcmp(sensitive_create.sensitive.user_auth.buffer,
                      key_auth.data(), key_auth.size()));
}

TEST_F(TpmUtilityTest, CreateECCKeyPairMultiplePCRSuccess) {
  TPML_PCR_SELECTION creation_pcrs;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<3>(&creation_pcrs), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string creation_blob;
  std::vector<uint32_t> creation_pcr_indexes({0, 2});
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey,
                TPM_ECC_NIST_P256, "password", "", false, creation_pcr_indexes,
                &mock_authorization_delegate_, &key_blob, &creation_blob));
  EXPECT_EQ(1u, creation_pcrs.count);
  TPMS_PCR_SELECTION pcr_selection = creation_pcrs.pcr_selections[0];
  EXPECT_EQ(TPM_ALG_SHA256, pcr_selection.hash);
  EXPECT_EQ(PCR_SELECT_MIN, pcr_selection.sizeof_select);
  EXPECT_EQ(creation_pcr_indexes.size(),
            CountSetBits(pcr_selection.pcr_select, PCR_SELECT_MIN));
  for (uint32_t pcr_index : creation_pcr_indexes) {
    uint8_t creation_pcr_index = pcr_index / 8;
    uint8_t creation_pcr_mask = 1u << (pcr_index % 8);
    EXPECT_EQ(creation_pcr_mask,
              creation_pcr_mask & pcr_selection.pcr_select[creation_pcr_index]);
  }
}

TEST_F(TpmUtilityTest, CreateECCKeyPairDecryptKeySuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.curve_id,
            TPM_ECC_NIST_P256);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.kdf.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.scheme.scheme,
            TPM_ALG_NULL);
}

TEST_F(TpmUtilityTest, CreateECCKeyPairSignKeySuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, 0);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.curve_id,
            TPM_ECC_NIST_P256);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.kdf.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.scheme.scheme,
            TPM_ALG_NULL);
}

TEST_F(TpmUtilityTest, CreateECCKeyPairWithPolicyAuthSuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string policy_digest(32, 'a');
  EXPECT_EQ(
      TPM_RC_SUCCESS,
      utility_.CreateECCKeyPair(
          TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
          "password", policy_digest, true /* use_only_policy_authorization */,
          std::vector<uint32_t>(), &mock_authorization_delegate_, &key_blob,
          nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy,
            kAdminWithPolicy);
  EXPECT_EQ(public_area.public_area.auth_policy.size, policy_digest.size());
  EXPECT_EQ(0, memcmp(public_area.public_area.auth_policy.buffer,
                      policy_digest.data(), policy_digest.size()));
}

TEST_F(TpmUtilityTest, CreateECCKeyPairBadDelegate) {
  std::string key_blob;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(), nullptr,
                &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateECCKeyPairFailure) {
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateECCKeyPairKeyParserFail) {
  std::string key_blob;
  EXPECT_CALL(mock_blob_parser_, SerializeKeyBlob(_, _, &key_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateECCKeyPairCreationParserFail) {
  std::string creation_blob;
  std::string key_blob;
  EXPECT_CALL(mock_blob_parser_, SerializeCreationBlob(_, _, _, &creation_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.CreateECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, &creation_blob));
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairSuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  TPM2B_SENSITIVE_CREATE sensitive_create;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&sensitive_create), SaveArg<2>(&public_area),
                      Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string creation_blob;
  std::string key_auth("password");
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey,
                TPM_ECC_NIST_P256, key_auth, "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, &creation_blob));
  EXPECT_EQ(public_area.public_area.object_attributes & kRestricted,
            kRestricted);
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.curve_id,
            TPM_ECC_NIST_P256);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.kdf.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.scheme.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(sensitive_create.sensitive.user_auth.size, key_auth.size());
  EXPECT_EQ(0, memcmp(sensitive_create.sensitive.user_auth.buffer,
                      key_auth.data(), key_auth.size()));
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairMultiplePCRSuccess) {
  TPML_PCR_SELECTION creation_pcrs;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<3>(&creation_pcrs), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string creation_blob;
  std::vector<uint32_t> creation_pcr_indexes({0, 2});
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey,
                TPM_ECC_NIST_P256, "password", "", false, creation_pcr_indexes,
                &mock_authorization_delegate_, &key_blob, &creation_blob));
  EXPECT_EQ(1u, creation_pcrs.count);
  TPMS_PCR_SELECTION pcr_selection = creation_pcrs.pcr_selections[0];
  EXPECT_EQ(TPM_ALG_SHA256, pcr_selection.hash);
  EXPECT_EQ(PCR_SELECT_MIN, pcr_selection.sizeof_select);
  EXPECT_EQ(creation_pcr_indexes.size(),
            CountSetBits(pcr_selection.pcr_select, PCR_SELECT_MIN));
  for (uint32_t pcr_index : creation_pcr_indexes) {
    uint8_t creation_pcr_index = pcr_index / 8;
    uint8_t creation_pcr_mask = 1u << (pcr_index % 8);
    EXPECT_EQ(creation_pcr_mask,
              creation_pcr_mask & pcr_selection.pcr_select[creation_pcr_index]);
  }
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairDecryptKeySuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kRestricted,
            kRestricted);
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, kDecrypt);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.curve_id,
            TPM_ECC_NIST_P256);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.kdf.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.scheme.scheme,
            TPM_ALG_NULL);
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairSignKeySuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, 0);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth,
            kUserWithAuth);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy, 0u);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.curve_id,
            TPM_ECC_NIST_P256);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.kdf.scheme,
            TPM_ALG_NULL);
  EXPECT_EQ(public_area.public_area.parameters.ecc_detail.scheme.scheme,
            TPM_ALG_NULL);
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairWithPolicyAuthSuccess) {
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string policy_digest(32, 'a');
  EXPECT_EQ(
      TPM_RC_SUCCESS,
      utility_.CreateRestrictedECCKeyPair(
          TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
          "password", policy_digest, true /* use_only_policy_authorization */,
          std::vector<uint32_t>(), &mock_authorization_delegate_, &key_blob,
          nullptr));
  EXPECT_EQ(public_area.public_area.object_attributes & kRestricted,
            kRestricted);
  EXPECT_EQ(public_area.public_area.object_attributes & kDecrypt, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kSign, kSign);
  EXPECT_EQ(public_area.public_area.object_attributes & kUserWithAuth, 0u);
  EXPECT_EQ(public_area.public_area.object_attributes & kAdminWithPolicy,
            kAdminWithPolicy);
  EXPECT_EQ(public_area.public_area.auth_policy.size, policy_digest.size());
  EXPECT_EQ(0, memcmp(public_area.public_area.auth_policy.buffer,
                      policy_digest.data(), policy_digest.size()));
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairBadDelegate) {
  std::string key_blob;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(), nullptr,
                &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairFailure) {
  EXPECT_CALL(mock_tpm_, CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _,
                                         _, &mock_authorization_delegate_))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairKeyParserFail) {
  std::string key_blob;
  EXPECT_CALL(mock_blob_parser_, SerializeKeyBlob(_, _, &key_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, nullptr));
}

TEST_F(TpmUtilityTest, CreateRestrictedECCKeyPairCreationParserFail) {
  std::string creation_blob;
  std::string key_blob;
  EXPECT_CALL(mock_blob_parser_, SerializeCreationBlob(_, _, _, &creation_blob))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.CreateRestrictedECCKeyPair(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256,
                "password", "", false, std::vector<uint32_t>(),
                &mock_authorization_delegate_, &key_blob, &creation_blob));
}

TEST_F(TpmUtilityTest, LoadKeySuccess) {
  TPM_HANDLE key_handle = TPM_RH_FIRST;
  TPM_HANDLE loaded_handle;
  EXPECT_CALL(mock_tpm_, LoadSync(kStorageRootKey, _, _, _, _, _,
                                  &mock_authorization_delegate_))
      .WillOnce(DoAll(SetArgPointee<4>(key_handle), Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadKey(key_blob, &mock_authorization_delegate_,
                             &loaded_handle));
  EXPECT_EQ(loaded_handle, key_handle);
}

TEST_F(TpmUtilityTest, LoadKeyFailure) {
  TPM_HANDLE key_handle;
  EXPECT_CALL(mock_tpm_, LoadSync(_, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string key_blob;
  EXPECT_EQ(
      TPM_RC_FAILURE,
      utility_.LoadKey(key_blob, &mock_authorization_delegate_, &key_handle));
}

TEST_F(TpmUtilityTest, LoadKeyBadDelegate) {
  TPM_HANDLE key_handle;
  std::string key_blob;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.LoadKey(key_blob, nullptr, &key_handle));
}

TEST_F(TpmUtilityTest, LoadKeyParserFail) {
  TPM_HANDLE key_handle;
  std::string key_blob;
  EXPECT_CALL(mock_blob_parser_, ParseKeyBlob(key_blob, _, _))
      .WillOnce(Return(false));
  EXPECT_EQ(
      SAPI_RC_BAD_TCTI_STRUCTURE,
      utility_.LoadKey(key_blob, &mock_authorization_delegate_, &key_handle));
}

TEST_F(TpmUtilityTest, LoadECPublicKey) {
  const TPM_HANDLE kKeyHandle = TPM_RH_FIRST;
  // Two sample EC points
  const std::string x_hex =
      "C892FCCAC397FC9C50490756AB189C18742F60855FF241D2D21A84F322EB5237";
  std::vector<uint8_t> x_vec;
  base::HexStringToBytes(x_hex, &x_vec);
  std::string x(x_vec.begin(), x_vec.end());

  const std::string y_hex =
      "6586EEBDB86E937B5598304C16BE51DB581BD150432AA35A8F1C0FE83C8B1E7B";
  std::vector<uint8_t> y_vec;
  base::HexStringToBytes(y_hex, &y_vec);
  std::string y(y_vec.begin(), y_vec.end());

  TPM2B_SENSITIVE in_private_arg;
  memset(&in_private_arg, 0, sizeof(TPM2B_SENSITIVE));
  TPM2B_PUBLIC in_public_arg = kTpm2bPublic;
  TPMI_RH_HIERARCHY hierarchy_arg = 0;
  TPM_HANDLE loaded_handle = 0;

  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<0>(&in_private_arg), SaveArg<1>(&in_public_arg),
                      SaveArg<2>(&hierarchy_arg), SetArgPointee<3>(kKeyHandle),
                      Return(TPM_RC_SUCCESS)));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadECPublicKey(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ECC_NIST_P256,
                TPM_ALG_ECDSA,  /* default scheme, TPM_ALG_ECDSA */
                TPM_ALG_SHA256, /* default hash alg, TPM_ALG_SHA256 */
                x, y, &mock_authorization_delegate_, &loaded_handle));

  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(0, in_private_arg.size);
  EXPECT_EQ(kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_ECDSA, /* default algorithm */
            in_public_arg.public_area.parameters.ecc_detail.scheme.scheme);
  EXPECT_EQ(TPM_ALG_SHA256,
            in_public_arg.public_area.parameters.ecc_detail.kdf.scheme);
  EXPECT_EQ(TPM_ECC_NIST_P256,
            in_public_arg.public_area.parameters.ecc_detail.curve_id);
  EXPECT_EQ(TPM_RH_NULL, hierarchy_arg);
  EXPECT_EQ(kKeyHandle, loaded_handle);
}

TEST_F(TpmUtilityTest, LoadRSAPublicKey) {
  const TPM_HANDLE kKeyHandle = TPM_RH_FIRST;
  const std::string kModulus(128, '\1');
  const int kModulusSizeBits = 1024;
  const uint32_t kPublicExponent = 3;

  TPM2B_SENSITIVE in_private_arg;
  memset(&in_private_arg, 0, sizeof(TPM2B_SENSITIVE));
  TPM2B_PUBLIC in_public_arg = kTpm2bPublic;
  TPMI_RH_HIERARCHY hierarchy_arg = 0;
  TPM_HANDLE loaded_handle = 0;

  // Test a signing RSASSA SHA-256 key.
  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<0>(&in_private_arg), SaveArg<1>(&in_public_arg),
                      SaveArg<2>(&hierarchy_arg), SetArgPointee<3>(kKeyHandle),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadRSAPublicKey(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ALG_RSASSA,
                TPM_ALG_SHA256, kModulus, kPublicExponent,
                &mock_authorization_delegate_, &loaded_handle));
  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(0, in_private_arg.size);
  EXPECT_EQ(kSign | kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_RSASSA,
            in_public_arg.public_area.parameters.rsa_detail.scheme.scheme);
  EXPECT_EQ(TPM_ALG_SHA256, in_public_arg.public_area.parameters.rsa_detail
                                .scheme.details.rsassa.hash_alg);
  EXPECT_EQ(kModulusSizeBits,
            in_public_arg.public_area.parameters.rsa_detail.key_bits);
  EXPECT_EQ(kPublicExponent,
            in_public_arg.public_area.parameters.rsa_detail.exponent);
  EXPECT_EQ(kModulus, StringFrom_TPM2B_PUBLIC_KEY_RSA(
                          in_public_arg.public_area.unique.rsa));
  EXPECT_EQ(TPM_RH_NULL, hierarchy_arg);
  EXPECT_EQ(kKeyHandle, loaded_handle);

  // Test a signing SHA-256 key with the default (RSASSA) scheme.
  in_public_arg = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&in_public_arg), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadRSAPublicKey(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ALG_NULL,
                TPM_ALG_SHA256, kModulus, kPublicExponent,
                &mock_authorization_delegate_, &loaded_handle));
  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(kSign | kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_RSASSA,
            in_public_arg.public_area.parameters.rsa_detail.scheme.scheme);
  EXPECT_EQ(TPM_ALG_SHA256, in_public_arg.public_area.parameters.rsa_detail
                                .scheme.details.rsassa.hash_alg);

  // Test a signing RSAPSS SHA-512 key.
  in_public_arg = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&in_public_arg), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadRSAPublicKey(
                TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ALG_RSAPSS,
                TPM_ALG_SHA512, kModulus, kPublicExponent,
                &mock_authorization_delegate_, &loaded_handle));
  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(kSign | kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_RSAPSS,
            in_public_arg.public_area.parameters.rsa_detail.scheme.scheme);
  EXPECT_EQ(TPM_ALG_SHA512, in_public_arg.public_area.parameters.rsa_detail
                                .scheme.details.rsapss.hash_alg);

  // Test a decrypting OAEP SHA-256 key.
  in_public_arg = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&in_public_arg), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadRSAPublicKey(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ALG_OAEP,
                TPM_ALG_SHA256, kModulus, kPublicExponent,
                &mock_authorization_delegate_, &loaded_handle));
  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(kDecrypt | kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_OAEP,
            in_public_arg.public_area.parameters.rsa_detail.scheme.scheme);
  EXPECT_EQ(TPM_ALG_SHA256, in_public_arg.public_area.parameters.rsa_detail
                                .scheme.details.oaep.hash_alg);

  // Test a decrypting SHA-256 key with the default (OAEP) scheme.
  in_public_arg = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&in_public_arg), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadRSAPublicKey(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ALG_NULL,
                TPM_ALG_SHA256, kModulus, kPublicExponent,
                &mock_authorization_delegate_, &loaded_handle));
  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(kDecrypt | kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_OAEP,
            in_public_arg.public_area.parameters.rsa_detail.scheme.scheme);
  EXPECT_EQ(TPM_ALG_SHA256, in_public_arg.public_area.parameters.rsa_detail
                                .scheme.details.oaep.hash_alg);

  // Test a decrypting RSAES key.
  memset(&in_public_arg, 0, sizeof(TPM2B_PUBLIC));
  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&in_public_arg), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadRSAPublicKey(
                TpmUtility::AsymmetricKeyUsage::kDecryptKey, TPM_ALG_RSAES,
                TPM_ALG_NULL, kModulus, kPublicExponent,
                &mock_authorization_delegate_, &loaded_handle));
  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(kDecrypt | kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_RSAES,
            in_public_arg.public_area.parameters.rsa_detail.scheme.scheme);

  // Test a key that is both for decrypting and signing.
  in_public_arg = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              LoadExternalSync(_, _, _, _, _, &mock_authorization_delegate_))
      .WillOnce(DoAll(SaveArg<1>(&in_public_arg), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LoadRSAPublicKey(
                TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey,
                TPM_ALG_NULL, TPM_ALG_NULL, kModulus, kPublicExponent,
                &mock_authorization_delegate_, &loaded_handle));
  testing::Mock::VerifyAndClearExpectations(&mock_tpm_);
  EXPECT_EQ(kDecrypt | kSign | kFixedTPM | kFixedParent,
            in_public_arg.public_area.object_attributes);
  EXPECT_EQ(TPM_ALG_NULL,
            in_public_arg.public_area.parameters.rsa_detail.scheme.scheme);
}

TEST_F(TpmUtilityTest, SealedDataSuccess) {
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  TPM2B_SENSITIVE_CREATE sensitive_create;
  TPM2B_PUBLIC in_public = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<1>(&sensitive_create), SaveArg<2>(&in_public),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.SealData(data_to_seal, "none_empty_policy_digest",
                              "none_empty_auth_value",
                              /*require_admin_with_policy=*/true,
                              &mock_authorization_delegate_, &sealed_data));
  EXPECT_EQ(sensitive_create.sensitive.data.size, data_to_seal.size());
  EXPECT_EQ(0, memcmp(sensitive_create.sensitive.data.buffer,
                      data_to_seal.data(), data_to_seal.size()));
  EXPECT_EQ(in_public.public_area.type, TPM_ALG_KEYEDHASH);
  EXPECT_EQ(in_public.public_area.name_alg, TPM_ALG_SHA256);
  EXPECT_EQ(in_public.public_area.object_attributes, kAdminWithPolicy | kNoDA);
}

TEST_F(TpmUtilityTest, SealedDataEmptyAuthValueSuccess) {
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  TPM2B_SENSITIVE_CREATE sensitive_create;
  TPM2B_PUBLIC in_public = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<1>(&sensitive_create), SaveArg<2>(&in_public),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.SealData(data_to_seal, "none_empty_policy_digest", "",
                              /*require_admin_with_policy=*/true,
                              &mock_authorization_delegate_, &sealed_data));
  EXPECT_EQ(sensitive_create.sensitive.data.size, data_to_seal.size());
  EXPECT_EQ(0, memcmp(sensitive_create.sensitive.data.buffer,
                      data_to_seal.data(), data_to_seal.size()));
  EXPECT_EQ(in_public.public_area.type, TPM_ALG_KEYEDHASH);
  EXPECT_EQ(in_public.public_area.name_alg, TPM_ALG_SHA256);
  EXPECT_EQ(in_public.public_area.object_attributes, kAdminWithPolicy | kNoDA);
}

TEST_F(TpmUtilityTest, SealedDataEmptyPolicySuccess) {
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  TPM2B_SENSITIVE_CREATE sensitive_create;
  TPM2B_PUBLIC in_public = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_,
              CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<1>(&sensitive_create), SaveArg<2>(&in_public),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.SealData(data_to_seal, "", "none_empty_auth_value",
                              /*require_admin_with_policy=*/false,
                              &mock_authorization_delegate_, &sealed_data));
  EXPECT_EQ(sensitive_create.sensitive.data.size, data_to_seal.size());
  EXPECT_EQ(0, memcmp(sensitive_create.sensitive.data.buffer,
                      data_to_seal.data(), data_to_seal.size()));
  EXPECT_EQ(in_public.public_area.type, TPM_ALG_KEYEDHASH);
  EXPECT_EQ(in_public.public_area.name_alg, TPM_ALG_SHA256);
  EXPECT_EQ(in_public.public_area.object_attributes, kUserWithAuth | kNoDA);
}

TEST_F(TpmUtilityTest, SealedDataOnlyEmptyPolicy) {
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.SealData(data_to_seal, "", "none_empty_auth_value",
                              /*require_admin_with_policy=*/true,
                              &mock_authorization_delegate_, &sealed_data));
}

TEST_F(TpmUtilityTest, SealDataBadDelegate) {
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.SealData(data_to_seal, "none_empty_policy_digest",
                              "none_empty_auth_value",
                              /*require_admin_with_policy=*/true, nullptr,
                              &sealed_data));
}

TEST_F(TpmUtilityTest, SealDataFailure) {
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  EXPECT_CALL(mock_tpm_,
              CreateSyncShort(kStorageRootKey, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.SealData(data_to_seal, "none_empty_policy_digest",
                              "none_empty_auth_value",
                              /*require_admin_with_policy=*/true,
                              &mock_authorization_delegate_, &sealed_data));
}

TEST_F(TpmUtilityTest, SealDataParserFail) {
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  EXPECT_CALL(mock_blob_parser_, SerializeKeyBlob(_, _, &sealed_data))
      .WillOnce(Return(false));
  EXPECT_EQ(SAPI_RC_BAD_TCTI_STRUCTURE,
            utility_.SealData(data_to_seal, "none_empty_policy_digest",
                              "none_empty_auth_value",
                              /*require_admin_with_policy=*/true,
                              &mock_authorization_delegate_, &sealed_data));
}

TEST_F(TpmUtilityTest, UnsealDataSuccess) {
  std::string sealed_data;
  std::string tpm_unsealed_data("password");
  std::string unsealed_data;
  TPM_HANDLE object_handle = 42;
  TPM2B_PUBLIC public_data = kTpm2bPublic;
  public_data.public_area.type = TPM_ALG_RSA;
  public_data.public_area.object_attributes = kDecrypt;
  public_data.public_area.auth_policy.size = 0;
  public_data.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_data), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, ReadPublicSync(object_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_data), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, LoadSync(_, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(object_handle), Return(TPM_RC_SUCCESS)));
  TPM2B_SENSITIVE_DATA out_data = Make_TPM2B_SENSITIVE_DATA(tpm_unsealed_data);
  EXPECT_CALL(mock_tpm_, UnsealSync(object_handle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(out_data), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.UnsealData(sealed_data, &mock_authorization_delegate_,
                                &unsealed_data));
  EXPECT_EQ(unsealed_data, tpm_unsealed_data);
}

TEST_F(TpmUtilityTest, UnsealDataBadDelegate) {
  std::string sealed_data;
  std::string unsealed_data;
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.UnsealData(sealed_data, nullptr, &unsealed_data));
}

TEST_F(TpmUtilityTest, UnsealDataLoadFail) {
  std::string sealed_data;
  std::string unsealed_data;
  EXPECT_CALL(mock_tpm_, LoadSync(_, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.UnsealData(sealed_data, &mock_authorization_delegate_,
                                &unsealed_data));
}

TEST_F(TpmUtilityTest, UnsealDataBadKeyName) {
  std::string sealed_data;
  std::string unsealed_data;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.UnsealData(sealed_data, &mock_authorization_delegate_,
                                &unsealed_data));
}

TEST_F(TpmUtilityTest, UnsealObjectFailure) {
  std::string sealed_data;
  std::string unsealed_data;
  EXPECT_CALL(mock_tpm_, UnsealSync(_, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.UnsealData(sealed_data, &mock_authorization_delegate_,
                                &unsealed_data));
}

TEST_F(TpmUtilityTest, UnsealDataWithHandleSuccess) {
  std::string tpm_unsealed_data("password");
  std::string unsealed_data;
  TPM_HANDLE object_handle = 42;
  TPM2B_PUBLIC public_data = kTpm2bPublic;
  public_data.public_area.type = TPM_ALG_RSA;
  public_data.public_area.object_attributes = kDecrypt;
  public_data.public_area.auth_policy.size = 0;
  public_data.public_area.unique.rsa.size = 0;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_data), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, ReadPublicSync(object_handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_data), Return(TPM_RC_SUCCESS)));
  TPM2B_SENSITIVE_DATA out_data = Make_TPM2B_SENSITIVE_DATA(tpm_unsealed_data);
  EXPECT_CALL(mock_tpm_, UnsealSync(object_handle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(out_data), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.UnsealDataWithHandle(
                object_handle, &mock_authorization_delegate_, &unsealed_data));
  EXPECT_EQ(unsealed_data, tpm_unsealed_data);
}

TEST_F(TpmUtilityTest, UnsealDataWithHandleBadDelegate) {
  TPM_HANDLE object_handle = 42;
  std::string unsealed_data;
  EXPECT_EQ(
      SAPI_RC_INVALID_SESSIONS,
      utility_.UnsealDataWithHandle(object_handle, nullptr, &unsealed_data));
}

TEST_F(TpmUtilityTest, UnsealDataWithHandleBadKeyName) {
  TPM_HANDLE object_handle = 42;
  std::string unsealed_data;
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.UnsealDataWithHandle(
                object_handle, &mock_authorization_delegate_, &unsealed_data));
}

TEST_F(TpmUtilityTest, UnsealDataWithHandleObjectFailure) {
  TPM_HANDLE object_handle = 42;
  std::string unsealed_data;
  EXPECT_CALL(mock_tpm_, UnsealSync(_, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.UnsealDataWithHandle(
                object_handle, &mock_authorization_delegate_, &unsealed_data));
}

TEST_F(TpmUtilityTest, StartSessionSuccess) {
  EXPECT_CALL(mock_hmac_session_, StartUnboundSession(true, true))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.StartSession(&mock_hmac_session_));
}

TEST_F(TpmUtilityTest, StartSessionFailure) {
  EXPECT_CALL(mock_hmac_session_, StartUnboundSession(true, true))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.StartSession(&mock_hmac_session_));
}

TEST_F(TpmUtilityTest, GetPolicyDigestForPcrValuesSuccess) {
  uint32_t index = 5;
  std::string pcr_value("pcr_value");
  std::string policy_digest;
  TPML_PCR_SELECTION pcr_select;
  pcr_select.count = 1;
  pcr_select.pcr_selections[0].hash = TPM_ALG_SHA256;
  pcr_select.pcr_selections[0].sizeof_select = 1;
  pcr_select.pcr_selections[0].pcr_select[index / 8] = 1 << (index % 8);
  TPML_DIGEST pcr_values;
  pcr_values.count = 1;
  pcr_values.digests[0] = Make_TPM2B_DIGEST(pcr_value);
  EXPECT_CALL(mock_tpm_, PCR_ReadSync(_, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(pcr_select),
                      SetArgPointee<3>(pcr_values), Return(TPM_RC_SUCCESS)));
  std::map<uint32_t, std::string> pcr_map;
  EXPECT_CALL(mock_trial_session_, PolicyPCR(_))
      .WillOnce(DoAll(SaveArg<0>(&pcr_map), Return(TPM_RC_SUCCESS)));
  std::string tpm_policy_digest("digest");
  EXPECT_CALL(mock_trial_session_, GetDigest(_))
      .WillOnce(
          DoAll(SetArgPointee<0>(tpm_policy_digest), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetPolicyDigestForPcrValues(
                                std::map<uint32_t, std::string>({{index, ""}}),
                                false /* use_auth_value */, &policy_digest));
  EXPECT_EQ(policy_digest, tpm_policy_digest);
  EXPECT_EQ(pcr_value, pcr_map[index]);
}

TEST_F(TpmUtilityTest, GetPolicyDigestForPcrValuesSuccessWithPcrValue) {
  uint32_t index = 5;
  std::string pcr_value("pcr_value");
  std::string policy_digest;
  std::map<uint32_t, std::string> pcr_map;
  EXPECT_CALL(mock_trial_session_, PolicyPCR(_))
      .WillOnce(DoAll(SaveArg<0>(&pcr_map), Return(TPM_RC_SUCCESS)));
  std::string tpm_policy_digest("digest");
  EXPECT_CALL(mock_trial_session_, GetDigest(_))
      .WillOnce(
          DoAll(SetArgPointee<0>(tpm_policy_digest), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.GetPolicyDigestForPcrValues(
                std::map<uint32_t, std::string>({{index, pcr_value}}),
                false /* use_auth_value */, &policy_digest));
  EXPECT_EQ(policy_digest, tpm_policy_digest);
  EXPECT_EQ(pcr_value, pcr_map[index]);
}

TEST_F(TpmUtilityTest, GetPolicyDigestForPcrValuesSuccessMultiplePcrs) {
  uint32_t index1 = 5;
  std::string pcr_value1("pcr_value1");
  uint32_t index2 = 6;
  std::string pcr_value2("pcr_value2");
  uint32_t index3 = 13;
  std::string pcr_value3("");
  std::string policy_digest;
  TPML_PCR_SELECTION pcr_select;
  pcr_select.count = 1;
  pcr_select.pcr_selections[0].hash = TPM_ALG_SHA256;
  pcr_select.pcr_selections[0].sizeof_select = 2;
  pcr_select.pcr_selections[0].pcr_select[index3 / 8] = 1 << (index3 % 8);
  TPML_DIGEST pcr_values;
  pcr_values.count = 1;
  pcr_values.digests[0] = Make_TPM2B_DIGEST(pcr_value3);
  std::map<uint32_t, std::string> pcr_map;
  EXPECT_CALL(mock_trial_session_, PolicyPCR(_))
      .WillOnce(DoAll(SaveArg<0>(&pcr_map), Return(TPM_RC_SUCCESS)));
  std::string tpm_policy_digest("digest");
  EXPECT_CALL(mock_trial_session_, GetDigest(_))
      .WillOnce(
          DoAll(SetArgPointee<0>(tpm_policy_digest), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, PCR_ReadSync(_, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(pcr_select),
                      SetArgPointee<3>(pcr_values), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.GetPolicyDigestForPcrValues(
                std::map<uint32_t, std::string>({{index1, pcr_value1},
                                                 {index2, pcr_value2},
                                                 {index3, pcr_value3}}),
                false /* use_auth_value */, &policy_digest));
  EXPECT_EQ(policy_digest, tpm_policy_digest);
  EXPECT_EQ(pcr_value1, pcr_map[index1]);
  EXPECT_EQ(pcr_value2, pcr_map[index2]);
  EXPECT_EQ(pcr_value3, pcr_map[index3]);
}

TEST_F(TpmUtilityTest, GetPolicyDigestForPcrValuesBadSession) {
  int index = 5;
  std::string pcr_value("value");
  std::string policy_digest;
  EXPECT_CALL(mock_trial_session_, StartUnboundSession(false, false))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.GetPolicyDigestForPcrValues(
                std::map<uint32_t, std::string>({{index, pcr_value}}), false,
                &policy_digest));
}

TEST_F(TpmUtilityTest, GetPolicyDigestForPcrValuesPcrReadFail) {
  int index = 5;
  std::string policy_digest;
  EXPECT_CALL(mock_tpm_, PCR_ReadSync(_, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.GetPolicyDigestForPcrValues(
                                std::map<uint32_t, std::string>({{index, ""}}),
                                false /* use_auth_value */, &policy_digest));
}

TEST_F(TpmUtilityTest, GetPolicyDigestForPcrValuesBadPcr) {
  int index = 5;
  std::string pcr_value("value");
  std::string policy_digest;
  EXPECT_CALL(mock_trial_session_, PolicyPCR(_))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.GetPolicyDigestForPcrValues(
                std::map<uint32_t, std::string>({{index, pcr_value}}),
                false /* use_auth_value */, &policy_digest));
}

TEST_F(TpmUtilityTest, GetPolicyDigestForPcrValuesBadDigest) {
  int index = 5;
  std::string pcr_value("value");
  std::string policy_digest;
  EXPECT_CALL(mock_trial_session_, GetDigest(&policy_digest))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.GetPolicyDigestForPcrValues(
                std::map<uint32_t, std::string>({{index, pcr_value}}),
                false /* use_auth_value */, &policy_digest));
}

TEST_F(NVTpmUtilityTest, DefineNVSpaceSuccess) {
  TPM2B_NV_PUBLIC public_data;
  EXPECT_CALL(mock_tpm_, NV_DefineSpaceSync(TPM_RH_OWNER, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&public_data), Return(TPM_RC_SUCCESS)));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.DefineNVSpace(kNvIndex, kNvDataSize, kNvAttributes, "", "",
                                   &mock_authorization_delegate_));
  EXPECT_TRUE(public_data.size);
  EXPECT_EQ(public_data.nv_public.nv_index, kNvTpmIndex);
  EXPECT_EQ(public_data.nv_public.name_alg, kNvNameAlg);
  EXPECT_EQ(public_data.nv_public.attributes, kNvAttributes);
  EXPECT_EQ(public_data.nv_public.data_size, kNvDataSize);
}

TEST_F(NVTpmUtilityTest, DefineNVSpaceBadLength) {
  size_t bad_length = MAX_NV_INDEX_SIZE + 1;
  EXPECT_CALL(mock_tpm_, NV_DefineSpaceSync(_, _, _, _, _)).Times(0);

  EXPECT_EQ(SAPI_RC_BAD_SIZE,
            utility_.DefineNVSpace(kNvIndex, bad_length, kNvAttributes, "", "",
                                   &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, DefineNVSpaceBadIndex) {
  EXPECT_CALL(mock_tpm_, NV_DefineSpaceSync(_, _, _, _, _)).Times(0);

  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.DefineNVSpace(kNvBadIndex, kNvDataSize, kNvAttributes, "",
                                   "", &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, DefineNVSpaceBadSession) {
  EXPECT_CALL(mock_tpm_, NV_DefineSpaceSync(_, _, _, _, _)).Times(0);

  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.DefineNVSpace(kNvIndex, kNvDataSize, kNvAttributes, "", "",
                                   nullptr));
}

TEST_F(NVTpmUtilityTest, DefineNVSpaceFail) {
  EXPECT_CALL(mock_tpm_, NV_DefineSpaceSync(TPM_RH_OWNER, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.DefineNVSpace(kNvIndex, kNvDataSize, kNvAttributes, "", "",
                                   &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, DestroyNVSpaceSuccess) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              NV_UndefineSpaceSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.DestroyNVSpace(kNvIndex, &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, DestroyNVSpaceBadIndex) {
  EXPECT_CALL(mock_tpm_, NV_UndefineSpaceSync(_, _, _, _, _)).Times(0);

  EXPECT_EQ(
      SAPI_RC_BAD_PARAMETER,
      utility_.DestroyNVSpace(kNvBadIndex, &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, DestroyNVSpaceBadSession) {
  EXPECT_CALL(mock_tpm_, NV_UndefineSpaceSync(_, _, _, _, _)).Times(0);

  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            utility_.DestroyNVSpace(kNvIndex, nullptr));
}

TEST_F(NVTpmUtilityTest, DestroyNVSpaceFailure) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              NV_UndefineSpaceSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.DestroyNVSpace(kNvIndex, &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, LockNVSpaceWriteSuccess) {
  EXPECT_FALSE(kNvAttributes & TPMA_NV_WRITELOCKED);

  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_WriteLockSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, NV_ReadLockSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .Times(0);

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LockNVSpace(kNvIndex, false, true, true,
                                 &mock_authorization_delegate_));
  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS, GetNVRAMMap(kNvIndex, &public_area));
  EXPECT_EQ(kNvAttributes | TPMA_NV_WRITELOCKED, public_area.attributes);
}

TEST_F(NVTpmUtilityTest, LockNVSpaceReadSuccess) {
  EXPECT_FALSE(kNvAttributes & TPMA_NV_READLOCKED);

  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_WriteLockSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .Times(0);
  EXPECT_CALL(mock_tpm_, NV_ReadLockSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LockNVSpace(kNvIndex, true, false, true,
                                 &mock_authorization_delegate_));
  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS, GetNVRAMMap(kNvIndex, &public_area));
  EXPECT_EQ(kNvAttributes | TPMA_NV_READLOCKED, public_area.attributes);
}

TEST_F(NVTpmUtilityTest, LockNVSpaceBothSuccess) {
  EXPECT_FALSE(kNvAttributes & (TPMA_NV_READLOCKED | TPMA_NV_WRITELOCKED));

  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_WriteLockSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, NV_ReadLockSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LockNVSpace(kNvIndex, true, true, true,
                                 &mock_authorization_delegate_));
  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS, GetNVRAMMap(kNvIndex, &public_area));
  EXPECT_EQ(kNvAttributes | TPMA_NV_READLOCKED | TPMA_NV_WRITELOCKED,
            public_area.attributes);
}

TEST_F(NVTpmUtilityTest, LockNVSpaceBothNotOwner) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_WriteLockSync(kNvTpmIndex, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, NV_ReadLockSync(kNvTpmIndex, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.LockNVSpace(kNvIndex, true, true, false,
                                 &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, LockNVSpaceBadIndex) {
  EXPECT_CALL(mock_tpm_, NV_WriteLockSync(_, _, _, _, _)).Times(0);
  EXPECT_CALL(mock_tpm_, NV_ReadLockSync(_, _, _, _, _)).Times(0);

  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.LockNVSpace(kNvBadIndex, true, true, true,
                                 &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, LockNVSpaceFailure) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_WriteLockSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.LockNVSpace(kNvIndex, true, true, true,
                                 &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, WriteNVSpaceSuccess) {
  EXPECT_FALSE(kNvAttributes & TPMA_NV_WRITTEN);

  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              NV_WriteSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _, offset, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.WriteNVSpace(kNvIndex, offset, kNvData, true, false,
                                  &mock_authorization_delegate_));
  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS, GetNVRAMMap(kNvIndex, &public_area));
  EXPECT_EQ(kNvAttributes | TPMA_NV_WRITTEN, public_area.attributes);
}

TEST_F(NVTpmUtilityTest, WriteNVSpaceSuccessByChunks) {
  EXPECT_FALSE(kNvAttributes & TPMA_NV_WRITTEN);

  // We want to test if the chucks can be read by chunks with remainder part.
  const size_t kMaxNVChunkSize = kNvDataSize / 2 - 1;
  EXPECT_CALL(mock_tpm_state_, GetMaxNVSize())
      .WillOnce(Return(kMaxNVChunkSize));

  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  // Ideally we should also check the result of `Make_TPM2B_MAX_NV_BUFFER()`,
  // but at least we can verify the offset is correct.
  EXPECT_CALL(mock_tpm_,
              NV_WriteSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _, offset, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, NV_WriteSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _,
                                      offset + kMaxNVChunkSize, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, NV_WriteSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _,
                                      offset + kMaxNVChunkSize * 2, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.WriteNVSpace(kNvIndex, offset, kNvData, true, false,
                                  &mock_authorization_delegate_));
  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS, GetNVRAMMap(kNvIndex, &public_area));
  EXPECT_EQ(kNvAttributes | TPMA_NV_WRITTEN, public_area.attributes);
}

TEST_F(NVTpmUtilityTest, WriteNVSpaceNotOwner) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              NV_WriteSync(kNvTpmIndex, _, kNvTpmIndex, _, _, offset, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.WriteNVSpace(kNvIndex, offset, kNvData, false, false,
                                  &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, ExtendNVSpace) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_ExtendSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.WriteNVSpace(kNvIndex, offset, "", true, true,
                                  &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, ExtendNVSpaceWithBadSize) {
  // The data is 1 byte larger than the max size.
  const std::string nvram_data(MAX_NV_INDEX_SIZE + 1, 0);
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_ExtendSync(_, _, _, _, _, _)).Times(0);

  EXPECT_EQ(SAPI_RC_BAD_SIZE,
            utility_.WriteNVSpace(
                kNvIndex, 0, nvram_data, /*using_owner_authorization=*/false,
                /*extend=*/true, &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, WriteNVSpaceBadIndex) {
  EXPECT_CALL(mock_tpm_, NV_WriteSync(_, _, _, _, _, _, _)).Times(0);

  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.WriteNVSpace(kNvBadIndex, 0, "", true, false,
                                  &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, WriteNVSpaceFailure) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              NV_WriteSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _, offset, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.WriteNVSpace(kNvIndex, offset, kNvData, true, false,
                                  &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, WriteNVSpaceFailureAtNonFirstChunks) {
  EXPECT_FALSE(kNvAttributes & TPMA_NV_WRITTEN);

  // We want to test if the chucks can be read by chunks with remainder part.
  const size_t kMaxNVChunkSize = kNvDataSize / 2 - 1;
  EXPECT_CALL(mock_tpm_state_, GetMaxNVSize())
      .WillOnce(Return(kMaxNVChunkSize));

  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  // Ideally we should also check the result of `Make_TPM2B_MAX_NV_BUFFER()`,
  // but at least we can verify the offset is correct.
  EXPECT_CALL(mock_tpm_,
              NV_WriteSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _, offset, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_, NV_WriteSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _,
                                      offset + kMaxNVChunkSize, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.WriteNVSpace(kNvIndex, offset, kNvData, true, false,
                                  &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, WriteNVSpaceFailureGetChunkSize) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  // This fails the query of maximum nv chunk size.
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_CALL(mock_tpm_, NV_WriteSync(_, _, _, _, _, _, _)).Times(0);

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.WriteNVSpace(kNvIndex, offset, kNvData, false, false,
                                  &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, IncrementNVCounterReadPublicFailure) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.IncrementNVCounter(kNvIndex,
                                        /*using_owner_authorization=*/false,
                                        &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, IncrementNVCounterIncrementFailure) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_, NV_IncrementSync(_, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.IncrementNVCounter(kNvIndex,
                                        /*using_owner_authorization=*/true,
                                        &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, IncrementNVCounterNotOwnerSuccess) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_, NV_IncrementSync(kNvTpmIndex, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.IncrementNVCounter(kNvIndex,
                                        /*using_owner_authorization=*/false,
                                        &mock_authorization_delegate_));

  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS, GetNVRAMMap(kNvIndex, &public_area));
  EXPECT_EQ(kNvAttributes | TPMA_NV_WRITTEN, public_area.attributes);
}

TEST_F(NVTpmUtilityTest, IncrementNVCounterOwnerSuccess) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_, NV_IncrementSync(TPM_RH_OWNER, _, kNvTpmIndex, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));

  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.IncrementNVCounter(kNvIndex,
                                        /*using_owner_authorization=*/true,
                                        &mock_authorization_delegate_));

  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS, GetNVRAMMap(kNvIndex, &public_area));
  EXPECT_EQ(kNvAttributes | TPMA_NV_WRITTEN, public_area.attributes);
}

TEST_F(NVTpmUtilityTest, ReadNVSpaceSuccess) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_ReadSync(kNvTpmIndex, _, kNvTpmIndex, _,
                                     kNvDataSize, offset, _, _))
      .WillOnce(
          DoAll(SetArgPointee<6>(kTpm2bMaxNvBuffer), Return(TPM_RC_SUCCESS)));

  std::string nvram_data;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.ReadNVSpace(kNvIndex, offset, kNvDataSize, false,
                                 &nvram_data, &mock_authorization_delegate_));
  EXPECT_EQ(nvram_data, kNvData);
}

TEST_F(NVTpmUtilityTest, ReadNVSpaceSuccessByChunks) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  // We want to test if the chucks can be read by chunks with remainder part.
  const size_t kMaxNVChunkSize = kNvDataSize / 2 - 1;
  EXPECT_CALL(mock_tpm_state_, GetMaxNVSize())
      .WillOnce(Return(kMaxNVChunkSize));

  const auto k1stTpm2bMaxNvBuffer =
      MakeTpm2bMaxNvBufferWithData(kNvData.substr(0, kMaxNVChunkSize));
  const auto k2ndTpm2bMaxNvBuffer = MakeTpm2bMaxNvBufferWithData(
      kNvData.substr(kMaxNVChunkSize, kMaxNVChunkSize));
  const auto k3rdTpm2bMaxNvBuffer =
      MakeTpm2bMaxNvBufferWithData(kNvData.substr(2 * kMaxNVChunkSize));

  EXPECT_CALL(mock_tpm_, NV_ReadSync(kNvTpmIndex, _, kNvTpmIndex, _,
                                     kMaxNVChunkSize, offset, _, _))
      .WillOnce(DoAll(SetArgPointee<6>(k1stTpm2bMaxNvBuffer),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              NV_ReadSync(kNvTpmIndex, _, kNvTpmIndex, _, kMaxNVChunkSize,
                          offset + kMaxNVChunkSize, _, _))
      .WillOnce(DoAll(SetArgPointee<6>(k2ndTpm2bMaxNvBuffer),
                      Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_, NV_ReadSync(kNvTpmIndex, _, kNvTpmIndex, _,
                                     kNvDataSize - 2 * kMaxNVChunkSize,
                                     offset + 2 * kMaxNVChunkSize, _, _))
      .WillOnce(DoAll(SetArgPointee<6>(k3rdTpm2bMaxNvBuffer),
                      Return(TPM_RC_SUCCESS)));

  std::string nvram_data;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.ReadNVSpace(kNvIndex, offset, kNvDataSize, false,
                                 &nvram_data, &mock_authorization_delegate_));
  EXPECT_EQ(nvram_data, kNvData);
}

TEST_F(NVTpmUtilityTest, ReadNVSpaceOwner) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_ReadSync(TPM_RH_OWNER, _, kNvTpmIndex, _,
                                     kNvDataSize, offset, _, _))
      .WillOnce(
          DoAll(SetArgPointee<6>(kTpm2bMaxNvBuffer), Return(TPM_RC_SUCCESS)));

  std::string nvram_data;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.ReadNVSpace(kNvIndex, offset, kNvDataSize, true,
                                 &nvram_data, &mock_authorization_delegate_));
  EXPECT_EQ(nvram_data, kNvData);
}

TEST_F(NVTpmUtilityTest, ReadNVSpaceFailedToReadPublic) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_CALL(mock_tpm_, NV_ReadSync(_, _, _, _, _, _, _, _)).Times(0);

  std::string nvram_data;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.ReadNVSpace(kNvIndex, 0, kNvDataSize, true, &nvram_data,
                                 &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, ReadNVSpaceFailedToGetChunkSize) {
  // This fails the query of maximum nv chunk size.
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_ReadSync(_, _, _, _, _, _, _, _)).Times(0);

  std::string nvram_data;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.ReadNVSpace(kNvIndex, 0, kNvDataSize, true, &nvram_data,
                                 &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, ReadNVSpaceBadIndex) {
  EXPECT_CALL(mock_tpm_, NV_ReadSync(_, _, _, _, _, _, _, _)).Times(0);

  std::string nvram_data;
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            utility_.ReadNVSpace(kNvBadIndex, 0, 5, true, &nvram_data,
                                 &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, ReadNVSpaceFailure) {
  uint32_t offset = 5;
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, NV_ReadSync(kNvTpmIndex, _, kNvTpmIndex, _,
                                     kNvDataSize, offset, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string nvram_data;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.ReadNVSpace(kNvIndex, offset, kNvDataSize, false,
                                 &nvram_data, &mock_authorization_delegate_));
}

TEST_F(NVTpmUtilityTest, GetNVSpaceNameSuccess) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  std::string name;
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetNVSpaceName(kNvIndex, &name));
  EXPECT_TRUE(name.length());
}

TEST_F(NVTpmUtilityTest, GetNVSpaceNameFailure) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(_, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  std::string name;
  EXPECT_EQ(TPM_RC_FAILURE, utility_.GetNVSpaceName(kNvIndex, &name));
}

TEST_F(NVTpmUtilityTest, GetNVSpaceNameFailureEmptyData) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(_, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kEmptyTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  std::string name;
  EXPECT_EQ(TPM_RC_FAILURE, utility_.GetNVSpaceName(kNvIndex, &name));
}

TEST_F(NVTpmUtilityTest, GetNVSpacePublicAreaCachedSuccess) {
  SetNVRAMMap(kNvIndex, kTpm2bNvPublic.nv_public);
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(_, _, _, _, _)).Times(0);

  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.GetNVSpacePublicArea(kNvIndex, &public_area));
  EXPECT_EQ(kNvTpmIndex, public_area.nv_index);
  EXPECT_EQ(kNvNameAlg, public_area.name_alg);
  EXPECT_EQ(kNvAttributes, public_area.attributes);
  EXPECT_EQ(kNvDataSize, public_area.data_size);
}

TEST_F(NVTpmUtilityTest, GetNVSpacePublicAreaSuccess) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(kNvTpmIndex, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.GetNVSpacePublicArea(kNvIndex, &public_area));
  EXPECT_EQ(kNvTpmIndex, public_area.nv_index);
  EXPECT_EQ(kNvNameAlg, public_area.name_alg);
  EXPECT_EQ(kNvAttributes, public_area.attributes);
  EXPECT_EQ(kNvDataSize, public_area.data_size);
}

TEST_F(NVTpmUtilityTest, GetNVSpacePublicAreaFailure) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(_, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.GetNVSpacePublicArea(kNvIndex, &public_area));
}

TEST_F(NVTpmUtilityTest, GetNVSpacePublicAreaFailureEmptyData) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(_, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kEmptyTpm2bNvPublic), Return(TPM_RC_SUCCESS)));

  TPMS_NV_PUBLIC public_area;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.GetNVSpacePublicArea(kNvIndex, &public_area));
}

TEST_F(TpmUtilityTest, SetKnownPasswordSuccess) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet()).WillOnce(Return(false));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_OWNER, _, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, SetKnownOwnerPassword("password"));
}

TEST_F(TpmUtilityTest, SetKnownPasswordOwnershipDone) {
  EXPECT_EQ(TPM_RC_SUCCESS, SetKnownOwnerPassword("password"));
}

TEST_F(TpmUtilityTest, SetKnownPasswordFailure) {
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet()).WillOnce(Return(false));
  EXPECT_CALL(mock_tpm_, HierarchyChangeAuthSync(TPM_RH_OWNER, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, SetKnownOwnerPassword("password"));
}

TEST_F(TpmUtilityTest, RootKeysRsaSuccess) {
  EXPECT_CALL(mock_tpm_cache_, GetBestSupportedKeyType())
      .WillOnce(Return(TPM_ALG_RSA));
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreatePrimarySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(DoAll(SaveArg<1>(&public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, CreateStorageRootKeys("password"));
  EXPECT_EQ(TPM_ALG_RSA, public_area.public_area.type);
}

TEST_F(TpmUtilityTest, RootKeysEccSuccess) {
  EXPECT_CALL(mock_tpm_cache_, GetBestSupportedKeyType())
      .WillOnce(Return(TPM_ALG_ECC));
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreatePrimarySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(DoAll(SaveArg<1>(&public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, CreateStorageRootKeys("password"));
  EXPECT_EQ(TPM_ALG_ECC, public_area.public_area.type);
}

TEST_F(TpmUtilityTest, RootKeysTypeUnsupported) {
  EXPECT_CALL(mock_tpm_cache_, GetBestSupportedKeyType())
      .WillOnce(Return(TPM_ALG_ERROR));
  EXPECT_CALL(mock_tpm_, CreatePrimarySyncShort(_, _, _, _, _, _, _, _, _, _))
      .Times(0);
  EXPECT_EQ(TPM_RC_FAILURE, CreateStorageRootKeys("password"));
}

TEST_F(TpmUtilityTest, RootKeysHandleConsistency) {
  TPM_HANDLE test_handle = 42;
  EXPECT_CALL(mock_tpm_, CreatePrimarySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<3>(test_handle), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, EvictControlSync(_, _, test_handle, _, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, CreateStorageRootKeys("password"));
}

TEST_F(TpmUtilityTest, RootKeysCreateFailure) {
  EXPECT_CALL(mock_tpm_, CreatePrimarySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, CreateStorageRootKeys("password"));
}

TEST_F(TpmUtilityTest, RootKeysPersistFailure) {
  EXPECT_CALL(mock_tpm_, EvictControlSync(_, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, CreateStorageRootKeys("password"));
}

TEST_F(TpmUtilityTest, RootKeysAlreadyExist) {
  SetExistingKeyHandleExpectation(kStorageRootKey);
  EXPECT_EQ(TPM_RC_SUCCESS, CreateStorageRootKeys("password"));
}

TEST_F(TpmUtilityTest, SaltingKeyRsaSuccess) {
  EXPECT_CALL(mock_tpm_cache_, GetBestSupportedKeyType())
      .WillOnce(Return(TPM_ALG_RSA));
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, CreatePersistentSaltingKey("password"));
  EXPECT_EQ(TPM_ALG_RSA, public_area.public_area.type);
  EXPECT_EQ(TPM_ALG_SHA256, public_area.public_area.name_alg);
}

TEST_F(TpmUtilityTest, SaltingKeyEccSuccess) {
  EXPECT_CALL(mock_tpm_cache_, GetBestSupportedKeyType())
      .WillOnce(Return(TPM_ALG_ECC));
  TPM2B_PUBLIC public_area = kTpm2bPublic;
  EXPECT_CALL(mock_tpm_, CreateSyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, CreatePersistentSaltingKey("password"));
  EXPECT_EQ(TPM_ALG_ECC, public_area.public_area.type);
}

TEST_F(TpmUtilityTest, SaltingKeyTypeUnsupported) {
  EXPECT_CALL(mock_tpm_cache_, GetBestSupportedKeyType())
      .WillOnce(Return(TPM_ALG_ERROR));
  EXPECT_CALL(mock_tpm_, CreateSyncShort(_, _, _, _, _, _, _, _, _, _))
      .Times(0);
  EXPECT_EQ(TPM_RC_FAILURE, CreatePersistentSaltingKey("password"));
}

TEST_F(TpmUtilityTest, SaltingKeyConsistency) {
  TPM_HANDLE test_handle = 42;
  EXPECT_CALL(mock_tpm_, LoadSync(_, _, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<4>(test_handle), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, EvictControlSync(_, _, test_handle, _, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, CreatePersistentSaltingKey("password"));
}

TEST_F(TpmUtilityTest, SaltingKeyCreateFailure) {
  EXPECT_CALL(mock_tpm_, CreateSyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, CreatePersistentSaltingKey("password"));
}

TEST_F(TpmUtilityTest, SaltingKeyLoadFailure) {
  EXPECT_CALL(mock_tpm_, LoadSync(_, _, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, CreatePersistentSaltingKey("password"));
}

TEST_F(TpmUtilityTest, SaltingKeyPersistFailure) {
  EXPECT_CALL(mock_tpm_, EvictControlSync(_, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, CreatePersistentSaltingKey("password"));
}

TEST_F(TpmUtilityTest, SaltingKeyAlreadyExists) {
  SetExistingKeyHandleExpectation(kSaltingKey);
  EXPECT_EQ(TPM_RC_SUCCESS, CreatePersistentSaltingKey("password"));
}

TEST_F(TpmUtilityTest, SetDictionaryAttackParametersSuccess) {
  EXPECT_CALL(mock_tpm_, DictionaryAttackParametersSync(TPM_RH_LOCKOUT, _, 1, 2,
                                                        3, nullptr))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.SetDictionaryAttackParameters(1, 2, 3, nullptr));
}

TEST_F(TpmUtilityTest, SetDictionaryAttackParametersFailure) {
  EXPECT_CALL(mock_tpm_, DictionaryAttackParametersSync(TPM_RH_LOCKOUT, _, 1, 2,
                                                        3, nullptr))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.SetDictionaryAttackParameters(1, 2, 3, nullptr));
}

TEST_F(TpmUtilityTest, ResetDictionaryAttackLockSuccess) {
  EXPECT_CALL(mock_tpm_,
              DictionaryAttackLockResetSync(TPM_RH_LOCKOUT, _, nullptr))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.ResetDictionaryAttackLock(nullptr));
}

TEST_F(TpmUtilityTest, ResetDictionaryAttackLockFailure) {
  EXPECT_CALL(mock_tpm_,
              DictionaryAttackLockResetSync(TPM_RH_LOCKOUT, _, nullptr))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.ResetDictionaryAttackLock(nullptr));
}

TEST_F(TpmUtilityTest, GetEndorsementKey) {
  TPM2B_NAME key_name = {};
  EXPECT_CALL(mock_tpm_, CreatePrimarySyncShort(TPM_RH_ENDORSEMENT, _, _, _, _,
                                                _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<8>(key_name), Return(TPM_RC_SUCCESS)));
  TPM_HANDLE key_handle;
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetEndorsementKey(TPM_ALG_RSA, nullptr,
                                                       nullptr, &key_handle));
}

TEST_F(TpmUtilityTest, GetEndorsementKeyFail) {
  EXPECT_CALL(mock_tpm_, CreatePrimarySyncShort(TPM_RH_ENDORSEMENT, _, _, _, _,
                                                _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  TPM_HANDLE key_handle;
  EXPECT_EQ(TPM_RC_FAILURE, utility_.GetEndorsementKey(TPM_ALG_RSA, nullptr,
                                                       nullptr, &key_handle));
}

TEST_F(TpmUtilityTest, CreateIdentityKey) {
  EXPECT_CALL(mock_tpm_, CreateSyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_SUCCESS,
            utility_.CreateIdentityKey(TPM_ALG_RSA, nullptr, &key_blob));
}

TEST_F(TpmUtilityTest, CreateIdentityKeyFail) {
  EXPECT_CALL(mock_tpm_, CreateSyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string key_blob;
  EXPECT_EQ(TPM_RC_FAILURE,
            utility_.CreateIdentityKey(TPM_ALG_RSA, nullptr, &key_blob));
}

TEST_F(TpmUtilityTest, DeclareTpmFirmwareStableNonGsc) {
  SetGsc(false);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_)).Times(0);
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.DeclareTpmFirmwareStable());
}

TEST_F(TpmUtilityTest, DeclareTpmFirmwareStableGscSuccess) {
  // A hand-coded kGscSubcmdInvalidateInactiveRW command and response.
  std::string expected_command(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0C"  // size=12
      "\x20\x00\x00\x00"  // code=kGscVendorCC
      "\x00\x14",         // subcommand=kGscSubcmdInvalidateInactiveRW
      12);
  std::string command_response(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0C"  // size=12
      "\x00\x00\x00\x00"  // code=TPM_RC_SUCCESS
      "\x00\x14",         // subcommand=kGscSubcmdInvalidateInactiveRW
      12);
  SetGsc(true);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(expected_command))
      .WillOnce(Return(command_response));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.DeclareTpmFirmwareStable());
}

TEST_F(TpmUtilityTest, DeclareTpmFirmwareStableGscFailure) {
  // A hand-coded kGscSubcmdInvalidateInactiveRW command and response.
  std::string expected_command(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0C"  // size=12
      "\x20\x00\x00\x00"  // code=kGscVendorCC
      "\x00\x14",         // subcommand=kGscSubcmdInvalidateInactiveRW
      12);
  std::string command_response(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0C"  // size=10
      "\x00\x00\x01\x01"  // code=TPM_RC_FAILURE
      "\x00\x14",         // subcommand=kGscSubcmdInvalidateInactiveRW
      12);
  SetGsc(true);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(expected_command))
      .WillOnce(Return(command_response));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.DeclareTpmFirmwareStable());
}

TEST_F(TpmUtilityTest, GetPublicRSAEndorsementKeyModulus_NoDataInNvram) {
  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(_, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  std::string ekm;
  EXPECT_NE(TPM_RC_SUCCESS, utility_.GetPublicRSAEndorsementKeyModulus(&ekm));
}

TEST_F(TpmUtilityTest, GetPublicRSAEndorsementKeyModulus_EmptyNvram) {
  uint32_t nv_index = kRsaEndorsementCertificateIndex;
  TPM2B_MAX_NV_BUFFER nvram_data_buffer;
  nvram_data_buffer.size = 0;

  TPM2B_NV_PUBLIC public_area;
  public_area.size = sizeof(TPMS_NV_PUBLIC);
  // Note that, in particular, this implies that the size of the NVRAM data,
  // which is read from the |data_size| field of TPMS_NV_PUBLIC, is zero.
  memset(&public_area.nv_public, 0, sizeof(TPMS_NV_PUBLIC));

  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(nv_index, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_, NV_ReadSync(_, _, _, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<6>(nvram_data_buffer), Return(TPM_RC_SUCCESS)));

  std::string ekm;
  EXPECT_EQ(SAPI_RC_CORRUPTED_DATA,
            utility_.GetPublicRSAEndorsementKeyModulus(&ekm));
}

TEST_F(TpmUtilityTest, GetPublicRSAEndorsementKeyModulus_InvalidDataInNvram) {
  uint32_t nv_index = kRsaEndorsementCertificateIndex;
  std::vector<unsigned char> cert = {1, 2, 3, 4};
  TPM2B_MAX_NV_BUFFER nvram_data_buffer;
  nvram_data_buffer.size = cert.size();
  memcpy(nvram_data_buffer.buffer, cert.data(), cert.size());

  TPM2B_NV_PUBLIC public_area;
  public_area.size = sizeof(TPMS_NV_PUBLIC);
  memset(&public_area.nv_public, 0, sizeof(TPMS_NV_PUBLIC));
  public_area.nv_public.data_size = 4;

  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(nv_index, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_, NV_ReadSync(_, _, _, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<6>(nvram_data_buffer), Return(TPM_RC_SUCCESS)));

  std::string ekm;
  EXPECT_EQ(SAPI_RC_CORRUPTED_DATA,
            utility_.GetPublicRSAEndorsementKeyModulus(&ekm));
}

TEST_F(TpmUtilityTest,
       GetPublicRSAEndorsementKeyModulus_ValidCertificateInNvram) {
  std::string hex_encoded_cert =
      "308203EB308202D3A00302010202105A12528603AC1ABE3FE8EB925C951823300D06092A"
      "864886F70D01010B0500308180310B30090603550406130255533113301106035504080C"
      "0A43616C69666F726E696131143012060355040A0C0B476F6F676C6520496E632E312430"
      "22060355040B0C1B456E67696E656572696E6720616E6420446576656C6F706D656E7431"
      "20301E06035504030C1743524F532054504D2050524420454B20524F4F54204341301E17"
      "0D3137303232313030303030325A170D3237303232313030303030325A30003082012230"
      "0D06092A864886F70D01010105000382010F003082010A0282010100AC5869BD60F30463"
      "612BB0C472AA19E5400E524A213290EBFB728D1AAC956F74B7CF6A8D57F17C94D4BE2B3D"
      "07FD882CF708C30C476DCB1FF32695A8BAC77BDD5C04E89E2AB228D6EDFF2EFAA54BE9C3"
      "0F9D211E2E42DE7E50CF424EEE6C310D677D8870522E8C953711BE42C9B94579D56D4815"
      "60926606C60D74EFEEB013869C0424BB7D8585F79159BE7F476625B9BD2701D1C5ABA6D4"
      "07A4724C2165C176C45CD2188576ADC20303C3368D11603CFEEE4CFD81EB9C9EACF0029C"
      "4F41B2E4033AB68453884D5BB3E0DD9F680E150CB604428546CFA32B05743B073BAE9796"
      "4A847756BB79D132EAEFF44EE1B25315C6B45CE74087A777CFD142769B5CF4E502030100"
      "01A381DF3081DC300E0603551D0F0101FF04040302002030510603551D110101FF044730"
      "45A443304131163014060567810502010C0B69643A3437344634463437310F300D060567"
      "810502020C044831423231163014060567810502030C0B69643A3030313330303337300C"
      "0603551D130101FF0402300030130603551D20040C300A3008060667810C010202301F06"
      "03551D23041830168014153934FC5919CD2982F1F47FAD85D64469A1A17B30100603551D"
      "25040930070605678105080130210603551D09041A3018301606056781050210310D300B"
      "0C03322E30020100020110300D06092A864886F70D01010B05000382010100AE963A2EC0"
      "72B8DC7C673389B62112CFDEAD6A7C2A1D5142E74D628B9FCA1599C9705A23C2FCB3A529"
      "6B5CE3C2CB78A82B99D03D3B2E892C779EC46A2476CE70B68BE3FC87F1FC0B15A551F392"
      "33AAB7A0E0B425C709790C05298F101AC0CF95FE5C2502D4E5D78233041EBB66CFC0AA59"
      "983E20C915D7A35AE025FBE8ABBC898FD475288512C8BA2B70F4185E00A28A53D241188C"
      "C9216D6AA8FA0F15DE4BD8EF11A78F55B89C1C330A6C39EC6647954C816FB74BEFA02CAB"
      "C2B036B3E88DF7AE13F99449A2CADD70F322F64EFC437BA0A74BAE8354EAE44A5B0D5D66"
      "A3A6F14630157CD7BABDC6B0FD45EC71D208DD7BF1EA014540E46865E34947B87A2668";
  std::vector<uint8_t> cert;
  base::HexStringToBytes(hex_encoded_cert, &cert);

  ASSERT_TRUE(cert.size() <= MAX_NV_BUFFER_SIZE);

  uint32_t nv_index = kRsaEndorsementCertificateIndex;
  TPM2B_MAX_NV_BUFFER nvram_data_buffer;
  nvram_data_buffer.size = cert.size();
  memcpy(nvram_data_buffer.buffer, cert.data(), cert.size());

  TPM2B_NV_PUBLIC public_area;
  public_area.size = sizeof(TPMS_NV_PUBLIC);
  memset(&public_area.nv_public, 0, sizeof(TPMS_NV_PUBLIC));
  public_area.nv_public.data_size = cert.size();

  EXPECT_CALL(mock_tpm_, NV_ReadPublicSync(nv_index, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(public_area), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_, NV_ReadSync(_, _, _, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<6>(nvram_data_buffer), Return(TPM_RC_SUCCESS)));

  std::string ekm;
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetPublicRSAEndorsementKeyModulus(&ekm));
  std::string hex_encoded_ekm =
      "AC5869BD60F30463612BB0C472AA19E5400E524A213290EBFB728D1AAC956F74B7CF6A8D"
      "57F17C94D4BE2B3D07FD882CF708C30C476DCB1FF32695A8BAC77BDD5C04E89E2AB228D6"
      "EDFF2EFAA54BE9C30F9D211E2E42DE7E50CF424EEE6C310D677D8870522E8C953711BE42"
      "C9B94579D56D481560926606C60D74EFEEB013869C0424BB7D8585F79159BE7F476625B9"
      "BD2701D1C5ABA6D407A4724C2165C176C45CD2188576ADC20303C3368D11603CFEEE4CFD"
      "81EB9C9EACF0029C4F41B2E4033AB68453884D5BB3E0DD9F680E150CB604428546CFA32B"
      "05743B073BAE97964A847756BB79D132EAEFF44EE1B25315C6B45CE74087A777CFD14276"
      "9B5CF4E5";
  EXPECT_EQ(hex_encoded_ekm, base::HexEncode(ekm.data(), ekm.size()));
}

TEST_F(TpmUtilityTest, GetRsuDeviceIdDecodesCorrectly) {
  // Hardcoded kGscGetRmaChallenge command and response.
  std::string expected_command(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0c"  // size=12
      "\x20\x00\x00\x00"  // code=kGscVendorCC
      "\x00\x1e",         // subcommand=kGscGetRmaChallenge
      12);
  std::string command_response(
      "\x80\x01"          // tag=TPM_STD_NO_SESSIONS
      "\x00\x00\x00\x5c"  // size=92
      "\x00\x00\x00\x00"  // code=TPM_RC_SUCCESS
      "\x00\x1e\x41\x46\x48\x35\x53\x5a\x37\x51\x47\x55\x56\x58\x58\x33\x36\x56"
      "\x4e\x39\x41\x55\x51\x35\x48\x45\x46\x56\x47\x37\x57\x38\x4d\x45\x4b\x50"
      "\x56\x34\x53\x51\x4d\x42\x52\x45\x43\x54\x34\x46\x35\x50\x47\x5a\x57\x48"
      "\x53\x46\x33\x58\x58\x43\x54\x57\x55\x42\x4d\x4b\x50\x4a\x57\x58\x59\x48"
      "\x51\x45\x36\x57\x50\x34\x39\x46\x46\x46",  // RMA Challenge data
      92);
  std::string expected_device_id(
      "\xcc\x39\xa9\xc9\xfa\xc2\x02\x4d\xa1\xef\xe7\xd3\xec\xd3\x68\xe6\xa1\x9f"
      "\xa3\x79\xfc\x49\x29\x27\x8a\xf1\x31\x67\x33\xf3\x89\xa9",
      32);

  SetGsc(true);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(expected_command))
      .WillOnce(Return(command_response));

  std::string rsu_device_id;
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetRsuDeviceId(&rsu_device_id));
  EXPECT_EQ(rsu_device_id, expected_device_id);
}

TEST_F(TpmUtilityTest, GetRsuDeviceIdCaching) {
  std::string rsu_device_id, rsu_device_id2, rsu_device_id3;
  SetGsc(true);
  // Hardcoded RMA challenges from two devices.
  std::string command_response(
      "\x80\x01"          // tag=TPM_STD_NO_SESSIONS
      "\x00\x00\x00\x5c"  // size=92
      "\x00\x00\x00\x00"  // code=TPM_RC_SUCCESS
      "\x00\x1e\x41\x46\x48\x35\x53\x5a\x37\x51\x47\x55\x56\x58\x58\x33\x36\x56"
      "\x4e\x39\x41\x55\x51\x35\x48\x45\x46\x56\x47\x37\x57\x38\x4d\x45\x4b\x50"
      "\x56\x34\x53\x51\x4d\x42\x52\x45\x43\x54\x34\x46\x35\x50\x47\x5a\x57\x48"
      "\x53\x46\x33\x58\x58\x43\x54\x57\x55\x42\x4d\x4b\x50\x4a\x57\x58\x59\x48"
      "\x51\x45\x36\x57\x50\x34\x39\x46\x46\x46",  // RMA Challenge data
      92);
  std::string command_response2(
      "\x80\x01"          // tag=TPM_STD_NO_SESSIONS
      "\x00\x00\x00\x5c"  // size=92
      "\x00\x00\x00\x00"  // code=TPM_RC_SUCCESS
      "\x00\x1e\x41\x48\x47\x32\x48\x42\x4b\x45\x35\x42\x37\x52\x41\x4b\x55\x53"
      "\x43\x47\x5a\x45\x35\x56\x35\x4c\x38\x48\x46\x35\x33\x36\x4d\x34\x42\x36"
      "\x45\x45\x33\x33\x38\x34\x56\x39\x4c\x47\x4b\x53\x4e\x44\x41\x32\x41\x38"
      "\x50\x34\x5a\x58\x43\x55\x54\x57\x55\x42\x4d\x4b\x50\x51\x33\x4d\x5a\x39"
      "\x35\x52\x58\x39\x51\x45\x52\x33\x4c\x32",  // RMA challenge data
      92);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_))
      .WillOnce(Return(command_response))
      .WillOnce(Return(command_response2));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetRsuDeviceId(&rsu_device_id));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetRsuDeviceId(&rsu_device_id2));
  EXPECT_EQ(rsu_device_id, rsu_device_id2);

  EXPECT_EQ(TPM_RC_SUCCESS, TpmUtilityGetRsuDeviceIdInternal(&rsu_device_id3));
  EXPECT_NE(rsu_device_id, rsu_device_id3);
}

TEST_F(TpmUtilityTest,
       GetRsuDeviceIdReturnsTheSameValueForDifferentChallenges) {
  SetGsc(true);
  // Hardcoded RMA challenges from the same device.
  std::string command_response(
      "\x80\x01"          // tag=TPM_STD_NO_SESSIONS
      "\x00\x00\x00\x5c"  // size=92
      "\x00\x00\x00\x00"  // code=TPM_RC_SUCCESS
      "\x00\x1e\x41\x46\x48\x35\x53\x5a\x37\x51\x47\x55\x56\x58\x58\x33\x36\x56"
      "\x4e\x39\x41\x55\x51\x35\x48\x45\x46\x56\x47\x37\x57\x38\x4d\x45\x4b\x50"
      "\x56\x34\x53\x51\x4d\x42\x52\x45\x43\x54\x34\x46\x35\x50\x47\x5a\x57\x48"
      "\x53\x46\x33\x58\x58\x43\x54\x57\x55\x42\x4d\x4b\x50\x4a\x57\x58\x59\x48"
      "\x51\x45\x36\x57\x50\x34\x39\x46\x46\x46",  // RMA Challenge data
      92);
  std::string command_response2(
      "\x80\x01"
      "\x00\x00\x00\x5c"
      "\x00\x00\x00\x00"
      "\x00\x1e\x41\x46\x56\x4c\x4e\x4a\x4b\x48\x38\x4e\x4a\x46\x56\x35\x48\x34"
      "\x39\x57\x56\x59\x51\x43\x4a\x58\x52\x45\x4d\x5a\x32\x36\x44\x55\x4c\x51"
      "\x4e\x44\x39\x54\x35\x38\x50\x43\x33\x54\x52\x51\x55\x41\x4e\x35\x53\x51"
      "\x55\x54\x59\x35\x4d\x55\x54\x4b\x55\x42\x4d\x4b\x50\x4a\x57\x58\x59\x48"
      "\x51\x45\x36\x57\x50\x34\x39\x46\x46\x46",  // RMA Challenge data
      92);

  std::string rsu_device_id, rsu_device_id2;
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_))
      .WillOnce(Return(command_response))
      .WillOnce(Return(command_response2));
  EXPECT_EQ(TPM_RC_SUCCESS, TpmUtilityGetRsuDeviceIdInternal(&rsu_device_id));
  EXPECT_EQ(TPM_RC_SUCCESS, TpmUtilityGetRsuDeviceIdInternal(&rsu_device_id2));
  EXPECT_EQ(rsu_device_id, rsu_device_id2);
}

TEST_F(TpmUtilityTest, ManageCCDPwdNonGsc) {
  SetGsc(false);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_)).Times(0);
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.ManageCCDPwd(true));
}

TEST_F(TpmUtilityTest, ManageCCDPwdGscSuccess) {
  // A hand-coded kGscSubcmdManageCCDPwd command (two variants: true and false)
  // and response.
  std::string expected_command_true(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0D"  // size=13
      "\x20\x00\x00\x00"  // code=kGscVendorCC
      "\x00\x21"          // subcommand=kGscSubcmdManageCCDPwd
      "\x01",             // value=true
      13);
  std::string expected_command_false(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0D"  // size=13
      "\x20\x00\x00\x00"  // code=kGscVendorCC
      "\x00\x21"          // subcommand=kGscSubcmdManageCCDPwd
      "\x00",             // value=false
      13);
  std::string command_response(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0C"  // size=12
      "\x00\x00\x00\x00"  // code=TPM_RC_SUCCESS
      "\x00\x21",         // subcommand=kGscSubcmdManageCCDPwd
      12);
  SetGsc(true);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(expected_command_true))
      .WillOnce(Return(command_response));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.ManageCCDPwd(true));
  testing::Mock::VerifyAndClearExpectations(&mock_transceiver_);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(expected_command_false))
      .WillOnce(Return(command_response));
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.ManageCCDPwd(false));
}

TEST_F(TpmUtilityTest, ManageCCDPwdFailure) {
  // A hand-coded kGscSubcmdManageCCDPwd command and response.
  std::string expected_command(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0D"  // size=13
      "\x20\x00\x00\x00"  // code=kGscVendorCC
      "\x00\x21"          // subcommand=kGscSubcmdManageCCDPwd
      "\x01",             // value=true
      13);
  std::string command_response(
      "\x80\x01"          // tag=TPM_ST_NO_SESSIONS
      "\x00\x00\x00\x0C"  // size=12
      "\x00\x00\x01\x01"  // code=TPM_RC_FAILURE
      "\x00\x21",         // subcommand=kGscSubcmdManageCCDPwd
      12);
  SetGsc(true);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(expected_command))
      .WillOnce(Return(command_response));
  EXPECT_EQ(TPM_RC_FAILURE, utility_.ManageCCDPwd(true));
}

TEST_F(TpmUtilityTest, IsGsc) {
  SetGsc(true);
  EXPECT_TRUE(utility_.IsGsc());
}

TEST_F(TpmUtilityTest, NotGsc) {
  SetGsc(false);
  EXPECT_FALSE(utility_.IsGsc());
}

TEST_F(TpmUtilityTest, GetRoVerificationStatus) {
  // A hand-coded kGscSubcmdGetRoStatus command and response.
  std::string command_response(
      "\x80\x01"          // tag=TPM_STD_NO_SESSIONS
      "\x00\x00\x00\x0D"  // size=13
      "\x00\x00\x00\x00"  // code=TPM_RC_SUCCESS
      "\x00\x39"          // subcommand=kGscSubcmdGetRoStatus
      "\x01",             // ap_ro_status=AP_RO_PASS_UNVERIFIED_GBB
      13);
  SetGsc(true);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_))
      .WillOnce(Return(command_response));
  ap_ro_status status;
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetRoVerificationStatus(&status));
  EXPECT_EQ(status, AP_RO_PASS_UNVERIFIED_GBB);
}

TEST_F(TpmUtilityTest, GetRoVerificationStatusForNotGsc) {
  SetGsc(false);
  ap_ro_status status;
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetRoVerificationStatus(&status));
  EXPECT_EQ(status, AP_RO_NOT_RUN);
}

TEST_F(TpmUtilityTest, GetTi50Stats) {
  std::string command_response(
      "\x80\x01"           // tag=TPM_STD_NO_SESSIONS
      "\x00\x00\x00\x1C"   // size=28
      "\x00\x00\x00\x00"   // code=TPM_RC_SUCCESS
      "\x00\x41"           // subcommand=kTi50GetMetrics
      "\xAA\xBB\xCC\xDD"   // fs_init_time = 0xAABBCCDD
      "\x11\x22\x33\x44"   // fs_size = 0x11223344
      "\x55\x66\x77\x88"   // aprov_time = 0x55667788
      "\x99\x00\xAA\xBB",  // aprov_status = 0x9900AABB
      28);
  EXPECT_CALL(mock_transceiver_, SendCommandAndWait(_))
      .WillOnce(Return(command_response));
  uint32_t fs_time = 0;
  uint32_t fs_size = 0;
  uint32_t aprov_time = 0;
  uint32_t aprov_status = 0;
  EXPECT_EQ(TPM_RC_SUCCESS, utility_.GetTi50Stats(&fs_time, &fs_size,
                                                  &aprov_time, &aprov_status));
  EXPECT_EQ(fs_time, 0xAABBCCDD);
  EXPECT_EQ(fs_size, 0x11223344);
  EXPECT_EQ(aprov_time, 0x55667788);
  EXPECT_EQ(aprov_status, 0x9900AABB);
}
}  // namespace trunks
