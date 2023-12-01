// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Fuzzer for TPM Pinweaver.

#include <map>
#include <string>
#include <vector>

#include <stdint.h>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "trunks/tpm_pinweaver.h"

namespace {

// Max fuzzed string length.
constexpr size_t kMaxStringLength = 2048;

// Max size for other collection fields like maps, proto entries, etc.
constexpr size_t kMaxCollectionDataLength = 8;

// Max size for params that should be the length PW_SECRET_SIZE, we use the
// larger size to hit the cases where we should exit gracefully.
constexpr size_t kMaxPwSecretSize = PW_SECRET_SIZE * 2;

// Max size for params that should be the length PW_HASH_SIZE, we use the
// larger size to hit the cases where we should exit gracefully.
constexpr size_t kMaxPwHashSize = PW_HASH_SIZE * 2;

typedef enum PinweaverFunc {
  kSerializePwPing = 0,
  kSerializePwResetTree,
  kSerializePwInsertLeaf,
  kSerializePwRemoveLeaf,
  kSerializePwTryAuth,
  kSerializePwResetAuth,
  kSerializePwGetLog,
  kSerializePwLogReplay,
  kSerializePwSysInfo,
  kSerializePwGenerateBaPk,
  kSerializePwStartBioAuth,
  kSerializePwBlockGenerateBaPk,
  kParsePwResponseHeader,
  kParsePwShortMessage,
  kParsePwPong,
  kParsePwInsertLeaf,
  kParsePwTryAuth,
  kParsePwResetAuth,
  kParsePwGetLog,
  kParsePwLogReplay,
  kParsePwSysInfo,
  kParsePwGenerateBaPk,
  kParsePwStartBioAuth,
  kMaxValue = kParsePwStartBioAuth,
} PinweaverFunc;

// Manually create the fuzzed protobuf since it's only used in one function call
// we are fuzzing rather than being the overall input for the fuzzer target.
trunks::ValidPcrCriteria GenerateFuzzedValidPcrCriteria(
    FuzzedDataProvider* data_provider) {
  trunks::ValidPcrCriteria valid_pcr_criteria;
  int num_values =
      data_provider->ConsumeIntegralInRange<int>(0, kMaxCollectionDataLength);
  for (int i = 0; i < num_values; ++i) {
    trunks::ValidPcrValue* value = valid_pcr_criteria.add_valid_pcr_values();
    value->set_bitmask(data_provider->ConsumeRandomLengthString(8));
    value->set_digest(
        data_provider->ConsumeRandomLengthString(kMaxStringLength));
  }
  return valid_pcr_criteria;
}

trunks::PinWeaverEccPoint GenerateFuzzedEccPoint(
    FuzzedDataProvider* data_provider) {
  trunks::PinWeaverEccPoint ecc_point;
  data_provider->ConsumeData(&ecc_point, sizeof(ecc_point));
  return ecc_point;
}

}  // namespace

struct Environment {
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);

  // Randomly execute functions while we still have data.
  while (data_provider.remaining_bytes() > 0) {
    // Variables for all the output values from functions.
    std::string buf1, buf2, buf3;
    uint8_t res8;
    uint16_t res16;
    uint32_t res32_1;
    uint32_t res32_2;
    uint64_t res64;
    brillo::SecureBlob sec_blob1;
    brillo::SecureBlob sec_blob2;
    brillo::Blob blob1;
    brillo::Blob blob2;
    brillo::Blob blob3;
    std::vector<trunks::PinWeaverLogEntry> logs;
    trunks::TPM_RC retval;

    PinweaverFunc which_func = data_provider.ConsumeEnum<PinweaverFunc>();
    switch (which_func) {
      case kSerializePwPing:
        retval = trunks::Serialize_pw_ping_t(
            data_provider.ConsumeIntegral<uint8_t>(), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwResetTree:
        retval = trunks::Serialize_pw_reset_tree_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeIntegral<uint8_t>(), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwInsertLeaf: {
        std::map<uint32_t, uint32_t> delay_schedule;
        int map_size = data_provider.ConsumeIntegralInRange<int>(
            0, kMaxCollectionDataLength);
        for (int i = 0; i < map_size; ++i) {
          delay_schedule[data_provider.ConsumeIntegral<uint32_t>()] =
              data_provider.ConsumeIntegral<uint32_t>();
        }
        retval = trunks::Serialize_pw_insert_leaf_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeIntegral<uint64_t>(),
            data_provider.ConsumeRandomLengthString(kMaxStringLength),
            brillo::SecureBlob(
                data_provider.ConsumeRandomLengthString(kMaxPwSecretSize)),
            brillo::SecureBlob(
                data_provider.ConsumeRandomLengthString(kMaxPwSecretSize)),
            brillo::SecureBlob(
                data_provider.ConsumeRandomLengthString(kMaxPwSecretSize)),
            delay_schedule, GenerateFuzzedValidPcrCriteria(&data_provider),
            data_provider.ConsumeIntegral<uint32_t>(),
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeIntegral<uint8_t>(), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      }
      case kSerializePwRemoveLeaf:
        retval = trunks::Serialize_pw_remove_leaf_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeIntegral<uint64_t>(),
            data_provider.ConsumeRandomLengthString(kMaxStringLength),
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwTryAuth:
        retval = trunks::Serialize_pw_try_auth_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            brillo::SecureBlob(
                data_provider.ConsumeRandomLengthString(kMaxPwSecretSize)),
            data_provider.ConsumeRandomLengthString(kMaxStringLength),
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwResetAuth:
        retval = trunks::Serialize_pw_reset_auth_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            brillo::SecureBlob(
                data_provider.ConsumeRandomLengthString(kMaxPwSecretSize)),
            data_provider.ConsumeBool(),
            data_provider.ConsumeRandomLengthString(kMaxStringLength),
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwGetLog:
        retval = trunks::Serialize_pw_get_log_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeRandomLengthString(kMaxPwHashSize), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwLogReplay:
        retval = trunks::Serialize_pw_log_replay_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeRandomLengthString(kMaxPwHashSize),
            data_provider.ConsumeRandomLengthString(kMaxStringLength),
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwSysInfo:
        retval = trunks::Serialize_pw_sys_info_t(
            data_provider.ConsumeIntegral<uint8_t>(), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwGenerateBaPk:
        retval = trunks::Serialize_pw_generate_ba_pk_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeIntegral<uint8_t>(),
            GenerateFuzzedEccPoint(&data_provider), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwStartBioAuth:
        retval = trunks::Serialize_pw_start_bio_auth_t(
            data_provider.ConsumeIntegral<uint8_t>(),
            data_provider.ConsumeIntegral<uint8_t>(),
            brillo::BlobFromString(
                data_provider.ConsumeRandomLengthString(kMaxPwSecretSize)),
            data_provider.ConsumeRandomLengthString(kMaxStringLength),
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kSerializePwBlockGenerateBaPk:
        retval = trunks::Serialize_pw_block_generate_ba_pk_t(
            data_provider.ConsumeIntegral<uint8_t>(), &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwResponseHeader:
        retval = trunks::Parse_pw_response_header_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &res16);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwShortMessage:
        retval = trunks::Parse_pw_short_message(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwPong:
        trunks::Parse_pw_pong_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res8);
        break;
      case kParsePwInsertLeaf:
        retval = trunks::Parse_pw_insert_leaf_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &buf2, &buf3);
        // According to tpm_pinweaver.h, only the first buffer (root_hash) is
        // required to be non-empty on success in all cases for Parse_ calls.
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwTryAuth:
        retval = trunks::Parse_pw_try_auth_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &res32_2, &sec_blob1, &sec_blob2, &buf2, &buf3);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwResetAuth:
        retval = trunks::Parse_pw_reset_auth_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &buf2, &buf3);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwGetLog:
        retval = trunks::Parse_pw_get_log_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &logs);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwLogReplay:
        retval = trunks::Parse_pw_log_replay_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &buf2, &buf3);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwSysInfo:
        retval = trunks::Parse_pw_sys_info_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &res32_2, &res64);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      case kParsePwGenerateBaPk: {
        trunks::PinWeaverEccPoint pt;
        retval = trunks::Parse_pw_generate_ba_pk_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &pt);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
      }
      case kParsePwStartBioAuth:
        retval = trunks::Parse_pw_start_bio_auth_t(
            data_provider.ConsumeRandomLengthString(kMaxStringLength), &res32_1,
            &buf1, &blob1, &blob2, &blob3, &buf2, &buf3);
        if (retval == trunks::TPM_RC_SUCCESS)
          CHECK(!buf1.empty());
        break;
    }
  }

  return 0;
}
