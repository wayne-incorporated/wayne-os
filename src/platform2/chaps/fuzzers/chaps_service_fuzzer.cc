// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <vector>

#include <base/command_line.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/test/task_environment.h>
#include <base/test/test_timeouts.h>
#include <chaps/proto_bindings/ck_structs.pb.h>
#include <libhwsec/factory/fuzzed_factory.h>

#include "chaps/attributes.h"
#include "chaps/chaps_factory_impl.h"
#include "chaps/chaps_interface.h"
#include "chaps/chaps_service.h"
#include "chaps/isolate.h"
#include "chaps/session.h"
#include "chaps/slot_manager_impl.h"

namespace {
enum class ChapsServiceRequest {
  kGetSlotList,
  kGetSlotInfo,
  kGetTokenInfo,
  kGetMechanismList,
  kGetMechanismInfo,
  kInitToken,
  kInitPIN,
  kSetPIN,
  kOpenSession,
  kCloseSession,
  kGetSessionInfo,
  kGetOperationState,
  kSetOperationState,
  kLogin,
  kLogout,
  kCreateObject,
  kCopyObject,
  kDestroyObject,
  kGetObjectSize,
  kGetAttributeValue,
  kSetAttributeValue,
  kFindObjectsInit,
  kFindObjects,
  kFindObjectsFinal,
  kEncryptInit,
  kEncrypt,
  kEncryptUpdate,
  kEncryptFinal,
  kEncryptCancel,
  kDecryptInit,
  kDecrypt,
  kDecryptUpdate,
  kDecryptFinal,
  kDecryptCancel,
  kDigestInit,
  kDigest,
  kDigestUpdate,
  kDigestKey,
  kDigestFinal,
  kDigestCancel,
  kSignInit,
  kSign,
  kSignUpdate,
  kSignFinal,
  kSignCancel,
  kSignRecoverInit,
  kSignRecover,
  kVerifyInit,
  kVerify,
  kVerifyUpdate,
  kVerifyFinal,
  kVerifyCancel,
  kVerifyRecoverInit,
  kVerifyRecover,
  kDigestEncryptUpdate,
  kDecryptDigestUpdate,
  kSignEncryptUpdate,
  kDecryptVerifyUpdate,
  kGenerateKey,
  kGenerateKeyPair,
  kWrapKey,
  kUnwrapKey,
  kDeriveKey,
  kSeedRandom,
  kGenerateRandom,
  kMaxValue = kGenerateRandom,
};

enum class TokenManagerInterfaceRequest {
  kOpenIsolate,
  kCloseIsolate,
  kLoadToken,
  kUnloadToken,
  kGetTokenPath,
  kMaxValue = kGetTokenPath,
};

// An arbitrary choice that provides satisfactory coverage
constexpr int kSuccessProbability = 90;
constexpr int kChapsServiceProbability = 90;
// Provide max iterations for a single fuzz run, otherwise it might timeout.
constexpr int kMaxIterations = 100;
constexpr uint64_t kSmallLen = 10;
constexpr uint64_t kLargeLen = 100000;

constexpr uint64_t kUserTypes[4] = {CKU_SO, CKU_USER, CKU_CONTEXT_SPECIFIC,
                                    3 /*invalid user type*/};
constexpr uint64_t kMechanismTypes[5] = {
    // CKF_GENERATE_KEY_PAIR | CKF_HW
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    // CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY
    CKM_RSA_PKCS,
    // CKF_DIGEST
    CKM_MD5,
    // CKF_GENERATE
    CKM_GENERIC_SECRET_KEY_GEN,
    // Not used
    CKM_RSA_9796};

bool SerializeAttributes(CK_ATTRIBUTE_PTR attributes,
                         CK_ULONG num_attributes,
                         std::vector<uint8_t>* serialized) {
  chaps::Attributes tmp(attributes, num_attributes);
  return tmp.Serialize(serialized);
}

class ChapsServiceFuzzer {
 public:
  explicit ChapsServiceFuzzer(FuzzedDataProvider* hwsec_data_provider,
                              FuzzedDataProvider* data_provider)
      : data_provider_(data_provider) {
    CHECK(tmp_dir_.CreateUniqueTempDir());
    chaps_metrics_ = std::make_unique<chaps::ChapsMetrics>();
    factory_ = std::make_unique<chaps::ChapsFactoryImpl>(chaps_metrics_.get());
    hwsec_factory_ =
        std::make_unique<hwsec::FuzzedFactory>(*hwsec_data_provider);
    hwsec_ = hwsec_factory_->GetChapsFrontend();

    bool auto_load_system_token = data_provider_->ConsumeBool();
    slot_manager_ = std::make_unique<chaps::SlotManagerImpl>(
        factory_.get(), hwsec_.get(), auto_load_system_token, nullptr,
        chaps_metrics_.get());
    chaps_service_ =
        std::make_unique<chaps::ChapsServiceImpl>(slot_manager_.get());

    generated_isolate_credentials_.push_back(
        chaps::IsolateCredentialManager::GetDefaultIsolateCredential()
            .to_string());

    if (ConsumeProbability(kSuccessProbability)) {
      CreateObject(GetObjectAttribute());
      CreateObject(GetEncryptKeyAttribute());
      CreateObject(GetDigestKeyAttribute());
      CreateObject(GetSignKeyAttribute());
    }
  }

  ~ChapsServiceFuzzer() {
    chaps_service_.reset();
    slot_manager_.reset();
    hwsec_.reset();
    hwsec_factory_.reset();
    factory_.reset();
    chaps_metrics_.reset();
  }

  void Run() {
    int rounds = 0;
    while (data_provider_->remaining_bytes() > 0 && rounds < kMaxIterations) {
      if (ConsumeProbability(kChapsServiceProbability)) {
        FuzzChapsServiceRequest();
      } else {
        FuzzTokenManagerInterfaceRequest();
      }
      task_environment_.RunUntilIdle();
      rounds++;
    }
  }

 private:
  void FuzzChapsServiceRequest() {
    auto request = data_provider_->ConsumeEnum<ChapsServiceRequest>();

    LOG(INFO) << "chaps service request: " << static_cast<int>(request);

    switch (request) {
      case ChapsServiceRequest::kGetSlotList: {
        std::vector<uint64_t> slot_list;
        chaps_service_->GetSlotList(GetIsolateCredential(),
                                    data_provider_->ConsumeBool(), &slot_list);
        break;
      }
      case ChapsServiceRequest::kGetSlotInfo: {
        chaps::SlotInfo slot_info;
        chaps_service_->GetSlotInfo(GetIsolateCredential(), GetSlotId(),
                                    &slot_info);
        break;
      }
      case ChapsServiceRequest::kGetTokenInfo: {
        chaps::TokenInfo token_info;
        chaps_service_->GetTokenInfo(GetIsolateCredential(), GetSlotId(),
                                     &token_info);
        break;
      }
      case ChapsServiceRequest::kGetMechanismList: {
        std::vector<uint64_t> mechanism_list;
        chaps_service_->GetMechanismList(GetIsolateCredential(), GetSlotId(),
                                         &mechanism_list);
        break;
      }
      case ChapsServiceRequest::kGetMechanismInfo: {
        chaps::MechanismInfo mechanism_info;
        uint64_t mechanism_type =
            data_provider_->PickValueInArray(kMechanismTypes);
        chaps_service_->GetMechanismInfo(GetIsolateCredential(), GetSlotId(),
                                         mechanism_type, &mechanism_info);
        break;
      }
      case ChapsServiceRequest::kInitToken: {
        const std::vector<uint8_t> label(32);
        chaps_service_->InitToken(GetIsolateCredential(), GetSlotId(),
                                  /*so_pin=*/nullptr, label);
        break;
      }
      case ChapsServiceRequest::kInitPIN: {
        chaps_service_->InitPIN(GetIsolateCredential(), GetSessionId(),
                                /*pin=*/nullptr);
        break;
      }
      case ChapsServiceRequest::kSetPIN: {
        chaps_service_->SetPIN(GetIsolateCredential(), GetSessionId(),
                               /*old_pin=*/nullptr, /*new_pin=*/nullptr);
        break;
      }
      case ChapsServiceRequest::kOpenSession: {
        OpenSession();
        break;
      }
      case ChapsServiceRequest::kCloseSession: {
        chaps_service_->CloseSession(GetIsolateCredential(), GetSessionId());
        break;
      }
      case ChapsServiceRequest::kGetSessionInfo: {
        chaps::SessionInfo session_info;
        chaps_service_->GetSessionInfo(GetIsolateCredential(), GetSessionId(),
                                       &session_info);
        break;
      }
      case ChapsServiceRequest::kGetOperationState: {
        std::vector<uint8_t> operation_state;
        chaps_service_->GetOperationState(GetIsolateCredential(),
                                          GetSessionId(), &operation_state);
        break;
      }
      case ChapsServiceRequest::kSetOperationState: {
        const std::vector<uint8_t> operation_state;
        chaps_service_->SetOperationState(
            GetIsolateCredential(), GetSessionId(), operation_state,
            /*encryption_key_handle=*/0, /*authentication_key_handle=*/0);
        break;
      }
      case ChapsServiceRequest::kLogin: {
        uint64_t user_type = data_provider_->PickValueInArray(kUserTypes);
        std::string legacy_pin = std::string("111111");

        chaps_service_->Login(
            GetIsolateCredential(), GetSessionId(), user_type,
            /*pin=*/data_provider_->ConsumeBool() ? nullptr : &legacy_pin);
        break;
      }
      case ChapsServiceRequest::kLogout: {
        chaps_service_->Logout(GetIsolateCredential(), GetSessionId());
        break;
      }
      case ChapsServiceRequest::kCreateObject: {
        CreateRandomObject();
        break;
      }
      case ChapsServiceRequest::kCopyObject: {
        auto attributes = data_provider_->ConsumeBytes<uint8_t>(
            data_provider_->ConsumeIntegralInRange(0, 10));
        uint64_t new_object_handle;
        if (chaps_service_->CopyObject(GetIsolateCredential(), GetSessionId(),
                                       GetObjectHandle(), attributes,
                                       &new_object_handle) == CKR_OK) {
          generated_object_handles_.push_back(new_object_handle);
        }
        break;
      }
      case ChapsServiceRequest::kDestroyObject: {
        chaps_service_->DestroyObject(GetIsolateCredential(), GetSessionId(),
                                      GetObjectHandle());
        break;
      }
      case ChapsServiceRequest::kGetObjectSize: {
        uint64_t object_size;
        chaps_service_->GetObjectSize(GetIsolateCredential(), GetSessionId(),
                                      GetObjectHandle(), &object_size);
        break;
      }
      case ChapsServiceRequest::kGetAttributeValue: {
        auto attributes_in = data_provider_->ConsumeBytes<uint8_t>(
            data_provider_->ConsumeIntegralInRange(0, 10));
        std::vector<uint8_t> attributes_out;
        chaps_service_->GetAttributeValue(GetIsolateCredential(),
                                          GetSessionId(), GetObjectHandle(),
                                          attributes_in, &attributes_out);
        break;
      }
      case ChapsServiceRequest::kSetAttributeValue: {
        auto attributes = data_provider_->ConsumeBytes<uint8_t>(
            data_provider_->ConsumeIntegralInRange(0, 10));
        chaps_service_->SetAttributeValue(GetIsolateCredential(),
                                          GetSessionId(), GetObjectHandle(),
                                          attributes);
        break;
      }
      case ChapsServiceRequest::kFindObjectsInit: {
        auto attributes = data_provider_->ConsumeBytes<uint8_t>(
            data_provider_->ConsumeIntegralInRange(0, 10));
        chaps_service_->FindObjectsInit(GetIsolateCredential(), GetSessionId(),
                                        attributes);
        break;
      }
      case ChapsServiceRequest::kFindObjects: {
        std::vector<uint64_t> object_list;
        chaps_service_->FindObjects(
            GetIsolateCredential(), GetSessionId(),
            /*max_object_count=*/data_provider_->ConsumeIntegralInRange(0, 5),
            &object_list);
        break;
      }
      case ChapsServiceRequest::kFindObjectsFinal: {
        chaps_service_->FindObjectsFinal(GetIsolateCredential(),
                                         GetSessionId());
        break;
      }
      case ChapsServiceRequest::kEncryptInit: {
        uint64_t mechanism_type =
            data_provider_->PickValueInArray(kMechanismTypes);
        chaps_service_->EncryptInit(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)),
            GetObjectHandle());
        break;
      }
      case ChapsServiceRequest::kEncrypt: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->Encrypt(GetIsolateCredential(), GetSessionId(), data_in,
                                GetMaxOutLen(), &actual_out_length, &data_out);
        break;
      }
      case ChapsServiceRequest::kEncryptUpdate: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->EncryptUpdate(GetIsolateCredential(), GetSessionId(),
                                      data_in, GetMaxOutLen(),
                                      &actual_out_length, &data_out);
        break;
      }
      case ChapsServiceRequest::kEncryptFinal: {
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->EncryptFinal(GetIsolateCredential(), GetSessionId(),
                                     GetMaxOutLen(), &actual_out_length,
                                     &data_out);
        break;
      }
      case ChapsServiceRequest::kEncryptCancel: {
        chaps_service_->EncryptCancel(GetIsolateCredential(), GetSessionId());
        break;
      }
      case ChapsServiceRequest::kDecryptInit: {
        uint64_t mechanism_type =
            data_provider_->PickValueInArray(kMechanismTypes);
        chaps_service_->DecryptInit(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)),
            GetObjectHandle());
        break;
      }
      case ChapsServiceRequest::kDecrypt: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->Decrypt(GetIsolateCredential(), GetSessionId(), data_in,
                                GetMaxOutLen(), &actual_out_length, &data_out);
        break;
      }
      case ChapsServiceRequest::kDecryptUpdate: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->DecryptUpdate(GetIsolateCredential(), GetSessionId(),
                                      data_in, GetMaxOutLen(),
                                      &actual_out_length, &data_out);
        break;
      }
      case ChapsServiceRequest::kDecryptFinal: {
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->DecryptFinal(GetIsolateCredential(), GetSessionId(),
                                     GetMaxOutLen(), &actual_out_length,
                                     &data_out);
        break;
      }
      case ChapsServiceRequest::kDecryptCancel: {
        chaps_service_->DecryptCancel(GetIsolateCredential(), GetSessionId());
        break;
      }
      case ChapsServiceRequest::kDigestInit: {
        uint64_t mechanism_type =
            data_provider_->PickValueInArray(kMechanismTypes);
        chaps_service_->DigestInit(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)));
        break;
      }
      case ChapsServiceRequest::kDigest: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->Digest(GetIsolateCredential(), GetSessionId(), data_in,
                               GetMaxOutLen(), &actual_out_length, &data_out);
        break;
      }
      case ChapsServiceRequest::kDigestUpdate: {
        // Just try a zero, a small number, and a large number.

        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        chaps_service_->DigestUpdate(GetIsolateCredential(), GetSessionId(),
                                     data_in);
        break;
      }
      case ChapsServiceRequest::kDigestKey: {
        chaps_service_->DigestKey(GetIsolateCredential(), GetSessionId(),
                                  GetObjectHandle());
        break;
      }
      case ChapsServiceRequest::kDigestFinal: {
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->DigestFinal(GetIsolateCredential(), GetSessionId(),
                                    GetMaxOutLen(), &actual_out_length,
                                    &data_out);
        break;
      }
      case ChapsServiceRequest::kDigestCancel: {
        chaps_service_->DigestCancel(GetIsolateCredential(), GetSessionId());
        break;
      }
      case ChapsServiceRequest::kSignInit: {
        uint64_t mechanism_type =
            data_provider_->PickValueInArray(kMechanismTypes);
        chaps_service_->SignInit(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)),
            GetObjectHandle());
        break;
      }
      case ChapsServiceRequest::kSign: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->Sign(GetIsolateCredential(), GetSessionId(), data_in,
                             GetMaxOutLen(), &actual_out_length, &data_out);
        break;
      }
      case ChapsServiceRequest::kSignUpdate: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        chaps_service_->SignUpdate(GetIsolateCredential(), GetSessionId(),
                                   data_in);
        break;
      }
      case ChapsServiceRequest::kSignFinal: {
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->SignFinal(GetIsolateCredential(), GetSessionId(),
                                  GetMaxOutLen(), &actual_out_length,
                                  &data_out);
        break;
      }
      case ChapsServiceRequest::kSignCancel: {
        chaps_service_->SignCancel(GetIsolateCredential(), GetSessionId());
        break;
      }
      case ChapsServiceRequest::kSignRecoverInit: {
        uint64_t mechanism_type =
            data_provider_->PickValueInArray(kMechanismTypes);
        chaps_service_->SignRecoverInit(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)),
            GetObjectHandle());
        break;
      }
      case ChapsServiceRequest::kSignRecover: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        uint64_t actual_out_length;
        std::vector<uint8_t> data_out;
        chaps_service_->SignRecover(GetIsolateCredential(), GetSessionId(),
                                    data_in, GetMaxOutLen(), &actual_out_length,
                                    &data_out);
        break;
      }
      case ChapsServiceRequest::kVerifyInit: {
        uint64_t mechanism_type =
            data_provider_->PickValueInArray(kMechanismTypes);
        chaps_service_->VerifyInit(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)),
            GetObjectHandle());
        break;
      }
      case ChapsServiceRequest::kVerify: {
        std::vector<uint8_t> data = ConsumeLowEntropyRandomLengthBytes(20);
        std::vector<uint8_t> signature = ConsumeLowEntropyRandomLengthBytes(20);
        chaps_service_->Verify(GetIsolateCredential(), GetSessionId(), data,
                               signature);
        break;
      }
      case ChapsServiceRequest::kVerifyUpdate: {
        std::vector<uint8_t> data_in = ConsumeLowEntropyBytes(GetMaxOutLen());
        chaps_service_->VerifyUpdate(GetIsolateCredential(), GetSessionId(),
                                     data_in);
        break;
      }
      case ChapsServiceRequest::kVerifyFinal: {
        std::vector<uint8_t> signature = ConsumeLowEntropyRandomLengthBytes(20);
        chaps_service_->VerifyFinal(GetIsolateCredential(), GetSessionId(),
                                    signature);
        break;
      }
      case ChapsServiceRequest::kVerifyCancel: {
        chaps_service_->VerifyCancel(GetIsolateCredential(), GetSessionId());
        break;
      }
      case ChapsServiceRequest::kVerifyRecoverInit:
      case ChapsServiceRequest::kVerifyRecover:
      case ChapsServiceRequest::kDigestEncryptUpdate:
      case ChapsServiceRequest::kDecryptDigestUpdate:
      case ChapsServiceRequest::kSignEncryptUpdate:
      case ChapsServiceRequest::kDecryptVerifyUpdate:
        // not supported
        break;
      case ChapsServiceRequest::kGenerateKey: {
        // Just cover at least one mechanism that is included in the list. 0 and
        // 1 are included and 2 isn't.
        auto attributes = data_provider_->ConsumeBytes<uint8_t>(
            data_provider_->ConsumeIntegralInRange(0, 10));
        uint64_t mechanism_type = data_provider_->ConsumeIntegralInRange(0, 2);
        uint64_t key_handle;
        chaps_service_->GenerateKey(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)),
            attributes, &key_handle);
        break;
      }
      case ChapsServiceRequest::kGenerateKeyPair: {
        // Just cover at least one mechanism that is included in the list. 0 and
        // 1 are included and 2 isn't.
        auto public_attributes = data_provider_->ConsumeBytes<uint8_t>(
            data_provider_->ConsumeIntegralInRange(0, 10));
        auto private_attributes = data_provider_->ConsumeBytes<uint8_t>(
            data_provider_->ConsumeIntegralInRange(0, 10));
        uint64_t mechanism_type = data_provider_->ConsumeIntegralInRange(0, 2);
        uint64_t public_key_handle;
        uint64_t private_key_handle;
        chaps_service_->GenerateKeyPair(
            GetIsolateCredential(), GetSessionId(),
            mechanism_type, /*mechanism_parameter=*/
            data_provider_->ConsumeBytes<uint8_t>(
                data_provider_->ConsumeIntegralInRange(0, 10)),
            public_attributes, private_attributes, &public_key_handle,
            &private_key_handle);
        break;
      }
      case ChapsServiceRequest::kWrapKey:
      case ChapsServiceRequest::kUnwrapKey:
      case ChapsServiceRequest::kDeriveKey:
        // not supported
        break;
      case ChapsServiceRequest::kSeedRandom: {
        auto seed = ConsumeLowEntropyRandomLengthBytes(10);
        chaps_service_->SeedRandom(GetIsolateCredential(), GetSessionId(),
                                   seed);
        break;
      }
      case ChapsServiceRequest::kGenerateRandom: {
        std::vector<uint8_t> random_data;
        chaps_service_->GenerateRandom(
            GetIsolateCredential(), GetSessionId(),
            /*num_bytes=*/
            data_provider_->ConsumeIntegralInRange<uint64_t>(0, 1000),
            &random_data);
        break;
      }
      default:
        break;
    }
  }

  void FuzzTokenManagerInterfaceRequest() {
    auto request = data_provider_->ConsumeEnum<TokenManagerInterfaceRequest>();

    LOG(INFO) << "token manager request: " << static_cast<int>(request);

    switch (request) {
      case TokenManagerInterfaceRequest::kOpenIsolate: {
        brillo::SecureBlob isolate_credential;
        bool new_isolate_created;

        if (slot_manager_->OpenIsolate(&isolate_credential,
                                       &new_isolate_created) &&
            new_isolate_created) {
          generated_isolate_credentials_.push_back(
              isolate_credential.to_string());
        }
        break;
      }
      case TokenManagerInterfaceRequest::kCloseIsolate: {
        slot_manager_->CloseIsolate(GetIsolateCredential());
        break;
      }
      case TokenManagerInterfaceRequest::kLoadToken: {
        LoadToken();
        break;
      }
      case TokenManagerInterfaceRequest::kUnloadToken: {
        slot_manager_->UnloadToken(GetIsolateCredential(), tmp_dir_.GetPath());
        break;
      }
      case TokenManagerInterfaceRequest::kGetTokenPath: {
        base::FilePath path;
        slot_manager_->GetTokenPath(GetIsolateCredential(), GetSlotId(), &path);
        break;
      }
    }
  }

  bool ConsumeProbability(uint32_t probability) {
    return data_provider_->ConsumeIntegralInRange<uint32_t>(0, 9) * 10 <
           probability;
  }

  std::string ConsumeLowEntropyRandomLengthString(int len) {
    return std::string(
               data_provider_->ConsumeIntegralInRange<size_t>(0, len - 1),
               '0') +
           data_provider_->ConsumeBytesAsString(1);
  }

  std::vector<uint8_t> ConsumeLowEntropyRandomLengthBytes(int len) {
    return ConsumeLowEntropyBytes(
        data_provider_->ConsumeIntegralInRange<size_t>(1, len));
  }

  std::vector<uint8_t> ConsumeLowEntropyBytes(int len) {
    if (len == 0) {
      return std::vector<uint8_t>();
    }
    std::vector<uint8_t> bytes(len - 1, 0);
    bytes.push_back(data_provider_->ConsumeIntegral<uint8_t>());
    return bytes;
  }

  void LoadToken() {
    auto auth_data =
        brillo::SecureBlob(ConsumeLowEntropyRandomLengthString(10));
    std::string label = ConsumeLowEntropyRandomLengthString(10);
    int slot_id;
    if (slot_manager_->LoadToken(GetIsolateCredential(), tmp_dir_.GetPath(),
                                 auth_data, label, &slot_id)) {
      generated_slot_ids_.push_back(slot_id);
    }
  }

  void OpenSession() {
    uint64_t session_id;
    // Only the three lowest bits are used in flags.
    int flags = data_provider_->ConsumeIntegralInRange(0, 7);
    if (ConsumeProbability(kSuccessProbability)) {
      // For legacy reasons, the CKF_SERIAL_SESSION bit must always be set; if a
      // call to C_OpenSession does not have this bit set, the call should
      // return unsuccessfully with the error code CKR_PARALLEL_NOT_SUPPORTED.
      // Thus setting this bit with high probability.
      flags |= CKF_SERIAL_SESSION;
    }
    if (chaps_service_->OpenSession(GetIsolateCredential(), GetSlotId(), flags,
                                    &session_id) == CKR_OK) {
      generated_session_ids_.push_back(session_id);
    }
  }

  void CreateObject(std::vector<uint8_t> attributes) {
    uint64_t new_object_handle;
    if (chaps_service_->CreateObject(GetIsolateCredential(), GetSessionId(),
                                     attributes,
                                     &new_object_handle) == CKR_OK) {
      generated_object_handles_.push_back(new_object_handle);
    }
  }

  void CreateRandomObject() {
    CreateObject(data_provider_->ConsumeBytes<uint8_t>(
        data_provider_->ConsumeIntegralInRange(0, 10)));
  }

  uint64_t GetMaxOutLen() {
    // Just try a zero, a small number, and a large number.
    switch (data_provider_->ConsumeIntegralInRange<int>(0, 2)) {
      case 0:
        return 0;
      case 1:
        return kSmallLen;
      case 2:
        return kLargeLen;
      default:
        // Not reached.
        break;
    }
    return 0;
  }

  std::vector<uint8_t> GetObjectAttribute() {
    CK_OBJECT_CLASS class_value = CKO_DATA;
    CK_UTF8CHAR label[] = "A data object";
    CK_UTF8CHAR application[] = "An application";
    CK_BYTE data[] = "Sample data";
    CK_BBOOL false_value = CK_FALSE;
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &class_value, sizeof(class_value)},
        {CKA_TOKEN, &false_value, sizeof(false_value)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_APPLICATION, application, sizeof(application) - 1},
        {CKA_VALUE, data, sizeof(data)}};
    std::vector<uint8_t> attribute_serial;
    if (!SerializeAttributes(attributes, 5, &attribute_serial)) {
      LOG(FATAL) << "GetObjectAttribute failed.";
    }
    return attribute_serial;
  }

  std::vector<uint8_t> GetEncryptKeyAttribute() {
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_BYTE key_value[32] = {0};
    CK_BBOOL false_value = CK_FALSE;
    CK_BBOOL true_value = CK_TRUE;
    CK_ATTRIBUTE key_desc[] = {{CKA_CLASS, &key_class, sizeof(key_class)},
                               {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                               {CKA_TOKEN, &false_value, sizeof(false_value)},
                               {CKA_ENCRYPT, &true_value, sizeof(true_value)},
                               {CKA_DECRYPT, &true_value, sizeof(true_value)},
                               {CKA_VALUE, key_value, sizeof(key_value)}};
    std::vector<uint8_t> key;
    if (!SerializeAttributes(key_desc, 6, &key)) {
      LOG(FATAL) << "GetEncryptKeyAttribute failed.";
    }
    return key;
  }

  std::vector<uint8_t> GetDigestKeyAttribute() {
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    std::vector<uint8_t> data(100, 2);
    CK_BYTE key_value[100] = {0};
    memcpy(key_value, data.data(), 100);
    CK_BBOOL false_value = CK_FALSE;
    CK_BBOOL true_value = CK_TRUE;
    CK_ATTRIBUTE key_desc[] = {{CKA_CLASS, &key_class, sizeof(key_class)},
                               {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                               {CKA_TOKEN, &false_value, sizeof(false_value)},
                               {CKA_SIGN, &true_value, sizeof(true_value)},
                               {CKA_VERIFY, &true_value, sizeof(true_value)},
                               {CKA_VALUE, key_value, sizeof(key_value)}};
    std::vector<uint8_t> key;
    if (!SerializeAttributes(key_desc, 6, &key)) {
      LOG(FATAL) << "GetDigestKeyAttribute failed.";
    }
    return key;
  }

  std::vector<uint8_t> GetSignKeyAttribute() {
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BYTE key_value[32] = {0};
    CK_BBOOL false_value = CK_FALSE;
    CK_BBOOL true_value = CK_TRUE;
    CK_ATTRIBUTE key_desc[] = {{CKA_CLASS, &key_class, sizeof(key_class)},
                               {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                               {CKA_TOKEN, &false_value, sizeof(false_value)},
                               {CKA_SIGN, &true_value, sizeof(true_value)},
                               {CKA_VERIFY, &true_value, sizeof(true_value)},
                               {CKA_VALUE, key_value, sizeof(key_value)}};
    std::vector<uint8_t> key;
    if (!SerializeAttributes(key_desc, 6, &key)) {
      LOG(FATAL) << "GetSignKeyAttribute failed.";
    }
    return key;
  }

  brillo::SecureBlob GetIsolateCredential() {
    if (data_provider_->ConsumeBool() ||
        generated_isolate_credentials_.empty()) {
      return brillo::SecureBlob(ConsumeLowEntropyRandomLengthString(16));
    } else {
      auto idx = data_provider_->ConsumeIntegralInRange(
          0ul, generated_isolate_credentials_.size() - 1);
      return brillo::SecureBlob(generated_isolate_credentials_[idx]);
    }
  }

  int GetSlotId() {
    int slot_id;
    // Open session if not exist yet with high probability.
    if (generated_slot_ids_.empty() &&
        ConsumeProbability(kSuccessProbability)) {
      LoadToken();
    }
    if (!ConsumeProbability(kSuccessProbability) ||
        generated_slot_ids_.empty()) {
      slot_id = data_provider_->ConsumeIntegral<int>();
    } else {
      auto idx = data_provider_->ConsumeIntegralInRange(
          0ul, generated_slot_ids_.size() - 1);
      slot_id = generated_slot_ids_[idx];
    }
    return slot_id;
  }

  uint64_t GetSessionId() {
    uint64_t session_id;
    // Open session if not exist yet with high probability.
    if (generated_session_ids_.empty() &&
        ConsumeProbability(kSuccessProbability)) {
      OpenSession();
    }
    if (!ConsumeProbability(kSuccessProbability) ||
        generated_session_ids_.empty()) {
      session_id = data_provider_->ConsumeIntegral<int>();
    } else {
      auto idx = data_provider_->ConsumeIntegralInRange(
          0ul, generated_session_ids_.size() - 1);
      session_id = generated_session_ids_[idx];
    }
    return session_id;
  }

  uint64_t GetObjectHandle() {
    // Create object if not exist yet with high probability.
    if (generated_object_handles_.empty() &&
        ConsumeProbability(kSuccessProbability)) {
      CreateRandomObject();
    }
    if (!ConsumeProbability(kSuccessProbability) ||
        generated_object_handles_.empty()) {
      return data_provider_->ConsumeIntegral<uint64_t>();
    } else {
      auto idx = data_provider_->ConsumeIntegralInRange(
          0ul, generated_object_handles_.size() - 1);
      return generated_object_handles_[idx];
    }
  }

  FuzzedDataProvider* data_provider_;
  std::unique_ptr<chaps::ChapsMetrics> chaps_metrics_;
  std::unique_ptr<chaps::ChapsFactoryImpl> factory_;
  std::unique_ptr<hwsec::FuzzedFactory> hwsec_factory_;
  std::unique_ptr<const hwsec::ChapsFrontend> hwsec_;
  std::unique_ptr<chaps::SlotManagerImpl> slot_manager_;
  std::unique_ptr<chaps::ChapsServiceImpl> chaps_service_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::vector<std::string> generated_isolate_credentials_;
  std::vector<int> generated_slot_ids_;
  std::vector<uint64_t> generated_session_ids_;
  std::vector<uint64_t> generated_object_handles_;
  base::ScopedTempDir tmp_dir_;
};

}  // namespace

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOG_FATAL);
    base::CommandLine::Init(0, nullptr);
    TestTimeouts::Initialize();
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  if (size <= 1) {
    return 0;
  }
  size_t hwsec_data_size = size / 2;
  FuzzedDataProvider hwsec_data_provider(data, hwsec_data_size),
      data_provider(data + hwsec_data_size, size - hwsec_data_size);

  ChapsServiceFuzzer fuzzer(&hwsec_data_provider, &data_provider);
  fuzzer.Run();
  return 0;
}
