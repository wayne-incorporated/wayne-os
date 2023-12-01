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
#include <libhwsec/factory/fuzzed_factory.h>

#include "chaps/chaps_interface.h"
#include "chaps/fuzzers/fuzzed_chaps_factory.h"
#include "chaps/fuzzers/fuzzed_object_pool.h"
#include "chaps/session.h"
#include "chaps/slot_manager_impl.h"
#include "chaps/token_manager_interface.h"

namespace {
enum class SlotManagerRequest {
  kInit,
  kGetSlotCount,
  kIsTokenAccessible,
  kIsTokenPresent,
  kGetSlotInfo,
  kGetTokenInfo,
  kGetMechanismInfo,
  kOpenSession,
  kCloseSession,
  kCloseAllSessions,
  kGetSession,
  kMaxValue = kGetSession,
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
// Provide max iterations for a single fuzz run, otherwise it might timeout.
constexpr int kMaxIterations = 100;

class SlotManagerFuzzer {
 public:
  explicit SlotManagerFuzzer(FuzzedDataProvider* hwsec_data_provider,
                             FuzzedDataProvider* data_provider)
      : data_provider_(data_provider) {
    chaps_metrics_ = std::make_unique<chaps::ChapsMetrics>();
    factory_ = std::make_unique<chaps::FuzzedChapsFactory>(data_provider_);
    hwsec_factory_ =
        std::make_unique<hwsec::FuzzedFactory>(*hwsec_data_provider);
    hwsec_ = hwsec_factory_->GetChapsFrontend();
    bool auto_load_system_token = data_provider_->ConsumeBool();
    slot_manager_ = std::make_unique<chaps::SlotManagerImpl>(
        factory_.get(), hwsec_.get(), auto_load_system_token, nullptr,
        chaps_metrics_.get());
  }

  ~SlotManagerFuzzer() {
    slot_manager_.reset();
    hwsec_.reset();
    hwsec_factory_.reset();
    factory_.reset();
    chaps_metrics_.reset();
  }

  void Run() {
    CHECK(tmp_dir_.CreateUniqueTempDir());
    int rounds = 0;
    while (data_provider_->remaining_bytes() > 0 && rounds < kMaxIterations) {
      if (data_provider_->ConsumeBool()) {
        FuzzSlotManagerRequest();
      } else {
        FuzzTokenManagerInterfaceRequest();
      }
      task_environment_.RunUntilIdle();
      rounds++;
    }
  }

 private:
  bool IsTokenPresent(const brillo::SecureBlob& isolate_credential,
                      int slot_id) {
    return slot_id < slot_manager_->GetSlotCount() &&
           slot_manager_->IsTokenAccessible(isolate_credential, slot_id) &&
           slot_manager_->IsTokenPresent(isolate_credential, slot_id);
  }

  void FuzzSlotManagerRequest() {
    auto request = data_provider_->ConsumeEnum<SlotManagerRequest>();
    brillo::SecureBlob isolate_credential;
    int slot_id;

    LOG(INFO) << "slot manager request: " << static_cast<int>(request);
    if (!ConsumeProbability(kSuccessProbability) ||
        generated_isolate_credentials_.empty()) {
      isolate_credential =
          brillo::SecureBlob(ConsumeLowEntropyRandomLengthString(16));
    } else {
      auto idx = data_provider_->ConsumeIntegralInRange(
          0ul, generated_isolate_credentials_.size() - 1);
      isolate_credential =
          brillo::SecureBlob(generated_isolate_credentials_[idx]);
    }
    if (!ConsumeProbability(kSuccessProbability) ||
        generated_slot_ids_.empty()) {
      slot_id = data_provider_->ConsumeIntegral<int>();
    } else {
      auto idx = data_provider_->ConsumeIntegralInRange(
          0ul, generated_slot_ids_.size() - 1);
      slot_id = generated_slot_ids_[idx];
    }

    switch (request) {
      case SlotManagerRequest::kInit: {
        slot_manager_->Init();
        break;
      }
      case SlotManagerRequest::kGetSlotCount: {
        slot_manager_->GetSlotCount();
        break;
      }
      case SlotManagerRequest::kIsTokenAccessible: {
        slot_id < slot_manager_->GetSlotCount() &&
            slot_manager_->IsTokenAccessible(isolate_credential, slot_id);
        break;
      }
      case SlotManagerRequest::kIsTokenPresent: {
        IsTokenPresent(isolate_credential, slot_id);
        break;
      }
      case SlotManagerRequest::kGetSlotInfo: {
        CK_SLOT_INFO slot_info;
        if (IsTokenPresent(isolate_credential, slot_id))
          slot_manager_->GetSlotInfo(isolate_credential, slot_id, &slot_info);
        break;
      }
      case SlotManagerRequest::kGetTokenInfo: {
        CK_TOKEN_INFO token_info;
        if (IsTokenPresent(isolate_credential, slot_id))
          slot_manager_->GetTokenInfo(isolate_credential, slot_id, &token_info);
        break;
      }
      case SlotManagerRequest::kGetMechanismInfo: {
        if (IsTokenPresent(isolate_credential, slot_id))
          slot_manager_->GetMechanismInfo(isolate_credential, slot_id);
        break;
      }
      case SlotManagerRequest::kOpenSession: {
        if (IsTokenPresent(isolate_credential, slot_id))
          slot_manager_->OpenSession(isolate_credential, slot_id,
                                     data_provider_->ConsumeBool());
        break;
      }
      case SlotManagerRequest::kCloseSession: {
        slot_manager_->CloseSession(isolate_credential, slot_id);
        break;
      }
      case SlotManagerRequest::kCloseAllSessions: {
        if (slot_id < slot_manager_->GetSlotCount() &&
            slot_manager_->IsTokenAccessible(isolate_credential, slot_id)) {
          slot_manager_->CloseAllSessions(isolate_credential, slot_id);
        }
        break;
      }
      case SlotManagerRequest::kGetSession: {
        chaps::Session* session = nullptr;
        slot_manager_->GetSession(isolate_credential, slot_id, &session);
        break;
      }
    }
  }

  void FuzzTokenManagerInterfaceRequest() {
    auto request = data_provider_->ConsumeEnum<TokenManagerInterfaceRequest>();
    brillo::SecureBlob isolate_credential;

    LOG(INFO) << "token manager request: " << static_cast<int>(request);
    if (data_provider_->ConsumeBool() ||
        generated_isolate_credentials_.empty()) {
      isolate_credential =
          brillo::SecureBlob(ConsumeLowEntropyRandomLengthString(16));
    } else {
      auto idx = data_provider_->ConsumeIntegralInRange(
          0ul, generated_isolate_credentials_.size() - 1);
      isolate_credential =
          brillo::SecureBlob(generated_isolate_credentials_[idx]);
    }

    switch (request) {
      case TokenManagerInterfaceRequest::kOpenIsolate: {
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
        slot_manager_->CloseIsolate(isolate_credential);
        break;
      }
      case TokenManagerInterfaceRequest::kLoadToken: {
        auto path = tmp_dir_.GetPath();
        auto auth_data =
            brillo::SecureBlob(ConsumeLowEntropyRandomLengthString(10));
        std::string label = ConsumeLowEntropyRandomLengthString(10);
        int slot_id;
        if (slot_manager_->LoadToken(isolate_credential, path, auth_data, label,
                                     &slot_id)) {
          generated_slot_ids_.push_back(slot_id);
        }

        break;
      }
      case TokenManagerInterfaceRequest::kUnloadToken: {
        auto path = tmp_dir_.GetPath();
        slot_manager_->UnloadToken(isolate_credential, path);
        break;
      }
      case TokenManagerInterfaceRequest::kGetTokenPath: {
        base::FilePath path;
        int slot_id = data_provider_->ConsumeIntegral<int>();
        slot_manager_->GetTokenPath(isolate_credential, slot_id, &path);
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

  FuzzedDataProvider* data_provider_;
  std::unique_ptr<chaps::SlotManagerImpl> slot_manager_;
  std::unique_ptr<chaps::ChapsMetrics> chaps_metrics_;
  std::unique_ptr<chaps::FuzzedChapsFactory> factory_;
  std::unique_ptr<hwsec::FuzzedFactory> hwsec_factory_;
  std::unique_ptr<const hwsec::ChapsFrontend> hwsec_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::vector<std::string> generated_isolate_credentials_;
  std::vector<int> generated_slot_ids_;
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

  SlotManagerFuzzer fuzzer(&hwsec_data_provider, &data_provider);
  fuzzer.Run();
  return 0;
}
