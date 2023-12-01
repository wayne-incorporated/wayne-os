// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <sysexits.h>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <libhwsec-foundation/tpm/tpm_version.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>
#include <metrics/metrics_library_mock.h>

#include "tpm_manager/proto_bindings/tpm_manager.pb.h"
#include "tpm_manager/server/fuzzers/tpm_manager_service_fuzzer_data.pb.h"
#include "tpm_manager/server/local_data_store_impl.h"
#include "tpm_manager/server/mock_pinweaver_provision.h"
#include "tpm_manager/server/tpm_manager_service.h"

#include "tpm_manager/server/fuzzers/tpm_fuzzer_utils.h"
// TPM2 headers go first because the macros defined in trousers (included by
// overalls) make trunks failed to compile.
#if USE_TPM2
#include "tpm_manager/server/fuzzers/tpm2_fuzzer_utils_impl.h"
#endif
#if USE_TPM1
#include "tpm_manager/server/fuzzers/tpm_fuzzer_utils_impl.h"
#endif

namespace {

constexpr char kTpmLocalDataFile[] = "/tmp/tpm_manager/local_tpm_data";

class TpmManagerServiceFuzzer : public brillo::Daemon {
 public:
  explicit TpmManagerServiceFuzzer(
      const tpm_manager::TpmManagerServiceFuzzerData& input)
      : data_provider_(
            reinterpret_cast<const uint8_t*>(input.fuzzed_data().c_str()),
            input.fuzzed_data().size()),
        fuzzer_data_(input) {
    fuzzed_requests_iter_ = input.requests().begin();
    num_pending_requests_ = input.requests().size();
  }

  TpmManagerServiceFuzzer(const TpmManagerServiceFuzzer&) = delete;
  TpmManagerServiceFuzzer& operator=(const TpmManagerServiceFuzzer&) = delete;

  ~TpmManagerServiceFuzzer() override = default;

 protected:
  int OnInit() override {
    int exit_code = brillo::Daemon::OnInit();
    if (exit_code != EX_OK) {
      return exit_code;
    }

    Init();
    ScheduleSendFuzzedRequest();

    return EX_OK;
  }

 private:
  void Init() {
    SET_DEFAULT_TPM_FOR_TESTING;
    TPM_SELECT_BEGIN;
    TPM2_SECTION({
      fuzzer_utils_ =
          std::make_unique<tpm_manager::Tpm2FuzzerUtilsImpl>(&data_provider_);
    });
    TPM1_SECTION({
      fuzzer_utils_ =
          std::make_unique<tpm_manager::TpmFuzzerUtilsImpl>(&data_provider_);
    });
    OTHER_TPM_SECTION();
    TPM_SELECT_END;

    if (!base::DeletePathRecursively(base::FilePath(kTpmLocalDataFile))) {
      PLOG(FATAL) << "Failed to clear directory for LocalDataStore.";
    }

    tpm_manager_metrics_.set_metrics_library_for_testing(&mock_metrics_);

    auto mock_pinweaver_provision = std::make_unique<
        testing::NiceMock<tpm_manager::MockPinWeaverProvision>>();

    tpm_manager_ = std::make_unique<tpm_manager::TpmManagerService>(
        fuzzer_data_.perform_preinit(), &local_data_store_,
        std::move(mock_pinweaver_provision), nullptr, nullptr, nullptr,
        &tpm_manager_metrics_);
    fuzzer_utils_->SetupTpm(tpm_manager_.get());
    CHECK(tpm_manager_->Initialize());
  }

  void ScheduleSendFuzzedRequest() {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&TpmManagerServiceFuzzer::SendFuzzedRequest,
                                  base::Unretained(this)));
  }

  void SendFuzzedRequest() {
    if (fuzzed_requests_iter_ == fuzzer_data_.requests().end()) {
      return;
    }

    const tpm_manager::TpmManagerServiceFuzzerData::Request& request =
        *fuzzed_requests_iter_;
    if (request.has_get_tpm_status_request()) {
      tpm_manager_->GetTpmStatus(
          request.get_tpm_status_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::GetTpmStatusReply>,
                         base::Unretained(this)));
    } else if (request.has_get_tpm_nonsensitive_status_request()) {
      tpm_manager_->GetTpmNonsensitiveStatus(
          request.get_tpm_nonsensitive_status_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::GetTpmNonsensitiveStatusReply>,
                         base::Unretained(this)));
    } else if (request.has_get_version_info_request()) {
      tpm_manager_->GetVersionInfo(
          request.get_version_info_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::GetVersionInfoReply>,
                         base::Unretained(this)));
    } else if (request.has_get_supported_features_request()) {
      tpm_manager_->GetSupportedFeatures(
          request.get_supported_features_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::GetSupportedFeaturesReply>,
                         base::Unretained(this)));
    } else if (request.has_get_dictionary_attack_info_request()) {
      tpm_manager_->GetDictionaryAttackInfo(
          request.get_dictionary_attack_info_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::GetDictionaryAttackInfoReply>,
                         base::Unretained(this)));
    } else if (request.has_reset_dictionary_attack_lock_request()) {
      tpm_manager_->ResetDictionaryAttackLock(
          request.reset_dictionary_attack_lock_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::ResetDictionaryAttackLockReply>,
                         base::Unretained(this)));
    } else if (request.has_take_ownership_request()) {
      tpm_manager_->TakeOwnership(
          request.take_ownership_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::TakeOwnershipReply>,
                         base::Unretained(this)));
    } else if (request.has_remove_owner_dependency_request()) {
      tpm_manager_->RemoveOwnerDependency(
          request.remove_owner_dependency_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::RemoveOwnerDependencyReply>,
                         base::Unretained(this)));
    } else if (request.has_clear_stored_owner_password_request()) {
      tpm_manager_->ClearStoredOwnerPassword(
          request.clear_stored_owner_password_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::ClearStoredOwnerPasswordReply>,
                         base::Unretained(this)));
    } else if (request.has_define_space_request()) {
      tpm_manager_->DefineSpace(
          request.define_space_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::DefineSpaceReply>,
                         base::Unretained(this)));
    } else if (request.has_destroy_space_request()) {
      tpm_manager_->DestroySpace(
          request.destroy_space_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::DestroySpaceReply>,
                         base::Unretained(this)));
    } else if (request.has_write_space_request()) {
      tpm_manager_->WriteSpace(
          request.write_space_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::WriteSpaceReply>,
                         base::Unretained(this)));
    } else if (request.has_read_space_request()) {
      tpm_manager_->ReadSpace(
          request.read_space_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::ReadSpaceReply>,
                         base::Unretained(this)));
    } else if (request.has_lock_space_request()) {
      tpm_manager_->LockSpace(
          request.lock_space_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::LockSpaceReply>,
                         base::Unretained(this)));
    } else if (request.has_list_spaces_request()) {
      tpm_manager_->ListSpaces(
          request.list_spaces_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::ListSpacesReply>,
                         base::Unretained(this)));
    } else if (request.has_get_space_info_request()) {
      tpm_manager_->GetSpaceInfo(
          request.get_space_info_request(),
          base::BindOnce(&TpmManagerServiceFuzzer::GeneralCommandCallback<
                             tpm_manager::GetSpaceInfoReply>,
                         base::Unretained(this)));
    } else {
      Quit();
      return;
    }

    ++fuzzed_requests_iter_;
    ScheduleSendFuzzedRequest();
  }

  template <class T>
  void GeneralCommandCallback(const T&) {
    --num_pending_requests_;
    if (num_pending_requests_ == 0) {
      Quit();
    }
  }

  FuzzedDataProvider data_provider_;
  const tpm_manager::TpmManagerServiceFuzzerData& fuzzer_data_;
  google::protobuf::RepeatedPtrField<
      const tpm_manager::TpmManagerServiceFuzzerData::Request>::iterator
      fuzzed_requests_iter_;

  tpm_manager::LocalDataStoreImpl local_data_store_{kTpmLocalDataFile};
  tpm_manager::TpmManagerMetrics tpm_manager_metrics_;
  std::unique_ptr<tpm_manager::TpmFuzzerUtils> fuzzer_utils_;
  testing::NiceMock<MetricsLibraryMock> mock_metrics_;
  std::unique_ptr<tpm_manager::TpmManagerService> tpm_manager_;

  int num_pending_requests_ = 0;
};

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOG_FATAL); }
};

}  // namespace

DEFINE_PROTO_FUZZER(const tpm_manager::TpmManagerServiceFuzzerData& input) {
  static Environment env;

  // The fuzzer will never call |Quit| if there is no request.
  if (input.requests().empty())
    return;
  TpmManagerServiceFuzzer fuzzer(input);
  CHECK_EQ(fuzzer.Run(), EX_OK);
}
