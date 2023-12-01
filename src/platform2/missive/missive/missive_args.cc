// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/missive/missive_args.h"

#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/task/bind_post_task.h>
#include <base/time/time.h>
#include <base/time/time_delta_from_string.h>
#include <base/threading/thread.h>
#include <dbus/bus.h>
#include <featured/feature_library.h>

#include "missive/util/statusor.h"

namespace reporting {
namespace {

// Searches string map by `key`, returns matching value or empty string.
std::string FindValueOrEmpty(const std::string& key,
                             const std::map<std::string, std::string> params) {
  auto it = params.find(key);
  if (it == params.end()) {
    return "";
  }
  return it->second;
}

// Parses duration. If the parsed duration is invalid.
StatusOr<base::TimeDelta> ParseDuration(base::StringPiece duration_string) {
  const auto duration_result = base::TimeDeltaFromString(duration_string);
  if (!duration_result.has_value()) {
    return Status(error::INVALID_ARGUMENT, "Duration is not parseable.");
  }
  if (!duration_result.value().is_positive()) {
    return Status(error::INVALID_ARGUMENT, "Duration is not positive.");
  }
  return duration_result.value();
}

// Parses duration_string if valid. Otherwise, parses duration_default, which
// should always be valid.
base::TimeDelta DurationParameterValue(base::StringPiece parameter_name,
                                       base::StringPiece duration_string,
                                       base::StringPiece duration_default) {
  DCHECK(ParseDuration(duration_default).ok());

  if (duration_string.empty()) {
    return ParseDuration(duration_default).ValueOrDie();
  }
  const auto duration_result = ParseDuration(duration_string);
  if (!duration_result.ok()) {
    LOG(ERROR) << "Unable to parse parameter " << parameter_name << "="
               << duration_string << ", assumed default=" << duration_default
               << ", because: " << duration_result.status();
    return ParseDuration(duration_default).ValueOrDie();
  }
  return duration_result.ValueOrDie();
}

// Recognizes boolean setting if valid. Otherwise, substitutes default value.
bool BoolParameterValue(base::StringPiece parameter_name,
                        base::StringPiece value_string,
                        bool value_default) {
  if (value_string.empty()) {
    return value_default;
  }
  if (base::EqualsCaseInsensitiveASCII(value_string, "true")) {
    return true;
  }
  if (base::EqualsCaseInsensitiveASCII(value_string, "false")) {
    return false;
  }
  LOG(ERROR) << "Invalid parameter " << parameter_name << "=" << value_string
             << ", assumed default=" << (value_default ? "true" : "false");
  return value_default;
}

}  // namespace

MissiveArgs::MissiveArgs(feature::PlatformFeaturesInterface* feature_lib)
    : feature_lib_(feature_lib),
      features_to_load_({&kCollectorFeature, &kStorageFeature}) {
  CHECK(feature_lib_);
  feature_lib_->GetParamsAndEnabled(
      features_to_load_, base::BindPostTaskToCurrentDefault(base::BindOnce(
                             &MissiveArgs::OnParamResultInitially,
                             weak_ptr_factory_.GetWeakPtr())));
}

MissiveArgs::~MissiveArgs() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

void MissiveArgs::OnParamResultInitially(
    feature::PlatformFeaturesInterface::ParamsResult result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Enable listening for the future updates and deliver result after that.
  EnableListeningForUpdates(base::BindOnce(&MissiveArgs::OnParamResult,
                                           weak_ptr_factory_.GetWeakPtr(),
                                           std::move(result)));
}

void MissiveArgs::OnParamResult(
    feature::PlatformFeaturesInterface::ParamsResult result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Update the parameters.
  UpdateParameters(result);
  for (auto& cb : delayed_response_cbs_) {
    std::move(cb).Run();
  }
  delayed_response_cbs_.clear();

  // Also call recorded updates.
  for (auto& update_cb : update_cbs_) {
    update_cb.Run();
  }
}

void MissiveArgs::EnableListeningForUpdates(base::OnceClosure done_cb) {
  feature_lib_->ListenForRefetchNeeded(
      /*signal_callback=*/base::BindRepeating(
          [](base::WeakPtr<MissiveArgs> self) {
            if (!self) {
              return;
            }
            DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
            // Update the parameters.
            self->feature_lib_->GetParamsAndEnabled(
                self->features_to_load_,
                base::BindPostTaskToCurrentDefault(
                    base::BindOnce(&MissiveArgs::OnParamResult, self)));
          },
          weak_ptr_factory_.GetWeakPtr()),
      /*attached_callback=*/base::BindOnce(
          [](base::WeakPtr<MissiveArgs> self, base::OnceClosure done_cb,
             bool success) {
            if (!self) {
              std::move(done_cb).Run();
              return;
            }
            DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
            if (!success) {
              // Retry if failed to listen.
              self->EnableListeningForUpdates(std::move(done_cb));
              return;
            }
            // Succeeded.
            DCHECK(!self->responded_) << "Can only be called once";
            self->responded_ = true;
            std::move(done_cb).Run();
          },
          weak_ptr_factory_.GetWeakPtr(), std::move(done_cb)));
}

void MissiveArgs::UpdateParameters(
    feature::PlatformFeaturesInterface::ParamsResult result) {
  LOG(WARNING) << "Parameters updated";
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  {
    std::string enqueuing_record_tallier;
    std::string cpu_collector_interval;
    std::string storage_collector_interval;
    std::string memory_collector_interval;
    auto it = result.find(kCollectorFeature.name);
    if (it != result.end() && it->second.enabled) {
      enqueuing_record_tallier =
          FindValueOrEmpty(kEnqueuingRecordTallierParameter, it->second.params);
      cpu_collector_interval =
          FindValueOrEmpty(kCpuCollectorIntervalParameter, it->second.params);
      storage_collector_interval = FindValueOrEmpty(
          kStorageCollectorIntervalParameter, it->second.params);
      memory_collector_interval = FindValueOrEmpty(
          kMemoryCollectorIntervalParameter, it->second.params);
    }
    collection_parameters_.enqueuing_record_tallier = DurationParameterValue(
        kEnqueuingRecordTallierParameter, enqueuing_record_tallier,
        kEnqueuingRecordTallierDefault);
    collection_parameters_.cpu_collector_interval = DurationParameterValue(
        kCpuCollectorIntervalParameter, cpu_collector_interval,
        kCpuCollectorIntervalDefault);
    collection_parameters_.storage_collector_interval = DurationParameterValue(
        kStorageCollectorIntervalParameter, storage_collector_interval,
        kStorageCollectorIntervalDefault);
    collection_parameters_.memory_collector_interval = DurationParameterValue(
        kMemoryCollectorIntervalParameter, memory_collector_interval,
        kMemoryCollectorIntervalDefault);
  }
  {
    std::string compression_enabled;
    std::string encryption_enabled;
    std::string signature_verification_dev_enabled;
    std::string controlled_degradation;
    std::string legacy_storage_enabled;
    auto it = result.find(kStorageFeature.name);
    if (it != result.end() && it->second.enabled) {
      compression_enabled =
          FindValueOrEmpty(kCompressionEnabledParameter, it->second.params);
      encryption_enabled =
          FindValueOrEmpty(kEncryptionEnabledParameter, it->second.params);
      controlled_degradation =
          FindValueOrEmpty(kControlledDegradationParameter, it->second.params);
      legacy_storage_enabled =
          FindValueOrEmpty(kLegacyStorageEnabledParameter, it->second.params);
      signature_verification_dev_enabled = FindValueOrEmpty(
          kSignatureVerificationDevEnabledParameter, it->second.params);
    }
    storage_parameters_.compression_enabled =
        BoolParameterValue(kCompressionEnabledParameter, compression_enabled,
                           kCompressionEnabledDefault);
    storage_parameters_.encryption_enabled =
        BoolParameterValue(kEncryptionEnabledParameter, encryption_enabled,
                           kEncryptionEnabledDefault);
    storage_parameters_.controlled_degradation = BoolParameterValue(
        kControlledDegradationParameter, controlled_degradation,
        kControlledDegradationDefault);
    storage_parameters_.legacy_storage_enabled = BoolParameterValue(
        kLegacyStorageEnabledParameter, legacy_storage_enabled,
        kLegacyStorageEnabledDefault);
    storage_parameters_.signature_verification_dev_enabled =
        BoolParameterValue(kSignatureVerificationDevEnabledParameter,
                           signature_verification_dev_enabled,
                           kSignatureVerificationDevEnabledDefault);
  }
}

void MissiveArgs::GetCollectionParameters(
    base::OnceCallback<void(StatusOr<CollectionParameters>)> result_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!responded_) {
    // No response yet, delay.
    delayed_response_cbs_.emplace_back(
        base::BindOnce(&MissiveArgs::GetCollectionParameters,
                       weak_ptr_factory_.GetWeakPtr(), std::move(result_cb)));
    return;
  }
  std::move(result_cb).Run(collection_parameters_);  // Making a copy.
}

void MissiveArgs::GetStorageParameters(
    base::OnceCallback<void(StatusOr<StorageParameters>)> result_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!responded_) {
    // No response yet, delay.
    delayed_response_cbs_.emplace_back(
        base::BindOnce(&MissiveArgs::GetStorageParameters,
                       weak_ptr_factory_.GetWeakPtr(), std::move(result_cb)));
    return;
  }
  // Response is there, return a copy.
  std::move(result_cb).Run(storage_parameters_);  // Making a copy
}

void MissiveArgs::OnCollectionParametersUpdate(
    base::RepeatingCallback<void(CollectionParameters)> update_cb,
    base::OnceClosure done_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto cb = base::BindRepeating(
      [](base::WeakPtr<MissiveArgs> self,
         base::RepeatingCallback<void(CollectionParameters)> update_cb) {
        DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
        update_cb.Run(self->collection_parameters_);  // Making a copy.
      },
      weak_ptr_factory_.GetWeakPtr(), update_cb);
  update_cbs_.push_back(cb);
  std::move(done_cb).Run();
}

void MissiveArgs::OnStorageParametersUpdate(
    base::RepeatingCallback<void(StorageParameters)> update_cb,
    base::OnceClosure done_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto cb = base::BindRepeating(
      [](base::WeakPtr<MissiveArgs> self,
         base::RepeatingCallback<void(StorageParameters)> update_cb) {
        DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
        update_cb.Run(self->storage_parameters_);  // Making a copy.
      },
      weak_ptr_factory_.GetWeakPtr(), update_cb);
  update_cbs_.push_back(cb);
  std::move(done_cb).Run();
}
}  // namespace reporting
