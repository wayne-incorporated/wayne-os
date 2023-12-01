// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/fuzzers/tpm2_fuzzer_utils_impl.h"

#include <memory>
#include <utility>

#include <trunks/fuzzed_command_transceiver.h>
#include <trunks/trunks_factory_impl.h>

namespace tpm_manager {

namespace {
// An arbatrary choice that provides satisfatary coverage
constexpr size_t kMaxTpmMessageLength = 2048;
}  // namespace

void Tpm2FuzzerUtilsImpl::SetupTpm(TpmManagerService* tpm_manager) {
  command_transceiver_ = std::make_unique<trunks::FuzzedCommandTransceiver>(
      data_provider_, kMaxTpmMessageLength);
  auto trunks_factory =
      std::make_unique<trunks::TrunksFactoryImpl>(command_transceiver_.get());
  if (!trunks_factory->Initialize())
    LOG(ERROR) << "Failed to initialize TrunksFactory.";
  tpm_manager->SetTrunksFactoryForTesting(std::move(trunks_factory));
}

}  // namespace tpm_manager
