// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/check.h>

#include <libcrossystem/crossystem.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#if USE_TPM2
#include <trunks/command_transceiver.h>
#include <trunks/trunks_factory.h>
#endif

#if USE_TPM1
#include "libhwsec/overalls/overalls.h"
#endif

#include "libhwsec/proxy/proxy.h"
#include "libhwsec/platform/platform.h"

namespace hwsec {

void Proxy::SetOveralls(hwsec::overalls::Overalls* overalls) {
  overalls_ptr_ = overalls;
}

void Proxy::SetTrunksCommandTransceiver(
    trunks::CommandTransceiver* trunks_command_transceiver) {
  trunks_command_transceiver_ = trunks_command_transceiver;
}

void Proxy::SetTrunksFactory(trunks::TrunksFactory* trunks_factory) {
  trunks_factory_ptr_ = trunks_factory;
}

void Proxy::SetTpmManager(
    org::chromium::TpmManagerProxyInterface* tpm_manager) {
  tpm_manager_ = tpm_manager;
}

void Proxy::SetTpmNvram(org::chromium::TpmNvramProxyInterface* tpm_nvram) {
  tpm_nvram_ = tpm_nvram;
}

void Proxy::SetCrossystem(crossystem::Crossystem* crossystem) {
  crossystem_ = crossystem;
}

void Proxy::SetPlatform(Platform* platform) {
  platform_ = platform;
}

// A tricks to make the linkage failure if accessing wrong proxy on the
// wrong board.
#if USE_TPM1
hwsec::overalls::Overalls& Proxy::GetOveralls() const {
  CHECK(overalls_ptr_);
  return *overalls_ptr_;
}
#endif

// A tricks to make the linkage failure if accessing wrong proxy on the
// wrong board.
#if USE_TPM2
trunks::CommandTransceiver& Proxy::GetTrunksCommandTransceiver() const {
  CHECK(trunks_command_transceiver_);
  return *trunks_command_transceiver_;
}
trunks::TrunksFactory& Proxy::GetTrunksFactory() const {
  CHECK(trunks_factory_ptr_);
  return *trunks_factory_ptr_;
}
#endif

org::chromium::TpmManagerProxyInterface& Proxy::GetTpmManager() const {
  CHECK(tpm_manager_);
  return *tpm_manager_;
}

org::chromium::TpmNvramProxyInterface& Proxy::GetTpmNvram() const {
  CHECK(tpm_nvram_);
  return *tpm_nvram_;
}

crossystem::Crossystem& Proxy::GetCrossystem() const {
  CHECK(crossystem_);
  return *crossystem_;
}

Platform& Proxy::GetPlatform() const {
  CHECK(platform_);
  return *platform_;
}

}  // namespace hwsec
