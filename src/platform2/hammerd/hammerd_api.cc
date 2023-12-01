// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hammerd/hammerd_api.h"

#include <memory>
#include <string>

#include <chromeos/dbus/service_constants.h>

#include "hammerd/dbus_wrapper.h"
#include "hammerd/usb_utils.h"

// Because it returns std::string, which is not compatible with C, we move
// outside the extern "C" scope.
std::string ToString(const ByteString* s) {
  return std::string(s->ptr, s->size);
}

extern "C" {

using hammerd::FirmwareUpdater;
using hammerd::SectionName;
using hammerd::UpdateExtraCommand;
using hammerd::UsbEndpoint;

BRILLO_EXPORT FirmwareUpdater* FirmwareUpdater_New(uint16_t vendor_id,
                                                   uint16_t product_id,
                                                   const char* path) {
  return new FirmwareUpdater(
      std::make_unique<UsbEndpoint>(vendor_id, product_id, std::string(path)));
}
BRILLO_EXPORT bool FirmwareUpdater_LoadEcImage(FirmwareUpdater* updater,
                                               const ByteString* ec_image) {
  return updater->LoadEcImage(ToString(ec_image));
}
BRILLO_EXPORT bool FirmwareUpdater_LoadTouchpadImage(
    FirmwareUpdater* updater, const ByteString* touchpad_image) {
  return updater->LoadTouchpadImage(ToString(touchpad_image));
}
BRILLO_EXPORT UsbConnectStatus
FirmwareUpdater_TryConnectUsb(FirmwareUpdater* updater) {
  return updater->TryConnectUsb();
}
BRILLO_EXPORT void FirmwareUpdater_CloseUsb(FirmwareUpdater* updater) {
  updater->CloseUsb();
}
BRILLO_EXPORT bool FirmwareUpdater_SendFirstPdu(FirmwareUpdater* updater) {
  return updater->SendFirstPdu();
}
BRILLO_EXPORT void FirmwareUpdater_SendDone(FirmwareUpdater* updater) {
  return updater->SendDone();
}
BRILLO_EXPORT bool FirmwareUpdater_InjectEntropy(FirmwareUpdater* updater) {
  return updater->InjectEntropy();
}
BRILLO_EXPORT bool FirmwareUpdater_InjectEntropyWithPayload(
    FirmwareUpdater* updater, const ByteString* payload) {
  return updater->InjectEntropyWithPayload(ToString(payload));
}
BRILLO_EXPORT bool FirmwareUpdater_SendSubcommand(
    FirmwareUpdater* updater, UpdateExtraCommand subcommand) {
  return updater->SendSubcommand(subcommand);
}
BRILLO_EXPORT bool FirmwareUpdater_SendSubcommandWithPayload(
    FirmwareUpdater* updater,
    UpdateExtraCommand subcommand,
    const ByteString* cmd_body) {
  return updater->SendSubcommandWithPayload(subcommand, ToString(cmd_body));
}
BRILLO_EXPORT bool FirmwareUpdater_SendSubcommandReceiveResponse(
    FirmwareUpdater* updater,
    UpdateExtraCommand subcommand,
    const ByteString* cmd_body,
    void* resp,
    size_t resp_size) {
  return updater->SendSubcommandReceiveResponse(subcommand, ToString(cmd_body),
                                                resp, resp_size);
}
BRILLO_EXPORT bool FirmwareUpdater_TransferImage(FirmwareUpdater* updater,
                                                 SectionName section_name) {
  return updater->TransferImage(section_name);
}
BRILLO_EXPORT bool FirmwareUpdater_TransferTouchpadFirmware(
    FirmwareUpdater* updater, uint32_t section_addr, size_t data_len) {
  return updater->TransferTouchpadFirmware(section_addr, data_len);
}
BRILLO_EXPORT SectionName
FirmwareUpdater_CurrentSection(FirmwareUpdater* updater) {
  return updater->CurrentSection();
}
BRILLO_EXPORT bool FirmwareUpdater_ValidKey(FirmwareUpdater* updater) {
  return updater->ValidKey();
}
BRILLO_EXPORT int FirmwareUpdater_CompareRollback(FirmwareUpdater* updater) {
  return updater->CompareRollback();
}
BRILLO_EXPORT bool FirmwareUpdater_VersionMismatch(FirmwareUpdater* updater,
                                                   SectionName section_name) {
  return updater->VersionMismatch(section_name);
}
BRILLO_EXPORT bool FirmwareUpdater_IsSectionLocked(FirmwareUpdater* updater,
                                                   SectionName section_name) {
  return updater->IsSectionLocked(section_name);
}
BRILLO_EXPORT bool FirmwareUpdater_UnlockRW(FirmwareUpdater* updater) {
  return updater->UnlockRW();
}
BRILLO_EXPORT bool FirmwareUpdater_IsRollbackLocked(FirmwareUpdater* updater) {
  return updater->IsRollbackLocked();
}
BRILLO_EXPORT bool FirmwareUpdater_UnlockRollback(FirmwareUpdater* updater) {
  return updater->UnlockRollback();
}
BRILLO_EXPORT const FirstResponsePdu* FirmwareUpdater_GetFirstResponsePdu(
    FirmwareUpdater* updater) {
  return updater->GetFirstResponsePdu();
}
BRILLO_EXPORT const char* FirmwareUpdater_GetSectionVersion(
    FirmwareUpdater* updater, SectionName section_name) {
  // To avoid the string being freed from memory after exiting the function, we
  // store as a static variable here.  However, the return string should be
  // copied before calling the function again (Python ctypes does this).
  static std::string version = updater->GetSectionVersion(section_name);
  return version.c_str();
}

BRILLO_EXPORT PairManager* PairManager_New() {
  return new PairManager();
}
BRILLO_EXPORT int PairManager_PairChallenge(PairManager* self,
                                            FirmwareUpdater* fw_updater,
                                            uint8_t* public_key) {
  hammerd::ChallengeStatus ret;
  // We do not allow to send DBus signal from Hammerd API. Inject a dummy
  // DBus wrapper here.
  hammerd::DummyDBusWrapper dummy;

  ret = self->PairChallenge(fw_updater, &dummy);
  if (ret != ChallengeStatus::kChallengePassed)
    return static_cast<int>(ret);

  if (dummy.GetLastSignalName() != hammerd::kPairChallengeSucceededSignal)
    return static_cast<int>(ChallengeStatus::kUnknownError);

  if (public_key) {
    std::string last_value = dummy.GetLastValue();
    if (last_value.size() != kX25519PublicValueLen)
      return static_cast<int>(ChallengeStatus::kUnknownError);
    memcpy(public_key, last_value.c_str(), last_value.size());
  }

  return static_cast<int>(ret);
}

}  // extern "C"
