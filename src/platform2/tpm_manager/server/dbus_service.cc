// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/dbus_service.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <dbus/bus.h>
#include <dbus/object_path.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>

#include "tpm_manager/server/tpm_nvram_dbus_interface.h"

namespace tpm_manager {

using brillo::dbus_utils::DBusObject;

DBusService::DBusService(
    std::unique_ptr<TpmManagerService>&& tpm_manager_service,
    LocalDataStore* local_data_store)
    : DBusService(tpm_manager_service.get(),
                  tpm_manager_service.get(),
                  local_data_store) {
  tpm_manager_service->SetOwnershipTakenCallback(base::BindRepeating(
      &DBusService::NotifyOwnershipIsTaken, base::Unretained(this)));
  tpm_manager_service_ = std::move(tpm_manager_service);
}

DBusService::DBusService(TpmNvramInterface* nvram_service,
                         TpmOwnershipInterface* ownership_service,
                         LocalDataStore* local_data_store)
    : brillo::DBusServiceDaemon(tpm_manager::kTpmManagerServiceName),
      nvram_service_(nvram_service),
      ownership_service_(ownership_service),
      local_data_store_(local_data_store) {
  CHECK(nvram_service_);
  CHECK(ownership_service_);
  CHECK(local_data_store_);
}

DBusService::DBusService(scoped_refptr<dbus::Bus> bus,
                         TpmNvramInterface* nvram_service,
                         TpmOwnershipInterface* ownership_service,
                         LocalDataStore* local_data_store)
    : brillo::DBusServiceDaemon(tpm_manager::kTpmManagerServiceName),
      dbus_object_(new DBusObject(
          nullptr, bus, dbus::ObjectPath(kTpmManagerServicePath))),
      nvram_service_(nvram_service),
      ownership_service_(ownership_service),
      local_data_store_(local_data_store) {}

void DBusService::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  if (!dbus_object_.get()) {
    // At this point bus_ should be valid.
    CHECK(bus_.get());
    dbus_object_.reset(new DBusObject(
        nullptr, bus_, dbus::ObjectPath(kTpmManagerServicePath)));
  }
  brillo::dbus_utils::DBusInterface* ownership_dbus_interface =
      dbus_object_->AddOrGetInterface(kTpmManagerInterface);

  ownership_dbus_interface->AddMethodHandler(
      kGetTpmStatus, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          GetTpmStatusRequest, GetTpmStatusReply,
          &TpmOwnershipInterface::GetTpmStatus>);

  ownership_dbus_interface->AddMethodHandler(
      kGetTpmNonsensitiveStatus, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          GetTpmNonsensitiveStatusRequest, GetTpmNonsensitiveStatusReply,
          &TpmOwnershipInterface::GetTpmNonsensitiveStatus>);

  ownership_dbus_interface->AddMethodHandler(
      kGetVersionInfo, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          GetVersionInfoRequest, GetVersionInfoReply,
          &TpmOwnershipInterface::GetVersionInfo>);

  ownership_dbus_interface->AddMethodHandler(
      kGetSupportedFeatures, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          GetSupportedFeaturesRequest, GetSupportedFeaturesReply,
          &TpmOwnershipInterface::GetSupportedFeatures>);

  ownership_dbus_interface->AddMethodHandler(
      kGetDictionaryAttackInfo, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          GetDictionaryAttackInfoRequest, GetDictionaryAttackInfoReply,
          &TpmOwnershipInterface::GetDictionaryAttackInfo>);

  ownership_dbus_interface->AddMethodHandler(
      kGetRoVerificationStatus, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          GetRoVerificationStatusRequest, GetRoVerificationStatusReply,
          &TpmOwnershipInterface::GetRoVerificationStatus>);

  ownership_dbus_interface->AddMethodHandler(
      kResetDictionaryAttackLock, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          ResetDictionaryAttackLockRequest, ResetDictionaryAttackLockReply,
          &TpmOwnershipInterface::ResetDictionaryAttackLock>);

  ownership_dbus_interface->AddMethodHandler(
      kTakeOwnership, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          TakeOwnershipRequest, TakeOwnershipReply,
          &TpmOwnershipInterface::TakeOwnership>);

  ownership_dbus_interface->AddMethodHandler(
      kRemoveOwnerDependency, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          RemoveOwnerDependencyRequest, RemoveOwnerDependencyReply,
          &TpmOwnershipInterface::RemoveOwnerDependency>);

  ownership_dbus_interface->AddMethodHandler(
      kClearStoredOwnerPassword, base::Unretained(this),
      &DBusService::HandleOwnershipDBusMethod<
          ClearStoredOwnerPasswordRequest, ClearStoredOwnerPasswordReply,
          &TpmOwnershipInterface::ClearStoredOwnerPassword>);

  ownership_taken_signal_ =
      ownership_dbus_interface->RegisterSignal<OwnershipTakenSignal>(
          kOwnershipTakenSignal);

  brillo::dbus_utils::DBusInterface* nvram_dbus_interface =
      dbus_object_->AddOrGetInterface(kTpmNvramInterface);

  nvram_dbus_interface->AddMethodHandler(
      kDefineSpace, base::Unretained(this),
      &DBusService::HandleNvramDBusMethod<DefineSpaceRequest, DefineSpaceReply,
                                          &TpmNvramInterface::DefineSpace>);

  nvram_dbus_interface->AddMethodHandler(
      kDestroySpace, base::Unretained(this),
      &DBusService::HandleNvramDBusMethod<DestroySpaceRequest,
                                          DestroySpaceReply,
                                          &TpmNvramInterface::DestroySpace>);

  nvram_dbus_interface->AddMethodHandler(
      kWriteSpace, base::Unretained(this),
      &DBusService::HandleNvramDBusMethod<WriteSpaceRequest, WriteSpaceReply,
                                          &TpmNvramInterface::WriteSpace>);

  nvram_dbus_interface->AddMethodHandler(
      kReadSpace, base::Unretained(this),
      &DBusService::HandleNvramDBusMethod<ReadSpaceRequest, ReadSpaceReply,
                                          &TpmNvramInterface::ReadSpace>);

  nvram_dbus_interface->AddMethodHandler(
      kLockSpace, base::Unretained(this),
      &DBusService::HandleNvramDBusMethod<LockSpaceRequest, LockSpaceReply,
                                          &TpmNvramInterface::LockSpace>);

  nvram_dbus_interface->AddMethodHandler(
      kListSpaces, base::Unretained(this),
      &DBusService::HandleNvramDBusMethod<ListSpacesRequest, ListSpacesReply,
                                          &TpmNvramInterface::ListSpaces>);

  nvram_dbus_interface->AddMethodHandler(
      kGetSpaceInfo, base::Unretained(this),
      &DBusService::HandleNvramDBusMethod<GetSpaceInfoRequest,
                                          GetSpaceInfoReply,
                                          &TpmNvramInterface::GetSpaceInfo>);

  dbus_object_->RegisterAsync(
      sequencer->GetHandler("Failed to register D-Bus object.", true));
}

int DBusService::OnInit() {
  int ret = brillo::DBusServiceDaemon::OnInit();
  // Initializes TpmManagerService only when we have ownership of it. This must
  // go after brillo::DBusServiceDaemon::OnInit() so the asynchronous signal
  // handling works as expected.
  if (tpm_manager_service_) {
    CHECK(tpm_manager_service_->Initialize());
  }
  return ret;
}

void DBusService::NotifyOwnershipIsTaken() {
  ownership_already_taken_ = true;

  // Send the signal if it's registered in the ownership dbus interface.
  MaybeSendOwnershipTakenSignal();
}

bool DBusService::MaybeSendOwnershipTakenSignal() {
  if (already_sent_ownership_taken_signal_) {
    return true;
  }

  if (!ownership_already_taken_) {
    return false;
  }

  // We have to check if ownership_taken_signal_ is ready here because
  // TpmInitializer may try to take TPM ownership in another thread before
  // RegisterDBusObjectsAsync is called.
  auto signal = ownership_taken_signal_.lock();
  if (!signal) {
    LOG(INFO) << "Ownership taken signal has not been initialized yet.";
    return false;
  }

  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << "Failed to read local data.";
    return false;
  }

  // Currently we just keep the entirety of local data sent with the signal, but
  // ideally the sercrets should not be exposed unless it's necessary.
  // TODO(b/168852740): Wipe out the unnecessarily visible auth values before
  // sending the signal.
  OwnershipTakenSignal payload;
  *payload.mutable_local_data() = local_data;

  // The proto message |payload| will be converted to array of bytes by Send().
  if (!signal->Send(payload)) {
    LOG(ERROR) << "Failed to send ownership taken signal!";
    return false;
  }

  already_sent_ownership_taken_signal_ = true;
  LOG(INFO) << "Ownership taken signal is sent.";
  return true;
}

template <typename RequestProtobufType,
          typename ReplyProtobufType,
          DBusService::HandlerFunction<RequestProtobufType,
                                       ReplyProtobufType,
                                       TpmNvramInterface> func>
void DBusService::HandleNvramDBusMethod(
    std::unique_ptr<DBusMethodResponse<const ReplyProtobufType&>> response,
    const RequestProtobufType& request) {
  // A callback that sends off the reply protobuf.
  auto callback =
      [](std::unique_ptr<DBusMethodResponse<const ReplyProtobufType&>> response,
         const ReplyProtobufType& reply) { response->Return(reply); };
  (nvram_service_->*func)(request,
                          base::BindOnce(callback, std::move(response)));
}

template <typename RequestProtobufType,
          typename ReplyProtobufType,
          DBusService::HandlerFunction<RequestProtobufType,
                                       ReplyProtobufType,
                                       TpmOwnershipInterface> func>
void DBusService::HandleOwnershipDBusMethod(
    std::unique_ptr<DBusMethodResponse<const ReplyProtobufType&>> response,
    const RequestProtobufType& request) {
  // A callback that sends off the reply protobuf.
  auto callback =
      [](std::unique_ptr<DBusMethodResponse<const ReplyProtobufType&>> response,
         const ReplyProtobufType& reply) { response->Return(reply); };
  (ownership_service_->*func)(request,
                              base::BindOnce(callback, std::move(response)));
}

}  // namespace tpm_manager
