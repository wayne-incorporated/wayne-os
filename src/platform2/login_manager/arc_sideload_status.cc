// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/arc_sideload_status.h"

#include <string>
#include <utility>

#include <base/bind.h>
#include <base/callback.h>
#include <base/callback_helpers.h>
#include <base/files/file_util.h>
#include <brillo/cryptohome.h>
#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

#include "bootlockbox/proto_bindings/boot_lockbox_rpc.pb.h"
#include "login_manager/dbus_util.h"
#include "login_manager/proto_bindings/arc.pb.h"

namespace login_manager {

namespace {

// Boot attribute used to track if the user has allowed sideloading on the
// device.
constexpr char kSideloadingAllowedBootAttribute[] = "arc_sideloading_allowed";

// TODO(victorhsieh): switch to base::DoNothing() once libchrome is upreved.
void DoNothing(ArcSideloadStatusInterface::Status, const char*) {}

}  // namespace

ArcSideloadStatus::ArcSideloadStatus(dbus::ObjectProxy* boot_lockbox_proxy)
    : boot_lockbox_proxy_(boot_lockbox_proxy),
      sideload_status_(ArcSideloadStatusInterface::Status::UNDEFINED),
      weak_ptr_factory_(this) {}

ArcSideloadStatus::~ArcSideloadStatus() {}

void ArcSideloadStatus::Initialize() {
  boot_lockbox_proxy_->WaitForServiceToBeAvailable(
      base::Bind(&ArcSideloadStatus::OnBootLockboxServiceAvailable,
                 weak_ptr_factory_.GetWeakPtr()));
}

bool ArcSideloadStatus::IsAdbSideloadAllowed() {
  return sideload_status_ == ArcSideloadStatusInterface::Status::ENABLED;
}

void ArcSideloadStatus::EnableAdbSideload(EnableAdbSideloadCallback callback) {
  // Must be called after initialized.
  if (sideload_status_ == ArcSideloadStatusInterface::Status::UNDEFINED) {
    std::move(callback).Run(ArcSideloadStatusInterface::Status::DISABLED,
                            "D-Bus service not connected");
    return;
  }

  // TODO(crbug.com/1026460): Move the flow into a new transition state, such
  // that an interleaved call will be queued and handled when the transition is
  // finished. Otherwise, a QueryAdbSideload call (potentially from another
  // client) can return with a outdated cached result.

  dbus::MethodCall method_call(cryptohome::kBootLockboxInterface,
                               cryptohome::kBootLockboxStoreBootLockbox);

  cryptohome::StoreBootLockboxRequest proto;
  proto.set_key(kSideloadingAllowedBootAttribute);
  proto.set_data("1");
  dbus::MessageWriter writer(&method_call);
  writer.AppendProtoAsArrayOfBytes(proto);

  boot_lockbox_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::Bind(&ArcSideloadStatus::OnEnableAdbSideloadSet,
                 weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void ArcSideloadStatus::QueryAdbSideload(QueryAdbSideloadCallback callback) {
  if (sideload_status_ != ArcSideloadStatusInterface::Status::UNDEFINED) {
    // If we know the status, just return it immediately.
    SendQueryAdbSideloadResponse(std::move(callback));
  } else {
    // We don't know the status. Enqueue the callback for later handling when
    // the status becomes known.
    query_arc_sideload_callback_queue_.emplace(std::move(callback));
  }
}

void ArcSideloadStatus::OnBootLockboxServiceAvailable(bool service_available) {
  if (!service_available) {
    LOG(ERROR) << "Failed to listen for cryptohome service start. Continue as "
               << "sideloading is disallowed.";
    SetAdbSideloadStatusAndNotify(ArcSideloadStatusInterface::Status::DISABLED);
    return;
  }

  GetAdbSideloadAllowed(base::Bind(&DoNothing));
}

void ArcSideloadStatus::GetAdbSideloadAllowed(
    EnableAdbSideloadCallback callback) {
  dbus::MethodCall method_call(cryptohome::kBootLockboxInterface,
                               cryptohome::kBootLockboxReadBootLockbox);

  cryptohome::ReadBootLockboxRequest proto;
  proto.set_key(kSideloadingAllowedBootAttribute);
  dbus::MessageWriter writer(&method_call);
  writer.AppendProtoAsArrayOfBytes(proto);

  boot_lockbox_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::Bind(&ArcSideloadStatus::OnGotAdbSideloadAllowed,
                 weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

ArcSideloadStatusInterface::Status ArcSideloadStatus::ParseResponseFromRead(
    dbus::Response* response) {
  if (!response) {
    LOG(ERROR) << cryptohome::kBootLockboxInterface << "."
               << cryptohome::kBootLockboxReadBootLockbox << " request failed.";
    return ArcSideloadStatusInterface::Status::DISABLED;
  }

  dbus::MessageReader reader(response);
  cryptohome::ReadBootLockboxReply reply;
  if (!reader.PopArrayOfBytesAsProto(&reply)) {
    LOG(ERROR) << cryptohome::kBootLockboxInterface << "."
               << cryptohome::kBootLockboxReadBootLockbox
               << " unable to pop ReadBootLockboxReply proto.";
    return ArcSideloadStatusInterface::Status::DISABLED;
  }

  if (reply.has_error()) {
    switch (reply.error()) {
      // When the attribute is unset, defaults to no sideloading.
      case cryptohome::BOOTLOCKBOX_ERROR_MISSING_KEY:
        return ArcSideloadStatusInterface::Status::DISABLED;

      // When boot lockbox is still uninitialized, which is normal after
      // powerwash.
      case cryptohome::BOOTLOCKBOX_ERROR_NVSPACE_UNINITIALIZED:
        return ArcSideloadStatusInterface::Status::DISABLED;

      // When boot lockbox is not yet defined. This can happen to device
      // launched before boot lockbox was first introduced.
      case cryptohome::BOOTLOCKBOX_ERROR_NVSPACE_UNDEFINED:
        return ArcSideloadStatusInterface::Status::NEED_POWERWASH;

      default:
        LOG(ERROR) << cryptohome::kBootLockboxInterface << "."
                   << cryptohome::kBootLockboxReadBootLockbox
                   << " returned error: " << reply.error();
        return ArcSideloadStatusInterface::Status::DISABLED;
    }
  }

  if (!reply.has_data()) {
    LOG(ERROR) << cryptohome::kBootLockboxInterface << "."
               << cryptohome::kBootLockboxReadBootLockbox
               << " missing data field in ReadBootLockboxReply.";
    return ArcSideloadStatusInterface::Status::DISABLED;
  }

  std::string arc_sideload_allowed = reply.data();
  return arc_sideload_allowed == "1"
             ? ArcSideloadStatusInterface::Status::ENABLED
             : ArcSideloadStatusInterface::Status::DISABLED;
}

void ArcSideloadStatus::OnGotAdbSideloadAllowed(
    EnableAdbSideloadCallback callback, dbus::Response* response) {
  ArcSideloadStatusInterface::Status status = ParseResponseFromRead(response);
  SetAdbSideloadStatusAndNotify(status);
  std::move(callback).Run(status, nullptr);
}

void ArcSideloadStatus::OnEnableAdbSideloadSet(
    EnableAdbSideloadCallback callback, dbus::Response* result) {
  if (!result) {
    std::move(callback).Run(ArcSideloadStatusInterface::Status::DISABLED,
                            "result is null");
    return;
  }

  dbus::MessageReader reader(result);
  cryptohome::StoreBootLockboxReply reply;
  if (!reader.PopArrayOfBytesAsProto(&reply)) {
    std::move(callback).Run(ArcSideloadStatusInterface::Status::DISABLED,
                            "response is not a StoreBootLockboxReply");
    return;
  }

  if (reply.has_error()) {
    if (reply.error() == cryptohome::BOOTLOCKBOX_ERROR_NVSPACE_UNDEFINED) {
      std::move(callback).Run(
          ArcSideloadStatusInterface::Status::NEED_POWERWASH, nullptr);
    } else {
      std::move(callback).Run(ArcSideloadStatusInterface::Status::DISABLED,
                              nullptr);
    }
    return;
  }

  // Callback later. Re-read setting from bootlockbox now that it has been
  // stored.
  GetAdbSideloadAllowed(std::move(callback));
}

void ArcSideloadStatus::OverrideAdbSideloadStatusTestOnly(bool allowed) {
  sideload_status_ = allowed ? ArcSideloadStatusInterface::Status::ENABLED
                             : ArcSideloadStatusInterface::Status::DISABLED;
}

void ArcSideloadStatus::SetAdbSideloadStatusAndNotify(
    ArcSideloadStatusInterface::Status status) {
  sideload_status_ = status;

  while (!query_arc_sideload_callback_queue_.empty()) {
    SendQueryAdbSideloadResponse(
        std::move(query_arc_sideload_callback_queue_.front()));
    query_arc_sideload_callback_queue_.pop();
  }
}

void ArcSideloadStatus::SendQueryAdbSideloadResponse(
    QueryAdbSideloadCallback callback) {
  callback.Run(sideload_status_);
}

}  // namespace login_manager
