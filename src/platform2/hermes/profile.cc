// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/profile.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>
#include <metrics/structured_events.h>

#include "hermes/executor.h"
#include "hermes/hermes_common.h"
#include "hermes/lpa_util.h"
#include "hermes/type_traits.h"

namespace hermes {

namespace {

const char kBasePath[] = "/org/chromium/Hermes/profile/";

std::optional<profile::State> LpaProfileStateToHermes(
    lpa::proto::ProfileState state) {
  switch (state) {
    case lpa::proto::DISABLED:
      return profile::kInactive;
    case lpa::proto::ENABLED:
      return profile::kActive;
    default:
      LOG(ERROR) << "Unrecognized lpa ProfileState: " << state;
      return std::nullopt;
  }
}

std::optional<profile::ProfileClass> LpaProfileClassToHermes(
    lpa::proto::ProfileClass cls) {
  switch (cls) {
    case lpa::proto::TESTING:
      return profile::kTesting;
    case lpa::proto::PROVISIONING:
      return profile::kProvisioning;
    case lpa::proto::OPERATIONAL:
      return profile::kOperational;
    default:
      LOG(ERROR) << "Unrecognized lpa ProfileClass: " << cls;
      return std::nullopt;
  }
}

}  // namespace

// static
std::unique_ptr<Profile> Profile::Create(
    const lpa::proto::ProfileInfo& profile_info,
    const uint32_t physical_slot,
    const std::string& eid,
    bool is_pending,
    base::RepeatingCallback<void(const std::string&)> on_profile_enabled_cb) {
  CHECK(profile_info.has_iccid());
  auto profile = std::unique_ptr<Profile>(new Profile(
      dbus::ObjectPath(kBasePath + eid + "/" + profile_info.iccid()),
      physical_slot));
  LOG(INFO) << __func__ << " Slot:" << physical_slot << " "
            << GetObjectPathForLog(profile->object_path_);
  // Initialize properties.
  profile->SetIccid(profile_info.iccid());
  profile->SetServiceProvider(profile_info.service_provider_name());
  if (profile_info.has_profile_owner()) {
    profile->SetMccMnc(profile_info.profile_owner().mcc() +
                       profile_info.profile_owner().mnc());
  }
  profile->SetActivationCode(profile_info.activation_code());
  std::optional<profile::State> state;
  state = is_pending ? profile::kPending
                     : LpaProfileStateToHermes(profile_info.profile_state());
  if (!state.has_value()) {
    LOG(ERROR) << "Failed to create Profile for iccid " << profile_info.iccid()
               << "; invalid ProfileState " << profile_info.profile_state();
    return nullptr;
  }
  profile->SetState(state.value());
  auto cls = LpaProfileClassToHermes(profile_info.profile_class());
  if (!cls.has_value()) {
    LOG(ERROR) << "Failed to create Profile for iccid " << profile_info.iccid()
               << "; invalid ProfileClass " << profile_info.profile_class();
    return nullptr;
  }
  profile->SetProfileClass(cls.value());
  profile->SetName(profile_info.profile_name());
  profile->SetNickname(profile_info.profile_nickname());

  profile->RegisterWithDBusObject(&profile->dbus_object_);
  profile->dbus_object_.RegisterAndBlock();

  profile->on_profile_enabled_cb_ = std::move(on_profile_enabled_cb);

  LOG(INFO) << "Successfuly created Profile";
  VLOG(2) << profile_info.DebugString();
  return profile;
}

Profile::Profile(dbus::ObjectPath object_path, const uint32_t physical_slot)
    : org::chromium::Hermes::ProfileAdaptor(this),
      context_(Context::Get()),
      object_path_(std::move(object_path)),
      dbus_object_(nullptr, context_->bus(), object_path_),
      physical_slot_(physical_slot),
      weak_factory_(this) {}

void Profile::Enable(std::unique_ptr<DBusResponse<>> response) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(object_path_);
  if (context_->dbus_ongoing_) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Profile::Enable, weak_factory_.GetWeakPtr(),
                       std::move(response)),
        kLpaRetryDelay);
    return;
  }
  if (GetState() == profile::kPending) {
    response->ReplyWithError(FROM_HERE, brillo::errors::dbus::kDomain,
                             kErrorPendingProfile,
                             "Cannot enable a pending Profile object");
    return;
  }
  context_->dbus_ongoing_ = true;
  LOG(INFO) << "Enabling profile: " << GetObjectPathForLog(object_path_);
  auto enable_profile =
      base::BindOnce(&Profile::EnableProfile, weak_factory_.GetWeakPtr());
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::START, EuiccOp::ENABLE},
      base::BindOnce(&Profile::RunOnSuccess<std::unique_ptr<DBusResponse<>>>,
                     weak_factory_.GetWeakPtr(), EuiccOp::ENABLE,
                     std::move(enable_profile), std::move(response)));
}

void Profile::EnableProfile(std::unique_ptr<DBusResponse<>> response) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(object_path_);
  context_->lpa()->EnableProfile(
      GetIccid(), context_->executor(),
      [response{std::shared_ptr<DBusResponse<>>(std::move(response))},
       weak{weak_factory_.GetWeakPtr()}](int error) mutable {
        if (!weak) {
          return;
        }
        weak->OnEnabled(error, std::move(response));
      });
}

void Profile::Disable(std::unique_ptr<DBusResponse<>> response) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(object_path_);
  if (context_->dbus_ongoing_) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Profile::Disable, weak_factory_.GetWeakPtr(),
                       std::move(response)),
        kLpaRetryDelay);
    return;
  }
  if (GetState() == profile::kPending) {
    response->ReplyWithError(FROM_HERE, brillo::errors::dbus::kDomain,
                             kErrorPendingProfile,
                             "Cannot disable a pending Profile object");
    return;
  }
  context_->dbus_ongoing_ = true;

  LOG(INFO) << "Disabling profile: " << GetObjectPathForLog(object_path_);
  auto disable_profile =
      base::BindOnce(&Profile::DisableProfile, weak_factory_.GetWeakPtr());
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::START, EuiccOp::DISABLE},
      base::BindOnce(&Profile::RunOnSuccess<std::unique_ptr<DBusResponse<>>>,
                     weak_factory_.GetWeakPtr(), EuiccOp::DISABLE,
                     std::move(disable_profile), std::move(response)));
}

void Profile::DisableProfile(std::unique_ptr<DBusResponse<>> response) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(object_path_);
  context_->lpa()->DisableProfile(
      GetIccid(), context_->executor(),
      [response{std::shared_ptr<DBusResponse<>>(std::move(response))},
       weak{weak_factory_.GetWeakPtr()}](int error) mutable {
        if (!weak) {
          return;
        }
        weak->OnDisabled(error, std::move(response));
      });
}

void Profile::OnEnabled(int error, std::shared_ptr<DBusResponse<>> response) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(object_path_);
  if (error) {
    context_->modem_control()->ProcessEuiccEvent(
        {physical_slot_, EuiccStep::END},
        base::BindOnce(&Profile::SendDBusError, weak_factory_.GetWeakPtr(),
                       EuiccOp::ENABLE, std::move(response), error));
    return;
  }
  on_profile_enabled_cb_.Run(GetIccid());
  VLOG(2) << "Enabled profile: " << object_path_.value();
  auto send_notifs =
      base::BindOnce(&Profile::FinishProfileOpCb, weak_factory_.GetWeakPtr(),
                     EuiccOp::ENABLE, std::move(response));
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::PENDING_NOTIFICATIONS},
      std::move(send_notifs));
}

void Profile::OnDisabled(int error, std::shared_ptr<DBusResponse<>> response) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(object_path_);
  if (error) {
    context_->modem_control()->ProcessEuiccEvent(
        {physical_slot_, EuiccStep::END, EuiccOp::DISABLE},
        base::BindOnce(&Profile::SendDBusError, weak_factory_.GetWeakPtr(),
                       EuiccOp::DISABLE, std::move(response), error));
    return;
  }
  VLOG(2) << "Disabled profile: " << object_path_.value();
  SetState(profile::kInactive);

  auto send_notifs =
      base::BindOnce(&Profile::FinishProfileOpCb, weak_factory_.GetWeakPtr(),
                     EuiccOp::DISABLE, std::move(response));
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::PENDING_NOTIFICATIONS, EuiccOp::DISABLE},
      std::move(send_notifs));
}

void Profile::FinishProfileOpCb(EuiccOp euicc_op,
                                std::shared_ptr<DBusResponse<>> response,
                                int err) {
  LOG(INFO) << __func__;
  if (err) {
    LOG(WARNING) << "Could not finish profile op: " << object_path_.value();
    // Notifications are optional by the standard. Since FinishProfileOp failed,
    // it means notifications cannot be sent, but our enable/disable succeeded.
    // return success on DBus anyway since only notifications cannot be sent.
    SendDBusSuccess(euicc_op, response);
    return;
  }
  context_->lpa()->SendNotifications(
      context_->executor(),
      [this, response{std::move(response)}](int /*error*/) {
        VLOG(2) << "FinishProfileOpCb: sent all notifications";
        context_->modem_control()->ProcessEuiccEvent(
            {physical_slot_, EuiccStep::END},
            base::BindOnce(
                [](Context* context, std::shared_ptr<DBusResponse<>> response,
                   int error) {
                  response->Return();
                  context->dbus_ongoing_ = false;
                  LOG(INFO)
                      << "FinishProfileOpCb: completed with err = " << error;
                },
                context_, response));
      });
}

void Profile::Rename(std::unique_ptr<DBusResponse<>> response,
                     const std::string& nickname) {
  LOG(INFO) << __func__ << " Nickname: " << nickname << " "
            << GetObjectPathForLog(object_path_);
  if (context_->dbus_ongoing_) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Profile::Rename, weak_factory_.GetWeakPtr(),
                       std::move(response), nickname),
        kLpaRetryDelay);
    return;
  }
  context_->dbus_ongoing_ = true;
  auto set_nickname =
      base::BindOnce(&Profile::SetNicknameMethod, weak_factory_.GetWeakPtr(),
                     std::move(nickname));
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::START, EuiccOp::RENAME},
      base::BindOnce(&Profile::RunOnSuccess<std::unique_ptr<DBusResponse<>>>,
                     weak_factory_.GetWeakPtr(), EuiccOp::RENAME,
                     std::move(set_nickname), std::move(response)));
}

void Profile::SetNicknameMethod(std::string nickname,
                                std::unique_ptr<DBusResponse<>> response) {
  LOG(INFO) << __func__ << " Nickname: " << nickname << " "
            << GetObjectPathForLog(object_path_);
  context_->lpa()->SetProfileNickname(
      GetIccid(), nickname, context_->executor(),
      [this, nickname,
       response{std::shared_ptr<DBusResponse<>>(std::move(response))}](
          int error) mutable {
        if (error) {
          SendDBusError(
              EuiccOp::RENAME, response, error /* lpa_error */,
              kSuccess /* modem_error */);  // kSuccess indicates that the modem
                                            // did not return an error but the
                                            // LPA did.
          return;
        }
        this->SetNickname(nickname);

        context_->modem_control()->RestoreActiveSlot(
            base::BindOnce(&Profile::OnRestoreActiveSlot,
                           weak_factory_.GetWeakPtr(), std::move(response)));
      });
}

void Profile::OnRestoreActiveSlot(std::shared_ptr<DBusResponse<>> response,
                                  int error) {
  if (error) {
    context_->modem_control()->ProcessEuiccEvent(
        {physical_slot_, EuiccStep::END},
        base::BindOnce(&Profile::SendDBusError, weak_factory_.GetWeakPtr(),
                       EuiccOp::RENAME, std::move(response), error));
    return;
  }
  auto return_dbus_success = base::BindOnce(
      &Profile::SendDBusSuccess, weak_factory_.GetWeakPtr(), EuiccOp::RENAME);
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::END},
      base::BindOnce(&Profile::RunOnSuccess<std::shared_ptr<DBusResponse<>>>,
                     weak_factory_.GetWeakPtr(), EuiccOp::RENAME,
                     std::move(return_dbus_success), std::move(response)));
}

void Profile::SendDBusError(EuiccOp euicc_op,
                            std::shared_ptr<Profile::DBusResponse<>> response,
                            int lpa_error,
                            int modem_error) {
  if (modem_error != kSuccess) {
    LOG(ERROR) << "Modem finished with error code: " << modem_error;
  }
  ::metrics::structured::events::cellular::HermesOp()
      .SetOperation(to_underlying(euicc_op))
      .SetResult(lpa_error)
      .Sethome_mccmnc(GetMCCMNCAsInt())
      .Record();
  auto decoded_error = LpaErrorToBrillo(FROM_HERE, lpa_error);
  LOG(ERROR) << euicc_op << " failed: " << decoded_error;
  response->ReplyWithError(decoded_error.get());
  context_->dbus_ongoing_ = false;
}

void Profile::SendDBusSuccess(
    EuiccOp euicc_op, std::shared_ptr<Profile::DBusResponse<>> response) {
  ::metrics::structured::events::cellular::HermesOp()
      .SetOperation(to_underlying(euicc_op))
      .Sethome_mccmnc(GetMCCMNCAsInt())
      .Record();
  response->Return();
  context_->dbus_ongoing_ = false;
}

template <typename T>
void Profile::RunOnSuccess(EuiccOp euicc_op,
                           base::OnceCallback<void(T)> cb,
                           T response,
                           int err) {
  if (err) {
    LOG(ERROR) << "Received modem error: " << err;
    ::metrics::structured::events::cellular::HermesOp()
        .SetOperation(to_underlying(euicc_op))
        .SetResult(err)
        .Sethome_mccmnc(GetMCCMNCAsInt())
        .Record();
    response->ReplyWithError(
        FROM_HERE, brillo::errors::dbus::kDomain, GetDBusError(err),
        "QMI/MBIM operation failed with code: " + std::to_string(err));
    context_->dbus_ongoing_ = false;
    return;
  }
  std::move(cb).Run(std::move(response));
}

int Profile::GetMCCMNCAsInt() {
  int res;
  std::string mccmnc = GetMccMnc();
  base::StringToInt(mccmnc, &res);
  return res;
}

Profile::~Profile() {
  dbus_object_.UnregisterAndBlock();
}

}  // namespace hermes
