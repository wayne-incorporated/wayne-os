// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/logging.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/scoped_dbus_error.h>

#include <dbus/login_manager/dbus-constants.h>

#include "biod/session_state_manager.h"
#include "biod/utils.h"

namespace biod {

using dbus::ObjectPath;
using RetrievePrimarySessionResult = BiodMetrics::RetrievePrimarySessionResult;

SessionStateManager::SessionStateManager(dbus::Bus* bus,
                                         BiodMetricsInterface* biod_metrics)
    : biod_metrics_(biod_metrics) {
  session_manager_proxy_ = bus->GetObjectProxy(
      login_manager::kSessionManagerServiceName,
      dbus::ObjectPath(login_manager::kSessionManagerServicePath));

  session_manager_proxy_->ConnectToSignal(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionStateChangedSignal,
      base::BindRepeating(&SessionStateManager::OnSessionStateChanged,
                          base::Unretained(this)),
      base::BindOnce(&LogOnSignalConnected));

  // Track org.chromium.SessionManager name owner changes.
  session_manager_proxy_->SetNameOwnerChangedCallback(base::BindRepeating(
      &SessionStateManager::OnSessionManagerNameOwnerChanged,
      base::Unretained(this)));
}

std::string SessionStateManager::GetPrimaryUser() const {
  return primary_user_;
}

bool SessionStateManager::RefreshPrimaryUser() {
  std::string old_primary_user = primary_user_;
  primary_user_.clear();

  bool update_result = UpdatePrimaryUser();

  if (old_primary_user.empty() && !primary_user_.empty()) {
    for (auto& observer : observers_) {
      observer.OnUserLoggedIn(primary_user_, false);
    }
  } else if (!old_primary_user.empty() && primary_user_.empty()) {
    for (auto& observer : observers_) {
      observer.OnUserLoggedOut();
    }
  }

  return update_result;
}

std::optional<std::string> SessionStateManager::RetrievePrimaryUser() {
  dbus::ScopedDBusError error;
  std::string sanitized_username;

  dbus::MethodCall method_call(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionManagerRetrievePrimarySession);

  base::Time start_time = base::Time::Now();

  std::unique_ptr<dbus::Response> response =
      session_manager_proxy_->CallMethodAndBlockWithErrorDetails(
          &method_call, dbus_constants::kDbusTimeoutMs, &error);

  // Record RetrievePrimarySession duration.
  base::TimeDelta call_duration = base::Time::Now() - start_time;
  biod_metrics_->SendSessionRetrievePrimarySessionDuration(
      call_duration.InMilliseconds());

  if (error.is_set()) {
    std::string error_name = error.name();
    LOG(ERROR) << "Calling "
               << login_manager::kSessionManagerRetrievePrimarySession
               << " from " << login_manager::kSessionManagerInterface
               << " interface finished with " << error_name << " error.";

    if (error_name == dbus_constants::kDBusErrorNoReply) {
      biod_metrics_->SendSessionRetrievePrimarySessionResult(
          RetrievePrimarySessionResult::kErrorDBusNoReply);
      LOG(ERROR) << "Timeout while getting primary session";
    } else if (error_name == dbus_constants::kDBusErrorServiceUnknown) {
      biod_metrics_->SendSessionRetrievePrimarySessionResult(
          RetrievePrimarySessionResult::kErrorDBusServiceUnknown);
      LOG(ERROR) << "Can't find " << login_manager::kSessionManagerServiceName
                 << " service. Maybe session_manager is not running?";
    } else {
      biod_metrics_->SendSessionRetrievePrimarySessionResult(
          RetrievePrimarySessionResult::kErrorUnknown);
      LOG(ERROR) << "Error details: " << error.message();
    }
    return std::nullopt;
  }

  if (!response.get()) {
    biod_metrics_->SendSessionRetrievePrimarySessionResult(
        RetrievePrimarySessionResult::kErrorResponseMissing);
    LOG(ERROR) << "Cannot retrieve username for primary session.";
    return std::nullopt;
  }

  dbus::MessageReader response_reader(response.get());
  std::string username;
  if (!response_reader.PopString(&username)) {
    biod_metrics_->SendSessionRetrievePrimarySessionResult(
        RetrievePrimarySessionResult::kErrorParsing);
    LOG(ERROR) << "Primary session username bad format.";
    return std::nullopt;
  }
  if (!response_reader.PopString(&sanitized_username)) {
    biod_metrics_->SendSessionRetrievePrimarySessionResult(
        RetrievePrimarySessionResult::kErrorParsing);
    LOG(ERROR) << "Primary session sanitized username bad format.";
    return std::nullopt;
  }

  biod_metrics_->SendSessionRetrievePrimarySessionResult(
      RetrievePrimarySessionResult::kSuccess);
  return sanitized_username;
}

bool SessionStateManager::UpdatePrimaryUser() {
  auto primary_user = RetrievePrimaryUser();

  if (!primary_user) {
    LOG(ERROR) << "Error while retrieving primary user";
    return false;
  }

  if (primary_user->empty()) {
    LOG(INFO) << "Primary user does not exist.";
    return false;
  }

  LOG(INFO) << "Primary user updated to " << LogSafeID(*primary_user) << ".";
  primary_user_.assign(std::move(*primary_user));

  return true;
}

void SessionStateManager::OnSessionStateChanged(dbus::Signal* signal) {
  dbus::MessageReader signal_reader(signal);
  std::string state;

  CHECK(signal_reader.PopString(&state));
  LOG(INFO) << "Session state changed to " << state << ".";

  if (state == dbus_constants::kSessionStateStarted) {
    if (!primary_user_.empty()) {
      LOG(INFO) << "Primary user already exists. Not updating primary user.";
      return;
    }

    if (UpdatePrimaryUser()) {
      for (auto& observer : observers_) {
        observer.OnUserLoggedIn(primary_user_, true);
      }
    }
  } else if (state == dbus_constants::kSessionStateStopped) {
    primary_user_.clear();
    for (auto& observer : observers_) {
      observer.OnUserLoggedOut();
    }
  }
}

void SessionStateManager::OnSessionManagerNameOwnerChanged(
    const std::string& old_owner, const std::string& new_owner) {
  LOG(INFO) << login_manager::kSessionManagerServiceName << " name owner was "
            << "changed from " << (old_owner.empty() ? "(empty)" : old_owner)
            << " to " << (new_owner.empty() ? "(empty)" : new_owner);

  // Do nothing when org.chromium.SessionManager service name is acquired.
  // When session_manager has started user is always logged out.
  // When user logs in, OnSessionStateChanged() callback will be called
  // accordingly.
  if (!new_owner.empty())
    return;

  // When primary user is empty, it means that user was not logged in or
  // session_manager notified us that session state was changed to stopped
  // before dying. In either case there is nothing to do.
  if (primary_user_.empty())
    return;

  LOG(WARNING)
      << "Name " << login_manager::kSessionManagerServiceName
      << " was released while user was logged in (primary user is set)."
      << " Clear primary user and perform user logout action.";

  primary_user_.clear();
  for (auto& observer : observers_) {
    observer.OnUserLoggedOut();
  }
}

void SessionStateManager::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void SessionStateManager::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

}  // namespace biod
