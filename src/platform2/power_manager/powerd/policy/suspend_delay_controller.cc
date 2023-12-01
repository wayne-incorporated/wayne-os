// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/suspend_delay_controller.h"

#include <algorithm>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>

#include "power_manager/common/tracing.h"
#include "power_manager/powerd/policy/suspend_delay_observer.h"
#include "power_manager/proto_bindings/suspend.pb.h"

namespace power_manager::policy {

// static.
constexpr base::TimeDelta
    SuspendDelayController::kDefaultMaxSuspendDelayTimeout;

SuspendDelayController::SuspendDelayController(
    int initial_delay_id,
    const std::string& description,
    base::TimeDelta max_delay_timeout)
    : description_(description),
      next_delay_id_(initial_delay_id),
      max_delay_timeout_(max_delay_timeout) {
  DCHECK_LT(dark_resume_min_delay_, max_delay_timeout_);
}

bool SuspendDelayController::ReadyForSuspend() const {
  return delay_ids_being_waited_on_.empty() &&
         !min_delay_expiration_timer_.IsRunning();
}

void SuspendDelayController::AddObserver(SuspendDelayObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void SuspendDelayController::RemoveObserver(SuspendDelayObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void SuspendDelayController::RegisterSuspendDelay(
    const RegisterSuspendDelayRequest& request,
    const std::string& dbus_client,
    RegisterSuspendDelayReply* reply) {
  DCHECK(reply);

  int delay_id = next_delay_id_++;

  DelayInfo info;
  // Timeout is sent as microseconds from clients.
  base::TimeDelta timeout = base::Microseconds(request.timeout());
  if ((timeout < base::TimeDelta()) || (timeout > max_delay_timeout_)) {
    info.timeout = max_delay_timeout_;
  } else {
    info.timeout = timeout;
  }
  info.dbus_client = dbus_client;
  info.description = request.description();

  LOG(INFO) << "Registering " << GetLogDescription() << " delay " << delay_id
            << " (" << info.description << ")"
            << " of " << info.timeout.InMilliseconds() << " ms on behalf of "
            << dbus_client;
  registered_delays_.insert(std::make_pair(delay_id, info));

  reply->Clear();
  reply->set_min_delay_timeout_ms(std::min(
      info.timeout.InMilliseconds(), max_delay_timeout_.InMilliseconds()));
  reply->set_delay_id(delay_id);
}

void SuspendDelayController::UnregisterSuspendDelay(
    const UnregisterSuspendDelayRequest& request,
    const std::string& dbus_client) {
  LOG(INFO) << "Unregistering " << GetLogDescription() << " delay "
            << request.delay_id() << " ("
            << GetDelayDescription(request.delay_id()) << ")"
            << " on behalf of " << dbus_client;
  UnregisterDelayInternal(request.delay_id());
}

void SuspendDelayController::HandleSuspendReadiness(
    const SuspendReadinessInfo& info, const std::string& dbus_client) {
  int delay_id = info.delay_id();
  int suspend_id = info.suspend_id();
  LOG(INFO) << "Got notification that delay " << delay_id << " ("
            << GetDelayDescription(delay_id) << ") is ready for "
            << GetLogDescription() << " request " << suspend_id << " from "
            << dbus_client;

  if (suspend_id != current_suspend_id_) {
    // This can legitimately happen if we cancel a suspend request, quickly
    // start a new request, and then receive a notification about the previous
    // request from a client.
    VLOG(1) << "Ignoring readiness notification for wrong "
            << GetLogDescription() << " request (got " << suspend_id
            << ", currently on " << current_suspend_id_ << ")";
    return;
  }

  if (!delay_ids_being_waited_on_.count(delay_id)) {
    LOG(WARNING) << "Ignoring readiness notification for "
                 << GetLogDescription() << " delay " << delay_id
                 << ", which we weren't waiting for";
    return;
  }
  RemoveDelayFromWaitList(delay_id);
}

void SuspendDelayController::HandleDBusClientDisconnected(
    const std::string& client) {
  std::vector<int> delay_ids_to_remove;
  for (DelayInfoMap::const_iterator it = registered_delays_.begin();
       it != registered_delays_.end(); ++it) {
    if (it->second.dbus_client == client)
      delay_ids_to_remove.push_back(it->first);
  }

  for (std::vector<int>::const_iterator it = delay_ids_to_remove.begin();
       it != delay_ids_to_remove.end(); ++it) {
    LOG(INFO) << "Unregistering " << GetLogDescription() << " delay " << *it
              << " (" << GetDelayDescription(*it) << ") due to D-Bus client "
              << client << " going away";
    UnregisterDelayInternal(*it);
  }
}

void SuspendDelayController::PrepareForSuspend(int suspend_id,
                                               bool in_dark_resume) {
  current_suspend_id_ = suspend_id;

  size_t old_count = delay_ids_being_waited_on_.size();
  delay_ids_being_waited_on_.clear();
  for (DelayInfoMap::const_iterator it = registered_delays_.begin();
       it != registered_delays_.end(); ++it)
    delay_ids_being_waited_on_.insert(it->first);

  LOG(INFO) << "Announcing " << GetLogDescription() << " request "
            << current_suspend_id_ << " with "
            << delay_ids_being_waited_on_.size() << " pending delay(s) and "
            << old_count << " outstanding delay(s) from previous request";

  const bool waiting = !delay_ids_being_waited_on_.empty();

  if (in_dark_resume) {
    min_delay_expiration_timer_.Start(
        FROM_HERE, dark_resume_min_delay_, this,
        &SuspendDelayController::OnMinDelayExpiration);
  } else if (!waiting) {
    PostNotifyObserversTask(current_suspend_id_);
  }

  if (waiting) {
    base::TimeDelta max_timeout;
    for (DelayInfoMap::const_iterator it = registered_delays_.begin();
         it != registered_delays_.end(); ++it) {
      max_timeout = std::max(max_timeout, it->second.timeout);
    }
    max_timeout = std::min(max_timeout, max_delay_timeout_);
    max_delay_expiration_timer_.Start(
        FROM_HERE, max_timeout, this,
        &SuspendDelayController::OnMaxDelayExpiration);
  }
}

void SuspendDelayController::FinishSuspend(int suspend_id) {
  if (suspend_id != current_suspend_id_)
    return;

  max_delay_expiration_timer_.Stop();
  min_delay_expiration_timer_.Stop();
  delay_ids_being_waited_on_.clear();
}

std::string SuspendDelayController::GetLogDescription() const {
  return (!description_.empty() ? description_ + " " : std::string()) +
         "suspend";
}

std::string SuspendDelayController::GetDelayDescription(int delay_id) const {
  DelayInfoMap::const_iterator it = registered_delays_.find(delay_id);
  return it != registered_delays_.end() ? it->second.description : "unknown";
}

void SuspendDelayController::UnregisterDelayInternal(int delay_id) {
  if (!registered_delays_.count(delay_id)) {
    LOG(WARNING) << "Ignoring request to remove unknown " << GetLogDescription()
                 << " delay " << delay_id;
    return;
  }
  RemoveDelayFromWaitList(delay_id);
  registered_delays_.erase(delay_id);
}

void SuspendDelayController::RemoveDelayFromWaitList(int delay_id) {
  if (!delay_ids_being_waited_on_.count(delay_id))
    return;

  delay_ids_being_waited_on_.erase(delay_id);
  if (delay_ids_being_waited_on_.empty() &&
      !min_delay_expiration_timer_.IsRunning()) {
    max_delay_expiration_timer_.Stop();
    PostNotifyObserversTask(current_suspend_id_);
  }
}

void SuspendDelayController::OnMaxDelayExpiration() {
  TRACE_EVENT("power", "SuspendDelayController::OnMaxDelayExpiration");
  std::string tardy_delays;
  for (int delay_id : delay_ids_being_waited_on_) {
    const DelayInfo& delay = registered_delays_[delay_id];
    if (!tardy_delays.empty())
      tardy_delays += ", ";
    tardy_delays += base::NumberToString(delay_id) + " (" + delay.dbus_client +
                    ": " + delay.description + ")";
  }
  LOG(WARNING) << "Timed out while waiting for " << GetLogDescription()
               << " request " << current_suspend_id_
               << " readiness confirmation for "
               << delay_ids_being_waited_on_.size()
               << " delay(s): " << tardy_delays;

  delay_ids_being_waited_on_.clear();
  PostNotifyObserversTask(current_suspend_id_);
}

void SuspendDelayController::OnMinDelayExpiration() {
  TRACE_EVENT("power", "SuspendDelayController::OnMinDelayExpiration");
  if (delay_ids_being_waited_on_.empty()) {
    max_delay_expiration_timer_.Stop();
    PostNotifyObserversTask(current_suspend_id_);
  }
}

void SuspendDelayController::PostNotifyObserversTask(int suspend_id) {
  notify_observers_timer_.Start(
      FROM_HERE, base::TimeDelta(),
      base::BindOnce(&SuspendDelayController::NotifyObservers,
                     base::Unretained(this), suspend_id));
}

void SuspendDelayController::NotifyObservers(int suspend_id) {
  TRACE_EVENT("power", "SuspendDelayController::NotifyObservers", "suspend_id",
              suspend_id, "description", GetLogDescription());
  LOG(INFO) << "Notifying observers that " << GetLogDescription()
            << " is ready";
  for (SuspendDelayObserver& observer : observers_)
    observer.OnReadyForSuspend(this, suspend_id);
}

}  // namespace power_manager::policy
