// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/arc_timer_manager.h"

#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <memory>
#include <set>
#include <utility>

#include <base/check.h>
#include <base/files/file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/unix_domain_socket.h>
#include <brillo/daemons/daemon.h>
#include <brillo/timers/alarm_timer.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

#include "power_manager/common/clock.h"
#include "power_manager/common/tracing.h"
#include "power_manager/powerd/system/wakeup_timer.h"

namespace power_manager::system {

namespace {

// Creates a new "invalid args" reply to |method_call|.
std::unique_ptr<dbus::Response> CreateInvalidArgsError(
    dbus::MethodCall* method_call, const std::string& message) {
  return std::unique_ptr<dbus::Response>(dbus::ErrorResponse::FromMethodCall(
      method_call, DBUS_ERROR_INVALID_ARGS, message));
}

// Expiration callback for timer of type |timer_id|. |expiration_fd| is the fd
// to write to to indicate timer expiration to the instance.
void OnExpiration(ArcTimerManager::TimerId timer_id, int expiration_fd) {
  TRACE_EVENT("power", "ArcTimerManager::OnExpiration", "timer_id", timer_id,
              "expiration_fd", expiration_fd);
  DVLOG(1) << "Expiration callback for timer id=" << timer_id;
  // Write to the |expiration_fd| to indicate to the instance that the timer has
  // expired. The instance expects 8 bytes on the read end similar to what
  // happens on a timerfd expiration. The timerfd API expects this to be the
  // number of expirations, however, more than one expiration isn't tracked
  // currently. This can block in the unlikely scenario of multiple writes
  // happening but the instance not reading the data. When the send queue is
  // full (64Kb), a write attempt here will block.
  const uint64_t timer_data = 1;
  if (!base::UnixDomainSocket::SendMsg(
          expiration_fd, &timer_data, sizeof(timer_data), std::vector<int>())) {
    PLOG(ERROR) << "Failed to indicate timer expiration to the instance";
  }
}

// Writes |timer_ids| as an array of int32s to |writer|.
void WriteTimerIdsToDBusResponse(
    const std::vector<ArcTimerManager::TimerId>& timer_ids,
    dbus::MessageWriter* writer) {
  dbus::MessageWriter array_writer(nullptr);
  writer->OpenArray("i", &array_writer);
  for (auto id : timer_ids)
    array_writer.AppendInt32(id);
  writer->CloseContainer(&array_writer);
}

}  // namespace

ArcTimerManager::ArcTimerManager()
    : clock_(std::make_unique<Clock>()), weak_ptr_factory_(this) {}

ArcTimerManager::~ArcTimerManager() = default;

struct ArcTimerManager::ArcTimerInfo {
  ArcTimerInfo() = delete;
  ArcTimerInfo(ArcTimerInfo&&) = delete;
  ArcTimerInfo(clockid_t clock_id,
               base::ScopedFD expiration_fd,
               std::unique_ptr<WakeupTimer> timer)
      : clock_id(clock_id),
        expiration_fd(std::move(expiration_fd)),
        timer(std::move(timer)) {}
  ArcTimerInfo(const ArcTimerInfo&) = delete;
  ArcTimerInfo& operator=(const ArcTimerInfo&) = delete;

  // Clock id associated with this timer.
  const clockid_t clock_id;

  // The file descriptor which will be written to when |timer| expires.
  const base::ScopedFD expiration_fd;

  // The timer that will be scheduled.
  const std::unique_ptr<WakeupTimer> timer;
};

void ArcTimerManager::Init(DBusWrapperInterface* dbus_wrapper) {
  DCHECK(dbus_wrapper);
  dbus_wrapper->ExportMethod(
      kCreateArcTimersMethod,
      base::BindRepeating(&ArcTimerManager::HandleCreateArcTimers,
                          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper->ExportMethod(
      kStartArcTimerMethod,
      base::BindRepeating(&ArcTimerManager::HandleStartArcTimer,
                          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper->ExportMethod(
      kDeleteArcTimersMethod,
      base::BindRepeating(&ArcTimerManager::HandleDeleteArcTimers,
                          weak_ptr_factory_.GetWeakPtr()));
}

std::vector<ArcTimerManager::TimerId> ArcTimerManager::GetTimerIdsForTesting(
    const std::string& tag) {
  auto it = client_timer_ids_.find(tag);
  if (it == client_timer_ids_.end())
    return std::vector<TimerId>();

  return it->second;
}

void ArcTimerManager::HandleCreateArcTimers(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  DVLOG(1) << "CreateArcTimers";
  dbus::MessageReader reader(method_call);

  std::string tag;
  if (!reader.PopString(&tag)) {
    LOG(WARNING) << "Failed to pop tag string arg from "
                 << kCreateArcTimersMethod << " D-Bus method call";
    std::move(response_sender)
        .Run(CreateInvalidArgsError(method_call, "Expected tag string"));
    return;
  }
  DVLOG(1) << "Creating timers for tag=" << tag;

  dbus::MessageReader array_reader(nullptr);
  if (!reader.PopArray(&array_reader)) {
    LOG(WARNING) << "Failed to pop {clock id, expiration fd} array from "
                 << kCreateArcTimersMethod << " D-Bus method call";
    std::move(response_sender)
        .Run(CreateInvalidArgsError(
            method_call, "Expected array of clock id and descriptors"));
    return;
  }

  DeleteArcTimers(tag);

  // Iterate over the array of |clock_id, expiration_fd| and create an
  // |ArcTimerInfo| entry for each clock.
  std::vector<std::unique_ptr<ArcTimerInfo>> arc_timers =
      CreateArcTimers(&array_reader, is_testing_);
  if (arc_timers.size() == 0) {
    std::move(response_sender)
        .Run(CreateInvalidArgsError(method_call, "Failed to create timers"));
    return;
  }

  if (ContainsDuplicateClocks(arc_timers)) {
    std::move(response_sender)
        .Run(CreateInvalidArgsError(method_call,
                                    "Duplicate clocks not supported"));
    return;
  }

  // For each timer:
  // - Map an entry from a timer id to the timer.
  // - Push the timer id to the list of ids associated with the client's tag.
  // Newly generated ids guarantee that there are no key collisions in the first
  // operation. Earlier checks guarantee that there are no key collisions in the
  // second operation.
  for (auto& timer : arc_timers) {
    DVLOG(1) << "Adding tag=" << tag << " timer id=" << next_timer_id_;
    CHECK(timers_.emplace(next_timer_id_, std::move(timer)).second);
    client_timer_ids_[tag].push_back(next_timer_id_);
    next_timer_id_++;
  }

  std::unique_ptr<dbus::Response> response(
      dbus::Response::FromMethodCall(method_call));
  dbus::MessageWriter writer(response.get());
  WriteTimerIdsToDBusResponse(client_timer_ids_[tag], &writer);
  std::move(response_sender).Run(std::move(response));
}

// static:
std::vector<std::unique_ptr<ArcTimerManager::ArcTimerInfo>>
ArcTimerManager::CreateArcTimers(dbus::MessageReader* array_reader,
                                 bool create_for_testing) {
  std::vector<std::unique_ptr<ArcTimerInfo>> result;
  while (array_reader->HasMoreData()) {
    std::unique_ptr<ArcTimerInfo> arc_timer =
        CreateArcTimer(array_reader, create_for_testing);
    if (!arc_timer) {
      result.clear();
      return result;
    }
    result.push_back(std::move(arc_timer));
  }
  return result;
}

// static:
std::unique_ptr<ArcTimerManager::ArcTimerInfo> ArcTimerManager::CreateArcTimer(
    dbus::MessageReader* array_reader, bool create_for_testing) {
  dbus::MessageReader struct_reader(nullptr);
  if (!array_reader->PopStruct(&struct_reader)) {
    LOG(WARNING) << "Failed to pop struct";
    return nullptr;
  }

  clockid_t clock_id;
  if (!struct_reader.PopInt32(&clock_id)) {
    LOG(WARNING) << "Failed to pop clock id";
    return nullptr;
  }

  // Make sure we're only using a clock of a type we can support with wakeup
  // alarms - either CLOCK_BOOTTIME_ALARM or CLOCK_REALTIME_ALARM.
  //
  // At present the instance uses only CLOCK_BOOTTIME_ALARM to set
  // wake up alarms.
  if (!brillo::timers::SimpleAlarmTimer::IsSupportedClock(clock_id)) {
    LOG(WARNING) << "Unsupported clock=" << clock_id;
    return nullptr;
  }

  base::ScopedFD expiration_fd;
  if (!struct_reader.PopFileDescriptor(&expiration_fd)) {
    LOG(WARNING) << "Failed to pop file descriptor for clock=" << clock_id;
    return nullptr;
  }
  if (!expiration_fd.is_valid()) {
    LOG(WARNING) << "Bad file descriptor for clock=" << clock_id;
    return nullptr;
  }

  if (create_for_testing) {
    return std::make_unique<ArcTimerInfo>(clock_id, std::move(expiration_fd),
                                          std::make_unique<TestWakeupTimer>());
  }

  std::unique_ptr<WakeupTimer> simple_alarm_timer =
      RealWakeupTimer::Create(clock_id);
  if (simple_alarm_timer == nullptr) {
    LOG(WARNING) << "Failed to create SimpleAlarmTimer for clock=" << clock_id;
    return nullptr;
  }
  return std::make_unique<ArcTimerInfo>(clock_id, std::move(expiration_fd),
                                        std::move(simple_alarm_timer));
}

// static.
bool ArcTimerManager::ContainsDuplicateClocks(
    const std::vector<std::unique_ptr<ArcTimerInfo>>& arc_timers) {
  std::set<clockid_t> seen_clock_ids;
  for (const auto& timer : arc_timers) {
    if (!seen_clock_ids.emplace(timer->clock_id).second)
      return true;
  }
  return false;
}

void ArcTimerManager::HandleStartArcTimer(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  dbus::MessageReader reader(method_call);

  ArcTimerManager::TimerId timer_id;
  if (!reader.PopInt32(&timer_id)) {
    LOG(WARNING) << "Failed to pop timer id from " << kStartArcTimerMethod
                 << " D-Bus method call";
    std::move(response_sender)
        .Run(CreateInvalidArgsError(method_call, "Expected timer id"));
    return;
  }

  int64_t absolute_expiration_time_us;
  if (!reader.PopInt64(&absolute_expiration_time_us)) {
    LOG(WARNING) << "Failed to pop absolute expiration time from "
                 << kStartArcTimerMethod << " D-Bus method call";
    std::move(response_sender)
        .Run(CreateInvalidArgsError(method_call,
                                    "Expected absolute expiration time"));
    return;
  }
  base::TimeTicks absolute_expiration_time =
      base::TimeTicks() + base::Microseconds(absolute_expiration_time_us);

  // If a timer for the given clock is not created prior to this call then
  // return error. Else retrieve the timer associated with it.
  ArcTimerInfo* arc_timer = FindArcTimerInfo(timer_id);
  if (!arc_timer) {
    std::move(response_sender)
        .Run(CreateInvalidArgsError(
            method_call, "Invalid timer id " + std::to_string(timer_id)));
    return;
  }

  // Start the timer to expire at |absolute_expiration_time|. This call
  // automatically overrides the previous timer set.
  //
  // If the firing time has expired then set the timer to expire
  // immediately. The |current_time_ticks| should always include ticks spent
  // in sleep.
  base::TimeTicks current_time_ticks = clock_->GetCurrentBootTime();
  base::TimeDelta delay;
  if (absolute_expiration_time > current_time_ticks)
    delay = absolute_expiration_time - current_time_ticks;
  base::Time current_time = base::Time::Now();
  DVLOG(1) << "TimerId=" << timer_id << " CurrentTime=" << current_time
           << " NextAlarmAt=" << current_time + delay;
  // Pass the raw fd to write to when the timer expires. This is safe to do
  // because if the parent object goes away the timers are cleared and all
  // pending callbacks are cancelled. If the instance sets new timers after a
  // respawn, again, the old timers and pending callbacks are cancelled.
  arc_timer->timer->Start(delay,
                          base::BindRepeating(&OnExpiration, timer_id,
                                              arc_timer->expiration_fd.get()));
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void ArcTimerManager::HandleDeleteArcTimers(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  DVLOG(1) << "DeleteArcTimers";
  dbus::MessageReader reader(method_call);

  std::string tag;
  if (!reader.PopString(&tag)) {
    LOG(WARNING) << "Failed to pop tag string arg from "
                 << kDeleteArcTimersMethod << " D-Bus method call";
    std::move(response_sender)
        .Run(CreateInvalidArgsError(method_call, "Expected tag string"));
    return;
  }

  DeleteArcTimers(tag);
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void ArcTimerManager::DeleteArcTimers(const std::string& tag) {
  // Iterate over timer ids associated with |tag| and delete the timers
  // associated with each timer id.
  auto it = client_timer_ids_.find(tag);
  if (it == client_timer_ids_.end()) {
    DVLOG(1) << "Tag=" << tag << " not found";
    return;
  }

  DVLOG(1) << "Deleting timers for tag=" << tag;
  const auto& timer_ids = it->second;
  for (auto timer_id : timer_ids)
    timers_.erase(timer_id);
  client_timer_ids_.erase(it);
}

ArcTimerManager::ArcTimerInfo* ArcTimerManager::FindArcTimerInfo(
    ArcTimerManager::TimerId timer_id) {
  auto it = timers_.find(timer_id);
  return (it == timers_.end()) ? nullptr : it->second.get();
}

}  // namespace power_manager::system
