// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/arc_timer_manager.h"

#include <time.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <sys/socket.h>

#include "power_manager/common/test_main_loop_runner.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

bool CreateSocketPair(base::ScopedFD* one, base::ScopedFD* two) {
  int raw_socks[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, raw_socks) != 0) {
    PLOG(ERROR) << "Failed to create socket pair";
    return false;
  }
  one->reset(raw_socks[0]);
  two->reset(raw_socks[1]);
  return true;
}

std::vector<base::ScopedFD> WriteCreateTimersDBusRequest(
    const std::string& tag,
    const std::vector<clockid_t>& clocks,
    dbus::MessageWriter* writer) {
  // Create D-Bus arguments i.e. tag followed by array of
  // {int32_t clock_id, base::ScopedFD expiration_fd}.
  writer->AppendString(tag);
  dbus::MessageWriter array_writer(nullptr);
  writer->OpenArray("(ih)", &array_writer);
  std::vector<base::ScopedFD> result;
  for (clockid_t clock_id : clocks) {
    // Create a socket pair for each clock. One socket will be part of the
    // mojo argument and will be used by the host to indicate when the timer
    // expires. The other socket will be used to detect the expiration of the
    // timer by epolling / reading.
    base::ScopedFD read_fd;
    base::ScopedFD write_fd;
    if (!CreateSocketPair(&read_fd, &write_fd)) {
      LOG(ERROR) << "Failed to create socket pair for ARC timers";
      return result;
    }
    result.push_back(std::move(read_fd));

    dbus::MessageWriter struct_writer(nullptr);
    array_writer.OpenStruct(&struct_writer);
    struct_writer.AppendInt32(static_cast<int32_t>(clock_id));
    struct_writer.AppendFileDescriptor(write_fd.get());
    array_writer.CloseContainer(&struct_writer);
  }
  writer->CloseContainer(&array_writer);
  return result;
}

std::vector<ArcTimerManager::TimerId> ReadTimerIds(
    std::unique_ptr<dbus::Response> response) {
  dbus::MessageReader reader(response.get());
  dbus::MessageReader array_reader(nullptr);
  std::vector<ArcTimerManager::TimerId> result;
  if (!reader.PopArray(&array_reader)) {
    LOG(ERROR) << "No timer ids returned";
    return result;
  }
  std::vector<ArcTimerManager::TimerId> timer_ids;
  while (array_reader.HasMoreData()) {
    ArcTimerManager::TimerId timer_id;
    if (!array_reader.PopInt32(&timer_id)) {
      LOG(ERROR) << "Failed to pop timer id";
      return result;
    }
    result.push_back(timer_id);
  }
  return result;
}

bool IsResponseValid(dbus::Response* response) {
  return response && response->GetMessageType() ==
                         dbus::Message::MessageType::MESSAGE_METHOD_RETURN;
}

// Returns true iff |a| and |b| are of the same size and all entries in |a| are
// different from |b|.
bool AreTimerIdsIdenticalSizeButDistinct(
    const std::vector<ArcTimerManager::TimerId>& a,
    const std::vector<ArcTimerManager::TimerId>& b) {
  if (a.size() != b.size())
    return false;

  for (auto id : a) {
    if (std::find(b.begin(), b.end(), id) != b.end())
      return false;
  }
  return true;
}

}  // namespace

class ArcTimerManagerTest : public TestEnvironment {
 public:
  ArcTimerManagerTest() {
    arc_timer_manager_.set_for_testing_(true);
    arc_timer_manager_.Init(&dbus_wrapper_);
  }
  ArcTimerManagerTest(const ArcTimerManagerTest&) = delete;
  ArcTimerManagerTest& operator=(const ArcTimerManagerTest&) = delete;

 protected:
  [[nodiscard]] bool CreateTimers(const std::string& tag,
                                  const std::vector<clockid_t>& clocks) {
    dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                                 power_manager::kCreateArcTimersMethod);
    dbus::MessageWriter writer(&method_call);
    std::vector<base::ScopedFD> read_fds =
        WriteCreateTimersDBusRequest(tag, clocks, &writer);
    size_t clocks_size = clocks.size();
    if (read_fds.size() != clocks_size) {
      LOG(ERROR) << "Failed to create D-Bus request";
      return false;
    }

    std::unique_ptr<dbus::Response> response =
        dbus_wrapper_.CallExportedMethodSync(&method_call);
    if (!IsResponseValid(response.get())) {
      LOG(ERROR) << power_manager::kCreateArcTimersMethod << " call failed";
      return false;
    }

    // Parse timer ids returned from the response.
    std::vector<ArcTimerManager::TimerId> timer_ids =
        ReadTimerIds(std::move(response));
    if (timer_ids.size() != clocks_size) {
      LOG(ERROR) << "Expected timer ids size=" << clocks_size
                 << " got size=" << timer_ids.size();
      return false;
    }

    // Map each clock id to its corresponding timer id. Also, map each timer id
    // to its corresponding read fd that will indicate timer expiration.
    auto timer_id_iter = timer_ids.begin();
    auto read_fd_iter = read_fds.begin();
    auto arc_timer_store = std::make_unique<ArcTimerStore>();
    for (clockid_t clock_id : clocks) {
      VLOG(1) << "Adding entry for clock=" << clock_id
              << " timer id=" << *timer_id_iter;
      if (!arc_timer_store->AddTimerEntry(clock_id, *timer_id_iter,
                                          std::move(*read_fd_iter))) {
        return false;
      }
      timer_id_iter++;
      read_fd_iter++;
    }
    // It's okay to overwrite a |tag|'s value here to support tests that
    // create-delete-create with the same tag.
    arc_timer_stores_[tag] = std::move(arc_timer_store);
    return true;
  }

  [[nodiscard]] bool StartTimer(const std::string& tag,
                                clockid_t clock_id,
                                base::TimeTicks absolute_expiration_time) {
    dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                                 power_manager::kStartArcTimerMethod);

    if (arc_timer_stores_.find(tag) == arc_timer_stores_.end()) {
      LOG(ERROR) << "Tag=" << tag << " not created";
      return false;
    }
    const auto& arc_timer_store = arc_timer_stores_[tag];

    // Write timer id corresponding to |clock_id| and 64-bit expiration time
    // ticks value as a DBus message.
    dbus::MessageWriter writer(&method_call);
    ArcTimerManager::TimerId timer_id = arc_timer_store->GetTimerId(clock_id);
    if (timer_id < 0) {
      LOG(ERROR) << "Timer for clock=" << clock_id << " not created";
      return false;
    }
    writer.AppendInt32(timer_id);
    writer.AppendInt64(
        (absolute_expiration_time - base::TimeTicks()).InMicroseconds());
    std::unique_ptr<dbus::Response> response =
        dbus_wrapper_.CallExportedMethodSync(&method_call);
    if (!IsResponseValid(response.get())) {
      LOG(ERROR) << power_manager::kStartArcTimerMethod << " call failed";
      return false;
    }
    return true;
  }

  // Returns true iff the read descriptor of a timer is signalled. If the
  // signalling is incorrect returns false. Blocks otherwise.
  [[nodiscard]] bool WaitForExpiration(const std::string& tag,
                                       clockid_t clock_id) {
    if (arc_timer_stores_.find(tag) == arc_timer_stores_.end()) {
      LOG(ERROR) << "Tag=" << tag << " not created";
      return false;
    }
    const auto& arc_timer_store = arc_timer_stores_[tag];

    if (!arc_timer_store->HasTimer(clock_id)) {
      LOG(ERROR) << "Timer of type=" << clock_id << " not present";
      return false;
    }

    // Wait for the host to indicate expiration by watching the read end of the
    // socket pair.
    int timer_read_fd = arc_timer_store->GetTimerReadFd(clock_id);
    if (timer_read_fd < 0) {
      LOG(ERROR) << "Clock=" << clock_id << " fd not present";
      return false;
    }

    // Run the loop until the timer's read fd to becomes readable.
    base::RunLoop loop;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher;
    watcher = base::FileDescriptorWatcher::WatchReadable(
        timer_read_fd,
        base::BindRepeating(
            [](base::RunLoop* loop,
               std::unique_ptr<base::FileDescriptorWatcher::Controller>*
                   watcher) {
              VLOG(1) << "Fd readable";
              *watcher = nullptr;
              loop->Quit();
            },
            &loop, &watcher));
    loop.Run();

    // The timer expects 8 bytes to be written from the host upon expiration.
    // The read data signifies the number of expirations. The powerd
    // implementation always returns one expiration.
    uint64_t timer_data = 0;
    ssize_t bytes_read = read(timer_read_fd, &timer_data, sizeof(timer_data));
    if ((bytes_read != sizeof(timer_data)) || (timer_data != 1)) {
      LOG(ERROR) << "Bad expiration data: bytes_read=" << bytes_read
                 << " timer_data=" << timer_data;
      return false;
    }
    return true;
  }

  [[nodiscard]] bool DeleteTimers(const std::string& tag) {
    dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                                 power_manager::kDeleteArcTimersMethod);
    dbus::MessageWriter writer(&method_call);
    writer.AppendString(tag);
    std::unique_ptr<dbus::Response> response =
        dbus_wrapper_.CallExportedMethodSync(&method_call);
    if (!IsResponseValid(response.get())) {
      return false;
    }
    return true;
  }

 protected:
  ArcTimerManager arc_timer_manager_;

 private:
  // Stores clock ids and their corresponding file descriptors. These file
  // descriptors indicate when a timer corresponding to the clock has expired on
  // a read.
  class ArcTimerStore {
   public:
    ArcTimerStore() = default;
    ArcTimerStore(const ArcTimerStore&) = delete;
    ArcTimerStore& operator=(const ArcTimerStore&) = delete;

    bool AddTimerEntry(clockid_t clock_id,
                       ArcTimerManager::TimerId timer_id,
                       base::ScopedFD read_fd) {
      if (!timer_ids_.emplace(clock_id, timer_id).second) {
        LOG(ERROR) << "Failed to set timer id for clock=" << clock_id;
        return false;
      }
      if (!arc_timers_.emplace(timer_id, std::move(read_fd)).second) {
        LOG(ERROR) << "Failed to store read fd for timer id=" << timer_id;
        return false;
      }
      return true;
    }

    void ClearTimers() {
      timer_ids_.clear();
      arc_timers_.clear();
    }

    int GetTimerReadFd(clockid_t clock_id) {
      return HasTimer(clock_id) ? arc_timers_[GetTimerId(clock_id)].get() : -1;
    }

    bool HasTimer(clockid_t clock_id) const {
      ArcTimerManager::TimerId timer_id = GetTimerId(clock_id);
      return timer_id >= 0 && arc_timers_.find(timer_id) != arc_timers_.end();
    }

    ArcTimerManager::TimerId GetTimerId(clockid_t clock_id) const {
      auto it = timer_ids_.find(clock_id);
      return it == timer_ids_.end() ? -1 : it->second;
    }

   private:
    // Map of clock id to timer id of the associated timer created.
    std::map<clockid_t, ArcTimerManager::TimerId> timer_ids_;

    // Map of timer id to the read fd that will indicate expiration of the
    // timer.
    std::map<ArcTimerManager::TimerId, base::ScopedFD> arc_timers_;
  };

  // Mapping of a client's tag and the |ArcTimerStore| to use with it.
  std::map<std::string, std::unique_ptr<ArcTimerStore>> arc_timer_stores_;

  DBusWrapperStub dbus_wrapper_;
};

TEST_F(ArcTimerManagerTest, CreateAndStartTimer) {
  std::vector<clockid_t> clocks = {CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM};
  const std::string kTag = "Test";
  ASSERT_TRUE(CreateTimers(kTag, clocks));
  ASSERT_TRUE(StartTimer(kTag, CLOCK_BOOTTIME_ALARM,
                         base::TimeTicks::Now() + base::Milliseconds(1)));
  ASSERT_TRUE(WaitForExpiration(kTag, CLOCK_BOOTTIME_ALARM));
}

TEST_F(ArcTimerManagerTest, CreateAndDeleteTimers) {
  std::vector<clockid_t> clocks = {CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM};
  const std::string kTag = "Test";
  ASSERT_TRUE(CreateTimers(kTag, clocks));
  // |DeleteTimers| returns success for an unregistered tag.
  ASSERT_TRUE(DeleteTimers("Foo"));
  // Delete created timers and then try to start a timer. The call should fail
  // as the timer doesn't exist.
  ASSERT_TRUE(DeleteTimers(kTag));
  ASSERT_FALSE(StartTimer(kTag, CLOCK_BOOTTIME_ALARM,
                          base::TimeTicks::Now() + base::Milliseconds(1)));
}

TEST_F(ArcTimerManagerTest, CheckInvalidCreateTimersArgs) {
  std::vector<clockid_t> clocks = {CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
                                   CLOCK_REALTIME_ALARM};
  // Creating timers should fail when duplicate clock ids are passed in.
  ASSERT_FALSE(CreateTimers("Test", clocks));
}

TEST_F(ArcTimerManagerTest, CheckInvalidStartTimerArgs) {
  std::vector<clockid_t> clocks = {CLOCK_REALTIME_ALARM};
  const std::string kTag = "Test";
  ASSERT_TRUE(CreateTimers(kTag, clocks));
  // Starting timer for unregistered clock id should fail.
  ASSERT_FALSE(StartTimer(kTag, CLOCK_BOOTTIME_ALARM,
                          base::TimeTicks::Now() + base::Milliseconds(1)));
}

TEST_F(ArcTimerManagerTest, CheckMultipleCreateTimers) {
  std::vector<clockid_t> clocks = {CLOCK_REALTIME_ALARM};
  const std::string kTag = "Test1";
  ASSERT_TRUE(CreateTimers(kTag, clocks));
  std::vector<ArcTimerManager::TimerId> first_create_ids =
      arc_timer_manager_.GetTimerIdsForTesting(kTag);

  // Creating timers with a registered tag should delete the old timers
  // associated with the tag and succeed. Check that the delete succeeded by
  // checking that the new timer ids are different from the old timer ids.
  ASSERT_TRUE(CreateTimers(kTag, clocks));
  std::vector<ArcTimerManager::TimerId> second_create_ids =
      arc_timer_manager_.GetTimerIdsForTesting(kTag);
  ASSERT_TRUE(
      AreTimerIdsIdenticalSizeButDistinct(first_create_ids, second_create_ids));

  // Creating timers after deleting old timers should succeed.
  ASSERT_TRUE(DeleteTimers(kTag));
  ASSERT_TRUE(CreateTimers(kTag, clocks));

  // Create timers with a different tag should also succeed.
  ASSERT_TRUE(CreateTimers("Test2", clocks));
}

TEST_F(ArcTimerManagerTest, CheckDeleteAndStartOther) {
  // Create timers with two different tags. Delete the first tag and check if
  // the second tag's timers still start.
  std::vector<clockid_t> clocks = {CLOCK_REALTIME_ALARM};
  const std::string kTag1 = "Test1";
  ASSERT_TRUE(CreateTimers(kTag1, clocks));
  const std::string kTag2 = "Test2";
  ASSERT_TRUE(CreateTimers(kTag2, clocks));
  ASSERT_TRUE(DeleteTimers(kTag1));
  ASSERT_TRUE(StartTimer(kTag2, CLOCK_REALTIME_ALARM,
                         base::TimeTicks::Now() + base::Milliseconds(1)));
  ASSERT_TRUE(WaitForExpiration(kTag2, CLOCK_REALTIME_ALARM));
}

}  // namespace power_manager::system
