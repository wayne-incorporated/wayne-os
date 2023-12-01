// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gio/gio.h>
#include <glib.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/test/task_environment.h>
#include <base/run_loop.h>
#include <gtest/gtest.h>

#include "glib-bridge/glib_bridge.h"
#include "glib-bridge/glib_scopers.h"

namespace glib_bridge {

namespace {

constexpr base::TimeDelta kTestTimeout = base::Seconds(1);

// Use instead of g_idle_add, which implicitly uses the global default context.
void ScheduleIdleCallback(GSourceFunc func, gpointer data) {
  GSource* idle_source = g_idle_source_new();
  g_source_set_callback(idle_source, func, data, nullptr);
  g_source_set_priority(idle_source, G_PRIORITY_DEFAULT);
  g_source_attach(idle_source, g_main_context_get_thread_default());
  g_source_unref(idle_source);
}

// Use instead of g_timeout_add, which implicitly uses the global default
// context.
void ScheduleTimeoutCallback(int timeout_ms, GSourceFunc func, gpointer data) {
  GSource* timeout_source = g_timeout_source_new(timeout_ms);
  g_source_set_callback(timeout_source, func, data, nullptr);
  g_source_set_priority(timeout_source, G_PRIORITY_DEFAULT);
  g_source_attach(timeout_source, g_main_context_get_thread_default());
  g_source_unref(timeout_source);
}

}  // namespace

class GlibBridgeTest : public ::testing::Test {
 public:
  GlibBridgeTest() : glib_bridge_(new GlibBridge()) {}
  GlibBridgeTest(const GlibBridgeTest&) = delete;
  GlibBridgeTest& operator=(const GlibBridgeTest&) = delete;

  ~GlibBridgeTest() override {}

  void Finish() { run_loop_.Quit(); }

 protected:
  void Start() {
    // Set up timeout
    task_environment_.GetMainThreadTaskRunner()->PostDelayedTask(
        FROM_HERE, run_loop_.QuitClosure(), kTestTimeout);
    run_loop_.Run();
  }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
  base::RunLoop run_loop_;
  std::unique_ptr<GlibBridge> glib_bridge_;
};

TEST_F(GlibBridgeTest, ReadFileCallback) {
  struct UserData {
    GlibBridgeTest* test;
    ssize_t bytes_read;
  };
  UserData user_data{this, 0};

  ScopedGObject<GFile> dev_file(g_file_new_for_path("/dev/zero"));
  ASSERT_TRUE(dev_file);
  ScopedGObject<GFileInputStream> istream(
      g_file_read(dev_file.get(), nullptr, nullptr));
  ASSERT_TRUE(istream);

  constexpr int kBufSize = 64;
  char buf[kBufSize];
  memset(buf, 1, kBufSize);
  auto read_results_ready = [](GObject* source, GAsyncResult* res,
                               gpointer user_data) {
    UserData* ud = reinterpret_cast<UserData*>(user_data);
    ud->bytes_read =
        g_input_stream_read_finish(G_INPUT_STREAM(source), res, nullptr);
    ud->test->Finish();
  };
  g_input_stream_read_async(
      G_INPUT_STREAM(istream.get()), buf, kBufSize, G_PRIORITY_DEFAULT, nullptr,
      static_cast<GAsyncReadyCallback>(read_results_ready), &user_data);
  Start();

  ASSERT_EQ(user_data.bytes_read, kBufSize);
  char expected_buf[kBufSize];
  memset(expected_buf, 0, kBufSize);
  ASSERT_EQ(memcmp(buf, expected_buf, kBufSize), 0);
}

TEST_F(GlibBridgeTest, WriteFileCallback) {
  struct UserData {
    GlibBridgeTest* test;
    ssize_t bytes_written;
  };
  UserData user_data{this, 0};

  ScopedGObject<GFile> dev_file(g_file_new_for_path("/dev/null"));
  ASSERT_TRUE(dev_file);
  ScopedGObject<GFileOutputStream> ostream(
      g_file_append_to(dev_file.get(), G_FILE_CREATE_NONE, nullptr, nullptr));
  ASSERT_TRUE(ostream);

  const std::string buf("foobar");
  auto write_done = [](GObject* source, GAsyncResult* res, gpointer user_data) {
    UserData* ud = reinterpret_cast<UserData*>(user_data);
    ud->bytes_written = g_output_stream_write_finish(
        reinterpret_cast<GOutputStream*>(source), res, nullptr);
    ud->test->Finish();
  };
  g_output_stream_write_async(G_OUTPUT_STREAM(ostream.get()), buf.data(),
                              buf.size(), G_PRIORITY_DEFAULT, nullptr,
                              static_cast<GAsyncReadyCallback>(write_done),
                              &user_data);
  Start();

  ASSERT_EQ(user_data.bytes_written, buf.size());
}

TEST_F(GlibBridgeTest, IdleCallback) {
  struct UserData {
    GlibBridgeTest* test;
    bool called;
  };
  UserData user_data{this, false};

  auto idle_callback = [](gpointer user_data) {
    UserData* ud = reinterpret_cast<UserData*>(user_data);
    ud->called = true;
    ud->test->Finish();
    return G_SOURCE_REMOVE;
  };

  ScheduleIdleCallback(static_cast<GSourceFunc>(idle_callback), &user_data);
  Start();

  ASSERT_TRUE(user_data.called);
}

TEST_F(GlibBridgeTest, TimeoutOnceCallback) {
  struct UserData {
    GlibBridgeTest* test;
    bool called;
  };
  UserData user_data{this, false};

  auto timer_callback = [](gpointer user_data) {
    UserData* ud = reinterpret_cast<UserData*>(user_data);
    ud->called = true;
    ud->test->Finish();
    return G_SOURCE_REMOVE;
  };

  constexpr uint kTimeoutIntervalMs = 200;
  ScheduleTimeoutCallback(kTimeoutIntervalMs,
                          static_cast<GSourceFunc>(timer_callback), &user_data);
  Start();

  ASSERT_TRUE(user_data.called);
}

TEST_F(GlibBridgeTest, TimeoutMultiCallback) {
  constexpr int kTarget = 5;
  struct UserData {
    GlibBridgeTest* test;
    int counter;
  };
  UserData user_data{this, 0};

  auto timer_callback = [](gpointer user_data) -> gboolean {
    UserData* ud = reinterpret_cast<UserData*>(user_data);
    ud->counter++;
    if (ud->counter == kTarget) {
      ud->test->Finish();
      return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
  };

  constexpr uint kTimeoutIntervalMs = 100;
  ScheduleTimeoutCallback(kTimeoutIntervalMs,
                          static_cast<GSourceFunc>(timer_callback), &user_data);
  Start();

  ASSERT_EQ(user_data.counter, kTarget);
}

TEST_F(GlibBridgeTest, MultipleTimeouts) {
  constexpr uint kNumFlags = 5;
  struct UserData {
    GlibBridgeTest* test;
    int counter;
    bool called[kNumFlags];
  };
  UserData user_data{this, 0, {false}};

  auto timer_callback = [](gpointer user_data) {
    UserData* ud = reinterpret_cast<UserData*>(user_data);
    ud->called[ud->counter] = true;
    ud->counter++;
    if (ud->counter == kNumFlags)
      ud->test->Finish();
    return G_SOURCE_REMOVE;
  };

  constexpr uint kTimeoutIntervalMs = 100;
  for (int i = 0; i < kNumFlags; i++) {
    ScheduleTimeoutCallback(kTimeoutIntervalMs * (i + 1),
                            static_cast<GSourceFunc>(timer_callback),
                            &user_data);
  }
  Start();

  for (int i = 0; i < kNumFlags; i++)
    ASSERT_TRUE(user_data.called[i]);
}

namespace multi_io_test {

constexpr int kBufSize = 64;

struct UserData;
struct IoJob {
  IoJob(ScopedGObject<GFile> file,
        ScopedGObject<GFileInputStream> istream,
        UserData* user_data)
      : file(std::move(file)),
        istream(std::move(istream)),
        buf(kBufSize, 1),
        user_data(user_data) {}

  ScopedGObject<GFile> file;
  ScopedGObject<GFileInputStream> istream;
  std::vector<char> buf;
  bool complete = false;
  UserData* user_data;
};

struct UserData {
  GlibBridgeTest* test;
  std::vector<IoJob> io_jobs;
};

gboolean AllCompleteCheck(gpointer user_data) {
  UserData* ud = reinterpret_cast<UserData*>(user_data);
  bool all_complete = true;
  for (const IoJob& io_job : ud->io_jobs)
    all_complete &= io_job.complete;
  if (all_complete)
    ud->test->Finish();
  return G_SOURCE_REMOVE;
}

void ReadResultsReady(GObject* source, GAsyncResult* res, gpointer user_data) {
  IoJob* job = reinterpret_cast<IoJob*>(user_data);
  job->complete =
      g_input_stream_read_finish(G_INPUT_STREAM(source), res, nullptr) >= 0;
  ScheduleIdleCallback(static_cast<GSourceFunc>(&AllCompleteCheck),
                       job->user_data);
}

TEST_F(GlibBridgeTest, MultipleReadAndIdleCallbacks) {
  UserData user_data{this};
  constexpr int kNumFiles = 5;
  for (int i = 0; i < kNumFiles; i++) {
    ScopedGObject<GFile> dev_file(g_file_new_for_path("/dev/zero"));
    ASSERT_TRUE(dev_file);
    ScopedGObject<GFileInputStream> istream(
        g_file_read(dev_file.get(), nullptr, nullptr));
    ASSERT_TRUE(istream);
    user_data.io_jobs.emplace_back(std::move(dev_file), std::move(istream),
                                   &user_data);
  }

  for (IoJob& io_job : user_data.io_jobs) {
    g_input_stream_read_async(
        G_INPUT_STREAM(io_job.istream.get()), &io_job.buf[0], io_job.buf.size(),
        G_PRIORITY_DEFAULT, nullptr,
        static_cast<GAsyncReadyCallback>(&ReadResultsReady), &io_job);
  }
  Start();

  bool all_complete = true;
  for (const IoJob& io_job : user_data.io_jobs) {
    all_complete &= io_job.complete;
    std::vector<char> expected_buf(io_job.buf.size(), 0);
    ASSERT_EQ(io_job.buf, expected_buf);
  }
  ASSERT_TRUE(all_complete);
}

}  // namespace multi_io_test

}  // namespace glib_bridge
