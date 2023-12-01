// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <base/threading/platform_thread.h>
#include <base/threading/thread.h>
#include <base/time/time.h>

#include "perfetto_simple_producer/my_app_tracing_categories.h"

void Trial2() {
  TRACE_EVENT("perfetto_simple_producer", "Trial2");
  base::PlatformThread::Sleep(base::Milliseconds(500));
}

// This demonstrates an event that begins and ends on different threads.
void OnNewRequest(size_t request_id) {
  // Open a slice when the request came in.
  TRACE_EVENT_BEGIN("perfetto_simple_producer", "HandleRequest",
                    perfetto::Track(request_id));

  std::unique_ptr<base::Thread> thread(
      new base::Thread("HandleRequest Thread"));
  // Start a thread to handle the request.
  thread->Start();
  thread->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(
                     [](size_t request_id) {
                       TRACE_EVENT_END("perfetto_simple_producer",
                                       perfetto::Track(request_id));
                     },
                     request_id));
  thread->Stop();
}

int main(int argc, char** argv) {
  perfetto::TracingInitArgs args;

  // The system backend writes events into a system Perfetto daemon. Requires
  // the Perfetto `traced` daemon to be running (e.g., on Android Pie and
  // newer).
  args.backends |= perfetto::kSystemBackend;

  perfetto::Tracing::Initialize(args);
  perfetto::TrackEvent::Register();

  // Wait for the connection to the system Perfetto daemon being setup.
  base::PlatformThread::Sleep(base::Milliseconds(500));

  TRACE_EVENT("perfetto_simple_producer", "Trial1", "int", 100);

  // This demonstrates the nesting of trace events.
  Trial2();
  TRACE_EVENT_BEGIN("perfetto_simple_producer", "Trial3");
  OnNewRequest(100);
  base::PlatformThread::Sleep(base::Milliseconds(500));

  TRACE_EVENT_END("perfetto_simple_producer");

  LOG(INFO) << "Category enabled: "
            << TRACE_EVENT_CATEGORY_ENABLED("perfetto_simple_producer");

  LOG(INFO) << "Done tracing events";

  return 0;
}
