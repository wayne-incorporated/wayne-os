// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_EVENT_DISPATCHER_H_
#define MIST_EVENT_DISPATCHER_H_

#include <map>
#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/task/single_thread_task_executor.h>
#include <base/time/time.h>

namespace mist {

// An event dispatcher for posting a task to a message loop. To allow file
// descriptor monitoring via libevent, base::SingleThreadTaskExecutor, which
// uses base::MessagePumpLibevent, is used as the underlying message loop.
class EventDispatcher {
 public:
  EventDispatcher();
  EventDispatcher(const EventDispatcher&) = delete;
  EventDispatcher& operator=(const EventDispatcher&) = delete;

  ~EventDispatcher();

  // Starts dispatching event in a blocking manner until Stop() is called.
  void DispatchForever();

  // Stop dispatching events.
  void Stop();

  // Posts |task| to the message loop for execution. Returns true on success.
  bool PostTask(base::OnceClosure task);

  // Posts |task| to the message loop for execution after the specified |delay|.
  // Returns true on success.
  bool PostDelayedTask(base::OnceClosure task, const base::TimeDelta& delay);

 private:
  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  base::OnceClosure quit_closure_;
  base::FileDescriptorWatcher watcher_{task_executor_.task_runner()};
};

}  // namespace mist

#endif  // MIST_EVENT_DISPATCHER_H_
