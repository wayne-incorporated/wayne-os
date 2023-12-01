// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_BACKGROUND_COMMAND_TRANSCEIVER_H_
#define TRUNKS_BACKGROUND_COMMAND_TRANSCEIVER_H_

#include "trunks/command_transceiver.h"

#include <string>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>

#include "trunks/trunks_export.h"

namespace trunks {

// Sends commands to another CommandTransceiver on a background thread. Response
// callbacks are called on the original calling thread.
// Example:
//   base::Thread background_thread("my thread");
//   ...
//   BackgroundCommandTransceiver background_transceiver(
//       next_transceiver,
//       background_thread.message_loop_proxy());
//   ...
//   background_transceiver.SendCommand(my_command, MyCallback);
class TRUNKS_EXPORT BackgroundCommandTransceiver : public CommandTransceiver {
 public:
  // All commands will be forwarded to |next_transceiver| on |task_runner|,
  // regardless of whether the synchronous or asynchronous method is used. This
  // class will hold a reference count to |task_runner|. If |task_runner| is
  // nullptr, all commands will be forwarded on the current thread. This class
  // does not take ownership of |next_transceiver|; it must remain valid for
  // the lifetime of the object.
  explicit BackgroundCommandTransceiver(
      CommandTransceiver* next_transceiver,
      const scoped_refptr<base::SequencedTaskRunner>& task_runner);
  BackgroundCommandTransceiver(const BackgroundCommandTransceiver&) = delete;
  BackgroundCommandTransceiver& operator=(const BackgroundCommandTransceiver&) =
      delete;

  ~BackgroundCommandTransceiver() override;

  // CommandTranceiver methods.
  void SendCommand(const std::string& command,
                   ResponseCallback callback) override;
  std::string SendCommandAndWait(const std::string& command) override;

 private:
  // Sends a |command| to the |next_transceiver_| and invokes a |callback| with
  // the command response.
  void SendCommandTask(const std::string& command, ResponseCallback callback);

  base::WeakPtr<BackgroundCommandTransceiver> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  CommandTransceiver* next_transceiver_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // Declared last so weak pointers are invalidated first on destruction.
  base::WeakPtrFactory<BackgroundCommandTransceiver> weak_factory_;
};

}  // namespace trunks

#endif  // TRUNKS_BACKGROUND_COMMAND_TRANSCEIVER_H_
