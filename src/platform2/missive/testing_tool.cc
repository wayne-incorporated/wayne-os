// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/at_exit.h>
#include <base/logging.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/run_loop.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/task/thread_pool/thread_pool_instance.h>
#include <base/threading/sequence_bound.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <dbus/bus.h>

#include "base/functional/bind.h"
#include "base/task/task_traits.h"
#include "missive/client/missive_client.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/util/status.h"
#include "missive/util/status_macros.h"

// The tool for manual Enqueue and Flush operations.
// Built as part of missive when running tests.
// Detailed instruction - see in README.md
namespace reporting {
namespace {

class DBusSender {
 public:
  DBusSender() {
    dbus::Bus::Options options;
    bus_ = dbus_connection_.Connect();
    CHECK(bus_);
    MissiveClient::Initialize(bus_.get());
  }

  DBusSender(const DBusSender&) = delete;
  DBusSender& operator=(const DBusSender&) = delete;

  ~DBusSender() { MissiveClient::Shutdown(); }

  void EnqueueEvent(base::StringPiece priority_string,
                    base::StringPiece destination_string,
                    base::StringPiece event_string,
                    base::OnceCallback<void(Status)> cb) {
    ASSIGN_OR_ONCE_CALLBACK_AND_RETURN(Priority priority, cb,
                                       DecodePriority(priority_string));
    ASSIGN_OR_ONCE_CALLBACK_AND_RETURN(Destination destination, cb,
                                       DecodeDestination(destination_string));
    Record record;
    record.set_destination(destination);
    record.mutable_data()->assign(event_string);
    (new RunAndRetryIfNeeded(
         base::BindRepeating(&MissiveClient::EnqueueRecord,
                             base::Unretained(MissiveClient::Get()), priority,
                             std::move(record)),
         std::move(cb)))
        ->Run();
  }

  void Flush(base::StringPiece priority_string,
             base::OnceCallback<void(Status)> cb) {
    ASSIGN_OR_ONCE_CALLBACK_AND_RETURN(Priority priority, cb,
                                       DecodePriority(priority_string));
    (new RunAndRetryIfNeeded(
         base::BindRepeating(&MissiveClient::Flush,
                             base::Unretained(MissiveClient::Get()), priority),
         std::move(cb)))
        ->Run();
  }

 private:
  // Helper class runs `action` and repeats it if the returned `status` is
  // UNAVAILABLE. If the `status` is OK or any other error, exits.
  class RunAndRetryIfNeeded {
   public:
    RunAndRetryIfNeeded(
        base::RepeatingCallback<void(base::OnceCallback<void(Status)>)> action,
        base::OnceCallback<void(Status)> cb)
        : action_(action), cb_(std::move(cb)) {}

    void Run() {
      action_.Run(base::BindOnce(&RunAndRetryIfNeeded::CalledBack,
                                 base::Unretained(this)));
    }

   private:
    void CalledBack(Status status) {
      if (status.ok() || status.error_code() != error::UNAVAILABLE) {
        std::move(cb_).Run(status);
        delete this;
        return;
      }
      // Back off and retry.
      base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&RunAndRetryIfNeeded::Run, base::Unretained(this)),
          /*delay=*/base::Seconds(1));
    }

    const base::RepeatingCallback<void(base::OnceCallback<void(Status)>)>
        action_;
    base::OnceCallback<void(Status)> cb_;
  };

  StatusOr<Priority> DecodePriority(base::StringPiece priority_string) {
    Priority priority;
    if (!Priority_Parse(std::string(priority_string), &priority) ||
        priority == Priority::UNDEFINED_PRIORITY) {
      return Status(
          error::INVALID_ARGUMENT,
          base::StrCat({"Wrong priority: ", std::string(priority_string)}));
    }
    return priority;
  }

  StatusOr<Destination> DecodeDestination(
      base::StringPiece destination_string) {
    Destination destination;
    if (!Destination_Parse(std::string(destination_string), &destination) ||
        destination == Destination::UNDEFINED_DESTINATION) {
      return Status(error::INVALID_ARGUMENT,
                    base::StrCat({"Wrong destination: ",
                                  std::string(destination_string)}));
    }
    return destination;
  }

  brillo::DBusConnection dbus_connection_;
  scoped_refptr<::dbus::Bus> bus_;
};
}  // namespace
}  // namespace reporting

int main(int argc, char* argv[]) {
  base::AtExitManager exit_manager;

  DEFINE_string(priority, "UNDEFINED", "Priority of the queue");
  DEFINE_string(destination, "UNDEFINED", "Destination of the event");
  DEFINE_string(enqueue, "", "Event to be enqueued");
  DEFINE_bool(flush, false, "Flag to flush the event");

  brillo::FlagHelper::Init(argc, argv, R"(
  missive_testing_tool:

  To enqueue event:
    --priority=...       priority queue to enqueue to
    --destination=...    destination of the enqueued event
    --enqueue="..."      requesting to enqueue event
                         (record data passed as a string)

  To flush queue:
    --priority=...       priority queue to flush
    --flush              requesting to flush the queue
  )");

  // Always log to syslog and log to stderr if we are connected to a tty.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Override the log items set by brillo::InitLog.
  logging::SetLogItems(/*enable_process_id=*/true, /*enable_thread_id=*/true,
                       /*enable_timestamp=*/true, /*enable_tickcount=*/true);

  base::ThreadPoolInstance::CreateAndStartWithDefaultParams(
      "missive_test_thread_pool");

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::RunLoop run_loop;
  base::SequenceBound<::reporting::DBusSender> sender(
      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()}));

  auto cb = base::BindOnce(
      [](base::ScopedClosureRunner done, ::reporting::Status status) {
        LOG_IF(WARNING, status.ok()) << "Success!";
        LOG_IF(ERROR, !status.ok()) << "Failed: " << status;
      },
      base::ScopedClosureRunner(run_loop.QuitClosure()));
  if (FLAGS_flush) {
    LOG(INFO) << "Flush priority=" << FLAGS_priority;
    sender.AsyncCall(&::reporting::DBusSender::Flush)
        .WithArgs(FLAGS_priority, std::move(cb));
  } else if (!FLAGS_enqueue.empty()) {
    LOG(INFO) << "Enqueue priority=" << FLAGS_priority << " "
              << " destination=" << FLAGS_destination
              << " size_of_data=" << FLAGS_enqueue.size();
    sender.AsyncCall(&::reporting::DBusSender::EnqueueEvent)
        .WithArgs(FLAGS_priority, FLAGS_destination, FLAGS_enqueue,
                  std::move(cb));
  } else {
    std::move(cb).Run(::reporting::Status(
        ::reporting::error::FAILED_PRECONDITION, "No request specified."));
  }
  run_loop.Run();

  exit(0);
}
