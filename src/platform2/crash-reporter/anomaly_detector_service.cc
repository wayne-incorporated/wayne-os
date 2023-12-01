// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector_service.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/time/default_clock.h>
#include <chromeos/dbus/service_constants.h>
#include <metrics/metrics_library.h>
#include <metrics_event/proto_bindings/metrics_event.pb.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_util.h>
#include <brillo/process/process.h>
#include <vm_protos/proto_bindings/vm_host.pb.h>

#include "crash-reporter/anomaly_detector.h"
#include "crash-reporter/crash_reporter_parser.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace anomaly {

namespace {

// Callback to run crash-reporter.
void RunCrashReporter(const std::vector<std::string>& flags,
                      const std::string& input) {
  LOG(INFO) << "anomaly_detector invoking crash_reporter with "
            << base::JoinString(flags, " ");
  brillo::ProcessImpl cmd;
  cmd.AddArg("/sbin/crash_reporter");
  for (const std::string& flag : flags) {
    cmd.AddArg(flag);
  }
  cmd.RedirectUsingPipe(STDIN_FILENO, true);
  CHECK(cmd.Start());
  int stdin_fd = cmd.GetPipe(STDIN_FILENO);
  CHECK(base::WriteFileDescriptor(stdin_fd, input));
  CHECK_GE(close(stdin_fd), 0);
  CHECK_EQ(0, cmd.Wait());
}

std::unique_ptr<dbus::Signal> MakeOomSignal(const int64_t oom_timestamp_ms) {
  auto signal = std::make_unique<dbus::Signal>(
      anomaly_detector::kAnomalyEventServiceInterface,
      anomaly_detector::kAnomalyEventSignalName);
  dbus::MessageWriter writer(signal.get());
  metrics_event::Event payload;
  payload.set_type(metrics_event::Event_Type_OOM_KILL_KERNEL);
  payload.set_timestamp(oom_timestamp_ms);
  writer.AppendProtoAsArrayOfBytes(payload);

  return signal;
}

}  // namespace

// Time between calls to Parser::PeriodicUpdate.
constexpr base::TimeDelta kUpdatePeriod = base::Seconds(10);

const base::FilePath kAuditLogPath("/var/log/audit/audit.log");

const base::FilePath kUpstartLogPath("/var/log/upstart.log");

constexpr base::TimeDelta kTimeBetweenLogReads = base::Milliseconds(500);

Service::Service(base::OnceClosure shutdown_callback, bool testonly_send_all)
    : shutdown_callback_(std::move(shutdown_callback)),
      weak_ptr_factory_(this),
      testonly_send_all_(testonly_send_all) {
  parsers_["audit"] =
      std::make_unique<anomaly::SELinuxParser>(testonly_send_all);
  parsers_["init"] =
      std::make_unique<anomaly::ServiceParser>(testonly_send_all);
  parsers_["kernel"] =
      std::make_unique<anomaly::KernelParser>(testonly_send_all);
  parsers_["powerd_suspend"] =
      std::make_unique<anomaly::SuspendParser>(testonly_send_all);
  parsers_["crash_reporter"] = std::make_unique<anomaly::CrashReporterParser>(
      std::make_unique<base::DefaultClock>(),
      std::make_unique<MetricsLibrary>(), testonly_send_all);
  parsers_["cryptohomed"] =
      std::make_unique<anomaly::CryptohomeParser>(testonly_send_all);
  parsers_["tcsd"] = std::make_unique<anomaly::TcsdParser>();
  parsers_["shill"] = std::make_unique<anomaly::ShillParser>(testonly_send_all);
  parsers_["hermes"] =
      std::make_unique<anomaly::HermesParser>(testonly_send_all);

  // If any log file is missing, the LogReader will try to reopen the file on
  // GetNextEntry method call. After multiple attempts however LogReader will
  // give up and logs the error. Note that some boards do not have SELinux and
  // thus no audit.log.
  log_readers_.push_back(std::make_unique<anomaly::AuditReader>(
      kAuditLogPath, anomaly::kAuditLogPattern));
  log_readers_.push_back(std::make_unique<anomaly::MessageReader>(
      base::FilePath(paths::kMessageLogPath), anomaly::kMessageLogPattern));
  log_readers_.push_back(std::make_unique<anomaly::MessageReader>(
      kUpstartLogPath, anomaly::kUpstartLogPattern));
}

bool Service::Init() {
  // Connect to DBus.
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  dbus_ = base::MakeRefCounted<dbus::Bus>(options);

  if (!dbus_->Connect()) {
    LOG(ERROR) << "Failed to connect to D-Bus";
    return false;
  }
  termina_parser_ = std::make_unique<anomaly::TerminaParser>(
      dbus_, std::make_unique<MetricsLibrary>(), testonly_send_all_);

  // Export a bus object so that other processes can register signal handlers
  // and make method calls.
  exported_object_ = dbus_->GetExportedObject(
      dbus::ObjectPath(anomaly_detector::kAnomalyEventServicePath));

  // Export methods
  bool res = exported_object_->ExportMethodAndBlock(
      anomaly_detector::kAnomalyEventServiceInterface,
      anomaly_detector::kAnomalyVmKernelLogMethod,
      base::BindRepeating(&Service::ProcessVmKernelLog,
                          weak_ptr_factory_.GetWeakPtr()));
  if (!res) {
    LOG(ERROR) << "Failed to export DBus method "
               << anomaly_detector::kAnomalyVmKernelLogMethod;
    return false;
  }

  // Request ownership of the well known name for anomaly_detector. This must be
  // done after exporting all the methods above to ensure no one tries to call a
  // method not yet exposed.
  res = dbus_->RequestOwnershipAndBlock(
      anomaly_detector::kAnomalyEventServiceName,
      dbus::Bus::ServiceOwnershipOptions::REQUIRE_PRIMARY);
  if (!res) {
    LOG(ERROR) << "Failed to take ownership of the anomaly event service name";
    return false;
  }

  // Wait a short interval between reading logs
  short_timer_.Start(
      FROM_HERE, kTimeBetweenLogReads,
      base::BindRepeating(&Service::ReadLogs, weak_ptr_factory_.GetWeakPtr()));
  // For anomalies that may occur based on _lack_ of a certain log message,
  // check on a longer interval.
  long_timer_.Start(FROM_HERE, kUpdatePeriod,
                    base::BindRepeating(&Service::PeriodicUpdate,
                                        weak_ptr_factory_.GetWeakPtr()));

  // Indicate to tast tests that anomaly-detector has started.
  base::FilePath path = base::FilePath(paths::kSystemRunStateDirectory)
                            .Append(paths::kAnomalyDetectorReady);
  if (base::WriteFile(path, "", 0) == -1) {
    // Log but don't prevent anomaly detector from starting because this file
    // is not essential to its operation.
    PLOG(ERROR) << "Couldn't write " << path.value() << " (tests may fail)";
  }

  return true;
}

void Service::ReadLogs() {
  for (auto& reader : log_readers_) {
    anomaly::LogEntry entry;
    while (reader->GetNextEntry(&entry)) {
      anomaly::MaybeCrashReport crash_report;
      if (parsers_.count(entry.tag) > 0) {
        crash_report = parsers_[entry.tag]->ParseLogEntry(entry.message);
      }

      if (crash_report) {
        RunCrashReporter(crash_report->flags, crash_report->text);
      }

      // Handle OOM messages.
      if (entry.tag == "kernel" &&
          entry.message.find("Out of memory: Kill process") !=
              std::string::npos)
        exported_object_->SendSignal(
            MakeOomSignal(static_cast<int>(entry.timestamp.ToDoubleT() * 1000))
                .get());
    }
  }
}

void Service::PeriodicUpdate() {
  for (const auto& parser : parsers_) {
    anomaly::MaybeCrashReport crash_report = parser.second->PeriodicUpdate();
    if (crash_report) {
      RunCrashReporter(crash_report->flags, crash_report->text);
    }
  }
}

void Service::ProcessVmKernelLog(dbus::MethodCall* method_call,
                                 dbus::ExportedObject::ResponseSender sender) {
  dbus::MessageReader reader(method_call);
  auto response = dbus::Response::FromMethodCall(method_call);

  vm_tools::VmKernelLogRequest request;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse VmKernelLogRequest from DBus call";
    std::move(sender).Run(std::move(response));
    return;
  }

  // We don't currently care about logs from non-termina VMs, so just ignore
  // such calls.
  if (request.vm_type() != vm_tools::VmKernelLogRequest::TERMINA) {
    std::move(sender).Run(std::move(response));
    return;
  }

  for (const auto& message : request.records()) {
    termina_parser_->ParseLogEntryForBtrfs(request.cid(), message.content());
    auto crash_report =
        termina_parser_->ParseLogEntryForOom(request.cid(), message.content());

    if (crash_report) {
      RunCrashReporter(crash_report->flags, crash_report->text);
    }
  }

  std::move(sender).Run(std::move(response));
}

}  // namespace anomaly
