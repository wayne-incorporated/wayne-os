// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/crash_listener_impl.h"

#include <fcntl.h>
#include <unistd.h>

#include <optional>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_util.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/key_value_store.h>
#include <brillo/process/process.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include "vm_tools/cicerone/service.h"
#include "vm_tools/cicerone/virtual_machine.h"

namespace {

// These values are logged to UMA. Entries should not be renumbered and numeric
// values should never be reused. Please keep in sync with
// GuestOsFailureClasses in src/tools/metrics/histograms/enums.xml and the copy
// in src/chrome/browser/ash/guest_os/guest_os_stability_monitor.h
enum class FailureClasses {
  ConciergeStopped = 0,
  CiceroneStopped = 1,
  SeneschalStopped = 2,
  ChunneldStopped = 3,
  VmStopped = 4,
  VmSyslogStopped = 5,
  VshdStopped = 6,
  LxcFsStopped = 7,
  TremplinStopped = 8,
  NdproxydStopped = 9,
  McastdStopped = 10,
  LxdStopped = 11,
  GarconStopped = 12,
  SommelierStopped = 13,
  SommelierXStopped = 14,
  CrosSftpStopped = 15,
  CrosNotificationdStopped = 16,
  kMaxValue = CrosNotificationdStopped,
};

// In testing, crash_reporter uses a mock consent system to avoid flake in the
// real metrics consent. The in-VM crash_reporter can't check this itself for
// the same reason it can't check the actual metrics consent state, so we need
// to take this into account in our RPC. This is controlled by the existence of
// a file at a known location, and should only be checked on test images.
bool CheckForMockCrashReporterConsent() {
  brillo::KeyValueStore store;
  std::string channel;
  if (!store.Load(base::FilePath("/etc/lsb-release"))) {
    // Return false here to ensure the expectations are updated if
    // /etc/lsb-release changes
    LOG(WARNING) << "Failed to parse /etc/lsb-release, assuming non-test image";
    return false;
  }

  if (!store.GetString("CHROMEOS_RELEASE_TRACK", &channel)) {
    LOG(WARNING) << "Couldn't find release track an /etc/lsb-release, assuming "
                    "non-test image";
    return false;
  }

  if (!base::StartsWith(channel, "test", base::CompareCase::SENSITIVE)) {
    // Not a test image, mock consent should be disregarded.
    return false;
  }

  return base::PathExists(base::FilePath("/run/crash_reporter/mock-consent"));
}

}  // namespace

namespace vm_tools {
namespace cicerone {

CrashListenerImpl::CrashListenerImpl(
    base::WeakPtr<vm_tools::cicerone::Service> service)
    : service_(service),
      task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()) {}

grpc::Status CrashListenerImpl::CheckMetricsConsent(
    grpc::ServerContext* ctx,
    const EmptyMessage* request,
    MetricsConsentResponse* response) {
  response->set_consent_granted(metrics_.AreMetricsEnabled() ||
                                CheckForMockCrashReporterConsent());
  return grpc::Status::OK;
}

grpc::Status CrashListenerImpl::SendCrashReport(grpc::ServerContext* ctx,
                                                const CrashReport* crash_report,
                                                EmptyMessage* response) {
  // Set O_CLOEXEC on the pipe so that the write end doesn't get kept open by
  // the child process after we're done with it.
  int pipefd[2];
  if (HANDLE_EINTR(pipe2(pipefd, O_CLOEXEC)) != 0) {
    return {grpc::UNKNOWN, "Failed to create pipe"};
  }

  base::ScopedFD read(pipefd[0]);
  base::ScopedFD write(pipefd[1]);

  // Turn off CLOEXEC for the read end, as that needs to be sent to the child
  // process
  if (HANDLE_EINTR(fcntl(read.get(), F_SETFD, 0)) != 0) {
    return {grpc::UNKNOWN, "Failed to unset CLOEXEC on read end of pipe"};
  }

  brillo::ProcessImpl crash_reporter;
  crash_reporter.AddArg("/sbin/crash_reporter");
  crash_reporter.AddArg("--vm_crash");
  if (auto pid = GetPidFromPeerAddress(ctx)) {
    crash_reporter.AddArg(base::StringPrintf("--vm_pid=%d", *pid));
  }
  crash_reporter.BindFd(read.get(), 0 /* stdin */);
  crash_reporter.SetCloseUnusedFileDescriptors(true);

  if (!crash_reporter.Start())
    return {grpc::UNKNOWN, "Failed to start crash_reporter"};

  // Close the read end of the pipe after passing it to the child process.
  read.reset();

  google::protobuf::io::FileOutputStream output(write.get());

  // Some VMs may not have the correct channel/milestone info populated
  // correctly since it is not correct in the VM's /etc/lsb-release.
  // Modify it here before it gets sent.
  CrashReport modified_cr = ModifyCrashReport(crash_report);
  if (!google::protobuf::TextFormat::Print(modified_cr, &output)) {
    return {grpc::INVALID_ARGUMENT, "Failed to print CrashReport protobuf"};
  }
  if (!output.Flush()) {
    return {grpc::UNKNOWN, "Failed to send report to crash_reporter"};
  }
  // Close the write end of the pipe after we finish writing to it
  // so the child process knows we've finished.
  write.reset();

  int exit_status = crash_reporter.Wait();
  if (exit_status == 0)
    return grpc::Status::OK;
  else
    return {grpc::UNKNOWN, "Crash_reporter encountered an error"};
}

CrashReport CrashListenerImpl::ModifyCrashReport(
    const CrashReport* crash_report) {
  CrashReport modified_cr = *crash_report;
  std::string channel = GetLsbReleaseValue("CHROMEOS_RELEASE_TRACK");
  channel = channel.substr(0, channel.find("-"));
  if (channel == "testimage") {
    channel = "test";
  }
  (*modified_cr.mutable_metadata())["upload_var_channel"] = channel;
  (*modified_cr.mutable_metadata())["upload_var_cros_milestone"] =
      GetLsbReleaseValue("CHROMEOS_RELEASE_CHROME_MILESTONE");
  (*modified_cr.mutable_metadata())["upload_var_lsb-release"] =
      GetLsbReleaseValue("CHROMEOS_RELEASE_DESCRIPTION");
  return modified_cr;
}

std::string CrashListenerImpl::GetLsbReleaseValue(std::string key) {
  std::string output;
  if (!base::SysInfo::GetLsbReleaseValue(key, &output)) {
    LOG(ERROR) << "Failed to obtain lsb value for " << key;
    output = "unknown";
  }
  return output;
}

std::optional<pid_t> CrashListenerImpl::GetPidFromPeerAddress(
    grpc::ServerContext* ctx) {
  VirtualMachine* vm = GetVirtualMachineForContext(ctx);
  return vm ? std::optional<pid_t>(vm->pid()) : std::nullopt;
}

VirtualMachine* CrashListenerImpl::GetVirtualMachineForContext(
    grpc::ServerContext* ctx) {
  uint32_t cid = 0;
  std::string peer_address = ctx->peer();
  if (sscanf(peer_address.c_str(), "vsock:%u", &cid) != 1) {
    LOG(WARNING) << "Failed to parse peer address " << peer_address;
    return nullptr;
  }

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  VirtualMachine* vm = nullptr;
  std::string owner_id;
  std::string vm_name;
  bool result;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&CrashListenerImpl::GetVirtualMachineForCidOrToken,
                     base::Unretained(this), cid, &vm, &owner_id, &vm_name,
                     &result, &event));

  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failed to get VM for peer address " << peer_address;
    return nullptr;
  }

  return vm;
}

void CrashListenerImpl::GetVirtualMachineForCidOrToken(
    const uint32_t cid,
    VirtualMachine** vm_out,
    std::string* owner_id_out,
    std::string* name_out,
    bool* ret_value,
    base::WaitableEvent* event) {
  *ret_value = service_->GetVirtualMachineForCidOrToken(cid, "", vm_out,
                                                        owner_id_out, name_out);
  event->Signal();
}

grpc::Status CrashListenerImpl::SendFailureReport(
    grpc::ServerContext* ctx,
    const FailureReport* failure_report,
    EmptyMessage* response) {
  VirtualMachine* vm = GetVirtualMachineForContext(ctx);
  const std::string histogram =
      vm && vm->GetType() == VirtualMachine::VmType::BOREALIS
          ? "Borealis.Stability"
          : "Crostini.Stability";
  const std::string service = failure_report->failed_process();
  FailureClasses sample;

  if (!ShouldRecordFailures(ctx)) {
    // VM couldn't be found, or is shutting down. This isn't an error, but it
    // means we shouldn't record this service stopping because it's not a
    // failure.
    return grpc::Status::OK;
  }
  // Report is from a running VM, so no services should be stopping.

  if (service == "vm_syslog") {
    sample = FailureClasses::VmSyslogStopped;
  } else if (service == "vshd") {
    sample = FailureClasses::VshdStopped;
  } else if (service == "lxcfs") {
    sample = FailureClasses::LxcFsStopped;
  } else if (service == "tremplin") {
    sample = FailureClasses::TremplinStopped;
  } else if (service == "ndproxyd") {
    sample = FailureClasses::NdproxydStopped;
  } else if (service == "mcastd") {
    sample = FailureClasses::McastdStopped;
  } else if (service == "lxd") {
    sample = FailureClasses::LxdStopped;
  } else if (service == "cros-garcon") {
    sample = FailureClasses::GarconStopped;
  } else if (service == "sommelier") {
    sample = FailureClasses::SommelierStopped;
  } else if (service == "sommelier-x") {
    sample = FailureClasses::SommelierXStopped;
  } else if (service == "cros-sftp") {
    sample = FailureClasses::CrosSftpStopped;
  } else if (service == "cros-notificationd") {
    sample = FailureClasses::CrosNotificationdStopped;
  } else {
    return {grpc::INVALID_ARGUMENT, "Unknown service, ignoring"};
  }

  if (metrics_.SendEnumToUMA(histogram, sample)) {
    return grpc::Status::OK;
  } else {
    return {grpc::UNKNOWN, "Failed to record event in stability histogram"};
  }
}

bool CrashListenerImpl::ShouldRecordFailures(grpc::ServerContext* ctx) {
  uint32_t cid = 0;
  std::string peer_address = ctx->peer();
  if (sscanf(peer_address.c_str(), "vsock:%u", &cid) != 1) {
    LOG(WARNING) << "Failed to parse peer address " << peer_address;
    return false;
  }

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool is_stopping_or_stopped;
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CrashListenerImpl::GetVmStoppingOnDBusThread,
                                base::Unretained(this), cid,
                                &is_stopping_or_stopped, &event));

  event.Wait();

  return !is_stopping_or_stopped;
}

void CrashListenerImpl::GetVmStoppingOnDBusThread(const uint32_t cid,
                                                  bool* is_stopping_or_stopped,
                                                  base::WaitableEvent* event) {
  VirtualMachine* vm = nullptr;
  std::string owner_id, name;
  bool ret =
      service_->GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &name);
  if (ret) {
    *is_stopping_or_stopped = vm->is_stopping();
  } else {
    // VM couldn't be found, so it must have stopped.
    *is_stopping_or_stopped = true;
  }
  event->Signal();
}

}  // namespace cicerone
}  // namespace vm_tools
