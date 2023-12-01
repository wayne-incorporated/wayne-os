// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/packet_capture_tool.h"

#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <sys/select.h>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/helper_utils.h"
#include "debugd/src/process_with_id.h"
#include "debugd/src/variant_utils.h"

#include "policy/device_policy.h"
#include "policy/libpolicy.h"

namespace {

const char kPacketCaptureToolErrorString[] =
    "org.chromium.debugd.error.PacketCapture";

bool CreateStatusPipe(base::ScopedFD* read_fd, base::ScopedFD* write_fd) {
  int pipe_fd[2];
  int ret = pipe(pipe_fd);
  if (ret != 0) {
    return false;
  }
  read_fd->reset(pipe_fd[0]);
  write_fd->reset(pipe_fd[1]);
  return true;
}

// Reads the status from the given file descriptor with a timeout of 3 seconds.
// Returns true if "1" is successfully read from the pipe, returns false
// otherwise.
bool ReadStatusFromPipe(int read_fd) {
  fd_set set;
  struct timeval timeout;
  int rv;
  // The helper process (capture_packets.cc) will write "1" to the pipe on
  // successful start.
  char buff[1];
  int len = 1;

  FD_ZERO(&set);
  FD_SET(read_fd, &set);

  // The timeout will be three seconds for read.
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;

  rv = select(read_fd + 1, &set, NULL, NULL, &timeout);
  if (rv == -1) {
    PLOG(ERROR) << "packet_capture: failed to read from pipe";
    return false;
  } else if (rv == 0) {
    // The read operation didn't complete on time.
    return false;
  } else {
    // The character we read must be "1".
    return base::ReadFromFD(read_fd, buff, len) && buff[0] == '1';
  }
}

bool ValidateInterfaceName(const std::string& name) {
  for (char c : name) {
    // These are the only plausible interface name characters.
    if (!base::IsAsciiAlpha(c) && !base::IsAsciiDigit(c) && c != '-' &&
        c != '_')
      return false;
  }
  return true;
}

bool AddValidatedStringOption(debugd::ProcessWithId* p,
                              const brillo::VariantDictionary& options,
                              const std::string& dbus_option,
                              const std::string& command_line_option,
                              brillo::ErrorPtr* error) {
  std::string name;
  switch (debugd::GetOption(options, dbus_option, &name, error)) {
    case debugd::ParseResult::NOT_PRESENT:
      return true;
    case debugd::ParseResult::PARSE_ERROR:
      return false;
    case debugd::ParseResult::PARSED:
      break;
  }

  if (!ValidateInterfaceName(name)) {
    DEBUGD_ADD_ERROR_FMT(error, kPacketCaptureToolErrorString,
                         "\"%s\" is not a valid interface name", name.c_str());
    return false;
  }

  p->AddStringOption(command_line_option, name);
  return true;
}

// Returns true when packet capture is allowed in device. Packet capture is
// allowed in all devices (consumer-owned devices, enterprise-enrolled devices
// and OOBE) by default and can be disabled by the
// DeviceDebugPacketCaptureAllowed policy by the administrator for
// enterprise-enrolled devices.
bool IsDevicePacketCaptureAllowed(brillo::ErrorPtr* error) {
  policy::PolicyProvider policy_provider;

  // Return true without trying to check the policy if the device is not
  // enrolled as unenrolled devices won't have policies and packet capture
  // should be available by default. This means packet capture will be
  // allowed in consumer-owned devices and in OOBE state.
  if (!policy_provider.IsEnterpriseEnrolledDevice()) {
    return true;
  }

  policy_provider.Reload();
  // No available policies.
  if (!policy_provider.device_policy_is_loaded()) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "No device policy available on this device, can't check "
                     "for packet capture policy setting.");
    return false;
  }

  const policy::DevicePolicy* policy = &policy_provider.GetDevicePolicy();
  bool packet_capture_allowed = false;
  // Check if packet captures are allowed by policy for the device.
  if (!policy->GetDeviceDebugPacketCaptureAllowed(&packet_capture_allowed)) {
    // This means policy was not set for the device. Return true since the
    // default value of the policy is defined as true in the policy
    // documentation.
    return true;
  }
  return packet_capture_allowed;
}

bool CheckDeviceBasedCaptureMode(const brillo::VariantDictionary& options,
                                 brillo::ErrorPtr* error) {
  std::string device_value;
  // Check if the "device" option exists in options dictionary. It must be
  // present in device based capture mode.
  if (debugd::GetOption(options, "device", &device_value, error) !=
      debugd::ParseResult::PARSED) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Option 'device' is required.");
    return false;
  }
  int freq_value;
  // Check if the "frequency" option exists in options dictionary. It can't be
  // present in device based capture mode.
  if (debugd::GetOption(options, "frequency", &freq_value, error) ==
      debugd::ParseResult::PARSED) {
    DEBUGD_ADD_ERROR(
        error, kPacketCaptureToolErrorString,
        "Option 'frequency' cannot be present in device based capture mode.");
    return false;
  }
  std::string frequency_based_options[] = {"ht_location", "vht_width",
                                           "monitor_connection_on"};
  // If any of the frequency-based options is present in the arguments, it means
  // the capture will be frequency based.
  for (const std::string& option : frequency_based_options) {
    std::string val;
    debugd::ParseResult result =
        debugd::GetOption(options, option, &val, error);
    if (result == debugd::ParseResult::PARSED) {
      DEBUGD_ADD_ERROR_FMT(
          error, kPacketCaptureToolErrorString,
          "Frequency-based option '%s' cannot be present in device based "
          "capture mode.",
          val.c_str());
      return false;
    }
  }
  // If device option is parsed and none of the frequency based option is
  // present, it means the capture is on device based mode.
  return true;
}

}  // namespace

namespace debugd {

// Creates helper process for frequency-based (Layer-2) capture and return the
// process. Returns nullptr if process can't be created.
debugd::ProcessWithId*
PacketCaptureTool::CreateCaptureProcessForFrequencyBasedCapture(
    const brillo::VariantDictionary& options,
    int output_fd,
    int status_fd,
    brillo::ErrorPtr* error) {
  std::string exec_path;
  if (!GetHelperPath("capture_utility.sh", &exec_path)) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Unable to get helper path for frequency-based capture.");
    return nullptr;
  }

  debugd::ProcessWithId* p =
      CreateProcess(false /* sandboxed */, false /* access_root_mount_ns */);
  if (!p) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Failed to create process for device-based capture.");
    return nullptr;
  }
  p->AddArg(exec_path);
  if (!AddValidatedStringOption(p, options, "device", "--device", error))
    return nullptr;  // DEBUGD_ADD_ERROR is already called.
  if (!AddIntOption(p, options, "frequency", "--frequency", error))
    return nullptr;  // DEBUGD_ADD_ERROR is already called.
  if (!AddValidatedStringOption(p, options, "ht_location", "--ht-location",
                                error))
    return nullptr;  // DEBUGD_ADD_ERROR is already called.
  if (!AddValidatedStringOption(p, options, "vht_width", "--vht-width", error))
    return nullptr;  // DEBUGD_ADD_ERROR is already called.
  if (!AddValidatedStringOption(p, options, "monitor_connection_on",
                                "--monitor-connection-on", error))
    return nullptr;  // DEBUGD_ADD_ERROR is already called.
  int max_size = 0;
  debugd::GetOption(options, "max_size", &max_size, error);
  p->AddIntOption("--max-size", max_size);
  // Pass the output fd of the pcap as a command line option to the child
  // process.
  p->AddIntOption("--output-file", output_fd);
  p->AddIntOption("--status-pipe", status_fd);

  return p;
}

// Creates helper process for device-based (Layer-3) capture and return the
// process. Returns nullptr if process can't be created.
debugd::ProcessWithId*
PacketCaptureTool::CreateCaptureProcessForDeviceBasedCapture(
    const brillo::VariantDictionary& options,
    int output_fd,
    int status_fd,
    brillo::ErrorPtr* error) {
  std::string exec_path;
  if (!GetHelperPath("capture_packets", &exec_path)) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Unable to get helper path for device-based capture.");
    return nullptr;
  }

  ProcessWithId* p =
      CreateProcess(false /* sandboxed */, false /* access_root_mount_ns */);
  if (!p) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Failed to create process for device-based capture.");
    return nullptr;
  }
  p->AddArg(exec_path);
  // capture_packets executable takes four arguments as <device> <output_file>
  // <max_size> <status_pipe>
  std::string device;
  // device option must be present and successfully parsed in order to create
  // process.
  if (debugd::GetOption(options, "device", &device, error) !=
      debugd::ParseResult::PARSED) {
    DEBUGD_ADD_ERROR(
        error, kPacketCaptureToolErrorString,
        "Failed to parse required --device option from arguments.");
    return nullptr;
  }
  p->AddArg(device);
  p->AddArg(std::to_string(output_fd));
  int max_size = 0;
  debugd::GetOption(options, "max_size", &max_size, error);
  p->AddArg(std::to_string(max_size));
  p->AddArg(std::to_string(status_fd));

  return p;
}

void PacketCaptureTool::OnPacketCaptureStopped(std::string helper_process) {
  auto process_info_iter = helper_processes_.find(helper_process);
  if (process_info_iter == helper_processes_.end()) {
    // Helper process has already been cleaned up. Don't need to do anything.
    return;
  }
  base::OnceClosure callback =
      std::move(process_info_iter->second.on_stopped_callback);
  helper_processes_.erase(process_info_iter);
  std::move(callback).Run();
}

bool PacketCaptureTool::HasActivePacketCaptureProcess() {
  return !helper_processes_.empty();
}

bool PacketCaptureTool::Start(bool is_dev_mode,
                              const base::ScopedFD& status_fd,
                              const base::ScopedFD& output_fd,
                              const brillo::VariantDictionary& options,
                              std::string* out_id,
                              base::OnceClosure on_stopped_callback,
                              brillo::ErrorPtr* error) {
  if (!IsDevicePacketCaptureAllowed(error)) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Packet capture is not allowed on device. Please check "
                     "your policy settings to enable.");
    return false;
  }

  ProcessWithId* p;
  // The fd in the child that we bind output_fd to. Since all other fd's are
  // cleared automatically, picking a hardcoded value should be safe.
  int child_output_fd = STDERR_FILENO + 1;

  // Create a pipe to check the child process state and send the write end of
  // the pipe to the child process.
  base::ScopedFD write_fd, read_fd;
  if (!CreateStatusPipe(&read_fd, &write_fd)) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Cannot create a pipe");
    return false;
  }
  // Check if the capture will be device-based or frequency-based and create
  // helper process accordingly using different executables.
  // TODO(b/188391723): Merge capture_utility.sh and capture_packets executables
  // into one.
  if (CheckDeviceBasedCaptureMode(options, error)) {
    p = CreateCaptureProcessForDeviceBasedCapture(options, child_output_fd,
                                                  write_fd.get(), error);
  } else if (is_dev_mode) {
    p = CreateCaptureProcessForFrequencyBasedCapture(options, child_output_fd,
                                                     write_fd.get(), error);
  } else {
    DEBUGD_ADD_ERROR(
        error, kPacketCaptureToolErrorString,
        "The requested capture is frequency-based and it's only available in "
        "developer mode. Please switch to developer mode to use this option.");
    return false;
  }
  if (!p) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Failed to create helper process.");
    return false;
  }

  p->BindFd(output_fd.get(), child_output_fd);
  p->BindFd(status_fd.get(), STDOUT_FILENO);
  p->BindFd(status_fd.get(), STDERR_FILENO);
  p->BindFd(write_fd.get(), write_fd.get());

  LOG(INFO) << "packet_capture: running process id: " << p->id();
  p->Start();

  // Read the helper process status from the pipe and check if it was
  // successful.
  if (!ReadStatusFromPipe(read_fd.get())) {
    DEBUGD_ADD_ERROR(error, kPacketCaptureToolErrorString,
                     "Packet capture helper process failed to start.");
    return false;
  }

  // Watch the read end of the pipe. Since we read from the pipe already, the
  // pipe will be readable again when the helper process closes the pipe. It
  // means the packet capture has stopped.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> fd_watcher =
      base::FileDescriptorWatcher::WatchReadable(
          read_fd.get(),
          base::BindRepeating(&PacketCaptureTool::OnPacketCaptureStopped,
                              base::Unretained(this), p->id()));

  helper_processes_.insert(std::make_pair(
      p->id(), ChildProcessInfo(std::move(read_fd), std::move(fd_watcher),
                                std::move(on_stopped_callback))));
  *out_id = p->id();
  return true;
}

}  // namespace debugd
