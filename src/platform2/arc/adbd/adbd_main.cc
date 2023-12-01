/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <fcntl.h>

#include <base/at_exit.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/system/sys_info.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "arc/adbd/adbd.h"

namespace {

constexpr char kRuntimePath[] = "/run/arc/adbd";

}  // namespace

int main(int argc, char** argv) {
  DEFINE_string(serialnumber, "", "Serial number of the Android container");
  DEFINE_bool(arcvm, true, "setup adb over usb for arcvm");
  DEFINE_uint32(arcvm_cid, adbd::kVmAddrCidInvalid,
                "specify cid (>=3) of ARCVM for vsock connection");

  base::AtExitManager at_exit;

  brillo::FlagHelper::Init(argc, argv, "ADB over USB proxy.");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (FLAGS_arcvm) {
    // The two options, arcvm and arcvm_cid, must work together and there is no
    // point to have cid without VM (ignored). It is attempting to have cid arg
    // only to tell arcvm from ARC++ since only VM have cid and vsock is the
    // only way to talk with a VM. However, we still keep arcvm for the sake of
    // clarity in code and usage, instead of relying on any unacceptable value
    // of cid, either provided by user or from an initial value, to obscurely
    // branch to the container-based route which differs in many ways.
    if (FLAGS_arcvm_cid < adbd::kFirstGuestVmAddr) {
      LOG(ERROR) << "Invalid or no cid provided when VM(vsock) is selected.";
      return 1;
    }
  }

  const base::FilePath runtime_path(kRuntimePath);

  adbd::AdbdConfiguration config;
  if (!adbd::GetConfiguration(&config)) {
    LOG(INFO) << "Unable to find the configuration for this service. "
              << "This device does not support ADB over USB.";
    return 0;
  }

  const std::string board = base::SysInfo::HardwareModelName();

  const base::FilePath control_pipe_path = runtime_path.Append("ep0");
  if (!FLAGS_arcvm && !adbd::CreatePipe(control_pipe_path))
    return 1;

  char buffer[4096];

  bool configured = false;
  base::ScopedFD control_file;
  base::ScopedFD control_pipe;
  while (true) {
    if (!FLAGS_arcvm) {
      LOG(INFO) << "arc-adbd ready to receive connections";
      // O_RDONLY on a FIFO waits until another endpoint has opened the file
      // with O_WRONLY or O_RDWR.
      control_pipe = base::ScopedFD(
          HANDLE_EINTR(open(control_pipe_path.value().c_str(), O_RDONLY)));
      if (!control_pipe.is_valid()) {
        PLOG(ERROR) << "Failed to open FIFO at " << control_pipe_path.value();
        return 1;
      }
      LOG(INFO) << "arc-adbd connected";

      // Given that a FIFO can be opened by multiple processes, once a process
      // has opened it, we atomically replace it with a new FIFO (by using
      // rename(2)) so no other process can open it. This causes that when that
      // process close(2)s the FD, we will get an EOF when we attempt to read(2)
      // from it. This also causes any other process that attempts to open the
      // new FIFO to block until we are done processing the current one.
      //
      // There is a very small chance there is a race here if multiple processes
      // get to open the FIFO between the point in time where this process opens
      // the FIFO and CreatePipe() returns. That seems unavoidable, but should
      // not present too much of a problem since exactly one process in Android
      // has the correct user to open this file in the first place (adbd).
      if (!adbd::CreatePipe(control_pipe_path))
        return 1;
    }
    // Once adbd has opened the control pipe, we set up the adb gadget on behalf
    // of that process, if we have not already.
    if (!configured) {
      if (!adbd::SetupKernelModules(config.kernel_modules)) {
        LOG(ERROR) << "Failed to load kernel modules";
        return 1;
      }
      const std::string udc_driver_name = adbd::GetUDCDriver();
      if (udc_driver_name.empty()) {
        LOG(ERROR)
            << "Unable to find any registered UDC drivers in /sys/class/udc/. "
            << "This device does not support ADB using GadgetFS.";
        return 1;
      }
      if (!adbd::SetupConfigFS(FLAGS_serialnumber, config.usb_product_id,
                               board)) {
        LOG(ERROR) << "Failed to configure ConfigFS";
        return 1;
      }
      control_file = adbd::SetupFunctionFS(udc_driver_name);
      if (!control_file.is_valid()) {
        LOG(ERROR) << "Failed to configure FunctionFS";
        return 1;
      }
      if (!FLAGS_arcvm && !adbd::BindMountUsbBulkEndpoints()) {
        LOG(ERROR) << "Failed to bind mount FunctionFS";
        return 1;
      }
      configured = true;
    }
    if (FLAGS_arcvm) {
      adbd::StartArcVmAdbBridge(FLAGS_arcvm_cid);
      // TODO(crbug.com/1087440): Once we change the design of bridge to return
      // instead of terminating the process in error cases, we would
      // need to replace the LOG(FATAL) with something else since we
      // don't always want to trigger a crash dump.
      LOG(FATAL) << "Should not reach here";
    }
    // Drain the FIFO and wait until the other side closes it.
    // The data that is sent is kControlPayloadV2 (or kControlPayloadV1)
    // followed by kControlStrings. We ignore it completely since we have
    // already sent it to the underlying FunctionFS file, and also to avoid
    // parsing it to decrease the attack surface area.
    while (true) {
      ssize_t bytes_read =
          HANDLE_EINTR(read(control_pipe.get(), buffer, sizeof(buffer)));
      if (bytes_read < 0)
        PLOG(ERROR) << "Failed to read from FIFO";
      if (bytes_read <= 0)
        break;
    }
  }
}
