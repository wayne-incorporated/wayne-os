/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef ARC_ADBD_ADBD_H_
#define ARC_ADBD_ADBD_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>

namespace adbd {
// Refer to the man page of vsock for special VM addresses [0-2].
constexpr uint32_t kFirstGuestVmAddr = 3;

// Initial value of cid argument. It means a valid cid of guest VM
// hasn't been provided. It doesn't bear the meaning of any special
// addresses defined in the man page of vsock and Linux header files
// although its value is in their range.
constexpr uint32_t kVmAddrCidInvalid = 0;

// The path of USB function FS where endpoints of ADB interface live.
constexpr char kFunctionFSPath[] = "/dev/usb-ffs/adb";

// Represents a loadable kernel module. This is then converted to a modprobe(8)
// invocation.
struct AdbdConfigurationKernelModule {
  // Name of the kernel module.
  std::string name;

  // Optional parameters to the module.
  std::vector<std::string> parameters;
};

// Represents the configuration for the service.
struct AdbdConfiguration {
  // The USB product ID. Is SoC-specific.
  std::string usb_product_id;

  // Optional list of kernel modules that need to be loaded before setting up
  // the USB gadget.
  std::vector<AdbdConfigurationKernelModule> kernel_modules;
};

// Creates a FIFO at |path|, owned and only writable by the Android shell user.
bool CreatePipe(const base::FilePath& path);

// Returns the USB product ID for the current device, or an empty string if the
// device does not support ADB over USB.
bool GetConfiguration(AdbdConfiguration* config);

// Returns the name of the UDC driver that is available in the system, or an
// empty string if none are available.
std::string GetUDCDriver();

// Sets up the ConfigFS files to be able to use the ADB gadget. The
// |serialnumber| parameter is used to setup how the device appears in "adb
// devices". The |usb_product_id| and |usb_product_name| parameters are used so
// that the USB gadget self-reports as Android running in Chrome OS.
bool SetupConfigFS(const std::string& serialnumber,
                   const std::string& usb_product_id,
                   const std::string& usb_product_name);

// Sets up FunctionFS and returns an open FD to the control endpoint of the
// fully setup ADB gadget. The gadget will be torn down if the FD is closed when
// this program exits.
base::ScopedFD SetupFunctionFS(const std::string& udc_driver_name);

// Sets up all the necessary kernel modules for the device.
bool SetupKernelModules(
    const std::vector<AdbdConfigurationKernelModule>& kernel_modules);

// Bind-mount the bulk-in/bulk-out endpoints into the shared mount for
// container.
bool BindMountUsbBulkEndpoints();

// Starts Arcvm usb adb bridge. This function will create two channels
// to relay ADB data between USB endpoints and a socket to the ARC adb
// proxy service. This function creates threads that are expected to run
// until the whole process exits, so it should not return but waiting
// for the threads to join in the normal cases. The cid (>=3) of VM must
// be provided for vsock connection.
void StartArcVmAdbBridge(uint32_t cid);
}  // namespace adbd

#endif  // ARC_ADBD_ADBD_H_
