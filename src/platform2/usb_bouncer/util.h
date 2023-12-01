// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef USB_BOUNCER_UTIL_H_
#define USB_BOUNCER_UTIL_H_

#include <unistd.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/time/time.h>
#include <brillo/files/safe_fd.h>
#include <google/protobuf/map.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/timestamp.pb.h>
#include <metrics/metrics_library.h>

#include "usb_bouncer/usb_bouncer.pb.h"

namespace usb_bouncer {

using google::protobuf::Timestamp;
using EntryMap = google::protobuf::Map<std::string, RuleEntry>;

constexpr char kUsbBouncerUser[] = "usb_bouncer";
constexpr char kUsbBouncerGroup[] = "usb_bouncer";

constexpr char kDefaultDbName[] = "devices.proto";
constexpr char kUserDbBaseDir[] = "/run/daemon-store/usb_bouncer";
constexpr char kUserDbParentDir[] = "device-db";

constexpr char kDBusPath[] = "/run/dbus/system_bus_socket";

constexpr uid_t kRootUid = 0;

constexpr int kDefaultWaitTimeoutInSeconds = 5;

enum class UMADeviceRecognized {
  kRecognized,
  kUnrecognized,
};

enum class UMAEventTiming {
  kLoggedOut = 0,
  kLoggedIn = 1,
  kLocked = 2,

  // TODO(crbug.com/1218246) Change UMA enum names kUmaDeviceAttachedHistogram.*
  // if new enums are added to avoid data discontinuity.
  kMaxValue = kLocked,
};

enum class UMAPortType {
  kTypeA,
  kTypeC,
};

enum class UMADeviceSpeed {
  kOther = 0,
  k1_5 = 1,          // 1.5 Mbps (USB 1.1)
  k12 = 2,           // 12 Mbps (USB 1.1)
  k480 = 3,          // 480 Mbps (USB 2.0)
  k480Fallback = 4,  // SuperSpeed device operating in 480 Mbps (USB 2.0)
  k5000 = 5,         // 5000 Mbps (USB 3.2 Gen 1)
  k10000 = 6,        // 10000 Mbps (USB 3.2 Gen 2)
  k20000 = 7,        // 20000 Mbps (USB 3.2 Gen 2x2)
  kMaxValue = k20000,
};

struct UsbSessionMetric {
  std::string boot_id;
  int64_t system_time;
  int action;
  int devnum;
  int busnum;
  int depth;
  int vid;
  int pid;
};

// Returns true if the process has CAP_CHOWN.
bool CanChown();

std::string Hash(const std::string& content);
std::string Hash(const google::protobuf::RepeatedPtrField<std::string>& rules);

// Set USB devices to be authorized by default and authorize any devices that
// were left unauthorized. This is performed on unlock when USBGuard is
// disabled. If an error occurs, false is returned.
bool AuthorizeAll(const std::string& devpath = "/sys/devices");

// Invokes usbguard to get a rule corresponding to |devpath|. Note that
// |devpath| isn't actually a valid path until you prepend "/sys". This matches
// the behavior of udev. The return value is a allow-list rule from usbguard
// with the port specific fields removed.
std::string GetRuleFromDevPath(const std::string& devpath);

// Returns false for rules that should not be included in the allow-list at the
// lock screen. The basic idea is to exclude devices whose function cannot be
// performed if they are first plugged in at the lock screen. Some examples
// include printers, scanners, and USB storage devices.
bool IncludeRuleAtLockscreen(const std::string& rule);

// Returns false if rule is not a valid rule.
bool ValidateRule(const std::string& rule);

// Log device attach events to inform future changes in policy.
void UMALogDeviceAttached(MetricsLibrary* metrics,
                          const std::string& rule,
                          UMADeviceRecognized recognized,
                          UMAEventTiming timing);

// Log external device attach events.
void UMALogExternalDeviceAttached(MetricsLibrary* metrics,
                                  const std::string& rule,
                                  UMADeviceRecognized recognized,
                                  UMAEventTiming timing,
                                  UMAPortType port,
                                  UMADeviceSpeed speed);

// Report structured metrics on external device attach events.
void StructuredMetricsExternalDeviceAttached(
    int VendorId,
    std::string VendorName,
    int ProductId,
    std::string ProductName,
    int DeviceClass,
    std::vector<int64_t> InterfaceClass);

// Report structured metric on device attach and removal with topology and
// system boot information. Device topology information only gets recorded
// on device connection. This will only record the metric for devices in the
// USB metrics allowlist.
void StructuredMetricsUsbSessionEvent(UsbSessionMetric session_metric);

// Report structured metric on error uevents from the hub driver.
void StructuredMetricsHubError(int ErrorCode,
                               int VendorId,
                               int ProductId,
                               int DeviceClass,
                               std::string UsbTreePath,
                               int ConnectedDuration);

// Report structured metric on error uevents from the xHCI driver.
void StructuredMetricsXhciError(int ErrorCode, int DeviceClass);

// Returns the path where the user DB should be written if there is a user
// signed in and CrOS is unlocked. Otherwise, returns an empty path. In the
// multi-login case, the primary user's daemon-store is used.
base::FilePath GetUserDBDir();

// Returns true if a guest session is active.
bool IsGuestSession();

// Returns true if the lock screen is being shown. On a D-Bus failure true is
// returned because that is the safer failure state. This may result in some
// devices not being added to a user's allow-list, but that is safer than a
// malicious device being added to the allow-list while at the lock-screen.
bool IsLockscreenShown();

std::string StripLeadingPathSeparators(const std::string& path);

// Returns a set of all the rules present in |entries|. This serves as a
// filtering step prior to generating the rules configuration for
// usbguard-daemon so that there aren't duplicate rules. The rules are
// de-duplicated by string value ignoring any metadata like the time last used.
std::unordered_set<std::string> UniqueRules(const EntryMap& entries);

// Attempts to open the specified statefile at
// |base_path|/|parent|/|state_file_name| with the proper permissions. The
// parent directory and state file will be cleared if the ownership or
// permissions don't match. They will be created if they do not exist. If |lock|
// is true, this call blocks until an exclusive lock can be obtained for |path|.
// All runs of usb_bouncer are expected to be relatively fast (<250ms), so
// blocking should be ok.
brillo::SafeFD OpenStateFile(const base::FilePath& base_path,
                             const std::string& parent_dir,
                             const std::string& state_file_name,
                             bool lock);

// Forks (exiting the parent), calls setsid, and returns the result of a second
// fork.
//
// This is used to avoid blocking udev while waiting on journald to finish
// setting up logging, D-Bus to be ready, or D-Bus calls that can take on the
// order of seconds to complete.
void Daemonize();

void UpdateTimestamp(Timestamp* timestamp);
size_t RemoveEntriesOlderThan(base::TimeDelta cutoff, EntryMap* map);

// Given an USB device path, parse its root device path through USB device sysfs
// topology. If the given device is not part of a tree (no USB hub in between),
// return |dev| as it is.
//
// E.g. .../1-2/1-2.3/1-2.3.4 is attached to the root hub, .../1-2.
base::FilePath GetRootDevice(base::FilePath dev);

// Given a USB interface path, return the path of its parent USB device.
// If GetInterfaceDevice is unable to determine the parent USB device, it will
// return an empty FilePath.
base::FilePath GetInterfaceDevice(base::FilePath intf);

// Given a devpath, determine if the USB device is external or internal based on
// physical location of device (PLD) and removable property.
bool IsExternalDevice(base::FilePath normalized_devpath);

// Determine if the board is ChromeOS Flex to exclude from metrics reporting
// since we do not have control over firmware on ChromeOS Flex and sysfs values
// are unexpected. Return true if the board cannot be determined to avoid
// possibility of metrics pollution.
bool IsFlexBoard();

// Returns port type for a sysfs device (i.e. USB-A, USB-C).
UMAPortType GetPortType(base::FilePath normalized_devpath);

// Returns USB device speed for a sysfs device.
UMADeviceSpeed GetDeviceSpeed(base::FilePath normalized_devpath);

// Returns vendor ID for a sysfs device.
int GetVendorId(base::FilePath normalized_devpath);

// Returns vendor name for a sysfs device.
std::string GetVendorName(base::FilePath normalized_devpath);

// Returns product ID for a sysfs device.
int GetProductId(base::FilePath normalized_devpath);

// Returns product name for a sysfs device.
std::string GetProductName(base::FilePath normalized_devpath);

// Assigns VID and PID from a uevent's product environment variable. This can
// be used by USB bouncer methods that receive the product environment variable
// to read VID/PID on device disconnection.
void GetVidPidFromEnvVar(std::string product, int* vendor_id, int* product_id);

// Returns device class for a sysfs device.
int GetDeviceClass(base::FilePath normalized_devpath);

// Returns interface classes for a sysfs device.
std::vector<int64_t> GetInterfaceClass(base::FilePath normalized_devpath);

// Returns a USB device's location in the USB device tree. Here, the device
// location is a string with the content of the USB device's devpath file
// which includes a period-separated list of numbers with information on hubs
// and ports between the device and host controller (Example: "1.5.3.2").
std::string GetUsbTreePath(base::FilePath normalized_devpath);

// Returns the depth of a device in a USB topology. This is based on the USB
// tree path returned by GetUsbTreePath.
int GetUsbTreeDepth(base::FilePath normalized_devpath);

// Returns the connected duration, in milliseconds, for a sysfs device.
int GetConnectedDuration(base::FilePath normalized_devpath);

// Returns the PCI device class for a sysfs device.
int GetPciDeviceClass(base::FilePath normalized_devpath);

// Returns the busnum for a sysfs device.
int GetBusnum(base::FilePath normalized_devpath);

// Returns the kernel boot_id, which is a unique identifier randomly generated
// each time a system boots.
std::string GetBootId();

// Returns the time since boot in microseconds.
int64_t GetSystemTime();

}  // namespace usb_bouncer

#endif  // USB_BOUNCER_UTIL_H_
