// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "usb_bouncer/util.h"
#include "usb_bouncer/util_internal.h"

#include <fcntl.h>
#include <sys/capability.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/scoped_generic.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <brillo/file_utils.h>
#include <brillo/files/file_util.h>
#include <brillo/files/scoped_dir.h>
#include <brillo/key_value_store.h>
#include <brillo/userdb_utils.h>
#include <metrics/structured_events.h>
#include <openssl/sha.h>
#include <re2/re2.h>
#include <session_manager/dbus-proxies.h>
#include <usbguard/Device.hpp>
#include <usbguard/DeviceManager.hpp>
#include <usbguard/DeviceManagerHooks.hpp>

#include "usb_bouncer/metrics_allowlist.h"

using brillo::GetFDPath;
using brillo::SafeFD;
using brillo::ScopedDIR;
using brillo::cryptohome::home::GetHashedUserPath;
using org::chromium::SessionManagerInterfaceProxy;

namespace usb_bouncer {

namespace {

constexpr int kDbPermissions = S_IRUSR | S_IWUSR;
constexpr int kDbDirPermissions = S_IRUSR | S_IWUSR | S_IXUSR;

constexpr char kSysFSAuthorizedDefault[] = "authorized_default";
constexpr char kSysFSAuthorized[] = "authorized";
constexpr char kSysFSEnabled[] = "1";

constexpr char kUmaDeviceAttachedHistogram[] = "ChromeOS.USB.DeviceAttached";
constexpr char kUmaExternalDeviceAttachedHistogram[] =
    "ChromeOS.USB.ExternalDeviceAttached";

constexpr int kMaxWriteAttempts = 10;
constexpr int kAttemptDelayMicroseconds = 10000;

enum class Subsystem {
  kNone,
  kUsb,
};

// Returns base64 encoded strings since proto strings must be valid UTF-8.
std::string EncodeDigest(const std::vector<uint8_t>& digest) {
  std::string result;
  base::StringPiece digest_view(reinterpret_cast<const char*>(digest.data()),
                                digest.size());
  base::Base64Encode(digest_view, &result);
  return result;
}

std::unique_ptr<SessionManagerInterfaceProxy> SetUpDBus(
    scoped_refptr<dbus::Bus> bus) {
  if (!bus) {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;

    bus = new dbus::Bus(options);
    CHECK(bus->Connect());
  }
  return std::make_unique<SessionManagerInterfaceProxy>(bus);
}

class UsbguardDeviceManagerHooksImpl : public usbguard::DeviceManagerHooks {
 public:
  void dmHookDeviceEvent(usbguard::DeviceManager::EventType event,
                         std::shared_ptr<usbguard::Device> device) override {
    lastRule_ = *device->getDeviceRule(false /*include_port*/,
                                       false /*with_parent_hash*/);

    // If usbguard-daemon is running when a device is connected, it might have
    // blocked the particular device in which case this will be a block rule.
    // For the purpose of allow-listing, this needs to be an Allow rule.
    lastRule_.setTarget(usbguard::Rule::Target::Allow);
  }

  uint32_t dmHookAssignID() override {
    static uint32_t id = 0;
    return id++;
  }

  void dmHookDeviceException(const std::string& message) override {
    LOG(ERROR) << message;
  }

  std::string getLastRule() {
    if (!lastRule_) {
      return "";
    }
    return lastRule_.toString();
  }

 private:
  usbguard::Rule lastRule_;
};

// |fd| is assumed to be non-blocking.
bool WriteWithTimeout(
    SafeFD* fd,
    const std::string value,
    size_t max_tries = kMaxWriteAttempts,
    base::TimeDelta delay = base::Microseconds(kAttemptDelayMicroseconds)) {
  size_t tries = 0;
  size_t total = 0;
  int written = 0;
  while (tries < max_tries) {
    ++tries;

    written = write(fd->get(), value.c_str() + total, value.size() - total);
    if (written < 0) {
      if (errno == EAGAIN) {
        // Writing would block. Wait and try again.
        HANDLE_EINTR(usleep(delay.InMicroseconds()));
        continue;
      } else if (errno == EINTR) {
        // Count EINTR against the tries.
        continue;
      } else {
        PLOG(ERROR) << "Failed to write '" << GetFDPath(fd->get()).value()
                    << "'";
        return false;
      }
    }

    total += written;
    if (total == value.size()) {
      if (HANDLE_EINTR(ftruncate(fd->get(), value.size())) != 0) {
        PLOG(ERROR) << "Failed to truncate '" << GetFDPath(fd->get()).value()
                    << "'";
        return false;
      }
      return true;
    }
  }
  return false;
}

bool WriteWithTimeoutIfExists(SafeFD* dir,
                              const base::FilePath name,
                              const std::string& value) {
  SafeFD::Error err;
  SafeFD file;
  std::tie(file, err) =
      dir->OpenExistingFile(name, O_CLOEXEC | O_RDWR | O_NONBLOCK);
  if (err == SafeFD::Error::kDoesNotExist) {
    return true;
  } else if (SafeFD::IsError(err)) {
    LOG(ERROR) << "Failed to open authorized_default for '"
               << GetFDPath(dir->get()).value() << "'";
    return false;
  }

  return WriteWithTimeout(&file, value);
}

// This opens a subdirectory represented by a directory entry if it points to a
// subdirectory.
SafeFD::SafeFDResult OpenIfSubdirectory(SafeFD* parent,
                                        const struct stat& parent_info,
                                        const dirent& entry) {
  if (strcmp(entry.d_name, ".") == 0 || strcmp(entry.d_name, "..") == 0) {
    return std::make_pair(SafeFD(), SafeFD::Error::kNoError);
  }

  if (entry.d_type != DT_DIR) {
    return std::make_pair(SafeFD(), SafeFD::Error::kNoError);
  }

  struct stat child_info;
  if (fstatat(parent->get(), entry.d_name, &child_info,
              AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) != 0) {
    PLOG(ERROR) << "fstatat failed for '" << GetFDPath(parent->get()).value()
                << "/" << entry.d_name << "'";
    return std::make_pair(SafeFD(), SafeFD::Error::kIOError);
  }

  if (child_info.st_dev != parent_info.st_dev) {
    // Do not cross file system boundary.
    return std::make_pair(SafeFD(), SafeFD::Error::kBoundaryDetected);
  }

  SafeFD::SafeFDResult subdir =
      parent->OpenExistingDir(base::FilePath(entry.d_name));
  if (SafeFD::IsError(subdir.second)) {
    LOG(ERROR) << "Failed to open '" << GetFDPath(parent->get()).value() << "/"
               << entry.d_name << "'";
  }

  return subdir;
}

// dir is the path being walked.
// sub is used to exclude authorized attributes for devices that shouldn't be
//   touched.
// max_depth is used to limit the recursion.
bool AuthorizeAllImpl(SafeFD* dir,
                      Subsystem subsystem = Subsystem::kNone,
                      size_t max_depth = SafeFD::kDefaultMaxPathDepth) {
  if (max_depth == 0) {
    LOG(ERROR) << "AuthorizeAll read max depth at '"
               << GetFDPath(dir->get()).value() << "'";
    return false;
  }

  bool success = true;
  if (subsystem == Subsystem::kUsb) {
    if (!WriteWithTimeoutIfExists(dir, base::FilePath(kSysFSAuthorizedDefault),
                                  kSysFSEnabled)) {
      success = false;
    }

    if (!WriteWithTimeoutIfExists(dir, base::FilePath(kSysFSAuthorized),
                                  kSysFSEnabled)) {
      // EPIPE: wireless USB device that fails in usb_get_device_descriptor().
      // ENODEV: device that disappears before they can be authorized or fails
      //   during usb_autoresume_device()
      // EPROTO: usb_set_configuration() failed, but the device is still
      //   authorized. This is often caused by the device not having adequate
      //   power.
      if (errno == EPIPE || errno == ENODEV || errno == EPROTO) {
        PLOG(WARNING) << "Failed to authorize USB device: '"
                      << GetFDPath(dir->get()).value() << "'";
      } else {
        success = false;
      }
    }
  }

  // The ScopedDIR takes ownership of this so dup_fd is not scoped on its own.
  int dup_fd = dup(dir->get());
  if (dup_fd < 0) {
    PLOG(ERROR) << "dup failed for '" << GetFDPath(dir->get()).value() << "'";
    return false;
  }

  ScopedDIR listing(fdopendir(dup_fd));
  if (!listing.is_valid()) {
    PLOG(ERROR) << "fdopendir failed for '" << GetFDPath(dir->get()).value()
                << "'";
    IGNORE_EINTR(close(dup_fd));
    return false;
  }

  struct stat dir_info;
  if (fstat(dir->get(), &dir_info) != 0) {
    // If the directory no longer exists, skip it.
    if (errno == ENOENT) {
      return success;
    }
    return false;
  }

  for (;;) {
    errno = 0;
    const dirent* entry = HANDLE_EINTR_IF_EQ(readdir(listing.get()), nullptr);
    if (entry == nullptr) {
      break;
    }

    SafeFD::SafeFDResult subdir = OpenIfSubdirectory(dir, dir_info, *entry);
    if (SafeFD::IsError(subdir.second)) {
      success = false;
    }

    Subsystem child_subsystem = subsystem;
    if (base::StartsWith(entry->d_name, "usb", base::CompareCase::SENSITIVE)) {
      child_subsystem = Subsystem::kUsb;
    }

    if (subdir.first.is_valid()) {
      if (!AuthorizeAllImpl(&subdir.first, child_subsystem, max_depth - 1)) {
        success = false;
      }
    }
  }
  if (errno != 0) {
    PLOG(ERROR) << "readdir failed for '" << GetFDPath(dir->get()).value()
                << "'";
    return false;
  }

  // Check sub directories
  return success;
}

UMADeviceClass GetClassEnumFromValue(
    const usbguard::USBInterfaceType& interface) {
  const struct {
    uint8_t raw;
    UMADeviceClass typed;
  } mapping[] = {
      // clang-format off
      {0x01, UMADeviceClass::kAudio},
      {0x03, UMADeviceClass::kHID},
      {0x02, UMADeviceClass::kComm},
      {0x05, UMADeviceClass::kPhys},
      {0x06, UMADeviceClass::kImage},
      {0x07, UMADeviceClass::kPrint},
      {0x08, UMADeviceClass::kStorage},
      {0x09, UMADeviceClass::kHub},
      {0x0A, UMADeviceClass::kComm},
      {0x0B, UMADeviceClass::kCard},
      {0x0D, UMADeviceClass::kSec},
      {0x0E, UMADeviceClass::kVideo},
      {0x0F, UMADeviceClass::kHealth},
      {0x10, UMADeviceClass::kAV},
      {0xE0, UMADeviceClass::kWireless},
      {0xEF, UMADeviceClass::kMisc},
      {0xFE, UMADeviceClass::kApp},
      {0xFF, UMADeviceClass::kVendor},
      // clang-format on
  };
  for (const auto& m : mapping) {
    if (usbguard::USBInterfaceType(m.raw, 0, 0,
                                   usbguard::USBInterfaceType::MatchClass)
            .appliesTo(interface)) {
      return m.typed;
    }
  }
  return UMADeviceClass::kOther;
}

UMADeviceClass MergeClasses(UMADeviceClass a, UMADeviceClass b) {
  if (a == b) {
    return a;
  }

  if ((a == UMADeviceClass::kAV || a == UMADeviceClass::kAudio ||
       a == UMADeviceClass::kVideo) &&
      (b == UMADeviceClass::kAV || b == UMADeviceClass::kAudio ||
       b == UMADeviceClass::kVideo)) {
    return UMADeviceClass::kAV;
  }

  return UMADeviceClass::kOther;
}

struct ScopedCapTTraits {
  static cap_t InvalidValue() { return nullptr; }
  static void Free(cap_t cap_ptr) { cap_free(cap_ptr); }
};
typedef base::ScopedGeneric<cap_t, ScopedCapTTraits> ScopedCapT;

}  // namespace

bool CanChown() {
  ScopedCapT caps(cap_get_pid(0));
  if (!caps.is_valid()) {
    return false;
  }

  cap_flag_value_t value;
  if (cap_get_flag(caps.get(), CAP_CHOWN, CAP_EFFECTIVE, &value) == -1) {
    return false;
  }

  return value == CAP_SET;
}

std::string Hash(const std::string& content) {
  std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH, 0);

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, content.data(), content.size());
  SHA256_Final(digest.data(), &ctx);
  return EncodeDigest(digest);
}

std::string Hash(const google::protobuf::RepeatedPtrField<std::string>& rules) {
  std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH, 0);

  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  // This extra logic is needed for consistency with
  // Hash(const std::string& content)
  bool first = true;
  for (const auto& rule : rules) {
    SHA256_Update(&ctx, rule.data(), rule.size());
    if (!first) {
      // Add a end of line to delimit rules for the mode switching case when
      // more than one allow-listing rule is needed for a single device.
      SHA256_Update(&ctx, "\n", 1);
    } else {
      first = false;
    }
  }

  SHA256_Final(digest.data(), &ctx);
  return EncodeDigest(digest);
}

bool AuthorizeAll(const std::string& devpath) {
  if (devpath.front() != '/') {
    return false;
  }

  SafeFD::Error err;
  SafeFD dir;
  std::tie(dir, err) =
      SafeFD::Root().first.OpenExistingDir(base::FilePath(devpath.substr(1)));
  if (SafeFD::IsError(err)) {
    LOG(ERROR) << "Failed to open '" << GetFDPath(dir.get()).value() << "'.";
    return false;
  }

  return AuthorizeAllImpl(&dir);
}

std::string GetRuleFromDevPath(const std::string& devpath) {
  UsbguardDeviceManagerHooksImpl hooks;
  auto device_manager = usbguard::DeviceManager::create(hooks, "uevent");
  device_manager->setEnumerationOnlyMode(true);
  device_manager->scan(devpath);
  return hooks.getLastRule();
}

bool IncludeRuleAtLockscreen(const std::string& rule) {
  const usbguard::Rule filter_rule = usbguard::Rule::fromString(
      "block with-interface one-of { 05:*:* 06:*:* 07:*:* 08:*:* }");
  usbguard::Rule parsed_rule = GetRuleFromString(rule);
  if (!parsed_rule) {
    return false;
  }

  return !filter_rule.appliesTo(parsed_rule);
}

bool ValidateRule(const std::string& rule) {
  if (rule.empty()) {
    return false;
  }
  return usbguard::Rule::fromString(rule);
}

void UMALogDeviceAttached(MetricsLibrary* metrics,
                          const std::string& rule,
                          UMADeviceRecognized recognized,
                          UMAEventTiming timing) {
  usbguard::Rule parsed_rule = GetRuleFromString(rule);
  if (!parsed_rule) {
    return;
  }

  // TODO(crbug.com/1218246) Change UMA enum names kUmaDeviceAttachedHistogram.*
  // if new enums for UMAEventTiming are added to avoid data discontinuity, then
  // use kMaxValue+1 rather than kMaxValue (or templated SendEnumToUMA()).
  metrics->SendEnumToUMA(
      base::StringPrintf("%s.%s.%s", kUmaDeviceAttachedHistogram,
                         to_string(recognized).c_str(),
                         to_string(GetClassFromRule(parsed_rule)).c_str()),
      static_cast<int>(timing), static_cast<int>(UMAEventTiming::kMaxValue));
}

void UMALogExternalDeviceAttached(MetricsLibrary* metrics,
                                  const std::string& rule,
                                  UMADeviceRecognized recognized,
                                  UMAEventTiming timing,
                                  UMAPortType port,
                                  UMADeviceSpeed speed) {
  usbguard::Rule parsed_rule = GetRuleFromString(rule);
  if (!parsed_rule) {
    return;
  }

  metrics->SendEnumToUMA(
      base::StringPrintf("%s.%s.%s", kUmaExternalDeviceAttachedHistogram,
                         to_string(recognized).c_str(),
                         to_string(GetClassFromRule(parsed_rule)).c_str()),
      static_cast<int>(timing), static_cast<int>(UMAEventTiming::kMaxValue));

  // Another metrics on device class categorized by port type.
  // Report this separately since port type is not related to
  // Recongnized/Unrecognized and Event Timing.
  metrics->SendEnumToUMA(base::StringPrintf("%s.%s.DeviceClass",
                                            kUmaExternalDeviceAttachedHistogram,
                                            to_string(port).c_str()),
                         static_cast<int>(GetClassFromRule(parsed_rule)),
                         static_cast<int>(UMADeviceClass::kMaxValue));

  metrics->SendEnumToUMA(base::StringPrintf("%s.%s.DeviceSpeed",
                                            kUmaExternalDeviceAttachedHistogram,
                                            to_string(port).c_str()),
                         static_cast<int>(speed),
                         static_cast<int>(UMADeviceSpeed::kMaxValue));
}

void StructuredMetricsExternalDeviceAttached(
    int VendorId,
    std::string VendorName,
    int ProductId,
    std::string ProductName,
    int DeviceClass,
    std::vector<int64_t> InterfaceClass) {
  // Limit string length to prevent badly behaving device from creating huge
  // metrics packet.
  int string_len_limit = 200;
  VendorName = VendorName.substr(0, string_len_limit);
  ProductName = ProductName.substr(0, string_len_limit);

  // In case the size of InterfaceClass exceed the max number of interfaces
  // supported by the UsbDeviceInfo metrics, just slice the vector and report.
  // The max length supported is large enough that this is quite unlikely.
  int max_interface = metrics::structured::events::usb_device::UsbDeviceInfo::
      GetInterfaceClassMaxLength();
  if (InterfaceClass.size() > max_interface) {
    InterfaceClass.resize(max_interface);
  }

  metrics::structured::events::usb_device::UsbDeviceInfo()
      .SetVendorId(VendorId)
      .SetVendorName(VendorName)
      .SetProductId(ProductId)
      .SetProductName(ProductName)
      .SetDeviceClass(DeviceClass)
      .SetInterfaceClass(std::move(InterfaceClass))
      .Record();
}

void StructuredMetricsUsbSessionEvent(UsbSessionMetric session_metric) {
  // Only record UsbSessionEvents for devices in the USB metrics allowlist.
  if (!DeviceInMetricsAllowlist(session_metric.vid, session_metric.pid))
    return;

  metrics::structured::events::usb_session::UsbSessionEvent()
      .SetBootId(std::move(session_metric.boot_id))
      .SetSystemTime(std::move(session_metric.system_time))
      .SetAction(session_metric.action)
      .SetDeviceNum(session_metric.devnum)
      .SetBusNum(session_metric.busnum)
      .SetDepth(session_metric.depth)
      .SetVendorId(session_metric.vid)
      .SetProductId(session_metric.pid)
      .Record();
}

void StructuredMetricsHubError(int ErrorCode,
                               int VendorId,
                               int ProductId,
                               int DeviceClass,
                               std::string UsbTreePath,
                               int ConnectedDuration) {
  // Limit string length.
  int string_len_limit = 20;
  UsbTreePath = UsbTreePath.substr(0, string_len_limit);

  // Mask VID/PID if the error was reported about an obscure device.
  if (!DeviceInMetricsAllowlist(VendorId, ProductId)) {
    VendorId = 0;
    ProductId = 0;
  }

  metrics::structured::events::usb_error::HubError()
      .SetErrorCode(ErrorCode)
      .SetVendorId(VendorId)
      .SetProductId(ProductId)
      .SetDeviceClass(DeviceClass)
      .SetDevicePath(UsbTreePath)
      .SetConnectedDuration(ConnectedDuration)
      .Record();
}

void StructuredMetricsXhciError(int ErrorCode, int DeviceClass) {
  metrics::structured::events::usb_error::XhciError()
      .SetErrorCode(ErrorCode)
      .SetDeviceClass(DeviceClass)
      .Record();
}

base::FilePath GetUserDBDir() {
  // Usb_bouncer is called by udev even during early boot. If D-Bus is
  // inaccessible, it is early boot and the user hasn't logged in.
  if (!base::PathExists(base::FilePath(kDBusPath))) {
    return base::FilePath("");
  }

  scoped_refptr<dbus::Bus> bus;
  auto session_manager_proxy = SetUpDBus(bus);

  brillo::ErrorPtr error;
  std::string username, hashed_username;
  session_manager_proxy->RetrievePrimarySession(&username, &hashed_username,
                                                &error);
  if (hashed_username.empty()) {
    LOG(ERROR) << "No active user session.";
    return base::FilePath("");
  }

  base::FilePath UserDir =
      base::FilePath(kUserDbBaseDir).Append(hashed_username);
  if (!base::DirectoryExists(UserDir)) {
    LOG(ERROR) << "User daemon-store directory doesn't exist.";
    return base::FilePath("");
  }

  // A sub directory is used so permissions can be enforced by usb_bouncer
  // without affecting the daemon-store mount point.
  UserDir = UserDir.Append(kUserDbParentDir);

  return UserDir;
}

bool IsGuestSession() {
  // Usb_bouncer is called by udev even during early boot. If D-Bus is
  // inaccessible, it is early boot and a guest hasn't logged in.
  if (!base::PathExists(base::FilePath(kDBusPath))) {
    return false;
  }

  scoped_refptr<dbus::Bus> bus;
  auto session_manager_proxy = SetUpDBus(bus);

  bool is_guest = false;
  brillo::ErrorPtr error;
  session_manager_proxy->IsGuestSessionActive(&is_guest, &error);
  return is_guest;
}

bool IsLockscreenShown() {
  // Usb_bouncer is called by udev even during early boot. If D-Bus is
  // inaccessible, it is early boot and the lock-screen isn't shown.
  if (!base::PathExists(base::FilePath(kDBusPath))) {
    return false;
  }

  scoped_refptr<dbus::Bus> bus;
  auto session_manager_proxy = SetUpDBus(bus);

  brillo::ErrorPtr error;
  bool locked;
  if (!session_manager_proxy->IsScreenLocked(&locked, &error)) {
    LOG(ERROR) << "Failed to get lockscreen state.";
    locked = true;
  }
  return locked;
}

std::string StripLeadingPathSeparators(const std::string& path) {
  if (path.find_first_not_of('/') == std::string::npos)
    return std::string();

  return path.substr(path.find_first_not_of('/'));
}

std::unordered_set<std::string> UniqueRules(const EntryMap& entries) {
  std::unordered_set<std::string> aggregated_rules;
  for (const auto& entry_itr : entries) {
    for (const auto& rule : entry_itr.second.rules()) {
      if (!rule.empty()) {
        aggregated_rules.insert(rule);
      }
    }
  }
  return aggregated_rules;
}

SafeFD OpenStateFile(const base::FilePath& base_path,
                     const std::string& parent_dir,
                     const std::string& state_file_name,
                     bool lock) {
  uid_t proc_uid = getuid();
  uid_t uid = proc_uid;
  gid_t gid = getgid();
  if (CanChown() && !brillo::userdb::GetUserInfo(kUsbBouncerUser, &uid, &gid)) {
    LOG(ERROR) << "Failed to get uid & gid for \"" << kUsbBouncerUser << "\"";
    return SafeFD();
  }

  // Don't enforce permissions on the |base_path|. It is handled by the system.
  SafeFD::Error err;
  SafeFD base_fd;
  std::tie(base_fd, err) = SafeFD::Root().first.OpenExistingDir(base_path);
  if (!base_fd.is_valid()) {
    LOG(ERROR) << "\"" << base_path.value() << "\" does not exist!";
    return SafeFD();
  }

  // Acquire an exclusive lock on the base path to avoid races when creating
  // the sub directories. This lock is released when base_fd goes out of scope.
  if (HANDLE_EINTR(flock(base_fd.get(), LOCK_EX)) < 0) {
    PLOG(ERROR) << "Failed to lock \"" << base_path.value() << '"';
    return SafeFD();
  }

  // Ensure the parent directory has the correct permissions.
  SafeFD parent_fd;
  std::tie(parent_fd, err) =
      OpenOrRemakeDir(&base_fd, parent_dir, kDbDirPermissions, uid, gid);
  if (!parent_fd.is_valid()) {
    auto parent_path = base_path.Append(parent_dir);
    LOG(ERROR) << "Failed to validate '" << parent_path.value() << "'";
    return SafeFD();
  }

  // Create the DB file with the correct permissions.
  SafeFD fd;
  std::tie(fd, err) =
      OpenOrRemakeFile(&parent_fd, state_file_name, kDbPermissions, uid, gid);
  if (!fd.is_valid()) {
    auto full_path = base_path.Append(parent_dir).Append(state_file_name);
    LOG(ERROR) << "Failed to validate '" << full_path.value() << "'";
    return SafeFD();
  }

  if (lock) {
    if (HANDLE_EINTR(flock(fd.get(), LOCK_EX)) < 0) {
      auto full_path = base_path.Append(parent_dir).Append(state_file_name);
      PLOG(ERROR) << "Failed to lock \"" << full_path.value() << '"';
      return SafeFD();
    }
  }

  return fd;
}

void UpdateTimestamp(Timestamp* timestamp) {
  auto time = (base::Time::Now() - base::Time::UnixEpoch()).ToTimeSpec();
  timestamp->set_seconds(time.tv_sec);
  timestamp->set_nanos(time.tv_nsec);
}

size_t RemoveEntriesOlderThan(base::TimeDelta cutoff, EntryMap* map) {
  size_t num_removed = 0;
  auto itr = map->begin();
  auto cuttoff_time =
      (base::Time::Now() - base::Time::UnixEpoch() - cutoff).ToTimeSpec();
  while (itr != map->end()) {
    const Timestamp& entry_timestamp = itr->second.last_used();
    if (entry_timestamp.seconds() < cuttoff_time.tv_sec ||
        (entry_timestamp.seconds() == cuttoff_time.tv_sec &&
         entry_timestamp.nanos() < cuttoff_time.tv_nsec)) {
      ++num_removed;
      map->erase(itr++);
    } else {
      ++itr;
    }
  }
  return num_removed;
}

void Daemonize() {
  pid_t result = fork();
  if (result < 0) {
    PLOG(FATAL) << "First fork failed";
  }
  if (result != 0) {
    exit(0);
  }

  setsid();

  result = fork();
  if (result < 0) {
    PLOG(FATAL) << "Second fork failed";
  }
  if (result != 0) {
    exit(0);
  }

  // Since we're demonizing we don't expect to ever read or write from the
  // standard file descriptors. Also, udev waits for the hangup before
  // continuing to execute on the same event, so this is necessary to unblock
  // udev.
  if (freopen("/dev/null", "a+", stdout) == nullptr) {
    LOG(FATAL) << "Failed to replace stdout.";
  }
  if (freopen("/dev/null", "a+", stderr) == nullptr) {
    LOG(FATAL) << "Failed to replace stdout.";
  }
  if (fclose(stdin) != 0) {
    LOG(FATAL) << "Failed to close stdin.";
  }
}

#define TO_STRING_HELPER(x)  \
  case UMADeviceClass::k##x: \
    return #x
const std::string to_string(UMADeviceClass device_class) {
  switch (device_class) {
    TO_STRING_HELPER(App);
    TO_STRING_HELPER(Audio);
    TO_STRING_HELPER(AV);
    TO_STRING_HELPER(Card);
    TO_STRING_HELPER(Comm);
    TO_STRING_HELPER(Health);
    TO_STRING_HELPER(HID);
    TO_STRING_HELPER(Hub);
    TO_STRING_HELPER(Image);
    TO_STRING_HELPER(Misc);
    TO_STRING_HELPER(Other);
    TO_STRING_HELPER(Phys);
    TO_STRING_HELPER(Print);
    TO_STRING_HELPER(Sec);
    TO_STRING_HELPER(Storage);
    TO_STRING_HELPER(Vendor);
    TO_STRING_HELPER(Video);
    TO_STRING_HELPER(Wireless);
  }
}
#undef TO_STRING_HELPER

#define TO_STRING_HELPER(x)       \
  case UMADeviceRecognized::k##x: \
    return #x
const std::string to_string(UMADeviceRecognized recognized) {
  switch (recognized) {
    TO_STRING_HELPER(Recognized);
    TO_STRING_HELPER(Unrecognized);
  }
}
#undef TO_STRING_HELPER

#define TO_STRING_HELPER(x) \
  case UMAPortType::k##x:   \
    return #x
const std::string to_string(UMAPortType port) {
  switch (port) {
    TO_STRING_HELPER(TypeC);
    TO_STRING_HELPER(TypeA);
  }
}
#undef TO_STRING_HELPER

std::ostream& operator<<(std::ostream& out, UMADeviceClass device_class) {
  out << to_string(device_class);
  return out;
}

std::ostream& operator<<(std::ostream& out, UMADeviceRecognized recognized) {
  out << to_string(recognized);
  return out;
}

std::ostream& operator<<(std::ostream& out, UMAPortType port) {
  out << to_string(port);
  return out;
}

usbguard::Rule GetRuleFromString(const std::string& to_parse) {
  usbguard::Rule parsed_rule;
  parsed_rule.setTarget(usbguard::Rule::Target::Invalid);
  if (to_parse.empty()) {
    return parsed_rule;
  }
  try {
    parsed_rule = usbguard::Rule::fromString(to_parse);
  } catch (std::exception ex) {
    // RuleParseException isn't exported by libusbguard.
    LOG(ERROR) << "Failed parse (exception) '" << to_parse << "'.";
  }
  return parsed_rule;
}

UMADeviceClass GetClassFromRule(const usbguard::Rule& rule) {
  const auto& interfaces = rule.attributeWithInterface();
  if (interfaces.empty()) {
    return UMADeviceClass::kOther;
  }

  UMADeviceClass device_class = GetClassEnumFromValue(interfaces.get(0));
  for (int x = 1; x < interfaces.count(); ++x) {
    device_class =
        MergeClasses(device_class, GetClassEnumFromValue(interfaces.get(x)));
  }
  return device_class;
}

base::FilePath GetRootDevice(base::FilePath dev) {
  auto dev_components = dev.GetComponents();
  auto it = dev_components.begin();
  base::FilePath root_dev(*it++);

  for (; it != dev_components.end(); it++) {
    root_dev = root_dev.Append(*it);
    if (RE2::FullMatch(*it, R"((\d+)-(\d+))")) {
      break;
    }
  }
  return root_dev;
}

base::FilePath GetInterfaceDevice(base::FilePath intf) {
  std::string dev;
  if (!RE2::PartialMatch(intf.value(), R"((.*\/).*)", &dev))
    return base::FilePath();

  return base::FilePath(dev);
}

bool IsExternalDevice(base::FilePath normalized_devpath) {
  std::string removable;
  if (base::ReadFileToString(normalized_devpath.Append("removable"),
                             &removable)) {
    base::TrimWhitespaceASCII(removable, base::TRIM_ALL, &removable);
    if (removable == "removable")
      return true;
  }

  std::string panel;
  if (base::ReadFileToString(
          normalized_devpath.Append("physical_location/panel"), &panel)) {
    base::TrimWhitespaceASCII(panel, base::TRIM_ALL, &panel);
    if (panel != "unknown")
      return true;
  }

  return false;
}

bool IsFlexBoard() {
  brillo::KeyValueStore store;
  if (!store.Load(base::FilePath("/etc/lsb-release"))) {
    LOG(WARNING) << "Could not read lsb-release";
    return true;
  }

  std::string value;
  if (!store.GetString("CHROMEOS_RELEASE_BOARD", &value)) {
    LOG(WARNING) << "Could not determine board";
    return true;
  }

  return value.find("reven") != std::string::npos;
}

UMAPortType GetPortType(base::FilePath normalized_devpath) {
  std::string connector_uevent;
  std::string devtype;
  if (base::ReadFileToString(normalized_devpath.Append("port/connector/uevent"),
                             &connector_uevent) &&
      RE2::PartialMatch(connector_uevent, R"(DEVTYPE=(\w+))", &devtype) &&
      devtype == "typec_port") {
    return UMAPortType::kTypeC;
  }

  return UMAPortType::kTypeA;
}

UMADeviceSpeed GetDeviceSpeed(base::FilePath normalized_devpath) {
  std::string speed;
  if (base::ReadFileToString(normalized_devpath.Append("speed"), &speed)) {
    base::TrimWhitespaceASCII(speed, base::TRIM_ALL, &speed);
  }
  std::string version;
  if (base::ReadFileToString(normalized_devpath.Append("version"), &version)) {
    base::TrimWhitespaceASCII(version, base::TRIM_ALL, &version);
  }

  if (speed == "20000") {
    return UMADeviceSpeed::k20000;
  } else if (speed == "10000") {
    return UMADeviceSpeed::k10000;
  } else if (speed == "5000") {
    return UMADeviceSpeed::k5000;
  } else if (speed == "480") {
    if (version == "2.10") {
      return UMADeviceSpeed::k480Fallback;
    } else {
      return UMADeviceSpeed::k480;
    }
  } else if (speed == "12") {
    return UMADeviceSpeed::k12;
  } else if (speed == "1.5") {
    return UMADeviceSpeed::k1_5;
  } else {
    return UMADeviceSpeed::kOther;
  }
}

int GetVendorId(base::FilePath normalized_devpath) {
  std::string vendor_id;
  int vendor_id_int;
  if (base::ReadFileToString(normalized_devpath.Append("idVendor"),
                             &vendor_id)) {
    base::TrimWhitespaceASCII(vendor_id, base::TRIM_ALL, &vendor_id);
    if (base::HexStringToInt(vendor_id, &vendor_id_int)) {
      return vendor_id_int;
    }
  }

  return 0;
}

std::string GetVendorName(base::FilePath normalized_devpath) {
  std::string vendor_name;
  if (base::ReadFileToString(normalized_devpath.Append("manufacturer"),
                             &vendor_name)) {
    base::TrimWhitespaceASCII(vendor_name, base::TRIM_ALL, &vendor_name);
    return vendor_name;
  }

  return std::string();
}

int GetProductId(base::FilePath normalized_devpath) {
  std::string product_id;
  int product_id_int;
  if (base::ReadFileToString(normalized_devpath.Append("idProduct"),
                             &product_id)) {
    base::TrimWhitespaceASCII(product_id, base::TRIM_ALL, &product_id);
    if (base::HexStringToInt(product_id, &product_id_int)) {
      return product_id_int;
    }
  }

  return 0;
}

std::string GetProductName(base::FilePath normalized_devpath) {
  std::string product_name;
  if (base::ReadFileToString(normalized_devpath.Append("product"),
                             &product_name)) {
    base::TrimWhitespaceASCII(product_name, base::TRIM_ALL, &product_name);
    return product_name;
  }

  return std::string();
}

void GetVidPidFromEnvVar(std::string product, int* vendor_id, int* product_id) {
  *vendor_id = 0;
  *product_id = 0;
  std::size_t index1 = product.find('/');
  std::size_t index2 = product.find('/', index1 + 1);
  if (index1 == std::string::npos || index2 == std::string::npos)
    return;

  base::HexStringToInt(product.substr(0, index1), vendor_id);
  base::HexStringToInt(product.substr(index1 + 1, index2 - index1 - 1),
                       product_id);
}

int GetDeviceClass(base::FilePath normalized_devpath) {
  std::string device_class;
  int device_class_int;
  if (base::ReadFileToString(normalized_devpath.Append("bDeviceClass"),
                             &device_class)) {
    base::TrimWhitespaceASCII(device_class, base::TRIM_ALL, &device_class);
    if (base::HexStringToInt(device_class, &device_class_int) &&
        device_class_int != 0) {
      return device_class_int;
    }
  }

  return 0;
}

std::vector<int64_t> GetInterfaceClass(base::FilePath normalized_devpath) {
  std::vector<int64_t> ret;
  base::FileEnumerator enumerator(normalized_devpath, false,
                                  base::FileEnumerator::DIRECTORIES);
  for (auto intf_path = enumerator.Next(); !intf_path.empty();
       intf_path = enumerator.Next()) {
    std::string intf_class;
    int64_t intf_class_int;
    if (!base::ReadFileToString(intf_path.Append("bInterfaceClass"),
                                &intf_class)) {
      continue;
    }
    base::TrimWhitespaceASCII(intf_class, base::TRIM_ALL, &intf_class);
    if (base::HexStringToInt64(intf_class, &intf_class_int)) {
      ret.push_back(intf_class_int);
    }
  }

  return ret;
}

std::string GetUsbTreePath(base::FilePath normalized_devpath) {
  std::string device_path;
  if (base::ReadFileToString(normalized_devpath.Append("devpath"),
                             &device_path)) {
    base::TrimWhitespaceASCII(device_path, base::TRIM_ALL, &device_path);
    return device_path;
  }

  return std::string();
}

int GetUsbTreeDepth(base::FilePath normalized_devpath) {
  std::string devpath = GetUsbTreePath(normalized_devpath);
  return std::count(devpath.begin(), devpath.end(), '.');
}

int GetConnectedDuration(base::FilePath normalized_devpath) {
  std::string connected_duration;
  int connected_duration_int;
  if (base::ReadFileToString(
          normalized_devpath.Append("power/connected_duration"),
          &connected_duration)) {
    base::TrimWhitespaceASCII(connected_duration, base::TRIM_ALL,
                              &connected_duration);
    if (base::StringToInt(connected_duration, &connected_duration_int)) {
      return connected_duration_int;
    }
  }

  return 0;
}

int GetPciDeviceClass(base::FilePath normalized_devpath) {
  std::string device_class;
  int device_class_int;
  if (base::ReadFileToString(normalized_devpath.Append("class"),
                             &device_class)) {
    base::TrimWhitespaceASCII(device_class, base::TRIM_ALL, &device_class);
    if (base::HexStringToInt(device_class, &device_class_int)) {
      // The sysfs "class" file includes class, subclass and interface
      // information. Shifting 16 bits to return only the device class.
      return (device_class_int >> 16);
    }
  }

  return 0;
}

int GetBusnum(base::FilePath normalized_devpath) {
  std::string busnum;
  int busnum_int;
  if (base::ReadFileToString(normalized_devpath.Append("busnum"), &busnum)) {
    base::TrimWhitespaceASCII(busnum, base::TRIM_ALL, &busnum);
    if (base::StringToInt(busnum, &busnum_int)) {
      return busnum_int;
    }
  }

  return 0;
}

std::string GetBootId() {
  std::string boot_id;
  if (base::ReadFileToString(base::FilePath("/proc/sys/kernel/random/boot_id"),
                             &boot_id)) {
    base::TrimWhitespaceASCII(boot_id, base::TRIM_ALL, &boot_id);
    return boot_id;
  }
  return std::string();
}

int64_t GetSystemTime() {
  struct timespec ts;
  clock_gettime(CLOCK_BOOTTIME, &ts);
  return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

}  // namespace usb_bouncer
