// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/debug_mode_tool.h"

#include <memory>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/property.h>
#include <shill/dbus-proxies.h>

namespace debugd {

namespace {

const int kFlimflamLogLevelVerbose3 = -3;
const int kFlimflamLogLevelWiFi = -2;
const int kFlimflamLogLevelInfo = 0;

const char kSupplicantServiceName[] = "fi.w1.wpa_supplicant1";
const char kSupplicantObjectPath[] = "/fi/w1/wpa_supplicant1";
const char kSupplicantDebugLevel[] = "DebugLevel";

class SupplicantProxy {
 public:
  struct Properties : public dbus::PropertySet {
    dbus::Property<std::string> debug_level;

    explicit Properties(dbus::ObjectProxy* proxy)
        : dbus::PropertySet(proxy,
                            kSupplicantServiceName,
                            dbus::PropertySet::PropertyChangedCallback()) {
      RegisterProperty(kSupplicantDebugLevel, &debug_level);
    }

    ~Properties() override = default;
  };

  explicit SupplicantProxy(scoped_refptr<dbus::Bus> bus)
      : bus_(bus),
        properties_(bus->GetObjectProxy(
            kSupplicantServiceName, dbus::ObjectPath(kSupplicantObjectPath))) {}
  SupplicantProxy(const SupplicantProxy&) = delete;
  SupplicantProxy& operator=(const SupplicantProxy&) = delete;

  ~SupplicantProxy() {}

  void SetDebugLevel(const std::string& level) {
    properties_.debug_level.SetAndBlock(level);
  }

 private:
  scoped_refptr<dbus::Bus> bus_;
  Properties properties_;
};

// Marvell wifi.
constexpr char kMwifiexDebugFlag[] =
    "/sys/kernel/debug/mwifiex/mlan0/debug_mask";
// Enable extra debugging: MSG | FATAL | ERROR | CMD | EVENT.
constexpr char kMwifiexEnable[] = "0x37";
// Default debugging level: MSG | FATAL | ERROR.
constexpr char kMwifiexDisable[] = "0x7";

// Intel wifi.
constexpr char kIwlwifiDebugFlag[] = "/sys/module/iwlwifi/parameters/debug";
// Enable INFO, MAC80211 and HCMD logs: see below file for details on each bit:
// drivers/net/wireless-$(WIFIVERSION)/iwl7000/iwlwifi/iwl-debug.h
constexpr char kIwlwifiEnable[] = "0x7";
// Default debugging: none
constexpr char kIwlwifiDisable[] = "0x0";

// Qualcomm/Atheros wifi.
constexpr char kAth10kDebugFlag[] =
    "/sys/module/ath10k_core/parameters/debug_mask";
// Enable all debug logs except PCI_PS, SDIO_DUMP, TESTMODE, PCI_DUMP, HTT_DUMP:
// see below file for details on each bit:
// drivers/net/wireless/ath/ath10k/debug.h
constexpr char kAth10kEnable[] = "0xFFFDAF3F";
// Default debugging: none
constexpr char kAth10kDisable[] = "0x0";

// Realtek wifi.
constexpr char kRtw88DebugFlag[] =
    "/sys/module/rtw88_core/parameters/debug_mask";
// Enable all debug logs except COEX: see below file for details on each bit:
// drivers/net/wireless/realtek/rtw88/debug.h
constexpr char kRtw88Enable[] = "0xFFFFFFBF";
// Default debugging: none
constexpr char kRtw88Disable[] = "0x0";

void MaybeWriteSysfs(const char* sysfs_path, const char* data) {
  base::FilePath path(sysfs_path);

  if (base::PathExists(path)) {
    int len = strlen(data);
    if (base::WriteFile(path, data, len) != len)
      PLOG(WARNING) << "Writing to " << path.value() << " failed";
  }
}
void WifiSetDebugLevels(bool enable) {
  MaybeWriteSysfs(kIwlwifiDebugFlag, enable ? kIwlwifiEnable : kIwlwifiDisable);

  MaybeWriteSysfs(kMwifiexDebugFlag, enable ? kMwifiexEnable : kMwifiexDisable);

  MaybeWriteSysfs(kAth10kDebugFlag, enable ? kAth10kEnable : kAth10kDisable);

  MaybeWriteSysfs(kRtw88DebugFlag, enable ? kRtw88Enable : kRtw88Disable);
}

}  // namespace

DebugModeTool::DebugModeTool(scoped_refptr<dbus::Bus> bus) : bus_(bus) {}

void DebugModeTool::SetDebugMode(const std::string& subsystem) {
  std::string flimflam_tags;
  std::string supplicant_level = "info";
  std::string modemmanager_level = "info";
  bool wifi_debug = false;

  if (subsystem == "wifi") {
    flimflam_tags = "service+wifi+inet+device+manager";
    supplicant_level = "msgdump";
    wifi_debug = true;
  } else if (subsystem == "cellular") {
    flimflam_tags = "service+cellular+modem+device+manager";
    modemmanager_level = "debug";
  } else if (subsystem == "ethernet") {
    flimflam_tags = "service+ethernet+device+manager";
  } else if (subsystem == "none") {
    flimflam_tags = "";
  }

  auto shill = std::make_unique<org::chromium::flimflam::ManagerProxy>(bus_);
  if (shill) {
    shill->SetDebugTags(flimflam_tags, nullptr);
    if (flimflam_tags.length() == 0) {
      shill->SetDebugLevel(kFlimflamLogLevelInfo, nullptr);
    } else if (subsystem == "wifi") {
      shill->SetDebugLevel(kFlimflamLogLevelWiFi, nullptr);
    } else {
      shill->SetDebugLevel(kFlimflamLogLevelVerbose3, nullptr);
    }
  }

  WifiSetDebugLevels(wifi_debug);

  SupplicantProxy supplicant(bus_);
  supplicant.SetDebugLevel(supplicant_level);

  SetModemManagerLogging(modemmanager_level);
}

void DebugModeTool::SetModemManagerLogging(const std::string& level) {
#if USE_CELLULAR
  static constexpr char kSetLogging[] = "SetLogging";

  dbus::ObjectProxy* proxy = bus_->GetObjectProxy(
      modemmanager::kModemManager1ServiceName,
      dbus::ObjectPath(modemmanager::kModemManager1ServicePath));
  dbus::MethodCall method_call(modemmanager::kModemManager1ServiceName,
                               kSetLogging);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(level);
  proxy->CallMethodAndBlock(&method_call,
                            dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
#endif  // USE_CELLULAR
}

}  // namespace debugd
