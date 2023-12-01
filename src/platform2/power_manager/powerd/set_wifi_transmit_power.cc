// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Helper program for setting WiFi transmission power.

#include <map>
#include <string>
#include <vector>

#include <linux/nl80211.h>
#include <net/if.h>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/threading/platform_thread.h>
#include <brillo/flag_helper.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <power_manager/common/power_constants.h>

// Vendor command definition for marvell mwifiex driver
// Defined in Linux kernel:
// drivers/net/wireless/marvell/mwifiex/main.h
#define MWIFIEX_VENDOR_ID 0x005043

// Vendor sub command
#define MWIFIEX_VENDOR_CMD_SET_TX_POWER_LIMIT 0

#define MWIFIEX_VENDOR_CMD_ATTR_TXP_LIMIT_24 1
#define MWIFIEX_VENDOR_CMD_ATTR_TXP_LIMIT_52 2

// Vendor command definition for intel iwl7000 driver
// Defined in Linux kernel:
// drivers/net/wireless/iwl7000/iwlwifi/mvm/vendor-cmd.h
#define INTEL_OUI 0x001735

// Vendor sub command
#define IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE 28

#define IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE 58
#define IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE 59

#define IWL_TABLET_PROFILE_INDEX 1
#define IWL_CLAMSHELL_PROFILE_INDEX 2

// Legacy vendor subcommand used for devices without limits in ACPI.
#define IWL_MVM_VENDOR_CMD_SET_NIC_TXPOWER_LIMIT 13

#define IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24 13
#define IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L 14
#define IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H 15

#define REALTEK_OUI 0x00E04C
#define REALTEK_NL80211_VNDCMD_SET_SAR 0x88
#define REALTEK_VNDCMD_ATTR_SAR_RULES 1
#define REALTEK_VNDCMD_ATTR_SAR_BAND 2
#define REALTEK_VNDCMD_ATTR_SAR_POWER 3

// COMMON SAR API COMMANDS
#define NL80211_CMD_SET_SAR_SPECS 140
#define NL80211_ATTR_SAR_SPEC 300
#define NL80211_SAR_ATTR_TYPE 1
#define NL80211_SAR_TYPE_POWER 0
#define NL80211_SAR_ATTR_SPECS 2
#define NL80211_SAR_ATTR_SPECS_POWER 1
#define NL80211_SAR_ATTR_SPECS_RANGE_INDEX 2

// Implementation constants
#define MAX_ATTEMPTS 3

namespace {

int ErrorHandler(struct sockaddr_nl* nla, struct nlmsgerr* err, void* arg) {
  // nl80211 error codes must be negative. Zero means success, which should
  // land in AckHandler.
  CHECK_LE(err->error, 0);
  *static_cast<int*>(arg) = err->error;
  return NL_STOP;
}

int FinishHandler(struct nl_msg* msg, void* arg) {
  *static_cast<int*>(arg) = 0;
  return NL_SKIP;
}

int AckHandler(struct nl_msg* msg, void* arg) {
  *static_cast<int*>(arg) = 0;
  return NL_STOP;
}

int ValidHandler(struct nl_msg* msg, void* arg) {
  return NL_OK;
}

enum class WirelessDriver { NONE, MWIFIEX, IWL, ATH10K, RTW88, RTW89, MTK };

enum RealtekVndcmdSARBand {
  REALTEK_VNDCMD_ATTR_SAR_BAND_2g = 0,
  REALTEK_VNDCMD_ATTR_SAR_BAND_5g_1 = 1,
  REALTEK_VNDCMD_ATTR_SAR_BAND_5g_3 = 3,
  REALTEK_VNDCMD_ATTR_SAR_BAND_5g_4 = 4,
};

enum Rtw89SARBand {
  kRtw89SarBand2g = 0,
  kRtw89SarBand5g1 = 1,
  kRtw89SarBand5g3 = 2,
  kRtw89SarBand5g4 = 3,
  kRtw89SarBand6g1 = 4,
  kRtw89SarBand6g2 = 5,
  kRtw89SarBand6g3 = 6,
  kRtw89SarBand6g4 = 7,
  kRtw89SarBand6g5 = 8,
  kRtw89SarBand6g6 = 9,
};

// For ath10k the driver configures index 0 for 2g and index 1 for 5g.
// This dependency is a bit fragile and can break if the underlying
// assumption changes. In the upcoming implementation where the the driver
// capabilities are published, we will use the driver capability to find the
// index and frequency band mapping and can avoid enums like these.
enum Ath10kSARBand {
  kAth10kSarBand2g = 0,
  kAth10kSarBand5g = 1,
};

std::map<enum Ath10kSARBand, uint8_t> GetAth10kChromeosConfigPowerTable(
    bool tablet) {
  std::map<enum Ath10kSARBand, uint8_t> power_table = {};
  auto config = std::make_unique<brillo::CrosConfig>();
  std::string wifi_power_table_path =
      tablet ? "/wifi/tablet-mode-power-table-ath10k"
             : "/wifi/non-tablet-mode-power-table-ath10k";

  std::string value;
  int power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-2g", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value);
  CHECK(power_limit <= UINT8_MAX)
      << "Invalid power limit configs. Limit value cannot exceed 255.";
  power_table[kAth10kSarBand2g] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-5g", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value);
  CHECK(power_limit <= UINT8_MAX)
      << "Invalid power limit configs. Limit value cannot exceed 255.";
  power_table[kAth10kSarBand5g] = power_limit;

  return power_table;
}

// Returns the type of wireless driver that's present on the system.
WirelessDriver GetWirelessDriverType(const std::string& device_name) {
  const std::map<std::string, WirelessDriver> drivers = {
      {"ath10k_pci", WirelessDriver::ATH10K},
      {"ath10k_sdio", WirelessDriver::ATH10K},
      {"ath10k_snoc", WirelessDriver::ATH10K},
      {"iwlwifi", WirelessDriver::IWL},
      {"mwifiex_pcie", WirelessDriver::MWIFIEX},
      {"mwifiex_sdio", WirelessDriver::MWIFIEX},
      {"rtw_pci", WirelessDriver::RTW88},
      {"rtw_8822ce", WirelessDriver::RTW88},
      {"rtw89_8852ae", WirelessDriver::RTW89},
      {"rtw89_8852ce", WirelessDriver::RTW89},
      {"mt7921e", WirelessDriver::MTK},
      {"mt7921s", WirelessDriver::MTK},
  };

  // .../device/driver symlink should point at the driver's module.
  base::FilePath link_path(base::StringPrintf("/sys/class/net/%s/device/driver",
                                              device_name.c_str()));
  base::FilePath driver_path;
  if (!base::ReadSymbolicLink(link_path, &driver_path)) {
    // This can race with device removal, for instance. Just warn and do
    // nothing.
    PLOG(ERROR) << "Failed reading symbolic link: " << link_path.value();
    return WirelessDriver::NONE;
  }

  base::FilePath driver_name = driver_path.BaseName();
  const auto driver = drivers.find(driver_name.value());
  if (driver != drivers.end())
    return driver->second;

  return WirelessDriver::NONE;
}

// Returns a vector of wireless device name(s) found on the system. We
// generally should only have 1 internal WiFi device, but it's possible to have
// an external device plugged in (e.g., via USB).
std::vector<std::string> GetWirelessDeviceNames() {
  std::vector<std::string> names;
  base::FileEnumerator iter(base::FilePath("/sys/class/net"), false,
                            base::FileEnumerator::FileType::FILES |
                                base::FileEnumerator::FileType::SHOW_SYM_LINKS,
                            "*");

  for (base::FilePath name = iter.Next(); !name.empty(); name = iter.Next()) {
    std::string uevent;
    CHECK(base::ReadFileToString(name.Append("uevent"), &uevent));

    for (const auto& line : base::SplitString(
             uevent, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL)) {
      if (line == "DEVTYPE=wlan") {
        names.push_back(name.BaseName().value());
        break;
      }
    }
  }
  return names;
}

// Returns a vector of tx power limits for mode |tablet|.
// If the board does not store power limits for rtw88 driver in chromeos-config,
// the function will fail.
std::map<enum RealtekVndcmdSARBand, uint8_t> GetRtw88ChromeosConfigPowerTable(
    bool tablet, power_manager::WifiRegDomain domain) {
  std::map<enum RealtekVndcmdSARBand, uint8_t> power_table = {};
  auto config = std::make_unique<brillo::CrosConfig>();
  std::string wifi_power_table_path =
      tablet ? "/wifi/tablet-mode-power-table-rtw"
             : "/wifi/non-tablet-mode-power-table-rtw";
  std::string wifi_geo_offsets_path;
  switch (domain) {
    case power_manager::WifiRegDomain::FCC:
      wifi_geo_offsets_path = "/wifi/geo-offsets-fcc";
      break;
    case power_manager::WifiRegDomain::EU:
      wifi_geo_offsets_path = "/wifi/geo-offsets-eu";
      break;
    case power_manager::WifiRegDomain::REST_OF_WORLD:
      wifi_geo_offsets_path = "/wifi/geo-offsets-rest-of-world";
      break;
    case power_manager::WifiRegDomain::NONE:
      break;
  }

  int offset_2g = 0, offset_5g = 0;
  if (domain != power_manager::WifiRegDomain::NONE) {
    std::string offset_string;
    if (config->GetString(wifi_geo_offsets_path, "offset-2g", &offset_string)) {
      offset_2g = std::stoi(offset_string);
    }
    if (config->GetString(wifi_geo_offsets_path, "offset-5g", &offset_string)) {
      offset_5g = std::stoi(offset_string);
    }
  }

  std::string value;
  int power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-2g", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_2g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[REALTEK_VNDCMD_ATTR_SAR_BAND_2g] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-1", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[REALTEK_VNDCMD_ATTR_SAR_BAND_5g_1] = power_limit;

  // Rtw88 driver does not support 5g band 2, so skip it.

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-3", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[REALTEK_VNDCMD_ATTR_SAR_BAND_5g_3] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-4", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[REALTEK_VNDCMD_ATTR_SAR_BAND_5g_4] = power_limit;

  return power_table;
}

// Returns a vector of tx power limits for mode |tablet|.
// If the board does not store power limits for rtw89 driver in chromeos-config,
// the function will fail.
std::map<enum Rtw89SARBand, uint8_t> GetRtw89ChromeosConfigPowerTable(
    bool tablet, power_manager::WifiRegDomain domain) {
  std::map<enum Rtw89SARBand, uint8_t> power_table = {};
  auto config = std::make_unique<brillo::CrosConfig>();
  std::string wifi_power_table_path =
      tablet ? "/wifi/tablet-mode-power-table-rtw"
             : "/wifi/non-tablet-mode-power-table-rtw";
  std::string wifi_geo_offsets_path;
  switch (domain) {
    case power_manager::WifiRegDomain::FCC:
      wifi_geo_offsets_path = "/wifi/geo-offsets-fcc";
      break;
    case power_manager::WifiRegDomain::EU:
      wifi_geo_offsets_path = "/wifi/geo-offsets-eu";
      break;
    case power_manager::WifiRegDomain::REST_OF_WORLD:
      wifi_geo_offsets_path = "/wifi/geo-offsets-rest-of-world";
      break;
    case power_manager::WifiRegDomain::NONE:
      break;
  }

  int offset_2g = 0, offset_5g = 0, offset_6g = 0;
  if (domain != power_manager::WifiRegDomain::NONE) {
    std::string offset_string;
    if (config->GetString(wifi_geo_offsets_path, "offset-2g", &offset_string)) {
      offset_2g = std::stoi(offset_string);
    }
    if (config->GetString(wifi_geo_offsets_path, "offset-5g", &offset_string)) {
      offset_5g = std::stoi(offset_string);
    }
    if (config->GetString(wifi_geo_offsets_path, "offset-6g", &offset_string)) {
      offset_6g = std::stoi(offset_string);
    }
  }

  std::string value;
  int power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-2g", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_2g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand2g] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-1", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand5g1] = power_limit;

  // Rtw89 driver does not support 5g band 2, so skip it.

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-3", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand5g3] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-4", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand5g4] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-6g-1", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_6g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand6g1] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-6g-2", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_6g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand6g2] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-6g-3", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_6g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand6g3] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-6g-4", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_6g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand6g4] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-6g-5", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_6g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand6g5] = power_limit;

  CHECK(config->GetString(wifi_power_table_path, "limit-6g-6", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_6g;
  CHECK(power_limit <= UINT8_MAX) << "Invalid power limit configs. Limit "
                                     "value cannot exceed 255.";
  power_table[kRtw89SarBand6g6] = power_limit;
  return power_table;
}

// Fill in nl80211 message for the mwifiex driver.
void FillMessageMwifiex(struct nl_msg* msg, bool tablet) {
  CHECK(!nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, MWIFIEX_VENDOR_ID))
      << "Failed to put NL80211_ATTR_VENDOR_ID";
  CHECK(!nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                     MWIFIEX_VENDOR_CMD_SET_TX_POWER_LIMIT))
      << "Failed to put NL80211_ATTR_VENDOR_SUBCMD";

  struct nlattr* limits =
      nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
  CHECK(limits) << "Failed in nla_nest_start";

  CHECK(!nla_put_u8(msg, MWIFIEX_VENDOR_CMD_ATTR_TXP_LIMIT_24, tablet))
      << "Failed to put MWIFIEX_VENDOR_CMD_ATTR_TXP_LIMIT_24";
  CHECK(!nla_put_u8(msg, MWIFIEX_VENDOR_CMD_ATTR_TXP_LIMIT_52, tablet))
      << "Failed to put MWIFIEX_VENDOR_CMD_ATTR_TXP_LIMIT_52";
  CHECK(!nla_nest_end(msg, limits)) << "Failed in nla_nest_end";
}

// Returns a vector of three IWL transmit power limits for mode |tablet| if the
// board doesn't contain limits in ACPI, or an empty vector if ACPI should be
// used. ACPI limits are expected; this is just a hack for devices (currently
// only cave) that lack limits in ACPI. See b:70549692 for details.
std::vector<uint32_t> GetNonAcpiIwlPowerTable(bool tablet) {
  // Get the board name minus an e.g. "-signed-mpkeys" suffix.
  std::string board = base::SysInfo::GetLsbReleaseBoard();
  const size_t index = board.find("-signed-");
  if (index != std::string::npos)
    board.resize(index);

  if (board == "cave") {
    return tablet ? std::vector<uint32_t>{13, 9, 9}
                  : std::vector<uint32_t>{30, 30, 30};
  }
  return {};
}

// Fill in nl80211 message for the iwl driver.
void FillMessageIwl(struct nl_msg* msg, bool tablet) {
  CHECK(!nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI))
      << "Failed to put NL80211_ATTR_VENDOR_ID";

  const std::vector<uint32_t> table = GetNonAcpiIwlPowerTable(tablet);
  const bool use_acpi = table.empty();

  CHECK(!nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                     use_acpi ? IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE
                              : IWL_MVM_VENDOR_CMD_SET_NIC_TXPOWER_LIMIT))
      << "Failed to put NL80211_ATTR_VENDOR_SUBCMD";

  struct nlattr* limits =
      nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
  CHECK(limits) << "Failed in nla_nest_start";

  if (use_acpi) {
    int index = tablet ? IWL_TABLET_PROFILE_INDEX : IWL_CLAMSHELL_PROFILE_INDEX;
    CHECK(!nla_put_u8(msg, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE, index))
        << "Failed to put IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE";
    CHECK(!nla_put_u8(msg, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE, index))
        << "Failed to put IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE";
  } else {
    DCHECK_EQ(table.size(), 3);
    CHECK(!nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24, table[0] * 8))
        << "Failed to put IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24";
    CHECK(!nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L, table[1] * 8))
        << "Failed to put IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L";
    CHECK(!nla_put_u32(msg, IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H, table[2] * 8))
        << "Failed to put IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H";
  }

  CHECK(!nla_nest_end(msg, limits)) << "Failed in nla_nest_end";
}

// Fill in nl80211 message for the rtw88 driver.
// TODO(b/211772409): Support common SAR API for rtw88. Note that rtw89 already
// does (see below).
void FillMessageRtw88(struct nl_msg* msg,
                      bool tablet,
                      power_manager::WifiRegDomain domain) {
  CHECK(!nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, REALTEK_OUI))
      << "Failed to put NL80211_ATTR_VENDOR_ID";
  CHECK(!nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                     REALTEK_NL80211_VNDCMD_SET_SAR))
      << "Failed to put NL80211_ATTR_VENDOR_SUBCMD";

  struct nlattr* vendor_cmd =
      nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
  struct nlattr* rules =
      nla_nest_start(msg, REALTEK_VNDCMD_ATTR_SAR_RULES | NLA_F_NESTED);
  for (const auto& limit : GetRtw88ChromeosConfigPowerTable(tablet, domain)) {
    struct nlattr* rule = nla_nest_start(msg, 1 | NLA_F_NESTED);
    CHECK(rule) << "Failed in nla_nest_start";
    CHECK(!nla_put_u32(msg, REALTEK_VNDCMD_ATTR_SAR_BAND, limit.first))
        << "Failed to put REALTEK_VNDCMD_ATTR_SAR_BAND";
    CHECK(!nla_put_u8(msg, REALTEK_VNDCMD_ATTR_SAR_POWER, limit.second))
        << "Failed to put REALTEK_VNDCMD_ATTR_SAR_POWER";
    CHECK(!nla_nest_end(msg, rule)) << "Failed in nla_nest_end";
  }
  CHECK(!nla_nest_end(msg, rules)) << "Failed in nla_nest_end";
  CHECK(!nla_nest_end(msg, vendor_cmd)) << "Failed in nla_nest_end";
}

// Fill in nl80211 message for the rtw89 driver.
void FillMessageRtw89(struct nl_msg* msg,
                      bool tablet,
                      power_manager::WifiRegDomain domain) {
  struct nlattr* sar_capa =
      nla_nest_start(msg, NL80211_ATTR_SAR_SPEC | NLA_F_NESTED);
  nla_put_u32(msg, NL80211_SAR_ATTR_TYPE, NL80211_SAR_TYPE_POWER);
  struct nlattr* specs =
      nla_nest_start(msg, NL80211_SAR_ATTR_SPECS | NLA_F_NESTED);
  int i = 0;

  for (const auto& limit : GetRtw89ChromeosConfigPowerTable(tablet, domain)) {
    struct nlattr* sub_freq_range = nla_nest_start(msg, ++i | NLA_F_NESTED);
    CHECK(sub_freq_range) << "Failed to execute nla_nest_start";
    CHECK(!nla_put_u32(msg, NL80211_SAR_ATTR_SPECS_RANGE_INDEX, limit.first))
        << "Failed to put frequency index";
    CHECK(!nla_put_s32(msg, NL80211_SAR_ATTR_SPECS_POWER, limit.second))
        << "Failed to put band power";
    CHECK(!nla_nest_end(msg, sub_freq_range)) << "Failed in nla_nest_end";
  }

  CHECK(!nla_nest_end(msg, specs)) << "Failed in nla_nest_end";
  CHECK(!nla_nest_end(msg, sar_capa)) << "Failed in nla_nest_end";
}

// Fill in nl80211 message for ath10k driver
void FillMessageAth10k(struct nl_msg* msg, bool tablet) {
  struct nlattr* sar_capa =
      nla_nest_start(msg, NL80211_ATTR_SAR_SPEC | NLA_F_NESTED);
  nla_put_u32(msg, NL80211_SAR_ATTR_TYPE, NL80211_SAR_TYPE_POWER);
  struct nlattr* specs =
      nla_nest_start(msg, NL80211_SAR_ATTR_SPECS | NLA_F_NESTED);
  int i = 0;

  for (const auto& limit : GetAth10kChromeosConfigPowerTable(tablet)) {
    struct nlattr* sub_freq_range = nla_nest_start(msg, ++i | NLA_F_NESTED);
    CHECK(sub_freq_range) << "Failed to execute nla_nest_start";
    CHECK(!nla_put_u32(msg, NL80211_SAR_ATTR_SPECS_RANGE_INDEX, limit.first))
        << "Failed to put frequency index";
    CHECK(!nla_put_s32(msg, NL80211_SAR_ATTR_SPECS_POWER, limit.second))
        << "Failed to put band power";
    CHECK(!nla_nest_end(msg, sub_freq_range)) << "Failed in nla_nest_end";
  }

  CHECK(!nla_nest_end(msg, specs)) << "Failed in nla_nest_end";
  CHECK(!nla_nest_end(msg, sar_capa)) << "Failed in nla_nest_end";
}

// The mt7921 driver configures index 0 for 2g and indexes 1-4 for 5g.  This
// dependency is a bit fragile and can break if the underlying assumption
// changes. Since the mt7921 driver already publishes its capabilities (see
// crrev.com/c/3009850), this could use the driver capability to find the index
// and frequency band mapping to avoid enums like these (b/172377638).
// Note: Enum indices 5-10 were added for the 6GHz bands present in
// crrev.com/c/3953998.
enum MtkSARBand {
  kMtkSarBand2g = 0,
  kMtkSarBand5g1 = 1,
  kMtkSarBand5g2 = 2,
  kMtkSarBand5g3 = 3,
  kMtkSarBand5g4 = 4,
  kMtkSarBand6g1 = 5,
  kMtkSarBand6g2 = 6,
  kMtkSarBand6g3 = 7,
  kMtkSarBand6g4 = 8,
  kMtkSarBand6g5 = 9,
  kMtkSarBand6g6 = 10,
};

std::map<enum MtkSARBand, uint8_t> GetMtkChromeosConfigPowerTable(
    bool tablet, power_manager::WifiRegDomain domain) {
  std::map<enum MtkSARBand, uint8_t> power_table = {};
  auto config = std::make_unique<brillo::CrosConfig>();
  std::string wifi_power_table_path =
      tablet ? "/wifi/tablet-mode-power-table-mtk"
             : "/wifi/non-tablet-mode-power-table-mtk";
  std::string wifi_geo_power_table_path;
  switch (domain) {
    case power_manager::WifiRegDomain::FCC:
      wifi_geo_power_table_path = "/wifi/fcc-power-table-mtk";
      break;
    case power_manager::WifiRegDomain::EU:
      wifi_geo_power_table_path = "/wifi/eu-power-table-mtk";
      break;
    case power_manager::WifiRegDomain::REST_OF_WORLD:
      wifi_geo_power_table_path = "/wifi/rest-of-world-power-table-mtk";
      break;
    case power_manager::WifiRegDomain::NONE:
      break;
  }

  int limit_2g = UINT8_MAX, limit_5g = UINT8_MAX, limit_6g = UINT8_MAX,
      offset_2g = 0, offset_5g = 0, offset_6g = 0;
  if (domain != power_manager::WifiRegDomain::NONE) {
    std::string geo_string;
    if (config->GetString(wifi_geo_power_table_path, "limit-2g", &geo_string)) {
      limit_2g = std::stoi(geo_string);
    }
    if (config->GetString(wifi_geo_power_table_path, "limit-5g", &geo_string)) {
      limit_5g = std::stoi(geo_string);
    }
    if (config->GetString(wifi_geo_power_table_path, "limit-6g", &geo_string)) {
      limit_6g = std::stoi(geo_string);
    }
    if (config->GetString(wifi_geo_power_table_path, "offset-2g",
                          &geo_string)) {
      offset_2g = std::stoi(geo_string);
    }
    if (config->GetString(wifi_geo_power_table_path, "offset-5g",
                          &geo_string)) {
      offset_5g = std::stoi(geo_string);
    }
    if (config->GetString(wifi_geo_power_table_path, "offset-6g",
                          &geo_string)) {
      offset_6g = std::stoi(geo_string);
    }
  }

  std::string value;
  int power_limit = UINT8_MAX;

  CHECK(config->GetString(wifi_power_table_path, "limit-2g", &value))
      << "Could not get ChromeosConfig power table: " << wifi_power_table_path;
  power_limit = std::stoi(value) + offset_2g;
  CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
      << "Invalid power limit configs. Limit value cannot exceed 255.";
  power_table[kMtkSarBand2g] = std::min(power_limit, limit_2g);

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-1", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
      << "Invalid power limit configs. Limit value cannot exceed 255.";
  power_table[kMtkSarBand5g1] = std::min(power_limit, limit_5g);

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-2", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
      << "Invalid power limit configs. Limit value cannot exceed 255.";
  power_table[kMtkSarBand5g2] = std::min(power_limit, limit_5g);

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-3", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
      << "Invalid power limit configs. Limit value cannot exceed 255.";
  power_table[kMtkSarBand5g3] = std::min(power_limit, limit_5g);

  CHECK(config->GetString(wifi_power_table_path, "limit-5g-4", &value))
      << "Could not get ChromeosConfig power table.";
  power_limit = std::stoi(value) + offset_5g;
  CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
      << "Invalid power limit configs. Limit value cannot exceed 255.";
  power_table[kMtkSarBand5g4] = std::min(power_limit, limit_5g);

  // See if there's a 6GHz entry.  If so, assume that all 6GHz values will
  // be populated.  Otherwise, assume no 6GHz values and don't touch the
  // 6GHz config.
  // This is largely done to be backwards compatible with MT7921, which doesn't
  // require 6GHz config (as it is not 6GHz capable).
  if (config->GetString(wifi_power_table_path, "limit-6g-1", &value)) {
    power_limit = std::stoi(value) + offset_6g;
    CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
        << "Invalid power limit configs. Limit value cannot exceed 255.";
    power_table[kMtkSarBand6g1] = std::min(power_limit, limit_6g);

    CHECK(config->GetString(wifi_power_table_path, "limit-6g-2", &value))
        << "Could not get ChromeosConfig power table.";
    power_limit = std::stoi(value) + offset_6g;
    CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
        << "Invalid power limit configs. Limit value cannot exceed 255.";
    power_table[kMtkSarBand6g2] = std::min(power_limit, limit_6g);

    CHECK(config->GetString(wifi_power_table_path, "limit-6g-3", &value))
        << "Could not get ChromeosConfig power table.";
    power_limit = std::stoi(value) + offset_6g;
    CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
        << "Invalid power limit configs. Limit value cannot exceed 255.";
    power_table[kMtkSarBand6g3] = std::min(power_limit, limit_6g);

    CHECK(config->GetString(wifi_power_table_path, "limit-6g-4", &value))
        << "Could not get ChromeosConfig power table.";
    power_limit = std::stoi(value) + offset_6g;
    CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
        << "Invalid power limit configs. Limit value cannot exceed 255.";
    power_table[kMtkSarBand6g4] = std::min(power_limit, limit_6g);

    CHECK(config->GetString(wifi_power_table_path, "limit-6g-5", &value))
        << "Could not get ChromeosConfig power table.";
    power_limit = std::stoi(value) + offset_6g;
    CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
        << "Invalid power limit configs. Limit value cannot exceed 255.";
    power_table[kMtkSarBand6g5] = std::min(power_limit, limit_6g);

    CHECK(config->GetString(wifi_power_table_path, "limit-6g-6", &value))
        << "Could not get ChromeosConfig power table.";
    power_limit = std::stoi(value) + offset_6g;
    CHECK(power_limit >= 0 && power_limit <= UINT8_MAX)
        << "Invalid power limit configs. Limit value cannot exceed 255.";
    power_table[kMtkSarBand6g6] = std::min(power_limit, limit_6g);
  }

  return power_table;
}

// Fill in nl80211 message for the mtk driver.
void FillMessageMTK(struct nl_msg* msg,
                    bool tablet,
                    power_manager::WifiRegDomain domain) {
  struct nlattr* sar_capa =
      nla_nest_start(msg, NL80211_ATTR_SAR_SPEC | NLA_F_NESTED);
  nla_put_u32(msg, NL80211_SAR_ATTR_TYPE, NL80211_SAR_TYPE_POWER);
  struct nlattr* specs =
      nla_nest_start(msg, NL80211_SAR_ATTR_SPECS | NLA_F_NESTED);
  int i = 0;

  for (const auto& limit : GetMtkChromeosConfigPowerTable(tablet, domain)) {
    struct nlattr* sub_freq_range = nla_nest_start(msg, ++i | NLA_F_NESTED);
    CHECK(sub_freq_range) << "Failed to execute nla_nest_start";
    CHECK(!nla_put_u32(msg, NL80211_SAR_ATTR_SPECS_RANGE_INDEX, limit.first))
        << "Failed to put frequency index";
    CHECK(!nla_put_s32(msg, NL80211_SAR_ATTR_SPECS_POWER, limit.second))
        << "Failed to put band power";
    CHECK(!nla_nest_end(msg, sub_freq_range)) << "Failed in nla_nest_end";
  }

  CHECK(!nla_nest_end(msg, specs)) << "Failed in nla_nest_end";
  CHECK(!nla_nest_end(msg, sar_capa)) << "Failed in nla_nest_end";
}

class PowerSetter {
 public:
  PowerSetter() : nl_sock_(nl_socket_alloc()), cb_(nl_cb_alloc(NL_CB_DEFAULT)) {
    CHECK(nl_sock_);
    CHECK(cb_);

    // Register libnl callbacks.
    nl_cb_err(cb_, NL_CB_CUSTOM, ErrorHandler, &err_);
    nl_cb_set(cb_, NL_CB_FINISH, NL_CB_CUSTOM, FinishHandler, &err_);
    nl_cb_set(cb_, NL_CB_ACK, NL_CB_CUSTOM, AckHandler, &err_);
    nl_cb_set(cb_, NL_CB_VALID, NL_CB_CUSTOM, ValidHandler, nullptr);
  }
  PowerSetter(const PowerSetter&) = delete;
  PowerSetter& operator=(const PowerSetter&) = delete;

  ~PowerSetter() {
    nl_socket_free(nl_sock_);
    nl_cb_put(cb_);
  }

  bool SendModeSwitch(const std::string& dev_name,
                      bool tablet,
                      power_manager::WifiRegDomain domain,
                      power_manager::TriggerSource tr_source,
                      int attempt = 0) {
    const uint32_t index = if_nametoindex(dev_name.c_str());
    if (!index) {
      LOG(ERROR) << "Failed to find wireless device index for " << dev_name;
      return false;
    }
    WirelessDriver driver = GetWirelessDriverType(dev_name);
    if (driver == WirelessDriver::NONE) {
      LOG(ERROR) << "No valid wireless driver found for " << dev_name;
      return false;
    }
    LOG(INFO) << "Found wireless device " << dev_name << " (index " << index
              << ")";

    struct nl_msg* msg = nlmsg_alloc();
    CHECK(msg);

    // Ath10k, MTK, and rtw89 use the common SAR API. Other drivers use vendor-
    // specific commands.
    // TODO(b/172377638): Use common API for all platforms and fallback to
    // vendor API if common API is not supported.
    if (driver == WirelessDriver::ATH10K || driver == WirelessDriver::MTK ||
        driver == WirelessDriver::RTW89)
      genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nl_family_id_, 0, 0,
                  NL80211_CMD_SET_SAR_SPECS, 0);
    else
      genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nl_family_id_, 0, 0,
                  NL80211_CMD_VENDOR, 0);

    // Marvell does not support Tx power change based on reg domain change.
    if (driver == WirelessDriver::MWIFIEX &&
        tr_source == power_manager::TriggerSource::REG_DOMAIN) {
      DLOG(WARNING) << "Marvell WiFi does not support Tx power change based on "
                       "reg domain change.";

      return false;
    }

    // Set actual message.
    CHECK(!nla_put_u32(msg, NL80211_ATTR_IFINDEX, index))
        << "Failed to put NL80211_ATTR_IFINDEX";

    switch (driver) {
      case WirelessDriver::MWIFIEX:
        FillMessageMwifiex(msg, tablet);
        break;
      case WirelessDriver::IWL:
        FillMessageIwl(msg, tablet);
        break;
      case WirelessDriver::RTW88:
        FillMessageRtw88(msg, tablet, domain);
        break;
      case WirelessDriver::RTW89:
        FillMessageRtw89(msg, tablet, domain);
        break;
      case WirelessDriver::ATH10K:
        FillMessageAth10k(msg, tablet);
        break;
      case WirelessDriver::MTK:
        FillMessageMTK(msg, tablet, domain);
        break;
      case WirelessDriver::NONE:
        NOTREACHED() << "No driver found";
    }

    PCHECK(nl_send_auto(nl_sock_, msg) > 0) << "nl_send_auto failed";

    err_ = 1;
    while (err_ > 0)
      nl_recvmsgs(nl_sock_, cb_);

    // Mediatek chips have a command queue. It's possible that this is full
    // when the request to change modes was sent. This should not be a fatal
    // error, it should be retried.
    if (driver == WirelessDriver::MTK && err_ == -ENOMEM &&
        attempt <= MAX_ATTEMPTS) {
      LOG(WARNING) << "Retrying as a result of ENOMEM error attempt: "
                   << attempt;
      base::PlatformThread::Sleep(base::Milliseconds(10 << attempt));
      return SendModeSwitch(dev_name, tablet, domain, tr_source, ++attempt);
    }

    CHECK(err_ == 0) << "netlink command failed: " << strerror(-err_);

    LOG(INFO) << "Succeeded after " << attempt << " retries";
    nlmsg_free(msg);
    return err_ == 0;
  }

  // Sets power mode according to tablet mode state. Returns true on success and
  // false on failure.
  bool SetPowerMode(bool tablet,
                    power_manager::WifiRegDomain domain,
                    power_manager::TriggerSource tr_source) {
    CHECK(!genl_connect(nl_sock_)) << "Failed to connect to netlink";

    nl_family_id_ = genl_ctrl_resolve(nl_sock_, "nl80211");
    CHECK_GE(nl_family_id_, 0) << "family nl80211 not found";

    const std::vector<std::string> device_names = GetWirelessDeviceNames();
    if (device_names.empty()) {
      LOG(ERROR) << "No wireless device found";
      return false;
    }

    bool ret = true;
    for (const auto& name : device_names)
      if (!SendModeSwitch(name, tablet, domain, tr_source))
        ret = false;
    return ret;
  }

 private:
  struct nl_sock* nl_sock_;
  int nl_family_id_ = 0;
  struct nl_cb* cb_;
  int err_ = 0;  // Used by |cb_| to store errors.
};

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_bool(tablet, false, "Set wifi transmit power mode to tablet mode");
  DEFINE_string(domain, "none",
                "Regulatory domain for wifi transmit power"
                "Options: fcc, eu, rest-of-world, none");
  DEFINE_string(source, "unknown",
                "Trigger source for wifi transmit power"
                "Options: init, tablet_mode, reg_domain,"
                " proximity, udev_event, unknown");
  CHECK(brillo::FlagHelper::Init(argc, argv, "Set wifi transmit power mode",
                                 brillo::FlagHelper::InitFuncType::kReturn));

  base::AtExitManager at_exit_manager;
  power_manager::WifiRegDomain domain = power_manager::WifiRegDomain::NONE;
  power_manager::TriggerSource tr_source =
      power_manager::TriggerSource::UNKNOWN;
  if (FLAGS_domain == "fcc") {
    domain = power_manager::WifiRegDomain::FCC;
  } else if (FLAGS_domain == "eu") {
    domain = power_manager::WifiRegDomain::EU;
  } else if (FLAGS_domain == "rest-of-world") {
    domain = power_manager::WifiRegDomain::REST_OF_WORLD;
  } else if (FLAGS_domain != "none") {
    LOG(ERROR) << "Domain argument \"" << FLAGS_domain
               << "\" is not an "
                  "accepted value. Options: fcc, eu, rest-of-world, none";
    return 1;
  }

  if (FLAGS_source == "init") {
    tr_source = power_manager::TriggerSource::INIT;
  } else if (FLAGS_source == "tablet_mode") {
    tr_source = power_manager::TriggerSource::TABLET_MODE;
  } else if (FLAGS_source == "reg_domain") {
    tr_source = power_manager::TriggerSource::REG_DOMAIN;
  } else if (FLAGS_source == "proximity") {
    tr_source = power_manager::TriggerSource::PROXIMITY;
  } else if (FLAGS_source == "udev_event") {
    tr_source = power_manager::TriggerSource::UDEV_EVENT;
  } else if (FLAGS_source != "unknown") {
    LOG(ERROR) << "Trigger source argument \"" << FLAGS_source
               << "\" is not an "
                  "accepted value. Options: init, tablet_mode,"
                  " reg_domain, proximity, udev_event, unknown";
    return 1;
  }

  return PowerSetter().SetPowerMode(FLAGS_tablet, domain, tr_source) ? 0 : 1;
}
