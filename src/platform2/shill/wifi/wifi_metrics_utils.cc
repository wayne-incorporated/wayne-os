// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_metrics_utils.h"

#include <string>

#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

#include "shill/metrics.h"

namespace shill::WiFiMetricsUtils {

namespace {

constexpr char kBootIdProcPath[] = "/proc/sys/kernel/random/boot_id";

// List of WiFi adapters that have been added to AVL.
// TODO(b/229020553): Instead of hardcoding the list here and in other places
// (e.g. Tast), use a single source of truth.
constexpr Metrics::WiFiAdapterInfo AVLWiFiAdapters[] = {
    {0x02df, 0x912d,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Marvell88w8897SDIO,
    {0x1b4b, 0x2b42,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Marvell88w8997PCIE,
    {0x168c, 0x003e,
     Metrics::kWiFiStructuredMetricsErrorValue},  // QualcommAtherosQCA6174,
    {0x0271, 0x050a,
     Metrics::kWiFiStructuredMetricsErrorValue},  // QualcommAtherosQCA6174SDIO,
    {0x17cb, 0x1103,
     Metrics::kWiFiStructuredMetricsErrorValue},  // QualcommWCN6855,
    {0x8086, 0x08b1, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7260,
    {0x8086, 0x08b2, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7260,
    {0x8086, 0x095a, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7265,
    {0x8086, 0x095b, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel7265,
    // Note that Intel 9000 is also Intel 9560 aka Jefferson Peak 2
    {0x8086, 0x9df0, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel9000,
    {0x8086, 0x31dc, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel9000,
    {0x8086, 0x2526, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel9260,
    {0x8086, 0x2723, Metrics::kWiFiStructuredMetricsErrorValue},  // Intel22260,
    // For integrated wifi chips, use device_id and subsystem_id together
    // as an identifier.
    // 0x02f0 is for Quasar on CML; 0x4070, 0x0074, 0x6074 are for HrP2.
    {0x8086, 0x02f0, 0x0034},  // Intel9000,
    {0x8086, 0x02f0, 0x4070},  // Intel22560,
    {0x8086, 0x02f0, 0x0074},  // Intel22560,
    {0x8086, 0x02f0, 0x6074},  // Intel22560,
    {0x8086, 0x4df0, 0x0070},  // Intel22560,
    {0x8086, 0x4df0, 0x4070},  // Intel22560,
    {0x8086, 0x4df0, 0x0074},  // Intel22560,
    {0x8086, 0x4df0, 0x6074},  // Intel22560,
    {0x8086, 0xa0f0, 0x4070},  // Intel22560,
    {0x8086, 0xa0f0, 0x0074},  // Intel22560,
    {0x8086, 0xa0f0, 0x6074},  // Intel22560,
    {0x8086, 0x51f0, 0x0090},  // IntelAX211,
    {0x8086, 0x51f1, 0x0090},  // IntelAX211,
    {0x8086, 0x51f1, 0x0094},  // IntelAX211,
    {0x8086, 0x51f0, 0x0094},  // IntelAX211,
    {0x8086, 0x51f0, 0x4094},  // IntelAX211,
    {0x8086, 0x54f0, 0x0090},  // IntelAX211,
    {0x8086, 0x54f0, 0x0094},  // IntelAX211,
    {0x8086, 0x7e40, 0x0090},  // IntelAX211,
    {0x8086, 0x7e40, 0x0094},  // IntelAX211,
    {0x14e4, 0x43ec,
     Metrics::kWiFiStructuredMetricsErrorValue},  // BroadcomBCM4356PCIE,
    {0x10ec, 0xc822,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Realtek8822CPCIE,
    {0x10ec, 0x8852,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Realtek8852APCIE,
    {0x10ec, 0xc852,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Realtek8852CPCIE,
    {0x14c3, 0x7961,
     Metrics::kWiFiStructuredMetricsErrorValue},  // MediaTekMT7921PCIE,
    {0x037a, 0x7901,
     Metrics::kWiFiStructuredMetricsErrorValue},  // MediaTekMT7921SDIO,
    {Metrics::kWiFiIntegratedAdapterVendorId, 3990,
     Metrics::kWiFiStructuredMetricsErrorValue},  // Qualcomm WCN3990 integrated
                                                  // chipset,
    {Metrics::kWiFiIntegratedAdapterVendorId, 6750,
     Metrics::kWiFiStructuredMetricsErrorValue}  // Qualcomm WCN6750 integrated
                                                 // chipset,
};

// List of OUIs of popular APs, per go/cros-wifi-popular-ap-oui.
constexpr int OUIAllowList[] = {
    0xD88466, 0x348584, 0x1C28AF, 0xD0D3E0, 0xDCB808, 0x00D01D, 0xF4EAB5,
    0xC413E2, 0xC8B5AD, 0xBCF310, 0xD854A2, 0x3817C3, 0x20A6CD, 0x04BD88,
    0x2462CE, 0xC8675E, 0xA8BD27, 0x34FCB9, 0x9C5D12, 0x8A1514, 0xF42E7F,
    0x90B832, 0xB8F853, 0x94B40F, 0xE2CBAC, 0x9A1898, 0x40E3D6, 0x38FF36,
    0x84D47E, 0x9C8CD8, 0xFA9E38, 0xB0B867, 0x904C81, 0x1006ED, 0x808DB7,
    0xB45D50, 0x703A0E, 0x4448C1, 0x2E3F1B, 0x004E35, 0xE6CBAC, 0x0027E3,
    0x58B633, 0xFE9E38, 0xFC7FF1, 0x800384, 0xBC9FE4, 0xF05C19, 0xE82689,
    0x48C093, 0x4C195D, 0xCC88C7, 0x000CE6, 0x3CBDC5, 0x186472, 0xCCDB93,
    0x5859C2, 0xACA31E, 0x488B0A, 0xE0DBD1, 0x00D78F, 0x0E8DCB, 0x885BDD,
    0x28B371, 0xFCECDA, 0xE063DA, 0x484AE9, 0x3453D2, 0x84F147, 0x485D36,
    0x68D79A, 0x00F663, 0xF09FC2, 0x60D02C, 0x1CD1E0, 0xF85B3B, 0xB8114B,
    0xAA468D, 0x802AA8, 0x6026EF, 0x7483C2, 0xD015A6, 0x24792A, 0x1C3A60,
    0x743E2B, 0x5CDF89, 0x00DCB2, 0xA4CFD2, 0x5C7D7D, 0xAE468D, 0xF4DBE6,
    0x100C6B, 0x2CC5D3, 0x2CEADC, 0x8C7A15, 0xCC167E, 0xF46942, 0xDC8C37,
    0x3C3786, 0x54EC2F, 0xF85E42, 0xE01C41, 0xE2556D, 0xA8705D, 0x002A10,
    0xAE17D8, 0x8A1554, 0x9E1898, 0x263F1B, 0x506028, 0x18E829, 0xEACBAC,
    0xBCA511, 0xAA17D8, 0x6CC49F, 0x40017A, 0x8CFE74, 0x58FB96, 0x88DE7C,
    0x24F27F, 0x2A3F1B, 0x3087D9, 0x3420E3, 0x5C5AC7, 0xA48873, 0x205869,
    0x788A20, 0x3894ED, 0x10868C, 0xF417B8, 0xD04DC6, 0xA49733, 0x0A8DCB,
    0x147D05, 0x74ACB9, 0xC09435, 0x989D5D, 0x6CCDD6, 0x188090, 0x842388,
    0xE44E2D, 0xEECBAC, 0x500F80, 0x209EF7, 0x946424, 0xC8B422, 0x20C047,
    0x9CC9EB, 0xB4FBE4, 0xC4411E, 0x7CDB98, 0xE4BFFA, 0xF492BF, 0x78BC1A,
    0xACF8CC, 0x02185A, 0xB83A5A, 0x04A222, 0xD8B190, 0x94A67E, 0x9C3426,
    0x78725D, 0x94B34F, 0x7C573C, 0xEC8CA2, 0x78D294, 0x6C4BB4, 0x0CF4D5,
    0x6ED79A, 0xA0B439, 0x44A56E, 0xAC4CA5, 0xCC40D0, 0x08A7C0, 0xF2CBAC,
    0x5C8FE0, 0xEC58EA, 0x70B317, 0x1C9ECC, 0xF08175, 0x58278C, 0xD0768F,
    0xACDB48, 0xD6351D, 0xE89F80, 0xE6552D, 0xA09351, 0x8C6A8D, 0x046273,
    0x0081C4, 0x484BD4, 0x3C7A8A, 0x04AB18, 0x38700C, 0x441E98, 0x1C9D72,
    0x40E1E4, 0x184B0D, 0xFC5C45, 0x784558,
};

}  // namespace

int AllowlistedOUIForTesting() {
  return OUIAllowList[0];
}

bool CanReportOUI(int oui) {
  return base::Contains(OUIAllowList, oui);
}

bool CanReportAdapterInfo(const Metrics::WiFiAdapterInfo& info) {
  for (const auto& item : AVLWiFiAdapters) {
    if (item.vendor_id == info.vendor_id &&
        item.product_id == info.product_id &&
        (item.subsystem_id == info.subsystem_id ||
         item.subsystem_id == Metrics::kWiFiStructuredMetricsErrorValue))
      return true;
  }
  return false;
}

std::string GetBootId() {
  std::string boot_id;
  if (!base::ReadFileToString(base::FilePath(kBootIdProcPath), &boot_id)) {
    LOG(ERROR) << "Failed to read boot_id";
    return std::string();
  }
  base::RemoveChars(boot_id, "-\r\n", &boot_id);
  return boot_id;
}

Metrics::BTProfileConnectionState ConvertBTProfileConnectionState(
    BluetoothManagerInterface::BTProfileConnectionState state) {
  switch (state) {
    case BluetoothManagerInterface::BTProfileConnectionState::kDisconnected:
      return Metrics::kBTProfileConnectionStateDisconnected;
    case BluetoothManagerInterface::BTProfileConnectionState::kDisconnecting:
      return Metrics::kBTProfileConnectionStateDisconnecting;
    case BluetoothManagerInterface::BTProfileConnectionState::kConnecting:
      return Metrics::kBTProfileConnectionStateConnecting;
    case BluetoothManagerInterface::BTProfileConnectionState::kConnected:
      return Metrics::kBTProfileConnectionStateConnected;
    case BluetoothManagerInterface::BTProfileConnectionState::kActive:
      return Metrics::kBTProfileConnectionStateActive;
    case BluetoothManagerInterface::BTProfileConnectionState::kInvalid:
      return Metrics::kBTProfileConnectionStateInvalid;
  }
}

}  // namespace shill::WiFiMetricsUtils
