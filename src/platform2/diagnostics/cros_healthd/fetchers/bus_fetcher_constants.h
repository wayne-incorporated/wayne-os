// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BUS_FETCHER_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BUS_FETCHER_CONSTANTS_H_

namespace diagnostics {

inline constexpr char kPathSysPci[] = "sys/bus/pci/devices/";
inline constexpr char kPathSysUsb[] = "sys/bus/usb/devices/";
inline constexpr char kPathSysThunderbolt[] = "sys/bus/thunderbolt/devices/";

inline constexpr char kFileDriver[] = "driver";

inline constexpr char kFilePciClass[] = "class";
inline constexpr char kFilePciDevice[] = "device";
inline constexpr char kFilePciVendor[] = "vendor";
inline constexpr char kFilePciSubDevice[] = "subsystem_device";
inline constexpr char kFilePciSubVendor[] = "subsystem_vendor";

#define GET_BYTE_(val, id) ((val >> (id * 8)) & 0xFF)
#define GET_PCI_CLASS(val) GET_BYTE_(val, 2)
#define GET_PCI_SUBCLASS(val) GET_BYTE_(val, 1)
#define GET_PCI_PROG_IF(val) GET_BYTE_(val, 0)

inline constexpr char kFileThunderboltAuthorized[] = "authorized";
inline constexpr char kFileThunderboltSecurity[] = "security";
inline constexpr char kFileThunderboltRxSpeed[] = "rx_speed";
inline constexpr char kFileThunderboltTxSpeed[] = "tx_speed";
inline constexpr char kFileThunderboltVendorName[] = "vendor_name";
inline constexpr char kFileThunderboltDeviceName[] = "device_name";
inline constexpr char kFileThunderboltDeviceType[] = "device";
inline constexpr char kFileThunderboltUUID[] = "unique_id";
inline constexpr char kFileThunderboltFWVer[] = "nvm_version";

// The classes of pci / usb ids. See https://github.com/gentoo/hwids.
// clang-format off
namespace pci_ids {
  namespace network {  // NOLINT(runtime/indentation_namespace)
    inline constexpr uint8_t kId = 0x02;
    namespace ethernet {  // NOLINT(runtime/indentation_namespace)
      inline constexpr uint8_t kId = 0x00;
    }
    namespace network {  // NOLINT(runtime/indentation_namespace)
      inline constexpr uint8_t kId = 0x80;
    }
  }
  namespace display {  // NOLINT(runtime/indentation_namespace)
    inline constexpr uint8_t kId = 0x03;
  }
}  // namespace pci_ids

namespace usb_ids {
  namespace wireless {  // NOLINT(runtime/indentation_namespace)
    inline constexpr uint8_t kId = 0xe0;
    namespace radio_frequency {  // NOLINT(runtime/indentation_namespace)
      inline constexpr uint8_t kId = 0x01;
      namespace bluetooth {  // NOLINT(runtime/indentation_namespace)
        inline constexpr uint8_t kId = 0x01;
      }
    }
  }
}  // namespace usb_ids
// clang-format on

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BUS_FETCHER_CONSTANTS_H_
