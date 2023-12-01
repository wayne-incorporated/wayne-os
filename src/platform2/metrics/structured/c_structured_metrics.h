// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_STRUCTURED_C_STRUCTURED_METRICS_H_
#define METRICS_STRUCTURED_C_STRUCTURED_METRICS_H_

#include <stdint.h>

#include <brillo/brillo_export.h>

#if defined(__cplusplus)
extern "C" {
#endif

// C wrapper for
// metrics::structured::events::bluetooth::BluetoothAdapterStateChanged.
BRILLO_EXPORT void BluetoothAdapterStateChanged(const char* boot_id,
                                                int64_t system_time,
                                                bool is_floss,
                                                int state);

// C wrapper for
// metrics::structured::events::bluetooth::BluetoothPairingStateChanged.
BRILLO_EXPORT void BluetoothPairingStateChanged(const char* boot_id,
                                                int64_t system_time,
                                                const char* device_id,
                                                int device_type,
                                                int state);

// C wrapper for
// metrics::structured::events::bluetooth::BluetoothAclConnectionStateChanged.
BRILLO_EXPORT void BluetoothAclConnectionStateChanged(const char* boot_id,
                                                      int64_t system_time,
                                                      bool is_floss,
                                                      const char* device_id,
                                                      int device_type,
                                                      int connection_direction,
                                                      int connection_initiator,
                                                      int state_change_type,
                                                      int state);

// C wrapper for
// metrics::structured::events::bluetooth::
// BluetoothProfileConnectionStateChanged.
BRILLO_EXPORT void BluetoothProfileConnectionStateChanged(const char* boot_id,
                                                          int64_t system_time,
                                                          const char* device_id,
                                                          int state_change_type,
                                                          int profile,
                                                          int state);

// C wrapper for
// metrics::structured::events::bluetooth::BluetoothDeviceInfoReport.
BRILLO_EXPORT void BluetoothDeviceInfoReport(const char* boot_id,
                                             int64_t system_time,
                                             const char* device_id,
                                             int device_type,
                                             int device_class,
                                             int device_category,
                                             int vendor_id,
                                             int vendor_id_source,
                                             int product_id,
                                             int product_version);

// C wrapper for
// metrics::structured::events::bluetooth::BluetoothAudioQualityReport.
BRILLO_EXPORT void BluetoothAudioQualityReport(const char* boot_id,
                                               int64_t system_time,
                                               const char* device_id,
                                               int profile,
                                               int quality_type,
                                               int64_t average,
                                               int64_t std_dev,
                                               int64_t percentile95);

// C wrapper for
// metrics::structured::events::bluetooth::BluetoothChipsetInfoReport.
BRILLO_EXPORT void BluetoothChipsetInfoReport(const char* boot_id,
                                              int vendor_id,
                                              int product_id,
                                              int transport,
                                              uint64_t chipset_string_hval);

// C wrapper for
// metrics::structured::events::bluetooth_device::BluetoothDeviceInfo.
BRILLO_EXPORT void BluetoothDeviceInfo(int device_type,
                                       int device_class,
                                       int device_category,
                                       int vendor_id,
                                       int vendor_id_source,
                                       int product_id,
                                       int product_version);

// C wrapper for
// metrics::structured::events::bluetooth_chipset::BluetoothChipsetInfo.
BRILLO_EXPORT void BluetoothChipsetInfo(int vendor_id,
                                        int product_id,
                                        int transport,
                                        const char* chipset_string);
#if defined(__cplusplus)
}
#endif
#endif  // METRICS_STRUCTURED_C_STRUCTURED_METRICS_H_
