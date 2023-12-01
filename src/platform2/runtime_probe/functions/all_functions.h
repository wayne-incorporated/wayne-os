// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_ALL_FUNCTIONS_H_
#define RUNTIME_PROBE_FUNCTIONS_ALL_FUNCTIONS_H_

// TODO(stimim): auto generate this file.

#include "runtime_probe/function_templates/network.h"
#include "runtime_probe/functions/ap_i2c.h"
#include "runtime_probe/functions/ata_storage.h"
#include "runtime_probe/functions/audio_codec.h"
#include "runtime_probe/functions/cellular_network.h"
#include "runtime_probe/functions/ec_i2c.h"
#include "runtime_probe/functions/edid.h"
#include "runtime_probe/functions/ethernet_network.h"
#include "runtime_probe/functions/generic_battery.h"
#include "runtime_probe/functions/generic_camera.h"
#include "runtime_probe/functions/generic_network.h"
#include "runtime_probe/functions/generic_storage.h"
#include "runtime_probe/functions/gpu.h"
#include "runtime_probe/functions/input_device.h"
#include "runtime_probe/functions/memory.h"
#include "runtime_probe/functions/mipi_camera.h"
#include "runtime_probe/functions/mmc_host.h"
#include "runtime_probe/functions/mmc_storage.h"
#include "runtime_probe/functions/nvme_storage.h"
#include "runtime_probe/functions/sequence.h"
#include "runtime_probe/functions/shell.h"
#include "runtime_probe/functions/sysfs.h"
#include "runtime_probe/functions/tcpc.h"
#include "runtime_probe/functions/ufs_storage.h"
#include "runtime_probe/functions/usb_camera.h"
#include "runtime_probe/functions/vpd_cached.h"
#include "runtime_probe/functions/wireless_network.h"

namespace runtime_probe {

using AllFunctions = ProbeFunctions<ApI2cFunction,
                                    AtaStorageFunction,
                                    AudioCodecFunction,
                                    CellularNetworkFunction,
                                    EcI2cFunction,
                                    EdidFunction,
                                    EthernetNetworkFunction,
                                    GenericBattery,
                                    GenericCameraFunction,
                                    GenericNetworkFunction,
                                    GenericStorageFunction,
                                    GpuFunction,
                                    InputDeviceFunction,
                                    MemoryFunction,
                                    MipiCameraFunction,
                                    MmcHostFunction,
                                    MmcStorageFunction,
                                    NetworkFunction,
                                    NvmeStorageFunction,
                                    SequenceFunction,
                                    ShellFunction,
                                    SysfsFunction,
                                    TcpcFunction,
                                    UfsStorageFunction,
                                    UsbCameraFunction,
                                    VPDCached,
                                    WirelessNetworkFunction>;

using AvlAllowedProbeFunctions = ProbeFunctions<AtaStorageFunction,
                                                AudioCodecFunction,
                                                CellularNetworkFunction,
                                                EdidFunction,
                                                EthernetNetworkFunction,
                                                GenericBattery,
                                                GenericCameraFunction,
                                                GenericNetworkFunction,
                                                GenericStorageFunction,
                                                GpuFunction,
                                                InputDeviceFunction,
                                                MemoryFunction,
                                                MipiCameraFunction,
                                                MmcHostFunction,
                                                MmcStorageFunction,
                                                NetworkFunction,
                                                NvmeStorageFunction,
                                                TcpcFunction,
                                                UfsStorageFunction,
                                                UsbCameraFunction,
                                                WirelessNetworkFunction>;

using SsfcAllowedProbeFunctions =
    ProbeFunctions<ApI2cFunction, EcI2cFunction, TcpcFunction>;
}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_ALL_FUNCTIONS_H_
