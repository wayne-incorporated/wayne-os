// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_REFPTR_TYPES_H_
#define SHILL_REFPTR_TYPES_H_

#include <base/memory/ref_counted.h>

namespace shill {

class Device;
using DeviceConstRefPtr = scoped_refptr<const Device>;
using DeviceRefPtr = scoped_refptr<Device>;

class Cellular;
using CellularConstRefPtr = scoped_refptr<const Cellular>;
using CellularRefPtr = scoped_refptr<Cellular>;

class Ethernet;
using EthernetConstRefPtr = scoped_refptr<const Ethernet>;
using EthernetRefPtr = scoped_refptr<Ethernet>;

class VirtualDevice;
using VirtualDeviceConstRefPtr = scoped_refptr<const VirtualDevice>;
using VirtualDeviceRefPtr = scoped_refptr<VirtualDevice>;

class WiFi;
using WiFiConstRefPtr = scoped_refptr<const WiFi>;
using WiFiRefPtr = scoped_refptr<WiFi>;

class WiFiEndpoint;
using WiFiEndpointConstRefPtr = scoped_refptr<const WiFiEndpoint>;
using WiFiEndpointRefPtr = scoped_refptr<WiFiEndpoint>;

class PasspointCredentials;
using PasspointCredentialsConstRefPtr =
    scoped_refptr<const PasspointCredentials>;
using PasspointCredentialsRefPtr = scoped_refptr<PasspointCredentials>;

class Service;
using ServiceConstRefPtr = scoped_refptr<const Service>;
using ServiceRefPtr = scoped_refptr<Service>;

class CellularService;
using CellularServiceConstRefPtr = scoped_refptr<const CellularService>;
using CellularServiceRefPtr = scoped_refptr<CellularService>;

class EthernetService;
using EthernetServiceConstRefPtr = scoped_refptr<const EthernetService>;
using EthernetServiceRefPtr = scoped_refptr<EthernetService>;

class VPNService;
using VPNServiceConstRefPtr = scoped_refptr<const VPNService>;
using VPNServiceRefPtr = scoped_refptr<VPNService>;

class WiFiService;
using WiFiServiceConstRefPtr = scoped_refptr<const WiFiService>;
using WiFiServiceRefPtr = scoped_refptr<WiFiService>;

class Profile;
using ProfileConstRefPtr = scoped_refptr<const Profile>;
using ProfileRefPtr = scoped_refptr<Profile>;

class LocalDevice;
using LocalDeviceConstRefPtr = scoped_refptr<const LocalDevice>;
using LocalDeviceRefPtr = scoped_refptr<LocalDevice>;

class HotspotDevice;
using HotspotDeviceConstRefPtr = scoped_refptr<const HotspotDevice>;
using HotspotDeviceRefPtr = scoped_refptr<HotspotDevice>;

}  // namespace shill

#endif  // SHILL_REFPTR_TYPES_H_
