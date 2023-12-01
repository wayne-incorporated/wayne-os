// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/output_util.h"

#include <iostream>
#include <utility>
#include <vector>

#include <base/json/json_writer.h>
#include <base/strings/string_number_conversions.h>
#include <base/values.h>

#include "diagnostics/mojom/external/network_health_types.mojom.h"
#include "diagnostics/mojom/external/network_types.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;
namespace network_config_mojom = ::chromeos::network_config::mojom;
namespace network_health_mojom = ::chromeos::network_health::mojom;

}  // namespace

std::string EnumToString(mojom::ProcessState state) {
  switch (state) {
    case mojom::ProcessState::kUnknown:
      return "Unknown";
    case mojom::ProcessState::kRunning:
      return "Running";
    case mojom::ProcessState::kSleeping:
      return "Sleeping";
    case mojom::ProcessState::kWaiting:
      return "Waiting";
    case mojom::ProcessState::kZombie:
      return "Zombie";
    case mojom::ProcessState::kStopped:
      return "Stopped";
    case mojom::ProcessState::kTracingStop:
      return "Tracing Stop";
    case mojom::ProcessState::kDead:
      return "Dead";
    case mojom::ProcessState::kIdle:
      return "Idle";
  }
}

std::string EnumToString(mojom::ErrorType type) {
  switch (type) {
    case mojom::ErrorType::kUnknown:
      return "Unknown Error";
    case mojom::ErrorType::kFileReadError:
      return "File Read Error";
    case mojom::ErrorType::kParseError:
      return "Parse Error";
    case mojom::ErrorType::kSystemUtilityError:
      return "Error running system utility";
    case mojom::ErrorType::kServiceUnavailable:
      return "External service not aviailable";
  }
}

std::string EnumToString(mojom::CpuArchitectureEnum architecture) {
  switch (architecture) {
    case mojom::CpuArchitectureEnum::kUnknown:
      return "unknown";
    case mojom::CpuArchitectureEnum::kX86_64:
      return "x86_64";
    case mojom::CpuArchitectureEnum::kAArch64:
      return "aarch64";
    case mojom::CpuArchitectureEnum::kArmv7l:
      return "armv7l";
  }
}

std::string EnumToString(network_config_mojom::NetworkType type) {
  switch (type) {
    case network_config_mojom::NetworkType::kAll:
      return "Unknown";
    case network_config_mojom::NetworkType::kCellular:
      return "Cellular";
    case network_config_mojom::NetworkType::kEthernet:
      return "Ethernet";
    case network_config_mojom::NetworkType::kMobile:
      return "Mobile";
    case network_config_mojom::NetworkType::kTether:
      return "Tether";
    case network_config_mojom::NetworkType::kVPN:
      return "VPN";
    case network_config_mojom::NetworkType::kWireless:
      return "Wireless";
    case network_config_mojom::NetworkType::kWiFi:
      return "WiFi";
  }
}

std::string EnumToString(network_health_mojom::NetworkState state) {
  switch (state) {
    case network_health_mojom::NetworkState::kUninitialized:
      return "Uninitialized";
    case network_health_mojom::NetworkState::kDisabled:
      return "Disabled";
    case network_health_mojom::NetworkState::kProhibited:
      return "Prohibited";
    case network_health_mojom::NetworkState::kNotConnected:
      return "Not Connected";
    case network_health_mojom::NetworkState::kConnecting:
      return "Connecting";
    case network_health_mojom::NetworkState::kPortal:
      return "Portal";
    case network_health_mojom::NetworkState::kConnected:
      return "Connected";
    case network_health_mojom::NetworkState::kOnline:
      return "Online";
  }
}

std::string EnumToString(network_config_mojom::PortalState state) {
  switch (state) {
    case network_config_mojom::PortalState::kUnknown:
      return "Unknown";
    case network_config_mojom::PortalState::kOnline:
      return "Online";
    case network_config_mojom::PortalState::kPortalSuspected:
      return "Portal Suspected";
    case network_config_mojom::PortalState::kPortal:
      return "Portal Detected";
    case network_config_mojom::PortalState::kProxyAuthRequired:
      return "Proxy Auth Required";
    case network_config_mojom::PortalState::kNoInternet:
      return "No Internet";
  }
}

std::string EnumToString(mojom::EncryptionState encryption_state) {
  switch (encryption_state) {
    case mojom::EncryptionState::kEncryptionDisabled:
      return "Memory encryption disabled";
    case mojom::EncryptionState::kTmeEnabled:
      return "TME enabled";
    case mojom::EncryptionState::kMktmeEnabled:
      return "MKTME enabled";
    case mojom::EncryptionState::kUnknown:
      return "Unknown state";
  }
}

std::string EnumToString(mojom::CryptoAlgorithm algorithm) {
  switch (algorithm) {
    case mojom::CryptoAlgorithm::kAesXts128:
      return "AES-XTS-128";
    case mojom::CryptoAlgorithm::kAesXts256:
      return "AES-XTS-256";
    case mojom::CryptoAlgorithm::kUnknown:
      return "Invalid Algorithm";
  }
}

std::string EnumToString(mojom::BusDeviceClass device_class) {
  switch (device_class) {
    case mojom::BusDeviceClass::kOthers:
      return "others";
    case mojom::BusDeviceClass::kDisplayController:
      return "display controller";
    case mojom::BusDeviceClass::kEthernetController:
      return "ethernet controller";
    case mojom::BusDeviceClass::kWirelessController:
      return "wireless controller";
    case mojom::BusDeviceClass::kBluetoothAdapter:
      return "bluetooth controller";
    case mojom::BusDeviceClass::kThunderboltController:
      return "thunderbolt controller";
    case mojom::BusDeviceClass::kAudioCard:
      return "audio card";
  }
}

// The conversion, except for kUnmappedEnumField, follows the function
// |fwupd_version_format_to_string| in the libfwupd.
std::string EnumToString(mojom::FwupdVersionFormat fwupd_version_format) {
  switch (fwupd_version_format) {
    case mojom::FwupdVersionFormat::kUnmappedEnumField:

      return "unmapped-enum-field";
    case mojom::FwupdVersionFormat::kUnknown:
      return "unknown";
    case mojom::FwupdVersionFormat::kPlain:
      return "plain";
    case mojom::FwupdVersionFormat::kNumber:
      return "number";
    case mojom::FwupdVersionFormat::kPair:
      return "pair";
    case mojom::FwupdVersionFormat::kTriplet:
      return "triplet";
    case mojom::FwupdVersionFormat::kQuad:
      return "quad";
    case mojom::FwupdVersionFormat::kBcd:
      return "bcd";
    case mojom::FwupdVersionFormat::kIntelMe:
      return "intel-me";
    case mojom::FwupdVersionFormat::kIntelMe2:
      return "intel-me2";
    case mojom::FwupdVersionFormat::kSurfaceLegacy:
      return "surface-legacy";
    case mojom::FwupdVersionFormat::kSurface:
      return "surface";
    case mojom::FwupdVersionFormat::kDellBios:
      return "dell-bios";
    case mojom::FwupdVersionFormat::kHex:
      return "hex";
  }
}

std::string EnumToString(mojom::BootMode mode) {
  switch (mode) {
    case mojom::BootMode::kUnknown:
      return "Unknown";
    case mojom::BootMode::kCrosSecure:
      return "cros_secure";
    case mojom::BootMode::kCrosEfi:
      return "cros_efi";
    case mojom::BootMode::kCrosLegacy:
      return "cros_legacy";
    case mojom::BootMode::kCrosEfiSecure:
      return "cros_efi_secure";
  }
}

std::string EnumToString(mojom::TpmGSCVersion version) {
  switch (version) {
    case mojom::TpmGSCVersion::kNotGSC:
      return "NotGSC";
    case mojom::TpmGSCVersion::kCr50:
      return "Cr50";
    case mojom::TpmGSCVersion::kTi50:
      return "Ti50";
  }
}

std::string EnumToString(mojom::ThunderboltSecurityLevel level) {
  switch (level) {
    case mojom::ThunderboltSecurityLevel::kNone:
      return "None";
    case mojom::ThunderboltSecurityLevel::kUserLevel:
      return "User";
    case mojom::ThunderboltSecurityLevel::kSecureLevel:
      return "Secure";
    case mojom::ThunderboltSecurityLevel::kDpOnlyLevel:
      return "DpOnly";
    case mojom::ThunderboltSecurityLevel::kUsbOnlyLevel:
      return "UsbOnly";
    case mojom::ThunderboltSecurityLevel::kNoPcieLevel:
      return "NoPcie";
  }
}

std::optional<std::string> EnumToString(mojom::BluetoothDeviceType type) {
  switch (type) {
    case mojom::BluetoothDeviceType::kBrEdr:
      return "BR/EDR";
    case mojom::BluetoothDeviceType::kLe:
      return "LE";
    case mojom::BluetoothDeviceType::kDual:
      return "DUAL";
    case mojom::BluetoothDeviceType::kUnfound:
      return std::nullopt;
    case mojom::BluetoothDeviceType::kUnmappedEnumField:
      return std::nullopt;
  }
}

std::string EnumToString(mojom::VulnerabilityInfo::Status status) {
  switch (status) {
    case mojom::VulnerabilityInfo::Status::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::VulnerabilityInfo::Status::kNotAffected:
      return "Not affected";
    case mojom::VulnerabilityInfo::Status::kVulnerable:
      return "Vulnerable";
    case mojom::VulnerabilityInfo::Status::kMitigation:
      return "Mitigation";
    case mojom::VulnerabilityInfo::Status::kUnknown:
      return "Unknown";
    case mojom::VulnerabilityInfo::Status::kUnrecognized:
      return "Unrecognized";
  }
}

std::string EnumToString(mojom::CpuVirtualizationInfo::Type type) {
  switch (type) {
    case mojom::CpuVirtualizationInfo::Type::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::CpuVirtualizationInfo::Type::kVMX:
      return "VMX";
    case mojom::CpuVirtualizationInfo::Type::kSVM:
      return "SVM";
  }
}

std::string EnumToString(mojom::VirtualizationInfo::SMTControl control) {
  switch (control) {
    case mojom::VirtualizationInfo::SMTControl::kUnmappedEnumField:
      return "UnmappedEnumField";
    case mojom::VirtualizationInfo::SMTControl::kOn:
      return "on";
    case mojom::VirtualizationInfo::SMTControl::kOff:
      return "off";
    case mojom::VirtualizationInfo::SMTControl::kForceOff:
      return "forceoff";
    case mojom::VirtualizationInfo::SMTControl::kNotSupported:
      return "notsupported";
    case mojom::VirtualizationInfo::SMTControl::kNotImplemented:
      return "notimplemented";
  }
}

std::string EnumToString(mojom::InputDevice::ConnectionType type) {
  switch (type) {
    case mojom::InputDevice::ConnectionType::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::InputDevice::ConnectionType::kInternal:
      return "Internal";
    case mojom::InputDevice::ConnectionType::kUSB:
      return "USB";
    case mojom::InputDevice::ConnectionType::kBluetooth:
      return "Bluetooth";
    case mojom::InputDevice::ConnectionType::kUnknown:
      return "Unknown";
  }
}

std::optional<std::string> EnumToString(mojom::DisplayInputType type) {
  switch (type) {
    case mojom::DisplayInputType::kDigital:
      return "Digital";
    case mojom::DisplayInputType::kAnalog:
      return "Analog";
    case mojom::DisplayInputType::kUnmappedEnumField:
      return std::nullopt;
  }
}

std::string EnumToString(mojom::OsInfo::EfiPlatformSize size) {
  switch (size) {
    case mojom::OsInfo::EfiPlatformSize::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::OsInfo::EfiPlatformSize::kUnknown:
      return "unknown";
    case mojom::OsInfo::EfiPlatformSize::k64:
      return "64";
    case mojom::OsInfo::EfiPlatformSize::k32:
      return "32";
  }
}

std::string EnumToString(mojom::Sensor::Type type) {
  switch (type) {
    case mojom::Sensor::Type::kUnmappedEnumField:
      return "UnmappedEnumField";
    case mojom::Sensor::Type::kAccel:
      return "Accel";
    case mojom::Sensor::Type::kLight:
      return "Light";
    case mojom::Sensor::Type::kGyro:
      return "Gyro";
    case mojom::Sensor::Type::kAngle:
      return "Angle";
    case mojom::Sensor::Type::kGravity:
      return "Gravity";
    case mojom::Sensor::Type::kMagn:
      return "Magn";
  }
}

std::string EnumToString(mojom::Sensor::Location type) {
  switch (type) {
    case mojom::Sensor::Location::kUnmappedEnumField:
      return "UnmappedEnumField";
    case mojom::Sensor::Location::kUnknown:
      return "Unknown";
    case mojom::Sensor::Location::kBase:
      return "Base";
    case mojom::Sensor::Location::kLid:
      return "Lid";
    case mojom::Sensor::Location::kCamera:
      return "Camera";
  }
}

std::string EnumToString(mojom::UsbVersion version) {
  switch (version) {
    case mojom::UsbVersion::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::UsbVersion::kUnknown:
      return "Unknown";
    case mojom::UsbVersion::kUsb1:
      return "Usb1";
    case mojom::UsbVersion::kUsb2:
      return "Usb2";
    case mojom::UsbVersion::kUsb3:
      return "Usb3";
  }
}

std::string EnumToString(mojom::UsbSpecSpeed spec_speed) {
  switch (spec_speed) {
    case mojom::UsbSpecSpeed::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::UsbSpecSpeed::kUnknown:
      return "Unknown";
    case mojom::UsbSpecSpeed::k1_5Mbps:
      return "1.5";
    case mojom::UsbSpecSpeed::k12Mbps:
      return "12";
    case mojom::UsbSpecSpeed::kDeprecateSpeed:
      LOG(FATAL) << "Got Deprecated";
      return "Deprecated";
    case mojom::UsbSpecSpeed::k480Mbps:
      return "480";
    case mojom::UsbSpecSpeed::k5Gbps:
      return "5000";
    case mojom::UsbSpecSpeed::k10Gbps:
      return "10000";
    case mojom::UsbSpecSpeed::k20Gbps:
      return "20000";
  }
}

std::string EnumToString(mojom::PsrInfo::LogState state) {
  switch (state) {
    case mojom::PsrInfo::LogState::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::PsrInfo::LogState::kStarted:
      return "Started";
    case mojom::PsrInfo::LogState::kNotStarted:
      return "NotStarted";
    case mojom::PsrInfo::LogState::kStopped:
      return "Stopped";
  }
}

std::string EnumToString(mojom::PsrEvent::EventType type) {
  switch (type) {
    case mojom::PsrEvent::EventType::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "UnmappedEnumField";
    case mojom::PsrEvent::EventType::kLogStart:
      return "LogStarted";
    case mojom::PsrEvent::EventType::kLogEnd:
      return "LogEnd";
    case mojom::PsrEvent::EventType::kPrtcFailure:
      return "PrtcFailure";
    case mojom::PsrEvent::EventType::kCsmeRecovery:
      return "CsmeRecovery";
    case mojom::PsrEvent::EventType::kSvnIncrease:
      return "SvnIncrease";
  }
}

std::string EnumToString(mojom::MemtesterTestItemEnum test_item) {
  switch (test_item) {
    case mojom::MemtesterTestItemEnum::kStuckAddress:
      return "StuckAddress";
    case mojom::MemtesterTestItemEnum::kCompareAND:
      return "CompareAND";
    case mojom::MemtesterTestItemEnum::kCompareDIV:
      return "CompareDIV";
    case mojom::MemtesterTestItemEnum::kCompareMUL:
      return "CompareMUL";
    case mojom::MemtesterTestItemEnum::kCompareOR:
      return "CompareOR";
    case mojom::MemtesterTestItemEnum::kCompareSUB:
      return "CompareSUB";
    case mojom::MemtesterTestItemEnum::kCompareXOR:
      return "CompareXOR";
    case mojom::MemtesterTestItemEnum::kSequentialIncrement:
      return "SequentialIncrement";
    case mojom::MemtesterTestItemEnum::kBitFlip:
      return "BitFlip";
    case mojom::MemtesterTestItemEnum::kBitSpread:
      return "BitSpread";
    case mojom::MemtesterTestItemEnum::kBlockSequential:
      return "BlockSequential";
    case mojom::MemtesterTestItemEnum::kCheckerboard:
      return "Checkerboard";
    case mojom::MemtesterTestItemEnum::kRandomValue:
      return "RandomValue";
    case mojom::MemtesterTestItemEnum::kSolidBits:
      return "SolidBits";
    case mojom::MemtesterTestItemEnum::kWalkingOnes:
      return "WalkingOnes";
    case mojom::MemtesterTestItemEnum::kWalkingZeroes:
      return "WalkingZeroes";
    case mojom::MemtesterTestItemEnum::k8BitWrites:
      return "8-bitWrites";
    case mojom::MemtesterTestItemEnum::k16BitWrites:
      return "16-bitWrites";
    case mojom::MemtesterTestItemEnum::kUnknown:
      return "Unknown";
    case mojom::MemtesterTestItemEnum::kUnmappedEnumField:
      LOG(FATAL) << "Got UnmappedEnumField";
      return "Unmapped Enum Field";
  }
}

void OutputJson(const base::Value::Dict& output) {
  std::string json;
  base::JSONWriter::WriteWithOptions(
      output, base::JSONWriter::Options::OPTIONS_PRETTY_PRINT, &json);

  std::cout << json << std::endl;
}

void OutputSingleLineJson(const base::Value::Dict& output) {
  std::string json;
  base::JSONWriter::Write(output, &json);
  std::cout << json << std::endl;
}

void OutputSupportStatus(const mojom::SupportStatusPtr status) {
  base::Value::Dict output;

  switch (status->which()) {
    case mojom::SupportStatus::Tag::kUnmappedUnionField:
      LOG(FATAL) << "Got mojom::SupportStatus::Tag::kUnmappedUnionField";
      break;
    case mojom::SupportStatus::Tag::kException:
      output.Set("status", "Exception");
      output.Set("debug_message", status->get_exception()->debug_message);
      break;
    case mojom::SupportStatus::Tag::kSupported:
      output.Set("status", "Supported");
      break;
    case mojom::SupportStatus::Tag::kUnsupported:
      output.Set("status", "Not supported");
      output.Set("debug_message", status->get_unsupported()->debug_message);
      break;
  }

  OutputJson(output);
}

}  // namespace diagnostics
