// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/mojo_type_utils.h"

#include <optional>

#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace ash::cros_healthd::mojom {

bool operator<(const BusInfo& a, const BusInfo& b) {
  if (a.which() != b.which())
    return a.which() < b.which();
  switch (a.which()) {
    case BusInfo::Tag::kPciBusInfo:
      return a.get_pci_bus_info() < b.get_pci_bus_info();
    case BusInfo::Tag::kUsbBusInfo:
      return a.get_usb_bus_info() < b.get_usb_bus_info();
    case BusInfo::Tag::kThunderboltBusInfo:
      return a.get_thunderbolt_bus_info() < b.get_thunderbolt_bus_info();
    case BusInfo::Tag::kUnmappedField:
      return a.get_unmapped_field() < b.get_unmapped_field();
  }
}

}  // namespace ash::cros_healthd::mojom

namespace diagnostics {
namespace internal {
// For each line, adds a 2-space-indent at the beginning.
std::string Indent(const std::string& s) {
  const auto prefix = "  ";
  std::string res;
  for (const auto& line :
       SplitString(s, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    res += prefix + line + "\n";
  }
  return res;
}

std::string StringCompareFormat(const std::string& a, const std::string& b) {
  return "'" + a + "' vs '" + b + "'";
}
}  // namespace internal
namespace {

using internal::Indent;
using internal::kEqualStr;
using internal::kNullStr;
using internal::StringCompareFormat;

const auto kMissingMessage =
    "It is possible that some fields are missing in GetDiffString.";

namespace mojom = ::ash::cros_healthd::mojom;

template <typename MojoType>
class CompareHelper {
 public:
  CompareHelper(const MojoType& a, const MojoType& b) : a_(a), b_(b) {}

  template <typename Field>
  CompareHelper& AddField(const std::string& label,
                          const Field& a_field,
                          const Field& b_field) {
    if (a_field != b_field)
      res_ += label + ":\n" + Indent(GetDiffString(a_field, b_field));
    return *this;
  }

  template <typename Field>
  CompareHelper& AddUnion(const std::string& label,
                          const Field* a_field,
                          const Field* b_field) {
    if (a_field)
      a_type_ = "type[" + label + "]";
    if (b_field)
      b_type_ = "type[" + label + "]";
    if (!a_field || !b_field)
      return *this;
    return AddField(label, *a_field, *b_field);
  }

  std::string GetResult() {
    if constexpr (IsMojoUnion<MojoType>::value) {
      // Mojo union
      CHECK(a_type_ != "" && b_type_ != "")
          << "Missing type info. " << kMissingMessage;
      if (a_.which() != b_.which())
        res_ = StringCompareFormat(a_type_, b_type_);
    } else {
      // Mojo struct
      if (res_ == "") {
        CHECK(a_ == b_) << "The structs do not equal to each other, while all "
                           "the fields are "
                           "equal. "
                        << kMissingMessage;
        res_ = kEqualStr;
      }
    }
    return res_;
  }

 private:
  const MojoType& a_;
  const MojoType& b_;
  std::string res_;
  std::string a_type_;
  std::string b_type_;
};

// Helper macro for defining the |GetDiffString| of mojo structs. See below
// definitions of |GetDiffString| for the usage.
#define FIELD(label) AddField(#label, a.label, b.label)

#define UNION(label)                                              \
  AddUnion(#label, (a.is_##label() ? &a.get_##label() : nullptr), \
           (b.is_##label() ? &b.get_##label() : nullptr))
}  // namespace

template <>
std::string GetDiffString<std::string>(const std::string& a,
                                       const std::string& b) {
  if (a == b)
    return kEqualStr;
  return StringCompareFormat(a, b);
}

template <>
std::string GetDiffString<std::optional<std::string>>(
    const std::optional<std::string>& a, const std::optional<std::string>& b) {
  if (a == b)
    return kEqualStr;
  return StringCompareFormat(a.value_or(kNullStr), b.value_or(kNullStr));
}

template <>
std::string GetDiffString<mojom::NullableUint64>(
    const mojom::NullableUint64& a, const mojom::NullableUint64& b) {
  return GetDiffString(base::NumberToString(a.value),
                       base::NumberToString(b.value));
}

template <>
std::string GetDiffString<mojom::NullableUint16>(
    const mojom::NullableUint16& a, const mojom::NullableUint16& b) {
  return GetDiffString(base::NumberToString(a.value),
                       base::NumberToString(b.value));
}

template <>
std::string GetDiffString<mojom::VpdInfo>(const mojom::VpdInfo& a,
                                          const mojom::VpdInfo& b) {
  return CompareHelper(a, b)
      .FIELD(activate_date)
      .FIELD(mfg_date)
      .FIELD(model_name)
      .FIELD(region)
      .FIELD(serial_number)
      .FIELD(sku_number)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::DmiInfo>(const mojom::DmiInfo& a,
                                          const mojom::DmiInfo& b) {
  return CompareHelper(a, b)
      .FIELD(bios_vendor)
      .FIELD(bios_version)
      .FIELD(board_name)
      .FIELD(board_vendor)
      .FIELD(board_version)
      .FIELD(chassis_vendor)
      .FIELD(chassis_type)
      .FIELD(product_family)
      .FIELD(product_name)
      .FIELD(product_version)
      .FIELD(sys_vendor)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::OsVersion>(const mojom::OsVersion& a,
                                            const mojom::OsVersion& b) {
  return CompareHelper(a, b)
      .FIELD(release_milestone)
      .FIELD(build_number)
      .FIELD(branch_number)
      .FIELD(patch_number)
      .FIELD(release_channel)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::OsInfo>(const mojom::OsInfo& a,
                                         const mojom::OsInfo& b) {
  return CompareHelper(a, b)
      .FIELD(code_name)
      .FIELD(marketing_name)
      .FIELD(oem_name)
      .FIELD(boot_mode)
      .FIELD(os_version)
      .FIELD(efi_platform_size)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::PsrInfo>(const mojom::PsrInfo& a,
                                          const mojom::PsrInfo& b) {
  return CompareHelper(a, b)
      .FIELD(log_state)
      .FIELD(uuid)
      .FIELD(upid)
      .FIELD(log_start_date)
      .FIELD(oem_name)
      .FIELD(oem_make)
      .FIELD(oem_model)
      .FIELD(manufacture_country)
      .FIELD(oem_data)
      .FIELD(uptime_seconds)
      .FIELD(s5_counter)
      .FIELD(s4_counter)
      .FIELD(s3_counter)
      .FIELD(warm_reset_counter)
      .FIELD(events)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::PsrEvent>(const mojom::PsrEvent& a,
                                           const mojom::PsrEvent& b) {
  return CompareHelper(a, b).FIELD(type).FIELD(time).FIELD(data).GetResult();
}

template <>
std::string GetDiffString<mojom::SystemInfo>(const mojom::SystemInfo& a,
                                             const mojom::SystemInfo& b) {
  return CompareHelper(a, b)
      .FIELD(vpd_info)
      .FIELD(dmi_info)
      .FIELD(os_info)
      .FIELD(psr_info)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::BusDevice>(const mojom::BusDevice& a,
                                            const mojom::BusDevice& b) {
  return CompareHelper(a, b)
      .FIELD(vendor_name)
      .FIELD(product_name)
      .FIELD(device_class)
      .FIELD(bus_info)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::BusInfo>(const mojom::BusInfo& a,
                                          const mojom::BusInfo& b) {
  return CompareHelper(a, b)
      .UNION(pci_bus_info)
      .UNION(usb_bus_info)
      .UNION(thunderbolt_bus_info)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::PciBusInfo>(const mojom::PciBusInfo& a,
                                             const mojom::PciBusInfo& b) {
  return CompareHelper(a, b)
      .FIELD(class_id)
      .FIELD(subclass_id)
      .FIELD(prog_if_id)
      .FIELD(device_id)
      .FIELD(vendor_id)
      .FIELD(sub_device_id)
      .FIELD(sub_vendor_id)
      .FIELD(driver)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::UsbBusInfo>(const mojom::UsbBusInfo& a,
                                             const mojom::UsbBusInfo& b) {
  return CompareHelper(a, b)
      .FIELD(class_id)
      .FIELD(subclass_id)
      .FIELD(protocol_id)
      .FIELD(vendor_id)
      .FIELD(product_id)
      .FIELD(interfaces)
      .FIELD(fwupd_firmware_version_info)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::UsbBusInterfaceInfo>(
    const mojom::UsbBusInterfaceInfo& a, const mojom::UsbBusInterfaceInfo& b) {
  return CompareHelper(a, b)
      .FIELD(interface_number)
      .FIELD(class_id)
      .FIELD(subclass_id)
      .FIELD(protocol_id)
      .FIELD(driver)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::FwupdFirmwareVersionInfo>(
    const mojom::FwupdFirmwareVersionInfo& a,
    const mojom::FwupdFirmwareVersionInfo& b) {
  return CompareHelper(a, b).FIELD(version).FIELD(version_format).GetResult();
}

template <>
std::string GetDiffString<mojom::ThunderboltBusInfo>(
    const mojom::ThunderboltBusInfo& a, const mojom::ThunderboltBusInfo& b) {
  return CompareHelper(a, b)
      .FIELD(security_level)
      .FIELD(thunderbolt_interfaces)
      .GetResult();
}

template <>
std::string GetDiffString<mojom::ThunderboltBusInterfaceInfo>(
    const mojom::ThunderboltBusInterfaceInfo& a,
    const mojom::ThunderboltBusInterfaceInfo& b) {
  return CompareHelper(a, b)
      .FIELD(authorized)
      .FIELD(rx_speed_gbs)
      .FIELD(tx_speed_gbs)
      .FIELD(vendor_name)
      .FIELD(device_name)
      .FIELD(device_type)
      .FIELD(device_uuid)
      .FIELD(device_fw_version)
      .GetResult();
}
}  // namespace diagnostics
