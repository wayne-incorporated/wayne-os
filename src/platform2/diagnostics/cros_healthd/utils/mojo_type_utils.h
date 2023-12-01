// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_TYPE_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_TYPE_UTILS_H_

#include <algorithm>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <mojo/public/cpp/bindings/struct_ptr.h>

#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace ash::cros_healthd::mojom {
// Union types don't have default operator<. Define them so we can use std::sort
// to sort them.
bool operator<(const BusInfo& a, const BusInfo& b);
}  // namespace ash::cros_healthd::mojom

namespace diagnostics {
namespace internal {
constexpr auto kEqualStr = "[Equal]";
constexpr auto kNullStr = "[Null]";
constexpr auto kNotNullStr = "[Not Null]";

std::string Indent(const std::string& s);

std::string StringCompareFormat(const std::string& a, const std::string& b);
}  // namespace internal

// Type traits templates for identifying the mojo StructPtr types.
template <typename>
class IsStructPtr : public std::false_type {};
template <typename T>
class IsStructPtr<::mojo::StructPtr<T>> : public std::true_type {};
template <typename T>
class IsStructPtr<::mojo::InlinedStructPtr<T>> : public std::true_type {};

// Type traits templates for identifying the mojo Union types.
template <typename T>
class HasWhichFunction {
  template <typename U>
  static int8_t test_funtion(decltype(&U::which));
  template <typename U>
  static int16_t test_funtion(...);

 public:
  static constexpr bool value = (sizeof(test_funtion<T>(0)) == sizeof(int8_t));
};
template <typename T>
class IsMojoUnion : public HasWhichFunction<T> {};

// Type traits templates for identifying the vector.
template <typename>
class IsVector : public std::false_type {};
template <typename T>
class IsVector<std::vector<T>> : public std::true_type {};

// Helper type for better compiler error message.
template <typename T>
class UndefinedMojoType : public std::false_type {};

// Returns the difference between |a| and |b|. This is for the debugging of the
// unittest related to mojo types. Each mojo type needs to be manually defined.
// Example usage:
//    EXPECT_EQ(a, b) << GetDiffString(a, b);
//
// Example output:
//    field_a:
//       [Equal]
//    field_b:
//       "a value" vs "another value"
template <typename T>
std::string GetDiffString(const T& a, const T& b) {
  if (a == b)
    return internal::kEqualStr;
  if constexpr (IsStructPtr<T>::value) {
    if (a.is_null()) {
      return internal::StringCompareFormat(internal::kNullStr,
                                           internal::kNotNullStr);
    }
    if (b.is_null()) {
      return internal::StringCompareFormat(internal::kNotNullStr,
                                           internal::kNullStr);
    }
    return GetDiffString(*a, *b);
  } else if constexpr (std::is_enum_v<T>) {
    return GetDiffString("[Enum]:" + base::NumberToString(static_cast<int>(a)),
                         "[Enum]:" + base::NumberToString(static_cast<int>(b)));
  } else if constexpr (IsVector<T>::value) {  // NOLINT(readability/braces)
                                              // b/194872701
    if (a.size() != b.size()) {
      return internal::StringCompareFormat(
          "Vector[size: " + base::NumberToString(a.size()) + "]",
          "Vector[size: " + base::NumberToString(b.size()) + "]");
    }
    for (size_t i = 0; i < a.size(); ++i) {
      if (a[i] != b[i]) {
        return "Vector[" + base::NumberToString(i) + "]:\n" +
               internal::Indent(GetDiffString(a[i], b[i]));
      }
    }
    return internal::kEqualStr;
  } else if constexpr (std::is_arithmetic_v<T>) {
    return GetDiffString(base::NumberToString(a), base::NumberToString(b));
  } else {
    static_assert(UndefinedMojoType<T>::value,
                  "Undefined type for GetDiffString().");
  }
}

template <>
std::string GetDiffString<std::string>(const std::string& a,
                                       const std::string& b);

template <>
std::string GetDiffString<std::optional<std::string>>(
    const std::optional<std::string>& a, const std::optional<std::string>& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::NullableUint64>(
    const ::ash::cros_healthd::mojom::NullableUint64& a,
    const ::ash::cros_healthd::mojom::NullableUint64& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::VpdInfo>(
    const ::ash::cros_healthd::mojom::VpdInfo& a,
    const ::ash::cros_healthd::mojom::VpdInfo& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::DmiInfo>(
    const ::ash::cros_healthd::mojom::DmiInfo& a,
    const ::ash::cros_healthd::mojom::DmiInfo& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::OsVersion>(
    const ::ash::cros_healthd::mojom::OsVersion& a,
    const ::ash::cros_healthd::mojom::OsVersion& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::OsInfo>(
    const ::ash::cros_healthd::mojom::OsInfo& a,
    const ::ash::cros_healthd::mojom::OsInfo& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::SystemInfo>(
    const ::ash::cros_healthd::mojom::SystemInfo& a,
    const ::ash::cros_healthd::mojom::SystemInfo& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::BusDevice>(
    const ::ash::cros_healthd::mojom::BusDevice& a,
    const ::ash::cros_healthd::mojom::BusDevice& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::BusInfo>(
    const ::ash::cros_healthd::mojom::BusInfo& a,
    const ::ash::cros_healthd::mojom::BusInfo& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::PciBusInfo>(
    const ::ash::cros_healthd::mojom::PciBusInfo& a,
    const ::ash::cros_healthd::mojom::PciBusInfo& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::UsbBusInfo>(
    const ::ash::cros_healthd::mojom::UsbBusInfo& a,
    const ::ash::cros_healthd::mojom::UsbBusInfo& b);

template <>
std::string GetDiffString<::ash::cros_healthd::mojom::UsbBusInterfaceInfo>(
    const ::ash::cros_healthd::mojom::UsbBusInterfaceInfo& a,
    const ::ash::cros_healthd::mojom::UsbBusInterfaceInfo& b);

// Clones and sorts the vector.
template <typename T, typename = std::enable_if_t<IsStructPtr<T>::value>>
std::vector<T> Sorted(const std::vector<T>& in) {
  std::vector<T> out;
  for (const auto& ele : in) {
    out.push_back(ele.Clone());
  }
  sort(out.begin(), out.end());
  return out;
}

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_TYPE_UTILS_H_
