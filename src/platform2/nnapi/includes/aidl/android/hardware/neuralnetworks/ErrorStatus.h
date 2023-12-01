#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_enums.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
enum class ErrorStatus : int32_t {
  NONE = 0,
  DEVICE_UNAVAILABLE = 1,
  GENERAL_FAILURE = 2,
  OUTPUT_INSUFFICIENT_SIZE = 3,
  INVALID_ARGUMENT = 4,
  MISSED_DEADLINE_TRANSIENT = 5,
  MISSED_DEADLINE_PERSISTENT = 6,
  RESOURCE_EXHAUSTED_TRANSIENT = 7,
  RESOURCE_EXHAUSTED_PERSISTENT = 8,
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
[[nodiscard]] static inline std::string toString(ErrorStatus val) {
  switch(val) {
  case ErrorStatus::NONE:
    return "NONE";
  case ErrorStatus::DEVICE_UNAVAILABLE:
    return "DEVICE_UNAVAILABLE";
  case ErrorStatus::GENERAL_FAILURE:
    return "GENERAL_FAILURE";
  case ErrorStatus::OUTPUT_INSUFFICIENT_SIZE:
    return "OUTPUT_INSUFFICIENT_SIZE";
  case ErrorStatus::INVALID_ARGUMENT:
    return "INVALID_ARGUMENT";
  case ErrorStatus::MISSED_DEADLINE_TRANSIENT:
    return "MISSED_DEADLINE_TRANSIENT";
  case ErrorStatus::MISSED_DEADLINE_PERSISTENT:
    return "MISSED_DEADLINE_PERSISTENT";
  case ErrorStatus::RESOURCE_EXHAUSTED_TRANSIENT:
    return "RESOURCE_EXHAUSTED_TRANSIENT";
  case ErrorStatus::RESOURCE_EXHAUSTED_PERSISTENT:
    return "RESOURCE_EXHAUSTED_PERSISTENT";
  default:
    return std::to_string(static_cast<int32_t>(val));
  }
}
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace ndk {
namespace internal {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template <>
constexpr inline std::array<aidl::android::hardware::neuralnetworks::ErrorStatus, 9> enum_values<aidl::android::hardware::neuralnetworks::ErrorStatus> = {
  aidl::android::hardware::neuralnetworks::ErrorStatus::NONE,
  aidl::android::hardware::neuralnetworks::ErrorStatus::DEVICE_UNAVAILABLE,
  aidl::android::hardware::neuralnetworks::ErrorStatus::GENERAL_FAILURE,
  aidl::android::hardware::neuralnetworks::ErrorStatus::OUTPUT_INSUFFICIENT_SIZE,
  aidl::android::hardware::neuralnetworks::ErrorStatus::INVALID_ARGUMENT,
  aidl::android::hardware::neuralnetworks::ErrorStatus::MISSED_DEADLINE_TRANSIENT,
  aidl::android::hardware::neuralnetworks::ErrorStatus::MISSED_DEADLINE_PERSISTENT,
  aidl::android::hardware::neuralnetworks::ErrorStatus::RESOURCE_EXHAUSTED_TRANSIENT,
  aidl::android::hardware::neuralnetworks::ErrorStatus::RESOURCE_EXHAUSTED_PERSISTENT,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
