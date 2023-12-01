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
enum class DeviceType : int32_t {
  OTHER = 1,
  CPU = 2,
  GPU = 3,
  ACCELERATOR = 4,
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
[[nodiscard]] static inline std::string toString(DeviceType val) {
  switch(val) {
  case DeviceType::OTHER:
    return "OTHER";
  case DeviceType::CPU:
    return "CPU";
  case DeviceType::GPU:
    return "GPU";
  case DeviceType::ACCELERATOR:
    return "ACCELERATOR";
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
constexpr inline std::array<aidl::android::hardware::neuralnetworks::DeviceType, 4> enum_values<aidl::android::hardware::neuralnetworks::DeviceType> = {
  aidl::android::hardware::neuralnetworks::DeviceType::OTHER,
  aidl::android::hardware::neuralnetworks::DeviceType::CPU,
  aidl::android::hardware::neuralnetworks::DeviceType::GPU,
  aidl::android::hardware::neuralnetworks::DeviceType::ACCELERATOR,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
