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
enum class ExecutionPreference : int32_t {
  LOW_POWER = 0,
  FAST_SINGLE_ANSWER = 1,
  SUSTAINED_SPEED = 2,
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
[[nodiscard]] static inline std::string toString(ExecutionPreference val) {
  switch(val) {
  case ExecutionPreference::LOW_POWER:
    return "LOW_POWER";
  case ExecutionPreference::FAST_SINGLE_ANSWER:
    return "FAST_SINGLE_ANSWER";
  case ExecutionPreference::SUSTAINED_SPEED:
    return "SUSTAINED_SPEED";
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
constexpr inline std::array<aidl::android::hardware::neuralnetworks::ExecutionPreference, 3> enum_values<aidl::android::hardware::neuralnetworks::ExecutionPreference> = {
  aidl::android::hardware::neuralnetworks::ExecutionPreference::LOW_POWER,
  aidl::android::hardware::neuralnetworks::ExecutionPreference::FAST_SINGLE_ANSWER,
  aidl::android::hardware::neuralnetworks::ExecutionPreference::SUSTAINED_SPEED,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
