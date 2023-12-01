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
enum class FusedActivationFunc : int32_t {
  NONE = 0,
  RELU = 1,
  RELU1 = 2,
  RELU6 = 3,
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
[[nodiscard]] static inline std::string toString(FusedActivationFunc val) {
  switch(val) {
  case FusedActivationFunc::NONE:
    return "NONE";
  case FusedActivationFunc::RELU:
    return "RELU";
  case FusedActivationFunc::RELU1:
    return "RELU1";
  case FusedActivationFunc::RELU6:
    return "RELU6";
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
constexpr inline std::array<aidl::android::hardware::neuralnetworks::FusedActivationFunc, 4> enum_values<aidl::android::hardware::neuralnetworks::FusedActivationFunc> = {
  aidl::android::hardware::neuralnetworks::FusedActivationFunc::NONE,
  aidl::android::hardware::neuralnetworks::FusedActivationFunc::RELU,
  aidl::android::hardware::neuralnetworks::FusedActivationFunc::RELU1,
  aidl::android::hardware::neuralnetworks::FusedActivationFunc::RELU6,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
