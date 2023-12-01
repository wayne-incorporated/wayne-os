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
enum class OperandLifeTime : int32_t {
  TEMPORARY_VARIABLE = 0,
  SUBGRAPH_INPUT = 1,
  SUBGRAPH_OUTPUT = 2,
  CONSTANT_COPY = 3,
  CONSTANT_POOL = 4,
  NO_VALUE = 5,
  SUBGRAPH = 6,
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
[[nodiscard]] static inline std::string toString(OperandLifeTime val) {
  switch(val) {
  case OperandLifeTime::TEMPORARY_VARIABLE:
    return "TEMPORARY_VARIABLE";
  case OperandLifeTime::SUBGRAPH_INPUT:
    return "SUBGRAPH_INPUT";
  case OperandLifeTime::SUBGRAPH_OUTPUT:
    return "SUBGRAPH_OUTPUT";
  case OperandLifeTime::CONSTANT_COPY:
    return "CONSTANT_COPY";
  case OperandLifeTime::CONSTANT_POOL:
    return "CONSTANT_POOL";
  case OperandLifeTime::NO_VALUE:
    return "NO_VALUE";
  case OperandLifeTime::SUBGRAPH:
    return "SUBGRAPH";
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
constexpr inline std::array<aidl::android::hardware::neuralnetworks::OperandLifeTime, 7> enum_values<aidl::android::hardware::neuralnetworks::OperandLifeTime> = {
  aidl::android::hardware::neuralnetworks::OperandLifeTime::TEMPORARY_VARIABLE,
  aidl::android::hardware::neuralnetworks::OperandLifeTime::SUBGRAPH_INPUT,
  aidl::android::hardware::neuralnetworks::OperandLifeTime::SUBGRAPH_OUTPUT,
  aidl::android::hardware::neuralnetworks::OperandLifeTime::CONSTANT_COPY,
  aidl::android::hardware::neuralnetworks::OperandLifeTime::CONSTANT_POOL,
  aidl::android::hardware::neuralnetworks::OperandLifeTime::NO_VALUE,
  aidl::android::hardware::neuralnetworks::OperandLifeTime::SUBGRAPH,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
