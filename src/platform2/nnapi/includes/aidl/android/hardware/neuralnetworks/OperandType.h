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
enum class OperandType : int32_t {
  FLOAT32 = 0,
  INT32 = 1,
  UINT32 = 2,
  TENSOR_FLOAT32 = 3,
  TENSOR_INT32 = 4,
  TENSOR_QUANT8_ASYMM = 5,
  BOOL = 6,
  TENSOR_QUANT16_SYMM = 7,
  TENSOR_FLOAT16 = 8,
  TENSOR_BOOL8 = 9,
  FLOAT16 = 10,
  TENSOR_QUANT8_SYMM_PER_CHANNEL = 11,
  TENSOR_QUANT16_ASYMM = 12,
  TENSOR_QUANT8_SYMM = 13,
  TENSOR_QUANT8_ASYMM_SIGNED = 14,
  SUBGRAPH = 15,
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
[[nodiscard]] static inline std::string toString(OperandType val) {
  switch(val) {
  case OperandType::FLOAT32:
    return "FLOAT32";
  case OperandType::INT32:
    return "INT32";
  case OperandType::UINT32:
    return "UINT32";
  case OperandType::TENSOR_FLOAT32:
    return "TENSOR_FLOAT32";
  case OperandType::TENSOR_INT32:
    return "TENSOR_INT32";
  case OperandType::TENSOR_QUANT8_ASYMM:
    return "TENSOR_QUANT8_ASYMM";
  case OperandType::BOOL:
    return "BOOL";
  case OperandType::TENSOR_QUANT16_SYMM:
    return "TENSOR_QUANT16_SYMM";
  case OperandType::TENSOR_FLOAT16:
    return "TENSOR_FLOAT16";
  case OperandType::TENSOR_BOOL8:
    return "TENSOR_BOOL8";
  case OperandType::FLOAT16:
    return "FLOAT16";
  case OperandType::TENSOR_QUANT8_SYMM_PER_CHANNEL:
    return "TENSOR_QUANT8_SYMM_PER_CHANNEL";
  case OperandType::TENSOR_QUANT16_ASYMM:
    return "TENSOR_QUANT16_ASYMM";
  case OperandType::TENSOR_QUANT8_SYMM:
    return "TENSOR_QUANT8_SYMM";
  case OperandType::TENSOR_QUANT8_ASYMM_SIGNED:
    return "TENSOR_QUANT8_ASYMM_SIGNED";
  case OperandType::SUBGRAPH:
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
constexpr inline std::array<aidl::android::hardware::neuralnetworks::OperandType, 16> enum_values<aidl::android::hardware::neuralnetworks::OperandType> = {
  aidl::android::hardware::neuralnetworks::OperandType::FLOAT32,
  aidl::android::hardware::neuralnetworks::OperandType::INT32,
  aidl::android::hardware::neuralnetworks::OperandType::UINT32,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_FLOAT32,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_INT32,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_QUANT8_ASYMM,
  aidl::android::hardware::neuralnetworks::OperandType::BOOL,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_QUANT16_SYMM,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_FLOAT16,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_BOOL8,
  aidl::android::hardware::neuralnetworks::OperandType::FLOAT16,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_QUANT8_SYMM_PER_CHANNEL,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_QUANT16_ASYMM,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_QUANT8_SYMM,
  aidl::android::hardware::neuralnetworks::OperandType::TENSOR_QUANT8_ASYMM_SIGNED,
  aidl::android::hardware::neuralnetworks::OperandType::SUBGRAPH,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
