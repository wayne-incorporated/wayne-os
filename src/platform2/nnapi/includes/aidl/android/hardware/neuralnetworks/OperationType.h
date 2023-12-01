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
enum class OperationType : int32_t {
  ADD = 0,
  AVERAGE_POOL_2D = 1,
  CONCATENATION = 2,
  CONV_2D = 3,
  DEPTHWISE_CONV_2D = 4,
  DEPTH_TO_SPACE = 5,
  DEQUANTIZE = 6,
  EMBEDDING_LOOKUP = 7,
  FLOOR = 8,
  FULLY_CONNECTED = 9,
  HASHTABLE_LOOKUP = 10,
  L2_NORMALIZATION = 11,
  L2_POOL_2D = 12,
  LOCAL_RESPONSE_NORMALIZATION = 13,
  LOGISTIC = 14,
  LSH_PROJECTION = 15,
  LSTM = 16,
  MAX_POOL_2D = 17,
  MUL = 18,
  RELU = 19,
  RELU1 = 20,
  RELU6 = 21,
  RESHAPE = 22,
  RESIZE_BILINEAR = 23,
  RNN = 24,
  SOFTMAX = 25,
  SPACE_TO_DEPTH = 26,
  SVDF = 27,
  TANH = 28,
  BATCH_TO_SPACE_ND = 29,
  DIV = 30,
  MEAN = 31,
  PAD = 32,
  SPACE_TO_BATCH_ND = 33,
  SQUEEZE = 34,
  STRIDED_SLICE = 35,
  SUB = 36,
  TRANSPOSE = 37,
  ABS = 38,
  ARGMAX = 39,
  ARGMIN = 40,
  AXIS_ALIGNED_BBOX_TRANSFORM = 41,
  BIDIRECTIONAL_SEQUENCE_LSTM = 42,
  BIDIRECTIONAL_SEQUENCE_RNN = 43,
  BOX_WITH_NMS_LIMIT = 44,
  CAST = 45,
  CHANNEL_SHUFFLE = 46,
  DETECTION_POSTPROCESSING = 47,
  EQUAL = 48,
  EXP = 49,
  EXPAND_DIMS = 50,
  GATHER = 51,
  GENERATE_PROPOSALS = 52,
  GREATER = 53,
  GREATER_EQUAL = 54,
  GROUPED_CONV_2D = 55,
  HEATMAP_MAX_KEYPOINT = 56,
  INSTANCE_NORMALIZATION = 57,
  LESS = 58,
  LESS_EQUAL = 59,
  LOG = 60,
  LOGICAL_AND = 61,
  LOGICAL_NOT = 62,
  LOGICAL_OR = 63,
  LOG_SOFTMAX = 64,
  MAXIMUM = 65,
  MINIMUM = 66,
  NEG = 67,
  NOT_EQUAL = 68,
  PAD_V2 = 69,
  POW = 70,
  PRELU = 71,
  QUANTIZE = 72,
  QUANTIZED_16BIT_LSTM = 73,
  RANDOM_MULTINOMIAL = 74,
  REDUCE_ALL = 75,
  REDUCE_ANY = 76,
  REDUCE_MAX = 77,
  REDUCE_MIN = 78,
  REDUCE_PROD = 79,
  REDUCE_SUM = 80,
  ROI_ALIGN = 81,
  ROI_POOLING = 82,
  RSQRT = 83,
  SELECT = 84,
  SIN = 85,
  SLICE = 86,
  SPLIT = 87,
  SQRT = 88,
  TILE = 89,
  TOPK_V2 = 90,
  TRANSPOSE_CONV_2D = 91,
  UNIDIRECTIONAL_SEQUENCE_LSTM = 92,
  UNIDIRECTIONAL_SEQUENCE_RNN = 93,
  RESIZE_NEAREST_NEIGHBOR = 94,
  QUANTIZED_LSTM = 95,
  IF = 96,
  WHILE = 97,
  ELU = 98,
  HARD_SWISH = 99,
  FILL = 100,
  RANK = 101,
  BATCH_MATMUL = 102,
  PACK = 103,
  MIRROR_PAD = 104,
  REVERSE = 105,
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
[[nodiscard]] static inline std::string toString(OperationType val) {
  switch(val) {
  case OperationType::ADD:
    return "ADD";
  case OperationType::AVERAGE_POOL_2D:
    return "AVERAGE_POOL_2D";
  case OperationType::CONCATENATION:
    return "CONCATENATION";
  case OperationType::CONV_2D:
    return "CONV_2D";
  case OperationType::DEPTHWISE_CONV_2D:
    return "DEPTHWISE_CONV_2D";
  case OperationType::DEPTH_TO_SPACE:
    return "DEPTH_TO_SPACE";
  case OperationType::DEQUANTIZE:
    return "DEQUANTIZE";
  case OperationType::EMBEDDING_LOOKUP:
    return "EMBEDDING_LOOKUP";
  case OperationType::FLOOR:
    return "FLOOR";
  case OperationType::FULLY_CONNECTED:
    return "FULLY_CONNECTED";
  case OperationType::HASHTABLE_LOOKUP:
    return "HASHTABLE_LOOKUP";
  case OperationType::L2_NORMALIZATION:
    return "L2_NORMALIZATION";
  case OperationType::L2_POOL_2D:
    return "L2_POOL_2D";
  case OperationType::LOCAL_RESPONSE_NORMALIZATION:
    return "LOCAL_RESPONSE_NORMALIZATION";
  case OperationType::LOGISTIC:
    return "LOGISTIC";
  case OperationType::LSH_PROJECTION:
    return "LSH_PROJECTION";
  case OperationType::LSTM:
    return "LSTM";
  case OperationType::MAX_POOL_2D:
    return "MAX_POOL_2D";
  case OperationType::MUL:
    return "MUL";
  case OperationType::RELU:
    return "RELU";
  case OperationType::RELU1:
    return "RELU1";
  case OperationType::RELU6:
    return "RELU6";
  case OperationType::RESHAPE:
    return "RESHAPE";
  case OperationType::RESIZE_BILINEAR:
    return "RESIZE_BILINEAR";
  case OperationType::RNN:
    return "RNN";
  case OperationType::SOFTMAX:
    return "SOFTMAX";
  case OperationType::SPACE_TO_DEPTH:
    return "SPACE_TO_DEPTH";
  case OperationType::SVDF:
    return "SVDF";
  case OperationType::TANH:
    return "TANH";
  case OperationType::BATCH_TO_SPACE_ND:
    return "BATCH_TO_SPACE_ND";
  case OperationType::DIV:
    return "DIV";
  case OperationType::MEAN:
    return "MEAN";
  case OperationType::PAD:
    return "PAD";
  case OperationType::SPACE_TO_BATCH_ND:
    return "SPACE_TO_BATCH_ND";
  case OperationType::SQUEEZE:
    return "SQUEEZE";
  case OperationType::STRIDED_SLICE:
    return "STRIDED_SLICE";
  case OperationType::SUB:
    return "SUB";
  case OperationType::TRANSPOSE:
    return "TRANSPOSE";
  case OperationType::ABS:
    return "ABS";
  case OperationType::ARGMAX:
    return "ARGMAX";
  case OperationType::ARGMIN:
    return "ARGMIN";
  case OperationType::AXIS_ALIGNED_BBOX_TRANSFORM:
    return "AXIS_ALIGNED_BBOX_TRANSFORM";
  case OperationType::BIDIRECTIONAL_SEQUENCE_LSTM:
    return "BIDIRECTIONAL_SEQUENCE_LSTM";
  case OperationType::BIDIRECTIONAL_SEQUENCE_RNN:
    return "BIDIRECTIONAL_SEQUENCE_RNN";
  case OperationType::BOX_WITH_NMS_LIMIT:
    return "BOX_WITH_NMS_LIMIT";
  case OperationType::CAST:
    return "CAST";
  case OperationType::CHANNEL_SHUFFLE:
    return "CHANNEL_SHUFFLE";
  case OperationType::DETECTION_POSTPROCESSING:
    return "DETECTION_POSTPROCESSING";
  case OperationType::EQUAL:
    return "EQUAL";
  case OperationType::EXP:
    return "EXP";
  case OperationType::EXPAND_DIMS:
    return "EXPAND_DIMS";
  case OperationType::GATHER:
    return "GATHER";
  case OperationType::GENERATE_PROPOSALS:
    return "GENERATE_PROPOSALS";
  case OperationType::GREATER:
    return "GREATER";
  case OperationType::GREATER_EQUAL:
    return "GREATER_EQUAL";
  case OperationType::GROUPED_CONV_2D:
    return "GROUPED_CONV_2D";
  case OperationType::HEATMAP_MAX_KEYPOINT:
    return "HEATMAP_MAX_KEYPOINT";
  case OperationType::INSTANCE_NORMALIZATION:
    return "INSTANCE_NORMALIZATION";
  case OperationType::LESS:
    return "LESS";
  case OperationType::LESS_EQUAL:
    return "LESS_EQUAL";
  case OperationType::LOG:
    return "LOG";
  case OperationType::LOGICAL_AND:
    return "LOGICAL_AND";
  case OperationType::LOGICAL_NOT:
    return "LOGICAL_NOT";
  case OperationType::LOGICAL_OR:
    return "LOGICAL_OR";
  case OperationType::LOG_SOFTMAX:
    return "LOG_SOFTMAX";
  case OperationType::MAXIMUM:
    return "MAXIMUM";
  case OperationType::MINIMUM:
    return "MINIMUM";
  case OperationType::NEG:
    return "NEG";
  case OperationType::NOT_EQUAL:
    return "NOT_EQUAL";
  case OperationType::PAD_V2:
    return "PAD_V2";
  case OperationType::POW:
    return "POW";
  case OperationType::PRELU:
    return "PRELU";
  case OperationType::QUANTIZE:
    return "QUANTIZE";
  case OperationType::QUANTIZED_16BIT_LSTM:
    return "QUANTIZED_16BIT_LSTM";
  case OperationType::RANDOM_MULTINOMIAL:
    return "RANDOM_MULTINOMIAL";
  case OperationType::REDUCE_ALL:
    return "REDUCE_ALL";
  case OperationType::REDUCE_ANY:
    return "REDUCE_ANY";
  case OperationType::REDUCE_MAX:
    return "REDUCE_MAX";
  case OperationType::REDUCE_MIN:
    return "REDUCE_MIN";
  case OperationType::REDUCE_PROD:
    return "REDUCE_PROD";
  case OperationType::REDUCE_SUM:
    return "REDUCE_SUM";
  case OperationType::ROI_ALIGN:
    return "ROI_ALIGN";
  case OperationType::ROI_POOLING:
    return "ROI_POOLING";
  case OperationType::RSQRT:
    return "RSQRT";
  case OperationType::SELECT:
    return "SELECT";
  case OperationType::SIN:
    return "SIN";
  case OperationType::SLICE:
    return "SLICE";
  case OperationType::SPLIT:
    return "SPLIT";
  case OperationType::SQRT:
    return "SQRT";
  case OperationType::TILE:
    return "TILE";
  case OperationType::TOPK_V2:
    return "TOPK_V2";
  case OperationType::TRANSPOSE_CONV_2D:
    return "TRANSPOSE_CONV_2D";
  case OperationType::UNIDIRECTIONAL_SEQUENCE_LSTM:
    return "UNIDIRECTIONAL_SEQUENCE_LSTM";
  case OperationType::UNIDIRECTIONAL_SEQUENCE_RNN:
    return "UNIDIRECTIONAL_SEQUENCE_RNN";
  case OperationType::RESIZE_NEAREST_NEIGHBOR:
    return "RESIZE_NEAREST_NEIGHBOR";
  case OperationType::QUANTIZED_LSTM:
    return "QUANTIZED_LSTM";
  case OperationType::IF:
    return "IF";
  case OperationType::WHILE:
    return "WHILE";
  case OperationType::ELU:
    return "ELU";
  case OperationType::HARD_SWISH:
    return "HARD_SWISH";
  case OperationType::FILL:
    return "FILL";
  case OperationType::RANK:
    return "RANK";
  case OperationType::BATCH_MATMUL:
    return "BATCH_MATMUL";
  case OperationType::PACK:
    return "PACK";
  case OperationType::MIRROR_PAD:
    return "MIRROR_PAD";
  case OperationType::REVERSE:
    return "REVERSE";
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
constexpr inline std::array<aidl::android::hardware::neuralnetworks::OperationType, 106> enum_values<aidl::android::hardware::neuralnetworks::OperationType> = {
  aidl::android::hardware::neuralnetworks::OperationType::ADD,
  aidl::android::hardware::neuralnetworks::OperationType::AVERAGE_POOL_2D,
  aidl::android::hardware::neuralnetworks::OperationType::CONCATENATION,
  aidl::android::hardware::neuralnetworks::OperationType::CONV_2D,
  aidl::android::hardware::neuralnetworks::OperationType::DEPTHWISE_CONV_2D,
  aidl::android::hardware::neuralnetworks::OperationType::DEPTH_TO_SPACE,
  aidl::android::hardware::neuralnetworks::OperationType::DEQUANTIZE,
  aidl::android::hardware::neuralnetworks::OperationType::EMBEDDING_LOOKUP,
  aidl::android::hardware::neuralnetworks::OperationType::FLOOR,
  aidl::android::hardware::neuralnetworks::OperationType::FULLY_CONNECTED,
  aidl::android::hardware::neuralnetworks::OperationType::HASHTABLE_LOOKUP,
  aidl::android::hardware::neuralnetworks::OperationType::L2_NORMALIZATION,
  aidl::android::hardware::neuralnetworks::OperationType::L2_POOL_2D,
  aidl::android::hardware::neuralnetworks::OperationType::LOCAL_RESPONSE_NORMALIZATION,
  aidl::android::hardware::neuralnetworks::OperationType::LOGISTIC,
  aidl::android::hardware::neuralnetworks::OperationType::LSH_PROJECTION,
  aidl::android::hardware::neuralnetworks::OperationType::LSTM,
  aidl::android::hardware::neuralnetworks::OperationType::MAX_POOL_2D,
  aidl::android::hardware::neuralnetworks::OperationType::MUL,
  aidl::android::hardware::neuralnetworks::OperationType::RELU,
  aidl::android::hardware::neuralnetworks::OperationType::RELU1,
  aidl::android::hardware::neuralnetworks::OperationType::RELU6,
  aidl::android::hardware::neuralnetworks::OperationType::RESHAPE,
  aidl::android::hardware::neuralnetworks::OperationType::RESIZE_BILINEAR,
  aidl::android::hardware::neuralnetworks::OperationType::RNN,
  aidl::android::hardware::neuralnetworks::OperationType::SOFTMAX,
  aidl::android::hardware::neuralnetworks::OperationType::SPACE_TO_DEPTH,
  aidl::android::hardware::neuralnetworks::OperationType::SVDF,
  aidl::android::hardware::neuralnetworks::OperationType::TANH,
  aidl::android::hardware::neuralnetworks::OperationType::BATCH_TO_SPACE_ND,
  aidl::android::hardware::neuralnetworks::OperationType::DIV,
  aidl::android::hardware::neuralnetworks::OperationType::MEAN,
  aidl::android::hardware::neuralnetworks::OperationType::PAD,
  aidl::android::hardware::neuralnetworks::OperationType::SPACE_TO_BATCH_ND,
  aidl::android::hardware::neuralnetworks::OperationType::SQUEEZE,
  aidl::android::hardware::neuralnetworks::OperationType::STRIDED_SLICE,
  aidl::android::hardware::neuralnetworks::OperationType::SUB,
  aidl::android::hardware::neuralnetworks::OperationType::TRANSPOSE,
  aidl::android::hardware::neuralnetworks::OperationType::ABS,
  aidl::android::hardware::neuralnetworks::OperationType::ARGMAX,
  aidl::android::hardware::neuralnetworks::OperationType::ARGMIN,
  aidl::android::hardware::neuralnetworks::OperationType::AXIS_ALIGNED_BBOX_TRANSFORM,
  aidl::android::hardware::neuralnetworks::OperationType::BIDIRECTIONAL_SEQUENCE_LSTM,
  aidl::android::hardware::neuralnetworks::OperationType::BIDIRECTIONAL_SEQUENCE_RNN,
  aidl::android::hardware::neuralnetworks::OperationType::BOX_WITH_NMS_LIMIT,
  aidl::android::hardware::neuralnetworks::OperationType::CAST,
  aidl::android::hardware::neuralnetworks::OperationType::CHANNEL_SHUFFLE,
  aidl::android::hardware::neuralnetworks::OperationType::DETECTION_POSTPROCESSING,
  aidl::android::hardware::neuralnetworks::OperationType::EQUAL,
  aidl::android::hardware::neuralnetworks::OperationType::EXP,
  aidl::android::hardware::neuralnetworks::OperationType::EXPAND_DIMS,
  aidl::android::hardware::neuralnetworks::OperationType::GATHER,
  aidl::android::hardware::neuralnetworks::OperationType::GENERATE_PROPOSALS,
  aidl::android::hardware::neuralnetworks::OperationType::GREATER,
  aidl::android::hardware::neuralnetworks::OperationType::GREATER_EQUAL,
  aidl::android::hardware::neuralnetworks::OperationType::GROUPED_CONV_2D,
  aidl::android::hardware::neuralnetworks::OperationType::HEATMAP_MAX_KEYPOINT,
  aidl::android::hardware::neuralnetworks::OperationType::INSTANCE_NORMALIZATION,
  aidl::android::hardware::neuralnetworks::OperationType::LESS,
  aidl::android::hardware::neuralnetworks::OperationType::LESS_EQUAL,
  aidl::android::hardware::neuralnetworks::OperationType::LOG,
  aidl::android::hardware::neuralnetworks::OperationType::LOGICAL_AND,
  aidl::android::hardware::neuralnetworks::OperationType::LOGICAL_NOT,
  aidl::android::hardware::neuralnetworks::OperationType::LOGICAL_OR,
  aidl::android::hardware::neuralnetworks::OperationType::LOG_SOFTMAX,
  aidl::android::hardware::neuralnetworks::OperationType::MAXIMUM,
  aidl::android::hardware::neuralnetworks::OperationType::MINIMUM,
  aidl::android::hardware::neuralnetworks::OperationType::NEG,
  aidl::android::hardware::neuralnetworks::OperationType::NOT_EQUAL,
  aidl::android::hardware::neuralnetworks::OperationType::PAD_V2,
  aidl::android::hardware::neuralnetworks::OperationType::POW,
  aidl::android::hardware::neuralnetworks::OperationType::PRELU,
  aidl::android::hardware::neuralnetworks::OperationType::QUANTIZE,
  aidl::android::hardware::neuralnetworks::OperationType::QUANTIZED_16BIT_LSTM,
  aidl::android::hardware::neuralnetworks::OperationType::RANDOM_MULTINOMIAL,
  aidl::android::hardware::neuralnetworks::OperationType::REDUCE_ALL,
  aidl::android::hardware::neuralnetworks::OperationType::REDUCE_ANY,
  aidl::android::hardware::neuralnetworks::OperationType::REDUCE_MAX,
  aidl::android::hardware::neuralnetworks::OperationType::REDUCE_MIN,
  aidl::android::hardware::neuralnetworks::OperationType::REDUCE_PROD,
  aidl::android::hardware::neuralnetworks::OperationType::REDUCE_SUM,
  aidl::android::hardware::neuralnetworks::OperationType::ROI_ALIGN,
  aidl::android::hardware::neuralnetworks::OperationType::ROI_POOLING,
  aidl::android::hardware::neuralnetworks::OperationType::RSQRT,
  aidl::android::hardware::neuralnetworks::OperationType::SELECT,
  aidl::android::hardware::neuralnetworks::OperationType::SIN,
  aidl::android::hardware::neuralnetworks::OperationType::SLICE,
  aidl::android::hardware::neuralnetworks::OperationType::SPLIT,
  aidl::android::hardware::neuralnetworks::OperationType::SQRT,
  aidl::android::hardware::neuralnetworks::OperationType::TILE,
  aidl::android::hardware::neuralnetworks::OperationType::TOPK_V2,
  aidl::android::hardware::neuralnetworks::OperationType::TRANSPOSE_CONV_2D,
  aidl::android::hardware::neuralnetworks::OperationType::UNIDIRECTIONAL_SEQUENCE_LSTM,
  aidl::android::hardware::neuralnetworks::OperationType::UNIDIRECTIONAL_SEQUENCE_RNN,
  aidl::android::hardware::neuralnetworks::OperationType::RESIZE_NEAREST_NEIGHBOR,
  aidl::android::hardware::neuralnetworks::OperationType::QUANTIZED_LSTM,
  aidl::android::hardware::neuralnetworks::OperationType::IF,
  aidl::android::hardware::neuralnetworks::OperationType::WHILE,
  aidl::android::hardware::neuralnetworks::OperationType::ELU,
  aidl::android::hardware::neuralnetworks::OperationType::HARD_SWISH,
  aidl::android::hardware::neuralnetworks::OperationType::FILL,
  aidl::android::hardware::neuralnetworks::OperationType::RANK,
  aidl::android::hardware::neuralnetworks::OperationType::BATCH_MATMUL,
  aidl::android::hardware::neuralnetworks::OperationType::PACK,
  aidl::android::hardware::neuralnetworks::OperationType::MIRROR_PAD,
  aidl::android::hardware::neuralnetworks::OperationType::REVERSE,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
