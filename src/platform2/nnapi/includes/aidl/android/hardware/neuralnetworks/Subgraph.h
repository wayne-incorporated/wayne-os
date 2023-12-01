#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/Operand.h>
#include <aidl/android/hardware/neuralnetworks/Operation.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class Subgraph {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  std::vector<::aidl::android::hardware::neuralnetworks::Operand> operands;
  std::vector<::aidl::android::hardware::neuralnetworks::Operation> operations;
  std::vector<int32_t> inputIndexes;
  std::vector<int32_t> outputIndexes;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const Subgraph& rhs) const {
    return std::tie(operands, operations, inputIndexes, outputIndexes) != std::tie(rhs.operands, rhs.operations, rhs.inputIndexes, rhs.outputIndexes);
  }
  inline bool operator<(const Subgraph& rhs) const {
    return std::tie(operands, operations, inputIndexes, outputIndexes) < std::tie(rhs.operands, rhs.operations, rhs.inputIndexes, rhs.outputIndexes);
  }
  inline bool operator<=(const Subgraph& rhs) const {
    return std::tie(operands, operations, inputIndexes, outputIndexes) <= std::tie(rhs.operands, rhs.operations, rhs.inputIndexes, rhs.outputIndexes);
  }
  inline bool operator==(const Subgraph& rhs) const {
    return std::tie(operands, operations, inputIndexes, outputIndexes) == std::tie(rhs.operands, rhs.operations, rhs.inputIndexes, rhs.outputIndexes);
  }
  inline bool operator>(const Subgraph& rhs) const {
    return std::tie(operands, operations, inputIndexes, outputIndexes) > std::tie(rhs.operands, rhs.operations, rhs.inputIndexes, rhs.outputIndexes);
  }
  inline bool operator>=(const Subgraph& rhs) const {
    return std::tie(operands, operations, inputIndexes, outputIndexes) >= std::tie(rhs.operands, rhs.operations, rhs.inputIndexes, rhs.outputIndexes);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "Subgraph{";
    os << "operands: " << ::android::internal::ToString(operands);
    os << ", operations: " << ::android::internal::ToString(operations);
    os << ", inputIndexes: " << ::android::internal::ToString(inputIndexes);
    os << ", outputIndexes: " << ::android::internal::ToString(outputIndexes);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
