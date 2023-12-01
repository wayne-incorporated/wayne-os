#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/OutputShape.h>
#include <aidl/android/hardware/neuralnetworks/Timing.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class ExecutionResult {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  bool outputSufficientSize = false;
  std::vector<::aidl::android::hardware::neuralnetworks::OutputShape> outputShapes;
  ::aidl::android::hardware::neuralnetworks::Timing timing;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const ExecutionResult& rhs) const {
    return std::tie(outputSufficientSize, outputShapes, timing) != std::tie(rhs.outputSufficientSize, rhs.outputShapes, rhs.timing);
  }
  inline bool operator<(const ExecutionResult& rhs) const {
    return std::tie(outputSufficientSize, outputShapes, timing) < std::tie(rhs.outputSufficientSize, rhs.outputShapes, rhs.timing);
  }
  inline bool operator<=(const ExecutionResult& rhs) const {
    return std::tie(outputSufficientSize, outputShapes, timing) <= std::tie(rhs.outputSufficientSize, rhs.outputShapes, rhs.timing);
  }
  inline bool operator==(const ExecutionResult& rhs) const {
    return std::tie(outputSufficientSize, outputShapes, timing) == std::tie(rhs.outputSufficientSize, rhs.outputShapes, rhs.timing);
  }
  inline bool operator>(const ExecutionResult& rhs) const {
    return std::tie(outputSufficientSize, outputShapes, timing) > std::tie(rhs.outputSufficientSize, rhs.outputShapes, rhs.timing);
  }
  inline bool operator>=(const ExecutionResult& rhs) const {
    return std::tie(outputSufficientSize, outputShapes, timing) >= std::tie(rhs.outputSufficientSize, rhs.outputShapes, rhs.timing);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "ExecutionResult{";
    os << "outputSufficientSize: " << ::android::internal::ToString(outputSufficientSize);
    os << ", outputShapes: " << ::android::internal::ToString(outputShapes);
    os << ", timing: " << ::android::internal::ToString(timing);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
