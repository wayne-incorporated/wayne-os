#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/OperandPerformance.h>
#include <aidl/android/hardware/neuralnetworks/PerformanceInfo.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class Capabilities {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  ::aidl::android::hardware::neuralnetworks::PerformanceInfo relaxedFloat32toFloat16PerformanceScalar;
  ::aidl::android::hardware::neuralnetworks::PerformanceInfo relaxedFloat32toFloat16PerformanceTensor;
  std::vector<::aidl::android::hardware::neuralnetworks::OperandPerformance> operandPerformance;
  ::aidl::android::hardware::neuralnetworks::PerformanceInfo ifPerformance;
  ::aidl::android::hardware::neuralnetworks::PerformanceInfo whilePerformance;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const Capabilities& rhs) const {
    return std::tie(relaxedFloat32toFloat16PerformanceScalar, relaxedFloat32toFloat16PerformanceTensor, operandPerformance, ifPerformance, whilePerformance) != std::tie(rhs.relaxedFloat32toFloat16PerformanceScalar, rhs.relaxedFloat32toFloat16PerformanceTensor, rhs.operandPerformance, rhs.ifPerformance, rhs.whilePerformance);
  }
  inline bool operator<(const Capabilities& rhs) const {
    return std::tie(relaxedFloat32toFloat16PerformanceScalar, relaxedFloat32toFloat16PerformanceTensor, operandPerformance, ifPerformance, whilePerformance) < std::tie(rhs.relaxedFloat32toFloat16PerformanceScalar, rhs.relaxedFloat32toFloat16PerformanceTensor, rhs.operandPerformance, rhs.ifPerformance, rhs.whilePerformance);
  }
  inline bool operator<=(const Capabilities& rhs) const {
    return std::tie(relaxedFloat32toFloat16PerformanceScalar, relaxedFloat32toFloat16PerformanceTensor, operandPerformance, ifPerformance, whilePerformance) <= std::tie(rhs.relaxedFloat32toFloat16PerformanceScalar, rhs.relaxedFloat32toFloat16PerformanceTensor, rhs.operandPerformance, rhs.ifPerformance, rhs.whilePerformance);
  }
  inline bool operator==(const Capabilities& rhs) const {
    return std::tie(relaxedFloat32toFloat16PerformanceScalar, relaxedFloat32toFloat16PerformanceTensor, operandPerformance, ifPerformance, whilePerformance) == std::tie(rhs.relaxedFloat32toFloat16PerformanceScalar, rhs.relaxedFloat32toFloat16PerformanceTensor, rhs.operandPerformance, rhs.ifPerformance, rhs.whilePerformance);
  }
  inline bool operator>(const Capabilities& rhs) const {
    return std::tie(relaxedFloat32toFloat16PerformanceScalar, relaxedFloat32toFloat16PerformanceTensor, operandPerformance, ifPerformance, whilePerformance) > std::tie(rhs.relaxedFloat32toFloat16PerformanceScalar, rhs.relaxedFloat32toFloat16PerformanceTensor, rhs.operandPerformance, rhs.ifPerformance, rhs.whilePerformance);
  }
  inline bool operator>=(const Capabilities& rhs) const {
    return std::tie(relaxedFloat32toFloat16PerformanceScalar, relaxedFloat32toFloat16PerformanceTensor, operandPerformance, ifPerformance, whilePerformance) >= std::tie(rhs.relaxedFloat32toFloat16PerformanceScalar, rhs.relaxedFloat32toFloat16PerformanceTensor, rhs.operandPerformance, rhs.ifPerformance, rhs.whilePerformance);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "Capabilities{";
    os << "relaxedFloat32toFloat16PerformanceScalar: " << ::android::internal::ToString(relaxedFloat32toFloat16PerformanceScalar);
    os << ", relaxedFloat32toFloat16PerformanceTensor: " << ::android::internal::ToString(relaxedFloat32toFloat16PerformanceTensor);
    os << ", operandPerformance: " << ::android::internal::ToString(operandPerformance);
    os << ", ifPerformance: " << ::android::internal::ToString(ifPerformance);
    os << ", whilePerformance: " << ::android::internal::ToString(whilePerformance);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
