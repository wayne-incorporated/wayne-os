#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/ExtensionNameAndPrefix.h>
#include <aidl/android/hardware/neuralnetworks/TokenValuePair.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class ExecutionConfig {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  bool measureTiming = false;
  int64_t loopTimeoutDurationNs = 0L;
  std::vector<::aidl::android::hardware::neuralnetworks::TokenValuePair> executionHints;
  std::vector<::aidl::android::hardware::neuralnetworks::ExtensionNameAndPrefix> extensionNameToPrefix;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const ExecutionConfig& rhs) const {
    return std::tie(measureTiming, loopTimeoutDurationNs, executionHints, extensionNameToPrefix) != std::tie(rhs.measureTiming, rhs.loopTimeoutDurationNs, rhs.executionHints, rhs.extensionNameToPrefix);
  }
  inline bool operator<(const ExecutionConfig& rhs) const {
    return std::tie(measureTiming, loopTimeoutDurationNs, executionHints, extensionNameToPrefix) < std::tie(rhs.measureTiming, rhs.loopTimeoutDurationNs, rhs.executionHints, rhs.extensionNameToPrefix);
  }
  inline bool operator<=(const ExecutionConfig& rhs) const {
    return std::tie(measureTiming, loopTimeoutDurationNs, executionHints, extensionNameToPrefix) <= std::tie(rhs.measureTiming, rhs.loopTimeoutDurationNs, rhs.executionHints, rhs.extensionNameToPrefix);
  }
  inline bool operator==(const ExecutionConfig& rhs) const {
    return std::tie(measureTiming, loopTimeoutDurationNs, executionHints, extensionNameToPrefix) == std::tie(rhs.measureTiming, rhs.loopTimeoutDurationNs, rhs.executionHints, rhs.extensionNameToPrefix);
  }
  inline bool operator>(const ExecutionConfig& rhs) const {
    return std::tie(measureTiming, loopTimeoutDurationNs, executionHints, extensionNameToPrefix) > std::tie(rhs.measureTiming, rhs.loopTimeoutDurationNs, rhs.executionHints, rhs.extensionNameToPrefix);
  }
  inline bool operator>=(const ExecutionConfig& rhs) const {
    return std::tie(measureTiming, loopTimeoutDurationNs, executionHints, extensionNameToPrefix) >= std::tie(rhs.measureTiming, rhs.loopTimeoutDurationNs, rhs.executionHints, rhs.extensionNameToPrefix);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "ExecutionConfig{";
    os << "measureTiming: " << ::android::internal::ToString(measureTiming);
    os << ", loopTimeoutDurationNs: " << ::android::internal::ToString(loopTimeoutDurationNs);
    os << ", executionHints: " << ::android::internal::ToString(executionHints);
    os << ", extensionNameToPrefix: " << ::android::internal::ToString(extensionNameToPrefix);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
