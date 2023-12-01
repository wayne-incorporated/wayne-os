#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/ExecutionPreference.h>
#include <aidl/android/hardware/neuralnetworks/ExtensionNameAndPrefix.h>
#include <aidl/android/hardware/neuralnetworks/Priority.h>
#include <aidl/android/hardware/neuralnetworks/TokenValuePair.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class PrepareModelConfig {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  ::aidl::android::hardware::neuralnetworks::ExecutionPreference preference = ::aidl::android::hardware::neuralnetworks::ExecutionPreference(0);
  ::aidl::android::hardware::neuralnetworks::Priority priority = ::aidl::android::hardware::neuralnetworks::Priority(0);
  int64_t deadlineNs = 0L;
  std::vector<::ndk::ScopedFileDescriptor> modelCache;
  std::vector<::ndk::ScopedFileDescriptor> dataCache;
  std::array<uint8_t, 32> cacheToken = {{}};
  std::vector<::aidl::android::hardware::neuralnetworks::TokenValuePair> compilationHints;
  std::vector<::aidl::android::hardware::neuralnetworks::ExtensionNameAndPrefix> extensionNameToPrefix;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const PrepareModelConfig& rhs) const {
    return std::tie(preference, priority, deadlineNs, modelCache, dataCache, cacheToken, compilationHints, extensionNameToPrefix) != std::tie(rhs.preference, rhs.priority, rhs.deadlineNs, rhs.modelCache, rhs.dataCache, rhs.cacheToken, rhs.compilationHints, rhs.extensionNameToPrefix);
  }
  inline bool operator<(const PrepareModelConfig& rhs) const {
    return std::tie(preference, priority, deadlineNs, modelCache, dataCache, cacheToken, compilationHints, extensionNameToPrefix) < std::tie(rhs.preference, rhs.priority, rhs.deadlineNs, rhs.modelCache, rhs.dataCache, rhs.cacheToken, rhs.compilationHints, rhs.extensionNameToPrefix);
  }
  inline bool operator<=(const PrepareModelConfig& rhs) const {
    return std::tie(preference, priority, deadlineNs, modelCache, dataCache, cacheToken, compilationHints, extensionNameToPrefix) <= std::tie(rhs.preference, rhs.priority, rhs.deadlineNs, rhs.modelCache, rhs.dataCache, rhs.cacheToken, rhs.compilationHints, rhs.extensionNameToPrefix);
  }
  inline bool operator==(const PrepareModelConfig& rhs) const {
    return std::tie(preference, priority, deadlineNs, modelCache, dataCache, cacheToken, compilationHints, extensionNameToPrefix) == std::tie(rhs.preference, rhs.priority, rhs.deadlineNs, rhs.modelCache, rhs.dataCache, rhs.cacheToken, rhs.compilationHints, rhs.extensionNameToPrefix);
  }
  inline bool operator>(const PrepareModelConfig& rhs) const {
    return std::tie(preference, priority, deadlineNs, modelCache, dataCache, cacheToken, compilationHints, extensionNameToPrefix) > std::tie(rhs.preference, rhs.priority, rhs.deadlineNs, rhs.modelCache, rhs.dataCache, rhs.cacheToken, rhs.compilationHints, rhs.extensionNameToPrefix);
  }
  inline bool operator>=(const PrepareModelConfig& rhs) const {
    return std::tie(preference, priority, deadlineNs, modelCache, dataCache, cacheToken, compilationHints, extensionNameToPrefix) >= std::tie(rhs.preference, rhs.priority, rhs.deadlineNs, rhs.modelCache, rhs.dataCache, rhs.cacheToken, rhs.compilationHints, rhs.extensionNameToPrefix);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  enum : int32_t { BYTE_SIZE_OF_CACHE_TOKEN = 32 };
  inline std::string toString() const {
    std::ostringstream os;
    os << "PrepareModelConfig{";
    os << "preference: " << ::android::internal::ToString(preference);
    os << ", priority: " << ::android::internal::ToString(priority);
    os << ", deadlineNs: " << ::android::internal::ToString(deadlineNs);
    os << ", modelCache: " << ::android::internal::ToString(modelCache);
    os << ", dataCache: " << ::android::internal::ToString(dataCache);
    os << ", cacheToken: " << ::android::internal::ToString(cacheToken);
    os << ", compilationHints: " << ::android::internal::ToString(compilationHints);
    os << ", extensionNameToPrefix: " << ::android::internal::ToString(extensionNameToPrefix);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
