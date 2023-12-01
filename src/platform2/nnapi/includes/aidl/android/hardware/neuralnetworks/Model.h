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
#include <aidl/android/hardware/neuralnetworks/Memory.h>
#include <aidl/android/hardware/neuralnetworks/Subgraph.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class Model {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  ::aidl::android::hardware::neuralnetworks::Subgraph main;
  std::vector<::aidl::android::hardware::neuralnetworks::Subgraph> referenced;
  std::vector<uint8_t> operandValues;
  std::vector<::aidl::android::hardware::neuralnetworks::Memory> pools;
  bool relaxComputationFloat32toFloat16 = false;
  std::vector<::aidl::android::hardware::neuralnetworks::ExtensionNameAndPrefix> extensionNameToPrefix;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const Model& rhs) const {
    return std::tie(main, referenced, operandValues, pools, relaxComputationFloat32toFloat16, extensionNameToPrefix) != std::tie(rhs.main, rhs.referenced, rhs.operandValues, rhs.pools, rhs.relaxComputationFloat32toFloat16, rhs.extensionNameToPrefix);
  }
  inline bool operator<(const Model& rhs) const {
    return std::tie(main, referenced, operandValues, pools, relaxComputationFloat32toFloat16, extensionNameToPrefix) < std::tie(rhs.main, rhs.referenced, rhs.operandValues, rhs.pools, rhs.relaxComputationFloat32toFloat16, rhs.extensionNameToPrefix);
  }
  inline bool operator<=(const Model& rhs) const {
    return std::tie(main, referenced, operandValues, pools, relaxComputationFloat32toFloat16, extensionNameToPrefix) <= std::tie(rhs.main, rhs.referenced, rhs.operandValues, rhs.pools, rhs.relaxComputationFloat32toFloat16, rhs.extensionNameToPrefix);
  }
  inline bool operator==(const Model& rhs) const {
    return std::tie(main, referenced, operandValues, pools, relaxComputationFloat32toFloat16, extensionNameToPrefix) == std::tie(rhs.main, rhs.referenced, rhs.operandValues, rhs.pools, rhs.relaxComputationFloat32toFloat16, rhs.extensionNameToPrefix);
  }
  inline bool operator>(const Model& rhs) const {
    return std::tie(main, referenced, operandValues, pools, relaxComputationFloat32toFloat16, extensionNameToPrefix) > std::tie(rhs.main, rhs.referenced, rhs.operandValues, rhs.pools, rhs.relaxComputationFloat32toFloat16, rhs.extensionNameToPrefix);
  }
  inline bool operator>=(const Model& rhs) const {
    return std::tie(main, referenced, operandValues, pools, relaxComputationFloat32toFloat16, extensionNameToPrefix) >= std::tie(rhs.main, rhs.referenced, rhs.operandValues, rhs.pools, rhs.relaxComputationFloat32toFloat16, rhs.extensionNameToPrefix);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "Model{";
    os << "main: " << ::android::internal::ToString(main);
    os << ", referenced: " << ::android::internal::ToString(referenced);
    os << ", operandValues: " << ::android::internal::ToString(operandValues);
    os << ", pools: " << ::android::internal::ToString(pools);
    os << ", relaxComputationFloat32toFloat16: " << ::android::internal::ToString(relaxComputationFloat32toFloat16);
    os << ", extensionNameToPrefix: " << ::android::internal::ToString(extensionNameToPrefix);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
