#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/ExtensionOperandTypeInformation.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class Extension {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  std::string name;
  std::vector<::aidl::android::hardware::neuralnetworks::ExtensionOperandTypeInformation> operandTypes;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const Extension& rhs) const {
    return std::tie(name, operandTypes) != std::tie(rhs.name, rhs.operandTypes);
  }
  inline bool operator<(const Extension& rhs) const {
    return std::tie(name, operandTypes) < std::tie(rhs.name, rhs.operandTypes);
  }
  inline bool operator<=(const Extension& rhs) const {
    return std::tie(name, operandTypes) <= std::tie(rhs.name, rhs.operandTypes);
  }
  inline bool operator==(const Extension& rhs) const {
    return std::tie(name, operandTypes) == std::tie(rhs.name, rhs.operandTypes);
  }
  inline bool operator>(const Extension& rhs) const {
    return std::tie(name, operandTypes) > std::tie(rhs.name, rhs.operandTypes);
  }
  inline bool operator>=(const Extension& rhs) const {
    return std::tie(name, operandTypes) >= std::tie(rhs.name, rhs.operandTypes);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "Extension{";
    os << "name: " << ::android::internal::ToString(name);
    os << ", operandTypes: " << ::android::internal::ToString(operandTypes);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
