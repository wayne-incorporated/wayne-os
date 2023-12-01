#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class ExtensionOperandTypeInformation {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  char16_t type = '\0';
  bool isTensor = false;
  int32_t byteSize = 0;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const ExtensionOperandTypeInformation& rhs) const {
    return std::tie(type, isTensor, byteSize) != std::tie(rhs.type, rhs.isTensor, rhs.byteSize);
  }
  inline bool operator<(const ExtensionOperandTypeInformation& rhs) const {
    return std::tie(type, isTensor, byteSize) < std::tie(rhs.type, rhs.isTensor, rhs.byteSize);
  }
  inline bool operator<=(const ExtensionOperandTypeInformation& rhs) const {
    return std::tie(type, isTensor, byteSize) <= std::tie(rhs.type, rhs.isTensor, rhs.byteSize);
  }
  inline bool operator==(const ExtensionOperandTypeInformation& rhs) const {
    return std::tie(type, isTensor, byteSize) == std::tie(rhs.type, rhs.isTensor, rhs.byteSize);
  }
  inline bool operator>(const ExtensionOperandTypeInformation& rhs) const {
    return std::tie(type, isTensor, byteSize) > std::tie(rhs.type, rhs.isTensor, rhs.byteSize);
  }
  inline bool operator>=(const ExtensionOperandTypeInformation& rhs) const {
    return std::tie(type, isTensor, byteSize) >= std::tie(rhs.type, rhs.isTensor, rhs.byteSize);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "ExtensionOperandTypeInformation{";
    os << "type: " << ::android::internal::ToString(type);
    os << ", isTensor: " << ::android::internal::ToString(isTensor);
    os << ", byteSize: " << ::android::internal::ToString(byteSize);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
