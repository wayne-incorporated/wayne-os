#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/DataLocation.h>
#include <aidl/android/hardware/neuralnetworks/OperandExtraParams.h>
#include <aidl/android/hardware/neuralnetworks/OperandLifeTime.h>
#include <aidl/android/hardware/neuralnetworks/OperandType.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class Operand {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  ::aidl::android::hardware::neuralnetworks::OperandType type = ::aidl::android::hardware::neuralnetworks::OperandType::FLOAT32;
  std::vector<int32_t> dimensions;
  float scale = 0.000000f;
  int32_t zeroPoint = 0;
  ::aidl::android::hardware::neuralnetworks::OperandLifeTime lifetime = ::aidl::android::hardware::neuralnetworks::OperandLifeTime::TEMPORARY_VARIABLE;
  ::aidl::android::hardware::neuralnetworks::DataLocation location;
  std::optional<::aidl::android::hardware::neuralnetworks::OperandExtraParams> extraParams;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const Operand& rhs) const {
    return std::tie(type, dimensions, scale, zeroPoint, lifetime, location, extraParams) != std::tie(rhs.type, rhs.dimensions, rhs.scale, rhs.zeroPoint, rhs.lifetime, rhs.location, rhs.extraParams);
  }
  inline bool operator<(const Operand& rhs) const {
    return std::tie(type, dimensions, scale, zeroPoint, lifetime, location, extraParams) < std::tie(rhs.type, rhs.dimensions, rhs.scale, rhs.zeroPoint, rhs.lifetime, rhs.location, rhs.extraParams);
  }
  inline bool operator<=(const Operand& rhs) const {
    return std::tie(type, dimensions, scale, zeroPoint, lifetime, location, extraParams) <= std::tie(rhs.type, rhs.dimensions, rhs.scale, rhs.zeroPoint, rhs.lifetime, rhs.location, rhs.extraParams);
  }
  inline bool operator==(const Operand& rhs) const {
    return std::tie(type, dimensions, scale, zeroPoint, lifetime, location, extraParams) == std::tie(rhs.type, rhs.dimensions, rhs.scale, rhs.zeroPoint, rhs.lifetime, rhs.location, rhs.extraParams);
  }
  inline bool operator>(const Operand& rhs) const {
    return std::tie(type, dimensions, scale, zeroPoint, lifetime, location, extraParams) > std::tie(rhs.type, rhs.dimensions, rhs.scale, rhs.zeroPoint, rhs.lifetime, rhs.location, rhs.extraParams);
  }
  inline bool operator>=(const Operand& rhs) const {
    return std::tie(type, dimensions, scale, zeroPoint, lifetime, location, extraParams) >= std::tie(rhs.type, rhs.dimensions, rhs.scale, rhs.zeroPoint, rhs.lifetime, rhs.location, rhs.extraParams);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "Operand{";
    os << "type: " << ::android::internal::ToString(type);
    os << ", dimensions: " << ::android::internal::ToString(dimensions);
    os << ", scale: " << ::android::internal::ToString(scale);
    os << ", zeroPoint: " << ::android::internal::ToString(zeroPoint);
    os << ", lifetime: " << ::android::internal::ToString(lifetime);
    os << ", location: " << ::android::internal::ToString(location);
    os << ", extraParams: " << ::android::internal::ToString(extraParams);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
