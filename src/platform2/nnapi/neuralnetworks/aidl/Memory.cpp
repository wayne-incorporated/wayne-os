#include "aidl/android/hardware/neuralnetworks/Memory.h"

#include <android/binder_parcel_utils.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
const char* Memory::descriptor = "android.hardware.neuralnetworks.Memory";

binder_status_t Memory::readFromParcel(const AParcel* _parcel) {
  binder_status_t _aidl_ret_status;
  int32_t _aidl_tag;
  if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_tag)) != STATUS_OK) return _aidl_ret_status;
  switch (static_cast<Tag>(_aidl_tag)) {
  case ashmem: {
    ::aidl::android::hardware::common::Ashmem _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::common::Ashmem>) {
      set<ashmem>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<ashmem>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case mappableFile: {
    ::aidl::android::hardware::common::MappableFile _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::common::MappableFile>) {
      set<mappableFile>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<mappableFile>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case hardwareBuffer: {
    ::aidl::android::hardware::graphics::common::HardwareBuffer _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::graphics::common::HardwareBuffer>) {
      set<hardwareBuffer>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<hardwareBuffer>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  }
  return STATUS_BAD_VALUE;
}
binder_status_t Memory::writeToParcel(AParcel* _parcel) const {
  binder_status_t _aidl_ret_status = ::ndk::AParcel_writeData(_parcel, static_cast<int32_t>(getTag()));
  if (_aidl_ret_status != STATUS_OK) return _aidl_ret_status;
  switch (getTag()) {
  case ashmem: return ::ndk::AParcel_writeData(_parcel, get<ashmem>());
  case mappableFile: return ::ndk::AParcel_writeData(_parcel, get<mappableFile>());
  case hardwareBuffer: return ::ndk::AParcel_writeData(_parcel, get<hardwareBuffer>());
  }
  __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "can't reach here");
}

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
