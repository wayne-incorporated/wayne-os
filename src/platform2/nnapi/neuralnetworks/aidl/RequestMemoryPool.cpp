#include "aidl/android/hardware/neuralnetworks/RequestMemoryPool.h"

#include <android/binder_parcel_utils.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
const char* RequestMemoryPool::descriptor = "android.hardware.neuralnetworks.RequestMemoryPool";

binder_status_t RequestMemoryPool::readFromParcel(const AParcel* _parcel) {
  binder_status_t _aidl_ret_status;
  int32_t _aidl_tag;
  if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_tag)) != STATUS_OK) return _aidl_ret_status;
  switch (static_cast<Tag>(_aidl_tag)) {
  case pool: {
    ::aidl::android::hardware::neuralnetworks::Memory _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::neuralnetworks::Memory>) {
      set<pool>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<pool>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case token: {
    int32_t _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<int32_t>) {
      set<token>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<token>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  }
  return STATUS_BAD_VALUE;
}
binder_status_t RequestMemoryPool::writeToParcel(AParcel* _parcel) const {
  binder_status_t _aidl_ret_status = ::ndk::AParcel_writeData(_parcel, static_cast<int32_t>(getTag()));
  if (_aidl_ret_status != STATUS_OK) return _aidl_ret_status;
  switch (getTag()) {
  case pool: return ::ndk::AParcel_writeData(_parcel, get<pool>());
  case token: return ::ndk::AParcel_writeData(_parcel, get<token>());
  }
  __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "can't reach here");
}

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
