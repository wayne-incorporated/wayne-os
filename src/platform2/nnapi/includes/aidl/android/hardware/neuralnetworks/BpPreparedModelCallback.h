#pragma once

#include "aidl/android/hardware/neuralnetworks/IPreparedModelCallback.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BpPreparedModelCallback : public ::ndk::BpCInterface<IPreparedModelCallback> {
public:
  explicit BpPreparedModelCallback(const ::ndk::SpAIBinder& binder);
  virtual ~BpPreparedModelCallback();

  ::ndk::ScopedAStatus notify(::aidl::android::hardware::neuralnetworks::ErrorStatus in_status, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel>& in_preparedModel) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  int32_t _aidl_cached_version = -1;
  std::string _aidl_cached_hash = "-1";
  std::mutex _aidl_cached_hash_mutex;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
