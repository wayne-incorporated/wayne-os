#pragma once

#include "aidl/android/hardware/neuralnetworks/IPreparedModelCallback.h"

#include <android/binder_ibinder.h>
#include <cassert>

#ifndef __BIONIC__
#ifndef __assert2
#define __assert2(a,b,c,d) ((void)0)
#endif
#endif

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BnPreparedModelCallback : public ::ndk::BnCInterface<IPreparedModelCallback> {
public:
  BnPreparedModelCallback();
  virtual ~BnPreparedModelCallback();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IPreparedModelCallbackDelegator : public BnPreparedModelCallback {
public:
  explicit IPreparedModelCallbackDelegator(const std::shared_ptr<IPreparedModelCallback> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IPreparedModelCallback::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus notify(::aidl::android::hardware::neuralnetworks::ErrorStatus in_status, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel>& in_preparedModel) override {
    return _impl->notify(in_status, in_preparedModel);
  }
protected:
private:
  std::shared_ptr<IPreparedModelCallback> _impl;
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
