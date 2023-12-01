#pragma once

#include "aidl/android/hardware/neuralnetworks/IFencedExecutionCallback.h"

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
class BnFencedExecutionCallback : public ::ndk::BnCInterface<IFencedExecutionCallback> {
public:
  BnFencedExecutionCallback();
  virtual ~BnFencedExecutionCallback();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IFencedExecutionCallbackDelegator : public BnFencedExecutionCallback {
public:
  explicit IFencedExecutionCallbackDelegator(const std::shared_ptr<IFencedExecutionCallback> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IFencedExecutionCallback::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus getExecutionInfo(::aidl::android::hardware::neuralnetworks::Timing* out_timingLaunched, ::aidl::android::hardware::neuralnetworks::Timing* out_timingFenced, ::aidl::android::hardware::neuralnetworks::ErrorStatus* _aidl_return) override {
    return _impl->getExecutionInfo(out_timingLaunched, out_timingFenced, _aidl_return);
  }
protected:
private:
  std::shared_ptr<IFencedExecutionCallback> _impl;
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
