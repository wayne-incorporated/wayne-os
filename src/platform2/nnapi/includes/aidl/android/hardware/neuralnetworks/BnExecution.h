#pragma once

#include "aidl/android/hardware/neuralnetworks/IExecution.h"

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
class BnExecution : public ::ndk::BnCInterface<IExecution> {
public:
  BnExecution();
  virtual ~BnExecution();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IExecutionDelegator : public BnExecution {
public:
  explicit IExecutionDelegator(const std::shared_ptr<IExecution> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IExecution::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus executeSynchronously(int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override {
    return _impl->executeSynchronously(in_deadlineNs, _aidl_return);
  }
  ::ndk::ScopedAStatus executeFenced(const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override {
    return _impl->executeFenced(in_waitFor, in_deadlineNs, in_durationNs, _aidl_return);
  }
protected:
private:
  std::shared_ptr<IExecution> _impl;
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
