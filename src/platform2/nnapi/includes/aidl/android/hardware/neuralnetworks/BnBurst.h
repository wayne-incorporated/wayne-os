#pragma once

#include "aidl/android/hardware/neuralnetworks/IBurst.h"

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
class BnBurst : public ::ndk::BnCInterface<IBurst> {
public:
  BnBurst();
  virtual ~BnBurst();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IBurstDelegator : public BnBurst {
public:
  explicit IBurstDelegator(const std::shared_ptr<IBurst> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IBurst::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override {
    return _impl->executeSynchronously(in_request, in_memoryIdentifierTokens, in_measureTiming, in_deadlineNs, in_loopTimeoutDurationNs, _aidl_return);
  }
  ::ndk::ScopedAStatus releaseMemoryResource(int64_t in_memoryIdentifierToken) override {
    return _impl->releaseMemoryResource(in_memoryIdentifierToken);
  }
  ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override {
    return _impl->executeSynchronouslyWithConfig(in_request, in_memoryIdentifierTokens, in_config, in_deadlineNs, _aidl_return);
  }
protected:
private:
  std::shared_ptr<IBurst> _impl;
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
