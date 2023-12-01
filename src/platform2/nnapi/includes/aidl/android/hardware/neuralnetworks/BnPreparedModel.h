#pragma once

#include "aidl/android/hardware/neuralnetworks/IPreparedModel.h"

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
class BnPreparedModel : public ::ndk::BnCInterface<IPreparedModel> {
public:
  BnPreparedModel();
  virtual ~BnPreparedModel();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IPreparedModelDelegator : public BnPreparedModel {
public:
  explicit IPreparedModelDelegator(const std::shared_ptr<IPreparedModel> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IPreparedModel::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override {
    return _impl->executeSynchronously(in_request, in_measureTiming, in_deadlineNs, in_loopTimeoutDurationNs, _aidl_return);
  }
  ::ndk::ScopedAStatus executeFenced(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override {
    return _impl->executeFenced(in_request, in_waitFor, in_measureTiming, in_deadlineNs, in_loopTimeoutDurationNs, in_durationNs, _aidl_return);
  }
  ::ndk::ScopedAStatus configureExecutionBurst(std::shared_ptr<::aidl::android::hardware::neuralnetworks::IBurst>* _aidl_return) override {
    return _impl->configureExecutionBurst(_aidl_return);
  }
  ::ndk::ScopedAStatus createReusableExecution(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, std::shared_ptr<::aidl::android::hardware::neuralnetworks::IExecution>* _aidl_return) override {
    return _impl->createReusableExecution(in_request, in_config, _aidl_return);
  }
  ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override {
    return _impl->executeSynchronouslyWithConfig(in_request, in_config, in_deadlineNs, _aidl_return);
  }
  ::ndk::ScopedAStatus executeFencedWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override {
    return _impl->executeFencedWithConfig(in_request, in_waitFor, in_config, in_deadlineNs, in_durationNs, _aidl_return);
  }
protected:
private:
  std::shared_ptr<IPreparedModel> _impl;
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
