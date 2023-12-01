#pragma once

#include "aidl/android/hardware/neuralnetworks/IBuffer.h"

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
class BnBuffer : public ::ndk::BnCInterface<IBuffer> {
public:
  BnBuffer();
  virtual ~BnBuffer();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IBufferDelegator : public BnBuffer {
public:
  explicit IBufferDelegator(const std::shared_ptr<IBuffer> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IBuffer::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus copyFrom(const ::aidl::android::hardware::neuralnetworks::Memory& in_src, const std::vector<int32_t>& in_dimensions) override {
    return _impl->copyFrom(in_src, in_dimensions);
  }
  ::ndk::ScopedAStatus copyTo(const ::aidl::android::hardware::neuralnetworks::Memory& in_dst) override {
    return _impl->copyTo(in_dst);
  }
protected:
private:
  std::shared_ptr<IBuffer> _impl;
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
