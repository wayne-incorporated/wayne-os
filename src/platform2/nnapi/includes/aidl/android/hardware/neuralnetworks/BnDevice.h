#pragma once

#include "aidl/android/hardware/neuralnetworks/IDevice.h"

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
class BnDevice : public ::ndk::BnCInterface<IDevice> {
public:
  BnDevice();
  virtual ~BnDevice();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IDeviceDelegator : public BnDevice {
public:
  explicit IDeviceDelegator(const std::shared_ptr<IDevice> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IDevice::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus allocate(const ::aidl::android::hardware::neuralnetworks::BufferDesc& in_desc, const std::vector<::aidl::android::hardware::neuralnetworks::IPreparedModelParcel>& in_preparedModels, const std::vector<::aidl::android::hardware::neuralnetworks::BufferRole>& in_inputRoles, const std::vector<::aidl::android::hardware::neuralnetworks::BufferRole>& in_outputRoles, ::aidl::android::hardware::neuralnetworks::DeviceBuffer* _aidl_return) override {
    return _impl->allocate(in_desc, in_preparedModels, in_inputRoles, in_outputRoles, _aidl_return);
  }
  ::ndk::ScopedAStatus getCapabilities(::aidl::android::hardware::neuralnetworks::Capabilities* _aidl_return) override {
    return _impl->getCapabilities(_aidl_return);
  }
  ::ndk::ScopedAStatus getNumberOfCacheFilesNeeded(::aidl::android::hardware::neuralnetworks::NumberOfCacheFiles* _aidl_return) override {
    return _impl->getNumberOfCacheFilesNeeded(_aidl_return);
  }
  ::ndk::ScopedAStatus getSupportedExtensions(std::vector<::aidl::android::hardware::neuralnetworks::Extension>* _aidl_return) override {
    return _impl->getSupportedExtensions(_aidl_return);
  }
  ::ndk::ScopedAStatus getSupportedOperations(const ::aidl::android::hardware::neuralnetworks::Model& in_model, std::vector<bool>* _aidl_return) override {
    return _impl->getSupportedOperations(in_model, _aidl_return);
  }
  ::ndk::ScopedAStatus getType(::aidl::android::hardware::neuralnetworks::DeviceType* _aidl_return) override {
    return _impl->getType(_aidl_return);
  }
  ::ndk::ScopedAStatus getVersionString(std::string* _aidl_return) override {
    return _impl->getVersionString(_aidl_return);
  }
  ::ndk::ScopedAStatus prepareModel(const ::aidl::android::hardware::neuralnetworks::Model& in_model, ::aidl::android::hardware::neuralnetworks::ExecutionPreference in_preference, ::aidl::android::hardware::neuralnetworks::Priority in_priority, int64_t in_deadlineNs, const std::vector<::ndk::ScopedFileDescriptor>& in_modelCache, const std::vector<::ndk::ScopedFileDescriptor>& in_dataCache, const std::vector<uint8_t>& in_token, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) override {
    return _impl->prepareModel(in_model, in_preference, in_priority, in_deadlineNs, in_modelCache, in_dataCache, in_token, in_callback);
  }
  ::ndk::ScopedAStatus prepareModelFromCache(int64_t in_deadlineNs, const std::vector<::ndk::ScopedFileDescriptor>& in_modelCache, const std::vector<::ndk::ScopedFileDescriptor>& in_dataCache, const std::vector<uint8_t>& in_token, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) override {
    return _impl->prepareModelFromCache(in_deadlineNs, in_modelCache, in_dataCache, in_token, in_callback);
  }
  ::ndk::ScopedAStatus prepareModelWithConfig(const ::aidl::android::hardware::neuralnetworks::Model& in_model, const ::aidl::android::hardware::neuralnetworks::PrepareModelConfig& in_config, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) override {
    return _impl->prepareModelWithConfig(in_model, in_config, in_callback);
  }
protected:
private:
  std::shared_ptr<IDevice> _impl;
};

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
