#pragma once

#include "aidl/android/hardware/neuralnetworks/IDevice.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BpDevice : public ::ndk::BpCInterface<IDevice> {
public:
  explicit BpDevice(const ::ndk::SpAIBinder& binder);
  virtual ~BpDevice();

  ::ndk::ScopedAStatus allocate(const ::aidl::android::hardware::neuralnetworks::BufferDesc& in_desc, const std::vector<::aidl::android::hardware::neuralnetworks::IPreparedModelParcel>& in_preparedModels, const std::vector<::aidl::android::hardware::neuralnetworks::BufferRole>& in_inputRoles, const std::vector<::aidl::android::hardware::neuralnetworks::BufferRole>& in_outputRoles, ::aidl::android::hardware::neuralnetworks::DeviceBuffer* _aidl_return) override;
  ::ndk::ScopedAStatus getCapabilities(::aidl::android::hardware::neuralnetworks::Capabilities* _aidl_return) override;
  ::ndk::ScopedAStatus getNumberOfCacheFilesNeeded(::aidl::android::hardware::neuralnetworks::NumberOfCacheFiles* _aidl_return) override;
  ::ndk::ScopedAStatus getSupportedExtensions(std::vector<::aidl::android::hardware::neuralnetworks::Extension>* _aidl_return) override;
  ::ndk::ScopedAStatus getSupportedOperations(const ::aidl::android::hardware::neuralnetworks::Model& in_model, std::vector<bool>* _aidl_return) override;
  ::ndk::ScopedAStatus getType(::aidl::android::hardware::neuralnetworks::DeviceType* _aidl_return) override;
  ::ndk::ScopedAStatus getVersionString(std::string* _aidl_return) override;
  ::ndk::ScopedAStatus prepareModel(const ::aidl::android::hardware::neuralnetworks::Model& in_model, ::aidl::android::hardware::neuralnetworks::ExecutionPreference in_preference, ::aidl::android::hardware::neuralnetworks::Priority in_priority, int64_t in_deadlineNs, const std::vector<::ndk::ScopedFileDescriptor>& in_modelCache, const std::vector<::ndk::ScopedFileDescriptor>& in_dataCache, const std::vector<uint8_t>& in_token, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) override;
  ::ndk::ScopedAStatus prepareModelFromCache(int64_t in_deadlineNs, const std::vector<::ndk::ScopedFileDescriptor>& in_modelCache, const std::vector<::ndk::ScopedFileDescriptor>& in_dataCache, const std::vector<uint8_t>& in_token, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) override;
  ::ndk::ScopedAStatus prepareModelWithConfig(const ::aidl::android::hardware::neuralnetworks::Model& in_model, const ::aidl::android::hardware::neuralnetworks::PrepareModelConfig& in_config, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) override;
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
