#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/neuralnetworks/BufferDesc.h>
#include <aidl/android/hardware/neuralnetworks/BufferRole.h>
#include <aidl/android/hardware/neuralnetworks/Capabilities.h>
#include <aidl/android/hardware/neuralnetworks/DeviceBuffer.h>
#include <aidl/android/hardware/neuralnetworks/DeviceType.h>
#include <aidl/android/hardware/neuralnetworks/ExecutionPreference.h>
#include <aidl/android/hardware/neuralnetworks/Extension.h>
#include <aidl/android/hardware/neuralnetworks/IPreparedModelCallback.h>
#include <aidl/android/hardware/neuralnetworks/IPreparedModelParcel.h>
#include <aidl/android/hardware/neuralnetworks/Model.h>
#include <aidl/android/hardware/neuralnetworks/NumberOfCacheFiles.h>
#include <aidl/android/hardware/neuralnetworks/PrepareModelConfig.h>
#include <aidl/android/hardware/neuralnetworks/Priority.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IDevice : public ::ndk::ICInterface {
public:
  static const char* descriptor;
  IDevice();
  virtual ~IDevice();

  enum : int32_t { BYTE_SIZE_OF_CACHE_TOKEN = 32 };
  enum : int32_t { MAX_NUMBER_OF_CACHE_FILES = 32 };
  enum : int32_t { EXTENSION_TYPE_HIGH_BITS_PREFIX = 15 };
  enum : int32_t { EXTENSION_TYPE_LOW_BITS_TYPE = 16 };
  enum : int32_t { OPERAND_TYPE_BASE_MAX = 65535 };
  enum : int32_t { OPERATION_TYPE_BASE_MAX = 65535 };
  static const int32_t version = 4;
  static inline const std::string hash = "notfrozen";
  static constexpr uint32_t TRANSACTION_allocate = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_getCapabilities = FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_getNumberOfCacheFilesNeeded = FIRST_CALL_TRANSACTION + 2;
  static constexpr uint32_t TRANSACTION_getSupportedExtensions = FIRST_CALL_TRANSACTION + 3;
  static constexpr uint32_t TRANSACTION_getSupportedOperations = FIRST_CALL_TRANSACTION + 4;
  static constexpr uint32_t TRANSACTION_getType = FIRST_CALL_TRANSACTION + 5;
  static constexpr uint32_t TRANSACTION_getVersionString = FIRST_CALL_TRANSACTION + 6;
  static constexpr uint32_t TRANSACTION_prepareModel = FIRST_CALL_TRANSACTION + 7;
  static constexpr uint32_t TRANSACTION_prepareModelFromCache = FIRST_CALL_TRANSACTION + 8;
  static constexpr uint32_t TRANSACTION_prepareModelWithConfig = FIRST_CALL_TRANSACTION + 9;

  static std::shared_ptr<IDevice> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IDevice>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IDevice>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IDevice>& impl);
  static const std::shared_ptr<IDevice>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus allocate(const ::aidl::android::hardware::neuralnetworks::BufferDesc& in_desc, const std::vector<::aidl::android::hardware::neuralnetworks::IPreparedModelParcel>& in_preparedModels, const std::vector<::aidl::android::hardware::neuralnetworks::BufferRole>& in_inputRoles, const std::vector<::aidl::android::hardware::neuralnetworks::BufferRole>& in_outputRoles, ::aidl::android::hardware::neuralnetworks::DeviceBuffer* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getCapabilities(::aidl::android::hardware::neuralnetworks::Capabilities* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getNumberOfCacheFilesNeeded(::aidl::android::hardware::neuralnetworks::NumberOfCacheFiles* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getSupportedExtensions(std::vector<::aidl::android::hardware::neuralnetworks::Extension>* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getSupportedOperations(const ::aidl::android::hardware::neuralnetworks::Model& in_model, std::vector<bool>* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getType(::aidl::android::hardware::neuralnetworks::DeviceType* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getVersionString(std::string* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus prepareModel(const ::aidl::android::hardware::neuralnetworks::Model& in_model, ::aidl::android::hardware::neuralnetworks::ExecutionPreference in_preference, ::aidl::android::hardware::neuralnetworks::Priority in_priority, int64_t in_deadlineNs, const std::vector<::ndk::ScopedFileDescriptor>& in_modelCache, const std::vector<::ndk::ScopedFileDescriptor>& in_dataCache, const std::vector<uint8_t>& in_token, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) = 0;
  virtual ::ndk::ScopedAStatus prepareModelFromCache(int64_t in_deadlineNs, const std::vector<::ndk::ScopedFileDescriptor>& in_modelCache, const std::vector<::ndk::ScopedFileDescriptor>& in_dataCache, const std::vector<uint8_t>& in_token, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) = 0;
  virtual ::ndk::ScopedAStatus prepareModelWithConfig(const ::aidl::android::hardware::neuralnetworks::Model& in_model, const ::aidl::android::hardware::neuralnetworks::PrepareModelConfig& in_config, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModelCallback>& in_callback) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IDevice> default_impl;
};
class IDeviceDefault : public IDevice {
public:
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
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
