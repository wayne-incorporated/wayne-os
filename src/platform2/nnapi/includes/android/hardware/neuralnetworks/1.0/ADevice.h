#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_ADEVICE_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_ADEVICE_H

#include <android/hardware/neuralnetworks/1.0/IDevice.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_0 {

class ADevice : public ::android::hardware::neuralnetworks::V1_0::IDevice {
 public:
  typedef ::android::hardware::neuralnetworks::V1_0::IDevice Pure;
  ADevice(
      const ::android::sp<::android::hardware::neuralnetworks::V1_0::IDevice>&
          impl);
  // Methods from ::android::hardware::neuralnetworks::V1_0::IDevice follow.
  virtual ::android::hardware::Return<void> getCapabilities(
      getCapabilities_cb _hidl_cb) override;
  virtual ::android::hardware::Return<void> getSupportedOperations(
      const ::android::hardware::neuralnetworks::V1_0::Model& model,
      getSupportedOperations_cb _hidl_cb) override;
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus>
  prepareModel(
      const ::android::hardware::neuralnetworks::V1_0::Model& model,
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback>&
          callback) override;
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_0::DeviceStatus>
  getStatus() override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<::android::hardware::neuralnetworks::V1_0::IDevice> mImpl;
};

}  // namespace V1_0
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_ADEVICE_H
