#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_APREPAREDMODELCALLBACK_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_APREPAREDMODELCALLBACK_H

#include <android/hardware/neuralnetworks/1.3/IPreparedModelCallback.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_3 {

class APreparedModelCallback
    : public ::android::hardware::neuralnetworks::V1_3::IPreparedModelCallback {
 public:
  typedef ::android::hardware::neuralnetworks::V1_3::IPreparedModelCallback
      Pure;
  APreparedModelCallback(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_3::IPreparedModelCallback>&
          impl);
  // Methods from
  // ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback follow.
  virtual ::android::hardware::Return<void> notify(
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus status,
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_0::IPreparedModel>&
          preparedModel) override;

  // Methods from
  // ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback follow.
  virtual ::android::hardware::Return<void> notify_1_2(
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus status,
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_2::IPreparedModel>&
          preparedModel) override;

  // Methods from
  // ::android::hardware::neuralnetworks::V1_3::IPreparedModelCallback follow.
  virtual ::android::hardware::Return<void> notify_1_3(
      ::android::hardware::neuralnetworks::V1_3::ErrorStatus status,
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_3::IPreparedModel>&
          preparedModel) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<
      ::android::hardware::neuralnetworks::V1_3::IPreparedModelCallback>
      mImpl;
};

}  // namespace V1_3
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_APREPAREDMODELCALLBACK_H
