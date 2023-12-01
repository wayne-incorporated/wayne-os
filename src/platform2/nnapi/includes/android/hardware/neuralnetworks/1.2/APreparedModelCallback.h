#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_APREPAREDMODELCALLBACK_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_APREPAREDMODELCALLBACK_H

#include <android/hardware/neuralnetworks/1.2/IPreparedModelCallback.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_2 {

class APreparedModelCallback
    : public ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback {
 public:
  typedef ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback
      Pure;
  APreparedModelCallback(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback>&
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

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<
      ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback>
      mImpl;
};

}  // namespace V1_2
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_APREPAREDMODELCALLBACK_H
