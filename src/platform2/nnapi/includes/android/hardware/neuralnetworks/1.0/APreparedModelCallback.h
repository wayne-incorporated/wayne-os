#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_APREPAREDMODELCALLBACK_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_APREPAREDMODELCALLBACK_H

#include <android/hardware/neuralnetworks/1.0/IPreparedModelCallback.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_0 {

class APreparedModelCallback
    : public ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback {
 public:
  typedef ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback
      Pure;
  APreparedModelCallback(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback>&
          impl);
  // Methods from
  // ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback follow.
  virtual ::android::hardware::Return<void> notify(
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus status,
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_0::IPreparedModel>&
          preparedModel) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<
      ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback>
      mImpl;
};

}  // namespace V1_0
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_APREPAREDMODELCALLBACK_H
