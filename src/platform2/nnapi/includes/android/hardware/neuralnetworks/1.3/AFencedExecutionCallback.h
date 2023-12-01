#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_AFENCEDEXECUTIONCALLBACK_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_AFENCEDEXECUTIONCALLBACK_H

#include <android/hardware/neuralnetworks/1.3/IFencedExecutionCallback.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_3 {

class AFencedExecutionCallback : public ::android::hardware::neuralnetworks::
                                     V1_3::IFencedExecutionCallback {
 public:
  typedef ::android::hardware::neuralnetworks::V1_3::IFencedExecutionCallback
      Pure;
  AFencedExecutionCallback(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_3::IFencedExecutionCallback>&
          impl);
  // Methods from
  // ::android::hardware::neuralnetworks::V1_3::IFencedExecutionCallback follow.
  virtual ::android::hardware::Return<void> getExecutionInfo(
      getExecutionInfo_cb _hidl_cb) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<
      ::android::hardware::neuralnetworks::V1_3::IFencedExecutionCallback>
      mImpl;
};

}  // namespace V1_3
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_AFENCEDEXECUTIONCALLBACK_H
