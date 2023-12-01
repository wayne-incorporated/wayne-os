#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_APREPAREDMODEL_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_APREPAREDMODEL_H

#include <android/hardware/neuralnetworks/1.0/IPreparedModel.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_0 {

class APreparedModel
    : public ::android::hardware::neuralnetworks::V1_0::IPreparedModel {
 public:
  typedef ::android::hardware::neuralnetworks::V1_0::IPreparedModel Pure;
  APreparedModel(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_0::IPreparedModel>& impl);
  // Methods from ::android::hardware::neuralnetworks::V1_0::IPreparedModel
  // follow.
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus>
  execute(const ::android::hardware::neuralnetworks::V1_0::Request& request,
          const ::android::sp<
              ::android::hardware::neuralnetworks::V1_0::IExecutionCallback>&
              callback) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<::android::hardware::neuralnetworks::V1_0::IPreparedModel>
      mImpl;
};

}  // namespace V1_0
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_APREPAREDMODEL_H
