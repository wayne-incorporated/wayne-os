#include "aidl/android/hardware/neuralnetworks/IPreparedModelCallback.h"

#include <android/binder_parcel_utils.h>
#include <aidl/android/hardware/neuralnetworks/BnBurst.h>
#include <aidl/android/hardware/neuralnetworks/BnExecution.h>
#include <aidl/android/hardware/neuralnetworks/BnFencedExecutionCallback.h>
#include <aidl/android/hardware/neuralnetworks/BnPreparedModel.h>
#include <aidl/android/hardware/neuralnetworks/BnPreparedModelCallback.h>
#include <aidl/android/hardware/neuralnetworks/BpBurst.h>
#include <aidl/android/hardware/neuralnetworks/BpExecution.h>
#include <aidl/android/hardware/neuralnetworks/BpFencedExecutionCallback.h>
#include <aidl/android/hardware/neuralnetworks/BpPreparedModel.h>
#include <aidl/android/hardware/neuralnetworks/BpPreparedModelCallback.h>
#include <aidl/android/hardware/neuralnetworks/IBurst.h>
#include <aidl/android/hardware/neuralnetworks/IExecution.h>
#include <aidl/android/hardware/neuralnetworks/IFencedExecutionCallback.h>
#include <aidl/android/hardware/neuralnetworks/IPreparedModel.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
static binder_status_t _aidl_android_hardware_neuralnetworks_IPreparedModelCallback_onTransact(AIBinder* _aidl_binder, transaction_code_t _aidl_code, const AParcel* _aidl_in, AParcel* _aidl_out) {
  (void)_aidl_in;
  (void)_aidl_out;
  binder_status_t _aidl_ret_status = STATUS_UNKNOWN_TRANSACTION;
  std::shared_ptr<BnPreparedModelCallback> _aidl_impl = std::static_pointer_cast<BnPreparedModelCallback>(::ndk::ICInterface::asInterface(_aidl_binder));
  switch (_aidl_code) {
    case (FIRST_CALL_TRANSACTION + 0 /*notify*/): {
      ::aidl::android::hardware::neuralnetworks::ErrorStatus in_status;
      std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel> in_preparedModel;

      _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_status);
      if (_aidl_ret_status != STATUS_OK) break;

      _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_preparedModel);
      if (_aidl_ret_status != STATUS_OK) break;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->notify(in_status, in_preparedModel);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      break;
    }
    case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
      int32_t _aidl_return;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceVersion(&_aidl_return);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);
      if (_aidl_ret_status != STATUS_OK) break;

      break;
    }
    case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
      std::string _aidl_return;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceHash(&_aidl_return);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);
      if (_aidl_ret_status != STATUS_OK) break;

      break;
    }
  }
  return _aidl_ret_status;
}

static AIBinder_Class* _g_aidl_android_hardware_neuralnetworks_IPreparedModelCallback_clazz = ::ndk::ICInterface::defineClass(IPreparedModelCallback::descriptor, _aidl_android_hardware_neuralnetworks_IPreparedModelCallback_onTransact);

BpPreparedModelCallback::BpPreparedModelCallback(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
BpPreparedModelCallback::~BpPreparedModelCallback() {}

::ndk::ScopedAStatus BpPreparedModelCallback::notify(::aidl::android::hardware::neuralnetworks::ErrorStatus in_status, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel>& in_preparedModel) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_status);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_preparedModel);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 0 /*notify*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IPreparedModelCallback::getDefaultImpl()) {
    _aidl_status = IPreparedModelCallback::getDefaultImpl()->notify(in_status, in_preparedModel);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
::ndk::ScopedAStatus BpPreparedModelCallback::getInterfaceVersion(int32_t* _aidl_return) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  if (_aidl_cached_version != -1) {
    *_aidl_return = _aidl_cached_version;
    _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
    return _aidl_status;
  }
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IPreparedModelCallback::getDefaultImpl()) {
    _aidl_status = IPreparedModelCallback::getDefaultImpl()->getInterfaceVersion(_aidl_return);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_cached_version = *_aidl_return;
  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
::ndk::ScopedAStatus BpPreparedModelCallback::getInterfaceHash(std::string* _aidl_return) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  const std::lock_guard<std::mutex> lock(_aidl_cached_hash_mutex);
  if (_aidl_cached_hash != "-1") {
    *_aidl_return = _aidl_cached_hash;
    _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
    return _aidl_status;
  }
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IPreparedModelCallback::getDefaultImpl()) {
    _aidl_status = IPreparedModelCallback::getDefaultImpl()->getInterfaceHash(_aidl_return);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_cached_hash = *_aidl_return;
  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
// Source for BnPreparedModelCallback
BnPreparedModelCallback::BnPreparedModelCallback() {}
BnPreparedModelCallback::~BnPreparedModelCallback() {}
::ndk::SpAIBinder BnPreparedModelCallback::createBinder() {
  AIBinder* binder = AIBinder_new(_g_aidl_android_hardware_neuralnetworks_IPreparedModelCallback_clazz, static_cast<void*>(this));
  #ifdef BINDER_STABILITY_SUPPORT
  AIBinder_markVintfStability(binder);
  #endif  // BINDER_STABILITY_SUPPORT
  return ::ndk::SpAIBinder(binder);
}
::ndk::ScopedAStatus BnPreparedModelCallback::getInterfaceVersion(int32_t* _aidl_return) {
  *_aidl_return = IPreparedModelCallback::version;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::ScopedAStatus BnPreparedModelCallback::getInterfaceHash(std::string* _aidl_return) {
  *_aidl_return = IPreparedModelCallback::hash;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
// Source for IPreparedModelCallback
const char* IPreparedModelCallback::descriptor = "android.hardware.neuralnetworks.IPreparedModelCallback";
IPreparedModelCallback::IPreparedModelCallback() {}
IPreparedModelCallback::~IPreparedModelCallback() {}


std::shared_ptr<IPreparedModelCallback> IPreparedModelCallback::fromBinder(const ::ndk::SpAIBinder& binder) {
  if (!AIBinder_associateClass(binder.get(), _g_aidl_android_hardware_neuralnetworks_IPreparedModelCallback_clazz)) { return nullptr; }
  std::shared_ptr<::ndk::ICInterface> interface = ::ndk::ICInterface::asInterface(binder.get());
  if (interface) {
    return std::static_pointer_cast<IPreparedModelCallback>(interface);
  }
  return ::ndk::SharedRefBase::make<BpPreparedModelCallback>(binder);
}

binder_status_t IPreparedModelCallback::writeToParcel(AParcel* parcel, const std::shared_ptr<IPreparedModelCallback>& instance) {
  return AParcel_writeStrongBinder(parcel, instance ? instance->asBinder().get() : nullptr);
}
binder_status_t IPreparedModelCallback::readFromParcel(const AParcel* parcel, std::shared_ptr<IPreparedModelCallback>* instance) {
  ::ndk::SpAIBinder binder;
  binder_status_t status = AParcel_readStrongBinder(parcel, binder.getR());
  if (status != STATUS_OK) return status;
  *instance = IPreparedModelCallback::fromBinder(binder);
  return STATUS_OK;
}
bool IPreparedModelCallback::setDefaultImpl(const std::shared_ptr<IPreparedModelCallback>& impl) {
  // Only one user of this interface can use this function
  // at a time. This is a heuristic to detect if two different
  // users in the same process use this function.
  assert(!IPreparedModelCallback::default_impl);
  if (impl) {
    IPreparedModelCallback::default_impl = impl;
    return true;
  }
  return false;
}
const std::shared_ptr<IPreparedModelCallback>& IPreparedModelCallback::getDefaultImpl() {
  return IPreparedModelCallback::default_impl;
}
std::shared_ptr<IPreparedModelCallback> IPreparedModelCallback::default_impl = nullptr;
::ndk::ScopedAStatus IPreparedModelCallbackDefault::notify(::aidl::android::hardware::neuralnetworks::ErrorStatus /*in_status*/, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel>& /*in_preparedModel*/) {
  ::ndk::ScopedAStatus _aidl_status;
  _aidl_status.set(AStatus_fromStatus(STATUS_UNKNOWN_TRANSACTION));
  return _aidl_status;
}
::ndk::ScopedAStatus IPreparedModelCallbackDefault::getInterfaceVersion(int32_t* _aidl_return) {
  *_aidl_return = 0;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::ScopedAStatus IPreparedModelCallbackDefault::getInterfaceHash(std::string* _aidl_return) {
  *_aidl_return = "";
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::SpAIBinder IPreparedModelCallbackDefault::asBinder() {
  return ::ndk::SpAIBinder();
}
bool IPreparedModelCallbackDefault::isRemote() {
  return false;
}
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
