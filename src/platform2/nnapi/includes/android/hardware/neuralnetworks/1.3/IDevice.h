#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_IDEVICE_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_IDEVICE_H

#include <android/hardware/neuralnetworks/1.1/types.h>
#include <android/hardware/neuralnetworks/1.2/IDevice.h>
#include <android/hardware/neuralnetworks/1.2/types.h>
#include <android/hardware/neuralnetworks/1.3/IBuffer.h>
#include <android/hardware/neuralnetworks/1.3/IPreparedModel.h>
#include <android/hardware/neuralnetworks/1.3/IPreparedModelCallback.h>
#include <android/hardware/neuralnetworks/1.3/types.h>

#include <android/hidl/manager/1.0/IServiceNotification.h>

#include <hidl/HidlSupport.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <utils/NativeHandle.h>
#include <utils/misc.h>

namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_3 {

/**
 * This interface represents a device driver.
 */
struct IDevice : public ::android::hardware::neuralnetworks::V1_2::IDevice {
    /**
     * Type tag for use in template logic that indicates this is a 'pure' class.
     */
    typedef ::android::hardware::details::i_tag _hidl_tag;

    /**
     * Fully qualified interface name: "android.hardware.neuralnetworks@1.3::IDevice"
     */
    static const char* descriptor;

    /**
     * Returns whether this object's implementation is outside of the current process.
     */
    virtual bool isRemote() const override { return false; }

    /**
     * Return callback for getCapabilities
     */
    using getCapabilities_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::neuralnetworks::V1_0::Capabilities& capabilities)>;
    /**
     * Gets the capabilities of a driver.
     *
     * @return status Error status of the call, must be:
     *                - NONE if successful
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     * @return capabilities Capabilities of the driver.
     */
    virtual ::android::hardware::Return<void> getCapabilities(getCapabilities_cb _hidl_cb) = 0;

    /**
     * Return callback for getSupportedOperations
     */
    using getSupportedOperations_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::hidl_vec<bool>& supportedOperations)>;
    /**
     * Gets the supported operations in a model.
     *
     * getSupportedOperations indicates which operations of a model are fully
     * supported by the vendor driver. If an operation may not be supported for
     * any reason, getSupportedOperations must return false for that operation.
     *
     * @param model A model whose operations--and their corresponding
     *              operands--are to be verified by the driver.
     * @return status Error status of the call, must be:
     *                - NONE if successful
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - INVALID_ARGUMENT if provided model is invalid
     * @return supportedOperations A list of supported operations, where true
     *                             indicates the operation is supported and
     *                             false indicates the operation is not
     *                             supported. The index of "supported"
     *                             corresponds with the index of the operation
     *                             it is describing.
     */
    virtual ::android::hardware::Return<void> getSupportedOperations(const ::android::hardware::neuralnetworks::V1_0::Model& model, getSupportedOperations_cb _hidl_cb) = 0;

    /**
     * Creates a prepared model for execution.
     *
     * prepareModel is used to make any necessary transformations or alternative
     * representations to a model for execution, possiblly including
     * transformations on the constant data, optimization on the model's graph,
     * or compilation into the device's native binary format. The model itself
     * is not changed.
     *
     * The model is prepared asynchronously with respect to the caller. The
     * prepareModel function must verify the inputs to the prepareModel function
     * are correct. If there is an error, prepareModel must immediately invoke
     * the callback with the appropriate ErrorStatus value and nullptr for the
     * IPreparedModel, then return with the same ErrorStatus. If the inputs to
     * the prepareModel function are valid and there is no error, prepareModel
     * must launch an asynchronous task to prepare the model in the background,
     * and immediately return from prepareModel with ErrorStatus::NONE. If the
     * asynchronous task fails to launch, prepareModel must immediately invoke
     * the callback with ErrorStatus::GENERAL_FAILURE and nullptr for the
     * IPreparedModel, then return with ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished preparing the model, it must
     * immediately invoke the callback function provided as an input to
     * prepareModel. If the model was prepared successfully, the callback object
     * must be invoked with an error status of ErrorStatus::NONE and the
     * produced IPreparedModel object. If an error occurred preparing the model,
     * the callback object must be invoked with the appropriate ErrorStatus
     * value and nullptr for the IPreparedModel.
     *
     * The only information that may be unknown to the model at this stage is
     * the shape of the tensors, which may only be known at execution time. As
     * such, some driver services may return partially prepared models, where
     * the prepared model can only be finished when it is paired with a set of
     * inputs to the model. Note that the same prepared model object can be
     * used with different shapes of inputs on different (possibly concurrent)
     * executions.
     *
     * Multiple threads can call prepareModel on the same model concurrently.
     *
     * @param model The model to be prepared for execution.
     * @param callback A callback object used to return the error status of
     *                 preparing the model for execution and the prepared model
     *                 if successful, nullptr otherwise. The callback object's
     *                 notify function must be called exactly once, even if the
     *                 model could not be prepared.
     * @return status Error status of launching a task which prepares the model
     *                in the background; must be:
     *                - NONE if preparation task is successfully launched
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_0::ErrorStatus> prepareModel(const ::android::hardware::neuralnetworks::V1_0::Model& model, const ::android::sp<::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback>& callback) = 0;

    /**
     * Returns the current status of a driver.
     *
     * @return status Status of the driver, one of:
     *                - DeviceStatus::AVAILABLE
     *                - DeviceStatus::BUSY
     *                - DeviceStatus::OFFLINE
     *                - DeviceStatus::UNKNOWN
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_0::DeviceStatus> getStatus() = 0;

    /**
     * Return callback for getCapabilities_1_1
     */
    using getCapabilities_1_1_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::neuralnetworks::V1_1::Capabilities& capabilities)>;
    /**
     * Gets the capabilities of a driver.
     *
     * Note that @1.1::Capabilities provides performance information
     * on relaxed calculations, whereas @1.0::Capabilities does not.
     *
     * @return status Error status of the call, must be:
     *                - NONE if successful
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     * @return capabilities Capabilities of the driver.
     */
    virtual ::android::hardware::Return<void> getCapabilities_1_1(getCapabilities_1_1_cb _hidl_cb) = 0;

    /**
     * Return callback for getSupportedOperations_1_1
     */
    using getSupportedOperations_1_1_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::hidl_vec<bool>& supportedOperations)>;
    /**
     * Gets the supported operations in a model.
     *
     * getSupportedOperations indicates which operations of a model are fully
     * supported by the vendor driver. If an operation may not be supported for
     * any reason, getSupportedOperations must return false for that operation.
     *
     * @param model A model whose operations--and their corresponding
     *              operands--are to be verified by the driver.
     * @return status Error status of the call, must be:
     *                - NONE if successful
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - INVALID_ARGUMENT if provided model is invalid
     * @return supportedOperations A list of supported operations, where true
     *                             indicates the operation is supported and
     *                             false indicates the operation is not
     *                             supported. The index of "supported"
     *                             corresponds with the index of the operation
     *                             it is describing.
     */
    virtual ::android::hardware::Return<void> getSupportedOperations_1_1(const ::android::hardware::neuralnetworks::V1_1::Model& model, getSupportedOperations_1_1_cb _hidl_cb) = 0;

    /**
     * Creates a prepared model for execution.
     *
     * prepareModel is used to make any necessary transformations or alternative
     * representations to a model for execution, possiblly including
     * transformations on the constant data, optimization on the model's graph,
     * or compilation into the device's native binary format. The model itself
     * is not changed.
     *
     * The model is prepared asynchronously with respect to the caller. The
     * prepareModel function must verify the inputs to the prepareModel function
     * are correct. If there is an error, prepareModel must immediately invoke
     * the callback with the appropriate ErrorStatus value and nullptr for the
     * IPreparedModel, then return with the same ErrorStatus. If the inputs to
     * the prepareModel function are valid and there is no error, prepareModel
     * must launch an asynchronous task to prepare the model in the background,
     * and immediately return from prepareModel with ErrorStatus::NONE. If the
     * asynchronous task fails to launch, prepareModel must immediately invoke
     * the callback with ErrorStatus::GENERAL_FAILURE and nullptr for the
     * IPreparedModel, then return with ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished preparing the model, it must
     * immediately invoke the callback function provided as an input to
     * prepareModel. If the model was prepared successfully, the callback object
     * must be invoked with an error status of ErrorStatus::NONE and the
     * produced IPreparedModel object. If an error occurred preparing the model,
     * the callback object must be invoked with the appropriate ErrorStatus
     * value and nullptr for the IPreparedModel.
     *
     * The only information that may be unknown to the model at this stage is
     * the shape of the tensors, which may only be known at execution time. As
     * such, some driver services may return partially prepared models, where
     * the prepared model can only be finished when it is paired with a set of
     * inputs to the model. Note that the same prepared model object can be
     * used with different shapes of inputs on different (possibly concurrent)
     * executions.
     *
     * Multiple threads can call prepareModel on the same model concurrently.
     *
     * @param model The model to be prepared for execution.
     * @param preference Indicates the intended execution behavior of a prepared
     *                   model.
     * @param callback A callback object used to return the error status of
     *                 preparing the model for execution and the prepared model
     *                 if successful, nullptr otherwise. The callback object's
     *                 notify function must be called exactly once, even if the
     *                 model could not be prepared.
     * @return status Error status of launching a task which prepares the model
     *                in the background; must be:
     *                - NONE if preparation task is successfully launched
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_0::ErrorStatus> prepareModel_1_1(const ::android::hardware::neuralnetworks::V1_1::Model& model, ::android::hardware::neuralnetworks::V1_1::ExecutionPreference preference, const ::android::sp<::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback>& callback) = 0;

    /**
     * Return callback for getVersionString
     */
    using getVersionString_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::hidl_string& version)>;
    /**
     * Get the version string of the driver implementation.
     *
     * The version string must be a unique token among the set of version strings of
     * drivers of a specific device. The token identifies the device driver's
     * implementation. The token must not be confused with the feature level which is solely
     * defined by the interface version. This API is opaque to the Android framework, but the
     * Android framework may use the information for debugging or to pass on to NNAPI applications.
     *
     * Application developers sometimes have specific requirements to ensure good user experiences,
     * and they need more information to make intelligent decisions when the Android framework cannot.
     * For example, combined with the device name and other information, the token can help
     * NNAPI applications filter devices based on their needs:
     *     - An application demands a certain level of performance, but a specific version of
     *       the driver cannot meet that requirement because of a performance regression.
     *       The application can blacklist the driver based on the version provided.
     *     - An application has a minimum precision requirement, but certain versions of
     *       the driver cannot meet that requirement because of bugs or certain optimizations.
     *       The application can filter out versions of these drivers.
     *
     * @return status Error status returned from querying the version string. Must be:
     *     - NONE if the query was successful
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if the query resulted in an
     *       unspecified error
     * @return version The version string of the device implementation.
     *     Must have nonzero length
     */
    virtual ::android::hardware::Return<void> getVersionString(getVersionString_cb _hidl_cb) = 0;

    /**
     * Return callback for getType
     */
    using getType_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, ::android::hardware::neuralnetworks::V1_2::DeviceType type)>;
    /**
     * Get the type of a given device.
     *
     * The device type can be used to help application developers to distribute
     * Machine Learning workloads and other workloads such as graphical rendering.
     * E.g., for an app which renders AR scenes based on real time object detection
     * results, the developer could choose an ACCELERATOR type device for ML
     * workloads, and reserve GPU for graphical rendering.
     *
     * @return status Error status returned from querying the device type. Must be:
     *                - NONE if the query was successful
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if the query resulted in an
     *                  unspecified error
     * @return type The DeviceType of the device. Please note, this is not a
     *              bitfield of DeviceTypes. Each device must only be of a
     *              single DeviceType.
     */
    virtual ::android::hardware::Return<void> getType(getType_cb _hidl_cb) = 0;

    /**
     * Return callback for getCapabilities_1_2
     */
    using getCapabilities_1_2_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::neuralnetworks::V1_2::Capabilities& capabilities)>;
    /**
     * Gets the capabilities of a driver.
     *
     * @return status Error status of the call, must be:
     *                - NONE if successful
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     * @return capabilities Capabilities of the driver.
     */
    virtual ::android::hardware::Return<void> getCapabilities_1_2(getCapabilities_1_2_cb _hidl_cb) = 0;

    /**
     * Return callback for getSupportedExtensions
     */
    using getSupportedExtensions_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::hidl_vec<::android::hardware::neuralnetworks::V1_2::Extension>& extensions)>;
    /**
     * Gets information about extensions supported by the driver implementation.
     *
     * All extension operations and operands must be fully supported for the
     * extension to appear in the list of supported extensions.
     *
     * @return status Error status of the call, must be:
     *     - NONE if successful
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if there is an unspecified error
     * @return extensions A list of supported extensions.
     */
    virtual ::android::hardware::Return<void> getSupportedExtensions(getSupportedExtensions_cb _hidl_cb) = 0;

    /**
     * Return callback for getSupportedOperations_1_2
     */
    using getSupportedOperations_1_2_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::hidl_vec<bool>& supportedOperations)>;
    /**
     * Gets the supported operations in a model.
     *
     * getSupportedOperations indicates which operations of a model are fully
     * supported by the vendor driver. If an operation may not be supported for
     * any reason, getSupportedOperations must return false for that operation.
     *
     * @param model A model whose operations--and their corresponding operands--
     *     are to be verified by the driver.
     * @return status Error status of the call, must be:
     *     - NONE if successful
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if there is an unspecified error
     *     - INVALID_ARGUMENT if provided model is invalid
     * @return supportedOperations A list of supported operations, where true
     *     indicates the operation is supported and false indicates the
     *     operation is not supported. The index of "supported" corresponds with
     *     the index of the operation it is describing.
     */
    virtual ::android::hardware::Return<void> getSupportedOperations_1_2(const ::android::hardware::neuralnetworks::V1_2::Model& model, getSupportedOperations_1_2_cb _hidl_cb) = 0;

    /**
     * Return callback for getNumberOfCacheFilesNeeded
     */
    using getNumberOfCacheFilesNeeded_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, uint32_t numModelCache, uint32_t numDataCache)>;
    /**
     * Gets the caching requirements of the driver implementation.
     *
     * There are two types of cache file descriptors provided to the driver: model cache
     * and data cache.
     *
     * The data cache is for caching constant data, possibly including preprocessed
     * and transformed tensor buffers. Any modification to the data cache should
     * have no worse effect than generating bad output values at execution time.
     *
     * The model cache is for caching security-sensitive data such as compiled
     * executable machine code in the device's native binary format. A modification
     * to the model cache may affect the driver's execution behavior, and a malicious
     * client could make use of this to execute beyond the granted permission. Thus,
     * the driver must always check whether the model cache is corrupted before
     * preparing the model from cache.
     *
     * getNumberOfCacheFilesNeeded returns how many of each type of cache files the driver
     * implementation needs to cache a single prepared model. Returning 0 for both types
     * indicates compilation caching is not supported by this driver. The driver may
     * still choose not to cache certain compiled models even if it reports that caching
     * is supported.
     *
     * If the device reports that caching is not supported, the user may avoid calling
     * IDevice::prepareModelFromCache or providing cache file descriptors to
     * IDevice::prepareModel_1_2.
     *
     * @return status Error status of the call, must be:
     *     - NONE if successful
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if there is an unspecified error
     * @return numModelCache An unsigned integer indicating how many files for model cache
     *                       the driver needs to cache a single prepared model. It must
     *                       be less than or equal to Constant::MAX_NUMBER_OF_CACHE_FILES.
     * @return numDataCache An unsigned integer indicating how many files for data cache
     *                      the driver needs to cache a single prepared model. It must
     *                      be less than or equal to Constant::MAX_NUMBER_OF_CACHE_FILES.
     */
    virtual ::android::hardware::Return<void> getNumberOfCacheFilesNeeded(getNumberOfCacheFilesNeeded_cb _hidl_cb) = 0;

    /**
     * Asynchronously creates a prepared model for execution and optionally saves it
     * into cache files.
     *
     * prepareModel is used to make any necessary transformations to or alternative
     * representations to a model for execution, possibly including
     * transformations on the constant data, optimization on the model's graph,
     * or compilation into the device's native binary format. The model itself
     * is not changed.
     *
     * Optionally, caching information may be provided for the driver to save
     * the prepared model to cache files for faster model compilation time
     * when the same model preparation is requested in the future. There are
     * two types of cache file handles provided to the driver: model cache
     * and data cache. For more information on the two types of cache handles,
     * refer to getNumberOfCacheFilesNeeded.
     *
     * The file descriptors must be opened with read and write permission. A file may
     * have any size, and the corresponding file descriptor may have any offset. The
     * driver must truncate a file to zero size before writing to that file. The file
     * descriptors may be closed by the client once the asynchronous preparation has
     * finished. The driver must dup a file descriptor if it wants to get access to
     * the cache file later.
     *
     * The model is prepared asynchronously with respect to the caller. The
     * prepareModel function must verify the inputs to the preparedModel function
     * related to preparing the model (as opposed to saving the prepared model to
     * cache) are correct. If there is an error, prepareModel must immediately invoke
     * the callback with the appropriate ErrorStatus value and nullptr for the
     * IPreparedModel, then return with the same ErrorStatus. If the inputs to the
     * prepareModel function that are related to preparing the model are valid and
     * there is no error, prepareModel must launch an asynchronous task
     * to prepare the model in the background, and immediately return from
     * prepareModel with ErrorStatus::NONE. If the asynchronous task fails to launch,
     * prepareModel must immediately invoke the callback with
     * ErrorStatus::GENERAL_FAILURE and nullptr for the IPreparedModel, then return
     * with ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished preparing the model, it must
     * immediately invoke the callback function provided as an input to
     * prepareModel. If the model was prepared successfully, the callback object
     * must be invoked with an error status of ErrorStatus::NONE and the
     * produced IPreparedModel object. If an error occurred preparing the model,
     * the callback object must be invoked with the appropriate ErrorStatus
     * value and nullptr for the IPreparedModel.
     *
     * Optionally, the driver may save the prepared model to cache during the
     * asynchronous preparation. Any error that occurs when saving to cache must
     * not affect the status of preparing the model. Even if the input arguments
     * related to the cache may be invalid, or the driver may fail to save to cache,
     * the prepareModel function must finish preparing the model. The driver
     * may choose not to save to cache even if the caching information is
     * provided and valid.
     *
     * The only information that may be unknown to the model at this stage is
     * the shape of the tensors, which may only be known at execution time. As
     * such, some driver services may return partially prepared models, where
     * the prepared model may only be finished when it is paired with a set of
     * inputs to the model. Note that the same prepared model object may be
     * used with different shapes of inputs on different (possibly concurrent)
     * executions.
     *
     * Multiple threads may call prepareModel on the same model concurrently.
     *
     * @param model The model to be prepared for execution.
     * @param preference Indicates the intended execution behavior of a prepared
     *     model.
     * @param modelCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the security-sensitive cache. The length of
     *     the vector must either be 0 indicating that caching information is not provided,
     *     or match the numModelCache returned from getNumberOfCacheFilesNeeded. The cache
     *     handles will be provided in the same order when retrieving the
     *     preparedModel from cache files with prepareModelFromCache.
     * @param dataCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the constants' cache. The length of
     *     the vector must either be 0 indicating that caching information is not provided,
     *     or match the numDataCache returned from getNumberOfCacheFilesNeeded. The cache
     *     handles will be provided in the same order when retrieving the
     *     preparedModel from cache files with prepareModelFromCache.
     * @param token A caching token of length Constant::BYTE_SIZE_OF_CACHE_TOKEN
     *     identifying the prepared model. The same token will be provided when retrieving
     *     the prepared model from the cache files with prepareModelFromCache.
     *     Tokens should be chosen to have a low rate of collision for a particular
     *     application. The driver cannot detect a collision; a collision will result
     *     in a failed execution or in a successful execution that produces incorrect
     *     output values. If both modelCache and dataCache are empty indicating that
     *     caching information is not provided, this token must be ignored.
     * @param callback A callback object used to return the error status of
     *     preparing the model for execution and the prepared model if
     *     successful, nullptr otherwise. The callback object's notify function
     *     must be called exactly once, even if the model could not be prepared.
     * @return status Error status of launching a task which prepares the model
     *     in the background; must be:
     *     - NONE if preparation task is successfully launched
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if there is an unspecified error
     *     - INVALID_ARGUMENT if one of the input arguments related to preparing the
     *       model is invalid
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_0::ErrorStatus> prepareModel_1_2(const ::android::hardware::neuralnetworks::V1_2::Model& model, ::android::hardware::neuralnetworks::V1_1::ExecutionPreference preference, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& modelCache, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& dataCache, const ::android::hardware::hidl_array<uint8_t, 32 /* Constant:BYTE_SIZE_OF_CACHE_TOKEN */>& token, const ::android::sp<::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback>& callback) = 0;

    /**
     * Creates a prepared model from cache files for execution.
     *
     * prepareModelFromCache is used to retrieve a prepared model directly from
     * cache files to avoid slow model compilation time. There are
     * two types of cache file handles provided to the driver: model cache
     * and data cache. For more information on the two types of cache handles,
     * refer to getNumberOfCacheFilesNeeded.
     *
     * The file descriptors must be opened with read and write permission. A file may
     * have any size, and the corresponding file descriptor may have any offset. The
     * driver must truncate a file to zero size before writing to that file. The file
     * descriptors may be closed by the client once the asynchronous preparation has
     * finished. The driver must dup a file descriptor if it wants to get access to
     * the cache file later.
     *
     * The model is prepared asynchronously with respect to the caller. The
     * prepareModelFromCache function must verify the inputs to the
     * prepareModelFromCache function are correct, and that the security-sensitive
     * cache has not been modified since it was last written by the driver.
     * If there is an error, or if compilation caching is not supported, or if the
     * security-sensitive cache has been modified, prepareModelFromCache must
     * immediately invoke the callback with the appropriate ErrorStatus value and
     * nullptr for the IPreparedModel, then return with the same ErrorStatus. If
     * the inputs to the prepareModelFromCache function are valid, the security-sensitive
     * cache is not modified, and there is no error, prepareModelFromCache must launch an
     * asynchronous task to prepare the model in the background, and immediately return
     * from prepareModelFromCache with ErrorStatus::NONE. If the asynchronous task
     * fails to launch, prepareModelFromCache must immediately invoke the callback
     * with ErrorStatus::GENERAL_FAILURE and nullptr for the IPreparedModel, then
     * return with ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished preparing the model, it must
     * immediately invoke the callback function provided as an input to
     * prepareModelFromCache. If the model was prepared successfully, the
     * callback object must be invoked with an error status of ErrorStatus::NONE
     * and the produced IPreparedModel object. If an error occurred preparing
     * the model, the callback object must be invoked with the appropriate
     * ErrorStatus value and nullptr for the IPreparedModel.
     *
     * The only information that may be unknown to the model at this stage is
     * the shape of the tensors, which may only be known at execution time. As
     * such, some driver services may return partially prepared models, where
     * the prepared model may only be finished when it is paired with a set of
     * inputs to the model. Note that the same prepared model object may be
     * used with different shapes of inputs on different (possibly concurrent)
     * executions.
     *
     * @param modelCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the security-sensitive cache. The length of
     *     the vector must match the numModelCache returned from getNumberOfCacheFilesNeeded.
     *     The cache handles will be provided in the same order as with prepareModel_1_2.
     * @param dataCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the constants' cache. The length of the vector
     *     must match the numDataCache returned from getNumberOfCacheFilesNeeded.
     *     The cache handles will be provided in the same order as with prepareModel_1_2.
     * @param token A caching token of length Constant::BYTE_SIZE_OF_CACHE_TOKEN
     *     identifying the prepared model. It is the same token provided when saving
     *     the cache files with prepareModel_1_2. Tokens should be chosen
     *     to have a low rate of collision for a particular application. The driver
     *     cannot detect a collision; a collision will result in a failed execution
     *     or in a successful execution that produces incorrect output values.
     * @param callback A callback object used to return the error status of
     *     preparing the model for execution and the prepared model if
     *     successful, nullptr otherwise. The callback object's notify function
     *     must be called exactly once, even if the model could not be prepared.
     * @return status Error status of launching a task which prepares the model
     *     in the background; must be:
     *     - NONE if preparation task is successfully launched
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if caching is not supported or if there is an
     *       unspecified error
     *     - INVALID_ARGUMENT if one of the input arguments is invalid
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_0::ErrorStatus> prepareModelFromCache(const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& modelCache, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& dataCache, const ::android::hardware::hidl_array<uint8_t, 32 /* Constant:BYTE_SIZE_OF_CACHE_TOKEN */>& token, const ::android::sp<::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback>& callback) = 0;

    /**
     * Return callback for getCapabilities_1_3
     */
    using getCapabilities_1_3_cb = std::function<void(::android::hardware::neuralnetworks::V1_3::ErrorStatus status, const ::android::hardware::neuralnetworks::V1_3::Capabilities& capabilities)>;
    /**
     * Gets the capabilities of a driver.
     *
     * @return status Error status of the call, must be:
     *                - NONE if successful
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     * @return capabilities Capabilities of the driver.
     */
    virtual ::android::hardware::Return<void> getCapabilities_1_3(getCapabilities_1_3_cb _hidl_cb) = 0;

    /**
     * Return callback for getSupportedOperations_1_3
     */
    using getSupportedOperations_1_3_cb = std::function<void(::android::hardware::neuralnetworks::V1_3::ErrorStatus status, const ::android::hardware::hidl_vec<bool>& supportedOperations)>;
    /**
     * Gets the supported operations in a model.
     *
     * getSupportedOperations indicates which operations of the top-level
     * subgraph are fully supported by the vendor driver. If an operation may
     * not be supported for any reason, getSupportedOperations must return
     * false for that operation.
     *
     * The {@link OperationType::IF} and {@link OperationType::WHILE}
     * operations may only be fully supported if the vendor driver fully
     * supports all operations in the referenced subgraphs.
     *
     * @param model A model whose operations--and their corresponding operands--
     *     are to be verified by the driver.
     * @return status Error status of the call, must be:
     *     - NONE if successful
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if there is an unspecified error
     *     - INVALID_ARGUMENT if provided model is invalid
     * @return supportedOperations A list of supported operations, where true
     *     indicates the operation is supported and false indicates the
     *     operation is not supported. The index of "supported" corresponds with
     *     the index of the operation it is describing.
     */
    virtual ::android::hardware::Return<void> getSupportedOperations_1_3(const ::android::hardware::neuralnetworks::V1_3::Model& model, getSupportedOperations_1_3_cb _hidl_cb) = 0;

    /**
     * Asynchronously creates a prepared model for execution and optionally
     * saves it into cache files.
     *
     * prepareModel is used to make any necessary transformations to or
     * alternative representations to a model for execution, possibly including
     * transformations on the constant data, optimization on the model's graph,
     * or compilation into the device's native binary format. The model itself
     * is not changed.
     *
     * Optionally, caching information may be provided for the driver to save
     * the prepared model to cache files for faster model compilation time when
     * the same model preparation is requested in the future. There are two
     * types of cache file handles provided to the driver: model cache and data
     * cache. For more information on the two types of cache handles, refer to
     * getNumberOfCacheFilesNeeded.
     *
     * The file descriptors must be opened with read and write permission. A
     * file may have any size, and the corresponding file descriptor may have
     * any offset. The driver must truncate a file to zero size before writing
     * to that file. The file descriptors may be closed by the client once the
     * asynchronous preparation has finished. The driver must dup a file
     * descriptor if it wants to get access to the cache file later.
     *
     * The model is prepared asynchronously with respect to the caller. The
     * prepareModel function must verify the inputs to the preparedModel
     * function related to preparing the model (as opposed to saving the
     * prepared model to cache) are correct. If there is an error, prepareModel
     * must immediately invoke the callback with the appropriate ErrorStatus
     * value and nullptr for the IPreparedModel, then return with the same
     * ErrorStatus. If the inputs to the prepareModel function that are related
     * to preparing the model are valid and there is no error, prepareModel must
     * launch an asynchronous task to prepare the model in the background, and
     * immediately return from prepareModel with ErrorStatus::NONE. If the
     * asynchronous task fails to launch, prepareModel must immediately invoke
     * the callback with ErrorStatus::GENERAL_FAILURE and nullptr for the
     * IPreparedModel, then return with ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished preparing the model, it must
     * immediately invoke the callback function provided as an input to
     * prepareModel. If the model was prepared successfully, the callback object
     * must be invoked with an error status of ErrorStatus::NONE and the
     * produced IPreparedModel object. If an error occurred preparing the model,
     * the callback object must be invoked with the appropriate ErrorStatus
     * value and nullptr for the IPreparedModel.
     *
     * The model is prepared with a priority. This priority is relative to other
     * prepared models owned by the same client. Higher priority executions may
     * use more compute resources than lower priority executions, and may
     * preempt or starve lower priority executions.
     *
     * prepareModel_1_3 can be called with an optional deadline. If the model
     * is not able to be prepared before the provided deadline, the model
     * preparation may be aborted, and either {@link
     * ErrorStatus::MISSED_DEADLINE_TRANSIENT} or {@link
     * ErrorStatus::MISSED_DEADLINE_PERSISTENT} may be returned. The error due
     * to an abort must be sent the same way as other errors, described above.
     *
     * Optionally, the driver may save the prepared model to cache during the
     * asynchronous preparation. Any error that occurs when saving to cache must
     * not affect the status of preparing the model. Even if the input arguments
     * related to the cache may be invalid, or the driver may fail to save to
     * cache, the prepareModel function must finish preparing the model. The
     * driver may choose not to save to cache even if the caching information is
     * provided and valid.
     *
     * The only information that may be unknown to the model at this stage is
     * the shape of the tensors, which may only be known at execution time. As
     * such, some driver services may return partially prepared models, where
     * the prepared model may only be finished when it is paired with a set of
     * inputs to the model. Note that the same prepared model object may be used
     * with different shapes of inputs on different (possibly concurrent)
     * executions.
     *
     * Multiple threads may call prepareModel on the same model concurrently.
     *
     * @param model The model to be prepared for execution.
     * @param preference Indicates the intended execution behavior of a prepared
     *     model.
     * @param priority The priority of the prepared model relative to other
     *     prepared models owned by the client.
     * @param deadline The time by which the model is expected to be prepared.
     *     If the model cannot be prepared by the deadline, the preparation may
     *     be aborted.
     * @param modelCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the security-sensitive cache. The length of
     *     the vector must either be 0 indicating that caching information is
     *     not provided, or match the numModelCache returned from
     *     getNumberOfCacheFilesNeeded. The cache handles will be provided in
     *     the same order when retrieving the preparedModel from cache files
     *     with prepareModelFromCache_1_3.
     * @param dataCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the constants' cache. The length of the
     *     vector must either be 0 indicating that caching information is not
     *     provided, or match the numDataCache returned from
     *     getNumberOfCacheFilesNeeded. The cache handles will be provided in
     *     the same order when retrieving the preparedModel from cache files
     *     with prepareModelFromCache_1_3.
     * @param token A caching token of length Constant::BYTE_SIZE_OF_CACHE_TOKEN
     *     identifying the prepared model. The same token will be provided when
     *     retrieving the prepared model from the cache files with
     *     prepareModelFromCache_1_3.  Tokens should be chosen to have a low rate of
     *     collision for a particular application. The driver cannot detect a
     *     collision; a collision will result in a failed execution or in a
     *     successful execution that produces incorrect output values. If both
     *     modelCache and dataCache are empty indicating that caching
     *     information is not provided, this token must be ignored.
     * @param callback A callback object used to return the error status of
     *     preparing the model for execution and the prepared model if
     *     successful, nullptr otherwise. The callback object's notify function
     *     must be called exactly once, even if the model could not be prepared.
     * @return status Error status of launching a task which prepares the model
     *     in the background; must be:
     *     - NONE if preparation task is successfully launched
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if there is an unspecified error
     *     - INVALID_ARGUMENT if one of the input arguments related to preparing
     *       the model is invalid
     *     - MISSED_DEADLINE_* if the preparation is aborted because the model
     *       cannot be prepared by the deadline
     *     - RESOURCE_EXHAUSTED_* if the task was aborted by the driver
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_3::ErrorStatus> prepareModel_1_3(const ::android::hardware::neuralnetworks::V1_3::Model& model, ::android::hardware::neuralnetworks::V1_1::ExecutionPreference preference, ::android::hardware::neuralnetworks::V1_3::Priority priority, const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint& deadline, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& modelCache, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& dataCache, const ::android::hardware::hidl_array<uint8_t, 32 /* Constant:BYTE_SIZE_OF_CACHE_TOKEN */>& token, const ::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModelCallback>& callback) = 0;

    /**
     * Creates a prepared model from cache files for execution.
     *
     * prepareModelFromCache_1_3 is used to retrieve a prepared model directly from
     * cache files to avoid slow model compilation time. There are
     * two types of cache file handles provided to the driver: model cache
     * and data cache. For more information on the two types of cache handles,
     * refer to getNumberOfCacheFilesNeeded.
     *
     * The file descriptors must be opened with read and write permission. A file may
     * have any size, and the corresponding file descriptor may have any offset. The
     * driver must truncate a file to zero size before writing to that file. The file
     * descriptors may be closed by the client once the asynchronous preparation has
     * finished. The driver must dup a file descriptor if it wants to get access to
     * the cache file later.
     *
     * The model is prepared asynchronously with respect to the caller. The
     * prepareModelFromCache_1_3 function must verify the inputs to the
     * prepareModelFromCache_1_3 function are correct, and that the security-sensitive
     * cache has not been modified since it was last written by the driver.
     * If there is an error, or if compilation caching is not supported, or if the
     * security-sensitive cache has been modified, prepareModelFromCache_1_3 must
     * immediately invoke the callback with the appropriate ErrorStatus value and
     * nullptr for the IPreparedModel, then return with the same ErrorStatus. If
     * the inputs to the prepareModelFromCache_1_3 function are valid, the security-sensitive
     * cache is not modified, and there is no error, prepareModelFromCache_1_3 must launch an
     * asynchronous task to prepare the model in the background, and immediately return
     * from prepareModelFromCache_1_3 with ErrorStatus::NONE. If the asynchronous task
     * fails to launch, prepareModelFromCache_1_3 must immediately invoke the callback
     * with ErrorStatus::GENERAL_FAILURE and nullptr for the IPreparedModel, then
     * return with ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished preparing the model, it must
     * immediately invoke the callback function provided as an input to
     * prepareModelFromCache_1_3. If the model was prepared successfully, the
     * callback object must be invoked with an error status of ErrorStatus::NONE
     * and the produced IPreparedModel object. If an error occurred preparing
     * the model, the callback object must be invoked with the appropriate
     * ErrorStatus value and nullptr for the IPreparedModel.
     *
     * prepareModelFromCache_1_3 can be called with an optional deadline. If the
     * model is not able to prepared before the provided deadline, the model
     * preparation may be aborted, and either {@link
     * ErrorStatus::MISSED_DEADLINE_TRANSIENT}
     * or {@link ErrorStatus::MISSED_DEADLINE_PERSISTENT} may be returned. The
     * error due to an abort must be sent the same way as other errors,
     * described above.
     *
     * The only information that may be unknown to the model at this stage is
     * the shape of the tensors, which may only be known at execution time. As
     * such, some driver services may return partially prepared models, where
     * the prepared model may only be finished when it is paired with a set of
     * inputs to the model. Note that the same prepared model object may be
     * used with different shapes of inputs on different (possibly concurrent)
     * executions.
     *
     * @param deadline The time by which the model is expected to be prepared.
     *     If the model cannot be prepared by the deadline, the preparation may
     *     be aborted.
     * @param modelCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the security-sensitive cache. The length of
     *     the vector must match the numModelCache returned from getNumberOfCacheFilesNeeded.
     *     The cache handles will be provided in the same order as with prepareModel_1_3.
     * @param dataCache A vector of handles with each entry holding exactly one
     *     cache file descriptor for the constants' cache. The length of the vector
     *     must match the numDataCache returned from getNumberOfCacheFilesNeeded.
     *     The cache handles will be provided in the same order as with prepareModel_1_3.
     * @param token A caching token of length Constant::BYTE_SIZE_OF_CACHE_TOKEN
     *     identifying the prepared model. It is the same token provided when saving
     *     the cache files with prepareModel_1_3. Tokens should be chosen
     *     to have a low rate of collision for a particular application. The driver
     *     cannot detect a collision; a collision will result in a failed execution
     *     or in a successful execution that produces incorrect output values.
     * @param callback A callback object used to return the error status of
     *     preparing the model for execution and the prepared model if
     *     successful, nullptr otherwise. The callback object's notify function
     *     must be called exactly once, even if the model could not be prepared.
     * @return status Error status of launching a task which prepares the model
     *     in the background; must be:
     *     - NONE if preparation task is successfully launched
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if caching is not supported or if there is an
     *       unspecified error
     *     - INVALID_ARGUMENT if one of the input arguments is invalid
     *     - MISSED_DEADLINE_* if the preparation is aborted because the model
     *       cannot be prepared by the deadline
     *     - RESOURCE_EXHAUSTED_* if the task was aborted by the driver
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_3::ErrorStatus> prepareModelFromCache_1_3(const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint& deadline, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& modelCache, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& dataCache, const ::android::hardware::hidl_array<uint8_t, 32 /* Constant:BYTE_SIZE_OF_CACHE_TOKEN */>& token, const ::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModelCallback>& callback) = 0;

    /**
     * Return callback for allocate
     */
    using allocate_cb = std::function<void(::android::hardware::neuralnetworks::V1_3::ErrorStatus status, const ::android::sp<::android::hardware::neuralnetworks::V1_3::IBuffer>& buffer, uint32_t token)>;
    /**
     * Allocates a driver-managed buffer with the properties specified by the buffer descriptor
     * as well as the input and output roles.
     *
     * The allocate function must verify its inputs are correct. If there is an error, or if a
     * certain role or property is not supported by the driver, the allocate
     * function must return with an appropriate ErrorStatus, a nullptr as the IBuffer, and 0 as the
     * buffer token. If the allocation is successful, this method must return with ErrorStatus::NONE
     * and the produced IBuffer with a positive token identifying the allocated buffer. A successful
     * allocation must accommodate all of the specified roles and buffer properties.
     *
     * The buffer is allocated to an uninitialized state. An uninitialized buffer may only be used
     * in ways that are specified by outputRoles. A buffer is initialized after it is used as an
     * output in a successful execution, or after a successful invocation of IBuffer::copyFrom on
     * the buffer. An initialized buffer may be used according to all roles specified in inputRoles
     * and outputRoles. A buffer will return to the uninitialized state if it is used as an output
     * in a failed execution, or after a failed invocation of IBuffer::copyFrom on the buffer.
     *
     * The dimensions of the buffer can be deduced from the buffer descriptor as well as the
     * dimensions of the corresponding model operands of the input and output roles. The dimensions
     * or rank of the buffer may be unknown at this stage. As such, some driver services may only
     * create a placeholder and defer the actual allocation until execution time. Note that the
     * same buffer may be used for different shapes of outputs on different executions. When the
     * buffer is used as an input, the input shape must be the same as the output shape from the
     * last execution using this buffer as an output.
     *
     * The driver must apply proper validatation upon every usage of the buffer, and must fail the
     * execution immediately if the usage is illegal.
     *
     * @param desc A buffer descriptor specifying the properties of the buffer to allocate.
     * @param preparedModels A vector of IPreparedModel objects. Must only contain IPreparedModel
     *     objects from the same IDevice as this method is being invoked on.
     * @param inputRoles A vector of roles with each specifying an input to a prepared model.
     * @param outputRoles A vector of roles with each specifying an output to a prepared model.
     *     Each role specified in inputRoles and outputRoles must be unique. The corresponding
     *     model operands of the roles must have the same OperandType, scale, zero point, and
     *     ExtraParams. The dimensions of the operands and the dimensions specified in the buffer
     *     descriptor must be compatible with each other. Two dimensions are incompatible if there
     *     is at least one axis that is fully specified in both but has different values.
     * @return status Error status of the buffer allocation. Must be:
     *     - NONE if successful
     *     - DEVICE_UNAVAILABLE if driver is offline or busy
     *     - GENERAL_FAILURE if a certain buffer property or a certain role is not supported,
     *       or if there is an unspecified error
     *     - INVALID_ARGUMENT if one of the input arguments is invalid
     * @return buffer The allocated IBuffer object. If the buffer was unable to be allocated
     *     due to an error, nullptr must be returned.
     * @return token A positive token identifying the allocated buffer. The same token will be
     *     provided when referencing the buffer as one of the memory pools in the request of an
     *     execution. The token must not collide with the tokens of other IBuffer objects that are
     *     currently alive in the same driver service. If the buffer was unable to be allocated
     *     due to an error, the token must be 0.
     */
    virtual ::android::hardware::Return<void> allocate(const ::android::hardware::neuralnetworks::V1_3::BufferDesc& desc, const ::android::hardware::hidl_vec<::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>>& preparedModels, const ::android::hardware::hidl_vec<::android::hardware::neuralnetworks::V1_3::BufferRole>& inputRoles, const ::android::hardware::hidl_vec<::android::hardware::neuralnetworks::V1_3::BufferRole>& outputRoles, allocate_cb _hidl_cb) = 0;

    /**
     * Return callback for interfaceChain
     */
    using interfaceChain_cb = std::function<void(const ::android::hardware::hidl_vec<::android::hardware::hidl_string>& descriptors)>;
    /*
     * Provides run-time type information for this object.
     * For example, for the following interface definition:
     *     package android.hardware.foo@1.0;
     *     interface IParent {};
     *     interface IChild extends IParent {};
     * Calling interfaceChain on an IChild object must yield the following:
     *     ["android.hardware.foo@1.0::IChild",
     *      "android.hardware.foo@1.0::IParent"
     *      "android.hidl.base@1.0::IBase"]
     *
     * @return descriptors a vector of descriptors of the run-time type of the
     *         object.
     */
    virtual ::android::hardware::Return<void> interfaceChain(interfaceChain_cb _hidl_cb) override;

    /*
     * Emit diagnostic information to the given file.
     *
     * Optionally overriden.
     *
     * @param fd      File descriptor to dump data to.
     *                Must only be used for the duration of this call.
     * @param options Arguments for debugging.
     *                Must support empty for default debug information.
     */
    virtual ::android::hardware::Return<void> debug(const ::android::hardware::hidl_handle& fd, const ::android::hardware::hidl_vec<::android::hardware::hidl_string>& options) override;

    /**
     * Return callback for interfaceDescriptor
     */
    using interfaceDescriptor_cb = std::function<void(const ::android::hardware::hidl_string& descriptor)>;
    /*
     * Provides run-time type information for this object.
     * For example, for the following interface definition:
     *     package android.hardware.foo@1.0;
     *     interface IParent {};
     *     interface IChild extends IParent {};
     * Calling interfaceDescriptor on an IChild object must yield
     *     "android.hardware.foo@1.0::IChild"
     *
     * @return descriptor a descriptor of the run-time type of the
     *         object (the first element of the vector returned by
     *         interfaceChain())
     */
    virtual ::android::hardware::Return<void> interfaceDescriptor(interfaceDescriptor_cb _hidl_cb) override;

    /**
     * Return callback for getHashChain
     */
    using getHashChain_cb = std::function<void(const ::android::hardware::hidl_vec<::android::hardware::hidl_array<uint8_t, 32>>& hashchain)>;
    /*
     * Returns hashes of the source HAL files that define the interfaces of the
     * runtime type information on the object.
     * For example, for the following interface definition:
     *     package android.hardware.foo@1.0;
     *     interface IParent {};
     *     interface IChild extends IParent {};
     * Calling interfaceChain on an IChild object must yield the following:
     *     [(hash of IChild.hal),
     *      (hash of IParent.hal)
     *      (hash of IBase.hal)].
     *
     * SHA-256 is used as the hashing algorithm. Each hash has 32 bytes
     * according to SHA-256 standard.
     *
     * @return hashchain a vector of SHA-1 digests
     */
    virtual ::android::hardware::Return<void> getHashChain(getHashChain_cb _hidl_cb) override;

    /*
     * This method trigger the interface to enable/disable instrumentation based
     * on system property hal.instrumentation.enable.
     */
    virtual ::android::hardware::Return<void> setHALInstrumentation() override;

    /*
     * Registers a death recipient, to be called when the process hosting this
     * interface dies.
     *
     * @param recipient a hidl_death_recipient callback object
     * @param cookie a cookie that must be returned with the callback
     * @return success whether the death recipient was registered successfully.
     */
    virtual ::android::hardware::Return<bool> linkToDeath(const ::android::sp<::android::hardware::hidl_death_recipient>& recipient, uint64_t cookie) override;

    /*
     * Provides way to determine if interface is running without requesting
     * any functionality.
     */
    virtual ::android::hardware::Return<void> ping() override;

    /**
     * Return callback for getDebugInfo
     */
    using getDebugInfo_cb = std::function<void(const ::android::hidl::base::V1_0::DebugInfo& info)>;
    /*
     * Get debug information on references on this interface.
     * @return info debugging information. See comments of DebugInfo.
     */
    virtual ::android::hardware::Return<void> getDebugInfo(getDebugInfo_cb _hidl_cb) override;

    /*
     * This method notifies the interface that one or more system properties
     * have changed. The default implementation calls
     * (C++)  report_sysprop_change() in libcutils or
     * (Java) android.os.SystemProperties.reportSyspropChanged,
     * which in turn calls a set of registered callbacks (eg to update trace
     * tags).
     */
    virtual ::android::hardware::Return<void> notifySyspropsChanged() override;

    /*
     * Unregisters the registered death recipient. If this service was registered
     * multiple times with the same exact death recipient, this unlinks the most
     * recently registered one.
     *
     * @param recipient a previously registered hidl_death_recipient callback
     * @return success whether the death recipient was unregistered successfully.
     */
    virtual ::android::hardware::Return<bool> unlinkToDeath(const ::android::sp<::android::hardware::hidl_death_recipient>& recipient) override;

    // cast static functions
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>> castFrom(const ::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>& parent, bool emitError = false);
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>> castFrom(const ::android::sp<::android::hardware::neuralnetworks::V1_2::IDevice>& parent, bool emitError = false);
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>> castFrom(const ::android::sp<::android::hardware::neuralnetworks::V1_1::IDevice>& parent, bool emitError = false);
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>> castFrom(const ::android::sp<::android::hardware::neuralnetworks::V1_0::IDevice>& parent, bool emitError = false);
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>> castFrom(const ::android::sp<::android::hidl::base::V1_0::IBase>& parent, bool emitError = false);

    // helper methods for interactions with the hwservicemanager
    /**
     * This gets the service of this type with the specified instance name. If the
     * service is currently not available or not in the VINTF manifest on a Trebilized
     * device, this will return nullptr. This is useful when you don't want to block
     * during device boot. If getStub is true, this will try to return an unwrapped
     * passthrough implementation in the same process. This is useful when getting an
     * implementation from the same partition/compilation group.
     *
     * In general, prefer getService(std::string,bool)
     */
    static ::android::sp<IDevice> tryGetService(const std::string &serviceName="default", bool getStub=false);
    /**
     * Deprecated. See tryGetService(std::string, bool)
     */
    static ::android::sp<IDevice> tryGetService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return tryGetService(str, getStub); }
    /**
     * Deprecated. See tryGetService(std::string, bool)
     */
    static ::android::sp<IDevice> tryGetService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return tryGetService(str, getStub); }
    /**
     * Calls tryGetService("default", bool). This is the recommended instance name for singleton services.
     */
    static ::android::sp<IDevice> tryGetService(bool getStub) { return tryGetService("default", getStub); }
    /**
     * This gets the service of this type with the specified instance name. If the
     * service is not in the VINTF manifest on a Trebilized device, this will return
     * nullptr. If the service is not available, this will wait for the service to
     * become available. If the service is a lazy service, this will start the service
     * and return when it becomes available. If getStub is true, this will try to
     * return an unwrapped passthrough implementation in the same process. This is
     * useful when getting an implementation from the same partition/compilation group.
     */
    static ::android::sp<IDevice> getService(const std::string &serviceName="default", bool getStub=false);
    /**
     * Deprecated. See getService(std::string, bool)
     */
    static ::android::sp<IDevice> getService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return getService(str, getStub); }
    /**
     * Deprecated. See getService(std::string, bool)
     */
    static ::android::sp<IDevice> getService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return getService(str, getStub); }
    /**
     * Calls getService("default", bool). This is the recommended instance name for singleton services.
     */
    static ::android::sp<IDevice> getService(bool getStub) { return getService("default", getStub); }
    /**
     * Registers a service with the service manager. For Trebilized devices, the service
     * must also be in the VINTF manifest.
     */
    __attribute__ ((warn_unused_result))::android::status_t registerAsService(const std::string &serviceName="default");
    /**
     * Registers for notifications for when a service is registered.
     */
    static bool registerForNotifications(
            const std::string &serviceName,
            const ::android::sp<::android::hidl::manager::V1_0::IServiceNotification> &notification);
};

//
// type declarations for package
//

static inline std::string toString(const ::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>& o);

//
// type header definitions for package
//

static inline std::string toString(const ::android::sp<::android::hardware::neuralnetworks::V1_3::IDevice>& o) {
    std::string os = "[class or subclass of ";
    os += ::android::hardware::neuralnetworks::V1_3::IDevice::descriptor;
    os += "]";
    os += o->isRemote() ? "@remote" : "@local";
    return os;
}


}  // namespace V1_3
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android

//
// global type declarations for package
//


#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_IDEVICE_H
