#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_IPREPAREDMODEL_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_IPREPAREDMODEL_H

#include <android/hardware/neuralnetworks/1.2/IPreparedModel.h>
#include <android/hardware/neuralnetworks/1.2/types.h>
#include <android/hardware/neuralnetworks/1.3/IExecutionCallback.h>
#include <android/hardware/neuralnetworks/1.3/IFencedExecutionCallback.h>
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
 * IPreparedModel describes a model that has been prepared for execution and
 * is used to launch executions.
 */
struct IPreparedModel : public ::android::hardware::neuralnetworks::V1_2::IPreparedModel {
    /**
     * Type tag for use in template logic that indicates this is a 'pure' class.
     */
    typedef ::android::hardware::details::i_tag _hidl_tag;

    /**
     * Fully qualified interface name: "android.hardware.neuralnetworks@1.3::IPreparedModel"
     */
    static const char* descriptor;

    /**
     * Returns whether this object's implementation is outside of the current process.
     */
    virtual bool isRemote() const override { return false; }

    /**
     * Launches an asynchronous execution on a prepared model.
     *
     * The execution is performed asynchronously with respect to the caller.
     * execute must verify the inputs to the function are correct. If there is
     * an error, execute must immediately invoke the callback with the
     * appropriate ErrorStatus value, then return with the same ErrorStatus. If
     * the inputs to the function are valid and there is no error, execute must
     * launch an asynchronous task to perform the execution in the background,
     * and immediately return with ErrorStatus::NONE. If the asynchronous task
     * fails to launch, execute must immediately invoke the callback with
     * ErrorStatus::GENERAL_FAILURE, then return with
     * ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished its execution, it must
     * immediately invoke the callback object provided as an input to the
     * execute function. This callback must be provided with the ErrorStatus of
     * the execution.
     *
     * If the launch is successful, the caller must not change the content of
     * any data object referenced by 'request' (described by the
     * {@link DataLocation} of a {@link RequestArgument}) until the
     * asynchronous task has invoked the callback object. The asynchronous task
     * must not change the content of any of the data objects corresponding to
     * 'request' inputs.
     *
     * If the prepared model was prepared from a model wherein all tensor
     * operands have fully specified dimensions, and the inputs to the function
     * are valid, then:
     * - the execution should launch successfully (ErrorStatus::NONE): There
     *   must be no failure unless the device itself is in a bad state.
     * - if at execution time every operation's input operands have legal
     *   values, the execution should complete successfully (ErrorStatus::NONE):
     *   There must be no failure unless the device itself is in a bad state.
     *
     * Multiple threads can call the execute function on the same IPreparedModel
     * object concurrently with different requests.
     *
     * @param request The input and output information on which the prepared
     *                model is to be executed.
     * @param callback A callback object used to return the error status of
     *                 the execution. The callback object's notify function must
     *                 be called exactly once, even if the execution was
     *                 unsuccessful.
     * @return status Error status of the call, must be:
     *                - NONE if task is successfully launched
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - OUTPUT_INSUFFICIENT_SIZE if provided output buffer is
     *                  not large enough to store the resultant values
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_0::ErrorStatus> execute(const ::android::hardware::neuralnetworks::V1_0::Request& request, const ::android::sp<::android::hardware::neuralnetworks::V1_0::IExecutionCallback>& callback) = 0;

    /**
     * Launches an asynchronous execution on a prepared model.
     *
     * The execution is performed asynchronously with respect to the caller.
     * execute_1_2 must verify the inputs to the function are correct. If there is
     * an error, execute_1_2 must immediately invoke the callback with the
     * appropriate ErrorStatus value, then return with the same ErrorStatus. If
     * the inputs to the function are valid and there is no error, execute_1_2 must
     * launch an asynchronous task to perform the execution in the background,
     * and immediately return with ErrorStatus::NONE. If the asynchronous task
     * fails to launch, execute_1_2 must immediately invoke the callback with
     * ErrorStatus::GENERAL_FAILURE, then return with
     * ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished its execution, it must
     * immediately invoke the callback object provided as an input to the
     * execute_1_2 function. This callback must be provided with the ErrorStatus of
     * the execution.
     *
     * If the launch is successful, the caller must not change the content of
     * any data object referenced by 'request' (described by the
     * {@link @1.0::DataLocation} of a {@link @1.0::RequestArgument}) until the
     * asynchronous task has invoked the callback object. The asynchronous task
     * must not change the content of any of the data objects corresponding to
     * 'request' inputs.
     *
     * If the prepared model was prepared from a model wherein all tensor
     * operands have fully specified dimensions, and the inputs to the function
     * are valid, then:
     * - the execution should launch successfully (ErrorStatus::NONE): There
     *   must be no failure unless the device itself is in a bad state.
     * - if at execution time every operation's input operands have legal
     *   values, the execution should complete successfully (ErrorStatus::NONE):
     *   There must be no failure unless the device itself is in a bad state.
     *
     * Any number of calls to the execute, execute_1_2, and executeSynchronously
     * functions, in any combination, may be made concurrently, even on the same
     * IPreparedModel object.
     *
     * @param request The input and output information on which the prepared
     *                model is to be executed.
     * @param measure Specifies whether or not to measure duration of the execution.
     *                The duration runs from the time the driver sees the call
     *                to the execute_1_2 function to the time the driver invokes
     *                the callback.
     * @param callback A callback object used to return the error status of
     *                 the execution. The callback object's notify function must
     *                 be called exactly once, even if the execution was
     *                 unsuccessful.
     * @return status Error status of the call, must be:
     *                - NONE if task is successfully launched
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - OUTPUT_INSUFFICIENT_SIZE if provided output buffer is
     *                  not large enough to store the resultant values
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_0::ErrorStatus> execute_1_2(const ::android::hardware::neuralnetworks::V1_0::Request& request, ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure, const ::android::sp<::android::hardware::neuralnetworks::V1_2::IExecutionCallback>& callback) = 0;

    /**
     * Return callback for executeSynchronously
     */
    using executeSynchronously_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::hardware::hidl_vec<::android::hardware::neuralnetworks::V1_2::OutputShape>& outputShapes, const ::android::hardware::neuralnetworks::V1_2::Timing& timing)>;
    /**
     * Performs a synchronous execution on a prepared model.
     *
     * The execution is performed synchronously with respect to the caller.
     * executeSynchronously must verify the inputs to the function are
     * correct. If there is an error, executeSynchronously must immediately
     * return with the appropriate ErrorStatus value. If the inputs to the
     * function are valid and there is no error, executeSynchronously must
     * perform the execution, and must not return until the execution is
     * complete.
     *
     * The caller must not change the content of any data object referenced by
     * 'request' (described by the {@link @1.0::DataLocation} of a
     * {@link @1.0::RequestArgument}) until executeSynchronously
     * returns. executeSynchronously must not change the content of any of the
     * data objects corresponding to 'request' inputs.
     *
     * If the prepared model was prepared from a model wherein all tensor
     * operands have fully specified dimensions, and the inputs to the function
     * are valid, and at execution time every operation's input operands have
     * legal values, then the execution should complete successfully
     * (ErrorStatus::NONE): There must be no failure unless the device itself is
     * in a bad state.
     *
     * Any number of calls to the execute, execute_1_2, and executeSynchronously
     * functions, in any combination, may be made concurrently, even on the same
     * IPreparedModel object.
     *
     * @param request The input and output information on which the prepared
     *                model is to be executed.
     * @param measure Specifies whether or not to measure duration of the execution.
     *                The duration runs from the time the driver sees the call
     *                to the executeSynchronously function to the time the driver
     *                returns from the function.
     * @return status Error status of the execution, must be:
     *                - NONE if execution is performed successfully
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - OUTPUT_INSUFFICIENT_SIZE if at least one output
     *                  operand buffer is not large enough to store the
     *                  corresponding output
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     * @return outputShapes A list of shape information of model output operands.
     *                      The index into "outputShapes" corresponds to the index
     *                      of the output operand in the Request outputs vector.
     *                      outputShapes must be empty unless the status is either
     *                      NONE or OUTPUT_INSUFFICIENT_SIZE.
     * @return Timing Duration of execution. Unless measure is YES and status is
     *                NONE, all times must be reported as UINT64_MAX. A driver may
     *                choose to report any time as UINT64_MAX, indicating that
     *                measurement is not available.
     */
    virtual ::android::hardware::Return<void> executeSynchronously(const ::android::hardware::neuralnetworks::V1_0::Request& request, ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure, executeSynchronously_cb _hidl_cb) = 0;

    /**
     * Return callback for configureExecutionBurst
     */
    using configureExecutionBurst_cb = std::function<void(::android::hardware::neuralnetworks::V1_0::ErrorStatus status, const ::android::sp<::android::hardware::neuralnetworks::V1_2::IBurstContext>& context)>;
    /**
     * Configure a Burst object used to execute multiple inferences on a
     * prepared model in rapid succession.
     *
     * If the prepared model was prepared from a model wherein all tensor
     * operands have fully specified dimensions, and a valid serialized Request
     * is sent to the Burst for execution, and at execution time every
     * operation's input operands have legal values, then the execution should
     * complete successfully (ErrorStatus::NONE): There must be no failure
     * unless the device itself is in a bad state.
     *
     * @param callback A callback object used to retrieve memory resources
     *                 corresponding to unique identifiers ("slots").
     * @param requestChannel FMQ used by the client to send a serialized Request
     *                       to the Burst for execution. The client must not
     *                       change the content of any data object referenced by
     *                       the Request (described by the
     *                       {@link @1.0::DataLocation} of an
     *                       {@link OperandInformation}) until a result has been
     *                       received from resultChannel. Execution must not
     *                       change the content of any of the data objects
     *                       corresponding to Request inputs. requestChannel
     *                       must not be used to pass a second Request object
     *                       until a result has been received from
     *                       resultChannel. The client must send the request
     *                       messages to the consumer atomically by using
     *                       MessageQueue::writeBlocking if the queue is
     *                       blocking, or by using MessageQueue::write if the
     *                       queue is non-blocking. When the service receives a
     *                       packet, it must dequeue the entire packet from the
     *                       requestChannel. The client must not send a request
     *                       packet that exceeds the length of the FMQ.
     * @param resultChannel FMQ used by the service to return the results of an
     *                      execution to the client: the status of the
     *                      execution, OutputShape of all output tensors, and
     *                      timing information. resultChannel must be used to
     *                      return the results if a Request was sent through the
     *                      requestChannel. The service must send the result
     *                      messages to the consumer atomically by using
     *                      MessageQueue::writeBlocking if the queue is
     *                      blocking, or by using MessageQueue::write if the
     *                      queue is non-blocking. When the client receives a
     *                      packet, it must dequeue the entire packet from the
     *                      resultChannel. If the packet's length exceeds the
     *                      size of the FMQ, the service must not send this
     *                      result packet; instead, the service must send a
     *                      packet consisting of the error code
     *                      ErrorStatus::GENERAL_FAILURE, no information for the
     *                      outputShapes, and an indication that timing
     *                      information is unavailable.
     * @return status Error status of configuring the execution burst, must be:
     *                - NONE if the burst is successfully configured
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     * @return context Object containing all resources (such as cached
     *                 hidl_memory) related to a Burst if successful, otherwise
     *                 nullptr.
     */
    virtual ::android::hardware::Return<void> configureExecutionBurst(const ::android::sp<::android::hardware::neuralnetworks::V1_2::IBurstCallback>& callback, const ::android::hardware::MQDescriptorSync<::android::hardware::neuralnetworks::V1_2::FmqRequestDatum>& requestChannel, const ::android::hardware::MQDescriptorSync<::android::hardware::neuralnetworks::V1_2::FmqResultDatum>& resultChannel, configureExecutionBurst_cb _hidl_cb) = 0;

    /**
     * Launches an asynchronous execution on a prepared model.
     *
     * The execution is performed asynchronously with respect to the caller.
     * execute_1_3 must verify the inputs to the function are correct, and the usages
     * of memory pools allocated by IDevice::allocate are valid. If there is
     * an error, execute_1_3 must immediately invoke the callback with the
     * appropriate ErrorStatus value, then return with the same ErrorStatus. If
     * the inputs to the function are valid and there is no error, execute_1_3 must
     * launch an asynchronous task to perform the execution in the background,
     * and immediately return with ErrorStatus::NONE. If the asynchronous task
     * fails to launch, execute_1_3 must immediately invoke the callback with
     * ErrorStatus::GENERAL_FAILURE, then return with
     * ErrorStatus::GENERAL_FAILURE.
     *
     * When the asynchronous task has finished its execution, it must
     * immediately invoke the callback object provided as an input to the
     * execute_1_3 function. This callback must be provided with the ErrorStatus of
     * the execution.
     *
     * If the launch is successful, the caller must not change the content of
     * any data object referenced by 'request' (described by the
     * {@link @1.0::DataLocation} of a {@link @1.0::RequestArgument}) until the
     * asynchronous task has invoked the callback object. The asynchronous task
     * must not change the content of any of the data objects corresponding to
     * 'request' inputs.
     *
     * If the prepared model was prepared from a model wherein all tensor
     * operands have fully specified dimensions, and the inputs to the function
     * are valid, then:
     * - the execution should launch successfully (ErrorStatus::NONE): There
     *   must be no failure unless the device itself is in a bad state.
     * - if at execution time every operation's input operands have legal
     *   values, the execution should complete successfully (ErrorStatus::NONE):
     *   There must be no failure unless the device itself is in a bad state.
     *
     * execute_1_3 can be called with an optional deadline. If the execution
     * is not able to be completed before the provided deadline, the execution
     * may be aborted, and either {@link
     * ErrorStatus::MISSED_DEADLINE_TRANSIENT} or {@link
     * ErrorStatus::MISSED_DEADLINE_PERSISTENT} may be returned. The error due
     * to an abort must be sent the same way as other errors, described above.
     *
     * Any number of calls to the execute* and executeSynchronously* functions,
     * in any combination, may be made concurrently, even on the same
     * IPreparedModel object.
     *
     * @param request The input and output information on which the prepared
     *                model is to be executed.
     * @param measure Specifies whether or not to measure duration of the execution.
     *                The duration runs from the time the driver sees the call
     *                to the execute_1_3 function to the time the driver invokes
     *                the callback.
     * @param deadline The time by which the execution is expected to complete.
     *                 If the execution cannot be completed by the deadline, the
     *                 execution may be aborted.
     * @param loopTimeoutDuration The maximum amount of time that should be spent
     *                            executing a {@link OperationType::WHILE}
     *                            operation. If a loop condition model does not
     *                            output false within this duration, the
     *                            execution must be aborted. If no loop timeout
     *                            duration is provided, the maximum amount of
     *                            time is {@link LoopTimeoutDurationNs::DEFAULT}.
     *                            When provided, the duration must not exceed
     *                            {@link LoopTimeoutDurationNs::MAXIMUM}.
     * @param callback A callback object used to return the error status of
     *                 the execution, shape information of model output operands, and
     *                 duration of execution. The callback object's notify function must
     *                 be called exactly once, even if the execution was
     *                 unsuccessful.
     * @return status Error status of the call, must be:
     *                - NONE if task is successfully launched
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - OUTPUT_INSUFFICIENT_SIZE if provided output buffer is
     *                  not large enough to store the resultant values
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     *                - MISSED_DEADLINE_* if the execution is aborted because it
     *                  cannot be completed by the deadline
     *                - RESOURCE_EXHAUSTED_* if the task was aborted by the
     *                  driver
     */
    virtual ::android::hardware::Return<::android::hardware::neuralnetworks::V1_3::ErrorStatus> execute_1_3(const ::android::hardware::neuralnetworks::V1_3::Request& request, ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure, const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint& deadline, const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration& loopTimeoutDuration, const ::android::sp<::android::hardware::neuralnetworks::V1_3::IExecutionCallback>& callback) = 0;

    /**
     * Return callback for executeSynchronously_1_3
     */
    using executeSynchronously_1_3_cb = std::function<void(::android::hardware::neuralnetworks::V1_3::ErrorStatus status, const ::android::hardware::hidl_vec<::android::hardware::neuralnetworks::V1_2::OutputShape>& outputShapes, const ::android::hardware::neuralnetworks::V1_2::Timing& timing)>;
    /**
     * Performs a synchronous execution on a prepared model.
     *
     * The execution is performed synchronously with respect to the caller.
     * executeSynchronously_1_3 must verify the inputs to the function are
     * correct, and the usages of memory pools allocated by IDevice::allocate
     * are valid. If there is an error, executeSynchronously_1_3 must immediately
     * return with the appropriate ErrorStatus value. If the inputs to the
     * function are valid and there is no error, executeSynchronously_1_3 must
     * perform the execution, and must not return until the execution is
     * complete.
     *
     * The caller must not change the content of any data object referenced by
     * 'request' (described by the {@link @1.0::DataLocation} of a
     * {@link @1.0::RequestArgument}) until executeSynchronously_1_3
     * returns. executeSynchronously_1_3 must not change the content of any of the
     * data objects corresponding to 'request' inputs.
     *
     * If the prepared model was prepared from a model wherein all tensor
     * operands have fully specified dimensions, and the inputs to the function
     * are valid, and at execution time every operation's input operands have
     * legal values, then the execution should complete successfully
     * (ErrorStatus::NONE): There must be no failure unless the device itself is
     * in a bad state.
     *
     * executeSynchronously_1_3 may be called with an optional deadline. If the
     * execution is not able to be completed before the provided deadline, the
     * execution may be aborted, and either {@link
     * ErrorStatus::MISSED_DEADLINE_TRANSIENT} or {@link
     * ErrorStatus::MISSED_DEADLINE_PERSISTENT} may be returned. The error due
     * to an abort must be sent the same way as other errors, described above.
     *
     * Any number of calls to the execute* and executeSynchronously* functions,
     * in any combination, may be made concurrently, even on the same
     * IPreparedModel object.
     *
     * @param request The input and output information on which the prepared
     *                model is to be executed.
     * @param measure Specifies whether or not to measure duration of the execution.
     *                The duration runs from the time the driver sees the call
     *                to the executeSynchronously_1_3 function to the time the driver
     *                returns from the function.
     * @param deadline The time by which the execution is expected to complete.
     *                 If the execution cannot be finished by the deadline, the
     *                 execution may be aborted.
     * @param loopTimeoutDuration The maximum amount of time that should be spent
     *                            executing a {@link OperationType::WHILE}
     *                            operation. If a loop condition model does not
     *                            output false within this duration, the
     *                            execution must be aborted. If no loop timeout
     *                            duration is provided, the maximum amount of
     *                            time is {@link LoopTimeoutDurationNs::DEFAULT}.
     *                            When provided, the duration must not exceed
     *                            {@link LoopTimeoutDurationNs::MAXIMUM}.
     * @return status Error status of the execution, must be:
     *                - NONE if execution is performed successfully
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - OUTPUT_INSUFFICIENT_SIZE if at least one output
     *                  operand buffer is not large enough to store the
     *                  corresponding output
     *                - INVALID_ARGUMENT if one of the input arguments is
     *                  invalid
     *                - MISSED_DEADLINE_* if the execution is aborted because it
     *                  cannot be completed by the deadline
     *                - RESOURCE_EXHAUSTED_* if the task was aborted by the
     *                  driver
     * @return outputShapes A list of shape information of model output operands.
     *                      The index into "outputShapes" corresponds to the index
     *                      of the output operand in the Request outputs vector.
     *                      outputShapes must be empty unless the status is either
     *                      NONE or OUTPUT_INSUFFICIENT_SIZE.
     * @return timing Duration of execution. Unless measure is YES and status is
     *                NONE, all times must be reported as UINT64_MAX. A driver may
     *                choose to report any time as UINT64_MAX, indicating that
     *                measurement is not available.
     */
    virtual ::android::hardware::Return<void> executeSynchronously_1_3(const ::android::hardware::neuralnetworks::V1_3::Request& request, ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure, const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint& deadline, const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration& loopTimeoutDuration, executeSynchronously_1_3_cb _hidl_cb) = 0;

    /**
     * Return callback for executeFenced
     */
    using executeFenced_cb = std::function<void(::android::hardware::neuralnetworks::V1_3::ErrorStatus status, const ::android::hardware::hidl_handle& syncFence, const ::android::sp<::android::hardware::neuralnetworks::V1_3::IFencedExecutionCallback>& callback)>;
    /**
     * Launch a fenced asynchronous execution on a prepared model.
     *
     * The execution is performed asynchronously with respect to the caller.
     * executeFenced must verify the inputs to the function are correct, and the usages
     * of memory pools allocated by IDevice::allocate are valid. If there is an error,
     * executeFenced must immediately return with the corresponding ErrorStatus, an empty
     * handle for syncFence, and nullptr for callback. If the inputs to the function
     * are valid and there is no error, executeFenced must dispatch an asynchronous task
     * to perform the execution in the background, and immediately return with
     * ErrorStatus::NONE, a sync fence that will be signaled once the execution is completed,
     * and a callback that can be used by the client to query the duration and runtime error
     * status. If the task has finished before the call returns, an empty handle may be returned
     * for syncFence. The execution must wait for all the sync fences (if any) in waitFor
     * to be signaled before starting the actual execution.
     *
     * When the asynchronous task has finished its execution, it must
     * immediately signal the syncFence returned from the executeFenced call. After
     * the syncFence is signaled, the task must not modify the content of
     * any data object referenced by 'request' (described by the
     * {@link @1.0::DataLocation} of a {@link @1.0::RequestArgument}).
     *
     * executeFenced may be called with an optional deadline and an optional duration.
     * If the execution is not able to be completed before the provided deadline or
     * within the timeout duration (measured from when all sync fences in waitFor are
     * signaled), whichever comes earlier, the execution may be aborted, and either
     * {@link ErrorStatus::MISSED_DEADLINE_TRANSIENT} or {@link
     * ErrorStatus::MISSED_DEADLINE_PERSISTENT} may be returned. The error due
     * to an abort must be sent the same way as other errors, described above.
     *
     * If any of the sync fences in waitFor changes to error status after the executeFenced
     * call succeeds, or the execution is aborted because it cannot finish before the deadline
     * has been reached or the duration has elapsed, the driver must immediately set the returned
     * syncFence to error status.
     *
     * Any number of calls to the executeFenced, execute* and executeSynchronously*
     * functions, in any combination, may be made concurrently, even on the same
     * IPreparedModel object.
     *
     * @param request The input and output information on which the prepared
     *                model is to be executed. The outputs in the request must have
     *                fully specified dimensions.
     * @param waitFor A vector of sync fence file descriptors.
     *                Execution must not start until all sync fences have been signaled.
     * @param measure Specifies whether or not to measure duration of the execution.
     * @param deadline The time by which the execution is expected to complete.
     *                 If the execution cannot be finished by the deadline, the
     *                 execution may be aborted.
     * @param loopTimeoutDuration The maximum amount of time that should be spent
     *                            executing a {@link OperationType::WHILE}
     *                            operation. If a loop condition model does not
     *                            output false within this duration, the
     *                            execution must be aborted. If no loop timeout
     *                            duration is provided, the maximum amount of
     *                            time is {@link LoopTimeoutDurationNs::DEFAULT}.
     *                            When provided, the duration must not exceed
     *                            {@link LoopTimeoutDurationNs::MAXIMUM}.
     * @param duration The length of time within which the execution is expected
     *                 to complete after all sync fences in waitFor are signaled.
     *                 If the execution cannot be finished within the duration,
     *                 the execution may be aborted.
     * @return status Error status of the call, must be:
     *                - NONE if task is successfully launched
     *                - DEVICE_UNAVAILABLE if driver is offline or busy
     *                - GENERAL_FAILURE if there is an unspecified error
     *                - INVALID_ARGUMENT if one of the input arguments is invalid, including
     *                                   fences in error states.
     *                - MISSED_DEADLINE_* if the execution is aborted because it
     *                  cannot be completed by the deadline
     *                - RESOURCE_EXHAUSTED_* if the task was aborted by the
     *                  driver
     * @return syncFence The sync fence that will be signaled when the task is completed.
     *                   The sync fence will be set to error if a critical error,
     *                   e.g. hardware failure or kernel panic, occurs when doing execution.
     * @return callback The IFencedExecutionCallback can be used to query information like duration
     *                  and error status when the execution is completed.
     */
    virtual ::android::hardware::Return<void> executeFenced(const ::android::hardware::neuralnetworks::V1_3::Request& request, const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>& waitFor, ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure, const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint& deadline, const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration& loopTimeoutDuration, const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration& duration, executeFenced_cb _hidl_cb) = 0;

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
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>> castFrom(const ::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>& parent, bool emitError = false);
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>> castFrom(const ::android::sp<::android::hardware::neuralnetworks::V1_2::IPreparedModel>& parent, bool emitError = false);
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>> castFrom(const ::android::sp<::android::hardware::neuralnetworks::V1_0::IPreparedModel>& parent, bool emitError = false);
    /**
     * This performs a checked cast based on what the underlying implementation actually is.
     */
    static ::android::hardware::Return<::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>> castFrom(const ::android::sp<::android::hidl::base::V1_0::IBase>& parent, bool emitError = false);

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
    static ::android::sp<IPreparedModel> tryGetService(const std::string &serviceName="default", bool getStub=false);
    /**
     * Deprecated. See tryGetService(std::string, bool)
     */
    static ::android::sp<IPreparedModel> tryGetService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return tryGetService(str, getStub); }
    /**
     * Deprecated. See tryGetService(std::string, bool)
     */
    static ::android::sp<IPreparedModel> tryGetService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return tryGetService(str, getStub); }
    /**
     * Calls tryGetService("default", bool). This is the recommended instance name for singleton services.
     */
    static ::android::sp<IPreparedModel> tryGetService(bool getStub) { return tryGetService("default", getStub); }
    /**
     * This gets the service of this type with the specified instance name. If the
     * service is not in the VINTF manifest on a Trebilized device, this will return
     * nullptr. If the service is not available, this will wait for the service to
     * become available. If the service is a lazy service, this will start the service
     * and return when it becomes available. If getStub is true, this will try to
     * return an unwrapped passthrough implementation in the same process. This is
     * useful when getting an implementation from the same partition/compilation group.
     */
    static ::android::sp<IPreparedModel> getService(const std::string &serviceName="default", bool getStub=false);
    /**
     * Deprecated. See getService(std::string, bool)
     */
    static ::android::sp<IPreparedModel> getService(const char serviceName[], bool getStub=false)  { std::string str(serviceName ? serviceName : "");      return getService(str, getStub); }
    /**
     * Deprecated. See getService(std::string, bool)
     */
    static ::android::sp<IPreparedModel> getService(const ::android::hardware::hidl_string& serviceName, bool getStub=false)  { std::string str(serviceName.c_str());      return getService(str, getStub); }
    /**
     * Calls getService("default", bool). This is the recommended instance name for singleton services.
     */
    static ::android::sp<IPreparedModel> getService(bool getStub) { return getService("default", getStub); }
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

static inline std::string toString(const ::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>& o);

//
// type header definitions for package
//

static inline std::string toString(const ::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>& o) {
    std::string os = "[class or subclass of ";
    os += ::android::hardware::neuralnetworks::V1_3::IPreparedModel::descriptor;
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


#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_IPREPAREDMODEL_H
