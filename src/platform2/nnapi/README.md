# Chrome OS NNAPI Implementation

## Summary

The [Android Neural Networks API](https://developer.android.com/ndk/guides/neuralnetworks)
is an Android C API designed for running computationally intensive operations
for machine learning on Android Devices. NNAPI is designed to provide a base
layer of functionality for higher level machine learning frameworks, such as
[TensorFlow Lite](https://www.tensorflow.org/lite).

NNAPI is being ported to Chrome OS to provide a common abstraction for the
implementation of on device accelerators, using [Neural Networks HAL](https://source.android.com/devices/neural-networks).

Vendors will provide NNHAL implementations for their hardware for
acceleration on Chrome OS via ML Service.
