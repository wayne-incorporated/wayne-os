# ChromeOS ML Model Zoo

This is a collection of TFLite models that can be used to benchmark devices
for typical ML use cases within ChromeOS. Where applicable, baseline figures
are provided to indicate the minimum performance requirements for these models
to meet the user experience goals of those use cases.

These models can be easily deployed to `/usr/local/share/ml-test-assets` on a
DUT via the `chromeos-base/ml-test-assets` package:

`emerge-${BOARD} ml-test-assets && cros deploy <DUT> ml-test-assets`

The models can be downloaded directly [here](https://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/ml-test-assets-0.0.3.tar.xz)

## Tools

### Latency, Max Memory

Latency and maximum memory usage is measured by the
[TFLite Benchmark Model Tool](https://github.com/tensorflow/tensorflow/tree/master/tensorflow/lite/tools/benchmark).

This is installed by default on all ChromeOS test images.

Example usage:

`benchmark_model --graph=${tflite_file} --min_secs=20 <delegate options>`

### Accuracy

Accuracy is measured by the
[TFLite Inference Diff Tool](https://github.com/tensorflow/tensorflow/tree/master/tensorflow/lite/tools/evaluation/tasks/inference_diff).

This is installed by default on all ChromeOS test images.

Example usage:

`inference_diff_eval  --graph=${tflite_file} <delegate options>`

## Use Cases

### Video Conferencing

**Note: These models are CNN based.**

| Model                                     | Latency (ms)  | Accuracy                                    | Power Usage | Max Memory |
|-------------------------------------------|--------------:|--------------------------------------------:|-------------|------------|
| selfie_segmentation_landscape_256x256     |          <= 6 | avg_err <=0.0000003<br/> std_dev<=5e-06     |         TBD |    <=100MB |
| convolution_benchmark_1_144x256           |          <= 4 | avg_err <=0.0003<br/>std_dev <=5e-06        |         TBD |    <=100MB |
| convolution_benchmark_2_144x256           |          <= 4 | avg_err <=0.0003<br/>std_dev <=5e-06        |         TBD |    <=100MB |

### Image Search

**Note: These models are CNN based.**

| Model                      | Latency (ms)  | Accuracy                               | Power Usage | Max Memory |
|----------------------------|--------------:|---------------------------------------:|-------------|------------|
| mobilenet_v2_1.0_224       |          <= 5 | avg_err <=0.00005<br/>std_dev <=6e-06  |         TBD |    <=150MB |
| mobilenet_v2_1.0_224_quant |          <= 5 | avg_err <=1.5<br/>std_dev <=0.2        |         TBD |    <=150MB |

### Audio Models

**Note: These models are running on CPU in production**

**Note2: While running `benchmark_model` with following models,
add `--run_delay=<secs>` to simulate audio server behavior.**

| Model       | Latency on CPU (ms) | Extra arguments    | sha256                                                           |
|-------------|--------------------:|--------------------| ---------------------------------------------------------------- |
| lstm        |                <= 1 | `--run_delay=0.01` | 381506dd6209615e57285531d5e97c159ff41605341d184c7fd869eb8e364cfe |
| seanet_wave |                <= 2 | `--run_delay=0.02` | 78c23dbb0e82d3cd59d0027fbf5b4351c4125494d7bccb52eb6b509c5e72fca8 |
| seanet_stft |                <= 2 | `--run_delay=0.02` | a46d719aa611ceddc41f6a9437946f8ebb06cd774fc6db01b766110113f9be1b |

# ML accelerator requirements

The API for running ML workloads on ChromeOS is
[Tensorflow Lite](https://www.tensorflow.org/lite).
A discrete ML accelerator such as a TPU/NPU or a GPU can be made accessible
through TFLite to improve the performance of ML workloads.

The following requirements apply to such accelerators:

## Functional requirements

1. Any device kernel driver must be open source and integrated with upstream
   Linux or implemented in userspace through VFIO.
1. Direct dmabuf data sharing must be supported between the accelerator and
   other relevant IP blocks (e.g., GPU, ISP). Both buffer-user and exporter
   roles must be supported.

## Security requirements

1. Sandboxing must be supported for isolating untrusted workloads and any binary-only driver
   components.
1. Only signed and verified firmware must be allowed to be loaded onto the accelerator. See
   [Peripheral Firmware Security](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/security/firmware_updating.md).
1. An IOMMU must control access to system memory from the accelerator.

## Miscellaneous requirements

1. The driver's binary size (including dependent libraries and middleware) must be below 64 MB.
1. Tools should be provided for ChromeOS developers to analyze the performance of inference
   workloads (e.g. Perfetto and/or ftrace instrumentation).
