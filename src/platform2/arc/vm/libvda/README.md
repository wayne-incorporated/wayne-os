# libvda

## About

libvda is a library that provides a C API for video decoding as defined in
[libvda.h](./libvda.h).

## Implementations

### [GPU](./gpu)

An implementation that communicates with `GpuArcVideoDecodeAccelerator` running
in the GPU process. Internally, communication is done with libmojo using the
[VideoDecodeAccelerator](https://chromium.googlesource.com/chromium/src.git/+/HEAD/components/arc/common/video_decode_accelerator.mojom) mojo interface.

### [Fake](./fake)
An empty implementation useful for integration testing. Users can initialize
this implementation to see verbose logs when each vda function is called, as
well as receive empty PICTURE_READY events.

## Running unittests manually

There are unit tests for both the fake and the GPU implementation. The GPU unit
tests require ChromeOS with Chrome running in order to communicate with the GPU
process. The DecodeFileGpu unit test requires an encoded video file with
extension .h264, .vp8, .vp9 to be provided that contains an H264, VP8, or VP9
video stream respectively. This can be passed in using the `--test_video_file`
command line flag.

Example usage:

    ./libvda_unittest --test_video_file=test_stream.h264
