# Chrome OS Camera Fake HAL

This folder contains the HAL for emulating fake external camera(s) on Chrome OS
for testing.

## Usage

Fake HAL is built by the package `media-libs/cros-camera-hal-fake`, and is
default installed on all test image at `/usr/lib64/camera_hal/fake.so`.

Config file for fake HAL are located at:

* `/etc/camera/fake_hal.json`: Rootfs protected and persist between reboot.
  This file is only read once on HAL starts, so user need to `restart
  cros-camera` for changes to take effect.

* `/run/camera/fake_hal.json`: Takes priority over `/etc/camera/fake_hal.json`.
  Doesn't persist between reboot. Fake HAL watches content change of this file
  and immediately applies the change without needing to restart camera service.

  The config is applied by emitting unplug / plug event of the emulated camera.

Tests should use `/run/camera/fake_hal.json`.

### Config file format

The config file should be a JSON file with dictionary as top level value,
containing one required key:

* `cameras` (list of `CameraSpec`, required): A list of fake cameras.

Each `CameraSpec` is a dictionary, containing the following keys:

* `id` (integer, required):
  Device ID. Should be unique across all fake cameras. This is used to track
  config changes across reload.

* `connected` (boolean, default false):
  Whether the camera is connected. Useful for testing plug/unplug event of
  external camera.

* `supported_formats` (dictionary, optional):
  List of supported resolution / frame rates of the emulated camera. Defaults
  to a minimal required list (see `hal_spec.cc` for the list). Each entry
  contains the following keys:

  * `width`, `height` (integer, required):
    Width and height of the resolution, should be positive and even. Currently
    the maximum supported size is `8192x8192`.

  * `frame_rates` (list, default `[[15, 60], [60, 60]]`):
    List of supported frame rate ranges. Each entry should be an integer
    indicating a constant frame rate, or a list of two integers indicating a
    range of frame rates.

  Note that the `supported_formats` is used for reporting the supported
  resolutions and frame rates of the fake camera in static metadata, and
  there's a minimal requirement from camera3 API.

* `frames` (dictionary, optional):
  If not specified, the fake camera will show a test pattern. Otherwise, the
  value should contain the following keys:

  * `path` (string, required):
    Path to the frame content. Can be either `.jpg` (for still photo) or `.y4m`
    (for video). The video will loop indefinitely.

    The frame rate in `.y4m` file is ignored, and the playback will be using
    the requested frame rate specified in `supported_formats`.

    Also since camera service is inside minijail sandbox, it can't access most
    of the file system path. A recommended path to put the image / video file
    at is `/var/cache/camera`, which is accessible to the camera service.

  * `scale_mode` (string, default to `stretch`):
    How the image / video is resized to the requested resolution, can be either:

    * `stretch`: Stretch to the target resolution, ignoring aspect ratio.

    * `contain`: Resize the image to the largest size that will fit in the
      target resolution while maintaining the aspect ratio. The result image
      will be center aligned and outside area filled by black.

    * `cover`: Resize the image to the smallest size that will cover the target
      resolution while maintaining the aspect ratio. The result image will be
      center aligned and the excessive area cropped.

A sample config file is as follows:
```json
{
  "cameras": [
    {
      "id": 1,
      "connected": true,
      "supported_formats": [
        {
          "width": 1920,
          "height": 1080,
          "frame_rates": [[30, 999]]
        },
        {
          "width": 1280,
          "height": 720,
          "frame_rates": [15, 30, 60]
        }
      ],
      "frames": {
        "path": "/var/cache/camera/xxx.y4m",
        "scale_mode": "contain"
      }
    },
    { "id": 2, "connected": false }
  ]
}
```
Note that the sample `supported_formats` doesn't meet the requirements of the
camera3 API and might cause issue in CCA. For manual testing, please use `cca
fake-hal` (explained in the next section), which can generate a list of
supported formats that meets the requirement.

### Manual testing

For manual testing, a command line tool `cca` is available for easier adding /
removing fake HAL cameras.

Some sample usage:

```bash
# Add fake camera with generated ID and resolution filtered from a preconfigured list.
# Edit the config manually for fine grained control on the supported stream configurations.
$ cca fake-hal add --max-width=1920 --max-height=1200 --frame /var/cache/camera/video.y4m

# Open the config in vim
$ cca fake-hal edit

$ cca fake-hal connect --id=1

$ cca fake-hal disconnect --id=1

$ cca fake-hal remove --id=1

# Copy /run to /etc, need to remove rootfs protection first
$ cca fake-hal persist

$ cca fake-hal info
```

Please refer to `cca fake-hal --help` for complete usage documentation.
