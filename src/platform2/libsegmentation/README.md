# libsegmentation

C++ library to know if a software feature is enabled on a given device.

It is unrelated to featured. Although both returns if a given feature is enabled
or not, featured uses the variations framework while libsegmentation uses a
local store when enabled.

[TOC]

## Design Documentation

See the [design\_doc](go/cros-segmentation-dd) and the [application
note](go/cros-segmentation-an).

## Package dependency

    legend
    └── ► depends on

                 chromeos-base/libsegmentation
                             │
                             ▼
                 chromeos-base/feature-management-data
                      │      │                                  public-overlay
    ---------------------------------------------------------------------------
                                                                private-overlay
                      │      │
                      │      └── ► chromeos-base/feature-management-bsp
                      │
                      └── ► chromeos-base/feature-management-private

`chromeos-base/feature-management-private` provide the private features
definitions for `chromeos-base/feature-management-data`, that build the database
needed by `libsegmentation` in
`chromeos/feature-management-data/libsegmenation_pb.h`. It also holds the
[protobuf](https://chromium.googlesource.com/chromiumos/platform/feature-management/proto/feature_management.proto)
that describes a feature.

 chromeos-base/feature-management-bsp provide device selection override,
if needed.

## Usage

We can check manually if a feature is supported on the test image with

```bash
/usr/local/sbin/feature_explorer --feature_name=FeatureManagementNotSupported
0
/usr/local/sbin/feature_explorer --feature_name=FeatureManagementBasic
1
```

## Adding a feature

Public features are added in
[`features.star`](https://chromium.googlesource.com/chromiumos/platform/feature-management/+/HEAD/features.star)
starlak file.
