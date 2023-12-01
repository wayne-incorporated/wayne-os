# ChromeOS Feature Daemon

`featured` is a service used for enabling and managing platform specific
features. Its main user is Chrome field trials.

## Components

In this directory are two main components: `feature_library` and featured.

### feature\_library

The `feature_library` is the main way most users will interact with variations
in platform2. (If you're familiar with
[base::Feature and base::FeatureList](https://source.chromium.org/chromium/chromium/src/+/main:base/feature_list.h)
in chrome, it will look very similar.)  Most documentation for this is in
`feature_library.h`, but there is also a C wrapper API as well as a Rust API.

As of March 2023, all features queried via `feature_library` must start with
CrOSLateBoot. For CrOSLateBoot features, `feature_library` is a thin wrapper
around a dbus call to ash-chrome, so state can only be queried **after** chrome
is up.

Work is underway to support "early boot" features as well; feel free to contact
OWNERS for more details.

#### Using feature\_library
Clients can use `feature_library` by creating an instance of
[PlatformFeatures](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/featured/feature_library.h;l=169).
The instance is used to query feature state and associated parameters, if there are any.

`PlatformFeatures` is implemented as a singleton class and is thread-safe.
Here is an example of how to initialize and obtain an instance:

```
dbus::Bus::Options options;
options.bus_type = dbus::Bus::SYSTEM;
scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));

// |Initialize| must be called before calling |Get| and the return value must
// be used since it has the [[nodiscard]] attribute.
CHECK(feature::PlatformFeatures::Initialize(bus));

// |Get| will return a valid handle if |Initialize| succeeds.
// Note that |Get| and subsequent calls can happen much later than |Initialize|
// since the object pointer remains valid until program exit.
feature::PlatformFeatures* feature_lib = feature::PlatformFeatures::Get();

// Use the handle to query feature state.
feature_lib->GetParamsAndEnabled(...);
```

Note that no shutdown call is necessary. The initialized instance will get
automatically cleaned up on program exit.

[platform2/featured/cpp_feature_check_example.cc](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/featured/cpp_feature_check_example.cc)
provides another example on how to use `PlatformFeatures` and associated
functions like `IsEnabled{,Blocking}`, and `GetParamsAndEnabled{,Blocking}`.

### featured

The feature daemon (featured) is primarily responsible for managing
[share/platform-features.json](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform2/featured/share/platform-features.json).
This file configures platform and kernel features that can be enabled
_dynamically_ at runtime, late in boot (that is, after user login).

Each entry in this file consists of a feature name, to be checked using
`feature_library`, an optional set of `support_check_commands` (to check whether
the device supports the feature), and a set of `commands` to be run when the
feature is supported and chrome determines that it should be enabled.

Support check commands include FileExists and FileNotExists. Commands to execute
include WriteFile and Mkdir, which respectively write specified contents to a
file and create a given directory.

Featured is heavily sandboxed: writing to a new location requires an update to
selinux policy in `platform2/sepolicy/policy/chromeos/cros_featured.te` as well
as the allow-list in service.cc (see `CheckPathPrefix`).

We are actively working (in 2023) on support for "early boot" features in
featured. The primary user interface for these will be via `feature_library`,
but featured will perform some work to support this, largely behind the scenes.

### Upstart Configurations

Featured starts relatively late in boot, during
[system-services](https://www.chromium.org/chromium-os/chromiumos-design-docs/boot-design/#system-services-startup),
since Chrome needs to be available for platform-features.json support to work.

Additionally, featured waits for user login to enable platform-features.json
features for two reasons:
1. **Safety:** It is easier to roll back after user login since it is more
likely for the platform to have connected to the network and downloaded a new
seed.
2. **Compatibility:** Historically, we have checked after login. There is no
strong reason to change that, and changing it could break existing users.

Upon crashes or abnormal exits (non-zero status code), featured restarts with
the intention that if we fail initially, we want to re-try and make sure
platform-features.json (and eventually "early boot" features) will work.

We are actively working (in 2023) on support for "early boot" features in
featured. To support "early boot" features, featured startup will be moved
earlier to start during
[basic services](https://www.chromium.org/chromium-os/chromiumos-design-docs/boot-design/#basic-services-startup).
