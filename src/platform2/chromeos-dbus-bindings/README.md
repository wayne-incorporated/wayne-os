# chromeos-dbus-bindings

**chromeos-dbus-bindings** was created to supplement [libbrillo] and
simplify the implementation of [D-Bus] daemons and proxies. It generates C++
classes from the XML specifications of the D-Bus interface. Instead of dealing
directly with `MethodCall` objects and unpacking the arguments manually, the
generated bindings take care of marshalling and unmarshalling D-Bus method
call arguments for you.

Additionally, a Rust crate chromeos_dbus_bindings is supplied for generating a
Rust library with D-Bus bindings from the introspection XML data. Most of the
logic is already provided by dbus-codegen-rust, but the source XML is not always
available to the crate file, so this wraps the generated sources.

## Setting up chromeos-dbus-bindings

The XML format defining objects and interfaces is the same format used in
[the introspection API]. Method and signal handlers are generated from this XML
file. If you were using dbus-c++ before, you are probably using `xml2cpp`
to generate C++ bindings from the XML specification. If not, you may need to
write an XML specification.

After that, you will need to set up some actions in the `BUILD.gn` file for your
service and its users. That will look something like this in your service:

```
import("//common-mk/generate-dbus-adaptors.gni")

generate_dbus_adaptors("frobinator-adaptors") {
  sources = [
    "dbus_bindings/service.name.of.Frobinator.xml",
  ]
  dbus_adaptors_out_dir = "include/frobinator/dbus_adaptors"
  dbus_service_config = "dbus_bindings/dbus-service-config.json"
}
```

and this in users of your service (or for a client library target):

```
import("//common-mk/generate-dbus-proxies.gni")

generate_dbus_proxies("frobinator-proxies") {
  sources = [
    "path/to/frobinator/dbus_bindings/service.name.of.Frobinator.xml",
  ]
  proxy_output_file = "include/frobinator/dbus-proxies.h"
}
```

The JSON service configuration file will look like this:

```json
{
  "service_name": "service.name.of.Frobinator",
}
```

Then, in your service, you can
`#include "frobinator/dbus_adaptors/service.name.of.Frobinator.h"` to get the
interface and adaptor classes for Frobinator, and users can
`#include <frobinator/dbus-proxies.h>` to get the proxy classes. Try to
follow the [best practices] doc and only export one object for your service.

## D-Bus types vs. C++ types

D-Bus methods, signals and properties have [type signatures]. When generating
bindings, `chromeos-dbus-bindings` will map D-Bus types to C++ types like
so:

| D-Bus type signature | C++ type                    |
| -------------------- | ----------------------------|
| `y`                  | `uint8_t`                   |
| `b`                  | `bool`                      |
| `n`                  | `int16_t`                   |
| `q`                  | `uint16_t`                  |
| `i`                  | `int32_t`                   |
| `u`                  | `uint32_t`                  |
| `x`                  | `int64_t`                   |
| `t`                  | `uint64_t`                  |
| `d`                  | `double`                    |
| `s`                  | `std::string`               |
| `h`                  | [base::ScopedFD]            |
| `o`                  | [dbus::ObjectPath]          |
| `v` (variant)        | [brillo::Any]               |
| `(TU...)`            | `std::tuple<T, U, ...>`     |
| `aT`                 | `std::vector<T>`            |
| `a{TU}`              | `std::map<T, U>`            |
| `a{sv}`              | [brillo::VariantDictionary] |

This type mapping is also recursive, i.e. an argument of
type `a{s(io)}` will be mapped to
`std::map<std::string, std::tuple<int32_t, dbus::ObjectPath>>`.

For protocol buffers, add an annotation `ay` (array of bytes) with
`org.chromium.DBus.Argument.ProtobufClass`, like:

```
  <arg name="response" type="ay">
    <annotation name="org.chromium.DBus.Argument.ProtobufClass"
       value="vm_tools::concierge::DiskImageStatusResponse" />
  </arg>
```

## Method generation

Suppose you have a service with the following XML specification:

```xml
<node name="/org/chromium/Frobinator">
  <interface name="org.chromium.Frobinator">
    <method name="Frobinate">
      <arg name="foo" type="i" direction="in" />
      <arg name="bar" type="a{sv}" direction="in" />
      <arg name="baz" type="s" direction="out" />
    </method>
  </interface>
</node>
```

The generator will generate a class `org::chromium::FrobinatorInterface` with
the following C++ method signature:

```c++
bool Frobinate(brillo::ErrorPtr* error,
               int32_t foo,
               const brillo::VariantDictionary& bar,
               std::string* baz);
```

This method can be implemented by inheriting
`org::chromium::FrobinatorInterface` and can be called on proxy objects of type
`org::chromium::FrobinatorProxy`. If the method fails, it should set the `error`
to something descriptive and return false. If an arg has direction "in" and is
not a simple numeric type, it will be passed in as `const &`.

### Annotations

The bindings generator also supports several method annotations. Marking your
methods with these will change the generated bindings.

`org.chromium.DBus.Method.Kind`:

* `simple`: This method will not fail and no `brillo::ErrorPtr` argument is
  given. If it has only one "out" argument, it is treated as a normal return
  value. Otherwise, the method returns `void` and passes "out" arguments
  back as pointers as usual.
* `normal`: As stated above. Returns false and sets a `brillo::ErrorPtr` on
  failure.
* `async`: Instead of returning "out" arguments directly, the C++ method
  will take a [DBusMethodResponse] argument templated on the types of the
  "out" arguments. You can pass this object around and call its methods to
  reply later.
* `raw`: Takes a `dbus::MethodCall` and
  `dbus::ExportedObject::ResponseSender` object directly. Use this if you
  need to do your own message parsing. Protos are often passed as type `ay`
  but Chrome's D-Bus bindings have special methods to handle them, and it
  might make sense to take the `MethodCall` directly for these.

These would have the following effect on the `Frobinate` method above:

| Kind annotation | C++ method signature |
| --------------- | -------------------- |
| `simple`        | `std::string Frobinate(int32_t foo, const brillo::VariantDictionary& bar);` |
| `normal`        | `bool Frobinate(brillo::ErrorPtr* error, int32_t foo, const brillo::VariantDictionary& bar, std::string* baz);` |
| `async`         | `void Frobinate(std::unique_ptr<DBusMethodResponse<std::string>> response, int32_t foo, const brillo::VariantDictionary& bar);` |
| `raw`           | `void Frobinate(dbus::MethodCall* method_call, ResponseSender sender);` |

`org.chromium.DBus.Method.Const`: "true" adds `const` to the method signature

`org.chromium.DBus.Method.IncludeDBusMessage`: passes the `dbus::Message*` as
an argument to the generated adaptor method following the `brillo::ErrorPtr*`
or `DBusMethodResponse`

`org.freedesktop.DBus.GLib.Async`: same as setting `Kind` to `async`

## Signal generation

Unlike methods which are exported in the `FrobinatorInterface` class, signals
are sent from the `FrobinatorAdaptor` class and received by the
`FrobinatorProxy` class. Thus, they look different to the service and its
users. Suppose our service has the following XML specification:

```xml
<node name="/org/chromium/Frobinator">
  <interface name="org.chromium.Frobinator">
    <signal name="FrobinationCompleted">
      <arg name="foo" type="i" direction="out" />
      <arg name="bar" type="a{sv}" direction="out" />
    </signal>
  </interface>
</node>
```

Our adaptor class will have a method:

```c++
void SendFrobinationCompletedSignal(int32_t foo,
                                    const brillo::VariantDictionary& bar);
```

and our proxy class will have a method:

```c++
void RegisterFrobinationCompletedSignalHandler(
    const base::RepeatingCallback<void(int32_t, const brillo::VariantDictionary&)>& signal_callback,
    dbus::ObjectProxy::OnConnectedCallback on_connected_callback);
```

Calling this function will call `on_connected_callback` with whether or not the
registration succeeded, and if it did, `signal_callback` will be called when
the service emits this signal.

## On properties

As stated the [best practices] doc, avoid using D-Bus properties because they
won't transfer well to other IPC mechanisms if we need to switch in the future.
Instead, get and set attributes on your service by using methods, and if you
want users to be able to listen for changes in attributes, use signals.

## Integrating with `DBusServiceDaemon`

[brillo::DBusServiceDaemon] is a class which abstracts away some initialization
tasks for D-Bus services and also ensures that all methods are exported before
the service takes its proper name on the bus. This helps prevent races where
users fail invoking methods on a service which claimed its name too early.

`DBusServiceDaemon` has a virtual method `RegisterDBusObjectsAsync` which is
where the adaptor can set up its D-Bus object and export it. Your adaptor
implementation can inherit from `DBusServiceDaemon`, but it's clearer just
to use containment instead here. A simple daemon could look like this:

```c++
class DBusAdaptor : public org::chromium::FrobinatorInterface,
                    public org::chromium::FrobinatorAdaptor {
 public:
  explicit DBusAdaptor(scoped_refptr<dbus::Bus> bus)
    : org::chromium::FrobinatorAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kFrobinatorServicePath)) {}
  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
    RegisterWithDBusObject(&dbus_object_);
    dbus_object_.RegisterAsync(std::move(cb));
  }

  // org::chromium::FrobinatorInterface overrides.
  bool Frobinate(brillo::ErrorPtr* error,
                 int32_t foo,
                 const brillo::VariantDictionary& bar,
                 std::string* baz) override;

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
};

class FrobinatorDaemon : public brillo::DBusServiceDaemon {
 public:
  FrobinatorDaemon() : DBusServiceDaemon(kFrobinatorServiceName) {}
  FrobinatorDaemon(const FrobinatorDaemon&) = delete;
  FrobinatorDaemon& operator=(const FrobinatorDaemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_.reset(new DBusAdaptor(bus_));
    adaptor_->RegisterAsync(sequencer->GetHandler("RegisterAsync() failed",
                                                  true));
  }

 private:
  std::unique_ptr<DBusAdaptor> adaptor_;
};

int main(int argc, char** argv) {
  return FrobinatorDaemon().Run();
}
```

When the `DBusServiceDaemon` is ready to register objects, it calls your
`RegisterDBusObjectsAsync` method. Here we use the `RegisterWithDBusObject`
method from the generated adaptor class to export the methods, and then
call `RegisterAsync` on the `DBusObject` to grab the name and interfaces
for the D-Bus service later. The `AsyncEventSequencer` that the base daemon
code passes us ensures that we'll do things in the right order.

Your service should now appear on the bus and you should be able to call
methods using `dbus-send` or create `org::chromium::FrobinatorProxy` objects
to interact with it:

```c++
dbus::Bus::Options options;
options.bus_type = dbus::Bus::SYSTEM;
scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));

auto frobinator = std::make_unique<org::chromium::FrobinatorProxy>(bus);
brillo::ErrorPtr error;
if (!frobinator->Frobinate(42, {{ "qux", brillo::Any("squawk") }}, &error))
  LOG(WARNING) << "Frobinate failed: " << error->GetMessage();
```

All methods on proxies are specified like `normal` kind methods on interfaces,
with the exception that the error argument appears at the end rather than the
beginning. Even if they are marked `simple` in the interface, there are other
possibilities for errors, such as timeouts, which need to be reported to the
client.

## chromeos_dbus_bindings: Rust D-Bus codegen helper

Tools for generating a Rust library with D-Bus bindings from the introspection
XML data. Most of the logic is already provided by dbus-codegen-rust, but the
source XML is not always available to the crate file, so this wraps the
generated sources.

To use this tool:
1) Add the following to `src/lib.rs`:
    ```rust
    include!(concat!(env!("OUT_DIR"), "/include_modules.rs"));
    ```

2) Add the following to `.gitignore`:
    ```.gitignore
    /src/bindings
    ```

3) Create the `Cargo.toml` file (system_api is a good examples). Be sure to
    include:
    ```toml
    [build-dependencies]
    chromeos_dbus_bindings = { path = "../chromeos-dbus-bindings"} # provided by ebuild

    [dependencies]
    dbus = "0.6"
    ```

4) Create the`build.rs` file. Here is a skeleton:
    ```rust
    use std::path::Path;

    use chromeos_dbus_bindings::{self, generate_module};

    const SOURCE_DIR: &str = ".";

    // (<module name>, <relative path to source xml>)
    const BINDINGS_TO_GENERATE: &[(&str, &str)] = &[
        (
            "org_chromium_sessionmanagerinterface",
            "dbus_bindings/org.chromium.SessionManagerInterface.xml",
        ),
    ];

    fn main() {
        generate_module(Path::new(SOURCE_DIR), BINDINGS_TO_GENERATE).unwrap();
    }
    ```


[D-Bus]: https://www.freedesktop.org/wiki/Software/dbus/
[libbrillo]: https://chromium.googlesource.com/aosp/platform/external/libbrillo/+/HEAD/brillo/dbus/
[the introspection API]: https://dbus.freedesktop.org/doc/dbus-specification.html#introspection-format
[best practices]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/dbus_best_practices.md
[type signatures]: https://dbus.freedesktop.org/doc/dbus-specification.html#type-system
[base::ScopedFD]: https://chromium.googlesource.com/chromiumos/platform/libchrome/+/HEAD/base/files/scoped_file.h
[dbus::ObjectPath]: https://chromium.googlesource.com/chromiumos/platform/libchrome/+/HEAD/dbus/object_path.h
[brillo::Any]: https://chromium.googlesource.com/aosp/platform/external/libbrillo/+/HEAD/brillo/any.h
[brillo::VariantDictionary]: https://chromium.googlesource.com/aosp/platform/external/libbrillo/+/HEAD/brillo/variant_dictionary.h
[DBusMethodResponse]: https://chromium.googlesource.com/aosp/platform/external/libbrillo/+/HEAD/brillo/dbus/dbus_method_response.h
[brillo::DBusServiceDaemon]: https://chromium.googlesource.com/aosp/platform/external/libbrillo/+/HEAD/brillo/daemons/dbus_daemon.h
