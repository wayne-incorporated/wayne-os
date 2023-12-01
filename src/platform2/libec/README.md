# libec

C++ library for interacting with the Chrome OS [Embedded Controller].

## Overview

Each EC command is represented with a C++ class that conforms to the
[`EcCommandInterface`] interface. All EC commands are either synchronous or
"asynchronous". Asynchronous EC commands are commands that do not complete
immediately and require polling to get the result. Most EC commands are
synchronous.

Synchronous commands should inherit from the [`EcCommand`] class. Asynchronous
commands should inherit from the [`EcCommandAsync`] class.

## Command Versions

Each EC command has a version number associated with it, which allows
introducing new versions of commands while maintaining backward compatibility
with older ECs that cannot be changed.

In order to abstract this complexity for consumers of `libec`, `libec` provides
a factory class called [`EcCommandFactory`]. [`EcCommandFactory`] can be used to
automatically instantiate the correct version of the command based on the
command version that the EC supports.

For example, [`EcCommandFactory::FpContextCommand`] uses
[`FpContextCommandFactory::Create`] to instantiate version `0` or version `1` of
the `EC_CMD_FP_CONTEXT` command, depending on what the EC supports.

## Testing

All commands have a unit test with a name of `<command>_test.cc`. It's possible
to mock the response from the EC by mocking the `EcCommand::Resp()` method. For
a simple example, see the [`DisplayStateOfChargeCommandTest`]. For an example of
more advanced testing you can do with mocking, see the [`FpFrameCommandTest`].

## Adding New Commands

To add a new command, create files for your command called `<command>.cc` and
`<command.h>`, as well as a test file `<command>_test.cc`. Create a `Command`
class that inherits from [`EcCommand`] or [`EcCommandAsync`]. The template
arguments are the params and response `struct`s for the command. For example,
the `EC_CMD_DEVICE_EVENT` command uses `struct ec_params_device_event` for
parameters and `struct ec_response_device_event` for the response, so the
[`DeviceEventCommand`] inherits from `EcCommand<struct ec_params_device_event,
struct response_device_event>`.

Commands that don't have a request or response use [`EmptyParam`] as the
template parameter. See the [`DisplayStateOfChargeCommand`] for an example.

Commands that have variable length arrays in the params or response `struct`
need to redefine the `struct` so that it has a well-defined size. See
[`fp_template_params.h`] for an example. Please include a test to validate that
the two `struct`s do not get out of sync. See [`fp_template_params_test.cc`] for
an example.

[Embedded Controller]: https://chromium.googlesource.com/chromiumos/platform/ec/
[`EcCommand`]: ./ec_command.h
[`EcCommandInterface`]: ./ec_command.h
[`EcCommandAsync`]: ./ec_command_async.h
[`EcCommandFactory`]: ./ec_command_factory.h
[`EcCommandFactory::FpContextCommand`]: ./ec_command_factory.h
[`FpContextCommandFactory::Create`]: ./fingerprint/fp_context_command_factory.cc
[`DisplayStateOfChargeCommandTest`]: ./display_soc_command_test.cc
[`FpFrameCommandTest`]: ./fingerprint/fp_frame_command_test.cc
[`EmptyParam`]: ./ec_command.h
[`DeviceEventCommand`]: ./device_event_command.h
[`DisplayStateOfChargeCommand`]: ./display_soc_command.h
[`fp_template_params.h`]: ./fingerprint/fp_template_params.h
[`fp_template_params_test.cc`]: ./fingerprint/fp_template_params_test.cc
