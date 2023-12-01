# Chrome OS IIO Sensor Utility Library

## `Project goal and motivation`

This library provides a set of wrapper and test helpers around libiio.

It is meant to provide a common foundation for Chrome OS to access and
interface IIO sensors, with:
 - a strong emphasis on testability;
 - readable code, with the ergonomics typical of platform2;
 - high performance.

## Class hierarchy

At the root of the hierarchy, there exists the `IioContext`, which represents
the IIO devices currently available on the system. These can be retrieved by
name and inspected, via instances of `IioDevice`.

An `IioDevice` allows reading and writing attributes of an IIO device via
type-safe helper APIs. It also offers support for configuring the buffer
and trigger of an IIO device, which we use in order to allow the Chrome UI
to read accelerometer data and support screen rotation.

An `IioDevice` also exposes a list of `IioChannel`s, which can individually be
enabled and disabled.

## Test mocks

Useful mocks for the core classes are provided, such that a test author
can focus on the logic of the unit tests and share a common testing language
with other engineers working in this space. Sharing the foundation of testing
IIO sensor access helps ensure that any improvement in this area can benefit
all clients.
