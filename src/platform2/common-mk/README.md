# common.mk: A common makefile helper for building daemons in Chromium OS

## Overview

`common.mk` is a centralized Makefile providing a large number of features that
ease regular development:

- known good linker and compiler flags
- target helpers for statically and dynamically linked binaries
- target helpers for statically and dynamically linked libraries
- target helper for running unittests under valgrind and qemu (when needed)
- separation of build artifacts and source code

In addition, `common.mk` systems are fully parallelizable for all targets
avoiding truncated file issues while still utilizing bigsmp systems as
completely as possible.

## Usage

A new project should create a top-level Makefile and after the boilerplate,
include `common.mk`.  After doing so, they may define their targets as usual.
If there are subdirectories, they will be pulled in automatically if they
contain a `module.mk` file.  This file will be just like the top-level Makefile
except that all targets and dependencies should be referred to by their
relative path to the top-level src. E.g., `lib/foo.o` instead of just `foo.o`.

The Makefile may be called from the source directory with just `make` or from
any other location with `make -C /path/to/source`.  If the build artifacts
should live somewhere other than `$PWD/build-$MODE`, then it may be called with
`make -C /path/to/source OUT=$PWD`, for instance.  In addition to `OUT` and
`MODE`, there are several commandline variables which may be set. See the
comment in `common.mk` for full explanation and defaults.

[`example/`](example/) contains a fully working example of a make hierarchy
that explores all the different ways `common.mk` can be used.

## Recipes

This section is a brief recipe book to some common activities, but you should
consult the `common.mk` file for detailed information. In these recipes replace
`<text>` with the appropriate text for your situation. These recipes assume
that you have organized your Makefile along the lines of the other recipes,
i.e. the add flag recipe assumes your targets follow the add target recipes.

For libraries these recipes assume that you want to build the PIE versions of
libraries. You have the option of building PIC versions by replacing where
`.pie.` is used with `.pic.`. One of these must be present, since `common.mk`
is looking to parse these out and there isn't a default behaviour.

### Adding a flag to a target:

- Add flag to `<target>_FLAGS =` line or add a line `<target>_FLAGS += flag`.

### Adding a library to a target:

- Add `-l<library>` to `<target>_LIBS =` line or add a line
  `<target>_LIBS += -l<library>`.

### Adding a complex dependency, like gtk, when `<target>_DEPS` exists:

- Add proper `pkg_config` name of the dependency to the `<target>_DEPS =` line.

### Adding a complex dependency, like gtk, when `<target>_DEPS` does not exist:

- Add a `<target>_DEPS =` line before the related `FLAGS` and `LIBS` lines,
  with the proper `pkg_config` name of your dependency.
- Change `<target>_FLAGS =` to `<target>_FLAGS :=` and add
  `$(shell $(PKG_CONFIG) --cflags $(<target>_DEPS))` to the line.
- Change `<target>_LIBS =` to `<target>_LIBS :=` and add
  `$(shell $(PKG_CONFIG) --libs $(<target>_DEPS))` to the line.

### Add a new source file, with name `<filename>.cc` to a existing target:
- Add `<filename>.o` to `<target>_OBJS`.
- Follow the instructions above for adding a new flags, libs and deps
  related to the file.

### Add a new library target dependency to binary target:
- Add `CXX_STATIC_LIBRARY(lib<library>.pie.a)` to the dependencies of
  `CXX_BINARY(<binary>)`.

### Add a new binary target:
- When creating the DEPS, FLAGS, and LIBS lines try to reuse existing
  definitions that make sense instead of declaring everything anew.
- If needed, add `<target>_DEPS =` line with dependency list
- Add `<target>_FLAGS =` line with flags list.
- Add `<target>_LIBS =` line with library list.
- Add `<target>_OBJS =` line with object list. The object list is composed of
  the `.cc` source files that are needed for the target, with `.o` replacing
  the `.cc`.
- Add `CXX_BINARY(<target>): $(<target>_OBJS) ...` line. This line should have
  any library dependencies that are built in this file included on it. How to
  do this is discussed above.
- Add remaining boilerplate:
  ```
  CXX_BINARY(<target>): CPPFLAGS += $(<target>_FLAGS)
  CXX_BINARY(<target>): LDLIBS += $(<target>_LIBS)
  clean: CLEAN(<target>)
  all: CXX_BINARY(<target>)
  ```

### Add a new unit test target:
It is assumed there is a <parent> binary or library target that defines the
environment.
- Add `<target>_FLAGS =` line with `$(<parent>_FLAGS)` and any other needed
  flags.
- Add `<target>_LIBS =` line with `$(<parent>_LIBS) -lgtest -lgmock` and other
  needed libs.
- Add `<target>_OBJS> =` line with the objects for the unit tests`
- Add `CXX_BINARY(<target>): $(<target>_OBJS) ...` line. This line should have
  any library dependencies that are built in this file included on it. How to
  do this is discussed above.
- Add remaining boilerplate:
  ```
  CXX_BINARY(<target>): CPPFLAGS += $(<target>_FLAGS)
  CXX_BINARY(<target>): LDLIBS += $(<target>_LIBS)
  clean: CLEAN(<target>)
  tests: TEST(CXX_BINARY(<target>))
  ```

### Add a new library target:
- When creating the DEPS, FLAGS, and LIBS lines try to reuse existing
  definitions that make sense instead of declaring everything anew.
  If needed, add `<target>_DEPS =` line with dependency list
- Add `<target>_FLAGS =` line with flags list.
- Add `<target>_LIBS =` line with library list.
- Add `<target>_OBJS =` line with object list. The object list is composed of
  the `.cc` source files that are needed for the target, with `.o` replacing
  the `.cc`.
- Add `CXX_STATIC_LIBRARY(lib<target>.pie.a): $(<target>_OBJS) ...` line.
- Add remaining boilerplate:
  ```
  CXX_STATIC_LIBRARY(<target>): CPPFLAGS += $(<target>_FLAGS)
  CXX_STATIC_LIBRARY(<target>): LDLIBS += $(<target>_LIBS)
  clean: CLEAN(<target>)
  ```
- Add a protocol buffer when there are already protocol buffers used from the
  same package/location as yours:
- Add `<protobuf>.pb.cc` to `<package>_PROTO_BINDINGS =` line or add a line
  `<package>_PROTO_BINDINGS += <protobuf>.pb.cc`.
- For every .o that depends on <protobuf>.pb.cc existing:
  ```
  <target>.o.depends: <protobuf>.pb.cc
  ```
- For every .o that depends on <protobuf>.pb.h existing:
  ```
  <target>.o.depends: <protobuf>.pb.h
  ```

### Add a protobuffer that is in a new package:
- Use the following template
  ```
  <package>_PROTO_BINDINGS =
  <package>_PROTO_PATH = $(SYSROOT)/<installed location of .proto files>
  <package>_PROTO_HEADERS = $(patsubst %.cc,%.h,$(<package>_PROTO_BINDINGS))
  <package>_PROTO_OBJS = $(patsubst %.cc,%.o,$(<package>_PROTO_BINDINGS))
  $(<package>_PROTO_HEADERS): %.h: %.cc ;
  $(<package>_PROTO_BINDINGS): %.pb.cc: $(<package>_PROTO_PATH)/%.proto
      $(PROTOC) --proto_path=$(<package>_PROTO_PATH) --cpp_out=. $<
  clean: CLEAN($(<package>_PROTO_BINDINGS))
  clean: CLEAN($(<package>_PROTO_HEADERS))
  clean: CLEAN($(<package>_PROTO_OBJS))
  # Add rules for compiling generated protobuffer code, as the CXX_OBJECTS list
  # is built before these source files exists and, as such, does not contain
  # them.
  $(eval $(call add_object_rules,$(<package>_PROTO_OBJS),CXX,cc))
  ```
- Use the above recipe to add in your protobufs

### NOTE:
If you have added in protocol buffer definitions directly to the package you
are working in, go undo that and figure out where they should actually go. If
you are really sure they should be in your package you are a bit on your own,
please feel free to contact chromium-os-dev@chromium.org.
