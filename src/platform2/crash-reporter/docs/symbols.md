# Symbol Life Cycle

Our crash reporting system strives to minimize on-device processing to keep the
runtime as light, fast, and small as possible.
This means we do quite a lot of work when building ChromiumOS, as well as
server processing (such as stack walking).
A break down in any one of these pieces can easily result in reports not being
processed correctly which significantly impairs developers.

Let's walk through all these systems to see how things are supposed to work so
that when one part breaks down, we have a blueprint to get back on track.

[TOC]

## Overview

Very briefly, the flow is:

*   [Debug info generated at compile time in each compilation unit](#compile);
*   [Debug info gathered at link time from inputs (objects, libraries, etc...)
    into the final output](#link);
*   [Debug info split out into separate debug files (e.g.
    `.debug` files under `/usr/lib/debug/`)](#separate-debug-files);
*   Debuggers (e.g. gdb) use output ELF & separate debug files when run by
    developers;
*   [Separate debug files processed into \[breakpad\] symbol files
    (`.sym`)](#generation);
*   [Symbol files uploaded to the symbol server backends](#upload);
*   Crash reports generated & uploaded to crash servers (we don't cover this);
*   Crash servers look up symbol files;
*   [Crash servers use symbol files (and other algorithms) to walk the stack
    and associate addresses with symbols](#crash-processing).

## Debug information

### Format (DWARF)

The foundation of the system depends on the [DWARF] format.
The quality of debugging depends quite a bit on this.

### Compression

Debug information could be compressed at various points in the process.
We don't currently utilize this in ChromiumOS.

### Compile

First, we need to compile code with debug information enabled.
This sounds easy enough (just add `-g` everywhere), but this can be subtle.
The toolchain (i.e. compiler) has to correctly produce [DWARF] data even in
spite of all the optimizations it has to apply.

This generally covers the `src_compile` stage of ebuild.

### Link

When we link all the inputs into a single object, we need to gather all that
debug information and bundle it in the output.

There's a few things to keep in mind:

*   The input objects might not be entirely from the current package.  When
    working with static libraries, many objects might come from other packages
    via those archives (i.e. `libfoo.a`).
*   In ChromiumOS, many packages are only static archives (e.g. protobufs).
*   Even if you don't think you're using static libraries, the vast majority of
    the time you actually are.  The toolchain (e.g. glibc & clang/gcc) provide a
    few small static libraries that are always implicitly linked in.  You can
    see this with glibc's `libc_nonshared.a`, clang's & gcc's `libgcc.a`, etc...
*   The toolchain also implicitly links in a few objects directly.  These are
    often referred to as C runtime objects and have names like `crtn.o`.

So even if you tweaked debug settings for a specific package, you might have to
chase down debug settings in dependencies, as well as the toolchain itself.

This generally covers the `src_compile` stage of ebuild.

### Build id

One critical aspect here is the concept of the executable's build-id.
This is a unique fingerprint of the program's loaded code.

In the minidump world, this is the same as the module id.

See the
[gdb documentation](https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html)
for more details.

### Separate debug files

Once we've finished linking everything, we create separate debug files
(which are often colloquially referred to as "splitdebug").
These can be found under the `/usr/lib/debug/` tree.
Typically it matches the path as it exists on the filesystem (e.g. `/bin/bash`
debug information is found at `/usr/lib/debug/bin/bash.debug`).

There are also symlinks to easily locate the debug information via build-ids.
`/usr/lib/debug/.build-id/xx/yy.debug` (where `xx/yy` are parts of the build-id)
is a symlink to e.g. `bash.debug`.

`objcopy` has a `--only-keep-debug` flag to pull out the debug information into
the `bash.debug` file before we `strip` it from the `bash` source.
We also use `--add-gnu-debuglink` to add `.gnu_debuglink` section for debuggers.

The content of `/usr/lib/debug/` tree is managed by Portage's [estrip] tool.
This automatically runs after the ebuild's `src_install` phase.

### Archiving

The default binpkgs produced locally include the separate debug files in the
package's binpkg file.
Builders will produce separate binpkgs to help speed things up for developers.

By default, the debug symbols from binpkgs won't be installed locally unless
`build_packages` is run with `--withdebugsymbols`.
Additionally, `cros_install_debug_syms` can be run manually.

Builders that build from source (e.g. all our release builders) will build &
install the debug information all the time.

### Usage

The `.debug` files are used during symbol generation (the next section), and by
local developers when using debuggers like `gdb`.
But they aren't really used otherwise.

## Symbol files

### Format

We use [Google Breakpad] currently to generate symbol files (`.sym`).
These contain the module id (a.k.a. build id) as well as all the function names
and reduced CFI data from [DWARF].
[Crashpad] uses the same output format here.

See the
[symbol files documentation](https://chromium.googlesource.com/breakpad/breakpad/+/HEAD/docs/symbol_files.md)
for more details.

### Generation

[chromite] has a [cros_generate_breakpad_symbols] script which runs
[Google Breakpad]'s dump_sym tool.
It needs the original program (e.g. `bash`) as well as the separate debug file
(e.g. `bash.debug`) to produce it.

This runs on builders after all build phases (`build_packages` & `build_image`).

### Upload

[chromite] has a [upload_symbols] script which uploads all the `.sym` files to
the symbol server.
It also has some swarming dedupe logic to avoid reuploading the same file.

This runs on builders after we've generated things.

### Archiving

[chromite] will create a `debug.tgz` archive during every build that includes
the `.sym` files in case we need to recreate things later on.
These can be found in the `gs://chromeos-image-archive/` with other build
specific artifact.

### Expiration

The symbol server will automatically expire unused symbol files (~6 months).
So if no crashes show up in that time, symbols could be thrown away.

## Crash processing

The crash servers rely on everything before this point in order to properly
unwind the stack and to symbolize the various addresses.

If the debug information (e.g. [DWARF]) is buggy, then all the CFI data will be
off, which means stack unwinding won't work well.

If the symbol addresses don't line up, then symbolizing will fail.

## FAQ

### How are symbols for prebuilt binaries handled?

If you have a package that is installing programs compiled outside of CrOS
(e.g. from Google prod systems), then keep the debugging information intact and
do not strip them before installing them.
The pipeline described in this document will pick them up correctly.

Shipping the debug information directly has the advantage of allowing direct
debugging by developers with test images e.g. using GDB.

If the package is internal-only (e.g. archives are in [localmirror-private]),
then you should be all set.

If the package is made available publicly (e.g. on [localmirror]), you have to
decide whether the debug information will leak details.
If it's all open source code, then you shouldn't have to worry about it, but if
it's proprietary code, you will need to take a different approach.
See the next section.

The increased size of the debug files isn't usually an issue as we'd generate
them normally anyways.
As long as it's under O(100's MB), don't sweat it.

#### Splitdebug handling

If you need to make prebuilt binaries public, but keep the debug symbols
private, then you will need separate archives.
One will contain the stripped release programs while the other will contain
splitdebug information.

You'll have to create two packages: the public one that installs the release
programs like normal, and a private one that only installs the symbols into
the `/usr/lib/debug` path.

You can create the splitdebug files using `objcopy`.
See portage's [estrip] for an example.

### How are symbols for non-ELF binaries handled?

Short answer: they aren't!

We haven't had any requests yet for supporting anything other than [ELF] files.
If you need this, please reach out to [chromeos-build-discuss] for help.
This includes NaCl, WASM, JS, or other programs.


[chromite]: https://chromium.googlesource.com/chromiumos/chromite/
[Crashpad]: https://chromium.googlesource.com/crashpad/crashpad/
[cros_generate_breakpad_symbols]: https://chromium.googlesource.com/chromiumos/chromite/+/HEAD/scripts/cros_generate_breakpad_symbols.py
[DWARF]: https://en.wikipedia.org/wiki/DWARF
[ELF]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
[estrip]: https://chromium.googlesource.com/chromiumos/third_party/portage_tool/+/refs/tags/portage-2.3.49/bin/estrip#192
[Google Breakpad]: https://chromium.googlesource.com/breakpad/breakpad/
[localmirror]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md#Public-mirrors
[localmirror-private]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md#Private-mirrors
[upload_symbols]: https://chromium.googlesource.com/chromiumos/chromite/+/HEAD/scripts/upload_symbols.py
