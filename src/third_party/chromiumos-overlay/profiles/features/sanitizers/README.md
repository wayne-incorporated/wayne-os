# Chrome OS sanitizer build profiles

This directory contains the profiles needed to build a board's packages with
various sanitizer flags e.g.
[address sanitizer](https://www.chromium.org/chromium-os/how-tos-and-troubleshooting/llvm-clang-build).

To build a package with sanitizers, the common steps are:
1.  Inherit `cros-sanitizers` eclass in the package ebuild.
2.  Call `sanitizers-setup-env` in the ebuild typically in `src_configure`
    step.

Depending on the sanitizer profile, the package will be built with appropriate
sanitizer flags. The profiles are listed in the following section.

## List of sanitizer profiles

### asan

Used for building packages with
[Address sanitizer](https://clang.llvm.org/docs/AddressSanitizer.html).

### coverage

Use it for building packages with
[Clang sanitizer coverage](https://clang.llvm.org/docs/SanitizerCoverage.html).

### msan

Use it for building packages with
[Memory sanitizer](https://clang.llvm.org/docs/MemorySanitizer.html).

### tsan

Use it for building packages with
[Thread sanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html).

### ubsan

Use it for building packages with
[Undefined behavior sanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).

### fuzzer

Fuzzer profiles provide further support for building packages with
[Libfuzzer](https://llvm.org/docs/LibFuzzer.html) needed for fuzzing.
For fuzzing, it is necessary to use a sanitizer subprofile in fuzzer directory
e.g. fuzzer/asan or fuzzer/msan must be used so that packages are built with
appropriate sanitizer flags in addition to libfuzzer flags.

Note: When building packages for fuzzing, binaries are not stripped and all
packages are built with sanitizer flags. This is in contrast to other profiles
where packages generally need to opt-in to be built by sanitizer flags.

## Example: Building a board with address sanitizer

To build packages with address sanitizer (asan) for a board, create a profile
in the overlays and point its parent to the appropriate architecture here. For
example, to add an asan profile for eve:

```bash
$ mkdir -p overlays/overlay-eve/profiles/asan
$ printf "../base\nchromiumos:features/sanitizers/asan/amd64\n" > \
    overlays/overlay-eve/profiles/asan/parent
```

A private profile may be needed as well.

```bash
$ mkdir -p private-overlays/overlay-eve-private/profiles/asan
$ printf "../base\neve:asan\n" > \
    private-overlays/overlay-eve-private/profiles/asan/parent
```

To build the eve board with asan profile, do:
```bash
$ setup_board --board=eve --profile=asan
$ build_packages --board=eve
```
