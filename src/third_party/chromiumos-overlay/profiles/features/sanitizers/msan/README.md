# Chrome OS memory sanitizer build profile

This directory contains the changes needed to build a board's packages with
[memory sanitizer](https://www.chromium.org/chromium-os/how-tos-and-troubleshooting/llvm-clang-build).

## Building a board with memory sanitizer

To build packages with memory sanitizer (msan) for a board, create a profile
in the overlays and point its parent to the appropriate architecture here. For
example, to add an msan profile for eve:

```bash
$ mkdir -p overlays/overlay-eve/profiles/msan
$ printf "../base\nchromiumos:features/sanitizers/msan/amd64\n" > \
    overlays/overlay-eve/profiles/msan/parent
```

A private profile may be needed as well.

```bash
$ mkdir -p private-overlays/overlay-eve-private/profiles/msan
$ printf "../base\neve:msan\n" > \
    private-overlays/overlay-eve-private/profiles/msan/parent
```

To build the eve board with msan profile, do:
```bash
$ setup_board --board=eve --profile=msan
$ build_packages --board=eve
```
