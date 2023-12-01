# Chrome OS thread sanitizer build profile

This directory contains the changes needed to build a board's packages with
[thread sanitizer](https://www.chromium.org/chromium-os/how-tos-and-troubleshooting/llvm-clang-build).

## Building a board with thread sanitizer

To build packages with thread sanitizer (tsan) for a board, create a profile
in the overlays and point its parent to the appropriate architecture here. For
example, to add an tsan profile for eve:

```bash
$ mkdir -p overlays/overlay-eve/profiles/tsan
$ printf "../base\nchromiumos:features/sanitizers/tsan/amd64\n" > \
    overlays/overlay-eve/profiles/tsan/parent
```

A private profile may be needed as well.

```bash
$ mkdir -p private-overlays/overlay-eve-private/profiles/tsan
$ printf "../base\neve:tsan\n" > \
    private-overlays/overlay-eve-private/profiles/tsan/parent
```

To build the eve board with tsan profile, do:
```bash
$ setup_board --board=eve --profile=tsan
$ build_packages --board=eve
```
