# Chrome OS coverage build profile

This directory contains the changes needed to build a board's packages with
[coverage profiling](https://www.chromium.org/chromium-os/how-tos-and-troubleshooting/llvm-clang-build).

## Building a board with coverage

To build packages with coverage profile for a board, create a profile
in the overlays and point its parent to the appropriate architecture here. For
example, to add an coverage profile for eve:

```bash
$ mkdir -p overlays/overlay-eve/profiles/coverage
$ printf "../base\nchromiumos:features/sanitizers/coverage/amd64\n" > \
    overlays/overlay-eve/profiles/coverage/parent
```

A private profile may be needed as well.

```bash
$ mkdir -p private-overlays/overlay-eve-private/profiles/coverage
$ printf "../base\neve:coverage\n" > \
    private-overlays/overlay-eve-private/profiles/coverage/parent
```

To build the eve board with coverage profile, do:
```bash
$ setup_board --board=eve --profile=coverage
$ build_packages --board=eve
```
