# Chrome OS undefined behavior sanitizer build profile

This directory contains the changes needed to build a board's packages with
[undefined behavior sanitizer](https://www.chromium.org/chromium-os/how-tos-and-troubleshooting/llvm-clang-build).

## Building a board with undefined behavior sanitizer

To build packages with memory sanitizer (ubsan) for a board, create a profile
in the overlays and point its parent to the appropriate architecture here. For
example, to add an ubsan profile for eve:

```bash
$ mkdir -p overlays/overlay-eve/profiles/ubsan
$ printf "../base\nchromiumos:features/sanitizers/ubsan/amd64\n" > \
    overlays/overlay-eve/profiles/ubsan/parent
```

A private profile may be needed as well.

```bash
$ mkdir -p private-overlays/overlay-eve-private/profiles/ubsan
$ printf "../base\neve:ubsan\n" > \
    private-overlays/overlay-eve-private/profiles/ubsan/parent
```

To build the eve board with ubsan profile, do:
```bash
$ setup_board --board=eve --profile=ubsan
$ build_packages --board=eve
```
