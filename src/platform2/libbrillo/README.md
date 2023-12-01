# libbrillo: platform utility library

libbrillo is a shared library meant to hold common utility code that we deem
useful for platform projects.
It supplements the functionality provided by libbase/libchrome since that
project, by design, only holds functionality that Chromium (the browser) needs.
As a result, this tends to be more OS-centric code.

## AOSP Usage

This project is also used by [Update Engine] which is maintained in AOSP.
However, AOSP doesn't use this codebase directly, it maintains its own
[libbrillo fork](https://android.googlesource.com/platform/external/libbrillo/).

To help keep the projects in sync, we have a gsubtree set up on our GoB:
https://chromium.googlesource.com/chromiumos/platform2/libbrillo/

This allows AOSP to cherry pick or merge changes directly back into their fork.

[Update Engine]: https://android.googlesource.com/platform/system/update_engine/
