# Starnix Overlay

This overlay aims to build a Chromium OS sysroot that can be run on Fuchsia
under Starnix. Starnix is a Linux emulation layer for Fuchsia.

The goal is to start with a minimal image, and slowly add back the components
that make a real, production Chromium OS image.

This is done by overriding most virtual targets with an empty `RDEPEND` set.
Most notably, this overlay will never need to build or create partitions for a
Linux kernel.
