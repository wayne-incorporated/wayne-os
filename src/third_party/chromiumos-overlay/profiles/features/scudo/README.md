This directory contains overlay features to build ChromiumOS overlays with the
LLVM Scudo Hardened Allocator as a system-wide allocator for all ChromiumOS
platform code.

To build packages with Scudo for a board, use a profile in the overlays
and point its parent to here. We generally however want Scudo to be
represented by its own separate overlay, as its intended to be built
with release builders (profiles alone create naming conflicts).

Check go/uprev-playbook for some details on how to configure new overlay
variants, which can be adapted to creating a new Scudo overlay.
