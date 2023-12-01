# Chrome OS Kernel Configuration

The [cros-kernel2] eclass supports automatically configuring and building a
kernel for Chrome OS. It supports the following methods of retrieving the
appropriate `.config` file:

1.  The "splitconfig" method, currently described in the [chromium.org docs].
    This mechanism is used when your kernel source tree has a
    `chromeos/{scripts,config}/` directory structure. This is used for all
    supported Chrome OS kernels.
1.  Direct specification, via the `CHROMEOS_KERNEL_CONFIG` variable, described
    below. This method is used by some build targets that deviate significantly
    from a standard Chrome OS kernel (e.g., some embedded targets).
1.  The "fallback" method, described below. This method is used when your build
    does not use a Chrome-OS-flavored kernel source tree. This commonly occurs,
    for example, when building a "mainline" kernel released directly by Linus
    Torvalds. This mechanism generally should be used only for local
    development and testing, not for any official build overlays.

## `CHROMEOS_KERNEL_CONFIG`

When set in your board overlay or in your environment, this variable specifies
the `.config` to use, either as a path relative to the kernel source directory
(e.g., `arch/${arch}/configs/<foo>_defconfig`) or as an absolute path within
the SDK (e.g., `/mnt/host/source/src/.../my_config`). This variable overrides
any other configuration mechanisms documented in this file.

## Fallback kernel config

When looking for a kernel configuration, the `cros-kernel2_src_configure()`
function looks first for the Chrome OS configuration via the other two
mechanisms (either in your kernel's `chromeos/scripts/` directory, or via
`CHROMEOS_KERNEL_CONFIG`). If these are not present, it "falls back" to a set
of defconfigs provided in [this directory].

### Fallback config selection

The [cros-kernel2] eclass tries to automatically determine an appropriate
`*_defconfig` to use for your given `${BOARD}`. e.g., for a Qualcomm platform,
it should select `qualcomm_defconfig`, and for an Intel system, it should
select `x86_64_defconfig`. These determinations are made (in
`get_build_arch()`) based on the values of the `ARCH` and
`CHROMEOS_KERNEL_SPLITCONFIG` variables. You can retrieve those values manually
via the `portageq` tool (e.g., `portageq-${BOARD} envvar
CHROMEOS_KERNEL_SPLITCONFIG`; `portageq-${BOARD} envvar ARCH`).

### Modifying the defconfigs

*   Because these `*_defconfig` files are not used for any official builds,
    it's generally OK to add any additional `CONFIG_*` options that might be
    useful to you or others (e.g., additional hardware support or features).

    *** promo
    If you find that you need defconfig modifications to support the hardware
    present on your Chrome OS system on an upstream kernel **please** consider
    submitting a CL to update the defconfigs. Other developers will appreciate
    the time you've saved them, when they don't have to figure this out
    themselves!
    ***

*   Fallback `*_defconfig` files tend to be useful to developers over a range
    of recent kernels (e.g., latest kernel `vX.Y`, previous kernel `v.X.(Y-1)`,
    etc.), so while Kconfig symbols may change in name or in default value, it
    is generally recommended to only add to the configs, rather than rename or
    delete entries. So for example, while `CONFIG_MFD_CROS_EC_CHARDEV` was
    renamed to `CONFIG_MFD_CROS_EC_DEV` (and enabled automatically via
    `CONFIG_CROS_EC`) upstream, this [qualcomm_defconfig update] did not delete
    `CONFIG_MFD_CROS_EC_CHARDEV=y` from `qualcomm_defconfig`. That way,
    `cros_ec` features would still work when built with both new and old
    kernels.

### Example upstream kernel build

*** note
It is common for upstream Linux not to support (or, only have limited support
for) hardware present on a given Chrome OS system, so there is no guarantee
this approach will be effective for your hardware.
***

The fallback kernel config mechanism can make testing and developing on
upstream kernels easy. The following is a quick walkthrough on one way to use
that support.

1.  Locate your `BOARD`'s existing kernel (e.g.,
    `sys-kernel/chromeos-kernel-X_Y`, with source at
    `src/third_party/kernel/vX.Y`).
1.  Check out a mainline kernel at that location:

    ```
    cd .../src/third_party/kernel/vX.Y
    git fetch https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git refs/tags/vN.M
    git checkout FETCH_HEAD
    ```

1.  Build your kernel as usual. e.g.:

    ```
    cros-workon-${BOARD} start chromeos-kernel-X_Y
    emerge-${BOARD} chromeos-kernel-X_Y
    ```

The resulting kernel can be deployed to your existing Chrome OS system as you
would deploy any other Chrome OS kernel.


[cros-kernel2]: ../cros-kernel2.eclass
[chromium.org docs]: https://dev.chromium.org/chromium-os/how-tos-and-troubleshooting/kernel-configuration
[this directory]: ./
[qualcomm_defconfig update]: https://crrev.com/c/2166346
