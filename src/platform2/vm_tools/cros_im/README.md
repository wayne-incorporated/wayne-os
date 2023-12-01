# cros\_im

This project implements support for using ChromeOS IMEs over the Wayland
protocols `zwp_unstable_text_input_v1` and
`zcr_text_input_extension_unstable_v1`. Googlers: See [go/crostini-ime],
[go/crostini-ime-rollout] and [go/crostini-ime-tests] for additional design
details.

This is currently under development and many desired pieces of functionality
may not work correctly or at all. If manually building cros\_im, it is
recommended to use a device on dev channel as backwards compatibility with
older versions of ChromeOS is not guaranteed.

IME Support is currently limited to GTK3 applications (including Electron-based
apps), and only Debian Bullseye containers are officially supported.  Known
issues are tracked [here][issue hotlist] and bugs can be reported
[here][new issue].

## System configuration
Enabling the #crostini-ime-support flag in chrome://flags is currently
required. Doing so will also set the env var `GTK_IM_MODULE=cros` globally.

The Qt IM module can be enabled via the #crostini-qt-ime-support flag, which
sets the env var `QT_IM_MODULE=cros`.

Configuring sommelier to allow the host compositor to handle Ctrl+Space is
suggested for users of multiple IMEs.

From M112, `cros-im` is installed by apt automatically.

## Building with pdebuild
.deb packages for bullseye on supported architectures (arm64, armhf, amd64,
i386) can be built and installed using the following commands.

**Crostini users:** Please note that these do not work on a Crostini terminal
because LXC containers in Crostini are unprivileged and do not have permission
to run the commands required.

```bash
git clone https://chromium.googlesource.com/chromiumos/platform2
cd platform2/vm_tools/cros_im

# Build for a specific architecture
ARCH=<architecture>
sudo ./build-packages ${ARCH}

# Install the resultant package for your device
sudo apt install ./bullseye_cros_im_debs/*${ARCH}.deb
```

## Manual build instructions
### Compiling
cros\_im can be compiled as follows:

```bash
git clone https://chromium.googlesource.com/chromiumos/platform2
cd platform2/vm_tools/cros_im
sudo apt install -y clang googletest libgtk-3-dev libgtkmm-3.0-dev libwayland-bin meson pkg-config xvfb weston dpkg-dev qtbase5-dev qtbase5-private-dev
meson build && cd build && ninja
```

### Testing
Automated tests can be run from a build directory with `meson test`. This
invokes `../test/run_tests.py`, which can also be run directly if needed.

The GTK IM module can be manually tested by setting up a custom IM module cache:
```bash
/usr/lib/*/libgtk-3-0/gtk-query-immodules-3.0 im-cros.so > dev-immodules.cache
export GTK_IM_MODULE_FILE=$(pwd)/dev-immodules.cache
```

The Qt IM module cannot be easily tested prior to installation.

### Installing
cros\_im can be installed as follows. It is recommended to uninstall the
`cros-im` apt package prior to doing this to avoid unexpected behaviour.
```bash
meson configure --prefix /usr && sudo meson install
```

[go/crostini-ime]: https://goto.google.com/crostini-ime
[go/crostini-ime-rollout]: https://goto.google.com/crostini-ime-rollout
[go/crostini-ime-tests]: https://goto.google.com/crostini-ime-tests
[new issue]: https://issuetracker.google.com/issues/new?component=1161264&template=1747723
[issue hotlist]: https://issuetracker.google.com/hotlists/4536324?s=resolved_time:asc&s=priority:asc
