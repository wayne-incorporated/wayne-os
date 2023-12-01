# `biod_proxy`: DBus proxy library for Biometrics Daemon

Note that only boards with the `biod` USE flag build the biod package.
However, other programs, e.g. cryptohome, may need to link against a dbus
proxy for biod on all boards. Since the dbus proxy for working with biod
needs to handle an "AuthSession", a dbus proxy generated with platform.eclass's
`platform_install_dbus_client_lib` function is not enough.
The `biod_proxy` package (with its own ebuild) provides a library, so that
all boards can include the proper proxy for working with biod, but only boards
with `biod` USE flag will actually build and run biod.
