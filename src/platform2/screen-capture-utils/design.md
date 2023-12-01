# kmsvnc Design notes

[TOC]

## Background

Long time ago VNC used to work on Chromebooks, when X11 was being used on DUT,
but with freon migration we lost that feature.

The current workaround is to use Chrome Remote Desktop on Chrome OS devices,
which does not work on the login screen. We have tast test dev.RemoteDesktop
which tries to automate logging in and starting Chrome Remote Desktop, it is
brittle because it relies on UI, and UI needs to be in English US, but it works
when it works.

Most of the time we just do with having the DUT locally or not watching the
display.

Betty is a board for running as virtual machines. Qemu can run betty images and
Qemu provides a VNC server capability. We found that GCE can run betty images
too, but does not provide a VNC server capability, and nested virtualization
running qemu on GCE was too slow for our use case, hence we needed VNC
capability more than before.

## Goals

Have VNC working on betty so that developers have the option of what is on the
display, and interact. Ideally I can see the login screen also so that I can log
in via VNC in a similar manner to qemu VNC.

## Detailed Design

### VNC server

We rely on libvncserver for the details of VNC serving. kmsvnc provides the
device manipulation specific to chromebooks.

### Authentication

kmsvnc does not provide authentication mechanism, and defers authentication to
ssh and its port forwarding feature already available on Chromebooks.

### Grabbing screen

We use KMS/DRM for grabbing the current display.

For devices that expose capability of capturing multiple planes we support
scanning multiple planes and merging.

There are two major types of boards that this code handles.

#### getfb2-capable

framebuffer is converted every frame to ARGB format using EGL call. This only
depends on getfb2 ioctl being available (kernel 4.4 or later).

Development was done typically with samus.

#### getfb2-capable and atomic_modeset capable

planes are scanned and merged so that when multiple planes are being used they
are correctly rendered. This needs getfb2 and in addition support for
`DRM_CLIENT_CAP_ATOMIC`.

Development was done typically with rammus.

### Display orientation

Tablets can be rotated, and we don't handle this yet, sorry! You will have to
turn you head 90 degrees to the left to view the display in the correct
orientation for now.

### Keyboard handling

The [RFB protocol](https://tools.ietf.org/html/rfc6143#section-7.5.4) follows
the X11 protocol for keyboard handling. Upon receiving an
[X11 key symbol](https://cgit.freedesktop.org/xorg/proto/x11proto/tree/keysymdef.h)
on server-side, we map them back to
[Linux input keycodes](https://chromium.googlesource.com/chromiumos/third_party/kernel/+/v4.4/include/uapi/linux/input-event-codes.h),
and emit input events using a virtual keyboard device created via the Linux
uinput module.

The protocol is defined such that, if the input keystroke effectively types an
ASCII char on the client, the char is sent directly to the server as the X11
keysym. For example when the user types the key `8`, the server would receive
`8` as the keysym. However when the user types ‘8’ while holding Shift, the
server would receive (assuming US layout) `*`. We need to map both `8` and `*`
into `KEY_8`.

Note that some keys map to ASCII chars directly but are considered special in
X11, e.g. keypad symbols like `XK_KP_Multiply`. We observed that some clients
are not handling them correctly which may cause interop issues. For example
using VNC Viewer for Google Chrome, when the keypad `*` key is pressed, it sends
`*` directly instead of `XK_KP_Multiply`, and maps to `KEY_8` in our
implementation.

### Mouse handling

The server receives pointer events with their absolute coordinates according to
screen size. Similar to the keyboard, we create a virtual uinput device for
those events. However it’s nontrivial to emulate a mouse since

-   Linux expects relative x/y movements from the mouse, not absolute positions
-   We don’t know the initial position of the mouse
-   In Chrome there’s pointer acceleration, we don’t know the actual pointer
    position after a mouse move event

We’ve ended up emulating a touch screen device so we can send touch events with
absolute coordinates. Only left click “tapping” works. Drag & drop works.
(Actually the QEMU VNC server uses the same approach, it’s Chrome’s fault that
it assumes touchscreens can’t emit `BTN_RIGHT` events.)
