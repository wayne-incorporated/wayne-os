// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "screen-capture-utils/uinput.h"

#include <cstdint>

#include <fcntl.h>
#include <linux/uinput.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>

namespace screenshot {
namespace {

// TODO(shaochuan): Possibly generate this list from the keymaps.
// clang-format off
constexpr const uint16_t kAllKeys[] = {
  KEY_0, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9,
  KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H, KEY_I, KEY_J, KEY_K,
  KEY_L, KEY_M, KEY_N, KEY_O, KEY_P, KEY_Q, KEY_R, KEY_S, KEY_T, KEY_U, KEY_V,
  KEY_W, KEY_X, KEY_Y, KEY_Z,
  KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6, KEY_F7, KEY_F8, KEY_F9,
  KEY_F10, KEY_F11, KEY_F12, KEY_F13, KEY_F14, KEY_F15, KEY_F16, KEY_F17,
  KEY_F18,
  KEY_UP, KEY_DOT, KEY_END, KEY_ESC, KEY_TAB, KEY_DOWN, KEY_HOME, KEY_LEFT,
  KEY_CLEAR, KEY_COMMA, KEY_ENTER, KEY_EQUAL, KEY_GRAVE, KEY_MINUS, KEY_PAUSE,
  KEY_RIGHT, KEY_SLASH, KEY_SPACE, KEY_SYSRQ, KEY_PAGEUP, KEY_LEFTALT,
  KEY_CAPSLOCK, KEY_LEFTCTRL, KEY_LEFTMETA, KEY_LINEFEED, KEY_PAGEDOWN,
  KEY_RIGHTALT, KEY_BACKSLASH, KEY_BACKSPACE, KEY_LEFTBRACE, KEY_LEFTSHIFT,
  KEY_RIGHTCTRL, KEY_RIGHTMETA, KEY_SEMICOLON, KEY_APOSTROPHE, KEY_RIGHTBRACE,
  KEY_RIGHTSHIFT, KEY_SCROLLLOCK, KEY_NUMLOCK,
  KEY_KP0, KEY_KP1, KEY_KP2, KEY_KP3, KEY_KP4, KEY_KP5, KEY_KP6, KEY_KP7,
  KEY_KP8, KEY_KP9, KEY_KPASTERISK, KEY_KPCOMMA, KEY_KPDOT, KEY_KPENTER,
  KEY_KPEQUAL, KEY_KPMINUS, KEY_KPPLUS, KEY_KPSLASH,
  0
};
// clang-format on

// Manages a file descriptor representing an uinput device.
class ScopedUinputFD final {
 public:
  ScopedUinputFD() : fd_(open("/dev/uinput", O_WRONLY | O_NONBLOCK)) {
    PCHECK(fd_.is_valid());

    // Ensure protocol version.
    unsigned int ver;
    Ioctl(UI_GET_VERSION, &ver);
    CHECK_GE(ver, 5) << "Unsupported protocol version, should be at least 5";
  }
  ScopedUinputFD(const ScopedUinputFD&) = delete;
  ScopedUinputFD& operator=(const ScopedUinputFD&) = delete;

  ~ScopedUinputFD() {
    if (created_) {
      Ioctl(UI_DEV_DESTROY);
    }
  }

  void CreateDevice() {
    Ioctl(UI_DEV_CREATE);
    created_ = true;
  }

  // Emits an input event with the current device.
  void Emit(uint16_t type, uint16_t code, int32_t value) const {
    input_event ev{
        {},  // time (struct timeval), filled in later
        type,
        code,
        value,
    };
    gettimeofday(&ev.time, nullptr);
    if (write(fd_.get(), &ev, sizeof(ev)) < 0) {
      PLOG(ERROR) << "Failed emitting input event";
    }
  }

  // Wrapped ioctl call to not expose |fd_|.
  template <typename... Args>
  void Ioctl(unsigned long req, Args... args) const {  // NOLINT(runtime/int)
    PCHECK(ioctl(fd_.get(), req, args...) == 0);
  }

 private:
  const base::ScopedFD fd_;
  bool created_{false};
};

// The actual implementation returned by Uinput::Create.
class UinputImpl final : public Uinput {
 public:
  explicit UinputImpl(rfbScreenInfoPtr server);
  ~UinputImpl() override;

 private:
  void SetupKeyboard();
  void SetupPointer(int32_t width, int32_t height);

  void OnKbdAddEvent(rfbBool down, rfbKeySym keySym, rfbClientPtr cl) const;
  void OnPtrAddEvent(int buttonMask, int x, int y, rfbClientPtr cl) const;

  ScopedUinputFD keyboard_;
  ScopedUinputFD pointer_;
};

// The current live instance, or nullptr if no instances exist.
UinputImpl* g_uinput{nullptr};

UinputImpl::UinputImpl(rfbScreenInfoPtr server) {
  CHECK(!g_uinput) << "Only one Uinput instance may exist at a time";
  g_uinput = this;

  // Setup devices.
  SetupKeyboard();
  SetupPointer(server->width, server->height);

  // Setup callbacks.
  server->kbdAddEvent = [](rfbBool down, rfbKeySym keySym, rfbClientPtr cl) {
    CHECK(g_uinput) << "uinput not set up";
    g_uinput->OnKbdAddEvent(down, keySym, cl);
  };
  server->ptrAddEvent = [](int buttonMask, int x, int y, rfbClientPtr cl) {
    CHECK(g_uinput) << "uinput not set up";
    g_uinput->OnPtrAddEvent(buttonMask, x, y, cl);
  };
}

UinputImpl::~UinputImpl() {
  g_uinput = nullptr;
}

// Sets up a uinput keyboard device. We simulate a standard 104-key keyboard in
// US layout.
void UinputImpl::SetupKeyboard() {
  // Enable key events.
  keyboard_.Ioctl(UI_SET_EVBIT, EV_KEY);
  for (auto* pkey = kAllKeys; *pkey; pkey++) {
    keyboard_.Ioctl(UI_SET_KEYBIT, *pkey);
  }

  const uinput_setup usetup{
      {BUS_USB /*bustype*/, 0, 0, 0},  // id (struct input_id)
      "kmsvnc keyboard",               // name
  };
  keyboard_.Ioctl(UI_DEV_SETUP, &usetup);

  keyboard_.CreateDevice();
}

// Sets up a uinput pointer device. We simulate a touch device with absolutely
// positioned "tap" events. Only the left mouse button works.
void UinputImpl::SetupPointer(int32_t width, int32_t height) {
  // Enable key events.
  pointer_.Ioctl(UI_SET_EVBIT, EV_KEY);
  pointer_.Ioctl(UI_SET_KEYBIT, BTN_LEFT);

  // Enable absolute events.
  pointer_.Ioctl(UI_SET_EVBIT, EV_ABS);
  pointer_.Ioctl(UI_SET_ABSBIT, ABS_X);
  pointer_.Ioctl(UI_SET_ABSBIT, ABS_Y);

  // Set up X/Y bounds.
  uinput_abs_setup uabs{};
  uabs.code = ABS_X;
  uabs.absinfo.maximum = width - 1;
  pointer_.Ioctl(UI_ABS_SETUP, &uabs);
  uabs.code = ABS_Y;
  uabs.absinfo.maximum = height - 1;
  pointer_.Ioctl(UI_ABS_SETUP, &uabs);

  const uinput_setup usetup{
      {BUS_USB /*bustype*/, 0, 0, 0},  // id (struct input_id)
      "kmsvnc touchscreen",            // name
  };
  pointer_.Ioctl(UI_DEV_SETUP, &usetup);

  pointer_.CreateDevice();
}

void UinputImpl::OnKbdAddEvent(rfbBool down,
                               rfbKeySym keySym,
                               rfbClientPtr cl) const {
  const int scancode = KeySymToScancode(keySym);
  if (!scancode) {
    LOG(WARNING) << "Received unknown keysym 0x" << std::hex << keySym;
    return;
  }

  VLOG(1) << "keysym 0x" << std::hex << keySym
          << " down:" << (down ? "true" : "false");
  keyboard_.Emit(EV_KEY, scancode, down);
  keyboard_.Emit(EV_SYN, SYN_REPORT, 0);
}

void UinputImpl::OnPtrAddEvent(int buttonMask,
                               int x,
                               int y,
                               rfbClientPtr cl) const {
  pointer_.Emit(EV_KEY, BTN_LEFT, buttonMask & 1);
  pointer_.Emit(EV_ABS, ABS_X, x);
  pointer_.Emit(EV_ABS, ABS_Y, y);
  pointer_.Emit(EV_SYN, SYN_REPORT, 0);

  rfbDefaultPtrAddEvent(buttonMask, x, y, cl);
}

}  // namespace

// Convert RFB keysyms (identical to X11 keysyms) to input event codes.
// ASCII chars are mapped back to their corresponding keys in US layout.
// Spec: https://tools.ietf.org/html/rfc6143#section-7.5.4
int KeySymToScancode(rfbKeySym key) {
  // We need custom formatting for the keymaps to make them readable.
  // clang-format off
  if ((0x20 <= key && key <= 0x7f) || (0xff00 <= key && key <= 0xff1f)) {
    static const uint16_t map[] = {
      /*0x00*/ 0, 0, 0, 0, 0, 0, 0, 0,
      /*0x08*/ KEY_BACKSPACE, KEY_TAB, KEY_LINEFEED, KEY_CLEAR, 0, KEY_ENTER, 0,
               0,
      /*0x10*/ 0, 0, 0, KEY_PAUSE, KEY_SCROLLLOCK, KEY_SYSRQ, 0, 0,
      /*0x18*/ 0, 0, 0, KEY_ESC, 0, 0, 0, 0,
      /*0x20*/ KEY_SPACE, KEY_1, KEY_APOSTROPHE, KEY_3, KEY_4, KEY_5, KEY_7,
               KEY_APOSTROPHE,
      /*0x28*/ KEY_9, KEY_0, KEY_8, KEY_EQUAL, KEY_COMMA, KEY_MINUS, KEY_DOT,
               KEY_SLASH,
      /*0x30*/ KEY_0, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7,
      /*0x38*/ KEY_8, KEY_9, KEY_SEMICOLON, KEY_SEMICOLON, KEY_COMMA, KEY_EQUAL,
               KEY_DOT, KEY_SLASH,
      /*0x40*/ KEY_2, KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G,
      /*0x48*/ KEY_H, KEY_I, KEY_J, KEY_K, KEY_L, KEY_M, KEY_N, KEY_O,
      /*0x50*/ KEY_P, KEY_Q, KEY_R, KEY_S, KEY_T, KEY_U, KEY_V, KEY_W,
      /*0x58*/ KEY_X, KEY_Y, KEY_Z, KEY_LEFTBRACE, KEY_BACKSLASH,
               KEY_RIGHTBRACE, KEY_6, KEY_MINUS,
      /*0x60*/ KEY_GRAVE, KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G,
      /*0x68*/ KEY_H, KEY_I, KEY_J, KEY_K, KEY_L, KEY_M, KEY_N, KEY_O,
      /*0x70*/ KEY_P, KEY_Q, KEY_R, KEY_S, KEY_T, KEY_U, KEY_V, KEY_W,
      /*0x78*/ KEY_X, KEY_Y, KEY_Z, KEY_LEFTBRACE, KEY_BACKSLASH,
               KEY_RIGHTBRACE, KEY_GRAVE, KEY_NUMLOCK,
    };
    return map[key & 0x7f];
  }
  if (0xff50 <= key && key <= 0xff5f) {
    static const uint16_t map[] = {
      /*0x0*/ KEY_HOME, KEY_LEFT, KEY_UP, KEY_RIGHT, KEY_DOWN, KEY_PAGEUP,
              KEY_PAGEDOWN, KEY_END,
      /*0x8*/ /*XK_Begin*/0, 0, 0, 0, 0, 0, 0, 0,
    };
    return map[key & 0xf];
  }
  if (0xff80 <= key && key <= 0xffbf) {
    static const uint16_t map[] = {
      /*0x80*/ 0, 0, 0, 0, 0, 0, 0, 0,
      /*0x88*/ 0, 0, 0, 0, 0, KEY_KPENTER, 0, 0,
      /*0x90*/ 0, 0, 0, 0, 0, KEY_KP7, KEY_KP4, KEY_KP8,
      /*0x98*/ KEY_KP6, KEY_KP2, KEY_KP9, KEY_KP3, KEY_KP1, 0, KEY_KP0,
               KEY_KPDOT,
      /*0xa0*/ 0, 0, 0, 0, 0, 0, 0, 0,
      /*0xa8*/ 0, 0, KEY_KPASTERISK, KEY_KPPLUS, KEY_KPCOMMA, KEY_KPMINUS,
               KEY_KPDOT, KEY_KPSLASH,
      /*0xb0*/ KEY_KP0, KEY_KP1, KEY_KP2, KEY_KP3, KEY_KP4, KEY_KP5, KEY_KP6,
               KEY_KP7,
      /*0xb8*/ KEY_KP8, KEY_KP9, 0, 0, 0, KEY_KPEQUAL, KEY_F1, KEY_F2,
    };
    return map[key & 0x3f];
  }
  if (0xffc0 <= key && key <= 0xffcf) {
    static const uint16_t map[] = {
      /*0x0*/ KEY_F3, KEY_F4, KEY_F5, KEY_F6, KEY_F7, KEY_F8, KEY_F9, KEY_F10,
      /*0x8*/ KEY_F11, KEY_F12, KEY_F13, KEY_F14, KEY_F15, KEY_F16, KEY_F17,
              KEY_F18,
    };
    return map[key & 0xf];
  }
  if (0xffe0 <= key && key <= 0xffef) {
    static const uint16_t map[] = {
      /*0x0*/ /*XK_F35*/0, KEY_LEFTSHIFT, KEY_RIGHTSHIFT, KEY_LEFTCTRL,
      /*0x4*/ KEY_RIGHTCTRL, KEY_CAPSLOCK, /*XK_Shift_Lock*/0, KEY_LEFTMETA,
      /*0x8*/ KEY_RIGHTMETA, KEY_LEFTALT, KEY_RIGHTALT, /*XK_Super_L*/0,
      /*0xc*/ /*XK_Super_R*/0, /*XK_Hyper_L*/0, /*XK_Hyper_R*/0, 0,
    };
    return map[key & 0xf];
  }
  // clang-format on
  return 0;
}

// static
std::unique_ptr<Uinput> Uinput::Create(rfbScreenInfoPtr server) {
  return std::make_unique<UinputImpl>(server);
}

}  // namespace screenshot
