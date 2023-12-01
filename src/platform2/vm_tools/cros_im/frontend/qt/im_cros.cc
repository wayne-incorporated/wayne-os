// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "frontend/qt/im_cros.h"

#include <QGuiApplication>
#include <qpa/qplatformnativeinterface.h>
#include <QScreen>
#include <QtConcurrent>
#include <QtDebug>
#include <QtGlobal>
#include <memory>

#include "backend/wayland_manager.h"
#include "frontend/qt/x11.h"

namespace {
bool application_quit = false;

void QuitListener() {
  application_quit = true;
}

void DispatchEvents() {
  cros_im::WaylandManager::Get()->DispatchEvents();
}

void FlushRequests() {
  cros_im::WaylandManager::Get()->FlushRequests();
}

void InitLoop(cros_im::qt::CrosQtIMContext* qt_im_context) {
  while (!application_quit && qApp && !qApp->closingDown() &&
         !qt_im_context->init()) {
    QThread::yieldCurrentThread();
  }
}

}  // namespace

cros_im::qt::CrosQtIMContext* QCrosPlatformInputContextPlugin::create(
    const QString& system, const QStringList&) {
  if (system.compare("cros", Qt::CaseInsensitive) != 0)
    return nullptr;

  if (!qGuiApp) {
    qWarning() << "qGuiApp is nullptr when trying to create cros IME plugin "
                  "instance, quitting.";
    return nullptr;
  }
  if (qGuiApp->platformName() == "" || qGuiApp->platformName() == "wayland") {
    if (qGuiApp->platformName() == "") {
      // This probably means wayland, but the QtWayland plugin isn't initialized
      // yet, will need to wait before trying to instantiate anything relying on
      // native display pointers
      qWarning() << "qGuiApp->platformName() is empty str, probably due to "
                    "QtWayland is uninitialized, continue";
    }
    context_ = new cros_im::qt::CrosQtIMContext(false);
    static_cast<void>(QtConcurrent::run(InitLoop, context_));
    connect(qGuiApp, &QGuiApplication::lastWindowClosed, QuitListener);
    return context_;
  } else if (qGuiApp->platformName() == "xcb") {
    qInfo() << "xcb detected, starting cros input plugin";
    auto screen = qGuiApp->primaryScreen();
    if (!screen) {
      qWarning() << "qGuiApp->primaryScreen() returns nullptr, quitting";
      return nullptr;
    }
    void* x11_display =
        qGuiApp->platformNativeInterface()->nativeResourceForScreen("display",
                                                                    screen);
    if (!x11_display) {
      qWarning() << "nativeResourceForScreen() returns nullptr, quitting";
      return nullptr;
    }
    char* display_name = cros_im::qt::DisplayName(x11_display);
    if (!cros_im::WaylandManager::CreateX11Instance(display_name)) {
      qWarning(
          "cros_im::WaylandManager::CreateX11Instance returned false, "
          "quitting");
      return nullptr;
    }

    connect(qGuiApp, &QGuiApplication::lastWindowClosed, QuitListener);
    // Monitor the Wayland socket for events from the host.
    wayland_watcher_ = std::make_unique<QSocketNotifier>(
        cros_im::WaylandManager::Get()->GetFd(), QSocketNotifier::Read);
    connect(wayland_watcher_.get(), &QSocketNotifier::activated,
            DispatchEvents);

    // Flush requests after each main loop iteration.
    connect(QAbstractEventDispatcher::instance(),
            &QAbstractEventDispatcher::awake, FlushRequests);

    // Process any already-queued events immediately.
    cros_im::WaylandManager::Get()->DispatchEvents();

    context_ = new cros_im::qt::CrosQtIMContext(true);
    context_->init();
    return context_;
  } else {
    qWarning() << "Unsupported QPA platform: " << qGuiApp->platformName();
    return nullptr;
  }
}
