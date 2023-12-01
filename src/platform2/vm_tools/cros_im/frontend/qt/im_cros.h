// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_FRONTEND_QT_IM_CROS_H_
#define VM_TOOLS_CROS_IM_FRONTEND_QT_IM_CROS_H_

#include <qpa/qplatforminputcontextplugin_p.h>
#include <QSocketNotifier>
#include <string>
#include <vector>

#include "frontend/qt/cros_qt_im_context.h"

class QCrosPlatformInputContextPlugin : public QPlatformInputContextPlugin {
  Q_OBJECT
  Q_PLUGIN_METADATA(IID QPlatformInputContextFactoryInterface_iid FILE
                    "cros.json")

 public:
  cros_im::qt::CrosQtIMContext* create(const QString& system,
                                       const QStringList&) override;

 private:
  cros_im::qt::CrosQtIMContext* context_ = nullptr;
  std::unique_ptr<QSocketNotifier> wayland_watcher_ = nullptr;
};
#endif  // VM_TOOLS_CROS_IM_FRONTEND_QT_IM_CROS_H_
