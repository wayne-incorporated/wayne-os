// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_FRONTEND_QT_CROS_QT_IM_CONTEXT_H_
#define VM_TOOLS_CROS_IM_FRONTEND_QT_CROS_QT_IM_CONTEXT_H_

#include <qpa/qplatforminputcontext.h>
#include <memory>
#include <QGuiApplication>
#include <QInputMethodEvent>
#include <string>
#include <vector>

#include "backend/im_context_backend.h"

namespace cros_im {
namespace qt {

class CrosQtIMContext : public QPlatformInputContext {
  Q_OBJECT

 public:
  explicit CrosQtIMContext(bool is_x11) : is_x11_(is_x11) {
    QInputMethod* p = qApp->inputMethod();
    connect(p, SIGNAL(cursorRectangleChanged()), this,
            SLOT(cursorRectangleChanged()));
  }

  // can be always true, return if the IME is connected
  bool isValid() const override;

  // equivalent to gtk side's set_client_window+focus_in+focus_out
  void setFocusObject(QObject* object) override;

  // seems just make QInputMethod::Click do a commit()
  // but what does click in our context do?
  void invokeAction(QInputMethod::Action action, int cursorPosition) override;

  // equivalent to gtk side's reset
  void reset() override;

  void commit() override;

  // mostly equivalent to gtk side's set_surrounding, but what does anchor do?
  void update(Qt::InputMethodQueries) override;

  // equivalent to gtk side's filter_keypress
  bool filterEvent(const QEvent* event) override;

  QLocale locale() const override;

  bool hasCapability(Capability capability) const override;

 public Q_SLOTS:

  // equivalent to gtk side's set_cursor_location
  void cursorRectangleChanged();

  bool init();

 private:
  // Receive callback from cros side
  class BackendObserver : public IMContextBackend::Observer {
   public:
    explicit BackendObserver(CrosQtIMContext* context) : context_(context) {}

    void SetPreedit(const std::string& preedit,
                    int cursor,
                    const std::vector<PreeditStyle>& styles) override;

    void SetPreeditRegion(int start_offset,
                          int length,
                          const std::vector<PreeditStyle>& styles) override;

    void Commit(const std::string& commit) override;

    void DeleteSurroundingText(int start_offset, int length) override;

    void KeySym(uint32_t keysym, KeyState state, uint32_t modifiers) override;

   private:
    CrosQtIMContext* context_;
  };

  void Activate();

  IMContextBackend::ContentTypeOld GetUpdatedHints();

  std::string preedit_;
  QList<QInputMethodEvent::Attribute> preedit_attributes_;
  bool inited_ = false;
  bool failed_init_ = false;
  bool is_x11_;
  bool is_in_focus_ = false;
  bool is_activated_ = false;

  std::unique_ptr<BackendObserver> backend_observer_ = nullptr;
  std::unique_ptr<cros_im::IMContextBackend> backend_ = nullptr;
};

}  // namespace qt
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_FRONTEND_QT_CROS_QT_IM_CONTEXT_H_
