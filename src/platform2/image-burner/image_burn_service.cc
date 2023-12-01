// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "image-burner/image_burn_service.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>

namespace imageburn {

namespace {
// Update signal is emitted only when there is at least
// |kProgressSignalInterval| bytes progress.
const int kProgressSignalInterval = 100 * 1024;  // 100 KB
}  // namespace

ImageBurnService::ImageBurnService(scoped_refptr<dbus::Bus> bus,
                                   BurnerImpl* burner_impl)
    : org::chromium::ImageBurnerInterfaceAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kImageBurnServicePath)),
      amount_burnt_for_next_signal_(0),
      burning_(false),
      burner_impl_(burner_impl) {
  DCHECK(burner_impl_);
  LOG(INFO) << "Image Burn Service created";
}

ImageBurnService::~ImageBurnService() = default;

void ImageBurnService::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

bool ImageBurnService::BurnImage(brillo::ErrorPtr* error,
                                 const std::string& from_path,
                                 const std::string& to_path) {
  if (burning_) {
    brillo::Error::AddTo(error, FROM_HERE, brillo::errors::dbus::kDomain,
                         "image-burn-quark", "Another burn in progress.");
    return false;
  }

  burning_ = true;
  amount_burnt_for_next_signal_ = 0;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&ImageBurnService::BurnImageInternal,
                                base::Unretained(this), from_path, to_path));

  return true;
}

void ImageBurnService::BurnImageInternal(const std::string& from_path,
                                         const std::string& to_path) {
  DCHECK(burning_);
  burner_impl_->BurnImage(from_path.c_str(), to_path.c_str());
  burning_ = false;
}

void ImageBurnService::SendFinishedSignal(const char* target_path,
                                          bool success,
                                          const char* error_message) {
  Sendburn_finishedSignal(target_path, success, error_message);
}

void ImageBurnService::SendProgressSignal(int64_t amount_burnt,
                                          int64_t total_size,
                                          const char* target_path) {
  // Send signal only when there is at least |kProgressSignalInterval| bytes
  // progress.
  if (amount_burnt >= amount_burnt_for_next_signal_) {
    Sendburn_progress_updateSignal(target_path, amount_burnt, total_size);
    amount_burnt_for_next_signal_ = amount_burnt + kProgressSignalInterval;
  }
}

}  // namespace imageburn
