// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SAMPLES_HANDLER_BASE_H_
#define IIOSERVICE_DAEMON_SAMPLES_HANDLER_BASE_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>

#include "iioservice/daemon/common_types.h"

namespace iioservice {

class SamplesHandlerBase {
 protected:
  class SampleData {
   public:
    explicit SampleData(ClientData* client_data = nullptr);
    ~SampleData();

    void SetTimeoutTask();
    void SampleTimeout(uint64_t sample_index);

    ClientData* client_data_ = nullptr;
    scoped_refptr<base::SequencedTaskRunner> task_runner_;

    // The starting index of the next sample.
    uint64_t sample_index_ = 0;
    // Moving averages of channels except for channels that have no batch mode
    std::map<int32_t, int64_t> chns_;

    base::WeakPtrFactory<SampleData> weak_factory_{this};
  };

  explicit SamplesHandlerBase(
      scoped_refptr<base::SequencedTaskRunner> task_runner);

  // Might not be called on |task_runner_| sequence;
  void SetNoBatchChannels(std::vector<std::string> channel_ids);

  void OnSamplesObserverDisconnect(ClientData* client_data);

  void ResetWithReasonOnThread(cros::mojom::SensorDeviceDisconnectReason reason,
                               std::string description);

  void AddClientOnThread(
      ClientData* client_data,
      mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer);
  virtual void AddActiveClientOnThread(ClientData* client_data);

  void RemoveClientOnThread(ClientData* client_data);
  virtual void RemoveActiveClientOnThread(ClientData* client_data,
                                          double orig_freq);

  virtual double FixFrequency(double frequency);

  // The max frequency among sensor clients.
  double GetRequestedFrequencyOnThread();

  bool AddFrequencyOnThread(double frequency);
  bool RemoveFrequencyOnThread(double frequency);
  virtual bool UpdateRequestedFrequencyOnThread() = 0;

  void SetTimeoutTaskOnThread(ClientData* client_data);

  virtual void OnSampleAvailableOnThread(
      const base::flat_map<int32_t, int64_t>& sample);
  void AddReadFailedLogOnThread();

  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // Clients that either have invalid frequency or no enabled channels.
  std::set<ClientData*> inactive_clients_;
  // First is the active client, second is its data.
  std::map<ClientData*, std::unique_ptr<SampleData>> clients_map_;

  // Requested frequencies from clients.
  std::multiset<double> frequencies_;
  // Max frequency among |frequencies_|.
  double requested_frequency_ = 0.0;

  // The real device frequency. Given the kernel is requesting upsampling,
  // |dev_frequency_| >= |requested_frequency_|.
  double dev_frequency_ = 0.0;

  // The next coming sample's id. 0-based.
  // Shouldn't overflow as timestamp will overflow first.
  uint64_t samples_cnt_ = 0;

  uint32_t num_read_failed_logs_ = 0;
  uint32_t num_read_failed_logs_recovery_ = 0;

  std::set<int32_t> no_batch_chn_indices_;

 private:
  base::WeakPtrFactory<SamplesHandlerBase> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SAMPLES_HANDLER_BASE_H_
