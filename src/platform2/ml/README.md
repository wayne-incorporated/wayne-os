# Chrome OS Machine Learning Service

## Summary

The Machine Learning (ML) Service provides a common runtime for evaluating
machine learning models on device. The service wraps the TensorFlow Lite runtime
and provides infrastructure for deployment of trained models. The TFLite runtime
runs in a sandboxed process. Chromium communicates with ML Service via a Mojo
interface.

## How to use ML Service

You need to provide your trained models to ML Service first, then load and use
your model from Chromium using the client library provided at
[//chromeos/services/machine_learning/public/cpp/]. See [this
doc](docs/publish_and_use_model.md) for more detailed instructions.

Note: The sandboxed process hosting TFLite models is currently shared between
all users of ML Service. If this isn't acceptable from a security perspective
for your model, follow [this bug](http://crbug.com/933017) about switching ML
Service to having a separate sandboxed process per loaded model.

## Metrics

The following metrics are currently recorded by the daemon process in order to
understand its resource costs in the wild:

* MachineLearningService.MojoConnectionEvent: Success/failure of the
  D-Bus->Mojo bootstrap.
* MachineLearningService.TotalMemoryKb: Total (shared+unshared) memory footprint
  every 5 minutes.
* MachineLearningService.PeakTotalMemoryKb: Peak value of
  MachineLearningService.TotalMemoryKb per 24 hour period. Daemon code can
  also call ml::Metrics::UpdateCumulativeMetricsNow() at any time to take a
  peak-memory observation, to catch short-lived memory usage spikes.
* MachineLearningService.CpuUsageMilliPercent: Fraction of total CPU resources
  consumed by the daemon every 5 minutes, in units of milli-percent (1/100,000).

Additional metrics added in order to understand the resource costs of each
request for a particular model:

* MachineLearningService.|MetricsModelName|.|request|.Event: OK/ErrorType of the
  request.
* MachineLearningService.|MetricsModelName|.|request|.TotalMemoryDeltaKb: Total
  (shared+unshared) memory delta caused by the request.
* MachineLearningService.|MetricsModelName|.|request|.CpuTimeMicrosec: CPU time
  usage of the request, which is scaled to one CPU core, i.e. the units are
  CPU-core\*microsec (10 CPU cores for 1 microsec = 1 CPU core for 10 microsec =
  recorded value of 10).

|MetricsModelName| is specified in the model's [metadata][model_metadata.cc] for
builtin models and is specified in |FlatBufferModelSpec| by the client for
flatbuffer models.
The above |request| can be following:

* LoadModelResult
* CreateGraphExecutorResult
* ExecuteResult (model inference)

The request name "LoadModelResult" is used no matter the model is loaded by
|LoadBuiltinModel| or by |LoadFlatBufferModel|. This is valid based on the fact
that for a particular model, it is either loaded by |LoadBuiltinModel| or by
|LoadFlatBufferModel| and never both.

There is also an enum histogram "MachineLearningService.LoadModelResult"
which records a generic model specification error event during a
|LoadBuiltinModel| or |LoadFlatBufferModel| request when the model name is
unknown.

## Original design docs

Note that aspects of the design may have evolved since the original design docs
were written.

* [Overall design](https://docs.google.com/document/d/1ezUf1hYTeFS2f5JUHZaNSracu2YmSBrjLkri6k6KB_w/edit#)
* [Mojo interface](https://docs.google.com/document/d/1pMXTG-OIhkNifR2DCPa2bCF0X3jrAM-U6UK230pBv5I/edit#)
* [Deamon\<-\>Chromium IPC implementation](https://docs.google.com/document/d/1EzBKLotvspe75GUB0Tdk_Namstyjm6rJHKvNmRCCAdM/edit#)
* [Model publishing](https://docs.google.com/document/d/1LD8sn8rMOX8y6CUGKsF9-0ieTbl97xZORZ2D2MjZeMI/edit#)


[//chromeos/services/machine_learning/public/cpp/]: https://cs.chromium.org/chromium/src/chromeos/services/machine_learning/public/cpp/service_connection.h
[model_metadata.cc]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/ml/model_metadata.cc
