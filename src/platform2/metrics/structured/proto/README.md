# What is this?

This directory contains the protobufs required to transmit structured metrics
from chrome to chromeos.

## structured_data.proto

This is copied from third_party/metrics_proto/structured_data.proto, which is
in turn exported from google3. Any changes should first be made to google3,
then exported to chrome, then manually copied to platform2. Changes must be
backwards compatible.

## storage.proto

This is copied from components/metrics/structured/storage.proto. Any changes
should first be made to chrome, then coped to platform2. Changes must be
backwards compatible.
