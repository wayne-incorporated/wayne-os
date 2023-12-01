# DPSL library

This directory contains the DPSL library ("diagnostics_processor support
library").

Please see ../README.md for general information on this project.

## Overview

This library is intended to be used by third-party implementors of the
`wilco_dtc` daemon.

Essentially, it's a helper library for writing an asynchronous program
that is able to:

* Make gRPC requests to the `wilco_dtc_supportd` daemon in order to fetch
  device telemetry information, make network requests, etc. See the API
  definition at grpc/wilco_dtc_supportd.proto.

* Serve incoming gRPC requests that the `wilco_dtc_supportd` daemon is making,
  which allow to pass the output of the telemetry processing. See the
  API definition at grpc/wilco_dtc.proto.

## API considerations

Considerations made when designing this DPSL library:

1. The library should take care of proper initialization of gRPC clients
   and services.

2. The API should incline towards simple threading models, similar in
   spirit to [Threading and Tasks in Chrome](https://chromium.googlesource.com/chromium/src/+/lkgr/docs/threading_and_tasks.md).
   Some precise goals: objects should be single-threaded (with a few
   clear exceptions); synchronous blocking should be avoided;
   long-running jobs should be offloaded to background threads.

3. The API should be stable and source-level backwards compatible
   whenever possible.
   The reason is that the consumers of this library will be implemented
   by third parties in the closed-source form.

4. The API should have no explicit dependency on symbols from
   libchrome/libbrillo.
   (This is a consequence of the item #3 - without this, third-party
   consumers of this library would have to constantly update their code
   to track libchrome/libbrillo changes.)
   Note, however, that the library continues to use libchrome/libbrillo
   under the hood.

5. The library should be licensed in a way that allows it to be used by
   third parties in their closed-source implementations.
