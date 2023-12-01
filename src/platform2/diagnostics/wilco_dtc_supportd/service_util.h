// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_SERVICE_UTIL_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_SERVICE_UTIL_H_

#include <initializer_list>

#include <base/barrier_closure.h>
#include <base/check.h>
#include <base/run_loop.h>

namespace diagnostics {
namespace wilco {

// Creates a RunLoop with a BarrierClosure and calls the ShutDown method
// on the passed-in |services|.
// ShutDown will be called in the order in which the |services| are provided.
// The caller is responsible for this order.
//
// Note: Do not call this function if your code is utilizing a RunLoop already.
template <typename... Services>
void ShutDownServicesInRunLoop(Services*... services) {
  CHECK(!base::RunLoop::IsRunningOnCurrentThread());
  base::RunLoop run_loop;
  const base::RepeatingClosure barrier_closure =
      base::BarrierClosure(sizeof...(services), run_loop.QuitClosure());

  // Braced initializer lists guarantee the execution of clauses from left to
  // right [dcl.init.list 8.5.4.4].
  // TODO(rbock, b/157435783): Once we have C++17, replace this with a proper
  // fold expression.
  (void)std::initializer_list<int>{
      (services->ShutDown(base::OnceClosure(barrier_closure)), 0)...};

  run_loop.Run();
}

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_SERVICE_UTIL_H_
