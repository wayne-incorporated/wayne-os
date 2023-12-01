// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if defined(SHILL_PCH_H_)
#error You should not include this header directly in the code.
#endif

#define SHILL_PCH_H_

// This is the precompiled header for building shill.
// - This header will be prepend to each cc file directly by the compiler, so
//   the code should not include this header directly.
// - It's better not to include any shill headers here, since any change to the
//   included header would trigger a full rebuild, which is not desired.

// C standard library headers used in shill.
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// C++ standard library headers used in shill.
#include <algorithm>
#include <bitset>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <numeric>
#include <optional>
#include <ostream>
#include <queue>
#include <set>
#include <string>
#include <utility>
#include <valarray>
#include <vector>

// Headers from other projects which are both commonly included in shill and
// expensive to compile.
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/time/time.h>
