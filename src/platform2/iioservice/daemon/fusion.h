/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Migrated from aosp/frameworks/native/services/sensorservice/Fusion.h
 */

#ifndef IIOSERVICE_DAEMON_FUSION_H_
#define IIOSERVICE_DAEMON_FUSION_H_

#include <set>

#include <aosp/frameworks/native/services/sensorservice/mat.h>
#include <aosp/frameworks/native/services/sensorservice/quat.h>
#include <aosp/frameworks/native/services/sensorservice/vec.h>

#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class Fusion {
 public:
  Fusion();

  void Init();

  void HandleAccel(const android::vec3_t& a, float dT);
  void HandleGyro(const android::vec3_t& w, float dT);

  android::mat33_t GetRotationMatrix() const;

  bool HasEstimate() const;

 private:
  bool CheckInitComplete(cros::mojom::DeviceType type,
                         const android::vec3_t& d,
                         float dT);
  void InitFusion(const android::vec4_t& q, float dT);
  void CheckState();

  void Update(const android::vec3_t& z, const android::vec3_t& Bi, float sigma);
  void Predict(const android::vec3_t& w, float dT);

  android::mat<android::mat33_t, 2, 2> Phi_;
  android::vec3_t Ba_, Bm_;
  std::set<cros::mojom::DeviceType> init_types_;
  float gyro_rate_;
  android::vec<android::vec3_t, 3> init_data_;
  size_t init_count_[3] = {0, 0, 0};

  /*
   * the state vector is made of two sub-vector containing respectively:
   * - modified Rodrigues parameters
   * - the estimated gyro bias
   */
  android::quat_t x0_;
  android::vec3_t x1_;

  /*
   * the predicated covariance matrix is made of 4 3x3 sub-matrices and
   * it is
   * semi-definite positive.
   *
   * P = | P00  P10 | = | P00  P10 |
   *     | P01  P11 |   | P10t P11 |
   *
   * Since P01 = transpose(P10), the code
   * below never calculates or
   * stores P01.
   */
  android::mat<android::mat33_t, 2, 2> P_;

  /*
   * the process noise covariance matrix
   */
  android::mat<android::mat33_t, 2, 2> GQGt_;
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_FUSION_H_
