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
 * Migrated from aosp/frameworks/native/services/sensorservice/Fusion.cpp
 */

#include "iioservice/daemon/fusion.h"

#include <math.h>

#include <base/notreached.h>

#include "iioservice/include/common.h"

namespace iioservice {

namespace {

/*
 * gyroVAR gives the measured variance of the gyro's output per
 * Hz (or variance at 1 Hz). This is an "intrinsic" parameter of the gyro,
 * which is independent of the sampling frequency.
 *
 * The variance of gyro's output at a given sampling period can be
 * calculated as:
 *      variance(T) = gyroVAR / T
 *
 * The variance of the INTEGRATED OUTPUT at a given sampling period can be
 * calculated as:
 *       variance_integrate_output(T) = gyroVAR * T
 *
 */
constexpr float gyroVAR = 1e-7;  // (rad/s)^2 / Hz
// TODO(gwendal): Check if we should use 1e-8 or 1e-12.
constexpr float biasVAR = 1e-12;  // (rad/s)^2 / s (guessed)

/*
 * Standard deviations of accelerometer and magnetometer
 */
constexpr float accSTDEV = 0.05f;  // m/s^2 (measured 0.08 / CDD 0.05)
constexpr float magSTDEV = 0.1f;   // uT (measured 0.7  / CDD 0.05)

constexpr float SYMMETRY_TOLERANCE = 1e-10f;

/*
 * Accelerometer updates will not be performed near free fall to avoid
 * ill-conditioning and div by zeros.
 * Threshold: 10% of g, in m/s^2
 */
constexpr float NOMINAL_GRAVITY = 9.81f;
constexpr float FREE_FALL_THRESHOLD = 0.1f * (NOMINAL_GRAVITY);

constexpr float SQRT_3 = 1.732f;
constexpr float WVEC_EPS = 1e-4f / SQRT_3;

template <typename TYPE, size_t C, size_t R>
static android::mat<TYPE, R, R> scaleCovariance(
    const android::mat<TYPE, C, R>& A, const android::mat<TYPE, C, C>& P) {
  // A*P*transpose(A);
  android::mat<TYPE, R, R> APAt;
  for (size_t r = 0; r < R; r++) {
    for (size_t j = r; j < R; j++) {
      double apat(0);
      for (size_t c = 0; c < C; c++) {
        double v(A[c][r] * P[c][c] * 0.5);
        for (size_t k = c + 1; k < C; k++)
          v += A[k][r] * P[c][k];
        apat += 2 * v * A[c][j];
      }
      APAt[j][r] = apat;
      APAt[r][j] = apat;
    }
  }
  return APAt;
}

template <typename TYPE, typename OTHER_TYPE>
static android::mat<TYPE, 3, 3> crossMatrix(const android::vec<TYPE, 3>& p,
                                            OTHER_TYPE diag) {
  android::mat<TYPE, 3, 3> r;
  r[0][0] = diag;
  r[1][1] = diag;
  r[2][2] = diag;
  r[0][1] = p.z;
  r[1][0] = -p.z;
  r[0][2] = -p.y;
  r[2][0] = p.y;
  r[1][2] = p.x;
  r[2][1] = -p.x;
  return r;
}

typedef android::mat<float, 3, 4> mat34_t;

mat34_t GetF(const android::vec4_t& q) {
  mat34_t F;

  // This is used to compute the derivative of q
  // F = | [q.xyz]x |
  //     |  -q.xyz  |

  F[0].x = q.w;
  F[1].x = -q.z;
  F[2].x = q.y;
  F[0].y = q.z;
  F[1].y = q.w;
  F[2].y = -q.x;
  F[0].z = -q.y;
  F[1].z = q.x;
  F[2].z = q.w;
  F[0].w = -q.x;
  F[1].w = -q.y;
  F[2].w = -q.z;
  return F;
}

android::vec3_t GetOrthogonal(const android::vec3_t& v) {
  android::vec3_t w;
  if (fabsf(v[0]) <= fabsf(v[1]) && fabsf(v[0]) <= fabsf(v[2])) {
    w[0] = 0.f;
    w[1] = v[2];
    w[2] = -v[1];
  } else if (fabsf(v[1]) <= fabsf(v[2])) {
    w[0] = v[2];
    w[1] = 0.f;
    w[2] = -v[0];
  } else {
    w[0] = v[1];
    w[1] = -v[0];
    w[2] = 0.f;
  }
  return normalize(w);
}

}  // namespace

Fusion::Fusion() {
  Phi_[0][1] = 0;
  Phi_[1][1] = 1;

  Ba_.x = 0;
  Ba_.y = 0;
  Ba_.z = 1;

  Bm_.x = 0;
  Bm_.y = 1;
  Bm_.z = 0;

  x0_ = 0;
  x1_ = 0;

  Init();
}

void Fusion::Init() {
  init_types_.clear();

  gyro_rate_ = 0;

  init_count_[0] = 0;
  init_count_[1] = 0;
  init_count_[2] = 0;

  init_data_ = 0;
}

void Fusion::HandleAccel(const android::vec3_t& a, float dT) {
  const float l = length(a);
  // Ignore accelerometer data if we're close to free-fall
  if (l < FREE_FALL_THRESHOLD)
    return;

  if (!CheckInitComplete(cros::mojom::DeviceType::ACCEL, a, dT))
    return;

  const float l_inv = 1.0f / l;

  android::vec3_t m;
  m = GetRotationMatrix() * Bm_;
  Update(m, Bm_, magSTDEV);

  android::vec3_t unityA = a * l_inv;
  const float d = sqrtf(fabsf(l - NOMINAL_GRAVITY));
  const float p = l_inv * accSTDEV * expf(d);
  Update(unityA, Ba_, p);
}

void Fusion::HandleGyro(const android::vec3_t& w, float dT) {
  if (!CheckInitComplete(cros::mojom::DeviceType::ANGLVEL, w, dT))
    return;

  Predict(w, dT);
}

android::mat33_t Fusion::GetRotationMatrix() const {
  return quatToMatrix(x0_);
}

bool Fusion::HasEstimate() const {
  return init_types_.find(cros::mojom::DeviceType::ACCEL) !=
             init_types_.end() &&
         init_types_.find(cros::mojom::DeviceType::ANGLVEL) !=
             init_types_.end();
}

bool Fusion::CheckInitComplete(cros::mojom::DeviceType type,
                               const android::vec3_t& d,
                               float dT) {
  if (HasEstimate())
    return true;

  switch (type) {
    case cros::mojom::DeviceType::ACCEL:
      init_data_[0] += d * (1 / length(d));
      init_count_[0]++;
      init_types_.emplace(type);
      break;

    case cros::mojom::DeviceType::ANGLVEL:
      gyro_rate_ = dT;
      init_data_[2] += d * dT;
      init_count_[2]++;
      // TODO(gwendal): Check if we should collect at least 64 samples.
      init_types_.emplace(type);
      break;

    default:
      NOTREACHED() << "Invalid type: " << type;
      break;
  }

  if (HasEstimate()) {
    // Average all the values we collected so far
    init_data_[0] *= 1.0f / init_count_[0];
    init_data_[2] *= 1.0f / init_count_[2];

    // calculate the MRPs from the data collection, this gives us
    // a rough estimate of our initial state
    android::mat33_t R;
    android::vec3_t up(init_data_[0]);
    android::vec3_t east = GetOrthogonal(up);
    android::vec3_t north(cross_product(up, east));
    R << east << north << up;
    const android::vec4_t q = matrixToQuat(R);
    InitFusion(q, gyro_rate_);
  }

  return false;
}

void Fusion::InitFusion(const android::vec4_t& q, float dT) {
  // initial estimate: E{ x(t0)  }
  x0_ = q;
  x1_ = 0;

  // process noise covariance matrix: G.Q.Gt, with
  //
  //  G = | -1 0 |        Q = | q00 q10 |
  //      |  0 1 |            | q01 q11 |
  //
  // q00 = sv^2.dt + 1/3.su^2.dt^3
  // q10 = q01 = 1/2.su^2.dt^2
  // q11 = su^2.dt
  //

  const float dT2 = dT * dT;
  const float dT3 = dT2 * dT;

  // variance of integrated output at 1/dT Hz (random drift)
  const float q00 = gyroVAR * dT + 0.33333f * biasVAR * dT3;
  // variance of drift rate ramp
  const float q11 = biasVAR * dT;
  const float q10 = 0.5f * biasVAR * dT2;
  const float q01 = q10;
  GQGt_[0][0] = q00;  // rad^2
  GQGt_[1][0] = -q10;
  GQGt_[0][1] = -q01;
  GQGt_[1][1] = q11;  // (rad/s)^2

  // initial covariance: Var{ x(t0)  }
  // TODO(chenghaoyang): initialize P correctly
  P_ = 0;
}

void Fusion::CheckState() {
  // P_ needs to stay positive semidefinite or the fusion diverges. When we
  // detect divergence, we reset the fusion.
  // TODO(braun): Instead, find the reason for the divergence and fix it.
  if (!isPositiveSemidefinite(P_[0][0], SYMMETRY_TOLERANCE) ||
      !isPositiveSemidefinite(P_[1][1], SYMMETRY_TOLERANCE)) {
    LOGF(WARNING) << "Sensor fusion diverged; resetting state.";
    P_ = 0;
  }
}

void Fusion::Update(const android::vec3_t& z,
                    const android::vec3_t& Bi,
                    float sigma) {
  android::vec4_t q(x0_);
  // measured vector in body space: h(p) = A(p)*Bi
  const android::mat33_t A(quatToMatrix(q));
  const android::vec3_t Bb(A * Bi);

  // Sensitivity matrix H = dh(p)/dp
  // H = [ L 0 ]
  const android::mat33_t L(crossMatrix(Bb, 0));

  // gain...
  // K = P_*Ht / [H*P_*Ht + R]
  android::vec<android::mat33_t, 2> K;
  const android::mat33_t R(sigma * sigma);
  const android::mat33_t S(scaleCovariance(L, P_[0][0]) + R);
  const android::mat33_t Si(invert(S));
  const android::mat33_t LtSi(transpose(L) * Si);
  K[0] = P_[0][0] * LtSi;
  K[1] = transpose(P_[1][0]) * LtSi;

  // update...
  // P_ = (I-K*H) * P_
  // P_ -= K*H*P_
  // | K0 | * | L 0 | * P_ = | K0*L  0 | * | P_00  P_10 | = | K0*L*P_00
  // K0*L*P_10 | | K1 |                 | K1*L  0 |   | P_01  P_11 |   |
  // K1*L*P_00  K1*L*P_10 | Note: the Joseph form is numerically more stable and
  // given by:
  //     P_ = (I-KH) * P_ * (I-KH)' + K*R*R'
  const android::mat33_t K0L(K[0] * L);
  const android::mat33_t K1L(K[1] * L);
  P_[0][0] -= K0L * P_[0][0];
  P_[1][1] -= K1L * P_[1][0];
  P_[1][0] -= K0L * P_[1][0];
  P_[0][1] = transpose(P_[1][0]);

  const android::vec3_t e(z - Bb);
  const android::vec3_t dq(K[0] * e);

  q += GetF(q) * (0.5f * dq);
  x0_ = normalize_quat(q);

  CheckState();
}

void Fusion::Predict(const android::vec3_t& w, float dT) {
  const android::vec4_t q = x0_;
  const android::vec3_t b = x1_;
  android::vec3_t we = w - b;

  if (length(we) < WVEC_EPS)
    we = (we[0] > 0.f) ? WVEC_EPS : -WVEC_EPS;

  // q(k+1) = O(we)*q(k)
  // --------------------
  //
  // O(w) = | cos(0.5*||w||*dT)*I33 - [psi]x                   psi |
  //        | -psi'                              cos(0.5*||w||*dT) |
  //
  // psi = sin(0.5*||w||*dT)*w / ||w||
  //
  //
  // P(k+1) = Phi(k)*P(k)*Phi(k)' + G*Q(k)*G'
  // ----------------------------------------
  //
  // G = | -I33    0 |
  //     |    0  I33 |
  //
  //  Phi = | Phi00 Phi10 |
  //        |   0     1   |
  //
  //  Phi00 =   I33
  //          - [w]x   * sin(||w||*dt)/||w||
  //          + [w]x^2 * (1-cos(||w||*dT))/||w||^2
  //
  //  Phi10 =   [w]x   * (1        - cos(||w||*dt))/||w||^2
  //          - [w]x^2 * (||w||*dT - sin(||w||*dt))/||w||^3
  //          - I33*dT

  const android::mat33_t I33(1);
  const android::mat33_t I33dT(dT);
  const android::mat33_t wx(crossMatrix(we, 0));
  const android::mat33_t wx2(wx * wx);
  const float lwedT = length(we) * dT;
  const float hlwedT = 0.5f * lwedT;
  const float ilwe = 1.f / length(we);
  const float k0 = (1 - cosf(lwedT)) * (ilwe * ilwe);
  const float k1 = sinf(lwedT);
  const float k2 = cosf(hlwedT);
  const android::vec3_t psi(sinf(hlwedT) * ilwe * we);
  const android::mat33_t O33(crossMatrix(-psi, k2));
  android::mat44_t O;
  O[0].xyz = O33[0];
  O[0].w = -psi.x;
  O[1].xyz = O33[1];
  O[1].w = -psi.y;
  O[2].xyz = O33[2];
  O[2].w = -psi.z;
  O[3].xyz = psi;
  O[3].w = k2;

  Phi_[0][0] = I33 - wx * (k1 * ilwe) + wx2 * k0;
  Phi_[1][0] = wx * k0 - I33dT - wx2 * (ilwe * ilwe * ilwe) * (lwedT - k1);

  x0_ = O * q;

  if (x0_.w < 0)
    x0_ = -x0_;

  P_ = Phi_ * P_ * transpose(Phi_) + GQGt_;

  CheckState();
}

}  // namespace iioservice
