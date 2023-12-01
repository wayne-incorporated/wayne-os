// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/chaps.h"
#include "chaps/session_impl.h"

#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/chaps/mock_frontend.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <metrics/metrics_library_mock.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "chaps/chaps_factory_impl.h"
#include "chaps/chaps_factory_mock.h"
#include "chaps/chaps_utility.h"
#include "chaps/handle_generator_mock.h"
#include "chaps/object_impl.h"
#include "chaps/object_mock.h"
#include "chaps/object_pool_mock.h"
#include "libhwsec/frontend/chaps/frontend.h"

using ::hwsec::TPMError;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnOk;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;
using ::hwsec_foundation::status::StatusChain;
using ::std::string;
using ::std::vector;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using Result = chaps::ObjectPool::Result;
using TPMRetryAction = ::hwsec::TPMRetryAction;

namespace {

hwsec::ECCPublicInfo GenerateECCPublicInfo() {
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  CHECK(ec_256.has_value());

  crypto::ScopedEC_KEY key = ec_256->GenerateKey(context.get());

  crypto::ScopedBIGNUM x(BN_new()), y(BN_new());
  CHECK_NE(x, nullptr);
  CHECK_NE(y, nullptr);

  const EC_POINT* ec_point = EC_KEY_get0_public_key(key.get());
  CHECK_NE(ec_point, nullptr);
  CHECK(EC_POINT_get_affine_coordinates_GFp(ec_256->GetGroup(), ec_point,
                                            x.get(), y.get(), nullptr));

  brillo::Blob x_point =
      brillo::BlobFromString(chaps::ConvertFromBIGNUM(x.get()));
  brillo::Blob y_point =
      brillo::BlobFromString(chaps::ConvertFromBIGNUM(y.get()));
  return hwsec::ECCPublicInfo{
      .nid = NID_X9_62_prime256v1,
      .x_point = x_point,
      .y_point = y_point,
  };
}

void ConfigureObjectPool(chaps::ObjectPoolMock* op, int handle_base) {
  op->SetupFake(handle_base);
  EXPECT_CALL(*op, Insert(_)).Times(AnyNumber());
  EXPECT_CALL(*op, Find(_, _)).Times(AnyNumber());
  EXPECT_CALL(*op, FindByHandle(_, _)).Times(AnyNumber());
  EXPECT_CALL(*op, Delete(_)).Times(AnyNumber());
  EXPECT_CALL(*op, Flush(_)).WillRepeatedly(Return(Result::Success));
}

chaps::ObjectPool* CreateObjectPoolMock() {
  chaps::ObjectPoolMock* op = new chaps::ObjectPoolMock();
  ConfigureObjectPool(op, 100);
  return op;
}

chaps::Object* CreateObjectMock() {
  chaps::ObjectMock* o = new chaps::ObjectMock();
  o->SetupFake();
  EXPECT_CALL(*o, GetObjectClass()).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributes(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, FinalizeNewObject()).WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(*o, Copy(_)).WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(*o, IsTokenObject()).Times(AnyNumber());
  EXPECT_CALL(*o, IsAttributePresent(_)).Times(AnyNumber());
  EXPECT_CALL(*o, GetAttributeString(_)).Times(AnyNumber());
  EXPECT_CALL(*o, GetAttributeInt(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, GetAttributeBool(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributeString(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributeInt(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributeBool(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, set_handle(_)).Times(AnyNumber());
  EXPECT_CALL(*o, set_store_id(_)).Times(AnyNumber());
  EXPECT_CALL(*o, handle()).Times(AnyNumber());
  EXPECT_CALL(*o, store_id()).Times(AnyNumber());
  EXPECT_CALL(*o, RemoveAttribute(_)).Times(AnyNumber());
  return o;
}

void ConfigureHwsec(hwsec::MockChapsFrontend* hwsec) {
  EXPECT_CALL(*hwsec, GetRandomBlob(_)).WillRepeatedly([](size_t size) {
    return brillo::Blob(size);
  });
  EXPECT_CALL(*hwsec, GetRandomSecureBlob(_)).WillRepeatedly([](size_t size) {
    return brillo::SecureBlob(size);
  });
}

string bn2bin(const BIGNUM* bn) {
  string bin;
  bin.resize(BN_num_bytes(bn));
  bin.resize(BN_bn2bin(bn, chaps::ConvertStringToByteBuffer(bin.data())));
  return bin;
}

std::string GetRSAPSSParam(CK_MECHANISM_TYPE hashAlg,
                           CK_RSA_PKCS_MGF_TYPE mgf,
                           CK_ULONG sLen) {
  CK_RSA_PKCS_PSS_PARAMS params;
  params.hashAlg = hashAlg;
  params.mgf = mgf;
  params.sLen = sLen;
  std::string param_bytes(reinterpret_cast<char*>(&params), sizeof(params));
  return param_bytes;
}

}  // namespace

namespace chaps {

const char kChapsSessionDecrypt[] = "Platform.Chaps.Session.Decrypt";
const char kChapsSessionDigest[] = "Platform.Chaps.Session.Digest";
const char kChapsSessionEncrypt[] = "Platform.Chaps.Session.Encrypt";
const char kChapsSessionSign[] = "Platform.Chaps.Session.Sign";
const char kChapsSessionVerify[] = "Platform.Chaps.Session.Verify";

// Test fixture for an initialized SessionImpl instance.
class TestSession : public ::testing::Test {
 public:
  TestSession() {
    EXPECT_CALL(factory_, CreateObject())
        .WillRepeatedly(InvokeWithoutArgs(CreateObjectMock));
    EXPECT_CALL(factory_, CreateObjectPool(_, _, _))
        .WillRepeatedly(InvokeWithoutArgs(CreateObjectPoolMock));
    EXPECT_CALL(handle_generator_, CreateHandle()).WillRepeatedly(Return(1));
    ConfigureObjectPool(&token_pool_, 0);
    ConfigureHwsec(&hwsec_);
  }
  void SetUp() {
    chaps_metrics_.set_metrics_library_for_testing(&mock_metrics_library_);
    session_.reset(new SessionImpl(1, &token_pool_, &hwsec_, &factory_,
                                   &handle_generator_, false, &chaps_metrics_));
  }
  void GenerateSecretKey(CK_MECHANISM_TYPE mechanism,
                         CK_ULONG size,
                         const Object** obj) {
    CK_BBOOL no = CK_FALSE;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE encdec_template[] = {{CKA_TOKEN, &no, sizeof(no)},
                                      {CKA_ENCRYPT, &yes, sizeof(yes)},
                                      {CKA_DECRYPT, &yes, sizeof(yes)},
                                      {CKA_VALUE_LEN, &size, sizeof(size)}};
    CK_ATTRIBUTE signverify_template[] = {{CKA_TOKEN, &no, sizeof(no)},
                                          {CKA_SIGN, &yes, sizeof(yes)},
                                          {CKA_VERIFY, &yes, sizeof(yes)},
                                          {CKA_VALUE_LEN, &size, sizeof(size)}};
    CK_ATTRIBUTE_PTR attr = encdec_template;
    if (mechanism == CKM_GENERIC_SECRET_KEY_GEN)
      attr = signverify_template;
    int handle = 0;
    ASSERT_EQ(CKR_OK, session_->GenerateKey(mechanism, "", attr, 4, &handle));
    ASSERT_TRUE(session_->GetObject(handle, obj));
  }
  void GenerateRSAKeyPair(bool signing,
                          CK_ULONG size,
                          const Object** pub,
                          const Object** priv) {
    CK_BBOOL no = CK_FALSE;
    CK_BBOOL yes = CK_TRUE;
    CK_BYTE pubexp[] = {1, 0, 1};
    CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &no, sizeof(no)},
                               {CKA_ENCRYPT, signing ? &no : &yes, sizeof(no)},
                               {CKA_VERIFY, signing ? &yes : &no, sizeof(no)},
                               {CKA_PUBLIC_EXPONENT, pubexp, 3},
                               {CKA_MODULUS_BITS, &size, sizeof(size)}};
    CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &no, sizeof(CK_BBOOL)},
                                {CKA_DECRYPT, signing ? &no : &yes, sizeof(no)},
                                {CKA_SIGN, signing ? &yes : &no, sizeof(no)}};
    int pubh = 0, privh = 0;
    ASSERT_EQ(CKR_OK,
              session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                        std::size(pub_attr), priv_attr,
                                        std::size(priv_attr), &pubh, &privh));
    ASSERT_TRUE(session_->GetObject(pubh, pub));
    ASSERT_TRUE(session_->GetObject(privh, priv));
  }

  string GetDERforNID(int openssl_nid) {
    // OBJ_nid2obj returns a pointer to an internal table and does not allocate
    // memory. No need to free.
    ASN1_OBJECT* obj = OBJ_nid2obj(NID_X9_62_prime256v1);
    int expected_size = i2d_ASN1_OBJECT(obj, nullptr);
    string output(expected_size, '\0');
    unsigned char* buf = ConvertStringToByteBuffer(output.data());
    int output_size = i2d_ASN1_OBJECT(obj, &buf);
    CHECK_EQ(output_size, expected_size);
    return output;
  }

  void GenerateECCKeyPair(bool use_token_object_for_pub,
                          bool use_token_object_for_priv,
                          const Object** pub,
                          const Object** priv) {
    // Create DER encoded OID of P-256 for CKA_EC_PARAMS (prime256v1 or
    // secp256r1)
    string ec_params = GetDERforNID(NID_X9_62_prime256v1);

    CK_BBOOL no = CK_FALSE;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE pub_attr[] = {
        {CKA_TOKEN, use_token_object_for_pub ? &yes : &no, sizeof(CK_BBOOL)},
        {CKA_ENCRYPT, &no, sizeof(CK_BBOOL)},
        {CKA_VERIFY, &yes, sizeof(CK_BBOOL)},
        {CKA_EC_PARAMS, ConvertStringToByteBuffer(ec_params.data()),
         ec_params.size()}};
    CK_ATTRIBUTE priv_attr[] = {
        {CKA_TOKEN, use_token_object_for_priv ? &yes : &no, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &no, sizeof(CK_BBOOL)},
        {CKA_SIGN, &yes, sizeof(CK_BBOOL)}};
    int pubh = 0, privh = 0;
    ASSERT_EQ(CKR_OK,
              session_->GenerateKeyPair(CKM_EC_KEY_PAIR_GEN, "", pub_attr,
                                        std::size(pub_attr), priv_attr,
                                        std::size(priv_attr), &pubh, &privh));
    ASSERT_TRUE(session_->GetObject(pubh, pub));
    ASSERT_TRUE(session_->GetObject(privh, priv));
  }

  int CreateObject() {
    CK_OBJECT_CLASS c = CKO_DATA;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE attr[] = {{CKA_CLASS, &c, sizeof(c)},
                           {CKA_TOKEN, &no, sizeof(no)}};
    int h;
    session_->CreateObject(attr, 2, &h);
    return h;
  }

  void TestSignVerify(const Object* pub,
                      const Object* priv,
                      size_t input_size,
                      CK_MECHANISM_TYPE mech,
                      const string& mechanism_parameter) {
    string in(input_size, 'A');
    int len = 0;
    string sig;

    // Sign / verify with OperationSinglePart().
    EXPECT_EQ(CKR_OK,
              session_->OperationInit(kSign, mech, mechanism_parameter, priv));
    EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
              session_->OperationSinglePart(kSign, in, &len, &sig));
    EXPECT_EQ(CKR_OK, session_->OperationSinglePart(kSign, in, &len, &sig));
    EXPECT_EQ(CKR_OK,
              session_->OperationInit(kVerify, mech, mechanism_parameter, pub));
    EXPECT_EQ(CKR_OK, session_->OperationUpdate(kVerify, in, nullptr, nullptr));
    EXPECT_EQ(CKR_OK, session_->VerifyFinal(sig));

    // Same stuff with OperationUpdate().
    in = string(input_size, 'B');
    string sig2;
    len = 0;
    size_t first_divide = input_size / 2;
    size_t second_divide = input_size / 5 * 2;
    EXPECT_EQ(CKR_OK,
              session_->OperationInit(kSign, mech, mechanism_parameter, priv));
    EXPECT_EQ(CKR_OK, session_->OperationUpdate(
                          kSign, in.substr(0, first_divide), nullptr, nullptr));
    EXPECT_EQ(CKR_OK,
              session_->OperationUpdate(
                  kSign, in.substr(first_divide, input_size - first_divide),
                  nullptr, nullptr));
    EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
              session_->OperationFinal(kSign, &len, &sig2));
    EXPECT_EQ(CKR_OK, session_->OperationFinal(kSign, &len, &sig2));

    // Test verification with OperationUpdate().
    EXPECT_EQ(CKR_OK,
              session_->OperationInit(kVerify, mech, mechanism_parameter, pub));
    EXPECT_EQ(CKR_OK,
              session_->OperationUpdate(kVerify, in.substr(0, second_divide),
                                        nullptr, nullptr));
    EXPECT_EQ(CKR_OK,
              session_->OperationUpdate(
                  kVerify, in.substr(second_divide, input_size - second_divide),
                  nullptr, nullptr));
    EXPECT_EQ(CKR_OK, session_->VerifyFinal(sig2));
  }

  hwsec::ScopedKey GetTestScopedKey() {
    return hwsec::ScopedKey(hwsec::Key{.token = 42},
                            hwsec_.GetFakeMiddlewareDerivative());
  }

 protected:
  ObjectPoolMock token_pool_;
  ChapsFactoryMock factory_;
  StrictMock<hwsec::MockChapsFrontend> hwsec_;
  HandleGeneratorMock handle_generator_;
  std::unique_ptr<SessionImpl> session_;
  StrictMock<MetricsLibraryMock> mock_metrics_library_;
  ChapsMetrics chaps_metrics_;
};

// Session Test that uses real Object implementation (ObjectImpl)
class TestSessionWithRealObject : public TestSession {
 public:
  TestSessionWithRealObject() {
    chaps::ChapsFactory* factory = &factory_;
    EXPECT_CALL(factory_, CreateObject())
        .WillRepeatedly(InvokeWithoutArgs(
            [factory] { return new chaps::ObjectImpl(factory); }));
    EXPECT_CALL(factory_, CreateObjectPool(_, _, _))
        .WillRepeatedly(InvokeWithoutArgs(CreateObjectPoolMock));
    EXPECT_CALL(factory_, CreateObjectPolicy(_))
        .WillRepeatedly(Invoke(ChapsFactoryImpl::GetObjectPolicyForType));
    EXPECT_CALL(handle_generator_, CreateHandle()).WillRepeatedly(Return(1));
    ConfigureObjectPool(&token_pool_, 0);
    ConfigureHwsec(&hwsec_);
  }
};

typedef TestSession TestSession_DeathTest;

// Test that SessionImpl asserts as expected when not properly initialized.
TEST(DeathTest, InvalidInit) {
  ObjectPoolMock pool;
  ChapsFactoryMock factory;
  hwsec::MockChapsFrontend hwsec;
  HandleGeneratorMock handle_generator;
  SessionImpl* session;
  ChapsMetrics chaps_metrics;
  EXPECT_CALL(factory, CreateObjectPool(_, _, _)).Times(AnyNumber());
  EXPECT_DEATH_IF_SUPPORTED(
      session = new SessionImpl(1, nullptr, &hwsec, &factory, &handle_generator,
                                false, &chaps_metrics),
      "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      session = new SessionImpl(1, &pool, &hwsec, nullptr, &handle_generator,
                                false, &chaps_metrics),
      "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      session = new SessionImpl(1, &pool, &hwsec, &factory, nullptr, false,
                                &chaps_metrics),
      "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      session = new SessionImpl(1, &pool, &hwsec, &factory, &handle_generator,
                                false, nullptr),
      "Check failed");
  (void)session;
}

// Test that SessionImpl asserts as expected when passed invalid arguments.
TEST_F(TestSession_DeathTest, InvalidArgs) {
  OperationType invalid_op = kNumOperationTypes;
  EXPECT_DEATH_IF_SUPPORTED(session_->IsOperationActive(invalid_op),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->CreateObject(nullptr, 0, nullptr),
                            "Check failed");
  int i;
  EXPECT_DEATH_IF_SUPPORTED(session_->CreateObject(nullptr, 1, &i),
                            "Check failed");
  i = CreateObject();
  EXPECT_DEATH_IF_SUPPORTED(session_->CopyObject(nullptr, 0, i, nullptr),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->CopyObject(nullptr, 1, i, &i),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->FindObjects(invalid_op, nullptr),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->GetObject(1, nullptr), "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->OperationInit(invalid_op, 0, "", nullptr),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      session_->OperationInit(kEncrypt, CKM_AES_CBC, "", nullptr),
      "Check failed");
  string s;
  const Object* o;
  GenerateSecretKey(CKM_AES_KEY_GEN, 32, &o);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt, static_cast<int>(CKR_OK)))
      .WillOnce(Return(true));
  ASSERT_EQ(CKR_OK, session_->OperationInit(kEncrypt, CKM_AES_ECB, "", o));
  EXPECT_DEATH_IF_SUPPORTED(session_->OperationUpdate(invalid_op, "", &i, &s),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      session_->OperationUpdate(kEncrypt, "", nullptr, &s), "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      session_->OperationUpdate(kEncrypt, "", &i, nullptr), "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->OperationFinal(invalid_op, &i, &s),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->OperationFinal(kEncrypt, nullptr, &s),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->OperationFinal(kEncrypt, &i, nullptr),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      session_->OperationSinglePart(invalid_op, "", &i, &s), "Check failed");
}

// Test that SessionImpl asserts when out-of-memory during initialization.
TEST(DeathTest, OutOfMemoryInit) {
  ObjectPoolMock pool;
  hwsec::MockChapsFrontend hwsec;
  ChapsFactoryMock factory;
  HandleGeneratorMock handle_generator;
  ObjectPool* null_pool = nullptr;
  ChapsMetrics chaps_metrics;
  EXPECT_CALL(factory, CreateObjectPool(_, _, _))
      .WillRepeatedly(Return(null_pool));
  Session* session;
  EXPECT_DEATH_IF_SUPPORTED(
      session = new SessionImpl(1, &pool, &hwsec, &factory, &handle_generator,
                                false, &chaps_metrics),
      "Check failed");
  (void)session;
}

// Test that SessionImpl asserts when out-of-memory during object creation.
TEST_F(TestSession_DeathTest, OutOfMemoryObject) {
  Object* null_object = nullptr;
  EXPECT_CALL(factory_, CreateObject()).WillRepeatedly(Return(null_object));
  int tmp;
  EXPECT_DEATH_IF_SUPPORTED(session_->CreateObject(nullptr, 0, &tmp),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(session_->FindObjectsInit(nullptr, 0),
                            "Check failed");
}

// Test that default session properties are correctly reported.
TEST_F(TestSession, DefaultSetup) {
  EXPECT_EQ(1, session_->GetSlot());
  EXPECT_FALSE(session_->IsReadOnly());
  EXPECT_FALSE(session_->IsOperationActive(kEncrypt));
}

// Test object management: create / copy / find / destroy.
TEST_F(TestSession, Objects) {
  EXPECT_CALL(token_pool_, Insert(_)).Times(2);
  EXPECT_CALL(token_pool_, Find(_, _)).Times(1);
  EXPECT_CALL(token_pool_, Delete(_)).Times(1);
  CK_OBJECT_CLASS oc = CKO_SECRET_KEY;
  CK_ATTRIBUTE attr[] = {{CKA_CLASS, &oc, sizeof(oc)}};
  int handle = 0;
  int invalid_handle = -1;
  // Create a new object.
  ASSERT_EQ(CKR_OK, session_->CreateObject(attr, std::size(attr), &handle));
  EXPECT_GT(handle, 0);
  const Object* o;
  // Get the new object from the new handle.
  EXPECT_TRUE(session_->GetObject(handle, &o));
  int handle2 = 0;
  // Copy an object (try invalid and valid handles).
  EXPECT_EQ(
      CKR_OBJECT_HANDLE_INVALID,
      session_->CopyObject(attr, std::size(attr), invalid_handle, &handle2));
  ASSERT_EQ(CKR_OK,
            session_->CopyObject(attr, std::size(attr), handle, &handle2));
  // Ensure handles are unique.
  EXPECT_TRUE(handle != handle2);
  EXPECT_TRUE(session_->GetObject(handle2, &o));
  EXPECT_FALSE(session_->GetObject(invalid_handle, &o));
  vector<int> v;
  // Find objects with calls out-of-order.
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED, session_->FindObjects(1, &v));
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED, session_->FindObjectsFinal());
  // Find the objects we've created (there should be 2).
  EXPECT_EQ(CKR_OK, session_->FindObjectsInit(attr, std::size(attr)));
  EXPECT_EQ(CKR_OPERATION_ACTIVE,
            session_->FindObjectsInit(attr, std::size(attr)));
  // Test multi-step finds by only allowing 1 result at a time.
  EXPECT_EQ(CKR_OK, session_->FindObjects(1, &v));
  EXPECT_EQ(1, v.size());
  EXPECT_EQ(CKR_OK, session_->FindObjects(1, &v));
  EXPECT_EQ(2, v.size());
  // We have them all but we'll query again to make sure it behaves properly.
  EXPECT_EQ(CKR_OK, session_->FindObjects(1, &v));
  ASSERT_EQ(2, v.size());
  // Check that the handles found are the same ones we know about.
  EXPECT_TRUE(v[0] == handle || v[1] == handle);
  EXPECT_TRUE(v[0] == handle2 || v[1] == handle2);
  EXPECT_EQ(CKR_OK, session_->FindObjectsFinal());
  // Destroy an object (try invalid and valid handles).
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID, session_->DestroyObject(invalid_handle));
  EXPECT_EQ(CKR_OK, session_->DestroyObject(handle));
  // Once destroyed, we should not be able to use the handle.
  EXPECT_FALSE(session_->GetObject(handle, &o));
}

// Test multi-part and single-part cipher operations.
TEST_F(TestSession, Cipher) {
  const Object* key_object = nullptr;
  GenerateSecretKey(CKM_AES_KEY_GEN, 32, &key_object);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt, static_cast<int>(CKR_OK)))
      .Times(3);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kEncrypt, CKM_AES_CBC_PAD,
                                            string(16, 'A'), key_object));
  string in(22, 'B');
  string out, tmp;
  int maxlen = 0;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .Times(2);
  // Check buffer-too-small semantics (and for each call following).
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationUpdate(kEncrypt, in, &maxlen, &tmp));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kEncrypt, in, &maxlen, &tmp));
  out += tmp;
  // The first block is ready, check that we've received it.
  EXPECT_EQ(16, out.length());
  maxlen = 0;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationFinal(kEncrypt, &maxlen, &tmp));
  EXPECT_EQ(CKR_OK, session_->OperationFinal(kEncrypt, &maxlen, &tmp));
  out += tmp;
  // Check that we've received the final block.
  EXPECT_EQ(32, out.length());
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDecrypt, static_cast<int>(CKR_OK)))
      .Times(2);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDecrypt, CKM_AES_CBC_PAD,
                                            string(16, 'A'), key_object));
  string in2;
  maxlen = 0;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDecrypt,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationSinglePart(kDecrypt, out, &maxlen, &in2));
  EXPECT_EQ(CKR_OK,
            session_->OperationSinglePart(kDecrypt, out, &maxlen, &in2));
  EXPECT_EQ(22, in2.length());
  // Check that what has been decrypted matches our original plain-text.
  EXPECT_TRUE(in == in2);
}

// Test multi-part and single-part digest operations.
TEST_F(TestSession, Digest) {
  string in(30, 'A');
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest, static_cast<int>(CKR_OK)))
      .Times(7);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDigest, CKM_SHA_1, "", nullptr));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kDigest, in.substr(0, 10),
                                              nullptr, nullptr));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kDigest, in.substr(10, 10),
                                              nullptr, nullptr));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kDigest, in.substr(20, 10),
                                              nullptr, nullptr));
  int len = 0;
  string out;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .Times(2);
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationFinal(kDigest, &len, &out));
  EXPECT_EQ(20, len);
  EXPECT_EQ(CKR_OK, session_->OperationFinal(kDigest, &len, &out));
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDigest, CKM_SHA_1, "", nullptr));
  string out2;
  len = 0;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationSinglePart(kDigest, in, &len, &out2));
  EXPECT_EQ(CKR_OK, session_->OperationSinglePart(kDigest, in, &len, &out2));
  EXPECT_EQ(20, len);
  // Check that both operations computed the same digest.
  EXPECT_TRUE(out == out2);
}

// Test HMAC sign and verify operations.
TEST_F(TestSession, HMAC) {
  const Object* key_object = nullptr;
  GenerateSecretKey(CKM_GENERIC_SECRET_KEY_GEN, 32, &key_object);
  string in(30, 'A');
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign, static_cast<int>(CKR_OK)))
      .Times(5);
  EXPECT_EQ(CKR_OK,
            session_->OperationInit(kSign, CKM_SHA256_HMAC, "", key_object));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kSign, in.substr(0, 10), nullptr,
                                              nullptr));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kSign, in.substr(10, 10), nullptr,
                                              nullptr));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kSign, in.substr(20, 10), nullptr,
                                              nullptr));
  int len = 0;
  string out;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL, session_->OperationFinal(kSign, &len, &out));
  EXPECT_EQ(CKR_OK, session_->OperationFinal(kSign, &len, &out));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionVerify, static_cast<int>(CKR_OK)))
      .Times(3);
  EXPECT_EQ(CKR_OK,
            session_->OperationInit(kVerify, CKM_SHA256_HMAC, "", key_object));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kVerify, in, nullptr, nullptr));
  // A successful verify implies both operations computed the same MAC.
  EXPECT_EQ(CKR_OK, session_->VerifyFinal(out));
}

// Test empty multi-part operation.
TEST_F(TestSession, FinalWithNoUpdate) {
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest, static_cast<int>(CKR_OK)))
      .Times(2);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDigest, CKM_SHA_1, "", nullptr));
  int len = 20;
  string out;
  EXPECT_EQ(CKR_OK, session_->OperationFinal(kDigest, &len, &out));
  EXPECT_EQ(20, len);
}

// Test multi-part and single-part operations inhibit each other.
TEST_F(TestSession, UpdateOperationPreventsSinglePart) {
  string in(30, 'A');
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest, static_cast<int>(CKR_OK)))
      .Times(2);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDigest, CKM_SHA_1, "", nullptr));
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kDigest, in.substr(0, 10),
                                              nullptr, nullptr));
  int len = 0;
  string out;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_OPERATION_ACTIVE)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_OPERATION_ACTIVE, session_->OperationSinglePart(
                                      kDigest, in.substr(10, 20), &len, &out));

  // The error also terminates the operation.
  len = 0;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_OPERATION_NOT_INITIALIZED)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
            session_->OperationFinal(kDigest, &len, &out));
}

TEST_F(TestSession, SinglePartOperationPreventsUpdate) {
  string in(30, 'A');
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest, static_cast<int>(CKR_OK)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDigest, CKM_SHA_1, "", nullptr));
  string out;
  int len = 0;
  // Perform a single part operation but leave the output to be collected.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationSinglePart(kDigest, in, &len, &out));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_OPERATION_ACTIVE)))
      .WillOnce(Return(true));
  EXPECT_EQ(
      CKR_OPERATION_ACTIVE,
      session_->OperationUpdate(kDigest, in.substr(10, 10), nullptr, nullptr));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_OPERATION_NOT_INITIALIZED)))
      .WillOnce(Return(true));
  // The error also terminates the operation.
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
            session_->OperationSinglePart(kDigest, in, &len, &out));
}

TEST_F(TestSession, SinglePartOperationPreventsFinal) {
  string in(30, 'A');
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest, static_cast<int>(CKR_OK)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDigest, CKM_SHA_1, "", nullptr));
  string out;
  int len = 0;
  // Perform a single part operation but leave the output to be collected.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationSinglePart(kDigest, in, &len, &out));

  len = 0;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_OPERATION_ACTIVE)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_OPERATION_ACTIVE,
            session_->OperationFinal(kDigest, &len, &out));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_OPERATION_NOT_INITIALIZED)))
      .WillOnce(Return(true));
  // The error also terminates the operation.
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
            session_->OperationSinglePart(kDigest, in, &len, &out));
}

// Test RSA PKCS #1 encryption.
TEST_F(TestSession, RSAEncrypt) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateRSAKeyPair(false, 1024, &pub, &priv);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt, static_cast<int>(CKR_OK)))
      .Times(2);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kEncrypt, CKM_RSA_PKCS, "", pub));
  string in(100, 'A');
  int len = 0;
  string out;
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationSinglePart(kEncrypt, in, &len, &out));
  EXPECT_EQ(CKR_OK, session_->OperationSinglePart(kEncrypt, in, &len, &out));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDecrypt, static_cast<int>(CKR_OK)))
      .Times(3);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kDecrypt, CKM_RSA_PKCS, "", priv));
  len = 0;
  string in2 = out;
  string out2;
  EXPECT_EQ(CKR_OK, session_->OperationUpdate(kDecrypt, in2, &len, &out2));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDecrypt,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            session_->OperationFinal(kDecrypt, &len, &out2));
  EXPECT_EQ(CKR_OK, session_->OperationFinal(kDecrypt, &len, &out2));
  EXPECT_EQ(in.length(), out2.length());
  // Check that what has been decrypted matches our original plain-text.
  EXPECT_TRUE(in == out2);
}

// Test RSA PKCS #1 sign / verify.
TEST_F(TestSession, RsaSign) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateRSAKeyPair(true, 1024, &pub, &priv);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .Times(4);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign, static_cast<int>(CKR_OK)))
      .Times(12);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionVerify, static_cast<int>(CKR_OK)))
      .Times(14);
  // Test the generic RSA mechanism.
  TestSignVerify(pub, priv, 100, CKM_RSA_PKCS, "");

  // Test RSA mechanism with built-in hash.
  TestSignVerify(pub, priv, 100, CKM_SHA256_RSA_PKCS, "");
}

// Test RSA PSS sign / verify.
TEST_F(TestSession, RsaPSSSign) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateRSAKeyPair(true, 1024, &pub, &priv);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .Times(4);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign, static_cast<int>(CKR_OK)))
      .Times(12);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionVerify, static_cast<int>(CKR_OK)))
      .Times(14);
  // Test the generic RSA PSS mechanism.
  TestSignVerify(pub, priv, 20, CKM_RSA_PKCS_PSS,
                 GetRSAPSSParam(CKM_SHA_1, CKG_MGF1_SHA1, 20));

  // Test the version with built-in hash.
  TestSignVerify(pub, priv, 100, CKM_SHA256_RSA_PKCS_PSS,
                 GetRSAPSSParam(CKM_SHA_1, CKG_MGF1_SHA1, 20));
}

// Test ECC ECDSA sign / verify.
TEST_F(TestSession, EcdsaSign) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateECCKeyPair(false, false, &pub, &priv);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_BUFFER_TOO_SMALL)))
      .Times(4);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign, static_cast<int>(CKR_OK)))
      .Times(12);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionVerify, static_cast<int>(CKR_OK)))
      .Times(14);
  // Test the generic ECDSA.
  TestSignVerify(pub, priv, 100, CKM_ECDSA, "");

  // Test ECDSA with built-in hash.
  TestSignVerify(pub, priv, 100, CKM_ECDSA_SHA1, "");
}

// Test that requests for unsupported mechanisms are handled correctly.
TEST_F(TestSession, MechanismInvalid) {
  const Object* key = nullptr;
  // Use a valid key so that key errors don't mask mechanism errors.
  GenerateSecretKey(CKM_AES_KEY_GEN, 16, &key);
  // We don't support IDEA.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt,
                              static_cast<int>(CKR_MECHANISM_INVALID)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            session_->OperationInit(kEncrypt, CKM_IDEA_CBC, "", key));
  // We don't support SHA-224.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_MECHANISM_INVALID)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            session_->OperationInit(kSign, CKM_SHA224_RSA_PKCS, "", key));
  // We don't support MD2.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_MECHANISM_INVALID)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            session_->OperationInit(kDigest, CKM_MD2, "", nullptr));
}

// Test that operation / mechanism mismatches are handled correctly.
TEST_F(TestSession, MechanismMismatch) {
  const Object* hmac = nullptr;
  GenerateSecretKey(CKM_GENERIC_SECRET_KEY_GEN, 16, &hmac);
  const Object* aes = nullptr;
  GenerateSecretKey(CKM_AES_KEY_GEN, 16, &aes);
  // Encrypt with a sign/verify mechanism.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt,
                              static_cast<int>(CKR_MECHANISM_INVALID)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            session_->OperationInit(kEncrypt, CKM_SHA_1_HMAC, "", hmac));
  // Sign with an encryption mechanism.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_MECHANISM_INVALID)))
      .Times(2);
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            session_->OperationInit(kSign, CKM_AES_CBC_PAD, "", aes));
  // Sign with a digest-only mechanism.
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            session_->OperationInit(kSign, CKM_SHA_1, "", hmac));
  // Digest with a sign+digest mechanism.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDigest,
                              static_cast<int>(CKR_MECHANISM_INVALID)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            session_->OperationInit(kDigest, CKM_SHA1_RSA_PKCS, "", nullptr));
}

// Test that mechanism / key type mismatches are handled correctly.
TEST_F(TestSession, KeyTypeMismatch) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  const Object* aes = nullptr;
  GenerateSecretKey(CKM_AES_KEY_GEN, 16, &aes);
  const Object* rsapub = nullptr;
  const Object* rsapriv = nullptr;
  GenerateRSAKeyPair(true, 512, &rsapub, &rsapriv);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt,
                              static_cast<int>(CKR_KEY_TYPE_INCONSISTENT)))
      .Times(2);
  // DES3 with an AES key.
  EXPECT_EQ(CKR_KEY_TYPE_INCONSISTENT,
            session_->OperationInit(kEncrypt, CKM_DES3_CBC, "", aes));
  // AES with an RSA key.
  EXPECT_EQ(CKR_KEY_TYPE_INCONSISTENT,
            session_->OperationInit(kEncrypt, CKM_AES_CBC, "", rsapriv));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_KEY_TYPE_INCONSISTENT)))
      .Times(2);
  // HMAC with an RSA key.
  EXPECT_EQ(CKR_KEY_TYPE_INCONSISTENT,
            session_->OperationInit(kSign, CKM_SHA_1_HMAC, "", rsapriv));
  // RSA with an AES key.
  EXPECT_EQ(CKR_KEY_TYPE_INCONSISTENT,
            session_->OperationInit(kSign, CKM_SHA1_RSA_PKCS, "", aes));
}

// Test that key function permissions are correctly enforced.
TEST_F(TestSession, KeyFunctionPermission) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  const Object* encpub = nullptr;
  const Object* encpriv = nullptr;
  GenerateRSAKeyPair(false, 512, &encpub, &encpriv);
  const Object* sigpub = nullptr;
  const Object* sigpriv = nullptr;
  GenerateRSAKeyPair(true, 512, &sigpub, &sigpriv);
  // Try decrypting with a sign-only key.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionDecrypt,
                              static_cast<int>(CKR_KEY_FUNCTION_NOT_PERMITTED)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_KEY_FUNCTION_NOT_PERMITTED,
            session_->OperationInit(kDecrypt, CKM_RSA_PKCS, "", sigpriv));
  // Try signing with a decrypt-only key.
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign,
                              static_cast<int>(CKR_KEY_FUNCTION_NOT_PERMITTED)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_KEY_FUNCTION_NOT_PERMITTED,
            session_->OperationInit(kSign, CKM_RSA_PKCS, "", encpriv));
}

// Test that invalid mechanism parameters for ciphers are handled correctly.
TEST_F(TestSession, BadIV) {
  const Object* aes = nullptr;
  GenerateSecretKey(CKM_AES_KEY_GEN, 16, &aes);
  const Object* des = nullptr;
  GenerateSecretKey(CKM_DES_KEY_GEN, 16, &des);
  const Object* des3 = nullptr;
  GenerateSecretKey(CKM_DES3_KEY_GEN, 16, &des3);
  // AES expects 16 bytes and DES/DES3 expects 8 bytes.
  string bad_iv(7, 0);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt,
                              static_cast<int>(CKR_MECHANISM_PARAM_INVALID)))
      .Times(3);
  EXPECT_EQ(CKR_MECHANISM_PARAM_INVALID,
            session_->OperationInit(kEncrypt, CKM_AES_CBC, bad_iv, aes));
  EXPECT_EQ(CKR_MECHANISM_PARAM_INVALID,
            session_->OperationInit(kEncrypt, CKM_DES_CBC, bad_iv, des));
  EXPECT_EQ(CKR_MECHANISM_PARAM_INVALID,
            session_->OperationInit(kEncrypt, CKM_DES3_CBC, bad_iv, des3));
}

// Test that invalid key size ranges are handled correctly.
TEST_F(TestSession, BadKeySize) {
  const Object* key = nullptr;
  GenerateSecretKey(CKM_AES_KEY_GEN, 16, &key);
  // AES keys can be 16, 24, or 32 bytes in length.
  const_cast<Object*>(key)->SetAttributeString(CKA_VALUE, string(33, 0));
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionEncrypt,
                              static_cast<int>(CKR_KEY_SIZE_RANGE)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_KEY_SIZE_RANGE,
            session_->OperationInit(kEncrypt, CKM_AES_ECB, "", key));
  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateRSAKeyPair(true, 512, &pub, &priv);
  // RSA keys can have a modulus size no smaller than 512.
  const_cast<Object*>(priv)->SetAttributeString(CKA_MODULUS, string(32, 0));
  EXPECT_CALL(
      mock_metrics_library_,
      SendSparseToUMA(kChapsSessionSign, static_cast<int>(CKR_KEY_SIZE_RANGE)))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_KEY_SIZE_RANGE,
            session_->OperationInit(kSign, CKM_RSA_PKCS, "", priv));
}

// Test that invalid attributes for key pair generation are handled correctly.
TEST_F(TestSession, BadRSAGenerate) {
  CK_BBOOL no = CK_FALSE;
  int size = 1024;
  CK_BYTE pubexp[] = {1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &no, sizeof(no)},
                             {CKA_PUBLIC_EXPONENT, pubexp, 12},
                             {CKA_MODULUS_BITS, &size, sizeof(size)}};
  CK_ATTRIBUTE priv_attr[] = {
      {CKA_TOKEN, &no, sizeof(no)},
  };
  int pub, priv;
  // CKA_PUBLIC_EXPONENT too large.
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      std::size(pub_attr), priv_attr,
                                      std::size(priv_attr), &pub, &priv));
  pub_attr[1].ulValueLen = 3;
  size = 20000;
  // CKA_MODULUS_BITS too large.
  EXPECT_EQ(CKR_KEY_SIZE_RANGE,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      std::size(pub_attr), priv_attr,
                                      std::size(priv_attr), &pub, &priv));
  // CKA_MODULUS_BITS missing.
  EXPECT_EQ(
      CKR_TEMPLATE_INCOMPLETE,
      session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr, 2,
                                priv_attr, std::size(priv_attr), &pub, &priv));
}

// Test that invalid attributes for key generation are handled correctly.
TEST_F(TestSession, BadAESGenerate) {
  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;
  int size = 33;
  CK_ATTRIBUTE attr[] = {{CKA_TOKEN, &no, sizeof(no)},
                         {CKA_ENCRYPT, &yes, sizeof(yes)},
                         {CKA_DECRYPT, &yes, sizeof(yes)},
                         {CKA_VALUE_LEN, &size, sizeof(size)}};
  int handle = 0;
  // CKA_VALUE_LEN missing.
  EXPECT_EQ(CKR_TEMPLATE_INCOMPLETE,
            session_->GenerateKey(CKM_AES_KEY_GEN, "", attr, 3, &handle));
  // CKA_VALUE_LEN out of range.
  EXPECT_EQ(CKR_KEY_SIZE_RANGE,
            session_->GenerateKey(CKM_AES_KEY_GEN, "", attr, 4, &handle));
}

// Test that signature verification fails as expected for invalid signatures.
TEST_F(TestSession, BadSignature) {
  string input(100, 'A');
  string signature(20, 0);
  const Object* hmac;
  GenerateSecretKey(CKM_GENERIC_SECRET_KEY_GEN, 32, &hmac);
  const Object *rsapub, *rsapriv;
  GenerateRSAKeyPair(true, 1024, &rsapub, &rsapriv);
  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionVerify, static_cast<int>(CKR_OK)))
      .Times(12);
  // HMAC with bad signature length.
  EXPECT_EQ(CKR_OK,
            session_->OperationInit(kVerify, CKM_SHA256_HMAC, "", hmac));
  EXPECT_EQ(CKR_OK,
            session_->OperationUpdate(kVerify, input, nullptr, nullptr));
  EXPECT_EQ(CKR_SIGNATURE_LEN_RANGE, session_->VerifyFinal(signature));
  // HMAC with bad signature.
  signature.resize(32);
  EXPECT_EQ(CKR_OK,
            session_->OperationInit(kVerify, CKM_SHA256_HMAC, "", hmac));
  EXPECT_EQ(CKR_OK,
            session_->OperationUpdate(kVerify, input, nullptr, nullptr));
  EXPECT_EQ(CKR_SIGNATURE_INVALID, session_->VerifyFinal(signature));
  // RSA with bad signature length.
  EXPECT_EQ(CKR_OK, session_->OperationInit(kVerify, CKM_RSA_PKCS, "", rsapub));
  EXPECT_EQ(CKR_OK,
            session_->OperationUpdate(kVerify, input, nullptr, nullptr));
  EXPECT_EQ(CKR_SIGNATURE_LEN_RANGE, session_->VerifyFinal(signature));
  // RSA with bad signature.
  signature.resize(128, 1);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kVerify, CKM_RSA_PKCS, "", rsapub));
  EXPECT_EQ(CKR_OK,
            session_->OperationUpdate(kVerify, input, nullptr, nullptr));
  EXPECT_EQ(CKR_SIGNATURE_INVALID, session_->VerifyFinal(signature));
}

TEST_F(TestSession, Flush) {
  ObjectMock token_object;
  EXPECT_CALL(token_object, IsTokenObject()).WillRepeatedly(Return(true));
  ObjectMock session_object;
  EXPECT_CALL(session_object, IsTokenObject()).WillRepeatedly(Return(false));
  EXPECT_CALL(token_pool_, Flush(_))
      .WillOnce(Return(Result::Failure))
      .WillRepeatedly(Return(Result::Success));
  EXPECT_NE(session_->FlushModifiableObject(&token_object), CKR_OK);
  EXPECT_EQ(session_->FlushModifiableObject(&token_object), CKR_OK);
  EXPECT_EQ(session_->FlushModifiableObject(&session_object), CKR_OK);
}

TEST_F(TestSessionWithRealObject, GenerateRSAWithHWSec) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(
      hwsec_,
      GenerateRSAKey(_, _, _, hwsec::ChapsFrontend::AllowSoftwareGen::kNotAllow,
                     hwsec::ChapsFrontend::AllowDecrypt::kNotAllow,
                     hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });
  EXPECT_CALL(hwsec_, GetRSAPublicKey(_))
      .WillRepeatedly(ReturnValue(hwsec::RSAPublicInfo{}));

  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;
  CK_BYTE pubexp[] = {1, 0, 1};
  int size = 2048;
  CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                             {CKA_ENCRYPT, &no, sizeof(no)},
                             {CKA_VERIFY, &yes, sizeof(yes)},
                             {CKA_PUBLIC_EXPONENT, pubexp, 3},
                             {CKA_MODULUS_BITS, &size, sizeof(size)}};
  CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                              {CKA_DECRYPT, &no, sizeof(no)},
                              {CKA_SIGN, &yes, sizeof(yes)}};
  int pubh = 0, privh = 0;
  ASSERT_EQ(CKR_OK,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      std::size(pub_attr), priv_attr,
                                      std::size(priv_attr), &pubh, &privh));
  // There are a few sensitive attributes that MUST not exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(privh, &object));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIVATE_EXPONENT));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIME_1));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIME_2));
  EXPECT_FALSE(object->IsAttributePresent(CKA_EXPONENT_1));
  EXPECT_FALSE(object->IsAttributePresent(CKA_EXPONENT_2));
  EXPECT_FALSE(object->IsAttributePresent(CKA_COEFFICIENT));

  // Check attributes that store security element wrapped blob exists.
  EXPECT_TRUE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_TRUE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_FALSE(object->GetAttributeBool(kKeyInSoftware, true));
}

TEST_F(TestSessionWithRealObject, GenerateRSAWithHWSecAndAllowSoftGen) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(
      hwsec_,
      GenerateRSAKey(_, _, _, hwsec::ChapsFrontend::AllowSoftwareGen::kAllow,
                     hwsec::ChapsFrontend::AllowDecrypt::kNotAllow,
                     hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });
  EXPECT_CALL(hwsec_, GetRSAPublicKey(_))
      .WillRepeatedly(ReturnValue(hwsec::RSAPublicInfo{}));

  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;
  CK_BYTE pubexp[] = {1, 0, 1};
  int size = 2048;
  CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                             {CKA_ENCRYPT, &no, sizeof(no)},
                             {CKA_VERIFY, &yes, sizeof(yes)},
                             {CKA_PUBLIC_EXPONENT, pubexp, 3},
                             {CKA_MODULUS_BITS, &size, sizeof(size)}};
  CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                              {CKA_DECRYPT, &no, sizeof(no)},
                              {CKA_SIGN, &yes, sizeof(yes)},
                              {kAllowSoftwareGenAttribute, &yes, sizeof(yes)}};
  int pubh = 0, privh = 0;
  ASSERT_EQ(CKR_OK,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      std::size(pub_attr), priv_attr,
                                      std::size(priv_attr), &pubh, &privh));
  // There are a few sensitive attributes that MUST not exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(privh, &object));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIVATE_EXPONENT));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIME_1));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIME_2));
  EXPECT_FALSE(object->IsAttributePresent(CKA_EXPONENT_1));
  EXPECT_FALSE(object->IsAttributePresent(CKA_EXPONENT_2));
  EXPECT_FALSE(object->IsAttributePresent(CKA_COEFFICIENT));

  // Check attributes that store security element wrapped blob exists.
  EXPECT_TRUE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_TRUE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_FALSE(object->GetAttributeBool(kKeyInSoftware, true));
}

TEST_F(TestSessionWithRealObject, GenerateRSAWithHWsecInconsistentToken) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(
      hwsec_,
      GenerateRSAKey(_, _, _, _, hwsec::ChapsFrontend::AllowDecrypt::kNotAllow,
                     hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });
  EXPECT_CALL(hwsec_, GetRSAPublicKey(_))
      .WillRepeatedly(ReturnValue(hwsec::RSAPublicInfo{}));

  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;
  CK_BYTE pubexp[] = {1, 0, 1};
  int size = 2048;
  CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &no, sizeof(no)},
                             {CKA_ENCRYPT, &no, sizeof(no)},
                             {CKA_VERIFY, &yes, sizeof(yes)},
                             {CKA_PUBLIC_EXPONENT, pubexp, 3},
                             {CKA_MODULUS_BITS, &size, sizeof(size)}};
  CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                              {CKA_DECRYPT, &no, sizeof(no)},
                              {CKA_SIGN, &yes, sizeof(yes)}};
  // Attempt to generate a private key on the token, but public key not on the
  // token.
  int pubh = 0, privh = 0;
  ASSERT_EQ(CKR_OK,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      std::size(pub_attr), priv_attr,
                                      std::size(priv_attr), &pubh, &privh));
  const Object* public_object = nullptr;
  const Object* private_object = nullptr;
  ASSERT_TRUE(session_->GetObject(pubh, &public_object));
  ASSERT_TRUE(session_->GetObject(privh, &private_object));
  EXPECT_FALSE(public_object->IsTokenObject());
  EXPECT_TRUE(private_object->IsTokenObject());

  // Destroy the objects.
  EXPECT_EQ(CKR_OK, session_->DestroyObject(pubh));
  EXPECT_EQ(CKR_OK, session_->DestroyObject(privh));
}

TEST_F(TestSessionWithRealObject, GenerateRSAWithNoHWSec) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(
          ReturnError<TPMError>("Not supported", TPMRetryAction::kNoRetry));
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));
  EXPECT_CALL(hwsec_, GenerateRSAKey(_, _, _, _, _, _)).Times(0);

  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;
  CK_BYTE pubexp[] = {1, 0, 1};
  int size = 1024;
  CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                             {CKA_ENCRYPT, &no, sizeof(no)},
                             {CKA_VERIFY, &yes, sizeof(yes)},
                             {CKA_PUBLIC_EXPONENT, pubexp, 3},
                             {CKA_MODULUS_BITS, &size, sizeof(size)}};
  CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                              {CKA_DECRYPT, &no, sizeof(no)},
                              {CKA_SIGN, &yes, sizeof(yes)}};
  int pubh = 0, privh = 0;
  ASSERT_EQ(CKR_OK,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      std::size(pub_attr), priv_attr,
                                      std::size(priv_attr), &pubh, &privh));
  // For a software key, the sensitive attributes should exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(privh, &object));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIVATE_EXPONENT));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_COEFFICIENT));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(object->GetAttributeBool(kKeyInSoftware, false));

  // Check attributes that store security element wrapped blob doesn't exists.
  EXPECT_FALSE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(object->IsAttributePresent(kKeyBlobAttribute));
}

TEST_F(TestSessionWithRealObject, GenerateRSAWithForceSoftware) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, GenerateRSAKey(_, _, _, _, _, _)).Times(0);

  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;
  CK_BYTE pubexp[] = {1, 0, 1};
  int size = 1024;
  CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                             {CKA_ENCRYPT, &no, sizeof(no)},
                             {CKA_VERIFY, &yes, sizeof(yes)},
                             {CKA_PUBLIC_EXPONENT, pubexp, 3},
                             {CKA_MODULUS_BITS, &size, sizeof(size)}};
  CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                              {CKA_DECRYPT, &no, sizeof(no)},
                              {CKA_SIGN, &yes, sizeof(yes)},
                              {kForceSoftwareAttribute, &yes, sizeof(yes)}};
  int pubh = 0, privh = 0;
  ASSERT_EQ(CKR_OK,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      std::size(pub_attr), priv_attr,
                                      std::size(priv_attr), &pubh, &privh));
  // For a software key, the sensitive attributes should exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(privh, &object));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIVATE_EXPONENT));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_COEFFICIENT));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(object->GetAttributeBool(kKeyInSoftware, false));

  // Check attributes that store security element wrapped blob doesn't exists.
  EXPECT_FALSE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(object->IsAttributePresent(kKeyBlobAttribute));
}

TEST_F(TestSessionWithRealObject, GenerateECCWithHWSec) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, GenerateECCKey(
                          _, _, hwsec::ChapsFrontend::AllowDecrypt::kNotAllow,
                          hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });
  EXPECT_CALL(hwsec_, GetECCPublicKey(_))
      .WillRepeatedly(ReturnValue(GenerateECCPublicInfo()));

  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateECCKeyPair(true, true, &pub, &priv);

  // Security element backed key object doesn't have CKA_VALUE which stored ECC
  // private key.
  EXPECT_FALSE(priv->IsAttributePresent(CKA_VALUE));

  // Check attributes that store security element wrapped blob exists.
  EXPECT_TRUE(priv->IsAttributePresent(kAuthDataAttribute));
  EXPECT_TRUE(priv->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(priv->IsAttributePresent(kKeyInSoftware));
  EXPECT_FALSE(priv->GetAttributeBool(kKeyInSoftware, true));
}

TEST_F(TestSessionWithRealObject, GenerateECCWithHWSecInconsistentToken) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, GenerateECCKey(
                          _, _, hwsec::ChapsFrontend::AllowDecrypt::kNotAllow,
                          hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });
  EXPECT_CALL(hwsec_, GetECCPublicKey(_))
      .WillRepeatedly(ReturnValue(GenerateECCPublicInfo()));

  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateECCKeyPair(false, true, &pub, &priv);

  EXPECT_FALSE(pub->IsTokenObject());
  EXPECT_TRUE(priv->IsTokenObject());
}

TEST_F(TestSessionWithRealObject, GenerateECCWithNoHWSec) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(
          ReturnError<TPMError>("Not supported", TPMRetryAction::kNoRetry));
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));

  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateECCKeyPair(true, true, &pub, &priv);

  // For a software key, the sensitive attributes should exist.
  EXPECT_TRUE(priv->IsAttributePresent(CKA_VALUE));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(priv->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(priv->GetAttributeBool(kKeyInSoftware, false));

  // Check attributes that store security element wrapped blob doesn't exists.
  EXPECT_FALSE(priv->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(priv->IsAttributePresent(kKeyBlobAttribute));
}

TEST_F(TestSessionWithRealObject, GenerateECCWithForceSoftware) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));

  const Object* priv = nullptr;

  // Create DER encoded OID of P-256 for CKA_EC_PARAMS (prime256v1 or
  // secp256r1)
  string ec_params = GetDERforNID(NID_X9_62_prime256v1);

  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;
  CK_ATTRIBUTE pub_attr[] = {
      {CKA_TOKEN, &yes, sizeof(CK_BBOOL)},
      {CKA_ENCRYPT, &no, sizeof(CK_BBOOL)},
      {CKA_VERIFY, &yes, sizeof(CK_BBOOL)},
      {CKA_EC_PARAMS, ConvertStringToByteBuffer(ec_params.data()),
       ec_params.size()}};
  CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &yes, sizeof(CK_BBOOL)},
                              {CKA_DECRYPT, &no, sizeof(CK_BBOOL)},
                              {CKA_SIGN, &yes, sizeof(CK_BBOOL)},
                              {kForceSoftwareAttribute, &yes, sizeof(yes)}};
  int pubh = 0, privh = 0;
  ASSERT_EQ(CKR_OK, session_->GenerateKeyPair(
                        CKM_EC_KEY_PAIR_GEN, "", pub_attr, std::size(pub_attr),
                        priv_attr, std::size(priv_attr), &pubh, &privh));
  ASSERT_TRUE(session_->GetObject(privh, &priv));

  // For a software key, the sensitive attributes should exist.
  EXPECT_TRUE(priv->IsAttributePresent(CKA_VALUE));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(priv->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(priv->GetAttributeBool(kKeyInSoftware, false));

  // Check attributes that store security element wrapped blob doesn't exists.
  EXPECT_FALSE(priv->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(priv->IsAttributePresent(kKeyBlobAttribute));
}

TEST_F(TestSession, EcdsaSignWithHWSec) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, GenerateECCKey(
                          _, _, hwsec::ChapsFrontend::AllowDecrypt::kNotAllow,
                          hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });
  EXPECT_CALL(hwsec_, GetECCPublicKey(_))
      .WillRepeatedly(ReturnValue(GenerateECCPublicInfo()));
  EXPECT_CALL(hwsec_, LoadKey(_, _)).WillRepeatedly([&](auto&&, auto&&) {
    return GetTestScopedKey();
  });
  EXPECT_CALL(hwsec_, Sign(_, _, _))
      .WillRepeatedly(ReturnValue(brillo::Blob()));

  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateECCKeyPair(true, true, &pub, &priv);

  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign, static_cast<int>(CKR_OK)))
      .Times(2);
  EXPECT_EQ(CKR_OK, session_->OperationInit(kSign, CKM_ECDSA_SHA1, "", priv));
  string in(100, 'A');
  int len = 0;
  string sig;
  EXPECT_EQ(CKR_OK, session_->OperationSinglePart(kSign, in, &len, &sig));
}

TEST_F(TestSessionWithRealObject, ImportRSAWithHWSec) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_,
              WrapRSAKey(_, _, _, _, hwsec::ChapsFrontend::AllowDecrypt::kAllow,
                         hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });

  crypto::ScopedBIGNUM exponent(BN_new());
  CHECK(exponent);
  EXPECT_TRUE(BN_set_word(exponent.get(), 0x10001));
  crypto::ScopedRSA rsa(RSA_new());
  CHECK(rsa);
  EXPECT_TRUE(RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr));
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  string id = "test_id";
  string label = "test_label";
  const BIGNUM* rsa_n;
  const BIGNUM* rsa_e;
  const BIGNUM* rsa_d;
  const BIGNUM* rsa_p;
  const BIGNUM* rsa_q;
  const BIGNUM* rsa_dmp1;
  const BIGNUM* rsa_dmq1;
  const BIGNUM* rsa_iqmp;
  RSA_get0_key(rsa.get(), &rsa_n, &rsa_e, &rsa_d);
  RSA_get0_factors(rsa.get(), &rsa_p, &rsa_q);
  RSA_get0_crt_params(rsa.get(), &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);
  string n = bn2bin(rsa_n);
  string e = bn2bin(rsa_e);
  string d = bn2bin(rsa_d);
  string p = bn2bin(rsa_p);
  string q = bn2bin(rsa_q);
  string dmp1 = bn2bin(rsa_dmp1);
  string dmq1 = bn2bin(rsa_dmq1);
  string iqmp = bn2bin(rsa_iqmp);

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, std::data(id), id.length()},
      {CKA_LABEL, std::data(label), label.length()},
      {CKA_MODULUS, std::data(n), n.length()},
      {CKA_PUBLIC_EXPONENT, std::data(e), e.length()},
      {CKA_PRIVATE_EXPONENT, std::data(d), d.length()},
      {CKA_PRIME_1, std::data(p), p.length()},
      {CKA_PRIME_2, std::data(q), q.length()},
      {CKA_EXPONENT_1, std::data(dmp1), dmp1.length()},
      {CKA_EXPONENT_2, std::data(dmq1), dmq1.length()},
      {CKA_COEFFICIENT, std::data(iqmp), iqmp.length()},
  };

  int handle = 0;
  ASSERT_EQ(CKR_OK,
            session_->CreateObject(private_attributes,
                                   std::size(private_attributes), &handle));
  // There are a few sensitive attributes that MUST be removed.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(handle, &object));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIVATE_EXPONENT));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIME_1));
  EXPECT_FALSE(object->IsAttributePresent(CKA_PRIME_2));
  EXPECT_FALSE(object->IsAttributePresent(CKA_EXPONENT_1));
  EXPECT_FALSE(object->IsAttributePresent(CKA_EXPONENT_2));
  EXPECT_FALSE(object->IsAttributePresent(CKA_COEFFICIENT));

  // Check attributes that store security element wrapped blob exists.
  EXPECT_TRUE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_TRUE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_FALSE(object->GetAttributeBool(kKeyInSoftware, true));
}

TEST_F(TestSessionWithRealObject, ImportRSAWithNoHWSec) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(
          ReturnError<TPMError>("Not supported", TPMRetryAction::kNoRetry));
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));

  crypto::ScopedBIGNUM exponent(BN_new());
  CHECK(exponent);
  EXPECT_TRUE(BN_set_word(exponent.get(), 0x10001));
  crypto::ScopedRSA rsa(RSA_new());
  CHECK(rsa);
  EXPECT_TRUE(RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr));
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  string id = "test_id";
  string label = "test_label";
  const BIGNUM* rsa_n;
  const BIGNUM* rsa_e;
  const BIGNUM* rsa_d;
  const BIGNUM* rsa_p;
  const BIGNUM* rsa_q;
  const BIGNUM* rsa_dmp1;
  const BIGNUM* rsa_dmq1;
  const BIGNUM* rsa_iqmp;
  RSA_get0_key(rsa.get(), &rsa_n, &rsa_e, &rsa_d);
  RSA_get0_factors(rsa.get(), &rsa_p, &rsa_q);
  RSA_get0_crt_params(rsa.get(), &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);
  string n = bn2bin(rsa_n);
  string e = bn2bin(rsa_e);
  string d = bn2bin(rsa_d);
  string p = bn2bin(rsa_p);
  string q = bn2bin(rsa_q);
  string dmp1 = bn2bin(rsa_dmp1);
  string dmq1 = bn2bin(rsa_dmq1);
  string iqmp = bn2bin(rsa_iqmp);

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, std::data(id), id.length()},
      {CKA_LABEL, std::data(label), label.length()},
      {CKA_MODULUS, std::data(n), n.length()},
      {CKA_PUBLIC_EXPONENT, std::data(e), e.length()},
      {CKA_PRIVATE_EXPONENT, std::data(d), d.length()},
      {CKA_PRIME_1, std::data(p), p.length()},
      {CKA_PRIME_2, std::data(q), q.length()},
      {CKA_EXPONENT_1, std::data(dmp1), dmp1.length()},
      {CKA_EXPONENT_2, std::data(dmq1), dmq1.length()},
      {CKA_COEFFICIENT, std::data(iqmp), iqmp.length()},
  };

  int handle = 0;
  ASSERT_EQ(CKR_OK,
            session_->CreateObject(private_attributes,
                                   std::size(private_attributes), &handle));
  // For a software key, the sensitive attributes should still exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(handle, &object));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIVATE_EXPONENT));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_COEFFICIENT));

  // Software key should not have security element related attributes.
  EXPECT_FALSE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(object->GetAttributeBool(kKeyInSoftware, false));
}

TEST_F(TestSessionWithRealObject, ImportRSAWithForceSoftware) {
  EXPECT_CALL(hwsec_, IsRSAModulusSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, WrapRSAKey(_, _, _, _, _, _)).Times(0);

  crypto::ScopedBIGNUM exponent(BN_new());
  CHECK(exponent);
  EXPECT_TRUE(BN_set_word(exponent.get(), 0x10001));
  crypto::ScopedRSA rsa(RSA_new());
  CHECK(rsa);
  EXPECT_TRUE(RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr));
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  string id = "test_id";
  string label = "test_label";
  const BIGNUM* rsa_n;
  const BIGNUM* rsa_e;
  const BIGNUM* rsa_d;
  const BIGNUM* rsa_p;
  const BIGNUM* rsa_q;
  const BIGNUM* rsa_dmp1;
  const BIGNUM* rsa_dmq1;
  const BIGNUM* rsa_iqmp;
  RSA_get0_key(rsa.get(), &rsa_n, &rsa_e, &rsa_d);
  RSA_get0_factors(rsa.get(), &rsa_p, &rsa_q);
  RSA_get0_crt_params(rsa.get(), &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);
  string n = bn2bin(rsa_n);
  string e = bn2bin(rsa_e);
  string d = bn2bin(rsa_d);
  string p = bn2bin(rsa_p);
  string q = bn2bin(rsa_q);
  string dmp1 = bn2bin(rsa_dmp1);
  string dmq1 = bn2bin(rsa_dmq1);
  string iqmp = bn2bin(rsa_iqmp);

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, std::data(id), id.length()},
      {CKA_LABEL, std::data(label), label.length()},
      {CKA_MODULUS, std::data(n), n.length()},
      {CKA_PUBLIC_EXPONENT, std::data(e), e.length()},
      {CKA_PRIVATE_EXPONENT, std::data(d), d.length()},
      {CKA_PRIME_1, std::data(p), p.length()},
      {CKA_PRIME_2, std::data(q), q.length()},
      {CKA_EXPONENT_1, std::data(dmp1), dmp1.length()},
      {CKA_EXPONENT_2, std::data(dmq1), dmq1.length()},
      {CKA_COEFFICIENT, std::data(iqmp), iqmp.length()},
      {kForceSoftwareAttribute, &true_value, sizeof(true_value)},
  };

  int handle = 0;
  ASSERT_EQ(CKR_OK,
            session_->CreateObject(private_attributes,
                                   std::size(private_attributes), &handle));
  // For a software key, the sensitive attributes should still exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(handle, &object));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIVATE_EXPONENT));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_PRIME_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_1));
  EXPECT_TRUE(object->IsAttributePresent(CKA_EXPONENT_2));
  EXPECT_TRUE(object->IsAttributePresent(CKA_COEFFICIENT));

  // Software key should not have security element related attributes.
  EXPECT_FALSE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(object->GetAttributeBool(kKeyInSoftware, false));
}

TEST_F(TestSessionWithRealObject, ImportECCWithHWSec) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(NID_X9_62_prime256v1))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, WrapECCKey(_, _, _, _, _,
                                 hwsec::ChapsFrontend::AllowDecrypt::kAllow,
                                 hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });

  crypto::ScopedEC_KEY key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  ASSERT_NE(key, nullptr);
  // Focus GetECParametersAsString() dump OID to CKA_EC_PARAMS
  EC_KEY_set_asn1_flag(key.get(), OPENSSL_EC_NAMED_CURVE);
  ASSERT_TRUE(EC_KEY_generate_key(key.get()));

  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  string id = "test_id";
  string label = "test_label";
  string ec_params = GetECParametersAsString(key.get());
  string private_value = bn2bin(EC_KEY_get0_private_key(key.get()));

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, std::data(id), id.length()},
      {CKA_LABEL, std::data(label), label.length()},
      {CKA_EC_PARAMS, std::data(ec_params), ec_params.length()},
      {CKA_VALUE, std::data(private_value), private_value.length()},
  };

  int handle = 0;
  ASSERT_EQ(CKR_OK,
            session_->CreateObject(private_attributes,
                                   std::size(private_attributes), &handle));

  // There are a few sensitive attributes that MUST be removed.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(handle, &object));
  EXPECT_FALSE(object->IsAttributePresent(CKA_VALUE));

  // Check attributes that store security element wrapped blob exists.
  EXPECT_TRUE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_TRUE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_FALSE(object->GetAttributeBool(kKeyInSoftware, true));
}

TEST_F(TestSessionWithRealObject, ImportECCWithNoHWSec) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(
          ReturnError<TPMError>("Not supported", TPMRetryAction::kNoRetry));
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));

  crypto::ScopedEC_KEY key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  ASSERT_NE(key, nullptr);
  ASSERT_TRUE(EC_KEY_generate_key(key.get()));

  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  string id = "test_id";
  string label = "test_label";
  string ec_params = GetECParametersAsString(key.get());
  string private_value = bn2bin(EC_KEY_get0_private_key(key.get()));

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, std::data(id), id.length()},
      {CKA_LABEL, std::data(label), label.length()},
      {CKA_EC_PARAMS, std::data(ec_params), ec_params.length()},
      {CKA_VALUE, std::data(private_value), private_value.length()},
  };

  int handle = 0;
  ASSERT_EQ(CKR_OK,
            session_->CreateObject(private_attributes,
                                   std::size(private_attributes), &handle));

  // For a software key, the sensitive attributes should still exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(handle, &object));
  EXPECT_TRUE(object->IsAttributePresent(CKA_VALUE));

  // Software key should not have security element related attributes.
  EXPECT_FALSE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(object->GetAttributeBool(kKeyInSoftware, false));
}

TEST_F(TestSessionWithRealObject, ImportECCWithForceSoftware) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(NID_X9_62_prime256v1))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, WrapECCKey(_, _, _, _, _, _, _)).Times(0);

  crypto::ScopedEC_KEY key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  ASSERT_NE(key, nullptr);
  ASSERT_TRUE(EC_KEY_generate_key(key.get()));

  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  string id = "test_id";
  string label = "test_label";
  string ec_params = GetECParametersAsString(key.get());
  string private_value = bn2bin(EC_KEY_get0_private_key(key.get()));

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, std::data(id), id.length()},
      {CKA_LABEL, std::data(label), label.length()},
      {CKA_EC_PARAMS, std::data(ec_params), ec_params.length()},
      {CKA_VALUE, std::data(private_value), private_value.length()},
      {kForceSoftwareAttribute, &true_value, sizeof(true_value)},
  };

  int handle = 0;
  ASSERT_EQ(CKR_OK,
            session_->CreateObject(private_attributes,
                                   std::size(private_attributes), &handle));

  // For a software key, the sensitive attributes should still exist.
  const Object* object = nullptr;
  ASSERT_TRUE(session_->GetObject(handle, &object));
  EXPECT_TRUE(object->IsAttributePresent(CKA_VALUE));

  // Software key should not have security element related attributes.
  EXPECT_FALSE(object->IsAttributePresent(kAuthDataAttribute));
  EXPECT_FALSE(object->IsAttributePresent(kKeyBlobAttribute));

  // Check that kKeyInSoftware attribute is correctly set.
  EXPECT_TRUE(object->IsAttributePresent(kKeyInSoftware));
  EXPECT_TRUE(object->GetAttributeBool(kKeyInSoftware, false));
}

TEST_F(TestSession, CreateObjectsNoPrivate) {
  EXPECT_CALL(token_pool_, Insert(_))
      .WillRepeatedly(Return(ObjectPool::Result::WaitForPrivateObjects));

  int handle = 0;
  int size = 2048;
  CK_BBOOL no = CK_FALSE;
  CK_BBOOL yes = CK_TRUE;

  CK_OBJECT_CLASS oc = CKO_SECRET_KEY;
  CK_ATTRIBUTE attr[] = {{CKA_CLASS, &oc, sizeof(oc)}};
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS,
            session_->CreateObject(attr, std::size(attr), &handle));

  CK_ATTRIBUTE key_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                             {CKA_SIGN, &yes, sizeof(yes)},
                             {CKA_VERIFY, &yes, sizeof(yes)},
                             {CKA_VALUE_LEN, &size, sizeof(size)}};
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS,
            session_->GenerateKey(CKM_GENERIC_SECRET_KEY_GEN, "", key_attr, 4,
                                  &handle));

  CK_BYTE pubexp[] = {1, 0, 1};
  CK_ATTRIBUTE pub_attr[] = {{CKA_TOKEN, &yes, sizeof(yes)},
                             {CKA_ENCRYPT, &no, sizeof(no)},
                             {CKA_VERIFY, &yes, sizeof(yes)},
                             {CKA_PUBLIC_EXPONENT, pubexp, 3},
                             {CKA_MODULUS_BITS, &size, sizeof(size)}};
  CK_ATTRIBUTE priv_attr[] = {{CKA_TOKEN, &no, sizeof(CK_BBOOL)},
                              {CKA_DECRYPT, &no, sizeof(no)},
                              {CKA_SIGN, &yes, sizeof(yes)}};
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS,
            session_->GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, "", pub_attr,
                                      5, priv_attr, 3, &handle, &handle));
}

TEST_F(TestSession, FindObjectsNoPrivate) {
  EXPECT_CALL(token_pool_, Find(_, _))
      .WillRepeatedly(Return(ObjectPool::Result::WaitForPrivateObjects));

  CK_OBJECT_CLASS oc = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr[] = {{CKA_CLASS, &oc, sizeof(oc)}};
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS,
            session_->FindObjectsInit(attr, std::size(attr)));
}

TEST_F(TestSession, DestroyObjectsNoPrivate) {
  EXPECT_CALL(token_pool_, Delete(_))
      .WillRepeatedly(Return(ObjectPool::Result::WaitForPrivateObjects));

  int handle = 0;

  CK_OBJECT_CLASS oc = CKO_SECRET_KEY;
  CK_ATTRIBUTE attr[] = {{CKA_CLASS, &oc, sizeof(oc)}};
  ASSERT_EQ(CKR_OK, session_->CreateObject(attr, std::size(attr), &handle));
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS,
            session_->DestroyObject(handle));
}

TEST_F(TestSession, FlushObjectsNoPrivate) {
  EXPECT_CALL(token_pool_, Flush(_))
      .WillRepeatedly(Return(ObjectPool::Result::WaitForPrivateObjects));

  ObjectMock token_object;
  EXPECT_CALL(token_object, IsTokenObject()).WillRepeatedly(Return(true));
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS,
            session_->FlushModifiableObject(&token_object));
}

TEST_F(TestSession, MultipleSignWithHWSec) {
  EXPECT_CALL(hwsec_, IsECCurveSupported(_))
      .WillRepeatedly(ReturnOk<TPMError>());
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, GetECCPublicKey(_))
      .WillRepeatedly(ReturnValue(GenerateECCPublicInfo()));

  EXPECT_CALL(hwsec_, GenerateECCKey(
                          _, _, hwsec::ChapsFrontend::AllowDecrypt::kNotAllow,
                          hwsec::ChapsFrontend::AllowSign::kAllow))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&) {
        return hwsec::ChapsFrontend::CreateKeyResult{
            .key = GetTestScopedKey(),
        };
      });

  const Object* pub = nullptr;
  const Object* priv = nullptr;
  GenerateECCKeyPair(true, true, &pub, &priv);

  EXPECT_CALL(hwsec_, LoadKey(_, _)).WillRepeatedly([&](auto&&, auto&&) {
    return GetTestScopedKey();
  });
  EXPECT_CALL(hwsec_, Sign(_, _, _))
      .WillRepeatedly(ReturnValue(brillo::Blob()));

  EXPECT_CALL(mock_metrics_library_,
              SendSparseToUMA(kChapsSessionSign, static_cast<int>(CKR_OK)))
      .WillRepeatedly(Return(true));

  for (int i = 0; i < 100; i++) {
    EXPECT_EQ(CKR_OK, session_->OperationInit(kSign, CKM_ECDSA_SHA1, "", priv));
    string in(100, 'A');
    int len = 0;
    string sig;
    EXPECT_EQ(CKR_OK, session_->OperationSinglePart(kSign, in, &len, &sig));
  }

  EXPECT_EQ(session_->get_object_key_map_size_for_testing(), 0);
}

}  // namespace chaps

int main(int argc, char** argv) {
  ::testing::InitGoogleMock(&argc, argv);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  return RUN_ALL_TESTS();
}
