// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/well_known_key_pairs/well_known_key_pairs.h"

#include "hwsec-test-utils/common/openssl_utility.h"

namespace hwsec_test_utils {
namespace well_known_key_pairs {

namespace {

// From ca_encryption.pem
constexpr char kCaEncryptionKeyPem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEogIBAAKCAQEA0YCOrvl8h/mPS/mCUj00gA4V5BczMIKyl5HoVIl5T/ugU8GU\n"
    "1V7Ll1k7d2JCHWDc57khcXiAZMtRxFp4r6w2jeaUQDl4fEAMlHm8SeZ6GRxR7Yy5\n"
    "IIOwcMajUx2eyoFzPCAh7yH57WOoEWruzRIEKPwSIK0kddq2qpaN72iI3aspWufq\n"
    "nrKzk5i1sETcq5ikBKxQav4/2Nzws4IHJIfcF3uyCyCwe6rFWZ5uUKynPdaMySQD\n"
    "8FpmOIR6x4IzOpDWfj0Zs+glYEmO+paiMbWgCJvxMduCf+wpJfVr29jJ9pvuie69\n"
    "6dhy0wPaovjjzFZ0aHeegGCWgDBObb3HowI9cwIDAQABAoIBAEYXQqVbpsQ/RCfg\n"
    "9C7bd0MYc056TJAASgvXrukJjWKrBrq+2zJ/opGiMvkAEKqPi5ijIYM7E4mlVFfj\n"
    "BNmRPjc/W34ZPCwlqY/LIql+yH66MNbO6+jq5g71BhN6p3OM16bYAUJmFZ3MZ6Bc\n"
    "LETDsEyd+Nqh0r7zS4XLFPVx/chbLkDGezHg5+MrGy4kEvHMjf04XuakbjIQJWYz\n"
    "Nuo/jgVM7pLBuoR2zp3ixET4i9xSo8sRlVQifky3OfSW0bfJr4uRYfPtwk0NyJqb\n"
    "7SqRgG2piCQQWQHau8cC/Q2V8wOLwnNYCEc7HJT3kIGp2gaJ1uulqlPeYDzbuRE4\n"
    "9qQTc6ECgYEA8e9X5ssg1CiwfcWFLE0pJP/Q8bV27lI33a7wzan57p5A+7Dg7pHj\n"
    "vhMuyeD65rWcb/6+FXMCRRDZRTToxIu18qh93vXuhDh4pCBL3c7eDru2YX9rHrUA\n"
    "hxbCyziNgIx8BPXmQVhiJe7cTxlBo4lUhDXnK6jvfhCjOczGcRxVEusCgYEA3a6G\n"
    "guZdzVfFU9qZMYC+kOie+25WnwviGPHtAV80X1MJ9NIhhqs0NNNMVVk+hvYKzSqK\n"
    "6lYdvwrJ7oRSmrdol+HJEOGczjbIg9KCiFgdtAKX666ydh788M2GaT3wF9KE6B4a\n"
    "hKgGzNrzzgctk1dNKLatzStzkcckZc9jXNGcDZkCgYBQ9NArMImZtMvqKjA39NHx\n"
    "yZB3cUuM0AJVsfZuO5SgnmAMWNHLwxG8Rtr/PsN2dAsXBt1AfC2kQtERcXT6X+3Q\n"
    "d0U3WIApymPEN/JrFJAFyhZrZaHIsrSsf5dLPW9MNrZBSq9z6kldfCJIbaEjQg7/\n"
    "9rGWUH9jZdnYu4cjzmFBZQKBgFeeNn4gbSzPJygoe2osd6Wwu72m88ezG68+V622\n"
    "Im4W1RWVxDiFDIJgjYgiWOtg7g3/ZZ6PYPx0WDHUzQ1ntohpbl4kviRnVMN9fahE\n"
    "I6FVcRRvHQxA3TqUES8hkvbndy6DT3nlK6LmW3ywK5xT4iRYZ8NzDB+vNTykRqKW\n"
    "GnbpAoGARrDdq7yCuq1SHoVFoi4zOHhwCHWZ4r++aV5kMaluIogXShMmxwNbhm1D\n"
    "TQVq7mTo/movkvSwUtHLOBEX9IYFTBJ/dI2Bh+sh8utMrAweMUi+nyAMVqtRKfVQ\n"
    "RU6FfcYAFsQHMyJgBCfJp0DxCdHpjyNf8GRQt3ICPs5Gm39EAqU=\n"
    "-----END RSA PRIVATE KEY-----";

// From va_signing.pem
constexpr char kVaSigningKeyPem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA58sMydL5BOw/CaN5uP4Jp+9iHxVldSMTjohuu8AAgm4YmpR6\n"
    "YtUGefjBnP2EBlOI1ifdEffo5793gTV51vuKlnfkUIqiama+tp08YWxijVG+NQxZ\n"
    "1piNhmRcVMbsE9qdRRtEo4bJaZ2oCaLs7G8FOtbd12HTAj2UTxsLXhOFQ8OUj4p/\n"
    "DwaE8oTtOLTNN9wVUFBJ8JI+KrSfyF3IcCfFzL2G1IZhZiOXaWWHdIa+ZWQnou5W\n"
    "wZXuOL7MFTNp+NQ+LM2hjlP3Y5JUBlga3L6wdmuJjyeepRYTWbx50wACj+ij9SB3\n"
    "1Qqq+Cqttyc0g3Av/BfWjw9BNFntypdNdso8nwIDAQABAoIBAQDlPVSteeBbtQX3\n"
    "E107zspf8wj4suF/gqxBx760IoSeeiINJxEPE51vHczl5XggBZeMLSqfLa6DHEIl\n"
    "YGzaaDW88F+2JBXS40B0PHdN5rJlD1XtAwUKjh9RrYn/Miiizg/CG+C7VX9227wn\n"
    "o6Frh7UFZyFJdO8KBTrbLWUFqoqe4zl0asrEZnP+0jV5mpD7JhJpzGBTlGXGADID\n"
    "VXJX9zQAD8tuRdDl4SKSPu/V/TAPt4UdZyjvO9Ul6WDf5RGgzcWDk97TpkGCwSpn\n"
    "aQDU/DnrVTiLPftFhSAx4cqIxN6l0AsubK4W0J+BqR+0MovHpLTvQvKkW47hgOmi\n"
    "ROQfIbAJAoGBAP+LONlHyQcfJjJVH1KBtdws2NnOQvQlweuMf8o3p4xuBpSkDtUh\n"
    "idmD/lkKq+Wu1yWmH9+t7OJgzFVDlswM2dBR8oQGNyfqV+jI+fZiB8RvCel4P80K\n"
    "8pHAMTdPDUc4r+CVV+X9aUbSHA51PSL+Xg8ufFlRxPqyv4NYJwigomZtAoGBAOg0\n"
    "+W8mMLBfdRGBuNGoTzD1j1tf4v2neXnKve07PWQtAiiGbmldmyJd/UsbvtXFXCKC\n"
    "eqq6vdkMI+9c1ss/xAJEf0JsfvK1dF1HeTJvBvKCEgcIX1zFmIBkIdg0+uv9jon1\n"
    "nK+8U8g/sjOZYirKDOqL1Fl6Q84LRVm7LZuzyDe7AoGAbVea6Y3HvJ5db6fwkRMj\n"
    "R6SA3SFekK0fPrSNcW9C59mkQzG3jwacv0+1I1BnoQ2gzWE5vjHjbDHS/KDBA2p0\n"
    "QKjvxgIK0694Egj8u6nSfQCuExH66rdGd4rvBCV1HwZoawY76BL4Wu9IRf9wO2rv\n"
    "wDs5xdYxHLwjKgYsHYruMjkCgYBEETtJDK3bFbBQeHE/7BGCrYjfZSU567zdKcQw\n"
    "5VuioNrwHDADbPALy/dy6+gt69ONPihNIb6DAF8MTG+eVsvTSlbvlrRD21MIAOqT\n"
    "ER69OcmlDBxAKqAAitms8iLXyJTe9gN/NDpvCdTn8T9ogZ/1pRWTQRbdMEqc+hRt\n"
    "fu7i/wKBgQC+Nwv1cSvtJXTZ5z8UPBLKHELTAG1jPN5YuEFOIUaWJGJm/xCaj+cS\n"
    "SX2TJAlKmCEjEaHCgDBDUa+FJsxBLajHKTco1QqFwMRcXY9d2oVhPYQ1m6bF5bog\n"
    "6+0HlsMNdZ/TXych5CPIyjt4+ldSrmFdBVICO6F2wxYhgEyyO//FNA==\n"
    "-----END RSA PRIVATE KEY-----";

// From va_encryption.pem
constexpr char kVaEncryptionKeyPem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAvENdsGTs9EtlDq0W8pNANaDm7Px2xPP3wmzkWUgsZvZ0e45R\n"
    "DAPpSAhgjwdrTTrTRw1xDBuNcxy+LUxT4t9zZ3ztIB31fIyGUDzCRC+qcciKZvhn\n"
    "JrV5G414iN8TV9770bXN3/4Q4uye96R+7eTXTDPKTjTwgBvtBlGI8DXnKf/xC0ZD\n"
    "LtMg+ZPXXszOv/iNGXoPIN/vpDjV9YxpV45gN4IZQ3IcIdrquEVxb0gjdI6oCApL\n"
    "tDeG4cxw8zY7+5jVGjt3pbOkSxigKSlq0HXpPfMaviEFxopvr7i0etUuwB6t3lbF\n"
    "IuE2mp+1F16l6OvYw1wM0W7h1pMPNIIfEvRkWQIDAQABAoIBAChl0EHctlgJoarP\n"
    "i6AL5vhbCZKK7jV/IIgw86MQ8K47bm1g8ZVBdZqGaannbqgI2nNhuANgGi88WLbB\n"
    "rTJ+vnXTgdKlexr50IyBLTKSg+Gcpc5IuWG+CTnXVqkQLUdqyuCKQZ4yF4+KNOZw\n"
    "/uevdl+csWmsxHrJA0ia0GazOmJxchkijhLn4zy5+L+eAKb2RS3mIJhZCtnXb2C6\n"
    "8kCmzDgYXw8DOOfBYAj6c+q+M1KWxWyVcQQqrWRopFUY4RKT5EdWAXmqwGIZO35Q\n"
    "ABV/jcvjM9uT4IvgB8WyNjTHUCHVJFrGzoxEkNvPPIVCMBrk9w+zOEXHa408iviT\n"
    "4GrOqt0CgYEA4VXsEsLePosPHYNAz5dfrZ/Hc0joGXZGRn4XeYy5WcpQBFcTqo4l\n"
    "2DPThlFww/ZnuREpKDGWufyodj+8H5o94KXfiS0Xdd7ExBujs9X708Q9Qg3f2NbX\n"
    "vz0a0bLBD1owjQ25drmWBneO2nRXZt8ZLe+/5gvZJxjyXNqlZ8svpgMCgYEA1eHw\n"
    "kSFNsr6qfYBVCNf5VRGe+eAz7Hsy/3QQolMDicTWDwlYIOFEwjtwWtRnsQgLTMMX\n"
    "k0npIdBxNFt1MVe+jOzmQ/+fnvY1y1ma7uQzuIl5j2LEDv7elcQUOwP6VFmxNwG+\n"
    "W8WDFu+jbM3nT2bvHuHEdIUveQNYtxBJAqsDm3MCgYEAy3Gp/J5XzZv7f6fbQhHn\n"
    "XnjduKZgd2yjsk1xoFp/liPk7qY3qUtBu9u+5IxvBV5Y82wc/p8W+MC20Fxm2xmF\n"
    "OGhKVC2T+uWwPWa+/ET8YovQyux/5+TBUXY32pBLYjMJlrCHfDu+ygPzxCQ6LTTM\n"
    "JP9LAMY9vuD1IQR/RiDa2kUCgYBRb2KCT7Tevtv5RviZkmn7qubl6yi5/LqRKyb+\n"
    "Ny9csFZ0iTFF65+beLgxzTfh3tc2lf2O9hBO8Kd5sOzxKaCC1dxivZyQENywnWBx\n"
    "XvAWbjmbj5Zow0AKtAqj4cLZhQEFmaNaG9zqyblmvws4X0/iaUG8v80wfUa1BP1X\n"
    "h7eq4wKBgHhq/QIFk2rmZbLKuAcS1Frrs8MuqXLcGPGNvXYglDjfY0xtzEr+1/nL\n"
    "cSTtiip+2NCHd5P0R1h61+xmBxwpgsmZD0SHtETKdTyySzAeUPSK197SBl3s+nFb\n"
    "NPEew8iRaZYCR60JSs7vnlUL9QPrdbCutSs0nOPUAog6sneHIcg4\n"
    "-----END RSA PRIVATE KEY-----";

}  // namespace

crypto::ScopedEVP_PKEY GetCaEncryptionkey() {
  return PemToEVP(kCaEncryptionKeyPem);
}

crypto::ScopedEVP_PKEY GetVaSigningkey() {
  return PemToEVP(kVaSigningKeyPem);
}

crypto::ScopedEVP_PKEY GetVaEncryptionkey() {
  return PemToEVP(kVaEncryptionKeyPem);
}

}  // namespace well_known_key_pairs
}  // namespace hwsec_test_utils
