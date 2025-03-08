// firmware/esp32/signer.cpp
// Why sign bytes and not a struct or a JSON object:
//  - A C struct's layout is padding- and endianness-dependent. The same logical report
//    signed on the ESP32 and verified on x86 would hash differently.
//  - A dict/JSON object has no inherent key order, and encoders differ on whitespace,
//    integer formatting and escaping. Two encoders produce two different signatures for
//    the same data, so verification becomes a coin toss.
// So the tuple is flattened to one explicit byte string: a version tag, then each field
// length-prefixed and big-endian. Any change to that layout must bump kFormatVersion,
// because the gateway builds the identical bytes in gateway/signer.py.
//
// The seed is read from NVS at runtime. It is never compiled into the image.
#include "signer.h"

#include <cstring>

#include "esp_log.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "sodium/crypto_sign_ed25519.h"

namespace meter {

static const char* TAG = "signer";

// Bump this if the encoding below changes in any way.
static constexpr uint8_t kFormatVersion = 1;
static constexpr char kDomain[] = "ble-usage-meter/report/v1";

static void put_u64_be(std::vector<uint8_t>& out, uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

static void put_lp_string(std::vector<uint8_t>& out, const std::string& s) {
  // 2-byte big-endian length, then raw UTF-8 bytes. Length prefixing stops
  // ("ab","c") and ("a","bc") producing the same serialisation.
  uint16_t n = static_cast<uint16_t>(s.size());
  out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(n & 0xFF));
  out.insert(out.end(), s.begin(), s.end());
}

std::vector<uint8_t> canonical_bytes(const ReportTuple& r) {
  std::vector<uint8_t> out;
  out.reserve(96 + r.device_id.size());

  // Domain separation: a signature over a report can never be replayed as a signature
  // over some other message this key might sign later.
  out.insert(out.end(), kDomain, kDomain + sizeof(kDomain) - 1);
  out.push_back(kFormatVersion);

  put_lp_string(out, r.device_id);
  put_u64_be(out, r.count);
  put_u64_be(out, r.sequence);
  put_u64_be(out, r.window_start);
  put_u64_be(out, r.window_end);
  return out;
}

bool Signer::load_seed(const uint8_t seed[32]) {
  if (seed == nullptr) return false;
  std::memcpy(seed_, seed, 32);

  uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pub_, sk, seed_) != 0) {
    ESP_LOGE(TAG, "keypair derivation failed");
    std::memset(seed_, 0, sizeof(seed_));
    return false;
  }
  std::memset(sk, 0, sizeof(sk));
  ready_ = true;
  return true;
}

bool Signer::public_key(uint8_t out[32]) const {
  if (!ready_) return false;
  std::memcpy(out, pub_, 32);
  return true;
}

bool Signer::sign(const ReportTuple& r, uint8_t sig_out[64]) const {
  if (!ready_) return false;

  uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
  uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  if (crypto_sign_ed25519_seed_keypair(pk, sk, seed_) != 0) return false;

  std::vector<uint8_t> msg = canonical_bytes(r);
  unsigned long long siglen = 0;
  int rc = crypto_sign_ed25519_detached(sig_out, &siglen, msg.data(), msg.size(), sk);

  std::memset(sk, 0, sizeof(sk));
  return rc == 0 && siglen == 64;
}

}  // namespace meter
