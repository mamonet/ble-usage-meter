// firmware/esp32/signer.h
// Ed25519 over a canonical byte serialisation of the report tuple.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace meter {

struct ReportTuple {
  std::string device_id;
  uint64_t count = 0;
  uint64_t sequence = 0;
  uint64_t window_start = 0;  // unix seconds
  uint64_t window_end = 0;    // unix seconds
};

// Deterministic byte encoding. Same bytes on the ESP32 and on the Pi gateway.
std::vector<uint8_t> canonical_bytes(const ReportTuple& r);

class Signer {
 public:
  // seed is the 32-byte Ed25519 private seed, loaded from NVS at runtime.
  bool load_seed(const uint8_t seed[32]);
  bool public_key(uint8_t out[32]) const;

  // sig_out receives 64 bytes.
  bool sign(const ReportTuple& r, uint8_t sig_out[64]) const;

  bool ready() const { return ready_; }

 private:
  uint8_t seed_[32] = {0};
  uint8_t pub_[32] = {0};
  bool ready_ = false;
};

}  // namespace meter
