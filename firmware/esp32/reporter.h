// firmware/esp32/reporter.h
// POSTs signed usage reports. Derived from the counter, never authoritative over it.
#pragma once

#include <cstdint>
#include <string>

#include "counter.h"
#include "signer.h"

namespace meter {

struct ReportResult {
  bool posted = false;
  int http_status = 0;
  uint32_t attempts = 0;
};

class Reporter {
 public:
  void configure(const char* endpoint, const Signer* signer);

  // Builds, signs and posts one report for device_id at the current count.
  // Safe to call again after a failure: the same count is simply re-sent.
  ReportResult post(const std::string& device_id, uint64_t count, uint64_t sequence,
                    uint64_t window_start, uint64_t window_end);

 private:
  std::string build_body(const ReportTuple& r, const uint8_t sig[64]) const;

  const char* endpoint_ = nullptr;
  const Signer* signer_ = nullptr;
};

}  // namespace meter
