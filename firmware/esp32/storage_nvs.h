// firmware/esp32/storage_nvs.h
// NVS persistence for the counter and an append-only event log ring.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "counter.h"

namespace meter {

struct LogEntry {
  uint64_t seq = 0;        // log slot number, strictly increasing
  int64_t  ts_us = 0;      // esp_timer time at record, monotonic since boot
  char     device_id[24] = {0};
  char     event[24] = {0};  // "unknown" for an unrecognised write
  uint16_t payload_len = 0;
  uint8_t  payload_head[16] = {0};  // first bytes, for operator triage
};

class Storage {
 public:
  esp_err_t init();

  // Counter persistence. Write refuses to store a value below what is already stored.
  esp_err_t save_counter(const std::string& device_id, uint64_t count);
  esp_err_t load_counter(const std::string& device_id, uint64_t& out) const;
  esp_err_t save_sequence(uint64_t seq);
  esp_err_t load_sequence(uint64_t& out) const;

  // Append-only log. There is no erase or rewrite entry point by design; the ring
  // overwrites only the oldest slot once capacity is reached.
  esp_err_t append_event(const LogEntry& e);
  esp_err_t read_recent(std::vector<LogEntry>& out, size_t max_entries) const;

  // Signing key, provisioned out of band. Never compiled into the image.
  esp_err_t load_signing_key(uint8_t out[32]) const;

 private:
  uint32_t head_ = 0;   // next slot to write
  bool ready_ = false;
};

}  // namespace meter
