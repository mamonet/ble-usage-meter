// firmware/esp32/counter.h
// Per-device monotonic usage counter plus a report sequence number.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace meter {

struct CounterEntry {
  std::string device_id;
  uint64_t count = 0;
};

class Counter {
 public:
  // Restore a persisted value. Only ever moves the count forward: a restored value lower
  // than the value already in RAM is ignored.
  void restore(const std::string& device_id, uint64_t count);
  void restore_sequence(uint64_t seq);

  // Add n to the device count. Returns the new value.
  uint64_t increment(const std::string& device_id, uint64_t n = 1);

  uint64_t get(const std::string& device_id) const;
  const std::vector<CounterEntry>& entries() const { return entries_; }

  // Sequence advances once per report attempt batch, never reused.
  uint64_t next_sequence();
  uint64_t sequence() const { return sequence_; }

 private:
  CounterEntry* find(const std::string& device_id);
  const CounterEntry* find(const std::string& device_id) const;

  std::vector<CounterEntry> entries_;
  uint64_t sequence_ = 0;
};

}  // namespace meter
