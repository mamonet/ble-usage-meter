// firmware/esp32/counter.cpp
// The counter only ever goes up. A decrease is a bug, not a feature: the backend treats a
// count lower than the last accepted one as a rollback and rejects the report, so silently
// letting a count drop here would break every downstream check. There is deliberately no
// decrement, reset, or set-to API.
#include "counter.h"

#include "esp_log.h"

namespace meter {

static const char* TAG = "counter";

CounterEntry* Counter::find(const std::string& device_id) {
  for (CounterEntry& e : entries_) {
    if (e.device_id == device_id) return &e;
  }
  return nullptr;
}

const CounterEntry* Counter::find(const std::string& device_id) const {
  for (const CounterEntry& e : entries_) {
    if (e.device_id == device_id) return &e;
  }
  return nullptr;
}

void Counter::restore(const std::string& device_id, uint64_t count) {
  CounterEntry* e = find(device_id);
  if (e == nullptr) {
    entries_.push_back(CounterEntry{device_id, count});
    return;
  }
  if (count < e->count) {
    // Stale or corrupt persisted value. Keep the higher one.
    ESP_LOGW(TAG, "ignoring restore of %llu below live %llu for %s",
             (unsigned long long)count, (unsigned long long)e->count, device_id.c_str());
    return;
  }
  e->count = count;
}

void Counter::restore_sequence(uint64_t seq) {
  if (seq > sequence_) sequence_ = seq;
}

uint64_t Counter::increment(const std::string& device_id, uint64_t n) {
  CounterEntry* e = find(device_id);
  if (e == nullptr) {
    entries_.push_back(CounterEntry{device_id, n});
    return n;
  }
  // Saturate rather than wrap. A wrap would present as a rollback.
  if (e->count > UINT64_MAX - n) {
    e->count = UINT64_MAX;
  } else {
    e->count += n;
  }
  return e->count;
}

uint64_t Counter::get(const std::string& device_id) const {
  const CounterEntry* e = find(device_id);
  return e == nullptr ? 0 : e->count;
}

uint64_t Counter::next_sequence() {
  ++sequence_;
  return sequence_;
}

}  // namespace meter
