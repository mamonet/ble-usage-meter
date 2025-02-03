// firmware/esp32/event_matcher.h
// Maps an observed GATT write to a named event. Observation only.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace meter {

// 128-bit UUID in big-endian byte order. 16-bit UUIDs are expanded into the base UUID
// before comparison so there is exactly one representation to compare.
struct Uuid128 {
  uint8_t b[16];
  bool operator==(const Uuid128& o) const;
};

bool uuid_from_string(const char* s, Uuid128& out);
bool uuid_from_16(uint16_t short_uuid, Uuid128& out);

// One configured rule. prefix may be empty, meaning "any payload on this characteristic".
struct EventRule {
  Uuid128 service;
  Uuid128 characteristic;
  std::vector<uint8_t> prefix;
  std::string event;
};

// Result of matching. When event is empty the write was not recognised and must be
// recorded as unknown; it is never folded into a counted event.
struct MatchResult {
  bool matched = false;
  std::string event;
};

class EventMatcher {
 public:
  void add_rule(const EventRule& rule);
  void clear();
  size_t rule_count() const { return rules_.size(); }

  // payload must be the fully reassembled ATT value, not a single fragment.
  MatchResult match(const Uuid128& service,
                    const Uuid128& characteristic,
                    const uint8_t* payload,
                    size_t len) const;

 private:
  std::vector<EventRule> rules_;
};

}  // namespace meter
