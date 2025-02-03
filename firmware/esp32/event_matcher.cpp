// firmware/esp32/event_matcher.cpp
// Matching is exact and explicit. No fuzzy matching, no heuristics, no "close enough".
// An unmatched write is reported as unknown so the operator can inspect it; guessing it
// into a count would make the meter lie, which is the one thing it must not do.
#include "event_matcher.h"

#include <cstring>

namespace meter {

bool Uuid128::operator==(const Uuid128& o) const {
  return std::memcmp(b, o.b, sizeof(b)) == 0;
}

// Bluetooth Base UUID 00000000-0000-1000-8000-00805F9B34FB.
static const uint8_t kBaseUuid[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
                                      0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB};

bool uuid_from_16(uint16_t short_uuid, Uuid128& out) {
  std::memcpy(out.b, kBaseUuid, 16);
  out.b[2] = static_cast<uint8_t>((short_uuid >> 8) & 0xFF);
  out.b[3] = static_cast<uint8_t>(short_uuid & 0xFF);
  return true;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Accepts "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" or a bare 4-hex short form.
bool uuid_from_string(const char* s, Uuid128& out) {
  if (s == nullptr) return false;
  size_t n = std::strlen(s);

  if (n == 4) {
    uint16_t v = 0;
    for (size_t i = 0; i < 4; ++i) {
      int d = hex_nibble(s[i]);
      if (d < 0) return false;
      v = static_cast<uint16_t>((v << 4) | d);
    }
    return uuid_from_16(v, out);
  }

  size_t written = 0;
  int hi = -1;
  for (size_t i = 0; i < n; ++i) {
    if (s[i] == '-') continue;
    int d = hex_nibble(s[i]);
    if (d < 0) return false;
    if (hi < 0) {
      hi = d;
    } else {
      if (written >= 16) return false;
      out.b[written++] = static_cast<uint8_t>((hi << 4) | d);
      hi = -1;
    }
  }
  return hi < 0 && written == 16;
}

void EventMatcher::add_rule(const EventRule& rule) { rules_.push_back(rule); }

void EventMatcher::clear() { rules_.clear(); }

MatchResult EventMatcher::match(const Uuid128& service,
                                const Uuid128& characteristic,
                                const uint8_t* payload,
                                size_t len) const {
  MatchResult r;
  if (payload == nullptr && len != 0) return r;

  for (const EventRule& rule : rules_) {
    if (!(rule.service == service)) continue;
    if (!(rule.characteristic == characteristic)) continue;

    // Empty prefix means any payload on this characteristic counts.
    if (!rule.prefix.empty()) {
      if (len < rule.prefix.size()) continue;
      // Exact byte compare. Not a string compare: payloads are binary and may hold NULs.
      if (std::memcmp(payload, rule.prefix.data(), rule.prefix.size()) != 0) continue;
    }

    r.matched = true;
    r.event = rule.event;
    return r;
  }

  // Fall through: unknown. Caller logs it verbatim, counts nothing.
  return r;
}

}  // namespace meter
