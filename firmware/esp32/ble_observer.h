// firmware/esp32/ble_observer.h
// Passive NimBLE observer. Watches an operator-owned link and surfaces GATT writes to the
// matcher. It has no write, no notify-back and no connect-to-appliance path.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "event_matcher.h"

namespace meter {

struct ObservedWrite {
  std::string peer_addr;   // "aa:bb:cc:dd:ee:ff"
  Uuid128 service;
  Uuid128 characteristic;
  const uint8_t* payload = nullptr;
  size_t payload_len = 0;
};

using WriteCallback = std::function<void(const ObservedWrite&)>;

class BleObserver {
 public:
  // matcher is borrowed, must outlive the observer.
  void configure(const EventMatcher* matcher, WriteCallback on_write);

  // Starts the NimBLE host task and a passive scan. Returns once the host is up.
  int start();
  void stop();

  bool running() const { return running_; }

  // Invoked by the ATT path with one complete, reassembled value.
  void emit(const ObservedWrite& w);

 private:
  const EventMatcher* matcher_ = nullptr;
  WriteCallback on_write_;
  bool running_ = false;
};

}  // namespace meter
