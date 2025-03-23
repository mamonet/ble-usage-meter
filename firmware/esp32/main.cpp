// firmware/esp32/main.cpp
//
// ble-usage-meter, ESP32 firmware.
//
// Scope: an independent usage meter for BLE hardware the operator owns. It passively
// observes the link between the operator's own phone app and their own appliance, counts
// the writes that correspond to one unit of work, and posts a signed cumulative report.
// It is read-only with respect to device behaviour. There is no code path in this firmware
// that sends, injects, replays or forges a command to an appliance, and none that touches
// vendor credentials. Event signatures are configuration the operator supplies for their
// own device.
#include <cinttypes>
#include <cstring>
#include <string>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "ble_observer.h"
#include "config.h"
#include "counter.h"
#include "event_matcher.h"
#include "reporter.h"
#include "signer.h"
#include "storage_nvs.h"

using namespace meter;

static const char* TAG = "main";

static Storage g_storage;
static Counter g_counter;
static EventMatcher g_matcher;
static Signer g_signer;
static Reporter g_reporter;
static BleObserver g_observer;

// Rules would normally be provisioned alongside the signing key. These UUIDs are obvious
// placeholders, not values observed on any real device.
static void load_placeholder_rules() {
  EventRule r;
  if (!uuid_from_string("00000000-0000-1000-8000-00805f9b34fb", r.service)) return;
  if (!uuid_from_string("11111111-1111-1111-1111-111111111111", r.characteristic)) return;
  r.prefix = {0xAA, 0x01};  // REPLACE_ME with the operator's own observed opcode
  r.event = "work_unit";
  g_matcher.add_rule(r);
}

static void record(const ObservedWrite& w) {
  MatchResult m = g_matcher.match(w.service, w.characteristic, w.payload, w.payload_len);

  LogEntry e{};
  e.seq = g_counter.sequence();
  e.ts_us = esp_timer_get_time();
  std::strncpy(e.device_id, w.peer_addr.c_str(), sizeof(e.device_id) - 1);
  std::strncpy(e.event, m.matched ? m.event.c_str() : "unknown", sizeof(e.event) - 1);
  e.payload_len = static_cast<uint16_t>(w.payload_len);
  std::memcpy(e.payload_head, w.payload,
              w.payload_len < sizeof(e.payload_head) ? w.payload_len
                                                     : sizeof(e.payload_head));
  g_storage.append_event(e);

  if (!m.matched) {
    // Logged for the operator to inspect. Not counted. Never guessed.
    ESP_LOGI(TAG, "unknown write from %s, %u bytes", w.peer_addr.c_str(),
             (unsigned)w.payload_len);
    return;
  }

  uint64_t c = g_counter.increment(w.peer_addr, 1);
  esp_err_t err = g_storage.save_counter(w.peer_addr, c);
  if (err != ESP_OK) ESP_LOGE(TAG, "counter persist failed: %s", esp_err_to_name(err));
  ESP_LOGI(TAG, "%s %s -> %" PRIu64, w.peer_addr.c_str(), m.event.c_str(), c);
}

static void report_task(void* arg) {
  (void)arg;
  uint64_t window_start = 0;

  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(kReportIntervalSec * 1000));

    uint64_t window_end = static_cast<uint64_t>(esp_timer_get_time() / 1000000);
    uint64_t seq = g_counter.next_sequence();
    g_storage.save_sequence(seq);

    for (const CounterEntry& e : g_counter.entries()) {
      ReportResult r = g_reporter.post(e.device_id, e.count, seq, window_start, window_end);
      if (!r.posted) {
        // Nothing to unwind. The count is already durable.
        ESP_LOGW(TAG, "report for %s not delivered after %lu attempts", e.device_id.c_str(),
                 (unsigned long)r.attempts);
      }
    }
    window_start = window_end;
  }
}

extern "C" void app_main(void) {
  ESP_LOGI(TAG, "ble-usage-meter, observe-only");

  ESP_ERROR_CHECK(g_storage.init());

  uint8_t seed[32];
  if (g_storage.load_signing_key(seed) != ESP_OK || !g_signer.load_seed(seed)) {
    // No key provisioned: keep counting locally, refuse to fake a signed report.
    ESP_LOGE(TAG, "no signing key in NVS, reports disabled until provisioned");
  }
  std::memset(seed, 0, sizeof(seed));

  uint64_t seq = 0;
  if (g_storage.load_sequence(seq) == ESP_OK) g_counter.restore_sequence(seq);

  uint64_t c = 0;
  if (g_storage.load_counter(kMeterDeviceId, c) == ESP_OK && c > 0) {
    g_counter.restore(kMeterDeviceId, c);
  }

  load_placeholder_rules();
  ESP_LOGI(TAG, "%u match rules loaded", (unsigned)g_matcher.rule_count());

  g_observer.configure(&g_matcher, record);
  if (g_observer.start() != 0) {
    ESP_LOGE(TAG, "observer failed to start");
    return;
  }

  if (g_signer.ready()) {
    g_reporter.configure(kReportEndpoint, &g_signer);
    xTaskCreate(report_task, "report", 6144, nullptr, 4, nullptr);
  }
}
