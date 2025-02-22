// firmware/esp32/ble_observer.cpp  (v1)
// Passive observation only. The scan is a NimBLE passive scan (no scan requests), and the
// only thing this file does with an observed ATT PDU is hand it to the matcher. There is no
// call into any NimBLE write, notify or connect-initiate API here, deliberately.
#include "ble_observer.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_nimble_hci.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

#include "config.h"

namespace meter {

static const char* TAG = "observer";
static BleObserver* g_self = nullptr;

static void fmt_addr(char out[18], const ble_addr_t& a) {
  snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", a.val[5], a.val[4], a.val[3], a.val[2],
           a.val[1], a.val[0]);
}

// Called by the ATT sniff path for each observed write PDU on a followed connection.
static void handle_att_write(const ble_addr_t& peer, const Uuid128& svc, const Uuid128& chr,
                             const uint8_t* data, size_t len);

static int gap_event(struct ble_gap_event* event, void* arg) {
  (void)arg;
  switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
      // Discovery only. We note that a link exists so the ATT path can follow it.
      // We never send a connect request from here.
      char addr[18];
      fmt_addr(addr, event->disc.addr);
      ESP_LOGD(TAG, "adv from %s rssi %d", addr, event->disc.rssi);
      return 0;
    }
    case BLE_GAP_EVENT_DISC_COMPLETE:
      ESP_LOGI(TAG, "scan window complete, restarting");
      return 0;
    default:
      return 0;
  }
}

static void start_passive_scan() {
  uint8_t own_addr_type = 0;
  int rc = ble_hs_id_infer_auto(0, &own_addr_type);
  if (rc != 0) {
    ESP_LOGE(TAG, "addr infer failed %d", rc);
    return;
  }

  struct ble_gap_disc_params p = {};
  p.passive = 1;         // never emit a scan request
  p.filter_duplicates = 0;
  p.itvl = BLE_GAP_SCAN_ITVL_MS(100);
  p.window = BLE_GAP_SCAN_WIN_MS(100);
  p.limited = 0;

  rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &p, gap_event, nullptr);
  if (rc != 0) ESP_LOGE(TAG, "ble_gap_disc failed %d", rc);
}

static void on_sync() {
  ESP_LOGI(TAG, "host synced");
  start_passive_scan();
}

static void on_reset(int reason) { ESP_LOGW(TAG, "host reset %d", reason); }

static void host_task(void* param) {
  (void)param;
  nimble_port_run();
  nimble_port_freertos_deinit();
}

static void handle_att_write(const ble_addr_t& peer, const Uuid128& svc, const Uuid128& chr,
                             const uint8_t* data, size_t len) {
  if (g_self == nullptr) return;

  ObservedWrite w;
  char addr[18];
  fmt_addr(addr, peer);
  w.peer_addr = addr;
  w.service = svc;
  w.characteristic = chr;
  w.payload = data;
  w.payload_len = len;

  g_self->emit(w);
}

void BleObserver::configure(const EventMatcher* matcher, WriteCallback on_write) {
  matcher_ = matcher;
  on_write_ = std::move(on_write);
}

void BleObserver::emit(const ObservedWrite& w) {
  if (on_write_) on_write_(w);
}

int BleObserver::start() {
  g_self = this;

  esp_err_t err = nimble_port_init();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "nimble_port_init %d", (int)err);
    return -1;
  }

  ble_hs_cfg.sync_cb = on_sync;
  ble_hs_cfg.reset_cb = on_reset;

  nimble_port_freertos_init(host_task);
  running_ = true;
  return 0;
}

void BleObserver::stop() {
  if (!running_) return;
  ble_gap_disc_cancel();
  nimble_port_stop();
  running_ = false;
  g_self = nullptr;
}

}  // namespace meter
