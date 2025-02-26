// firmware/esp32/ble_observer.cpp  (final)
// Passive observation only. Passive scan, no scan requests, no connect-initiate, no write
// or notify call into NimBLE anywhere in this file. It reads and reports; that is all.
//
// FIX vs v1
// Defect: a single logical ATT write longer than ATT_MTU-3 arrives as Prepare Write Request
// fragments (and long notifications arrive similarly chunked). v1 matched each fragment
// independently against the configured prefix. The first fragment carries the opcode
// prefix, so it matched, and on some stacks a retransmit or an offset-0 continuation also
// matched, producing two counts for one user action. Every long write was at risk of
// double counting, and worse, a fragment boundary landing inside the prefix meant a real
// event silently matched nothing.
// Fix: buffer fragments per (connection handle, attribute handle) keyed by ATT offset and
// only run the matcher once the value is complete, i.e. on Execute Write or when a
// non-contiguous/short chunk closes the run. One reassembled value in, at most one match
// out.
#include "ble_observer.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include "esp_log.h"
#include "esp_nimble_hci.h"
#include "esp_timer.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

#include "config.h"

namespace meter {

static const char* TAG = "observer";
static BleObserver* g_self = nullptr;

// Drop a half-built value if the peer goes quiet mid-write; otherwise a stale prefix could
// be glued onto the next unrelated write.
static constexpr int64_t kReassemblyTimeoutUs = 5LL * 1000 * 1000;

namespace {

struct Reassembly {
  uint16_t conn_handle = 0;
  uint16_t attr_handle = 0;
  Uuid128 service{};
  Uuid128 characteristic{};
  ble_addr_t peer{};
  std::vector<uint8_t> buf;
  int64_t last_us = 0;
  bool in_use = false;
};

// Small fixed pool. A phone drives one or two concurrent long writes at most.
constexpr size_t kMaxReassembly = 4;
Reassembly g_reasm[kMaxReassembly];

Reassembly* find_slot(uint16_t conn, uint16_t attr) {
  for (auto& r : g_reasm) {
    if (r.in_use && r.conn_handle == conn && r.attr_handle == attr) return &r;
  }
  return nullptr;
}

Reassembly* claim_slot(uint16_t conn, uint16_t attr) {
  int64_t now = esp_timer_get_time();
  for (auto& r : g_reasm) {
    if (r.in_use && now - r.last_us > kReassemblyTimeoutUs) {
      ESP_LOGW(TAG, "dropping stale partial write conn %u attr %u", r.conn_handle,
               r.attr_handle);
      r.in_use = false;
      r.buf.clear();
    }
  }
  for (auto& r : g_reasm) {
    if (!r.in_use) {
      r.in_use = true;
      r.conn_handle = conn;
      r.attr_handle = attr;
      r.buf.clear();
      r.last_us = now;
      return &r;
    }
  }
  return nullptr;
}

}  // namespace

static void fmt_addr(char out[18], const ble_addr_t& a) {
  snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", a.val[5], a.val[4], a.val[3], a.val[2],
           a.val[1], a.val[0]);
}

// Hand one complete value to the callback. Called exactly once per logical write.
static void deliver(Reassembly& r) {
  if (g_self == nullptr || r.buf.empty()) {
    r.in_use = false;
    r.buf.clear();
    return;
  }

  ObservedWrite w;
  char addr[18];
  fmt_addr(addr, r.peer);
  w.peer_addr = addr;
  w.service = r.service;
  w.characteristic = r.characteristic;
  w.payload = r.buf.data();
  w.payload_len = r.buf.size();

  g_self->emit(w);

  r.in_use = false;
  r.buf.clear();
}

// ATT sniff entry point. is_final is true for a Write Request/Command (single PDU) or for
// the Execute Write that terminates a prepared run.
void observer_on_att_fragment(const ble_addr_t& peer, uint16_t conn_handle,
                              uint16_t attr_handle, const Uuid128& svc, const Uuid128& chr,
                              uint16_t offset, const uint8_t* data, size_t len,
                              bool is_final) {
  Reassembly* r = find_slot(conn_handle, attr_handle);

  if (r == nullptr) {
    if (offset != 0) {
      // Continuation with no run in progress: we joined mid-write. Cannot match a partial
      // value, and must not, so record nothing rather than count half an event.
      ESP_LOGW(TAG, "orphan fragment at offset %u, discarded", offset);
      return;
    }
    r = claim_slot(conn_handle, attr_handle);
    if (r == nullptr) {
      ESP_LOGE(TAG, "reassembly pool exhausted");
      return;
    }
    r->peer = peer;
    r->service = svc;
    r->characteristic = chr;
  }

  if (offset != r->buf.size()) {
    // Non-contiguous. Treat the run as broken; do not guess at the gap.
    ESP_LOGW(TAG, "fragment offset %u expected %u, dropping run", offset,
             (unsigned)r->buf.size());
    r->in_use = false;
    r->buf.clear();
    return;
  }

  if (r->buf.size() + len > kMaxAttPayload) {
    ESP_LOGW(TAG, "value over %u bytes, dropping run", (unsigned)kMaxAttPayload);
    r->in_use = false;
    r->buf.clear();
    return;
  }

  r->buf.insert(r->buf.end(), data, data + len);
  r->last_us = esp_timer_get_time();

  // Match only on a complete value. This is the whole point of the fix.
  if (is_final) deliver(*r);
}

static int gap_event(struct ble_gap_event* event, void* arg) {
  (void)arg;
  switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
      char addr[18];
      fmt_addr(addr, event->disc.addr);
      ESP_LOGD(TAG, "adv from %s rssi %d", addr, event->disc.rssi);
      return 0;
    }
    case BLE_GAP_EVENT_DISCONNECT: {
      // Abandon any partial write on that connection.
      for (auto& r : g_reasm) {
        if (r.in_use && r.conn_handle == event->disconnect.conn.conn_handle) {
          r.in_use = false;
          r.buf.clear();
        }
      }
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
  p.passive = 1;
  p.filter_duplicates = 0;
  p.itvl = BLE_GAP_SCAN_ITVL_MS(100);
  p.window = BLE_GAP_SCAN_WIN_MS(100);

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

void BleObserver::configure(const EventMatcher* matcher, WriteCallback on_write) {
  matcher_ = matcher;
  on_write_ = std::move(on_write);
}

void BleObserver::emit(const ObservedWrite& w) {
  if (on_write_) on_write_(w);
}

int BleObserver::start() {
  g_self = this;
  for (auto& r : g_reasm) {
    r.in_use = false;
    r.buf.clear();
  }

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
