// firmware/esp32/storage_nvs.cpp
// Counter and event log survive reboot and power loss. The log is append-only: slots are
// written once and never edited. The ring overwrites the oldest slot when full, which is
// bounded loss of old history, not mutation of a record that is still present. No delete
// path is exposed anywhere in this file.
#include "storage_nvs.h"

#include <cstring>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "config.h"

namespace meter {

static const char* TAG = "storage";

static void slot_key(char out[16], uint32_t slot) {
  snprintf(out, 16, "e%04lu", (unsigned long)(slot % kEventLogCapacity));
}

static void counter_key(char out[16], const std::string& device_id) {
  // NVS keys cap at 15 chars, so hash the device id into a short stable key.
  uint32_t h = 2166136261u;
  for (char c : device_id) {
    h ^= static_cast<uint8_t>(c);
    h *= 16777619u;
  }
  snprintf(out, 16, "c%08lx", (unsigned long)h);
}

esp_err_t Storage::init() {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    // Only reached on a partition the firmware cannot parse at all.
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  if (err != ESP_OK) return err;

  nvs_handle_t h;
  err = nvs_open(kNvsNamespace, NVS_READWRITE, &h);
  if (err != ESP_OK) return err;

  uint32_t head = 0;
  esp_err_t r = nvs_get_u32(h, kNvsKeyLogHead, &head);
  if (r == ESP_ERR_NVS_NOT_FOUND) head = 0;
  head_ = head;
  nvs_close(h);

  ready_ = true;
  ESP_LOGI(TAG, "nvs ready, log head %lu", (unsigned long)head_);
  return ESP_OK;
}

esp_err_t Storage::save_counter(const std::string& device_id, uint64_t count) {
  if (!ready_) return ESP_ERR_INVALID_STATE;
  nvs_handle_t h;
  esp_err_t err = nvs_open(kNvsNamespace, NVS_READWRITE, &h);
  if (err != ESP_OK) return err;

  char key[16];
  counter_key(key, device_id);

  uint64_t existing = 0;
  if (nvs_get_u64(h, key, &existing) == ESP_OK && count < existing) {
    // Refuse to write a lower value. Monotonicity is enforced at the storage layer too,
    // so a bug upstream cannot roll the persisted count back.
    ESP_LOGE(TAG, "refusing rollback %llu -> %llu", (unsigned long long)existing,
             (unsigned long long)count);
    nvs_close(h);
    return ESP_ERR_INVALID_ARG;
  }

  err = nvs_set_u64(h, key, count);
  if (err == ESP_OK) err = nvs_commit(h);
  nvs_close(h);
  return err;
}

esp_err_t Storage::load_counter(const std::string& device_id, uint64_t& out) const {
  nvs_handle_t h;
  esp_err_t err = nvs_open(kNvsNamespace, NVS_READONLY, &h);
  if (err != ESP_OK) return err;
  char key[16];
  counter_key(key, device_id);
  err = nvs_get_u64(h, key, &out);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    out = 0;
    err = ESP_OK;
  }
  nvs_close(h);
  return err;
}

esp_err_t Storage::save_sequence(uint64_t seq) {
  nvs_handle_t h;
  esp_err_t err = nvs_open(kNvsNamespace, NVS_READWRITE, &h);
  if (err != ESP_OK) return err;
  uint64_t existing = 0;
  if (nvs_get_u64(h, kNvsKeySeq, &existing) == ESP_OK && seq < existing) {
    nvs_close(h);
    return ESP_ERR_INVALID_ARG;  // sequence never goes backwards either
  }
  err = nvs_set_u64(h, kNvsKeySeq, seq);
  if (err == ESP_OK) err = nvs_commit(h);
  nvs_close(h);
  return err;
}

esp_err_t Storage::load_sequence(uint64_t& out) const {
  nvs_handle_t h;
  esp_err_t err = nvs_open(kNvsNamespace, NVS_READONLY, &h);
  if (err != ESP_OK) return err;
  err = nvs_get_u64(h, kNvsKeySeq, &out);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    out = 0;
    err = ESP_OK;
  }
  nvs_close(h);
  return err;
}

esp_err_t Storage::append_event(const LogEntry& e) {
  if (!ready_) return ESP_ERR_INVALID_STATE;
  nvs_handle_t h;
  esp_err_t err = nvs_open(kNvsNamespace, NVS_READWRITE, &h);
  if (err != ESP_OK) return err;

  char key[16];
  slot_key(key, head_);
  err = nvs_set_blob(h, key, &e, sizeof(LogEntry));
  if (err == ESP_OK) {
    head_ += 1;
    err = nvs_set_u32(h, kNvsKeyLogHead, head_);
  }
  if (err == ESP_OK) err = nvs_commit(h);
  nvs_close(h);
  return err;
}

esp_err_t Storage::read_recent(std::vector<LogEntry>& out, size_t max_entries) const {
  out.clear();
  nvs_handle_t h;
  esp_err_t err = nvs_open(kNvsNamespace, NVS_READONLY, &h);
  if (err != ESP_OK) return err;

  size_t n = head_ < max_entries ? head_ : max_entries;
  if (n > kEventLogCapacity) n = kEventLogCapacity;

  for (size_t i = 0; i < n; ++i) {
    uint32_t slot = head_ - 1 - static_cast<uint32_t>(i);
    char key[16];
    slot_key(key, slot);
    LogEntry e{};
    size_t len = sizeof(LogEntry);
    if (nvs_get_blob(h, key, &e, &len) == ESP_OK && len == sizeof(LogEntry)) {
      out.push_back(e);
    }
  }
  nvs_close(h);
  return ESP_OK;
}

esp_err_t Storage::load_signing_key(uint8_t out[32]) const {
  nvs_handle_t h;
  esp_err_t err = nvs_open(kNvsNamespace, NVS_READONLY, &h);
  if (err != ESP_OK) return err;
  size_t len = 32;
  err = nvs_get_blob(h, kNvsKeySignKey, out, &len);
  nvs_close(h);
  if (err == ESP_OK && len != 32) return ESP_ERR_INVALID_SIZE;
  return err;
}

}  // namespace meter
