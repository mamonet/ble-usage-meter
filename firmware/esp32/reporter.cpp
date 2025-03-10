// firmware/esp32/reporter.cpp
// The counter in NVS is the source of truth; a report is a derived snapshot of it. That is
// what makes retries safe:
//  - A failed POST loses nothing. The count is already persisted; the next report carries
//    the same or a higher cumulative value.
//  - A duplicate POST double-counts nothing. Reports carry an absolute cumulative count,
//    not a delta, so the backend takes max() and a replayed report is a no-op. The sequence
//    number lets the backend reject a rolled-back or stale one outright.
// Nothing here mutates the counter. Delivery state must never feed back into measurement.
#include "reporter.h"

#include <cstdio>
#include <cstring>

#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"

#include "config.h"

namespace meter {

static const char* TAG = "reporter";

static std::string b64(const uint8_t* data, size_t len) {
  size_t out_len = 4 * ((len + 2) / 3) + 1;
  std::string out(out_len, '\0');
  size_t written = 0;
  if (mbedtls_base64_encode(reinterpret_cast<unsigned char*>(&out[0]), out_len, &written,
                            data, len) != 0) {
    return std::string();
  }
  out.resize(written);
  return out;
}

void Reporter::configure(const char* endpoint, const Signer* signer) {
  endpoint_ = endpoint;
  signer_ = signer;
}

std::string Reporter::build_body(const ReportTuple& r, const uint8_t sig[64]) const {
  // JSON is transport only. The signature covers canonical_bytes(), not this text, so
  // whitespace or key order here cannot affect verification.
  char buf[512];
  int n = snprintf(buf, sizeof(buf),
                   "{\"device_id\":\"%s\",\"count\":%llu,\"sequence\":%llu,"
                   "\"window_start\":%llu,\"window_end\":%llu,\"sig\":\"%s\"}",
                   r.device_id.c_str(), (unsigned long long)r.count,
                   (unsigned long long)r.sequence, (unsigned long long)r.window_start,
                   (unsigned long long)r.window_end, b64(sig, 64).c_str());
  if (n < 0) return std::string();
  return std::string(buf, static_cast<size_t>(n < (int)sizeof(buf) ? n : sizeof(buf) - 1));
}

ReportResult Reporter::post(const std::string& device_id, uint64_t count, uint64_t sequence,
                            uint64_t window_start, uint64_t window_end) {
  ReportResult res;
  if (endpoint_ == nullptr || signer_ == nullptr || !signer_->ready()) {
    ESP_LOGE(TAG, "reporter not configured");
    return res;
  }

  ReportTuple r{device_id, count, sequence, window_start, window_end};
  uint8_t sig[64];
  if (!signer_->sign(r, sig)) {
    ESP_LOGE(TAG, "signing failed");
    return res;
  }
  std::string body = build_body(r, sig);

  uint32_t delay_s = kRetryBaseSec;
  for (uint32_t attempt = 1; attempt <= kRetryMaxAttempts; ++attempt) {
    res.attempts = attempt;

    esp_http_client_config_t cfg = {};
    cfg.url = endpoint_;
    cfg.method = HTTP_METHOD_POST;
    cfg.timeout_ms = 10000;
    cfg.cert_pem = kReportCaCertPem;

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == nullptr) return res;

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body.c_str(), body.size());

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
      res.http_status = esp_http_client_get_status_code(client);
      esp_http_client_cleanup(client);

      if (res.http_status >= 200 && res.http_status < 300) {
        res.posted = true;
        return res;
      }
      if (res.http_status >= 400 && res.http_status < 500) {
        // Rejected on content, not transport. Retrying the identical body will not help.
        // The count stays in NVS regardless; the operator investigates.
        ESP_LOGE(TAG, "report rejected %d, not retrying", res.http_status);
        return res;
      }
    } else {
      ESP_LOGW(TAG, "post failed: %s", esp_err_to_name(err));
      esp_http_client_cleanup(client);
    }

    if (attempt < kRetryMaxAttempts) {
      ESP_LOGI(TAG, "retry %lu in %lus", (unsigned long)attempt, (unsigned long)delay_s);
      vTaskDelay(pdMS_TO_TICKS(delay_s * 1000));
      delay_s = delay_s * 2 > kRetryMaxSec ? kRetryMaxSec : delay_s * 2;
    }
  }

  // Give up for this window. Nothing is lost: the next window re-sends the cumulative count.
  return res;
}

}  // namespace meter
