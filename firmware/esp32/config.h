// firmware/esp32/config.h
// Build-time config. All values are placeholders; override per deployment.
// Scope: this firmware observes and counts activity on hardware the operator owns.
// It never sends, injects, replays or forges a command to an appliance.
#pragma once

#include <cstddef>
#include <cstdint>

namespace meter {

// Backend endpoint for signed usage reports. REPLACE_ME.
constexpr const char* kReportEndpoint = "https://REPLACE_ME.example.invalid/v1/reports";

// Identifier for this meter unit. REPLACE_ME. Not a vendor identifier.
constexpr const char* kMeterDeviceId = "REPLACE_ME-meter-0001";

// Seconds between report attempts. The counter, not the report, is the source of truth.
constexpr uint32_t kReportIntervalSec = 300;

// Retry backoff for the reporter, seconds.
constexpr uint32_t kRetryBaseSec = 5;
constexpr uint32_t kRetryMaxSec  = 600;
constexpr uint32_t kRetryMaxAttempts = 8;

// NVS namespace and keys.
constexpr const char* kNvsNamespace  = "ble_meter";
constexpr const char* kNvsKeyCounter = "counter";
constexpr const char* kNvsKeySeq     = "seq";
constexpr const char* kNvsKeyLogHead = "loghead";
constexpr const char* kNvsKeySignKey = "ed25519_sk";   // provisioned at setup, never compiled in

// Append-only event log ring, entries retained in NVS.
constexpr size_t kEventLogCapacity = 512;

// Largest reassembled ATT payload we will attempt to match.
constexpr size_t kMaxAttPayload = 512;

// TLS root bundle name if pinning is used. REPLACE_ME.
constexpr const char* kReportCaCertPem = nullptr;

}  // namespace meter
