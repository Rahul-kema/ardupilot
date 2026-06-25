#pragma once
/*
   KFT DGCA Compliance - GCS Authentication
   CSUAS Clause 7 - GCS Locking via HMAC Challenge-Response
 
   Drone Model: MOINA
   Cert ref: KFT/MOINA/v1.0
 
   DO NOT modify without recertification.
*/
 
#include <AP_HAL/AP_HAL.h>
#include <stdint.h>
#include <string.h>
 
#define KFT_NUM_APPS 2
#define KFT_KEY_LEN 32
#define KFT_CHALLENGE_LEN 32
#define KFT_HMAC_TRUNC_LEN 24
 
// Timeouts
#define KFT_HEARTBEAT_TIMEOUT_MS 10000    // 10 seconds without heartbeat = link lost
#define KFT_CHALLENGE_TIMEOUT_MS 10000   // 10 seconds to respond to challenge
 
struct kft_app_entry {
    uint8_t app_id;
    const char *name;
    uint8_t secret[KFT_KEY_LEN];
};
 
// ===== REPLACE THESE WITH YOUR ACTUAL GENERATED KEYS =====
static const struct kft_app_entry kft_apps[KFT_NUM_APPS] = {
    {
        1, "KFT_GCS_Android",
        { 0x67,0x2d,0xce,0xf0,0x6d,0x87,0x64,0x4d,
          0x6e,0xac,0xfe,0x42,0x29,0x73,0x80,0x06,
          0x68,0xf2,0xed,0x18,0x5e,0x59,0x2e,0xc9,
          0xea,0x2a,0xcb,0xca,0x92,0xb8,0x02,0x21 }
    },
    {
        2, "KFT_Configurator_Win",
        { 0xfb,0x91,0xd1,0x2d,0x97,0x43,0x5e,0x08,
          0x1e,0x65,0xa9,0xb7,0x8b,0xb8,0x4a,0x88,
          0x30,0x9b,0xd6,0x3b,0xc5,0x9a,0x60,0xda,
          0xa9,0x83,0x73,0x34,0x83,0xa0,0xc6,0x9d }
    },
};
 
class KFT_GCSAuth {
public:
    // State
    static bool authenticated;
    static uint8_t authenticated_app_id;
    static uint8_t challenge[KFT_CHALLENGE_LEN];
    static bool challenge_valid;
    static uint32_t last_heartbeat_ms;
    static uint32_t challenge_issued_ms;
 
    // Generate a new random challenge
    static void generate_challenge();
 
    // Verify HMAC response from app
    static bool verify_hmac(uint8_t app_id, const uint8_t *received_hmac, uint8_t hmac_len);
 
    // Lookup app by ID
    static const kft_app_entry* find_app(uint8_t app_id);
 
    // Query state
    static bool is_authenticated() { return authenticated; }
 
    // Track heartbeats for timeout detection
    static void note_heartbeat();
 
    // Check for link loss or challenge expiry
    static void check_timeout();
 
    // Reset on disconnect
    static void reset();
 
    // HMAC-SHA256 computation
    static void hmac_sha256(const uint8_t *key, uint8_t key_len,
                            const uint8_t *msg, uint8_t msg_len,
                            uint8_t *output);

// POST: send registered checksums to GCS after authentication
    static void send_post_status();

};
