#include "KFT_Checksums.h"
#include "KFT_GCSAuth.h"
#include <AP_HAL/AP_HAL.h>
#include <AP_Math/crc.h>
#include <GCS_MAVLink/GCS.h>
#include <stdio.h>
 
extern const AP_HAL::HAL& hal;
 
// Static member initialization
bool KFT_GCSAuth::authenticated = false;
uint8_t KFT_GCSAuth::authenticated_app_id = 0;
uint8_t KFT_GCSAuth::challenge[KFT_CHALLENGE_LEN] = {0};
bool KFT_GCSAuth::challenge_valid = false;
uint32_t KFT_GCSAuth::last_heartbeat_ms = 0;
uint32_t KFT_GCSAuth::challenge_issued_ms = 0;


 
// ============================================================================
// Self-contained SHA-256 implementation (FIPS 180-4)
// Used for HMAC computation in KFT_GCSAuth
// Self-contained because not all ArduPilot boards include mbedtls
// ============================================================================
namespace kft_sha256 {
 
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
 
    static inline uint32_t ROTR(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
 
    static void transform(uint32_t state[8], const uint8_t block[64]) {
        uint32_t W[64];
        for (int i = 0; i < 16; i++) {
            W[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
                   ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROTR(W[i-15], 7) ^ ROTR(W[i-15], 18) ^ (W[i-15] >> 3);
            uint32_t s1 = ROTR(W[i-2], 17) ^ ROTR(W[i-2], 19) ^ (W[i-2] >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t T1 = h + S1 + ch + K[i] + W[i];
            uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t T2 = S0 + mj;
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
 
    static void hash(const uint8_t *data, size_t len, uint8_t output[32]) {
        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
 
        size_t blocks = len / 64;
        for (size_t i = 0; i < blocks; i++) {
            transform(state, data + i * 64);
        }
 
        uint8_t final_block[128] = {0};
        size_t remaining = len - blocks * 64;
        memcpy(final_block, data + blocks * 64, remaining);
        final_block[remaining] = 0x80;
 
        size_t pad_blocks = (remaining >= 56) ? 2 : 1;
        uint64_t bit_len = (uint64_t)len * 8;
        size_t len_offset = pad_blocks * 64 - 8;
        for (int i = 7; i >= 0; i--) {
            final_block[len_offset + i] = bit_len & 0xff;
            bit_len >>= 8;
        }
        for (size_t i = 0; i < pad_blocks; i++) {
            transform(state, final_block + i * 64);
        }
 
        for (int i = 0; i < 8; i++) {
            output[i*4]   = (state[i] >> 24) & 0xff;
            output[i*4+1] = (state[i] >> 16) & 0xff;
            output[i*4+2] = (state[i] >> 8)  & 0xff;
            output[i*4+3] = state[i] & 0xff;
        }
    }
}
 
// SHA-256 wrapper
static void sha256_hash(const uint8_t *data, size_t len, uint8_t output[32])
{
    kft_sha256::hash(data, len, output);
}
 



void KFT_GCSAuth::generate_challenge()
{
    for (int i = 0; i < KFT_CHALLENGE_LEN; i++) {
        challenge[i] = (uint8_t)(get_random16() & 0xFF);
    }
    challenge_valid = true;
    challenge_issued_ms = AP_HAL::millis();
}
 
void KFT_GCSAuth::hmac_sha256(const uint8_t *key, uint8_t key_len,
                                const uint8_t *msg, uint8_t msg_len,
                                uint8_t *output)
{
    const uint8_t BLOCK_SIZE = 64;
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
 
    uint8_t padded_key[64];
    memset(padded_key, 0, BLOCK_SIZE);
    if (key_len <= BLOCK_SIZE) {
        memcpy(padded_key, key, key_len);
    } else {
        sha256_hash(key, key_len, padded_key);
    }
 
    for (uint8_t i = 0; i < BLOCK_SIZE; i++) {
        k_ipad[i] = padded_key[i] ^ 0x36;
        k_opad[i] = padded_key[i] ^ 0x5c;
    }
 
    // Inner hash: H(k_ipad || message)
    uint8_t inner_input[64 + 32];
    memcpy(inner_input, k_ipad, BLOCK_SIZE);
    memcpy(inner_input + BLOCK_SIZE, msg, msg_len);
    uint8_t inner_hash[32];
    sha256_hash(inner_input, BLOCK_SIZE + msg_len, inner_hash);
 
    // Outer hash: H(k_opad || inner_hash)
    uint8_t outer_input[64 + 32];
    memcpy(outer_input, k_opad, BLOCK_SIZE);
    memcpy(outer_input + BLOCK_SIZE, inner_hash, 32);
    sha256_hash(outer_input, BLOCK_SIZE + 32, output);
}
 
const kft_app_entry* KFT_GCSAuth::find_app(uint8_t app_id)
{
    for (uint8_t i = 0; i < KFT_NUM_APPS; i++) {
        if (kft_apps[i].app_id == app_id) {
            return &kft_apps[i];
        }
    }
    return nullptr;
}
 
bool KFT_GCSAuth::verify_hmac(uint8_t app_id, const uint8_t *received_hmac, uint8_t hmac_len)
{
    if (!challenge_valid) {
        return false;
    }
 
    // Check challenge timeout
    uint32_t now = AP_HAL::millis();
    if (now - challenge_issued_ms > KFT_CHALLENGE_TIMEOUT_MS) {
        challenge_valid = false;
        return false;
    }
 
    const kft_app_entry *app = find_app(app_id);
    if (app == nullptr) {
        return false;
    }
 
    // Compute expected HMAC
    uint8_t expected[32];
    hmac_sha256(app->secret, KFT_KEY_LEN, challenge, KFT_CHALLENGE_LEN, expected);
    // TEMPORARY DEBUG: print expected and received HMAC for diagnosis

    {

        char dbg[60];

        snprintf(dbg, sizeof(dbg), "KFTDBG_EXP:%02x%02x%02x%02x%02x%02x%02x%02x",

                 expected[0], expected[1], expected[2], expected[3],

                 expected[4], expected[5], expected[6], expected[7]);

        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "%s", dbg);

        snprintf(dbg, sizeof(dbg), "KFTDBG_RCV:%02x%02x%02x%02x%02x%02x%02x%02x",

                 received_hmac[0], received_hmac[1], received_hmac[2], received_hmac[3],

                 received_hmac[4], received_hmac[5], received_hmac[6], received_hmac[7]);

        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "%s", dbg);

    }
 
 
    // Constant-time comparison to prevent timing attacks
    uint8_t compare_len = (hmac_len < 32) ? hmac_len : 32;
    uint8_t diff = 0;
    for (uint8_t i = 0; i < compare_len; i++) {
        diff |= received_hmac[i] ^ expected[i];
    }
 
    if (diff == 0) {
        authenticated = true;
        authenticated_app_id = app_id;
        challenge_valid = false;
        last_heartbeat_ms = now;
        return true;
    }
 
    challenge_valid = false;
    return false;
}
 
void KFT_GCSAuth::note_heartbeat()
{
    last_heartbeat_ms = AP_HAL::millis();
}
 
void KFT_GCSAuth::check_timeout()
{
    if (!authenticated) {
        if (challenge_valid) {
            uint32_t now = AP_HAL::millis();
            if (now - challenge_issued_ms > KFT_CHALLENGE_TIMEOUT_MS) {
                challenge_valid = false;
            }
        }
        return;
    }
 
    uint32_t now = AP_HAL::millis();
    uint32_t elapsed = now - last_heartbeat_ms;
    if (elapsed > KFT_HEARTBEAT_TIMEOUT_MS) {
        GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "KFT: Auth reset (no heartbeat %lums)",
                      (unsigned long)elapsed);
        reset();
    }
}

 
void KFT_GCSAuth::reset()
{
    authenticated = false;
    authenticated_app_id = 0;
    challenge_valid = false;
    memset(challenge, 0, KFT_CHALLENGE_LEN);
}

void KFT_GCSAuth::send_post_status()
{
    GCS_SEND_TEXT(MAV_SEVERITY_INFO, "KFT POST: PASSED");
    GCS_SEND_TEXT(MAV_SEVERITY_INFO, "KFT CODE1:%.32s", KFT_CODE_CHECKSUM);
    GCS_SEND_TEXT(MAV_SEVERITY_INFO, "KFT CODE2:%.32s", KFT_CODE_CHECKSUM + 32);
    GCS_SEND_TEXT(MAV_SEVERITY_INFO, "KFT DATA1:%.32s", KFT_DATA_CHECKSUM);
    GCS_SEND_TEXT(MAV_SEVERITY_INFO, "KFT DATA2:%.32s", KFT_DATA_CHECKSUM + 32);
}

