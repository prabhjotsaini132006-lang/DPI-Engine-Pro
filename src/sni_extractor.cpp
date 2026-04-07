#include "sni_extractor.h"
#include <cstring>

using namespace std;

string SNIExtractor::extract(const uint8_t* payload,
                              uint16_t len) const
{
    // Minimum TLS ClientHello size check
    // TLS Record:    5 bytes header
    // Handshake:     4 bytes header
    // ClientHello:   38 bytes minimum
    if (len < 47) return "";

    // ── TLS Record Header ──
    // byte 0: content type (22 = handshake)
    if (payload[0] != 22) return "";

    // ── Handshake Header ──
    // byte 5: handshake type (1 = ClientHello)
    if (payload[5] != 1) return "";

    // ── ClientHello ──
    // byte 9-10: legacy version
    // byte 11-42: random (32 bytes)
    // byte 43: session ID length
    uint8_t session_id_len = payload[43];

    // Move past session ID
    size_t pos = 44 + session_id_len;
    if (pos + 2 > len) return "";

    // Cipher suites length
    uint16_t cipher_len = ((uint16_t)payload[pos] << 8)
                         | payload[pos+1];
    pos += 2 + cipher_len;
    if (pos + 1 > len) return "";

    // Compression methods length
    uint8_t comp_len = payload[pos];
    pos += 1 + comp_len;
    if (pos + 2 > len) return "";

    // Extensions length
    uint16_t ext_total_len = ((uint16_t)payload[pos] << 8)
                            | payload[pos+1];
    pos += 2;

    if (pos + ext_total_len > len) return "";

    // Parse extensions
    return parseExtensions(payload + pos, ext_total_len);
}

string SNIExtractor::parseExtensions(const uint8_t* data,
                                      uint16_t len) const
{
    size_t pos = 0;

    while (pos + 4 <= len) {
        // Extension type (2 bytes)
        uint16_t ext_type = ((uint16_t)data[pos] << 8)
                           | data[pos+1];
        pos += 2;

        // Extension length (2 bytes)
        uint16_t ext_len = ((uint16_t)data[pos] << 8)
                          | data[pos+1];
        pos += 2;

        if (pos + ext_len > len) break;

        // SNI extension type = 0x0000
        if (ext_type == 0x0000 && ext_len > 5) {
            // SNI list length (2 bytes) → skip
            // SNI type (1 byte)         → skip
            // SNI name length (2 bytes)
            uint16_t name_len = ((uint16_t)data[pos+3] << 8)
                               | data[pos+4];

            if (pos + 5 + name_len <= len) {
                // Extract the domain name string
                return string((const char*)(data + pos + 5),
                              name_len);
            }
        }

        pos += ext_len;
    }

    return "";  // SNI not found
}