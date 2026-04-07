#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "types.h"
#include "pcap_reader.h"
#include <cstdint>

// ─────────────────────────────────────────
// Parsed packet — meaningful fields
// extracted from raw bytes
// ─────────────────────────────────────────
struct ParsedPacket {
    // Is this packet valid?
    bool valid = false;

    // IP layer
    uint32_t src_ip  = 0;
    uint32_t dst_ip  = 0;
    uint8_t  protocol = 0;   // 6=TCP, 17=UDP

    // Transport layer
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    // Payload
    const uint8_t* payload     = nullptr;
    uint16_t       payload_len = 0;

    // Metadata
    uint32_t packet_len    = 0;
    double   timestamp_ms  = 0.0;
    bool     is_tls        = false;
};

// ─────────────────────────────────────────
// Parses raw bytes into structured fields
// ─────────────────────────────────────────
class PacketParser {
public:
    // Parse a raw packet into structured fields
    ParsedPacket parse(const RawPacket& raw) const;

    // Extract FiveTuple from parsed packet
    FiveTuple extractTuple(const ParsedPacket& pkt) const;

private:
    // Read big-endian 16-bit value from bytes
    uint16_t readUint16BE(const uint8_t* ptr) const;

    // Read big-endian 32-bit value from bytes
    uint32_t readUint32BE(const uint8_t* ptr) const;

    // Check if payload looks like TLS
    bool detectTLS(const uint8_t* payload,
                   uint16_t len) const;
};

#endif // PACKET_PARSER_H