#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "types.h"
#include "pcap_reader.h"
#include <cstdint>

struct ParsedPacket {
    bool valid    = false;

    // IP
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint8_t  protocol = 0;

    // Transport
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    // TCP-specific (for stream reassembly)
    uint32_t tcp_seq   = 0;
    uint8_t  tcp_flags = 0;

    // Payload
    const uint8_t* payload     = nullptr;
    uint16_t       payload_len = 0;

    // Metadata
    uint32_t packet_len   = 0;
    double   timestamp_ms = 0.0;
    bool     is_tls       = false;

    // Flag helpers
    bool isSYN() const { return (tcp_flags & 0x02) != 0; }
    bool isFIN() const { return (tcp_flags & 0x01) != 0; }
    bool isRST() const { return (tcp_flags & 0x04) != 0; }
    bool isACK() const { return (tcp_flags & 0x10) != 0; }
};

class PacketParser {
public:
    ParsedPacket parse(const RawPacket& raw) const;
    FiveTuple    extractTuple(const ParsedPacket& pkt) const;

private:
    uint16_t readUint16BE(const uint8_t* ptr) const;
    uint32_t readUint32BE(const uint8_t* ptr) const;
    bool     detectTLS(const uint8_t* payload,
                       uint16_t len) const;
};

#endif // PACKET_PARSER_H