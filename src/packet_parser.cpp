#include "packet_parser.h"
#include <iostream>

using namespace std;

// Network packets store numbers in Big Endian format
// (most significant byte first)
// x86 CPUs use Little Endian
// So we need to swap bytes when reading

uint16_t PacketParser::readUint16BE(const uint8_t* ptr) const
{
    return ((uint16_t)ptr[0] << 8) | ptr[1];
}

uint32_t PacketParser::readUint32BE(const uint8_t* ptr) const
{
    return ((uint32_t)ptr[0] << 24) |
           ((uint32_t)ptr[1] << 16) |
           ((uint32_t)ptr[2] << 8)  |
            ptr[3];
}

bool PacketParser::detectTLS(const uint8_t* payload,
                              uint16_t len) const
{
    if (len < 3) return false;

    // TLS record starts with:
    // byte 0: content type (22 = handshake)
    // byte 1: major version (3)
    // byte 2: minor version (1=TLS1.0, 2=TLS1.1, 3=TLS1.2, 4=TLS1.3)
    return (payload[0] == 22 &&
            payload[1] == 3  &&
            payload[2] >= 1  &&
            payload[2] <= 4);
}

ParsedPacket PacketParser::parse(const RawPacket& raw) const
{
    ParsedPacket pkt;
    pkt.timestamp_ms = raw.timestamp_ms;
    pkt.packet_len   = raw.original_len;

    const uint8_t* data = raw.data.data();
    size_t         len  = raw.data.size();

    // ── Ethernet Header (14 bytes) ──
    // [6 bytes dst mac][6 bytes src mac][2 bytes ethertype]
    if (len < 14) return pkt;  // too short

    uint16_t ethertype = readUint16BE(data + 12);

    // Handle both IPv4 and IPv6
bool is_ipv4 = (ethertype == 0x0800);
bool is_ipv6 = (ethertype == 0x86DD);

if (!is_ipv4 && !is_ipv6) return pkt;

if (is_ipv6) {
    // IPv6 Header is fixed 40 bytes
    // [version+tc+flow:4][payload_len:2][next_header:1]
    // [hop_limit:1][src_addr:16][dst_addr:16]
    const uint8_t* ip6 = data + 14;
    size_t ip6_len = len - 14;

    if (ip6_len < 40) return pkt;

    pkt.protocol = ip6[6];  // next header

    // Use last 4 bytes of src/dst as IPv4-like ID
    pkt.src_ip = readUint32BE(ip6 + 8  + 12);
    pkt.dst_ip = readUint32BE(ip6 + 24 + 12);

    // Transport starts after 40 byte IPv6 header
    const uint8_t* transport = ip6 + 40;
    size_t transport_len = ip6_len - 40;

    if (pkt.protocol == 6) {
        // TCP
        if (transport_len < 20) return pkt;
        pkt.src_port = readUint16BE(transport);
        pkt.dst_port = readUint16BE(transport + 2);
        uint8_t tcp_hdr_len =
            ((transport[12] >> 4) & 0x0F) * 4;
        if (transport_len < tcp_hdr_len) return pkt;
        pkt.payload     = transport + tcp_hdr_len;
        pkt.payload_len = (uint16_t)(
            transport_len - tcp_hdr_len);
    } else if (pkt.protocol == 17) {
        // UDP
        if (transport_len < 8) return pkt;
        pkt.src_port    = readUint16BE(transport);
        pkt.dst_port    = readUint16BE(transport + 2);
        pkt.payload     = transport + 8;
        pkt.payload_len = (uint16_t)(
            transport_len - 8);
    } else {
        return pkt;
    }

    if (pkt.payload && pkt.payload_len > 0) {
        pkt.is_tls = detectTLS(
            pkt.payload, pkt.payload_len);
    }

    pkt.valid = true;
    return pkt;
}

    // ── IP Header ──
    const uint8_t* ip = data + 14;
    size_t ip_len = len - 14;

    if (ip_len < 20) return pkt;  // too short for IP header

    // IP header length is in lower 4 bits of first byte × 4
    uint8_t ihl        = (ip[0] & 0x0F) * 4;
    pkt.protocol       = ip[9];
    pkt.src_ip         = readUint32BE(ip + 12);
    pkt.dst_ip         = readUint32BE(ip + 16);

    if (ip_len < ihl) return pkt;

    // ── TCP/UDP Header ──
    const uint8_t* transport = ip + ihl;
    size_t transport_len = ip_len - ihl;

    if (pkt.protocol == 6) {
        // TCP Header (minimum 20 bytes)
        if (transport_len < 20) return pkt;

        pkt.src_port = readUint16BE(transport);
        pkt.dst_port = readUint16BE(transport + 2);

        // TCP header length in upper 4 bits of byte 12 × 4
        uint8_t tcp_hdr_len = ((transport[12] >> 4) & 0x0F) * 4;
        if (transport_len < tcp_hdr_len) return pkt;

        pkt.payload     = transport + tcp_hdr_len;
        pkt.payload_len = (uint16_t)(transport_len - tcp_hdr_len);

    } else if (pkt.protocol == 17) {
        // UDP Header (8 bytes fixed)
        if (transport_len < 8) return pkt;

        pkt.src_port    = readUint16BE(transport);
        pkt.dst_port    = readUint16BE(transport + 2);
        pkt.payload     = transport + 8;
        pkt.payload_len = (uint16_t)(transport_len - 8);

    } else {
        return pkt;  // not TCP or UDP
    }

    // ── Detect TLS ──
    if (pkt.payload && pkt.payload_len > 0) {
        pkt.is_tls = detectTLS(pkt.payload, pkt.payload_len);
    }

    pkt.valid = true;
    return pkt;
}

FiveTuple PacketParser::extractTuple(const ParsedPacket& pkt) const
{
    FiveTuple t;
    t.src_ip   = pkt.src_ip;
    t.dst_ip   = pkt.dst_ip;
    t.src_port = pkt.src_port;
    t.dst_port = pkt.dst_port;
    t.protocol = pkt.protocol;
    return t;
}