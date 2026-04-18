#include "packet_parser.h"
#include <iostream>

using namespace std;

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

    if (len < 14) return pkt;

    uint16_t ethertype = readUint16BE(data + 12);
    bool is_ipv4 = (ethertype == 0x0800);
    bool is_ipv6 = (ethertype == 0x86DD);
    if (!is_ipv4 && !is_ipv6) return pkt;

    // ── IPv6 ──
    if (is_ipv6) {
        const uint8_t* ip6 = data + 14;
        size_t ip6_len = len - 14;
        if (ip6_len < 40) return pkt;

        pkt.protocol = ip6[6];
        pkt.src_ip   = readUint32BE(ip6 + 8  + 12);
        pkt.dst_ip   = readUint32BE(ip6 + 24 + 12);

        const uint8_t* transport = ip6 + 40;
        size_t transport_len = ip6_len - 40;

        if (pkt.protocol == 6) {
            if (transport_len < 20) return pkt;
            pkt.src_port  = readUint16BE(transport);
            pkt.dst_port  = readUint16BE(transport + 2);
            pkt.tcp_seq   = readUint32BE(transport + 4);
            pkt.tcp_flags = transport[13];
            uint8_t tcp_hdr_len = ((transport[12] >> 4) & 0x0F) * 4;
            if (transport_len < tcp_hdr_len) return pkt;
            pkt.payload     = transport + tcp_hdr_len;
            pkt.payload_len = (uint16_t)(transport_len - tcp_hdr_len);
        } else if (pkt.protocol == 17) {
            if (transport_len < 8) return pkt;
            pkt.src_port    = readUint16BE(transport);
            pkt.dst_port    = readUint16BE(transport + 2);
            pkt.payload     = transport + 8;
            pkt.payload_len = (uint16_t)(transport_len - 8);
        } else {
            return pkt;
        }
        if (pkt.payload && pkt.payload_len > 0)
            pkt.is_tls = detectTLS(pkt.payload, pkt.payload_len);
        pkt.valid = true;
        return pkt;
    }

    // ── IPv4 ──
    const uint8_t* ip = data + 14;
    size_t ip_len = len - 14;
    if (ip_len < 20) return pkt;

    uint8_t ihl  = (ip[0] & 0x0F) * 4;
    pkt.protocol = ip[9];
    pkt.src_ip   = readUint32BE(ip + 12);
    pkt.dst_ip   = readUint32BE(ip + 16);
    if (ip_len < ihl) return pkt;

    const uint8_t* transport = ip + ihl;
    size_t transport_len = ip_len - ihl;

    if (pkt.protocol == 6) {
        if (transport_len < 20) return pkt;
        pkt.src_port  = readUint16BE(transport);
        pkt.dst_port  = readUint16BE(transport + 2);
        pkt.tcp_seq   = readUint32BE(transport + 4);
        pkt.tcp_flags = transport[13];
        uint8_t tcp_hdr_len = ((transport[12] >> 4) & 0x0F) * 4;
        if (transport_len < tcp_hdr_len) return pkt;
        pkt.payload     = transport + tcp_hdr_len;
        pkt.payload_len = (uint16_t)(transport_len - tcp_hdr_len);
    } else if (pkt.protocol == 17) {
        if (transport_len < 8) return pkt;
        pkt.src_port    = readUint16BE(transport);
        pkt.dst_port    = readUint16BE(transport + 2);
        pkt.payload     = transport + 8;
        pkt.payload_len = (uint16_t)(transport_len - 8);
    } else {
        return pkt;
    }

    if (pkt.payload && pkt.payload_len > 0)
        pkt.is_tls = detectTLS(pkt.payload, pkt.payload_len);

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