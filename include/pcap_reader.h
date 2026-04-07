#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

// ─────────────────────────────────────────
// Raw packet as read from .pcap file
// ─────────────────────────────────────────
struct RawPacket {
    std::vector<uint8_t> data;        // raw bytes
    double               timestamp_ms; // when was it captured
    uint32_t             original_len; // original packet length
};

// ─────────────────────────────────────────
// Reads packets from a .pcap file
// ─────────────────────────────────────────
class PcapReader {
public:
    // Open a pcap file
    // Returns true if successful
    bool open(const std::string& filename);

    // Read next packet
    // Returns false when no more packets
    bool readNext(RawPacket& packet);

    // Close the file
    void close();

    // Is file open?
    bool isOpen() const;

    // How many packets read so far
    uint64_t packetsRead() const;

private:
    FILE*    file          = nullptr;
    bool     swap_bytes    = false;  // for endianness
    uint64_t packets_read  = 0;

    // PCAP file magic numbers
    static const uint32_t PCAP_MAGIC    = 0xa1b2c3d4;
    static const uint32_t PCAP_MAGIC_NS = 0xa1b23c4d;
};

#endif // PCAP_READER_H