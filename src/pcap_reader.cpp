#include "pcap_reader.h"
#include <iostream>
#include <cstring>

using namespace std;

// PCAP Global Header structure (24 bytes)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// PCAP Packet Header structure (16 bytes)
struct PcapPacketHeader {
    uint32_t ts_sec;    // timestamp seconds
    uint32_t ts_usec;   // timestamp microseconds
    uint32_t incl_len;  // bytes captured
    uint32_t orig_len;  // original packet length
};

bool PcapReader::open(const string& filename)
{
    file = fopen(filename.c_str(), "rb");
    if (!file) {
        cerr << "PcapReader: Cannot open " << filename << endl;
        return false;
    }

    // Read global header
    PcapGlobalHeader header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        cerr << "PcapReader: Cannot read global header" << endl;
        fclose(file);
        file = nullptr;
        return false;
    }

    // Check magic number
    if (header.magic_number == PCAP_MAGIC ||
        header.magic_number == PCAP_MAGIC_NS) {
        swap_bytes = false;
    } else {
        cerr << "PcapReader: Invalid pcap file" << endl;
        fclose(file);
        file = nullptr;
        return false;
    }

    cout << "PcapReader: Opened " << filename << endl;
    return true;
}

bool PcapReader::readNext(RawPacket& packet)
{
    if (!file) return false;

    // Read packet header
    PcapPacketHeader header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        return false;  // end of file
    }

    // Calculate timestamp in milliseconds
    packet.timestamp_ms = (double)header.ts_sec * 1000.0
                        + (double)header.ts_usec / 1000.0;

    packet.original_len = header.orig_len;

    // Read packet data
    packet.data.resize(header.incl_len);
    if (fread(packet.data.data(), 1, header.incl_len, file)
        != header.incl_len) {
        return false;
    }

    packets_read++;
    return true;
}

void PcapReader::close()
{
    if (file) {
        fclose(file);
        file = nullptr;
    }
}

bool PcapReader::isOpen() const
{
    return file != nullptr;
}

uint64_t PcapReader::packetsRead() const
{
    return packets_read;
}