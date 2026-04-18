#ifndef STREAM_REASSEMBLER_H
#define STREAM_REASSEMBLER_H

#include "types.h"
#include "pcap_reader.h"
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <string>

struct TcpSegment {
    uint32_t             seq_num = 0;
    std::vector<uint8_t> data;
};

struct TcpStream {
    uint32_t             next_seq         = 0;
    bool                 initialized      = false;
    std::vector<uint8_t> buffer;
    std::vector<TcpSegment> out_of_order;
    uint64_t             bytes_reassembled = 0;
    uint64_t             segments_added    = 0;
    uint64_t             segments_dropped  = 0;
};

class StreamReassembler {
public:
    StreamReassembler(size_t max_streams   = 50000,
                      size_t max_buf_bytes = 1048576);

    int addSegment(const FiveTuple& tuple,
                   uint32_t         seq_num,
                   const uint8_t*   payload,
                   uint16_t         len,
                   bool             is_syn,
                   bool             is_fin);

    const std::vector<uint8_t>* getStream(
        const FiveTuple& tuple) const;

    uint64_t bytesReassembled(const FiveTuple& tuple) const;
    void     clearStream(const FiveTuple& tuple);
    size_t   streamCount() const;
    void     printStats() const;

private:
    size_t max_streams;
    size_t max_buf_bytes;

    mutable std::mutex mtx;
    std::unordered_map<FiveTuple,
                       TcpStream,
                       FiveTupleHash> streams;

    void flushOutOfOrder(TcpStream& stream);

    uint64_t total_segments_in  = 0;
    uint64_t total_bytes_in     = 0;
    uint64_t total_out_of_order = 0;
    uint64_t total_duplicates   = 0;
};

#endif // STREAM_REASSEMBLER_H