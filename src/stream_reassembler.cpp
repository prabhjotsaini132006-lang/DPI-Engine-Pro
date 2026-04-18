#include "stream_reassembler.h"
#include <iostream>
#include <algorithm>
#include <iomanip>

using namespace std;

StreamReassembler::StreamReassembler(size_t max_streams,
                                     size_t max_buf_bytes)
    : max_streams(max_streams),
      max_buf_bytes(max_buf_bytes)
{}

int StreamReassembler::addSegment(const FiveTuple& tuple,
                                   uint32_t         seq_num,
                                   const uint8_t*   payload,
                                   uint16_t         len,
                                   bool             is_syn,
                                   bool             is_fin)
{
    if (!payload || len == 0) return 0;

    unique_lock<mutex> lock(mtx);

    if (streams.size() >= max_streams) {
        streams.erase(streams.begin());
    }

    TcpStream& stream = streams[tuple];
    total_segments_in++;
    total_bytes_in += len;

    if (is_syn) {
        stream.next_seq    = seq_num + 1;
        stream.initialized = true;
        stream.buffer.clear();
        stream.out_of_order.clear();
        return 0;
    }

    if (!stream.initialized) {
        stream.next_seq    = seq_num;
        stream.initialized = true;
    }

    // Duplicate — drop
    if (seq_num < stream.next_seq) {
        total_duplicates++;
        stream.segments_dropped++;
        return 0;
    }

    // In-order — append
    if (seq_num == stream.next_seq) {
        if (stream.buffer.size() + len > max_buf_bytes) {
            size_t trim = stream.buffer.size() / 2;
            stream.buffer.erase(stream.buffer.begin(),
                                stream.buffer.begin() + (int)trim);
        }
        stream.buffer.insert(stream.buffer.end(),
                             payload, payload + len);
        stream.next_seq          += len;
        stream.bytes_reassembled += len;
        stream.segments_added++;
        if (is_fin) stream.next_seq++;
        flushOutOfOrder(stream);
        return (int)len;
    }

    // Future — hold
    if (seq_num > stream.next_seq) {
        if (stream.out_of_order.size() < 64) {
            bool already_held = false;
            for (const auto& seg : stream.out_of_order) {
                if (seg.seq_num == seq_num) {
                    already_held = true;
                    break;
                }
            }
            if (!already_held) {
                TcpSegment seg;
                seg.seq_num = seq_num;
                seg.data.assign(payload, payload + len);
                stream.out_of_order.push_back(move(seg));
                total_out_of_order++;
            }
        }
        return 0;
    }

    return 0;
}

void StreamReassembler::flushOutOfOrder(TcpStream& stream)
{
    bool progress = true;
    while (progress && !stream.out_of_order.empty()) {
        progress = false;
        for (auto it = stream.out_of_order.begin();
             it != stream.out_of_order.end(); ++it)
        {
            if (it->seq_num == stream.next_seq) {
                uint32_t seg_len = (uint32_t)it->data.size();
                if (stream.buffer.size() + seg_len <= max_buf_bytes) {
                    stream.buffer.insert(stream.buffer.end(),
                                         it->data.begin(),
                                         it->data.end());
                    stream.next_seq          += seg_len;
                    stream.bytes_reassembled += seg_len;
                    stream.segments_added++;
                }
                stream.out_of_order.erase(it);
                progress = true;
                break;
            }
        }
    }
}

const vector<uint8_t>* StreamReassembler::getStream(
    const FiveTuple& tuple) const
{
    unique_lock<mutex> lock(mtx);
    auto it = streams.find(tuple);
    if (it == streams.end()) return nullptr;
    return &it->second.buffer;
}

uint64_t StreamReassembler::bytesReassembled(
    const FiveTuple& tuple) const
{
    unique_lock<mutex> lock(mtx);
    auto it = streams.find(tuple);
    if (it == streams.end()) return 0;
    return it->second.bytes_reassembled;
}

void StreamReassembler::clearStream(const FiveTuple& tuple)
{
    unique_lock<mutex> lock(mtx);
    streams.erase(tuple);
}

size_t StreamReassembler::streamCount() const
{
    unique_lock<mutex> lock(mtx);
    return streams.size();
}

void StreamReassembler::printStats() const
{
    unique_lock<mutex> lock(mtx);

    uint64_t total_reassembled = 0;
    uint64_t total_ooo_held    = 0;
    for (const auto& pair : streams) {
        total_reassembled += pair.second.bytes_reassembled;
        total_ooo_held    += pair.second.out_of_order.size();
    }

    cout << "\n=== TCP Stream Reassembly Stats ===\n";
    cout << "  Active streams:     " << streams.size()    << "\n";
    cout << "  Segments received:  " << total_segments_in << "\n";
    cout << "  Bytes received:     " << total_bytes_in    << "\n";
    cout << "  Bytes reassembled:  " << total_reassembled << "\n";
    cout << "  Out-of-order held:  " << total_ooo_held    << "\n";
    cout << "  Duplicate drops:    " << total_duplicates  << "\n";
    if (total_bytes_in > 0) {
        double pct = (double)total_reassembled /
                     (double)total_bytes_in * 100.0;
        cout << fixed << setprecision(1);
        cout << "  Reassembly rate:    " << pct << "%\n";
    }
    cout << "===================================\n";
}