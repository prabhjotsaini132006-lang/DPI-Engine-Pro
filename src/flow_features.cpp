#include "flow_features.h"

void FlowFeatures::update(uint64_t packet_size_bytes,
                          double   timestamp_ms,
                          uint16_t destination_port,
                          uint8_t  ip_protocol,
                          bool     tls_detected)
{
    // Volume
    total_packets++;
    total_bytes += packet_size_bytes;

    if (packet_size_bytes > max_packet_size)
        max_packet_size = packet_size_bytes;

    if (packet_size_bytes < min_packet_size)
        min_packet_size = packet_size_bytes;

    // Protocol
    dst_port = destination_port;
    protocol = ip_protocol;
    if (tls_detected) has_tls = true;

    // Timing
    if (first_packet_ms < 0)
        first_packet_ms = timestamp_ms;

    last_packet_ms = timestamp_ms;
}

void FlowFeatures::finalize()
{
    if (total_packets == 0) return;

    avg_packet_size = (double)total_bytes / (double)total_packets;

    flow_duration_ms = last_packet_ms - first_packet_ms;

    if (flow_duration_ms > 0) {
        double duration_sec  = flow_duration_ms / 1000.0;
        packets_per_second   = (double)total_packets / duration_sec;
        bytes_per_second     = (double)total_bytes   / duration_sec;
        avg_inter_arrival_ms = flow_duration_ms / (double)total_packets;
    }

    if (min_packet_size == 0xFFFFFFFFFFFFFFFF)
        min_packet_size = max_packet_size;
}