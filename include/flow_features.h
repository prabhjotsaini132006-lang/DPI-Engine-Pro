#ifndef FLOW_FEATURES_H
#define FLOW_FEATURES_H

#include <cstdint>
#include <chrono>

enum class AppType {
    UNKNOWN  = 0,
    HTTP     = 1,
    HTTPS    = 2,
    DNS      = 3,
    YOUTUBE  = 4,
    FACEBOOK = 5,
    ZOOM     = 6,
    WHATSAPP = 7,
    GAMING   = 8,
    NETFLIX  = 9,
    SPOTIFY  = 10,
    STEAM    = 11,
    TIKTOK   = 12
};

struct FlowFeatures {

    // --- Volume Features ---
    uint64_t total_packets   = 0;
    uint64_t total_bytes     = 0;
    double   avg_packet_size = 0.0;
    uint64_t max_packet_size = 0;
    uint64_t min_packet_size = 0xFFFFFFFFFFFFFFFF;

    // --- Timing Features ---
    double flow_duration_ms     = 0.0;
    double packets_per_second   = 0.0;
    double bytes_per_second     = 0.0;
    double avg_inter_arrival_ms = 0.0;

    // --- Protocol Features ---
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;
    bool     has_tls  = false;

    // --- Internal timing helpers ---
    double first_packet_ms = -1.0;
    double last_packet_ms  =  0.0;

    // --- Label (training only) ---
    AppType label = AppType::UNKNOWN;

    void update(uint64_t packet_size_bytes,
                double   timestamp_ms,
                uint16_t destination_port,
                uint8_t  ip_protocol,
                bool     tls_detected);

    void finalize();
};

#endif // FLOW_FEATURES_H