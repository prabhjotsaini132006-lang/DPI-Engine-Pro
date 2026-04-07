#ifndef TYPES_H
#define TYPES_H

#include "flow_features.h"
#include <string>
#include <cstdint>

// ─────────────────────────────────────────
// Identifies a unique network connection
// src_ip:src_port → dst_ip:dst_port
// ─────────────────────────────────────────
struct FiveTuple {
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;

    // For using FiveTuple as a map key
    bool operator==(const FiveTuple& other) const {
        return src_ip   == other.src_ip   &&
               dst_ip   == other.dst_ip   &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// Hash function so FiveTuple can be used in unordered_map
struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        size_t h = 0;
        h ^= std::hash<uint32_t>{}(t.src_ip)   + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint32_t>{}(t.dst_ip)   + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint16_t>{}(t.src_port) + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint16_t>{}(t.dst_port) + 0x9e3779b9 + (h<<6) + (h>>2);
        h ^= std::hash<uint8_t> {}(t.protocol) + 0x9e3779b9 + (h<<6) + (h>>2);
        return h;
    }
};

// ─────────────────────────────────────────
// Represents one network flow
// (all packets between same src/dst pair)
// ─────────────────────────────────────────
struct Flow {
    FiveTuple    tuple;           // who is talking to whom
    FlowFeatures features;        // ML feature vector
    std::string  sni;             // domain name (if found)
    AppType      app_type;        // classified app
    bool         blocked = false; // is this flow blocked?
};

// ─────────────────────────────────────────
// Convert AppType enum to readable string
// ─────────────────────────────────────────
inline std::string appTypeToString(AppType app) {
    switch(app) {
        case AppType::HTTP:     return "HTTP";
        case AppType::HTTPS:    return "HTTPS";
        case AppType::DNS:      return "DNS";
        case AppType::YOUTUBE:  return "YOUTUBE";
        case AppType::FACEBOOK: return "FACEBOOK";
        case AppType::ZOOM:     return "ZOOM";
        case AppType::WHATSAPP: return "WHATSAPP";
        case AppType::GAMING:   return "GAMING";
        default:                return "UNKNOWN";
    }
}

// ─────────────────────────────────────────
// Convert SNI domain to AppType
// (used when SNI IS available)
// ─────────────────────────────────────────
inline AppType sniToAppType(const std::string& sni) {
    // YouTube and its CDNs
    if (sni.find("youtube")     != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("googlevideo") != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("ytimg")       != std::string::npos) return AppType::YOUTUBE;

    // Facebook and its CDNs
    if (sni.find("facebook")    != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("fbcdn")       != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("instagram")   != std::string::npos) return AppType::FACEBOOK;

    // Zoom
    if (sni.find("zoom")        != std::string::npos) return AppType::ZOOM;

    // WhatsApp
    if (sni.find("whatsapp")    != std::string::npos) return AppType::WHATSAPP;
    if (sni.find("wa.me")       != std::string::npos) return AppType::WHATSAPP;

    // Generic
    if (sni.find("google")      != std::string::npos) return AppType::HTTPS;

    return AppType::UNKNOWN;
}

#endif // TYPES_H