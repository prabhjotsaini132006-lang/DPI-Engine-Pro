#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "types.h"
#include "flow_features.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <cmath>

// ─────────────────────────────────────────
// Anomaly Types
// ─────────────────────────────────────────
enum class AnomalyType {
    PORT_SCAN,
    HIGH_PACKET_RATE,
    SUSPICIOUS_PORT,
    LARGE_FLOW,
    DNS_TUNNELING,
    UNKNOWN_PROTOCOL,
    BRUTE_FORCE
};

// ─────────────────────────────────────────
// Single Anomaly Alert
// ─────────────────────────────────────────
struct AnomalyAlert {
    AnomalyType type;
    std::string description;
    uint32_t    src_ip    = 0;
    uint32_t    dst_ip    = 0;
    uint16_t    dst_port  = 0;
    double      severity  = 0.0;  // 0.0 to 1.0
    double      z_score   = 0.0;  // standard deviations above baseline
    std::string timestamp = "";
};

// ─────────────────────────────────────────
// Rolling statistics (Welford's online algorithm)
// Computes mean and variance incrementally —
// no need to store the full history of values.
// ─────────────────────────────────────────
struct RollingStats {
    int    count = 0;
    double mean  = 0.0;
    double M2    = 0.0;   // sum of squared deviations

    void update(double x) {
        count++;
        double delta  = x - mean;
        mean         += delta / count;
        double delta2 = x - mean;
        M2           += delta * delta2;
    }

    double variance() const {
        return (count < 2) ? 0.0 : M2 / (count - 1);
    }

    double stddev() const {
        return std::sqrt(variance());
    }

    // Returns z-score (how many stddevs above mean).
    // Returns 0 if not enough data yet.
    double zscore(double x) const {
        if (count < 5) return 0.0;   // need baseline first
        double sd = stddev();
        if (sd < 1e-9) return 0.0;   // no variation = no anomaly
        return (x - mean) / sd;
    }
};

// ─────────────────────────────────────────
// Per-IP baseline profile
// ─────────────────────────────────────────
struct IpProfile {
    RollingStats dns_bytes;      // bytes per DNS flow
    RollingStats pkt_rate;       // packets/sec per flow
    RollingStats flow_bytes;     // total bytes per flow
};

// ─────────────────────────────────────────
// Anomaly Detector
// Detects suspicious traffic patterns using
// both hard thresholds and per-IP statistical
// baselines (z-score method).
// ─────────────────────────────────────────
class AnomalyDetector {
public:
    AnomalyDetector();

    // Check a flow for anomalies
    // Returns list of alerts (empty = normal)
    std::vector<AnomalyAlert> check(const Flow& flow);

    // Print all alerts so far
    void printAlerts() const;

    // Get total alert count
    size_t alertCount() const;

    // Clear all alerts
    void clearAlerts();

    // Configure thresholds
    void setPortScanThreshold(int ports);
    void setHighRateThreshold(double pps);
    void setLargeFlowThreshold(uint64_t bytes);

    // Z-score threshold — how many stddevs above
    // baseline before an alert fires (default: 3.0)
    void setZScoreThreshold(double z) { z_threshold = z; }

private:
    // Hard thresholds (fallback when no baseline exists)
    int      port_scan_threshold  = 10;
    double   high_rate_threshold  = 10000.0;
    uint64_t large_flow_threshold = 100000000;

    // Z-score threshold for statistical detection
    double   z_threshold          = 3.0;

    // Minimum hard-threshold for DNS tunneling
    // (even with low z-score, very large DNS flows are suspicious)
    uint64_t dns_hard_threshold   = 10000;

    // Suspicious ports list
    static const uint16_t SUSPICIOUS_PORTS[];
    static const int      NUM_SUSPICIOUS_PORTS;

    // Per-source-IP state
    std::unordered_map<uint32_t, std::vector<uint16_t>> ip_ports_seen;
    std::unordered_map<uint32_t, IpProfile>             ip_profiles;

    // All alerts generated
    std::vector<AnomalyAlert> all_alerts;

    // Detection methods
    AnomalyAlert checkPortScan(const Flow& flow);
    AnomalyAlert checkHighRate(const Flow& flow);
    AnomalyAlert checkSuspiciousPort(const Flow& flow);
    AnomalyAlert checkLargeFlow(const Flow& flow);
    AnomalyAlert checkDNSTunneling(const Flow& flow);

    // Helpers
    bool        isSuspiciousPort(uint16_t port) const;
    std::string ipToStr(uint32_t ip) const;
    std::string getCurrentTime() const;
    std::string anomalyTypeStr(AnomalyType type) const;
};

#endif // ANOMALY_DETECTOR_H
