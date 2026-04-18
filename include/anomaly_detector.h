#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "types.h"
#include "flow_features.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>

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
    std::string timestamp = "";
};

// ─────────────────────────────────────────
// Anomaly Detector
// Detects suspicious traffic patterns
// ─────────────────────────────────────────
class AnomalyDetector {
public:
    AnomalyDetector();

    // Check a flow for anomalies
    // Returns list of alerts (empty = normal)
    std::vector<AnomalyAlert> check(
        const Flow& flow);

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

private:
    // Thresholds
    int      port_scan_threshold  = 10;
    double   high_rate_threshold  = 10000.0;
    uint64_t large_flow_threshold = 100000000;

    // Suspicious ports
    static const uint16_t SUSPICIOUS_PORTS[];
    static const int      NUM_SUSPICIOUS_PORTS;

    // Track ports per source IP
    std::unordered_map<uint32_t,
        std::vector<uint16_t>> ip_ports_seen;

    // All alerts generated
    std::vector<AnomalyAlert> all_alerts;

    // Detection methods
    AnomalyAlert checkPortScan(const Flow& flow);
    AnomalyAlert checkHighRate(const Flow& flow);
    AnomalyAlert checkSuspiciousPort(
        const Flow& flow);
    AnomalyAlert checkLargeFlow(const Flow& flow);
    AnomalyAlert checkDNSTunneling(
        const Flow& flow);

    // Helpers
    bool isSuspiciousPort(uint16_t port) const;
    std::string ipToStr(uint32_t ip) const;
    std::string getCurrentTime() const;
    std::string anomalyTypeStr(
        AnomalyType type) const;
};

#endif // ANOMALY_DETECTOR_H