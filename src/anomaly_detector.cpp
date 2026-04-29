#include "anomaly_detector.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>

using namespace std;

const uint16_t AnomalyDetector::SUSPICIOUS_PORTS[] = {
    4444, 1337, 31337, 12345, 6667,
    6666, 9001, 9050, 1080, 3128,
};

const int AnomalyDetector::NUM_SUSPICIOUS_PORTS =
    sizeof(SUSPICIOUS_PORTS) / sizeof(SUSPICIOUS_PORTS[0]);

AnomalyDetector::AnomalyDetector() {}

string AnomalyDetector::ipToStr(uint32_t ip) const
{
    ostringstream ss;
    ss << ((ip >> 24) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >>  8) & 0xFF) << "."
       << ( ip        & 0xFF);
    return ss.str();
}

string AnomalyDetector::getCurrentTime() const
{
    auto   now = chrono::system_clock::now();
    time_t t   = chrono::system_clock::to_time_t(now);
    char   buf[20];
    struct tm tm_info;
#ifdef _WIN32
    localtime_s(&tm_info, &t);
#else
    localtime_r(&t, &tm_info);
#endif
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm_info);
    return string(buf);
}

string AnomalyDetector::anomalyTypeStr(AnomalyType type) const
{
    switch (type) {
        case AnomalyType::PORT_SCAN:        return "PORT_SCAN";
        case AnomalyType::HIGH_PACKET_RATE: return "HIGH_PACKET_RATE";
        case AnomalyType::SUSPICIOUS_PORT:  return "SUSPICIOUS_PORT";
        case AnomalyType::LARGE_FLOW:       return "LARGE_FLOW";
        case AnomalyType::DNS_TUNNELING:    return "DNS_TUNNELING";
        case AnomalyType::UNKNOWN_PROTOCOL: return "UNKNOWN_PROTOCOL";
        case AnomalyType::BRUTE_FORCE:      return "BRUTE_FORCE";
        default:                            return "UNKNOWN";
    }
}

bool AnomalyDetector::isSuspiciousPort(uint16_t port) const
{
    for (int i = 0; i < NUM_SUSPICIOUS_PORTS; i++)
        if (SUSPICIOUS_PORTS[i] == port) return true;
    return false;
}

AnomalyAlert AnomalyDetector::checkPortScan(const Flow& flow)
{
    AnomalyAlert alert;

    // Skip DNS — routers reply to many ephemeral ports
    if (flow.tuple.src_port == 53 || flow.tuple.dst_port == 53)
        return alert;

    uint32_t src      = flow.tuple.src_ip;
    auto&    ports    = ip_ports_seen[src];
    uint16_t dst_port = flow.tuple.dst_port;

    if (find(ports.begin(), ports.end(), dst_port) == ports.end())
        ports.push_back(dst_port);

    if ((int)ports.size() >= port_scan_threshold) {
        alert.type        = AnomalyType::PORT_SCAN;
        alert.src_ip      = src;
        alert.dst_ip      = flow.tuple.dst_ip;
        alert.severity    = 0.8;
        alert.timestamp   = getCurrentTime();
        alert.description = "Port scan from " + ipToStr(src) +
                            " (" + to_string(ports.size()) +
                            " ports scanned)";
    }
    return alert;
}

// ─────────────────────────────────────────
// Statistical high-rate detection
//
// For each source IP we maintain a rolling mean
// and standard deviation of packets/sec across
// all flows seen from that IP.
//
// A flow is flagged if its rate is:
//   (a) more than z_threshold stddevs above that
//       IP's own baseline, AND
//   (b) above a minimum floor (to avoid alerting
//       on tiny variation around zero)
//
// Falls back to the hard threshold if no baseline
// has been established yet (< 5 flows seen).
// ─────────────────────────────────────────
AnomalyAlert AnomalyDetector::checkHighRate(const Flow& flow)
{
    AnomalyAlert alert;
    uint32_t src = flow.tuple.src_ip;
    double   pps = flow.features.packets_per_second;

    IpProfile& profile = ip_profiles[src];

    // Update this IP's baseline with the current flow
    profile.pkt_rate.update(pps);

    double z = profile.pkt_rate.zscore(pps);

    bool statistical_alert = (z >= z_threshold) && (pps > 100.0);
    bool hard_alert        = (profile.pkt_rate.count < 5) &&
                             (pps > high_rate_threshold);

    if (statistical_alert || hard_alert) {
        double severity = min(1.0, 0.5 + (z / 20.0));
        if (hard_alert) severity = 0.7;

        ostringstream desc;
        desc << "High packet rate: " << fixed << setprecision(1)
             << pps << " pkt/s from " << ipToStr(src);
        if (statistical_alert) {
            desc << " (z=" << fixed << setprecision(1) << z
                 << ", baseline mean=" << fixed << setprecision(1)
                 << profile.pkt_rate.mean << ")";
        }

        alert.type        = AnomalyType::HIGH_PACKET_RATE;
        alert.src_ip      = src;
        alert.dst_ip      = flow.tuple.dst_ip;
        alert.severity    = severity;
        alert.z_score     = z;
        alert.timestamp   = getCurrentTime();
        alert.description = desc.str();
    }
    return alert;
}

AnomalyAlert AnomalyDetector::checkSuspiciousPort(const Flow& flow)
{
    AnomalyAlert alert;
    if (isSuspiciousPort(flow.tuple.dst_port)) {
        alert.type        = AnomalyType::SUSPICIOUS_PORT;
        alert.src_ip      = flow.tuple.src_ip;
        alert.dst_ip      = flow.tuple.dst_ip;
        alert.dst_port    = flow.tuple.dst_port;
        alert.severity    = 0.9;
        alert.timestamp   = getCurrentTime();
        alert.description = "Suspicious port " +
                            to_string(flow.tuple.dst_port) +
                            " connection from " +
                            ipToStr(flow.tuple.src_ip);
    }
    return alert;
}

AnomalyAlert AnomalyDetector::checkLargeFlow(const Flow& flow)
{
    AnomalyAlert alert;
    uint32_t src   = flow.tuple.src_ip;
    double   bytes = static_cast<double>(flow.features.total_bytes);

    IpProfile& profile = ip_profiles[src];
    profile.flow_bytes.update(bytes);

    double z = profile.flow_bytes.zscore(bytes);

    bool statistical_alert = (z >= z_threshold) &&
                             (bytes > 1000000);  // > 1 MB floor
    bool hard_alert        = (profile.flow_bytes.count < 5) &&
                             (flow.features.total_bytes > large_flow_threshold);

    if (statistical_alert || hard_alert) {
        double severity = min(1.0, 0.4 + (z / 20.0));
        if (hard_alert) severity = 0.5;

        ostringstream desc;
        desc << "Unusually large flow: "
             << (flow.features.total_bytes / 1048576) << " MB from "
             << ipToStr(src);
        if (statistical_alert) {
            desc << " (z=" << fixed << setprecision(1) << z << ")";
        }

        alert.type        = AnomalyType::LARGE_FLOW;
        alert.src_ip      = src;
        alert.dst_ip      = flow.tuple.dst_ip;
        alert.severity    = severity;
        alert.z_score     = z;
        alert.timestamp   = getCurrentTime();
        alert.description = desc.str();
    }
    return alert;
}

// ─────────────────────────────────────────
// Statistical DNS tunneling detection
//
// Normal DNS flows are tiny — a few hundred bytes
// at most. Tunneling hides data in DNS, so flows
// become unusually large for that protocol.
//
// For each source IP we track a rolling baseline
// of DNS flow sizes. A DNS flow is flagged if:
//   (a) z-score >= threshold (statistically anomalous
//       relative to this IP's own DNS history), OR
//   (b) bytes > hard floor (10 KB) when no baseline
//       exists yet
//
// The z-score approach means a host that legitimately
// sends slightly larger DNS flows won't be flagged —
// only genuinely anomalous spikes trigger alerts.
// ─────────────────────────────────────────
AnomalyAlert AnomalyDetector::checkDNSTunneling(const Flow& flow)
{
    AnomalyAlert alert;

    if (flow.tuple.dst_port != 53 && flow.tuple.src_port != 53)
        return alert;

    uint32_t src   = flow.tuple.src_ip;
    double   bytes = static_cast<double>(flow.features.total_bytes);

    IpProfile& profile = ip_profiles[src];

    // Update DNS baseline for this source IP
    profile.dns_bytes.update(bytes);

    double z = profile.dns_bytes.zscore(bytes);

    // Statistical alert: significantly above this IP's baseline
    bool statistical_alert = (z >= z_threshold);

    // Hard fallback: very large DNS flow with no baseline yet
    bool hard_alert = (profile.dns_bytes.count < 5) &&
                      (flow.features.total_bytes > dns_hard_threshold);

    if (statistical_alert || hard_alert) {
        // Severity scales with z-score: 3σ → 0.70, 6σ → 0.85, 10σ → 1.0
        double severity = min(1.0, 0.55 + (z / 20.0));
        if (hard_alert && !statistical_alert) severity = 0.75;

        ostringstream desc;
        desc << "Possible DNS tunneling: "
             << flow.features.total_bytes
             << " bytes in DNS flow from "
             << ipToStr(src);
        if (statistical_alert) {
            desc << " (z=" << fixed << setprecision(1) << z
                 << ", baseline mean=" << fixed << setprecision(0)
                 << profile.dns_bytes.mean << " bytes)";
        }

        alert.type        = AnomalyType::DNS_TUNNELING;
        alert.src_ip      = src;
        alert.dst_ip      = flow.tuple.dst_ip;
        alert.severity    = severity;
        alert.z_score     = z;
        alert.timestamp   = getCurrentTime();
        alert.description = desc.str();
    }
    return alert;
}

vector<AnomalyAlert> AnomalyDetector::check(const Flow& flow)
{
    vector<AnomalyAlert> alerts;

    auto tryAdd = [&](AnomalyAlert a) {
        if (!a.description.empty()) alerts.push_back(a);
    };

    tryAdd(checkPortScan(flow));
    tryAdd(checkHighRate(flow));
    tryAdd(checkSuspiciousPort(flow));
    tryAdd(checkLargeFlow(flow));
    tryAdd(checkDNSTunneling(flow));

    for (const auto& a : alerts) {
        all_alerts.push_back(a);
        cout << "\n[ALERT][" << a.timestamp << "] "
             << anomalyTypeStr(a.type) << "\n"
             << "  " << a.description << "\n"
             << "  Severity: " << (int)(a.severity * 100) << "%";
        if (a.z_score > 0.0) {
            cout << "  |  Z-score: " << fixed << setprecision(1)
                 << a.z_score << "σ above baseline";
        }
        cout << "\n";
    }

    return alerts;
}

void AnomalyDetector::printAlerts() const
{
    cout << "\n=== Anomaly Detection Report ===\n";
    cout << "Total alerts: " << all_alerts.size() << "\n\n";
    for (const auto& a : all_alerts) {
        cout << "[" << a.timestamp << "] "
             << "[" << anomalyTypeStr(a.type) << "] "
             << a.description << "\n"
             << "  Severity: " << (int)(a.severity * 100) << "%";
        if (a.z_score > 0.0) {
            cout << "  |  Z-score: " << fixed << setprecision(1)
                 << a.z_score << "σ";
        }
        cout << "\n\n";
    }
}

size_t AnomalyDetector::alertCount() const { return all_alerts.size(); }

void AnomalyDetector::clearAlerts()
{
    all_alerts.clear();
    ip_ports_seen.clear();
    ip_profiles.clear();   // reset all baselines too
}

void AnomalyDetector::setPortScanThreshold(int ports)   { port_scan_threshold  = ports; }
void AnomalyDetector::setHighRateThreshold(double pps)  { high_rate_threshold  = pps;   }
void AnomalyDetector::setLargeFlowThreshold(uint64_t b) { large_flow_threshold = b;     }
