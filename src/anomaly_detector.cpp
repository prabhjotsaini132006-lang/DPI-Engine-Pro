#include "anomaly_detector.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <ctime>

using namespace std;

// Known suspicious ports
const uint16_t AnomalyDetector::SUSPICIOUS_PORTS[] = {
    4444,   // Metasploit default
    1337,   // Leet/hacker
    31337,  // Back Orifice
    12345,  // NetBus
    6667,   // IRC (often malware C2)
    6666,   // IRC
    9001,   // Tor
    9050,   // Tor SOCKS
    1080,   // SOCKS proxy
    3128,   // Squid proxy
};

const int AnomalyDetector::NUM_SUSPICIOUS_PORTS =
    sizeof(SUSPICIOUS_PORTS) /
    sizeof(SUSPICIOUS_PORTS[0]);

AnomalyDetector::AnomalyDetector()
{}

string AnomalyDetector::ipToStr(uint32_t ip) const
{
    ostringstream ss;
    ss << ((ip >> 24) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 8)  & 0xFF) << "."
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
    strftime(buf, sizeof(buf),
             "%H:%M:%S", &tm_info);
    return string(buf);
}

string AnomalyDetector::anomalyTypeStr(
    AnomalyType type) const
{
    switch (type) {
        case AnomalyType::PORT_SCAN:
            return "PORT_SCAN";
        case AnomalyType::HIGH_PACKET_RATE:
            return "HIGH_PACKET_RATE";
        case AnomalyType::SUSPICIOUS_PORT:
            return "SUSPICIOUS_PORT";
        case AnomalyType::LARGE_FLOW:
            return "LARGE_FLOW";
        case AnomalyType::DNS_TUNNELING:
            return "DNS_TUNNELING";
        case AnomalyType::UNKNOWN_PROTOCOL:
            return "UNKNOWN_PROTOCOL";
        case AnomalyType::BRUTE_FORCE:
            return "BRUTE_FORCE";
        default:
            return "UNKNOWN";
    }
}

bool AnomalyDetector::isSuspiciousPort(
    uint16_t port) const
{
    for (int i = 0; i < NUM_SUSPICIOUS_PORTS; i++) {
        if (SUSPICIOUS_PORTS[i] == port) return true;
    }
    return false;
}

AnomalyAlert AnomalyDetector::checkPortScan(
    const Flow& flow)
{
    AnomalyAlert alert;
    uint32_t src = flow.tuple.src_ip;

    // Track ports this source has connected to
    auto& ports = ip_ports_seen[src];
    uint16_t dst_port = flow.tuple.dst_port;

    if (find(ports.begin(), ports.end(), dst_port)
        == ports.end()) {
        ports.push_back(dst_port);
    }

    if ((int)ports.size() >= port_scan_threshold) {
        alert.type        = AnomalyType::PORT_SCAN;
        alert.src_ip      = src;
        alert.dst_ip      = flow.tuple.dst_ip;
        alert.severity    = 0.8;
        alert.timestamp   = getCurrentTime();
        alert.description =
            "Port scan from " + ipToStr(src) +
            " (" + to_string(ports.size()) +
            " ports scanned)";
    }

    return alert;
}

AnomalyAlert AnomalyDetector::checkHighRate(
    const Flow& flow)
{
    AnomalyAlert alert;

    if (flow.features.packets_per_second >
        high_rate_threshold) {
        alert.type      = AnomalyType::HIGH_PACKET_RATE;
        alert.src_ip    = flow.tuple.src_ip;
        alert.dst_ip    = flow.tuple.dst_ip;
        alert.severity  = 0.7;
        alert.timestamp = getCurrentTime();
        alert.description =
            "High packet rate: " +
            to_string((int)
                flow.features.packets_per_second) +
            " pkt/s from " +
            ipToStr(flow.tuple.src_ip);
    }

    return alert;
}

AnomalyAlert AnomalyDetector::checkSuspiciousPort(
    const Flow& flow)
{
    AnomalyAlert alert;

    if (isSuspiciousPort(flow.tuple.dst_port)) {
        alert.type      = AnomalyType::SUSPICIOUS_PORT;
        alert.src_ip    = flow.tuple.src_ip;
        alert.dst_ip    = flow.tuple.dst_ip;
        alert.dst_port  = flow.tuple.dst_port;
        alert.severity  = 0.9;
        alert.timestamp = getCurrentTime();
        alert.description =
            "Suspicious port " +
            to_string(flow.tuple.dst_port) +
            " connection from " +
            ipToStr(flow.tuple.src_ip);
    }

    return alert;
}

AnomalyAlert AnomalyDetector::checkLargeFlow(
    const Flow& flow)
{
    AnomalyAlert alert;

    if (flow.features.total_bytes >
        large_flow_threshold) {
        alert.type      = AnomalyType::LARGE_FLOW;
        alert.src_ip    = flow.tuple.src_ip;
        alert.dst_ip    = flow.tuple.dst_ip;
        alert.severity  = 0.5;
        alert.timestamp = getCurrentTime();
        alert.description =
            "Large flow detected: " +
            to_string(flow.features.total_bytes /
                      1048576) +
            " MB from " +
            ipToStr(flow.tuple.src_ip);
    }

    return alert;
}

AnomalyAlert AnomalyDetector::checkDNSTunneling(
    const Flow& flow)
{
    AnomalyAlert alert;

    // DNS tunneling: DNS flow with unusually
    // high byte count (data hidden in DNS)
    if (flow.tuple.dst_port == 53 &&
        flow.features.total_bytes > 10000) {
        alert.type      = AnomalyType::DNS_TUNNELING;
        alert.src_ip    = flow.tuple.src_ip;
        alert.dst_ip    = flow.tuple.dst_ip;
        alert.severity  = 0.85;
        alert.timestamp = getCurrentTime();
        alert.description =
            "Possible DNS tunneling: " +
            to_string(flow.features.total_bytes) +
            " bytes in DNS flow from " +
            ipToStr(flow.tuple.src_ip);
    }

    return alert;
}

vector<AnomalyAlert> AnomalyDetector::check(
    const Flow& flow)
{
    vector<AnomalyAlert> alerts;

    // Run all checks
    AnomalyAlert port_scan =
        checkPortScan(flow);
    if (!port_scan.description.empty())
        alerts.push_back(port_scan);

    AnomalyAlert high_rate =
        checkHighRate(flow);
    if (!high_rate.description.empty())
        alerts.push_back(high_rate);

    AnomalyAlert susp_port =
        checkSuspiciousPort(flow);
    if (!susp_port.description.empty())
        alerts.push_back(susp_port);

    AnomalyAlert large_flow =
        checkLargeFlow(flow);
    if (!large_flow.description.empty())
        alerts.push_back(large_flow);

    AnomalyAlert dns_tunnel =
        checkDNSTunneling(flow);
    if (!dns_tunnel.description.empty())
        alerts.push_back(dns_tunnel);

    // Store alerts
    for (const auto& a : alerts) {
        all_alerts.push_back(a);
        // Print immediately
        cout << "\n[ALERT][" << a.timestamp << "] "
             << anomalyTypeStr(a.type) << "\n"
             << "  " << a.description << "\n"
             << "  Severity: "
             << (int)(a.severity * 100) << "%\n";
    }

    return alerts;
}

void AnomalyDetector::printAlerts() const
{
    cout << "\n=== Anomaly Detection Report ===\n";
    cout << "Total alerts: "
         << all_alerts.size() << "\n\n";

    for (const auto& alert : all_alerts) {
        cout << "[" << alert.timestamp << "] "
             << "[" << anomalyTypeStr(alert.type)
             << "] "
             << alert.description << "\n"
             << "  Severity: "
             << (int)(alert.severity * 100)
             << "%\n\n";
    }
}

size_t AnomalyDetector::alertCount() const
{
    return all_alerts.size();
}

void AnomalyDetector::clearAlerts()
{
    all_alerts.clear();
    ip_ports_seen.clear();
}

void AnomalyDetector::setPortScanThreshold(
    int ports)
{
    port_scan_threshold = ports;
}

void AnomalyDetector::setHighRateThreshold(
    double pps)
{
    high_rate_threshold = pps;
}

void AnomalyDetector::setLargeFlowThreshold(
    uint64_t bytes)
{
    large_flow_threshold = bytes;
}