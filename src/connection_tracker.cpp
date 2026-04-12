#include "connection_tracker.h"
#include <iostream>

using namespace std;

ConnectionTracker::ConnectionTracker(
    int flow_timeout_sec,
    int max_flows)
    : flow_timeout_sec(flow_timeout_sec),
      max_flows(max_flows)
{}

Flow& ConnectionTracker::processPacket(
    const ParsedPacket& pkt,
    double timestamp_ms)
{
    unique_lock<mutex> lock(mutex);

    FiveTuple tuple;
    tuple.src_ip   = pkt.src_ip;
    tuple.dst_ip   = pkt.dst_ip;
    tuple.src_port = pkt.src_port;
    tuple.dst_port = pkt.dst_port;
    tuple.protocol = pkt.protocol;

    // Find or create flow
    Flow& flow = flow_table[tuple];

    if (flow.features.total_packets == 0) {
        // New flow
        flow.tuple    = tuple;
        flow.app_type = AppType::UNKNOWN;
        flow.blocked  = false;
    }

    // Update features
    flow.features.update(
        pkt.packet_len,
        timestamp_ms,
        pkt.dst_port,
        pkt.protocol,
        pkt.is_tls
    );

    // Update last seen time
    last_seen[tuple] = timestamp_ms;

    return flow;
}

int ConnectionTracker::expireOldFlows(
    double current_time_ms)
{
    unique_lock<mutex> lock(mutex);

    double timeout_ms =
        flow_timeout_sec * 1000.0;

    vector<FiveTuple> to_remove;

    for (const auto& pair : last_seen) {
        double age = current_time_ms - pair.second;
        if (age > timeout_ms) {
            to_remove.push_back(pair.first);
        }
    }

    for (const auto& tuple : to_remove) {
        flow_table.erase(tuple);
        last_seen.erase(tuple);
    }

    if (!to_remove.empty()) {
        cout << "ConnectionTracker: Expired "
             << to_remove.size()
             << " old flows" << endl;
    }

    return (int)to_remove.size();
}

vector<Flow> ConnectionTracker::getAllFlows() const
{
    unique_lock<mutex> lock(mutex);

    vector<Flow> result;
    result.reserve(flow_table.size());

    for (const auto& pair : flow_table) {
        result.push_back(pair.second);
    }

    return result;
}

size_t ConnectionTracker::flowCount() const
{
    unique_lock<mutex> lock(mutex);
    return flow_table.size();
}

void ConnectionTracker::updateSNI(
    const FiveTuple& tuple,
    const string& sni)
{
    unique_lock<mutex> lock(mutex);
    auto it = flow_table.find(tuple);
    if (it != flow_table.end()) {
        it->second.sni = sni;
    }
}

void ConnectionTracker::updateAppType(
    const FiveTuple& tuple,
    AppType app_type)
{
    unique_lock<mutex> lock(mutex);
    auto it = flow_table.find(tuple);
    if (it != flow_table.end()) {
        it->second.app_type = app_type;
    }
}

void ConnectionTracker::updateBlocked(
    const FiveTuple& tuple,
    bool blocked)
{
    unique_lock<mutex> lock(mutex);
    auto it = flow_table.find(tuple);
    if (it != flow_table.end()) {
        it->second.blocked = blocked;
    }
}

void ConnectionTracker::printSummary() const
{
    unique_lock<mutex> lock(mutex);

    cout << "ConnectionTracker: "
         << flow_table.size()
         << " active flows" << endl;

    int app_counts[9] = {0};
    int blocked_count = 0;

    for (const auto& pair : flow_table) {
        const Flow& f = pair.second;
        app_counts[(int)f.app_type]++;
        if (f.blocked) blocked_count++;
    }

    cout << "  YOUTUBE:  "
         << app_counts[(int)AppType::YOUTUBE]  << endl;
    cout << "  DNS:      "
         << app_counts[(int)AppType::DNS]      << endl;
    cout << "  WHATSAPP: "
         << app_counts[(int)AppType::WHATSAPP] << endl;
    cout << "  ZOOM:     "
         << app_counts[(int)AppType::ZOOM]     << endl;
    cout << "  GAMING:   "
         << app_counts[(int)AppType::GAMING]   << endl;
    cout << "  UNKNOWN:  "
         << app_counts[(int)AppType::UNKNOWN]  << endl;
    cout << "  BLOCKED:  "
         << blocked_count                       << endl;
}