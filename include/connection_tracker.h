#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include "flow_features.h"
#include "rule_manager.h"
#include "ml_classifier.h"
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <vector>

// ─────────────────────────────────────────
// Tracks all active network flows
// Handles flow expiry and cleanup
// ─────────────────────────────────────────
class ConnectionTracker {
public:
    ConnectionTracker(
        int flow_timeout_sec = 120,
        int max_flows        = 100000);

    // Process a new parsed packet
    // Returns reference to updated flow
    Flow& processPacket(const ParsedPacket& pkt,
                        double timestamp_ms);

    // Remove flows that have timed out
    int  expireOldFlows(double current_time_ms);

    // Get all current flows (for reporting)
    std::vector<Flow> getAllFlows() const;

    // How many active flows
    size_t flowCount() const;

    // Update SNI for a flow
    void updateSNI(const FiveTuple& tuple,
                   const std::string& sni);

    // Update app type for a flow
    void updateAppType(const FiveTuple& tuple,
                       AppType app_type);

    // Update blocked status
    void updateBlocked(const FiveTuple& tuple,
                       bool blocked);

    // Print summary
    void printSummary() const;

private:
    std::unordered_map<FiveTuple,
                       Flow,
                       FiveTupleHash>  flow_table;
    mutable std::mutex                  mutex;
    int                                 flow_timeout_sec;
    int                                 max_flows;

    // Last seen time for each flow
    std::unordered_map<FiveTuple,
                       double,
                       FiveTupleHash>  last_seen;
};

#endif // CONNECTION_TRACKER_H