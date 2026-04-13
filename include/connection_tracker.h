#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include "flow_features.h"
#include "rule_manager.h"
#include "packet_parser.h"
#include <unordered_map>
#include <mutex>
#include <vector>
#include <string>

class ConnectionTracker {
public:
    ConnectionTracker(int flow_timeout_sec = 120,
                      int max_flows        = 100000);

    Flow& processPacket(const ParsedPacket& pkt,
                        double timestamp_ms);
    int   expireOldFlows(double current_time_ms);
    std::vector<Flow> getAllFlows() const;
    size_t flowCount() const;
    void   updateSNI(const FiveTuple& tuple,
                     const std::string& sni);
    void   updateAppType(const FiveTuple& tuple,
                         AppType app_type);
    void   updateBlocked(const FiveTuple& tuple,
                         bool blocked);
    void   printSummary() const;

private:
    std::unordered_map<FiveTuple,
                       Flow,
                       FiveTupleHash>  flow_table;
    std::unordered_map<FiveTuple,
                       double,
                       FiveTupleHash>  last_seen;
    mutable std::mutex mtx;
    int flow_timeout_sec;
    int max_flows;
};

#endif // CONNECTION_TRACKER_H