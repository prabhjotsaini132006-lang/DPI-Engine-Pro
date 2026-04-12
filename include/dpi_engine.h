#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "flow_features.h"
#include "ml_classifier.h"
#include "random_forest.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include "fast_path.h"
#include "thread_safe_queue.h"
#include "training_data.h"
#include <string>
#include <atomic>
#include <memory>

struct DPIConfig {
    std::string pcap_file          = "";
    std::string csv_file           = "data/training_flows.csv";
    std::string model_file         = "data/model.txt";
    std::string rules_file         = "data/rules.txt";
    bool        use_random_forest  = true;
    int         rf_trees           = 10;
    int         tree_max_depth     = 5;
    double      min_confidence     = 0.6;
    int         worker_threads     = 4;
    int         queue_size         = 10000;
    int         flow_timeout_sec   = 120;
    int         cache_timeout_sec  = 300;
    bool        verbose            = false;
    bool        print_blocked_only = false;
};

struct DPIStats {
    std::atomic<uint64_t> packets_processed {0};
    std::atomic<uint64_t> packets_dropped   {0};
    std::atomic<uint64_t> flows_classified  {0};
    std::atomic<uint64_t> flows_blocked     {0};
    std::atomic<uint64_t> sni_classified    {0};
    std::atomic<uint64_t> ml_classified     {0};
    std::atomic<uint64_t> cache_hits        {0};
    std::atomic<uint64_t> unknown_flows     {0};

    void print() const;
};

class DPIEngine {
public:
    DPIEngine(const DPIConfig& config);
    ~DPIEngine();

    bool initialize();
    bool processPcap(const std::string& pcap_file);
    const DPIStats& getStats() const;
    void printReport() const;

private:
    DPIConfig         config;
    DPIStats          stats;
    MLClassifier      ml_classifier;
    RandomForest      random_forest;
    RuleManager       rule_manager;
    ConnectionTracker conn_tracker;
    FastPath          fast_path;
    PacketParser      parser;
    SNIExtractor      sni_extractor;

    void    processPacket(const RawPacket& raw);
    AppType classifyFlow(Flow& flow);
    void    printIP(uint32_t ip) const;
};

#endif // DPI_ENGINE_H