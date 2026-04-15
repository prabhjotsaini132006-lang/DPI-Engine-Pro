#include "dpi_engine.h"
#include "pcap_reader.h"
#include "signal_handler.h"
#include <iostream>
#include <iomanip>

using namespace std;

void DPIStats::print() const
{
    cout << "\n=== DPI Engine Statistics ===" << endl;
    cout << "Packets processed: " << packets_processed << endl;
    cout << "Packets dropped:   " << packets_dropped   << endl;
    cout << "Flows classified:  " << flows_classified  << endl;
    cout << "Flows blocked:     " << flows_blocked     << endl;
    cout << "Via SNI:           " << sni_classified    << endl;
    cout << "Via ML:            " << ml_classified     << endl;
    cout << "Cache hits:        " << cache_hits        << endl;
    cout << "Unknown flows:     " << unknown_flows     << endl;
}
DPIEngine::DPIEngine(const DPIConfig& config)
    : config(config),
      random_forest(config.rf_trees,
                    config.tree_max_depth),
      conn_tracker(config.flow_timeout_sec),
      fast_path(config.cache_timeout_sec)
{}

DPIEngine::~DPIEngine() {}

bool DPIEngine::initialize()
{
    cout << "DPIEngine: Initializing..." << endl;

    // Step 1: Load ML model
    cout << "\n[1/4] Loading ML model..." << endl;

    if (config.use_random_forest) {
        TrainingData td;
        if (!td.loadCSV(config.csv_file)) {
            cerr << "DPIEngine: Failed to load CSV" << endl;
            return false;
        }
        random_forest.train(td.getData());
        cout << "      Random Forest ready ("
             << config.rf_trees << " trees)" << endl;
    } else {
        if (!ml_classifier.loadOrTrain(
                config.csv_file,
                config.model_file)) {
            cerr << "DPIEngine: Failed to load model" << endl;
            return false;
        }
    }

    // Step 2: Load rules
    cout << "\n[2/4] Loading rules..." << endl;
    if (!config.rules_file.empty()) {
        rule_manager.loadRules(config.rules_file);
    }
    rule_manager.addDefaultRules();
    rule_manager.printRules();

    // Step 3: Connection tracker
    cout << "\n[3/4] Connection tracker ready" << endl;

    // Step 4: Fast path cache
    cout << "\n[4/4] Fast path cache ready" << endl;

    cout << "\nDPIEngine: Initialization complete!" << endl;
    return true;
}

AppType DPIEngine::classifyFlow(Flow& flow)
{
    // Fast path cache check
    CacheEntry cache_entry;
    if (fast_path.lookup(flow.tuple, cache_entry)) {
        stats.cache_hits++;
        return cache_entry.app_type;
    }

    AppType result = AppType::UNKNOWN;

    // Priority 1: SNI
    if (!flow.sni.empty()) {
        result = sniToAppType(flow.sni);
        if (result != AppType::UNKNOWN) {
            stats.sni_classified++;
            fast_path.insert(
                flow.tuple, result, false,
                1.0,
                flow.features.flow_duration_ms);
            return result;
        }
    }

    // Priority 2: ML
    if (flow.features.total_packets >= 5) {
        if (config.use_random_forest) {
            Prediction pred =
                random_forest.predictWithConfidence(
                    flow.features);
            if (pred.confidence >= config.min_confidence) {
                result = pred.app_type;
                stats.ml_classified++;
                fast_path.insert(
                    flow.tuple, result, false,
                    pred.confidence,
                    flow.features.flow_duration_ms);
            }
        } else {
            Prediction pred =
                ml_classifier.predictWithConfidence(
                    flow.features);
            if (pred.confidence >= config.min_confidence) {
                result = pred.app_type;
                stats.ml_classified++;
            }
        }
    }

    if (result == AppType::UNKNOWN) {
        stats.unknown_flows++;
    }

    return result;
}

void DPIEngine::processPacket(const RawPacket& raw)
{
    ParsedPacket pkt = parser.parse(raw);
    if (!pkt.valid) {
        stats.packets_dropped++;
        return;
    }

    stats.packets_processed++;

    Flow& flow = conn_tracker.processPacket(
        pkt, raw.timestamp_ms);

    // SNI extraction
    if (pkt.is_tls && flow.sni.empty() &&
        pkt.payload && pkt.payload_len > 0)
    {
        string sni = sni_extractor.extract(
            pkt.payload, pkt.payload_len);
        if (!sni.empty()) {
            flow.sni = sni;
            conn_tracker.updateSNI(flow.tuple, sni);
        }
    }

    // Classify
    AppType app_type = classifyFlow(flow);
    flow.app_type    = app_type;

    if (app_type != AppType::UNKNOWN) {
        stats.flows_classified++;
    }

    // Block check
    bool blocked = rule_manager.shouldBlock(flow);
    flow.blocked = blocked;
    if (blocked) {
        stats.flows_blocked++;
        conn_tracker.updateBlocked(flow.tuple, true);
    }

    // Verbose output
    if (config.verbose) {
        if (!config.print_blocked_only || blocked) {
            printIP(pkt.src_ip);
            cout << ":" << pkt.src_port << " -> ";
            printIP(pkt.dst_ip);
            cout << ":" << pkt.dst_port;
            cout << " | " << appTypeToString(app_type);
            if (!flow.sni.empty())
                cout << " (" << flow.sni << ")";
            if (blocked)
                cout << " [BLOCKED]";
            cout << endl;
        }
    }
}

bool DPIEngine::processPcap(const string& pcap_file)
{
    PcapReader reader;

    if (!reader.open(pcap_file)) {
        cerr << "DPIEngine: Cannot open "
             << pcap_file << endl;
        return false;
    }

    cout << "\nDPIEngine: Processing "
         << pcap_file << "..." << endl;

    RawPacket raw;
    uint64_t  packet_count = 0;

    while (reader.readNext(raw)) {

    // Check for Ctrl+C graceful shutdown
    if (SignalHandler::shouldStop()) {
        cout << "\nDPIEngine: Stopping gracefully..."
             << endl;
        break;
    }

    processPacket(raw);
    packet_count++;
        if (packet_count % 10000 == 0) {
            conn_tracker.expireOldFlows(
                raw.timestamp_ms);
            fast_path.evictExpired(
                raw.timestamp_ms);
            cout << "Processed " << packet_count
                 << " packets, "
                 << conn_tracker.flowCount()
                 << " active flows" << endl;
        }
    }

    reader.close();
    cout << "DPIEngine: Finished processing "
         << packet_count << " packets" << endl;

    return true;
}

const DPIStats& DPIEngine::getStats() const
{
    return stats;
}

void DPIEngine::printReport() const
{
    cout << "\n";
    cout << "═══════════════════════════════════════\n";
    cout << "     DPI-Engine-Pro Final Report        \n";
    cout << "═══════════════════════════════════════\n";
    stats.print();
    cout << "\n── Active Flows ──" << endl;
    conn_tracker.printSummary();
    cout << "\n── Cache Performance ──" << endl;
    fast_path.printStats();
    cout << "\n── Blocking Rules ──" << endl;
    rule_manager.printRules();
    cout << "═══════════════════════════════════════\n";
}

void DPIEngine::printIP(uint32_t ip) const
{
    cout << ((ip >> 24) & 0xFF) << "."
         << ((ip >> 16) & 0xFF) << "."
         << ((ip >> 8)  & 0xFF) << "."
         << ( ip        & 0xFF);
}