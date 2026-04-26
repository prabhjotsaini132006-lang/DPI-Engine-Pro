#include "dpi_engine.h"
#include "pcap_reader.h"
#include "signal_handler.h"
#include <iostream>
#include <iomanip>

using namespace std;

void DPIStats::print() const
{
    cout << "\n=== DPI Engine Statistics ===\n";
    cout << "  Packets processed:   " << packets_processed   << "\n";
    cout << "  Packets dropped:     " << packets_dropped     << "\n";
    cout << "  Flows classified:    " << flows_classified    << "\n";
    cout << "  Flows blocked:       " << flows_blocked       << "\n";
    cout << "  Via SNI:             " << sni_classified      << "\n";
    cout << "  Via ML:              " << ml_classified       << "\n";
    cout << "  Cache hits:          " << cache_hits          << "\n";
    cout << "  Unknown flows:       " << unknown_flows       << "\n";
    cout << "  Anomaly alerts:      " << alerts_generated    << "\n";
    cout << "  Streams reassembled: " << streams_reassembled << "\n";
}

DPIEngine::DPIEngine(const DPIConfig& config)
    : config(config),
      random_forest(config.rf_trees, config.tree_max_depth),
      conn_tracker(config.flow_timeout_sec),
      fast_path(config.cache_timeout_sec)
{}

DPIEngine::~DPIEngine() {}

bool DPIEngine::initialize()
{
    cout << "DPIEngine: Initializing...\n";

    cout << "\n[1/4] Loading ML model...\n";
    if (config.use_random_forest) {
        TrainingData td;
        if (!td.loadCSV(config.csv_file)) {
            cerr << "DPIEngine: Failed to load CSV\n";
            return false;
        }
        random_forest.train(td.getData());
        cout << "      Random Forest ready ("
             << config.rf_trees << " trees)\n";
    } else {
        if (!ml_classifier.loadOrTrain(
                config.csv_file, config.model_file)) {
            cerr << "DPIEngine: Failed to load model\n";
            return false;
        }
    }

    cout << "\n[2/4] Loading rules...\n";
    if (!config.rules_file.empty())
        rule_manager.loadRules(config.rules_file);
    rule_manager.addDefaultRules();
    rule_manager.printRules();

    cout << "\n[3/4] Connection tracker ready\n";
    cout << "\n[4/4] Fast path cache ready\n";

    if (config.enable_reassembly)
        cout << "      TCP stream reassembly: ENABLED\n";
    if (config.enable_anomaly)
        cout << "      Anomaly detection:     ENABLED\n";
    if (config.enable_benchmark)
        cout << "      Performance benchmark: ENABLED\n";

    cout << "\nDPIEngine: Initialization complete!\n";
    return true;
}

AppType DPIEngine::classifyFlow(Flow& flow)
{
    CacheEntry cache_entry;
    if (fast_path.lookup(flow.tuple, cache_entry)) {
        stats.cache_hits++;
        return cache_entry.app_type;
    }

    AppType result = AppType::UNKNOWN;

    if (!flow.sni.empty()) {
        result = sniToAppType(flow.sni);
        if (result != AppType::UNKNOWN) {
            stats.sni_classified++;
            fast_path.insert(flow.tuple, result, false, 1.0,
                             flow.features.flow_duration_ms);
            return result;
        }
    }

    if (flow.features.total_packets >= 5) {
        Prediction pred;
        if (config.use_random_forest)
            pred = random_forest.predictWithConfidence(flow.features);
        else
            pred = ml_classifier.predictWithConfidence(flow.features);

        if (pred.confidence >= config.min_confidence) {
            result = pred.app_type;
            stats.ml_classified++;
            fast_path.insert(flow.tuple, result, false,
                             pred.confidence,
                             flow.features.flow_duration_ms);
        }
    }

    if (result == AppType::UNKNOWN)
        stats.unknown_flows++;

    return result;
}

void DPIEngine::processPacket(const RawPacket& raw)
{
    if (config.enable_benchmark)
        bench.recordPacket(raw.original_len);

    ParsedPacket pkt = parser.parse(raw);
    if (!pkt.valid) {
        stats.packets_dropped++;
        return;
    }

    stats.packets_processed++;

    Flow& flow = conn_tracker.processPacket(pkt, raw.timestamp_ms);

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

    // TCP Stream Reassembly
    if (config.enable_reassembly &&
        pkt.protocol == 6 && pkt.payload_len > 0)
    {
        int added = reassembler.addSegment(
            flow.tuple, pkt.tcp_seq,
            pkt.payload, pkt.payload_len,
            pkt.isSYN(), pkt.isFIN());
        if (added > 0)
            stats.streams_reassembled++;
        if (pkt.isRST())
            reassembler.clearStream(flow.tuple);
    }

    // Classify
    AppType app_type = classifyFlow(flow);
    flow.app_type = app_type;
    if (app_type != AppType::UNKNOWN)
        stats.flows_classified++;

    // Blocking
    bool blocked = rule_manager.shouldBlock(flow);
    flow.blocked = blocked;
    if (blocked) {
        stats.flows_blocked++;
        conn_tracker.updateBlocked(flow.tuple, true);
    }

    // Anomaly Detection
    if (config.enable_anomaly) {
        auto alerts = anomaly_detector.check(flow);
        if (!alerts.empty())
            stats.alerts_generated += (uint64_t)alerts.size();
    }

    if (config.enable_benchmark)
        bench.recordClassification();

    // Verbose
    if (config.verbose) {
        if (!config.print_blocked_only || blocked) {
            printIP(pkt.src_ip);
            cout << ":" << pkt.src_port << " -> ";
            printIP(pkt.dst_ip);
            cout << ":" << pkt.dst_port
                 << " | " << appTypeToString(app_type);
            if (!flow.sni.empty())
                cout << " (" << flow.sni << ")";
            if (blocked) cout << " [BLOCKED]";
            if (pkt.protocol == 6)
                cout << " TCP seq=" << pkt.tcp_seq;
            cout << "\n";
        }
    }
}

bool DPIEngine::processPcap(const string& pcap_file)
{
    PcapReader reader;
    if (!reader.open(pcap_file)) {
        cerr << "DPIEngine: Cannot open " << pcap_file << "\n";
        return false;
    }

    cout << "\nDPIEngine: Processing " << pcap_file << "...\n";

    if (config.enable_benchmark)
        bench.start("pcap_processing");

    RawPacket raw;
    uint64_t  packet_count = 0;

    while (reader.readNext(raw)) {
        if (SignalHandler::shouldStop()) {
            cout << "\nDPIEngine: Stopping gracefully...\n";
            break;
        }
        processPacket(raw);
        packet_count++;

        if (packet_count % 10000 == 0) {
            conn_tracker.expireOldFlows(raw.timestamp_ms);
            fast_path.evictExpired(raw.timestamp_ms);
            cout << "  Processed " << packet_count
                 << " packets | "
                 << conn_tracker.flowCount()
                 << " active flows | "
                 << stats.alerts_generated.load()
                 << " alerts\n";
        }
    }

    if (config.enable_benchmark)
        bench.stop("pcap_processing");

    reader.close();
    cout << "DPIEngine: Finished — " << packet_count << " packets\n";
    return true;
}

const DPIStats& DPIEngine::getStats() const   { return stats; }
const Benchmark& DPIEngine::getBenchmark() const { return bench; }

void DPIEngine::printReport() const
{
    cout << "\n═══════════════════════════════════════\n";
    cout << "     DPI-Engine-Pro v2.0 Final Report   \n";
    cout << "═══════════════════════════════════════\n";

    stats.print();

    if (config.enable_benchmark)
        bench.printReport();

    cout << "\n── Active Flows ──\n";
    conn_tracker.printSummary();

    cout << "\n── Cache Performance ──\n";
    fast_path.printStats();

    if (config.enable_reassembly)
        reassembler.printStats();

    if (config.enable_anomaly)
        anomaly_detector.printAlerts();

    cout << "\n── Blocking Rules ──\n";
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

void DPIEngine::expireFlows(double timestamp_ms)
{
    conn_tracker.expireOldFlows(timestamp_ms);
    fast_path.evictExpired(timestamp_ms);
}