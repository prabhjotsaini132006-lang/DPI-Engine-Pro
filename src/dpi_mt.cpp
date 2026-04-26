#include "dpi_engine.h"
#include "pcap_reader.h"
#include "live_capture.h"
#include "signal_handler.h"
#include "training_data.h"
#include "model_evaluator.h"
#include "ml_metrics.h"
#include "decision_tree.h"

#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

using namespace std;

void printUsageMT(const string& program)
{
    cout << "DPI-Engine-Pro v2.0\n";
    cout << "ML-powered Deep Packet Inspection\n\n";
    cout << "Usage: " << program << " [options]\n\n";
    cout << "Input (pick one):\n";
    cout << "  --input  <file>      Read pcap file\n";
    cout << "  --live               Capture live traffic\n";
    cout << "  --interface <n>      Interface for live capture\n\n";
    cout << "ML Options:\n";
    cout << "  --csv    <file>      Training data CSV\n";
    cout << "  --model  <file>      Saved model file\n";
    cout << "  --no-rf              Use single Decision Tree\n";
    cout << "  --trees  <n>         RF tree count (default: 10)\n";
    cout << "  --confidence <0-1>   Min ML confidence (default: 0.6)\n\n";
    cout << "Engine Options:\n";
    cout << "  --rules  <file>      Blocking rules file\n";
    cout << "  --no-reassembly      Disable TCP stream reassembly\n";
    cout << "  --no-anomaly         Disable anomaly detection\n\n";
    cout << "Output Options:\n";
    cout << "  --verbose            Print each packet\n";
    cout << "  --blocked-only       Print blocked flows only\n\n";
    cout << "Tools:\n";
    cout << "  --evaluate           Evaluate ML model accuracy\n";
    cout << "  --list-interfaces    Show network interfaces\n";
    cout << "  --help               Show this help\n\n";
    cout << "Examples:\n";
    cout << "  " << program << " --input capture.pcap\n";
    cout << "  " << program << " --input capture.pcap --verbose\n";
    cout << "  " << program << " --live --interface eth0\n";
    cout << "  " << program << " --evaluate\n";
}

void runEvaluation(const DPIConfig& config)
{
    cout << "\n═══════════════════════════════════════\n";
    cout << "        ML Model Evaluation Mode        \n";
    cout << "═══════════════════════════════════════\n";

    TrainingData td;
    if (!td.loadCSV(config.csv_file)) {
        cerr << "ERROR: Cannot load: " << config.csv_file << "\n";
        return;
    }
    cout << "Loaded " << td.size() << " flow samples\n\n";

    if (td.size() < 10) {
        cerr << "WARNING: Only " << td.size()
             << " samples — add more rows for reliable results.\n\n";
    }

    // Compare Decision Tree vs Random Forest
    ModelEvaluator evaluator(0.2);
    evaluator.compareModels(td.getData());

    // Detailed per-class metrics
    cout << "\n── Detailed ML Metrics ──\n";
    MLMetrics metrics;

    vector<FlowFeatures> train_set, test_set;
    for (size_t i = 0; i < td.getData().size(); i++) {
        if (i % 5 == 0) test_set.push_back(td.getData()[i]);
        else            train_set.push_back(td.getData()[i]);
    }

    if (!train_set.empty() && !test_set.empty()) {
        DecisionTree dt(5, 2);
        dt.train(train_set);
        for (const auto& f : test_set)
            metrics.addPrediction(f.label, dt.predict(f));
        metrics.calculate();
        metrics.printReport();
        metrics.printConfusionMatrix();
    }
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif

    cout << "DPI-Engine-Pro v2.0\n";
    cout << "ML-powered Deep Packet Inspection\n";
    cout << "══════════════════════════════════\n\n";

    if (argc < 2) { printUsageMT(argv[0]); return 1; }

    // Parse args
    DPIConfig config;
    config.enable_reassembly = true;
    config.enable_anomaly    = true;
    config.enable_benchmark  = true;

    bool   live_mode      = false;
    string interface_name = "";
    bool   do_evaluate    = false;
    bool   list_ifaces    = false;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if      (arg == "--input"      && i+1 < argc) config.pcap_file          = argv[++i];
        else if (arg == "--csv"        && i+1 < argc) config.csv_file           = argv[++i];
        else if (arg == "--model"      && i+1 < argc) config.model_file         = argv[++i];
        else if (arg == "--rules"      && i+1 < argc) config.rules_file         = argv[++i];
        else if (arg == "--trees"      && i+1 < argc) config.rf_trees           = stoi(argv[++i]);
        else if (arg == "--confidence" && i+1 < argc) config.min_confidence     = stod(argv[++i]);
        else if (arg == "--interface"  && i+1 < argc) interface_name            = argv[++i];
        else if (arg == "--verbose")                  config.verbose            = true;
        else if (arg == "--blocked-only")             config.print_blocked_only = true;
        else if (arg == "--no-rf")                    config.use_random_forest  = false;
        else if (arg == "--no-reassembly")            config.enable_reassembly  = false;
        else if (arg == "--no-anomaly")               config.enable_anomaly     = false;
        else if (arg == "--live")                     live_mode                 = true;
        else if (arg == "--evaluate")                 do_evaluate               = true;
        else if (arg == "--list-interfaces")          list_ifaces               = true;
        else if (arg == "--help" || arg == "-h") { printUsageMT(argv[0]); return 0; }
    }

    if (list_ifaces) { LiveCapture::printInterfaces(); return 0; }
    if (do_evaluate) { runEvaluation(config); return 0; }

    if (!live_mode && config.pcap_file.empty()) {
        cerr << "ERROR: No input. Use --input <file> or --live\n\n";
        printUsageMT(argv[0]);
        return 1;
    }

    // Print config
    cout << "Mode:            " << (live_mode ? "LIVE" : "PCAP") << "\n";
    if (!live_mode) cout << "Input:           " << config.pcap_file << "\n";
    cout << "ML:              " << (config.use_random_forest ? "Random Forest" : "Decision Tree") << "\n";
    cout << "TCP Reassembly:  " << (config.enable_reassembly ? "ON" : "OFF") << "\n";
    cout << "Anomaly Detect:  " << (config.enable_anomaly    ? "ON" : "OFF") << "\n";
    cout << "Benchmarking:    " << (config.enable_benchmark  ? "ON" : "OFF") << "\n\n";

    DPIEngine engine(config);
    if (!engine.initialize()) {
        cerr << "ERROR: Engine init failed!\n";
        return 1;
    }

    SignalHandler::setup();

    // ── PCAP MODE ──
    if (!live_mode) {
        if (!engine.processPcap(config.pcap_file)) {
            cerr << "ERROR: Failed to process " << config.pcap_file << "\n";
            return 1;
        }
        engine.printReport();
        return 0;
    }

    // ── LIVE MODE ──
    if (interface_name.empty()) {
        auto interfaces = LiveCapture::listInterfaces();
        if (interfaces.empty()) {
            cerr << "ERROR: No interfaces. Run as root.\n";
            return 1;
        }
        for (const auto& iface : interfaces) {
            if (iface.is_up && iface.ip_address != "0.0.0.0") {
                interface_name = iface.name;
                cout << "Auto-selected: " << iface.name
                     << " (" << iface.ip_address << ")\n";
                break;
            }
        }
        if (interface_name.empty()) {
            cerr << "ERROR: No suitable interface. Use --interface <n>\n";
            LiveCapture::printInterfaces();
            return 1;
        }
    }

    LiveCapture capture;
    if (!capture.open(interface_name)) {
        cerr << "ERROR: Cannot open: " << interface_name
             << "\nRun as root / Administrator\n";
        return 1;
    }

    cout << "Live capture on " << interface_name << "\n";
    cout << "Press Ctrl+C to stop\n\n";

    capture.startCapture();

    uint64_t packet_count = 0;
    uint64_t last_print   = 0;

    auto last_expiry = chrono::steady_clock::now();

while (!SignalHandler::shouldStop()) {
    RawPacket pkt;
    if (capture.getNextPacket(pkt)) {
        engine.processPacket(pkt);
        packet_count++;

        if (packet_count - last_print >= 1000) {
            last_print = packet_count;
            const DPIStats& s = engine.getStats();
            cout << "\r  Captured: "   << packet_count
                 << " | Classified: " << s.flows_classified.load()
                 << " | Blocked: "    << s.flows_blocked.load()
                 << " | Alerts: "     << s.alerts_generated.load()
                 << "          ";
            cout.flush();
        }
    } else {
        this_thread::sleep_for(chrono::microseconds(100));
    }

    // Expire old flows every 30 seconds
    auto now = chrono::steady_clock::now();
    if (chrono::duration_cast<chrono::seconds>(
            now - last_expiry).count() >= 30) {
        last_expiry = now;
        double ts = chrono::duration_cast<chrono::milliseconds>(
            now.time_since_epoch()).count();
        engine.expireFlows(ts);
    }
}

    capture.stopCapture();
    cout << "\n\nStopped. Captured: "
         << capture.packetsCaptured() << " packets\n";
    engine.printReport();
    return 0;
}