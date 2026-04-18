#include "dpi_engine.h"
#include "pcap_reader.h"
#include "load_balancer.h"
#include "live_capture.h"
#include "signal_handler.h"
#include <iostream>
#include <string>

using namespace std;

void printUsageMT(const string& program)
{
    cout << "Usage: " << program
         << " [options]\n\n";
    cout << "Input (required, pick one):\n";
    cout << "  --input  <file>    Read from pcap file\n";
    cout << "  --live             Capture live traffic\n";
    cout << "  --interface <name> Interface for live"
         << " capture (default: auto)\n\n";
    cout << "ML Options:\n";
    cout << "  --csv    <file>  Training CSV\n";
    cout << "  --model  <file>  Model file\n";
    cout << "  --no-rf          Use single tree\n";
    cout << "  --trees  <n>     RF trees (default: 10)\n";
    cout << "  --confidence <f> Min confidence"
         << " (default: 0.6)\n\n";
    cout << "Engine Options:\n";
    cout << "  --rules  <file>  Rules file\n";
    cout << "  --config <file>  Config INI file\n";
    cout << "  --threads <n>    Worker threads"
         << " (default: 4)\n\n";
    cout << "Output Options:\n";
    cout << "  --verbose        Print each packet\n";
    cout << "  --blocked-only   Print blocked only\n";
    cout << "  --list-interfaces  List network"
         << " interfaces\n\n";
    cout << "Examples:\n";
    cout << "  " << program
         << " --input capture.pcap --verbose\n";
    cout << "  " << program
         << " --live --interface eth0\n";
    cout << "  " << program
         << " --live --threads 8 --verbose\n";
}

DPIConfig parseArgsMT(int argc, char* argv[])
{
    DPIConfig config;
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--input" && i+1 < argc)
            config.pcap_file = argv[++i];
        else if (arg == "--csv" && i+1 < argc)
            config.csv_file = argv[++i];
        else if (arg == "--model" && i+1 < argc)
            config.model_file = argv[++i];
        else if (arg == "--rules" && i+1 < argc)
            config.rules_file = argv[++i];
        else if (arg == "--threads" && i+1 < argc)
            config.worker_threads = stoi(argv[++i]);
        else if (arg == "--trees" && i+1 < argc)
            config.rf_trees = stoi(argv[++i]);
        else if (arg == "--confidence" && i+1 < argc)
            config.min_confidence = stod(argv[++i]);
        else if (arg == "--verbose")
            config.verbose = true;
        else if (arg == "--blocked-only")
            config.print_blocked_only = true;
        else if (arg == "--no-rf")
            config.use_random_forest = false;
    }
    return config;
}

int main(int argc, char* argv[])
{
    cout << "DPI-Engine-Pro v2.0 (Multi-threaded)\n";
    cout << "ML-powered Deep Packet Inspection\n";
    cout << "══════════════════════════════════\n\n";

    // Handle special flags first
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];

        if (arg == "--list-interfaces") {
            LiveCapture::printInterfaces();
            return 0;
        }

        if (arg == "--help" || arg == "-h") {
            printUsageMT(argv[0]);
            return 0;
        }
    }

    if (argc < 2) {
        printUsageMT(argv[0]);
        return 1;
    }

    // Check mode
    bool live_mode = false;
    string interface_name = "";

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--live") {
            live_mode = true;
        }
        if (arg == "--interface" && i+1 < argc) {
            interface_name = argv[++i];
        }
    }

    DPIConfig config = parseArgsMT(argc, argv);

    if (!live_mode && config.pcap_file.empty()) {
        cerr << "ERROR: No input specified!\n";
        cerr << "Use --input <file> or --live\n\n";
        printUsageMT(argv[0]);
        return 1;
    }

    // Print config
    cout << "Mode:          "
         << (live_mode ? "LIVE CAPTURE" : "PCAP FILE")
         << "\n";
    if (live_mode) {
        cout << "Interface:     "
             << (interface_name.empty() ?
                 "auto" : interface_name) << "\n";
    } else {
        cout << "Input file:    "
             << config.pcap_file << "\n";
    }
    cout << "Threads:       "
         << config.worker_threads << "\n";
    cout << "Random Forest: "
         << (config.use_random_forest ? "YES" : "NO")
         << "\n\n";

    // Initialize engine
    DPIEngine engine(config);
    if (!engine.initialize()) {
        cerr << "ERROR: Engine init failed!\n";
        return 1;
    }

    // Setup signal handler
    SignalHandler::setup();

    // ── PCAP FILE MODE ──
    if (!live_mode) {
        if (!engine.processPcap(config.pcap_file)) {
            cerr << "ERROR: Failed to process "
                 << config.pcap_file << "\n";
            return 1;
        }
        engine.printReport();
        return 0;
    }

    // ── LIVE CAPTURE MODE ──
    if (interface_name.empty()) {
        // Auto-select first available interface
        auto interfaces =
            LiveCapture::listInterfaces();

        if (interfaces.empty()) {
            cerr << "ERROR: No interfaces found!\n";
            cerr << "Run as Administrator/root\n";
            return 1;
        }

        // Pick first UP interface
        for (const auto& iface : interfaces) {
            if (iface.is_up &&
                iface.ip_address != "0.0.0.0") {
                interface_name = iface.ip_address;
                cout << "Auto-selected interface: "
                     << iface.name
                     << " (" << iface.ip_address
                     << ")\n";
                break;
            }
        }

        if (interface_name.empty()) {
            cerr << "ERROR: No suitable interface!\n";
            cerr << "Use --interface <name>\n";
            LiveCapture::printInterfaces();
            return 1;
        }
    }

    LiveCapture capture;
    if (!capture.open(interface_name)) {
        cerr << "ERROR: Cannot open interface "
             << interface_name << "\n";
        return 1;
    }

    cout << "Starting live capture...\n";
    cout << "Press Ctrl+C to stop\n\n";

    capture.startCapture();

    uint64_t packet_count = 0;

    while (!SignalHandler::shouldStop()) {
        RawPacket pkt;
        if (capture.getNextPacket(pkt)) {
            packet_count++;
        } else {
            // No packet available, small sleep
            this_thread::sleep_for(
                chrono::microseconds(100));
        }

        // Print progress every 1000 packets
        if (packet_count % 1000 == 0 &&
            packet_count > 0) {
            cout << "Captured "
                 << packet_count
                 << " packets\r";
            cout.flush();
        }
    }

    capture.stopCapture();

    cout << "\nLive capture stopped.\n";
    cout << "Total captured: "
         << capture.packetsCaptured()
         << " packets\n";

    engine.printReport();
    return 0;
}