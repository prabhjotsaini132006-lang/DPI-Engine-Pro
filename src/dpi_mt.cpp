#include "dpi_engine.h"
#include "pcap_reader.h"
#include "load_balancer.h"
#include <iostream>
#include <string>

using namespace std;

void printUsageMT(const string& program)
{
    cout << "Usage: " << program
         << " <pcap_file> [options]\n";
    cout << "\nOptions:\n";
    cout << "  --csv    <file>  Training CSV\n";
    cout << "  --model  <file>  Model file\n";
    cout << "  --rules  <file>  Rules file\n";
    cout << "  --threads <n>    Worker threads (default: 4)\n";
    cout << "  --trees   <n>    RF trees (default: 10)\n";
    cout << "  --verbose        Print each packet\n";
    cout << "  --blocked-only   Print blocked only\n";
    cout << "  --no-rf          Use single tree\n";
    cout << "\nExample:\n";
    cout << "  " << program
         << " capture.pcap --threads 8 --verbose\n";
}

DPIConfig parseArgsMT(int argc, char* argv[])
{
    DPIConfig config;
    if (argc < 2) return config;

    config.pcap_file = argv[1];

    for (int i = 2; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--csv" && i+1 < argc)
            config.csv_file = argv[++i];
        else if (arg == "--model" && i+1 < argc)
            config.model_file = argv[++i];
        else if (arg == "--rules" && i+1 < argc)
            config.rules_file = argv[++i];
        else if (arg == "--threads" && i+1 < argc)
            config.worker_threads = stoi(argv[++i]);
        else if (arg == "--trees" && i+1 < argc)
            config.rf_trees = stoi(argv[++i]);
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

    if (argc < 2) {
        printUsageMT(argv[0]);
        return 1;
    }

    DPIConfig config = parseArgsMT(argc, argv);

    if (config.pcap_file.empty()) {
        printUsageMT(argv[0]);
        return 1;
    }

    cout << "Configuration:\n";
    cout << "  PCAP file:     " << config.pcap_file       << "\n";
    cout << "  CSV file:      " << config.csv_file        << "\n";
    cout << "  Rules file:    " << config.rules_file      << "\n";
    cout << "  Threads:       " << config.worker_threads  << "\n";
    cout << "  RF trees:      " << config.rf_trees        << "\n";
    cout << "  Random Forest: "
         << (config.use_random_forest ? "YES" : "NO")     << "\n\n";

    // Create and initialize engine
    DPIEngine engine(config);
    if (!engine.initialize()) {
        cerr << "ERROR: Engine initialization failed!\n";
        return 1;
    }

    // Process the pcap file
    if (!engine.processPcap(config.pcap_file)) {
        cerr << "ERROR: Failed to process pcap file!\n";
        return 1;
    }

    // Print final report
    engine.printReport();

    return 0;
}