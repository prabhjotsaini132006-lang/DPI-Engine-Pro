#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "flow_features.h"
#include "ml_classifier.h"
#include <iostream>
#include <unordered_map>
#include <string>
#include <iomanip>

using namespace std;

// ─────────────────────────────────────────
// Print a human readable IP address
// instead of raw uint32
// ─────────────────────────────────────────
void printIP(uint32_t ip)
{
    cout << ((ip >> 24) & 0xFF) << "."
         << ((ip >> 16) & 0xFF) << "."
         << ((ip >> 8)  & 0xFF) << "."
         << ( ip        & 0xFF);
}

// ─────────────────────────────────────────
// Hybrid classification logic
// SNI first, ML second
// ─────────────────────────────────────────
AppType classifyFlow(const Flow&         flow,
                     const MLClassifier& classifier)
{
    // Priority 1: SNI available → use it (100% accurate)
    if (!flow.sni.empty()) {
        return sniToAppType(flow.sni);
    }

    // Priority 2: Enough packets → use ML with confidence check
    if (flow.features.total_packets >= 5) {
        Prediction pred =
            classifier.predictWithConfidence(flow.features);

        // Only trust prediction if confidence is high enough
        if (pred.confidence >= 0.6) {
            return pred.app_type;
        } else {
            // Not confident enough → honest UNKNOWN
            return AppType::UNKNOWN;
        }
    }

    // Priority 3: Not enough data yet
    return AppType::UNKNOWN;
}
// ─────────────────────────────────────────
// Print final report after processing
// ─────────────────────────────────────────
void printReport(
    const unordered_map<FiveTuple, Flow, FiveTupleHash>& flows,
    uint64_t total_packets)
{
    cout << "\n";
    cout << "═══════════════════════════════════════" << endl;
    cout << "       DPI-Engine-Pro Report            " << endl;
    cout << "═══════════════════════════════════════" << endl;
    cout << "Total packets processed: "
         << total_packets << endl;
    cout << "Total flows detected:    "
         << flows.size()  << endl;
    cout << "\n";

    // Count apps
    int app_counts[9] = {0};
    int blocked_count = 0;
    int sni_classified = 0;
    int ml_classified  = 0;

    for (const auto& pair : flows) {
        const Flow& f = pair.second;
        app_counts[(int)f.app_type]++;
        if (f.blocked) blocked_count++;
        if (!f.sni.empty()) sni_classified++;
        else if (f.app_type != AppType::UNKNOWN) ml_classified++;
    }

    cout << "── App Distribution ──" << endl;
    cout << "  YOUTUBE:  " << app_counts[(int)AppType::YOUTUBE]  << endl;
    cout << "  DNS:      " << app_counts[(int)AppType::DNS]      << endl;
    cout << "  WHATSAPP: " << app_counts[(int)AppType::WHATSAPP] << endl;
    cout << "  ZOOM:     " << app_counts[(int)AppType::ZOOM]     << endl;
    cout << "  HTTP:     " << app_counts[(int)AppType::HTTP]     << endl;
    cout << "  HTTPS:    " << app_counts[(int)AppType::HTTPS]    << endl;
    cout << "  UNKNOWN:  " << app_counts[(int)AppType::UNKNOWN]  << endl;
    cout << "\n";

    cout << "── Classification Method ──" << endl;
    cout << "  Via SNI: " << sni_classified
         << " flows (100% accurate)" << endl;
    cout << "  Via ML:  " << ml_classified
         << " flows (ML predicted)" << endl;
    cout << "\n";

    cout << "── Blocked Flows ──" << endl;
    cout << "  Blocked: " << blocked_count << " flows" << endl;
    cout << "═══════════════════════════════════════" << endl;
}

// ─────────────────────────────────────────
// Returns true if this flow should be blocked
// Edit this function to change blocking rules
// ─────────────────────────────────────────
bool shouldBlock(const Flow& flow)
{
    // Example rules — customize as needed:

    // Block YouTube (bandwidth saving)
    // if (flow.app_type == AppType::YOUTUBE) return true;

    // Block gaming (work network policy)
    if (flow.app_type == AppType::GAMING) return true;

    // Block by specific IP
    // uint32_t blocked_ip = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    // if (flow.tuple.dst_ip == blocked_ip) return true;

    return false;
}

void printUsage(const string& program_name)
{
    cout << "Usage: " << program_name
         << " <pcap_file> [options]" << endl;
    cout << "\nOptions:" << endl;
    cout << "  --csv   <file>   Training data CSV "
         << "(default: data/training_flows.csv)" << endl;
    cout << "  --model <file>   Model file "
         << "(default: data/model.txt)" << endl;
    cout << "  --verbose        Print each packet" << endl;
    cout << "\nExample:" << endl;
    cout << "  " << program_name
         << " capture.pcap --verbose" << endl;
}

// Simple argument parser
struct Args {
    string pcap_file  = "";
    string csv_file   = "data/training_flows.csv";
    string model_file = "data/model.txt";
    bool   verbose    = false;
    bool   valid      = false;
};

Args parseArgs(int argc, char* argv[])
{
    Args args;

    if (argc < 2) {
        return args;  // valid = false
    }

    args.pcap_file = argv[1];

    for (int i = 2; i < argc; i++) {
        string arg = argv[i];

        if (arg == "--csv" && i+1 < argc) {
            args.csv_file = argv[++i];
        }
        else if (arg == "--model" && i+1 < argc) {
            args.model_file = argv[++i];
        }
        else if (arg == "--verbose") {
            args.verbose = true;
        }
    }

    args.valid = true;
    return args;
}

int main(int argc, char* argv[])
{
    cout << "DPI-Engine-Pro v1.0" << endl;
    cout << "ML-powered Deep Packet Inspection" << endl;
    cout << "══════════════════════════════════\n" << endl;

    // ── Parse arguments ──
    Args args = parseArgs(argc, argv);
    if (!args.valid) {
        printUsage(argv[0]);
        return 1;
    }

    // ── Step 1: Load or train ML model ──
    cout << "── Step 1: Loading ML Model ──" << endl;
    MLClassifier classifier;
    if (!classifier.loadOrTrain(args.csv_file,
                                args.model_file)) {
        cerr << "ERROR: Failed to load/train model!" << endl;
        return 1;
    }
    cout << endl;

    // ── Step 2: Open PCAP file ──
    cout << "── Step 2: Opening PCAP File ──" << endl;
    PcapReader   reader;
    PacketParser parser;
    SNIExtractor sni_extractor;

    if (!reader.open(args.pcap_file)) {
        cerr << "ERROR: Cannot open " << args.pcap_file << endl;
        return 1;
    }
    cout << endl;

    // ── Step 3: Flow table ──
    unordered_map<FiveTuple, Flow, FiveTupleHash> flow_table;

    // ── Step 4: Main packet processing loop ──
    cout << "── Step 3: Processing Packets ──" << endl;

    RawPacket raw;
    while (reader.readNext(raw)) {

        // Parse raw bytes into structured fields
        ParsedPacket pkt = parser.parse(raw);

        // Skip invalid packets
        if (!pkt.valid) continue;

        // Get FiveTuple for this packet
        FiveTuple tuple = parser.extractTuple(pkt);

        // Find or create flow in table
        Flow& flow = flow_table[tuple];
        if (flow.features.total_packets == 0) {
            // New flow — initialize tuple
            flow.tuple = tuple;
        }

        // Update flow features with this packet
        flow.features.update(
            pkt.packet_len,
            pkt.timestamp_ms,
            pkt.dst_port,
            pkt.protocol,
            pkt.is_tls
        );

        // Try SNI extraction (only works on TLS handshake)
        if (pkt.is_tls && flow.sni.empty() &&
            pkt.payload && pkt.payload_len > 0)
        {
            string sni = sni_extractor.extract(
                pkt.payload,
                pkt.payload_len
            );
            if (!sni.empty()) {
                flow.sni = sni;
            }
        }

        // Classify flow using hybrid strategy
        flow.app_type = classifyFlow(flow, classifier);

        // Apply blocking rules
        flow.blocked = shouldBlock(flow);

        // Verbose output per packet
        if (args.verbose) {
            cout << "Packet #" << reader.packetsRead()
                 << " | ";
            printIP(pkt.src_ip);
            cout << ":" << pkt.src_port << " → ";
            printIP(pkt.dst_ip);
            cout << ":" << pkt.dst_port;
            cout << " | " << appTypeToString(flow.app_type);
            if (!flow.sni.empty())
                cout << " (SNI: " << flow.sni << ")";
            if (flow.blocked)
                cout << " [BLOCKED]";
            cout << endl;
        }
    }

    // Finalize all flow features
    for (auto& pair : flow_table) {
        pair.second.features.finalize();
    }

    // ── Step 5: Print report ──
    printReport(flow_table, reader.packetsRead());

    reader.close();
    return 0;
}

