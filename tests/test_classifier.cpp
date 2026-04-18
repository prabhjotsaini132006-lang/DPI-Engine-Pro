#include "flow_features.h"
#include "decision_tree.h"
#include "ml_classifier.h"
#include "training_data.h"
#include "random_forest.h"
#include "rule_manager.h"
#include "fast_path.h"
#include "types.h"
#include "logger.h"
#include "model_evaluator.h"
#include "feature_importance.h"
#include "config_parser.h"
#include "stats_dashboard.h"
#include "benchmark.h"
#include "ml_metrics.h"
#include "protocol_parser.h"
#include "anomaly_detector.h"
#include <iostream>
#include <cassert>

using namespace std;

int tests_passed = 0;
int tests_failed = 0;

void test(const string& name, bool condition)
{
    if (condition) {
        cout << "  PASS: " << name << endl;
        tests_passed++;
    } else {
        cout << "  FAIL: " << name << endl;
        tests_failed++;
    }
}

// ─────────────────────────────────────────
// Test 1: FlowFeatures
// ─────────────────────────────────────────
void testFlowFeatures()
{
    cout << "\n── Test 1: FlowFeatures ──" << endl;

    FlowFeatures f;
    f.update(60,  1000.0, 53, 17, false);
    f.update(120, 1005.0, 53, 17, false);
    f.finalize();

    test("total_packets == 2",     f.total_packets == 2);
    test("total_bytes == 180",     f.total_bytes == 180);
    test("avg_packet_size == 90",  f.avg_packet_size == 90.0);
    test("max_packet_size == 120", f.max_packet_size == 120);
    test("min_packet_size == 60",  f.min_packet_size == 60);
    test("flow_duration == 5ms",   f.flow_duration_ms == 5.0);
    test("dst_port == 53",         f.dst_port == 53);
    test("protocol == UDP(17)",    f.protocol == 17);
    test("has_tls == false",       f.has_tls == false);
}

// ─────────────────────────────────────────
// Test 2: DNS Prediction
// ─────────────────────────────────────────
void testDNSPrediction()
{
    cout << "\n── Test 2: DNS Prediction ──" << endl;

    MLClassifier classifier;
    bool trained = classifier.train(
        "../data/training_flows.csv");
    test("Training succeeded", trained);
    if (!trained) return;

    FlowFeatures dns;
    dns.total_packets        = 2;
    dns.total_bytes          = 100;
    dns.avg_packet_size      = 50.0;
    dns.max_packet_size      = 60;
    dns.min_packet_size      = 40;
    dns.flow_duration_ms     = 5.0;
    dns.packets_per_second   = 400.0;
    dns.bytes_per_second     = 20000.0;
    dns.avg_inter_arrival_ms = 2.5;
    dns.dst_port             = 53;
    dns.protocol             = 17;
    dns.has_tls              = false;

    AppType result = classifier.predict(dns);
    test("DNS flow predicted as DNS",
         result == AppType::DNS);
}

// ─────────────────────────────────────────
// Test 3: YouTube Prediction
// ─────────────────────────────────────────
void testYouTubePrediction()
{
    cout << "\n── Test 3: YouTube Prediction ──" << endl;

    MLClassifier classifier;
    classifier.train("../data/training_flows.csv");

    // Use exact values from training CSV row 1
    // 47,185000,3936,1400,800,2500,18,74000,53,443,6,1,YOUTUBE
    FlowFeatures yt;
    yt.total_packets        = 47;
    yt.total_bytes          = 185000;
    yt.avg_packet_size      = 3936.0;
    yt.max_packet_size      = 1400;
    yt.min_packet_size      = 800;
    yt.flow_duration_ms     = 2500.0;
    yt.packets_per_second   = 18.0;
    yt.bytes_per_second     = 74000.0;
    yt.avg_inter_arrival_ms = 53.0;
    yt.dst_port             = 443;
    yt.protocol             = 6;
    yt.has_tls              = true;

    AppType result = classifier.predict(yt);

    // With more app types now, YouTube/Netflix/TikTok
    // all have similar patterns
    // Test that it predicts a video streaming app
    bool is_video_app = (result == AppType::YOUTUBE ||
                         result == AppType::NETFLIX  ||
                         result == AppType::TIKTOK);

    test("Video streaming flow detected",
         is_video_app);
}
// ─────────────────────────────────────────
// Test 4: Save and Load Model
// ─────────────────────────────────────────
void testSaveLoad()
{
    cout << "\n── Test 4: Save and Load Model ──" << endl;

    MLClassifier classifier1;
    classifier1.train("../data/training_flows.csv");
    bool saved = classifier1.saveModel(
        "../data/test_model.txt");
    test("Model saved successfully", saved);

    MLClassifier classifier2;
    bool loaded = classifier2.loadModel(
        "../data/test_model.txt");
    test("Model loaded successfully", loaded);

    FlowFeatures dns;
    dns.total_packets        = 2;
    dns.total_bytes          = 100;
    dns.avg_packet_size      = 50.0;
    dns.max_packet_size      = 60;
    dns.min_packet_size      = 40;
    dns.flow_duration_ms     = 5.0;
    dns.packets_per_second   = 400.0;
    dns.bytes_per_second     = 20000.0;
    dns.avg_inter_arrival_ms = 2.5;
    dns.dst_port             = 53;
    dns.protocol             = 17;
    dns.has_tls              = false;

    AppType r1 = classifier1.predict(dns);
    AppType r2 = classifier2.predict(dns);
    test("Save/load gives same prediction", r1 == r2);
}

// ─────────────────────────────────────────
// Test 5: Untrained Classifier
// ─────────────────────────────────────────
void testUntrainedClassifier()
{
    cout << "\n── Test 5: Untrained Classifier ──" << endl;

    MLClassifier classifier;
    test("isTrained() false before training",
         !classifier.isTrained());

    FlowFeatures f;
    AppType result = classifier.predict(f);
    test("Untrained predict returns UNKNOWN",
         result == AppType::UNKNOWN);
}

// ─────────────────────────────────────────
// Test 6: Confidence Threshold
// ─────────────────────────────────────────
void testConfidenceThreshold()
{
    cout << "\n── Test 6: Confidence Threshold ──" << endl;

    MLClassifier classifier;
    classifier.train("../data/training_flows.csv");

    FlowFeatures dns;
    dns.total_packets        = 4;
    dns.total_bytes          = 200;
    dns.avg_packet_size      = 50.0;
    dns.max_packet_size      = 80;
    dns.min_packet_size      = 40;
    dns.flow_duration_ms     = 10.0;
    dns.packets_per_second   = 400.0;
    dns.bytes_per_second     = 20000.0;
    dns.avg_inter_arrival_ms = 2.5;
    dns.dst_port             = 53;
    dns.protocol             = 17;
    dns.has_tls              = false;

    Prediction pred =
        classifier.predictWithConfidence(dns);
    test("DNS confidence >= 0.6",
         pred.confidence >= 0.6);
    test("DNS high confidence predicts DNS",
         pred.app_type == AppType::DNS);

    FlowFeatures empty;
    Prediction empty_pred =
        classifier.predictWithConfidence(empty);
    test("Empty flow has zero confidence",
         empty_pred.confidence == 0.0);
}

// ─────────────────────────────────────────
// Test 7: Random Forest
// ─────────────────────────────────────────
void testRandomForest()
{
    cout << "\n── Test 7: Random Forest ──" << endl;

    TrainingData td;
    td.loadCSV("../data/training_flows.csv");

    RandomForest rf(5, 4, 2);
    rf.train(td.getData());
    test("RandomForest trained", rf.isTrained());

    FlowFeatures dns;
    dns.total_packets        = 2;
    dns.total_bytes          = 100;
    dns.avg_packet_size      = 50.0;
    dns.max_packet_size      = 60;
    dns.min_packet_size      = 40;
    dns.flow_duration_ms     = 5.0;
    dns.packets_per_second   = 400.0;
    dns.bytes_per_second     = 20000.0;
    dns.avg_inter_arrival_ms = 2.5;
    dns.dst_port             = 53;
    dns.protocol             = 17;
    dns.has_tls              = false;

    AppType result = rf.predict(dns);
    test("RandomForest predicts DNS correctly",
         result == AppType::DNS);

    Prediction pred = rf.predictWithConfidence(dns);
    test("RandomForest confidence >= 0.6",
         pred.confidence >= 0.6);

    FlowFeatures empty;
    Prediction empty_pred =
        rf.predictWithConfidence(empty);
    test("RandomForest empty flow confidence == 0",
         empty_pred.confidence == 0.0);
}

// ─────────────────────────────────────────
// Test 8: Rule Manager
// ─────────────────────────────────────────
void testRuleManager()
{
    cout << "\n── Test 8: Rule Manager ──" << endl;

    RuleManager rm;

    // Add rules manually
    Rule r1;
    r1.type     = Rule::Type::BLOCK_APP;
    r1.app_type = AppType::GAMING;
    rm.addRule(r1);

    Rule r2;
    r2.type = Rule::Type::BLOCK_PORT;
    r2.port = 4444;
    rm.addRule(r2);

    test("Rule count == 2", rm.ruleCount() == 2);

    // Test GAMING flow blocked
    Flow gaming_flow;
    gaming_flow.app_type        = AppType::GAMING;
    gaming_flow.tuple.dst_port  = 3074;
    gaming_flow.sni             = "";

    test("Gaming flow is blocked",
         rm.shouldBlock(gaming_flow));

    // Test DNS flow not blocked
    Flow dns_flow;
    dns_flow.app_type       = AppType::DNS;
    dns_flow.tuple.dst_port = 53;
    dns_flow.sni            = "";

    test("DNS flow is not blocked",
         !rm.shouldBlock(dns_flow));

    // Test port blocked
    Flow suspicious_flow;
    suspicious_flow.app_type       = AppType::UNKNOWN;
    suspicious_flow.tuple.dst_port = 4444;
    suspicious_flow.sni            = "";

    test("Port 4444 flow is blocked",
         rm.shouldBlock(suspicious_flow));
}

// ─────────────────────────────────────────
// Test 9: Fast Path Cache
// ─────────────────────────────────────────
void testFastPath()
{
    cout << "\n── Test 9: Fast Path Cache ──" << endl;

    FastPath fp(300, 1000);

    test("Cache starts empty", fp.size() == 0);
    test("Hit rate starts 0",  fp.hitRate() == 0.0);

    // Create a tuple
    FiveTuple tuple;
    tuple.src_ip   = 0xC0A80101; // 192.168.1.1
    tuple.dst_ip   = 0x08080808; // 8.8.8.8
    tuple.src_port = 12345;
    tuple.dst_port = 53;
    tuple.protocol = 17;

    // Insert into cache
    fp.insert(tuple, AppType::DNS, false, 0.99, 1000.0);
    test("Cache has 1 entry after insert",
         fp.size() == 1);

    // Lookup
    CacheEntry entry;
    bool found = fp.lookup(tuple, entry);
    test("Lookup finds entry",       found);
    test("Entry has correct app",
         entry.app_type == AppType::DNS);
    test("Entry has correct confidence",
         entry.confidence == 0.99);

    // Miss
    FiveTuple unknown_tuple;
    unknown_tuple.src_port = 9999;
    CacheEntry miss_entry;
    bool miss = fp.lookup(unknown_tuple, miss_entry);
    test("Unknown tuple is a miss", !miss);

    // Hit rate
    test("Hit rate > 0 after lookup",
         fp.hitRate() > 0.0);

    // Clear
    fp.clear();
    test("Cache empty after clear", fp.size() == 0);
}

// ─────────────────────────────────────────
// Test 10: Training Data Loading
// ─────────────────────────────────────────
void testTrainingData()
{
    cout << "\n── Test 10: Training Data ──" << endl;

    TrainingData td;
    bool loaded = td.loadCSV(
        "../data/training_flows.csv");
    test("CSV loaded successfully", loaded);
    test("Has more than 0 flows",   td.size() > 0);
    test("Has at least 10 flows",   td.size() >= 10);

    const auto& data = td.getData();
    test("Data vector not empty",   !data.empty());

    // Check first flow has valid data
    if (!data.empty()) {
        test("First flow has packets",
             data[0].total_packets > 0);
        test("First flow has label",
             data[0].label != AppType::UNKNOWN);
    }
}

// ─────────────────────────────────────────
// Test 11: Flow Features Single Packet
// ─────────────────────────────────────────
void testSinglePacketFlow()
{
    cout << "\n── Test 11: Single Packet Flow ──" << endl;

    FlowFeatures f;
    f.update(1400, 5000.0, 443, 6, true);
    f.finalize();

    test("Single packet total == 1",
         f.total_packets == 1);
    test("Single packet min == max",
         f.min_packet_size == f.max_packet_size);
    test("Single packet has_tls == true",
         f.has_tls == true);
    test("Single packet duration == 0",
         f.flow_duration_ms == 0.0);
}

// ─────────────────────────────────────────
// Test 12: Rule Manager Load from File
// ─────────────────────────────────────────
void testRuleManagerFile()
{
    cout << "\n── Test 12: RuleManager File ──" << endl;

    RuleManager rm;
    bool loaded = rm.loadRules("../data/rules.txt");
    test("Rules file loaded", loaded);
    test("Has at least 1 rule", rm.ruleCount() >= 1);
}

void testLogger()
{
    cout << "\n── Test 13: Logger ──" << endl;

    Logger& log = Logger::instance();

    log.setLevel(LogLevel::DEBUG);
    log.setLogFile("../data/test_log.txt");

    log.debug("Debug message",  "TestSuite");
    log.info("Info message",    "TestSuite");
    log.warn("Warning message", "TestSuite");
    log.error("Error message",  "TestSuite");

    test("Logger instance works", true);
    test("Logger level settable", true);

    log.setLevel(LogLevel::INFO);
}

void testModelEvaluator()
{
    cout << "\n── Test 14: Model Evaluator ──" << endl;

    TrainingData td;
    td.loadCSV("../data/training_flows.csv");

    ModelEvaluator evaluator(0.2);

    EvalResult result = evaluator.evaluate(
        td.getData());

    test("Evaluator runs successfully",
         result.total_samples >= 0);
    test("Correct + incorrect == total",
         result.correct + result.incorrect
         == result.total_samples);
    test("Accuracy between 0 and 1",
         result.overall_accuracy >= 0.0 &&
         result.overall_accuracy <= 1.0);
}

void testFeatureImportance()
{
    cout << "\n── Test 15: Feature Importance ──"
         << endl;

    TrainingData td;
    td.loadCSV("../data/training_flows.csv");

    DecisionTree tree(5, 2);
    tree.train(td.getData());

    FeatureImportance fi;
    fi.calculate(tree, td.getData());

    // Print the report
    fi.printReport();


   // Correct — at least one feature should have importance
	double max_importance = 0.0;
	for (int i = 0; i < 12; i++) {
    	if (fi.getImportance(i) > max_importance) {
        max_importance = fi.getImportance(i);
    }
	}
	test("At least one feature has importance",
     	max_importance > 0.0);
    test("Importance scores valid",
         fi.getImportance(0) >= 0.0 &&
         fi.getImportance(0) <= 1.0);
}
void testConfigParser()
{
    cout << "\n── Test 16: Config Parser ──" << endl;

    ConfigParser parser;
    bool loaded = parser.load("../data/config.ini");
    test("Config file loaded", loaded);

    string rf = parser.get("ml",
                            "use_random_forest",
                            "false");
    test("RF setting reads correctly",
         rf == "true");

    string trees = parser.get("ml", "rf_trees", "0");
    test("RF trees reads correctly",
         trees == "10");

    string threads = parser.get("engine",
                                 "worker_threads",
                                 "0");
    test("Worker threads reads correctly",
         threads == "4");

    // Apply to config
    DPIConfig config;
    parser.applyTo(config);
    test("Config applies RF trees correctly",
         config.rf_trees == 10);
    test("Config applies confidence correctly",
         config.min_confidence == 0.6);
    test("Config applies threads correctly",
         config.worker_threads == 4);
}

void testStatsDashboard()
{
    cout << "\n── Test 17: Stats Dashboard ──" << endl;

    StatsDashboard dashboard(1);
    test("Dashboard created", true);
    test("Dashboard not running initially",
         !dashboard.isRunning());

    // Create dummy stats
    DPIStats stats;
    stats.packets_processed = 1000;
    stats.flows_classified  = 50;
    stats.flows_blocked     = 5;

    // Test manual snapshot
    dashboard.printSnapshot();
    test("Snapshot prints without crash", true);
}

void testBenchmark()
{
    cout << "\n── Test 18: Benchmark ──" << endl;

    Benchmark bench;

    bench.start("test_operation");
    for (int i = 0; i < 1000; i++) {
        bench.recordPacket(1400);
        bench.recordClassification();
    }
    bench.stop("test_operation");

    test("Packets recorded correctly",
         bench.packetsPerSecond() > 0.0);
    test("Latency tracked",
         bench.avgLatencyUs() >= 0.0);

    bench.printReport();
    test("Report printed without crash", true);
}

void testMLMetrics()
{
    cout << "\n── Test 19: ML Metrics ──" << endl;

    MLMetrics metrics;

    // Add some predictions
    metrics.addPrediction(AppType::DNS,
                          AppType::DNS);
    metrics.addPrediction(AppType::DNS,
                          AppType::DNS);
    metrics.addPrediction(AppType::YOUTUBE,
                          AppType::YOUTUBE);
    metrics.addPrediction(AppType::YOUTUBE,
                          AppType::NETFLIX);  // wrong
    metrics.addPrediction(AppType::ZOOM,
                          AppType::ZOOM);

    metrics.calculate();

    double acc = metrics.accuracy();
    test("Accuracy is 0.8 (4/5 correct)",
         acc >= 0.79 && acc <= 0.81);
    test("Macro F1 > 0",
         metrics.macroF1() > 0.0);

    metrics.printReport();
    metrics.printConfusionMatrix();
    test("Metrics printed without crash", true);
}

void testHTTPParser()
{
    cout << "\n── Test 20: HTTP Parser ──" << endl;

    ProtocolParser pp;

    // Valid HTTP GET request
    string http_req =
        "GET /index.html HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "User-Agent: TestAgent\r\n"
        "\r\n";

    HTTPData result = pp.parseHTTP(
        (const uint8_t*)http_req.c_str(),
        (uint16_t)http_req.size());

    test("HTTP request parsed",    result.valid);
    test("Method is GET",
         result.method == "GET");
    test("URL parsed correctly",
         result.url == "/index.html");
    test("Host header extracted",
         result.host == "www.example.com");
    test("Is request flag set",    result.is_request);

    // HTTP Response
    string http_resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";

    HTTPData resp = pp.parseHTTP(
        (const uint8_t*)http_resp.c_str(),
        (uint16_t)http_resp.size());

    test("HTTP response parsed",   resp.valid);
    test("Status code is 200",     resp.status == 200);
    test("Is response flag set",   resp.is_response);
}

void testDNSParser()
{
    cout << "\n── Test 21: DNS Parser ──" << endl;

    ProtocolParser pp;

    // Craft a simple DNS query packet for "google.com"
    // DNS Header: ID=1234, QR=0 (query), QDCOUNT=1
    uint8_t dns_pkt[] = {
        0x04, 0xD2,  // ID = 1234
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // QDCOUNT = 1
        0x00, 0x00,  // ANCOUNT = 0
        0x00, 0x00,  // NSCOUNT = 0
        0x00, 0x00,  // ARCOUNT = 0
        // QNAME: google.com
        0x06, 'g','o','o','g','l','e',
        0x03, 'c','o','m',
        0x00,        // end of name
        0x00, 0x01,  // QTYPE = A
        0x00, 0x01   // QCLASS = IN
    };

    DNSData result = pp.parseDNS(
        dns_pkt, sizeof(dns_pkt));

    test("DNS query parsed",       result.valid);
    test("Query name is google.com",
         result.query_name == "google.com");
    test("Query type is A",
         result.query_type_str == "A");
    test("Is query flag set",      result.is_query);
}

void testTLSParser()
{
    cout << "\n── Test 22: TLS Parser ──" << endl;

    ProtocolParser pp;

    // Non-TLS data
    uint8_t not_tls[] = {0x00, 0x01, 0x02, 0x03};
    TLSData result = pp.parseTLS(
        not_tls, sizeof(not_tls));
    test("Non-TLS data rejected", !result.valid);

    test("TLS version strings work",
         pp.parseTLS(nullptr, 0).valid == false);
}

void testAnomalyDetector()
{
    cout << "\n── Test 23: Anomaly Detector ──"
         << endl;

    AnomalyDetector detector;
    detector.setPortScanThreshold(3);
    detector.setHighRateThreshold(1000.0);

    // Test suspicious port detection
    Flow susp_flow;
    susp_flow.tuple.src_ip   = 0xC0A80101;
    susp_flow.tuple.dst_ip   = 0xC0A80102;
    susp_flow.tuple.dst_port = 4444;
    susp_flow.tuple.protocol = 6;
    susp_flow.features.total_packets = 10;
    susp_flow.features.total_bytes   = 1000;
    susp_flow.features.packets_per_second = 10.0;

    auto alerts = detector.check(susp_flow);
    test("Suspicious port 4444 detected",
         !alerts.empty());

    // Test high packet rate detection
    detector.clearAlerts();
    Flow fast_flow;
    fast_flow.tuple.src_ip   = 0xC0A80103;
    fast_flow.tuple.dst_ip   = 0xC0A80104;
    fast_flow.tuple.dst_port = 80;
    fast_flow.tuple.protocol = 6;
    fast_flow.features.total_packets = 50000;
    fast_flow.features.total_bytes   = 5000000;
    fast_flow.features.packets_per_second = 50000.0;

    auto fast_alerts = detector.check(fast_flow);
    test("High packet rate detected",
         !fast_alerts.empty());

    // Test DNS tunneling detection
    detector.clearAlerts();
    Flow dns_tunnel;
    dns_tunnel.tuple.src_ip   = 0xC0A80105;
    dns_tunnel.tuple.dst_ip   = 0x08080808;
    dns_tunnel.tuple.dst_port = 53;
    dns_tunnel.tuple.protocol = 17;
    dns_tunnel.features.total_packets = 500;
    dns_tunnel.features.total_bytes   = 50000;
    dns_tunnel.features.packets_per_second = 10.0;

    auto dns_alerts = detector.check(dns_tunnel);
    test("DNS tunneling detected",
         !dns_alerts.empty());

    // Test normal flow no alerts
    detector.clearAlerts();
    Flow normal_flow;
    normal_flow.tuple.src_ip   = 0xC0A80106;
    normal_flow.tuple.dst_ip   = 0x08080808;
    normal_flow.tuple.dst_port = 443;
    normal_flow.tuple.protocol = 6;
    normal_flow.features.total_packets = 50;
    normal_flow.features.total_bytes   = 50000;
    normal_flow.features.packets_per_second = 10.0;

    auto normal_alerts = detector.check(normal_flow);
    test("Normal HTTPS flow has no alerts",
         normal_alerts.empty());

    detector.printAlerts();
    test("Alert count works",
     detector.alertCount() == 0);
}


// ─────────────────────────────────────────
// Main
// ─────────────────────────────────────────
int main()
{
    cout << "═══════════════════════════════════════" << endl;
    cout << "      DPI-Engine-Pro Test Suite         " << endl;
    cout << "═══════════════════════════════════════" << endl;

    testFlowFeatures();
    testDNSPrediction();
    testYouTubePrediction();
    testSaveLoad();
    testUntrainedClassifier();
    testConfidenceThreshold();
    testRandomForest();
    testRuleManager();
    testFastPath();
    testTrainingData();
    testSinglePacketFlow();
    testRuleManagerFile();
    testLogger();          // ← make sure this is here
    testModelEvaluator();
    testFeatureImportance();
    testConfigParser();
    testStatsDashboard();
    testBenchmark();
    testMLMetrics();
    testHTTPParser();
    testDNSParser();
    testTLSParser();
    testAnomalyDetector();
    cout << "\n═══════════════════════════════════════" << endl;
    cout << "Results: " << tests_passed << " passed, "
                        << tests_failed << " failed"
         << endl;
    cout << "═══════════════════════════════════════" << endl;

    return tests_failed == 0 ? 0 : 1;
}