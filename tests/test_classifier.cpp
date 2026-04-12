#include "flow_features.h"
#include "decision_tree.h"
#include "ml_classifier.h"
#include "training_data.h"
#include "random_forest.h"
#include <iostream>
#include <cassert>

using namespace std;

// ─────────────────────────────────────────
// Simple test framework
// ─────────────────────────────────────────
int tests_passed = 0;
int tests_failed = 0;

void test(const string& name, bool condition)
{
    if (condition) {
        cout << "  ✓ PASS: " << name << endl;
        tests_passed++;
    } else {
        cout << "  ✗ FAIL: " << name << endl;
        tests_failed++;
    }
}

// ─────────────────────────────────────────
// Test 1: FlowFeatures update and finalize
// ─────────────────────────────────────────
void testFlowFeatures()
{
    cout << "\n── Test 1: FlowFeatures ──" << endl;

    FlowFeatures f;

    // Simulate 2 DNS packets
    f.update(60,  1000.0, 53, 17, false);
    f.update(120, 1005.0, 53, 17, false);
    f.finalize();

    test("total_packets == 2",    f.total_packets == 2);
    test("total_bytes == 180",    f.total_bytes == 180);
    test("avg_packet_size == 90", f.avg_packet_size == 90.0);
    test("max_packet_size == 120",f.max_packet_size == 120);
    test("min_packet_size == 60", f.min_packet_size == 60);
    test("flow_duration == 5ms",  f.flow_duration_ms == 5.0);
    test("dst_port == 53",        f.dst_port == 53);
    test("protocol == UDP(17)",   f.protocol == 17);
    test("has_tls == false",      f.has_tls == false);
}

// ─────────────────────────────────────────
// Test 2: DNS flow prediction
// ─────────────────────────────────────────
void testDNSPrediction()
{
    cout << "\n── Test 2: DNS Prediction ──" << endl;

    // Train classifier
    MLClassifier classifier;
    bool trained = classifier.train("../data/training_flows.csv");
    test("Training succeeded", trained);

    if (!trained) return;

    // Perfect DNS flow
    FlowFeatures dns;
    dns.total_packets      = 2;
    dns.total_bytes        = 100;
    dns.avg_packet_size    = 50.0;
    dns.max_packet_size    = 60;
    dns.min_packet_size    = 40;
    dns.flow_duration_ms   = 5.0;
    dns.packets_per_second = 400.0;
    dns.bytes_per_second   = 20000.0;
    dns.avg_inter_arrival_ms = 2.5;
    dns.dst_port           = 53;
    dns.protocol           = 17;
    dns.has_tls            = false;

    AppType result = classifier.predict(dns);
    test("DNS flow predicted as DNS",
         result == AppType::DNS);
}

// ─────────────────────────────────────────
// Test 3: YouTube flow prediction
// ─────────────────────────────────────────
void testYouTubePrediction()
{
    cout << "\n── Test 3: YouTube Prediction ──" << endl;

    MLClassifier classifier;
    classifier.train("../data/training_flows.csv");

    // Perfect YouTube flow
    FlowFeatures yt;
    yt.total_packets       = 47;
    yt.total_bytes         = 185000;
    yt.avg_packet_size     = 3936.0;
    yt.max_packet_size     = 1400;
    yt.min_packet_size     = 800;
    yt.flow_duration_ms    = 2500.0;
    yt.packets_per_second  = 18.0;
    yt.bytes_per_second    = 74000.0;
    yt.avg_inter_arrival_ms = 53.0;
    yt.dst_port            = 443;
    yt.protocol            = 6;
    yt.has_tls             = true;

    AppType result = classifier.predict(yt);
    test("YouTube flow predicted as YOUTUBE",
         result == AppType::YOUTUBE);
}

// ─────────────────────────────────────────
// Test 4: Save and load model
// ─────────────────────────────────────────
void testSaveLoad()
{
    cout << "\n── Test 4: Save and Load Model ──" << endl;

    // Train and save
    MLClassifier classifier1;
    classifier1.train("../data/training_flows.csv");
    bool saved = classifier1.saveModel("../data/test_model.txt");
    test("Model saved successfully", saved);

    // Load into new classifier
    MLClassifier classifier2;
    bool loaded = classifier2.loadModel("../data/test_model.txt");
    test("Model loaded successfully", loaded);

    // Both should give same prediction
    FlowFeatures dns;
    dns.total_packets      = 2;
    dns.total_bytes        = 100;
    dns.avg_packet_size    = 50.0;
    dns.max_packet_size    = 60;
    dns.min_packet_size    = 40;
    dns.flow_duration_ms   = 5.0;
    dns.packets_per_second = 400.0;
    dns.bytes_per_second   = 20000.0;
    dns.avg_inter_arrival_ms = 2.5;
    dns.dst_port           = 53;
    dns.protocol           = 17;
    dns.has_tls            = false;

    AppType result1 = classifier1.predict(dns);
    AppType result2 = classifier2.predict(dns);

    test("Save/load gives same prediction",
         result1 == result2);
}

// ─────────────────────────────────────────
// Test 5: Untrained classifier
// ─────────────────────────────────────────
void testUntrainedClassifier()
{
    cout << "\n── Test 5: Untrained Classifier ──" << endl;

    MLClassifier classifier;

    test("isTrained() is false before training",
         !classifier.isTrained());

    FlowFeatures f;
    AppType result = classifier.predict(f);

    test("Untrained predict returns UNKNOWN",
         result == AppType::UNKNOWN);
}


void testConfidenceThreshold()
{
    cout << "\n── Test 6: Confidence Threshold ──" << endl;

    MLClassifier classifier;
    classifier.train("../data/training_flows.csv");

    // Perfect DNS flow → should have high confidence
    FlowFeatures dns;
    dns.total_packets       = 4;
    dns.total_bytes         = 200;
    dns.avg_packet_size     = 50.0;
    dns.max_packet_size     = 80;
    dns.min_packet_size     = 40;
    dns.flow_duration_ms    = 10.0;
    dns.packets_per_second  = 400.0;
    dns.bytes_per_second    = 20000.0;
    dns.avg_inter_arrival_ms = 2.5;
    dns.dst_port            = 53;
    dns.protocol            = 17;
    dns.has_tls             = false;

    Prediction pred = classifier.predictWithConfidence(dns);

    test("DNS confidence >= 0.6",
         pred.confidence >= 0.6);
    test("DNS high confidence predicts DNS",
         pred.app_type == AppType::DNS);

    // Empty flow → should have zero confidence
    FlowFeatures empty;
    Prediction empty_pred =
        classifier.predictWithConfidence(empty);

    test("Empty flow has zero confidence",
         empty_pred.confidence == 0.0);
}

void testRandomForest()
{
    cout << "\n── Test 7: Random Forest ──" << endl;

    TrainingData td;
    td.loadCSV("../data/training_flows.csv");

    RandomForest rf(5, 4, 2);
    rf.train(td.getData());

    test("RandomForest trained", rf.isTrained());

    // DNS flow
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

    // Empty flow
    FlowFeatures empty;
    Prediction empty_pred = rf.predictWithConfidence(empty);
    test("RandomForest empty flow confidence == 0",
         empty_pred.confidence == 0.0);
}

// ─────────────────────────────────────────
// Main — run all tests
// ─────────────────────────────────────────

int main()
{
    cout << "═══════════════════════════════════" << endl;
    cout << "   DPI-Engine-Pro Test Suite        " << endl;
    cout << "═══════════════════════════════════" << endl;

    testFlowFeatures();
    testDNSPrediction();
    testYouTubePrediction();
    testSaveLoad();
    testUntrainedClassifier();
    testConfidenceThreshold();
    testRandomForest();          // ← add this

    cout << "\n═══════════════════════════════════" << endl;
    cout << "Results: " << tests_passed << " passed, "
                        << tests_failed << " failed" << endl;
    cout << "═══════════════════════════════════" << endl;

    return tests_failed == 0 ? 0 : 1;
}