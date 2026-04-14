#include "feature_importance.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cstdlib>

using namespace std;

const char* FeatureImportance::FEATURE_NAMES[12] = {
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "max_packet_size",
    "min_packet_size",
    "flow_duration_ms",
    "packets_per_second",
    "bytes_per_second",
    "avg_inter_arrival",
    "dst_port",
    "protocol",
    "has_tls"
};

double FeatureImportance::calcAccuracy(
    const DecisionTree& tree,
    const vector<FlowFeatures>& data) const
{
    if (data.empty()) return 0.0;

    int correct = 0;
    for (const auto& f : data) {
        if (tree.predict(f) == f.label) {
            correct++;
        }
    }
    return (double)correct / (double)data.size();
}

vector<FlowFeatures> FeatureImportance::shuffleFeature(
    const vector<FlowFeatures>& data,
    int feature_index) const
{
    vector<FlowFeatures> shuffled = data;

    // Collect all values for this feature
    vector<double> values;
    for (const auto& f : shuffled) {
        switch (feature_index) {
            case 0:  values.push_back(f.total_packets);   break;
            case 1:  values.push_back(f.total_bytes);     break;
            case 2:  values.push_back(f.avg_packet_size); break;
            case 5:  values.push_back(f.flow_duration_ms);break;
            case 7:  values.push_back(f.bytes_per_second);break;
            case 9:  values.push_back(f.dst_port);        break;
            case 10: values.push_back(f.protocol);        break;
            default: values.push_back(0.0);               break;
        }
    }

    // Shuffle values
    for (int i = (int)values.size()-1; i > 0; i--) {
        int j = rand() % (i + 1);
        swap(values[i], values[j]);
    }

    // Put shuffled values back
    for (size_t i = 0; i < shuffled.size(); i++) {
        switch (feature_index) {
            case 0:  shuffled[i].total_packets
                         = (uint64_t)values[i]; break;
            case 1:  shuffled[i].total_bytes
                         = (uint64_t)values[i]; break;
            case 2:  shuffled[i].avg_packet_size
                         = values[i];           break;
            case 5:  shuffled[i].flow_duration_ms
                         = values[i];           break;
            case 7:  shuffled[i].bytes_per_second
                         = values[i];           break;
            case 9:  shuffled[i].dst_port
                         = (uint16_t)values[i]; break;
            case 10: shuffled[i].protocol
                         = (uint8_t)values[i];  break;
            default: break;
        }
    }

    return shuffled;
}

void FeatureImportance::calculate(
    const DecisionTree& tree,
    const vector<FlowFeatures>& data)
{
    tree_ptr = &tree;

    if (data.empty()) return;

    // Baseline accuracy
    double baseline = calcAccuracy(tree, data);

    // For each feature measure accuracy drop
    // when that feature is shuffled (randomized)
    for (int i = 0; i < 12; i++) {
        vector<FlowFeatures> shuffled =
            shuffleFeature(data, i);

        double shuffled_acc =
            calcAccuracy(tree, shuffled);

        // Importance = how much accuracy drops
        double drop = baseline - shuffled_acc;
        scores[i]   = max(0.0, drop);
    }

    // Normalize scores to sum to 1.0
    double total = 0.0;
    for (int i = 0; i < 12; i++) total += scores[i];

    if (total > 0.0) {
        for (int i = 0; i < 12; i++) {
            scores[i] /= total;
        }
    }
}

double FeatureImportance::getImportance(
    int feature_index) const
{
    if (feature_index < 0 || feature_index >= 12) {
        return 0.0;
    }
    return scores[feature_index];
}

void FeatureImportance::printReport() const
{
    cout << "\n=== Feature Importance Report ===" << endl;
    cout << fixed << setprecision(1);

    // Sort by importance
    vector<pair<double, int>> ranked;
    for (int i = 0; i < 12; i++) {
        ranked.push_back({scores[i], i});
    }
    sort(ranked.rbegin(), ranked.rend());

    cout << setw(22) << "Feature"
         << setw(12) << "Importance"
         << "  Bar" << endl;
    cout << string(50, '-') << endl;

    for (const auto& pair : ranked) {
        double importance = pair.first * 100.0;
        int    feature    = pair.second;

        // Bar chart
        int bar_len = (int)(importance / 2.0);
        string bar(bar_len, '#');

        cout << setw(22) << FEATURE_NAMES[feature]
             << setw(10) << importance << "%"
             << "  " << bar << endl;
    }
    cout << string(50, '-') << endl;
}