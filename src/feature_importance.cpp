#include "feature_importance.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstdlib>

using namespace std;

const char* FeatureImportance::FEATURE_NAMES[12] = {
    "total_packets",    "total_bytes",      "avg_packet_size",
    "max_packet_size",  "min_packet_size",  "flow_duration_ms",
    "packets_per_sec",  "bytes_per_second", "avg_inter_arrival",
    "dst_port",         "protocol",         "has_tls"
};

double FeatureImportance::calcAccuracy(
    const DecisionTree& tree,
    const vector<FlowFeatures>& data) const
{
    if (data.empty()) return 0.0;
    int correct = 0;
    for (const auto& f : data)
        if (tree.predict(f) == f.label) correct++;
    return (double)correct / (double)data.size();
}

vector<FlowFeatures> FeatureImportance::shuffleFeature(
    const vector<FlowFeatures>& data, int fi) const
{
    vector<FlowFeatures> shuffled = data;
    vector<double> values;

    for (const auto& f : shuffled) {
        switch (fi) {
            case 0:  values.push_back((double)f.total_packets);      break;
            case 1:  values.push_back((double)f.total_bytes);        break;
            case 2:  values.push_back(f.avg_packet_size);            break;
            case 3:  values.push_back((double)f.max_packet_size);    break;
            case 4:  values.push_back((double)f.min_packet_size);    break;
            case 5:  values.push_back(f.flow_duration_ms);           break;
            case 6:  values.push_back(f.packets_per_second);         break;
            case 7:  values.push_back(f.bytes_per_second);           break;
            case 8:  values.push_back(f.avg_inter_arrival_ms);       break;
            case 9:  values.push_back((double)f.dst_port);           break;
            case 10: values.push_back((double)f.protocol);           break;
            case 11: values.push_back(f.has_tls ? 1.0 : 0.0);       break;
            default: values.push_back(0.0);                          break;
        }
    }

    for (int i = (int)values.size()-1; i > 0; i--) {
        int j = rand() % (i+1);
        swap(values[i], values[j]);
    }

    for (size_t i = 0; i < shuffled.size(); i++) {
        switch (fi) {
            case 0:  shuffled[i].total_packets        = (uint64_t)values[i]; break;
            case 1:  shuffled[i].total_bytes           = (uint64_t)values[i]; break;
            case 2:  shuffled[i].avg_packet_size       = values[i];           break;
            case 3:  shuffled[i].max_packet_size       = (uint64_t)values[i]; break;
            case 4:  shuffled[i].min_packet_size       = (uint64_t)values[i]; break;
            case 5:  shuffled[i].flow_duration_ms      = values[i];           break;
            case 6:  shuffled[i].packets_per_second    = values[i];           break;
            case 7:  shuffled[i].bytes_per_second      = values[i];           break;
            case 8:  shuffled[i].avg_inter_arrival_ms  = values[i];           break;
            case 9:  shuffled[i].dst_port              = (uint16_t)values[i]; break;
            case 10: shuffled[i].protocol              = (uint8_t)values[i];  break;
            case 11: shuffled[i].has_tls               = (values[i] > 0.5);   break;
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
    double baseline = calcAccuracy(tree, data);
    for (int i = 0; i < 12; i++) {
        auto shuffled    = shuffleFeature(data, i);
        double shuf_acc  = calcAccuracy(tree, shuffled);
        scores[i]        = max(0.0, baseline - shuf_acc);
    }
    double total = 0.0;
    for (int i = 0; i < 12; i++) total += scores[i];
    if (total > 0.0)
        for (int i = 0; i < 12; i++) scores[i] /= total;
}

double FeatureImportance::getImportance(int fi) const
{
    if (fi < 0 || fi >= 12) return 0.0;
    return scores[fi];
}

void FeatureImportance::printReport() const
{
    cout << "\n=== Feature Importance Report ===\n";
    cout << fixed << setprecision(1);
    vector<pair<double,int>> ranked;
    for (int i = 0; i < 12; i++) ranked.push_back({scores[i], i});
    sort(ranked.rbegin(), ranked.rend());
    cout << setw(22) << "Feature" << setw(12) << "Importance" << "  Bar\n";
    cout << string(55, '-') << "\n";
    for (const auto& p : ranked) {
        double imp = p.first * 100.0;
        string bar(max(0, (int)(imp/2.0)), '#');
        cout << setw(22) << FEATURE_NAMES[p.second]
             << setw(10) << imp << "%  " << bar << "\n";
    }
    cout << string(55, '-') << "\n";
}