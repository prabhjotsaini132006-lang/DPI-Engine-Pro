#include "decision_tree.h"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <map>
#include <limits>

using namespace std;

const char* DecisionTree::FEATURE_NAMES[12] = {
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "max_packet_size",
    "min_packet_size",
    "flow_duration_ms",
    "packets_per_second",
    "bytes_per_second",
    "avg_inter_arrival_ms",
    "dst_port",
    "protocol",
    "has_tls"
};

DecisionTree::DecisionTree(int max_depth, int min_samples)
    : max_depth(max_depth), min_samples(min_samples), root(nullptr)
{}

DecisionTree::~DecisionTree()
{
    deleteTree(root);
}

void DecisionTree::deleteTree(Node* node)
{
    if (node == nullptr) return;
    deleteTree(node->left);
    deleteTree(node->right);
    delete node;
}

double DecisionTree::getFeature(const FlowFeatures& f,
                                 int index) const
{
    switch(index) {
        case 0:  return (double)f.total_packets;
        case 1:  return (double)f.total_bytes;
        case 2:  return f.avg_packet_size;
        case 3:  return (double)f.max_packet_size;
        case 4:  return (double)f.min_packet_size;
        case 5:  return f.flow_duration_ms;
        case 6:  return f.packets_per_second;
        case 7:  return f.bytes_per_second;
        case 8:  return f.avg_inter_arrival_ms;
        case 9:  return (double)f.dst_port;
        case 10: return (double)f.protocol;
        case 11: return f.has_tls ? 1.0 : 0.0;
        default: return 0.0;
    }
}

bool DecisionTree::allSameClass(
    const vector<FlowFeatures>& data) const
{
    if (data.empty()) return true;
    AppType first = data[0].label;
    for (const auto& f : data) {
        if (f.label != first) return false;
    }
    return true;
}

AppType DecisionTree::majorityClass(
    const vector<FlowFeatures>& data) const
{
    map<AppType, int> counts;
    for (const auto& f : data) {
        counts[f.label]++;
    }

    AppType best_label = AppType::UNKNOWN;
    int     best_count = 0;

    for (const auto& pair : counts) {
        if (pair.second > best_count) {
            best_count = pair.second;
            best_label = pair.first;
        }
    }
    return best_label;
}

double DecisionTree::giniImpurity(
    const vector<FlowFeatures>& data) const
{
    if (data.empty()) return 0.0;

    map<AppType, int> counts;
    for (const auto& f : data) {
        counts[f.label]++;
    }

    double gini  = 1.0;
    double total = (double)data.size();

    for (const auto& pair : counts) {
        double fraction = pair.second / total;
        gini -= fraction * fraction;
    }
    return gini;
}

double DecisionTree::bestSplit(
    const vector<FlowFeatures>& data,
    int&    best_feature,
    double& best_threshold) const
{
    double best_gini = numeric_limits<double>::max();
    best_feature     = -1;
    best_threshold   = 0.0;
    double total     = (double)data.size();

    for (int feature = 0; feature < 12; feature++) {

        vector<double> values;
        for (const auto& f : data) {
            values.push_back(getFeature(f, feature));
        }
        sort(values.begin(), values.end());
        values.erase(
            unique(values.begin(), values.end()),
            values.end()
        );

        for (double threshold : values) {

            vector<FlowFeatures> left, right;
            for (const auto& f : data) {
                if (getFeature(f, feature) <= threshold)
                    left.push_back(f);
                else
                    right.push_back(f);
            }

            if (left.empty() || right.empty()) continue;

            double weighted_gini =
                (left.size()  / total) * giniImpurity(left) +
                (right.size() / total) * giniImpurity(right);

            if (weighted_gini < best_gini) {
                best_gini      = weighted_gini;
                best_feature   = feature;
                best_threshold = threshold;
            }
        }
    }
    return best_gini;
}

Node* DecisionTree::buildTree(
    vector<FlowFeatures> data, int depth)
{
    if (allSameClass(data)) {
        Node* leaf = new Node();
        leaf->leaf_label = data[0].label;
        return leaf;
    }

    if (depth >= max_depth) {
        Node* leaf = new Node();
        leaf->leaf_label = majorityClass(data);
        return leaf;
    }

    if ((int)data.size() < min_samples) {
        Node* leaf = new Node();
        leaf->leaf_label = majorityClass(data);
        return leaf;
    }

    int    best_feature;
    double best_threshold;
    bestSplit(data, best_feature, best_threshold);

    if (best_feature == -1) {
        Node* leaf = new Node();
        leaf->leaf_label = majorityClass(data);
        return leaf;
    }

    vector<FlowFeatures> left_data, right_data;
    for (const auto& f : data) {
        if (getFeature(f, best_feature) <= best_threshold)
            left_data.push_back(f);
        else
            right_data.push_back(f);
    }

    Node* node          = new Node();
    node->feature_index = best_feature;
    node->threshold     = best_threshold;
    node->left          = buildTree(left_data,  depth + 1);
    node->right         = buildTree(right_data, depth + 1);

    return node;
}

void DecisionTree::train(const vector<FlowFeatures>& data)
{
    deleteTree(root);
    root = buildTree(data, 0);
    cout << "Decision Tree trained successfully!" << endl;
}

AppType DecisionTree::predictNode(const Node* node,
                                   const FlowFeatures& flow) const
{
    if (node->isLeaf()) {
        return node->leaf_label;
    }

    double value = getFeature(flow, node->feature_index);

    if (value <= node->threshold)
        return predictNode(node->left,  flow);
    else
        return predictNode(node->right, flow);
}

AppType DecisionTree::predict(const FlowFeatures& flow) const
{
    if (root == nullptr) {
        cerr << "ERROR: Tree not trained yet!" << endl;
        return AppType::UNKNOWN;
    }
    return predictNode(root, flow);
}

void DecisionTree::printNode(const Node* node, int depth) const
{
    if (node == nullptr) return;

    string indent(depth * 4, ' ');

    if (node->isLeaf()) {
        cout << indent << "LEAF -> AppType("
             << (int)node->leaf_label << ")" << endl;
    } else {
        cout << indent << "SPLIT on ["
             << FEATURE_NAMES[node->feature_index]
             << "] <= " << node->threshold << endl;
        cout << indent << "LEFT:" << endl;
        printNode(node->left,  depth + 1);
        cout << indent << "RIGHT:" << endl;
        printNode(node->right, depth + 1);
    }
}

void DecisionTree::print() const
{
    cout << "=== Decision Tree ===" << endl;
    printNode(root, 0);
}

void DecisionTree::saveNode(const Node* node,
                             ofstream& file) const
{
    if (node == nullptr) {
        file << "NULL\n";
        return;
    }

    if (node->isLeaf()) {
        file << "LEAF " << (int)node->leaf_label << "\n";
    } else {
        file << "NODE " << node->feature_index
             << " "     << node->threshold << "\n";
        saveNode(node->left,  file);
        saveNode(node->right, file);
    }
}

void DecisionTree::save(const string& filename) const
{
    ofstream file(filename);
    if (!file.is_open()) {
        cerr << "ERROR: Cannot save model to "
             << filename << endl;
        return;
    }
    saveNode(root, file);
    cout << "Model saved to " << filename << endl;
}

Node* DecisionTree::loadNode(ifstream& file)
{
    string type;
    file >> type;

    if (type == "NULL") return nullptr;

    Node* node = new Node();

    if (type == "LEAF") {
        int label;
        file >> label;
        node->leaf_label = (AppType)label;
    } else {
        file >> node->feature_index >> node->threshold;
        node->left  = loadNode(file);
        node->right = loadNode(file);
    }
    return node;
}

void DecisionTree::load(const string& filename)
{
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "ERROR: Cannot load model from "
             << filename << endl;
        return;
    }
    deleteTree(root);
    root = loadNode(file);
    cout << "Model loaded from " << filename << endl;
}