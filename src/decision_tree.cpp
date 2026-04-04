#include "decision_tree.h"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <map>
#include <cmath>
#include <limits>

using namespace std;

// Names matching feature indices 0-11
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

// Get numeric value of a feature by index
double DecisionTree::getFeature(const FlowFeatures& f, int index) const
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

// Check if all flows have the same label
bool DecisionTree::allSameClass(const vector<FlowFeatures>& data) const
{
    if (data.empty()) return true;
    AppType first = data[0].label;
    for (const auto& f : data) {
        if (f.label != first) return false;
    }
    return true;
}

// Find the most common label in a set of flows
AppType DecisionTree::majorityClass(const vector<FlowFeatures>& data) const
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

// Calculate Gini impurity of a set of flows
double DecisionTree::giniImpurity(const vector<FlowFeatures>& data) const
{
    if (data.empty()) return 0.0;

    // Count each class
    map<AppType, int> counts;
    for (const auto& f : data) {
        counts[f.label]++;
    }

    double gini = 1.0;
    double total = (double)data.size();

    for (const auto& pair : counts) {
        double fraction = pair.second / total;
        gini -= fraction * fraction;
    }

    return gini;
}

double DecisionTree::bestSplit(const vector<FlowFeatures>& data,
                                int&    best_feature,
                                double& best_threshold) const
{
    double best_gini = numeric_limits<double>::max();
    best_feature  = -1;
    best_threshold = 0.0;
    double total = (double)data.size();

    // Try every feature
    for (int feature = 0; feature < 12; feature++) {

        // Collect all unique values for this feature
        vector<double> values;
        for (const auto& f : data) {
            values.push_back(getFeature(f, feature));
        }
        sort(values.begin(), values.end());
        values.erase(unique(values.begin(), values.end()),
                     values.end());

        // Try each value as a threshold
        for (double threshold : values) {

            // Split data into left and right
            vector<FlowFeatures> left, right;
            for (const auto& f : data) {
                if (getFeature(f, feature) <= threshold)
                    left.push_back(f);
                else
                    right.push_back(f);
            }

            // Skip if one side is empty
            if (left.empty() || right.empty()) continue;

            // Calculate weighted Gini
            double weighted_gini =
                (left.size()  / total) * giniImpurity(left) +
                (right.size() / total) * giniImpurity(right);

            // Is this better than our best so far?
            if (weighted_gini < best_gini) {
                best_gini      = weighted_gini;
                best_feature   = feature;
                best_threshold = threshold;
            }
        }
    }

    return best_gini;
}

Node* DecisionTree::buildTree(vector<FlowFeatures> data, int depth)
{
    // ── Stopping conditions ──

    // 1. All same class → make leaf
    if (allSameClass(data)) {
        Node* leaf = new Node();
        leaf->leaf_label = data[0].label;
        return leaf;
    }

    // 2. Max depth reached → make leaf with majority class
    if (depth >= max_depth) {
        Node* leaf = new Node();
        leaf->leaf_label = majorityClass(data);
        return leaf;
    }

    // 3. Too few samples → make leaf
    if ((int)data.size() < min_samples) {
        Node* leaf = new Node();
        leaf->leaf_label = majorityClass(data);
        return leaf;
    }

    // ── Find best split ──
    int    best_feature;
    double best_threshold;
    double best_gini = bestSplit(data, best_feature, best_threshold);

    // If no good split found → make leaf
    if (best_feature == -1) {
        Node* leaf = new Node();
        leaf->leaf_label = majorityClass(data);
        return leaf;
    }

    // ── Split data ──
    vector<FlowFeatures> left_data, right_data;
    for (const auto& f : data) {
        if (getFeature(f, best_feature) <= best_threshold)
            left_data.push_back(f);
        else
            right_data.push_back(f);
    }

    // ── Create internal node ──
    Node* node = new Node();
    node->feature_index = best_feature;
    node->threshold     = best_threshold;

    // ── Recurse on children ──
    node->left  = buildTree(left_data,  depth + 1);
    node->right = buildTree(right_data, depth + 1);

    return node;
}

// Public train() just calls buildTree on all data
void DecisionTree::train(const vector<FlowFeatures>& data)
{
    deleteTree(root);
    root = buildTree(data, 0);
    cout << "Decision Tree trained successfully!" << endl;
}

// Recursive predict helper
AppType DecisionTree::predictNode(const Node* node,
                                   const FlowFeatures& flow) const
{
    // Base case: leaf node → return label
    if (node->isLeaf()) {
        return node->leaf_label;
    }

    // Follow the branch
    double value = getFeature(flow, node->feature_index);

    if (value <= node->threshold)
        return predictNode(node->left,  flow);
    else
        return predictNode(node->right, flow);
}

// Public predict
AppType DecisionTree::predict(const FlowFeatures& flow) const
{
    if (root == nullptr) {
        cerr << "ERROR: Tree not trained yet!" << endl;
        return AppType::UNKNOWN;
    }
    return predictNode(root, flow);
}

// Print tree for debugging
void DecisionTree::printNode(const Node* node, int depth) const
{
    if (node == nullptr) return;

    string indent(depth * 4, ' ');

    if (node->isLeaf()) {
        cout << indent << "LEAF → AppType("
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

void DecisionTree::saveNode(const Node* node, ofstream& file) const
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
        cerr << "ERROR: Cannot save model to " << filename << endl;
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
    } else { // NODE
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
        cerr << "ERROR: Cannot load model from " << filename << endl;
        return;
    }
    deleteTree(root);
    root = loadNode(file);
    cout << "Model loaded from " << filename << endl;
}