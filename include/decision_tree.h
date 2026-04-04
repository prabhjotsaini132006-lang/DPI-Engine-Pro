#ifndef DECISION_TREE_H
#define DECISION_TREE_H

#include "flow_features.h"
#include <vector>
#include <string>

// ─────────────────────────────────────────
// A single node in the Decision Tree
// ─────────────────────────────────────────
struct Node {
    // Split info (for internal nodes)
    int    feature_index = -1;
    double threshold     = 0.0;

    // Prediction (for leaf nodes)
    AppType leaf_label = AppType::UNKNOWN;

    // Children
    Node* left  = nullptr;
    Node* right = nullptr;

    // Is this node a leaf?
    bool isLeaf() const {
        return left == nullptr && right == nullptr;
    }
};

// ─────────────────────────────────────────
// The Decision Tree classifier
// ─────────────────────────────────────────
class DecisionTree {
public:
    DecisionTree(int max_depth = 5, int min_samples = 2);
    ~DecisionTree();

    // Build tree from labeled training data
    void train(const std::vector<FlowFeatures>& data);

    // Predict app type for a new flow
    AppType predict(const FlowFeatures& flow) const;

    // Save and load tree
    void save(const std::string& filename) const;
    void load(const std::string& filename);

    // Print tree structure (for debugging)
    void print() const;

private:
    Node* root      = nullptr;
    int   max_depth = 5;
    int   min_samples = 2;

    // ── Core algorithm functions ──

    // Recursively build tree
    Node* buildTree(std::vector<FlowFeatures> data, int depth);

    // Calculate Gini impurity of a set of flows
    double giniImpurity(const std::vector<FlowFeatures>& data) const;

    // Find the best feature and threshold to split on
    // Returns weighted gini of best split
    double bestSplit(const std::vector<FlowFeatures>& data,
                     int&    best_feature,
                     double& best_threshold) const;

    // Get value of feature[index] from a FlowFeatures
    double getFeature(const FlowFeatures& f, int index) const;

    // Get majority class from a set of flows
    AppType majorityClass(const std::vector<FlowFeatures>& data) const;

    // Check if all flows have the same label
    bool allSameClass(const std::vector<FlowFeatures>& data) const;

    // Recursive predict helper
    AppType predictNode(const Node* node,
                        const FlowFeatures& flow) const;

    // Recursive delete tree
    void deleteTree(Node* node);

    // Recursive print helper
    void printNode(const Node* node, int depth) const;

    // Save/load helpers
    void saveNode(const Node* node, std::ofstream& file) const;
    Node* loadNode(std::ifstream& file);

    // Feature names for printing
    static const char* FEATURE_NAMES[12];
};

#endif // DECISION_TREE_H