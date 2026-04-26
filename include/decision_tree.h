#ifndef DECISION_TREE_H
#define DECISION_TREE_H

#include "flow_features.h"
#include "types.h"
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <fstream>

struct Node {
    bool    is_split      = false;
    int     feature_index = -1;
    double  threshold     = 0.0;
    AppType leaf_label    = AppType::UNKNOWN;

    // Real confidence tracking
    std::map<AppType, int> class_counts;
    int                    total_samples = 0;

    Node* left  = nullptr;
    Node* right = nullptr;

    bool isLeaf() const { return !is_split; }
};

class DecisionTree {
public:
    DecisionTree(int max_depth = 5, int min_samples = 2);
    ~DecisionTree();

    void    train(const std::vector<FlowFeatures>& data);
    AppType predict(const FlowFeatures& flow) const;
    Prediction predictWithConfidence(const FlowFeatures& flow) const;

    void setFeatureSubsampling(bool enabled) {
        use_feature_subsampling = enabled;
    }

    void save(const std::string& filename) const;
    void load(const std::string& filename);
    void save(std::ofstream& file) const;
    void load(std::ifstream& file);
    void print() const;

    static const char* FEATURE_NAMES[12];

private:
    int     max_depth;
    int     min_samples;
    Node*   root;
    bool    use_feature_subsampling = false;

    void    deleteTree(Node* node);
    double  getFeature(const FlowFeatures& f, int index) const;
    bool    allSameClass(const std::vector<FlowFeatures>& data) const;
    AppType majorityClass(const std::vector<FlowFeatures>& data) const;
    double  giniImpurity(const std::vector<FlowFeatures>& data) const;
    double  bestSplit(const std::vector<FlowFeatures>& data,
                     int& best_feature,
                     double& best_threshold) const;
    Node*   buildTree(std::vector<FlowFeatures> data, int depth);
    AppType predictNode(const Node* node,
                        const FlowFeatures& flow) const;
    void    printNode(const Node* node, int depth) const;
    void    saveNode(const Node* node, std::ofstream& file) const;
    Node*   loadNode(std::ifstream& file);
};

#endif // DECISION_TREE_H