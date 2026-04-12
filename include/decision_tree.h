#ifndef DECISION_TREE_H
#define DECISION_TREE_H

#include "flow_features.h"
#include <vector>
#include <string>

struct Node {
    int     feature_index = -1;
    double  threshold     = 0.0;
    AppType leaf_label    = AppType::UNKNOWN;
    Node*   left          = nullptr;
    Node*   right         = nullptr;

    bool isLeaf() const {
        return left == nullptr && right == nullptr;
    }
};

class DecisionTree {
public:
    DecisionTree(int max_depth = 5, int min_samples = 2);
    ~DecisionTree();

    void    train(const std::vector<FlowFeatures>& data);
    AppType predict(const FlowFeatures& flow) const;
    void    save(const std::string& filename) const;
    void    load(const std::string& filename);
    void    print() const;

private:
    int   max_depth   = 5;
    int   min_samples = 2;
    Node* root        = nullptr;

    Node*   buildTree(std::vector<FlowFeatures> data, int depth);
    double  giniImpurity(const std::vector<FlowFeatures>& data) const;
    double  bestSplit(const std::vector<FlowFeatures>& data,
                     int& best_feature,
                     double& best_threshold) const;
    double  getFeature(const FlowFeatures& f, int index) const;
    AppType majorityClass(const std::vector<FlowFeatures>& data) const;
    bool    allSameClass(const std::vector<FlowFeatures>& data) const;
    AppType predictNode(const Node* node,
                        const FlowFeatures& flow) const;
    void    deleteTree(Node* node);
    void    printNode(const Node* node, int depth) const;
    void    saveNode(const Node* node, std::ofstream& file) const;
    Node*   loadNode(std::ifstream& file);

    static const char* FEATURE_NAMES[12];
};

#endif // DECISION_TREE_H