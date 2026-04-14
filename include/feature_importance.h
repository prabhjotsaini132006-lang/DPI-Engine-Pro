#ifndef FEATURE_IMPORTANCE_H
#define FEATURE_IMPORTANCE_H

#include "flow_features.h"
#include "decision_tree.h"
#include <vector>
#include <string>
#include <map>

// ─────────────────────────────────────────
// Calculates feature importance by counting
// how many times each feature is used
// as a split in the Decision Tree
// ─────────────────────────────────────────
class FeatureImportance {
public:
    // Calculate importance from a trained tree
    void calculate(const DecisionTree& tree,
                   const std::vector<FlowFeatures>& data);

    // Print importance report
    void printReport() const;

    // Get importance score for a feature
    double getImportance(int feature_index) const;

private:
    // Feature names
    static const char* FEATURE_NAMES[12];

    // Importance scores
    double scores[12] = {0.0};

    // Count splits per feature by traversing tree
    void countSplits(
        const std::vector<FlowFeatures>& data);

    // Measure how much accuracy drops when
    // a feature is removed (permutation importance)
    double measureDrop(
        const std::vector<FlowFeatures>& data,
        int feature_index);

    // Shuffle one feature in data
    std::vector<FlowFeatures> shuffleFeature(
        const std::vector<FlowFeatures>& data,
        int feature_index) const;

    // Calculate accuracy on data
    double calcAccuracy(
        const DecisionTree& tree,
        const std::vector<FlowFeatures>& data) const;

    const DecisionTree* tree_ptr = nullptr;
};

#endif // FEATURE_IMPORTANCE_H