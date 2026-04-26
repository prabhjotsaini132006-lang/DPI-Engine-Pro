#ifndef RANDOM_FOREST_H
#define RANDOM_FOREST_H

#include "flow_features.h"
#include "decision_tree.h"
#include "ml_classifier.h"
#include <vector>
#include <string>

class RandomForest {
public:
    RandomForest(int n_trees    = 10,
                 int max_depth  = 5,
                 int min_samples = 2);

    ~RandomForest();

    void    train(const std::vector<FlowFeatures>& data);
    AppType predict(const FlowFeatures& flow) const;
    Prediction predictWithConfidence(
                const FlowFeatures& flow) const;
    bool    isTrained() const { return trained; }
    bool saveModel(const std::string& filename) const;
    bool loadModel(const std::string& filename);

private:
    int  n_trees     = 10;
    int  max_depth   = 5;
    int  min_samples = 2;
    bool trained     = false;

    std::vector<DecisionTree*> trees;

    std::vector<FlowFeatures> randomSubset(
        const std::vector<FlowFeatures>& data,
        int subset_size) const;
};

#endif // RANDOM_FOREST_H