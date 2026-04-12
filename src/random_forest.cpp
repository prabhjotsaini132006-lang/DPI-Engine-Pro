#include "random_forest.h"
#include <iostream>
#include <map>
#include <cstdlib>
#include <ctime>

using namespace std;

RandomForest::RandomForest(int n_trees,
                           int max_depth,
                           int min_samples)
    : n_trees(n_trees),
      max_depth(max_depth),
      min_samples(min_samples),
      trained(false)
{
    srand((unsigned int)time(nullptr));
}

RandomForest::~RandomForest()
{
    for (auto* tree : trees) {
        delete tree;
    }
    trees.clear();
}

vector<FlowFeatures> RandomForest::randomSubset(
    const vector<FlowFeatures>& data,
    int subset_size) const
{
    vector<FlowFeatures> subset;
    for (int i = 0; i < subset_size; i++) {
        int index = rand() % data.size();
        subset.push_back(data[index]);
    }
    return subset;
}

void RandomForest::train(const vector<FlowFeatures>& data)
{
    for (auto* tree : trees) delete tree;
    trees.clear();

    int subset_size = (int)data.size();

    cout << "RandomForest: Training " << n_trees
         << " trees..." << endl;

    for (int i = 0; i < n_trees; i++) {
        vector<FlowFeatures> subset =
            randomSubset(data, subset_size);

        DecisionTree* tree =
            new DecisionTree(max_depth, min_samples);
        tree->train(subset);
        trees.push_back(tree);

        cout << "  Tree " << (i+1) << "/"
             << n_trees << " trained" << endl;
    }

    trained = true;
    cout << "RandomForest: All trees trained!" << endl;
}

AppType RandomForest::predict(
    const FlowFeatures& flow) const
{
    if (!trained || trees.empty()) {
        cerr << "RandomForest: Not trained!" << endl;
        return AppType::UNKNOWN;
    }

    map<AppType, int> votes;
    for (const auto* tree : trees) {
        AppType prediction = tree->predict(flow);
        votes[prediction]++;
    }

    AppType best_app   = AppType::UNKNOWN;
    int     best_votes = 0;

    for (const auto& pair : votes) {
        if (pair.second > best_votes) {
            best_votes = pair.second;
            best_app   = pair.first;
        }
    }

    return best_app;
}

Prediction RandomForest::predictWithConfidence(
    const FlowFeatures& flow) const
{
    Prediction result;

    if (!trained || trees.empty()) {
        return result;
    }

    // Empty flow check
    if (flow.total_packets == 0) {
        result.app_type   = AppType::UNKNOWN;
        result.confidence = 0.0;
        return result;
    }

    map<AppType, int> votes;
    for (const auto* tree : trees) {
        AppType prediction = tree->predict(flow);
        votes[prediction]++;
    }

    AppType best_app   = AppType::UNKNOWN;
    int     best_votes = 0;

    for (const auto& pair : votes) {
        if (pair.second > best_votes) {
            best_votes = pair.second;
            best_app   = pair.first;
        }
    }

    result.app_type   = best_app;
    result.confidence = (double)best_votes /
                        (double)n_trees;

    return result;
}