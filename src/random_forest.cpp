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

        tree->setFeatureSubsampling(true);  // TRUE RANDOM FOREST

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

bool RandomForest::saveModel(const string& filename) const
{
    ofstream file(filename);
    if (!file.is_open()) {
        cerr << "RandomForest: Cannot save to "
             << filename << "\n";
        return false;
    }

    file << "RF_V2\n";
    file << trees.size() << "\n";
    for (const auto* tree : trees) {
        tree->save(file);  // calls saveNode internally
    }

    cout << "RandomForest: Model saved to "
         << filename << "\n";
    return true;
}

bool RandomForest::loadModel(const string& filename)
{
    ifstream file(filename);
    if (!file.is_open()) return false;

    string header;
    getline(file, header);
    if (header != "RF_V2") {
        cerr << "RandomForest: Invalid model format\n";
        return false;
    }

    int n_trees;
    file >> n_trees;
    file.ignore();

    for (auto* t : trees) delete t;
    trees.clear();

    for (int i = 0; i < n_trees; i++) {
        DecisionTree* tree =
            new DecisionTree(max_depth, min_samples);
        tree->load(file);  // calls loadNode internally
        trees.push_back(tree);
    }

    trained = true;
    cout << "RandomForest: Loaded " << n_trees
         << " trees from " << filename << "\n";
    return true;
}