#include "ml_classifier.h"
#include <iostream>
#include <fstream>

using namespace std;

MLClassifier::MLClassifier()
    : tree(5, 2), trained(false), training_samples(0)
{
    // tree(5, 2) means:
    //   max_depth   = 5
    //   min_samples = 2
}

bool MLClassifier::train(const string& csv_file)
{
    // Step 1: Load training data from CSV
    TrainingData td;
    if (!td.loadCSV(csv_file)) {
        cerr << "MLClassifier: Failed to load " << csv_file << endl;
        return false;
    }

    // Step 2: Check we have enough data
    if (td.size() < 2) {
        cerr << "MLClassifier: Not enough training data!" << endl;
        return false;
    }

    // Step 3: Train the decision tree
    cout << "MLClassifier: Training on "
         << td.size() << " flows..." << endl;

    tree.train(td.getData());

    // Step 4: Mark as trained
    trained          = true;
    training_samples = (int)td.size();

    cout << "MLClassifier: Training complete!" << endl;
    return true;
}

AppType MLClassifier::predict(const FlowFeatures& flow) const
{
    if (!trained) {
        cerr << "MLClassifier: Not trained yet!" << endl;
        return AppType::UNKNOWN;
    }
    return tree.predict(flow);
}

bool MLClassifier::saveModel(const string& filename) const
{
    if (!trained) {
        cerr << "MLClassifier: Nothing to save!" << endl;
        return false;
    }
    tree.save(filename);
    cout << "MLClassifier: Model saved to " << filename << endl;
    return true;
}

bool MLClassifier::loadModel(const string& filename)
{
    // Check if file exists before loading
    ifstream check(filename);
    if (!check.is_open()) {
        return false;   // file doesn't exist
    }
    check.close();

    tree.load(filename);
    trained = true;
    cout << "MLClassifier: Model loaded from " << filename << endl;
    return true;
}

bool MLClassifier::loadOrTrain(const string& csv_file,
                                const string& model_file)
{
    // Try loading existing model first
    cout << "MLClassifier: Looking for saved model..." << endl;

    if (loadModel(model_file)) {
        cout << "MLClassifier: Found and loaded saved model!" << endl;
        return true;
    }

    // No saved model found → train from scratch
    cout << "MLClassifier: No saved model found." << endl;
    cout << "MLClassifier: Training from CSV..." << endl;

    if (!train(csv_file)) {
        return false;
    }

    // Save the newly trained model for next time
    saveModel(model_file);
    return true;
}

bool MLClassifier::isTrained() const
{
    return trained;
}

void MLClassifier::printInfo() const
{
    cout << "=== MLClassifier Info ===" << endl;
    cout << "Trained:          " << (trained ? "YES" : "NO") << endl;
    cout << "Training samples: " << training_samples << endl;
    cout << "Max depth:        5" << endl;
    cout << "Min samples:      2" << endl;

    if (trained) {
        tree.print();
    }
}

Prediction MLClassifier::predictWithConfidence(
    const FlowFeatures& flow) const
{
    Prediction result;

    if (!trained) {
        cerr << "MLClassifier: Not trained yet!" << endl;
        return result;
    }

    // Empty flow check → zero confidence
    if (flow.total_packets == 0) {
        result.app_type   = AppType::UNKNOWN;
        result.confidence = 0.0;
        return result;
    }

    // Get base prediction
    result.app_type = tree.predict(flow);

    // Calculate confidence based on flow data quality
    double confidence = 0.5;

    if (flow.total_packets >= 10) confidence += 0.2;
    if (flow.total_packets >= 50) confidence += 0.1;

    if (flow.dst_port == 53 &&
        result.app_type == AppType::DNS)
        confidence = 0.99;

    if (result.app_type == AppType::UNKNOWN)
        confidence = 0.0;

    if (confidence > 1.0) confidence = 1.0;

    result.confidence = confidence;
    return result;
}