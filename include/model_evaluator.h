#ifndef MODEL_EVALUATOR_H
#define MODEL_EVALUATOR_H

#include "flow_features.h"
#include "decision_tree.h"
#include "random_forest.h"
#include "training_data.h"
#include <vector>
#include <map>
#include <string>

// ─────────────────────────────────────────
// Evaluation results for one model
// ─────────────────────────────────────────
struct EvalResult {
    double   overall_accuracy  = 0.0;
    int      total_samples     = 0;
    int      correct           = 0;
    int      incorrect         = 0;

    // Per class accuracy
    std::map<AppType, int> class_correct;
    std::map<AppType, int> class_total;

    void print() const;
};

// ─────────────────────────────────────────
// Evaluates ML model accuracy
// Uses train/test split
// ─────────────────────────────────────────
class ModelEvaluator {
public:
    ModelEvaluator(double test_split = 0.2);

    // Evaluate Decision Tree
    EvalResult evaluate(
        const std::vector<FlowFeatures>& data);

    // Evaluate Random Forest
    EvalResult evaluateRF(
        const std::vector<FlowFeatures>& data,
        int n_trees    = 10,
        int max_depth  = 5,
        int min_samples = 2);

    // Print comparison of both
    void compareModels(
        const std::vector<FlowFeatures>& data);

private:
    double test_split;

    // Split data into train and test sets
    void splitData(
        const std::vector<FlowFeatures>& data,
        std::vector<FlowFeatures>& train,
        std::vector<FlowFeatures>& test);

    // Convert AppType to string
    std::string appTypeToStr(AppType app) const;
};

#endif // MODEL_EVALUATOR_H