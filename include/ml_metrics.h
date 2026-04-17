#ifndef ML_METRICS_H
#define ML_METRICS_H

#include "flow_features.h"
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <iomanip>

// ─────────────────────────────────────────
// ML Evaluation Metrics
// Accuracy, Precision, Recall, F1, Confusion Matrix
// ─────────────────────────────────────────
struct ClassMetrics {
    double precision = 0.0;
    double recall    = 0.0;
    double f1_score  = 0.0;
    int    support   = 0;
};

class MLMetrics {
public:
    // Add one prediction result
    void addPrediction(AppType actual,
                       AppType predicted);

    // Calculate all metrics
    void calculate();

    // Print full metrics report
    void printReport() const;

    // Print confusion matrix
    void printConfusionMatrix() const;

    // Get overall accuracy
    double accuracy() const;

    // Get macro F1 score
    double macroF1() const;

    // Reset all data
    void reset();

private:
    struct Entry {
        AppType actual;
        AppType predicted;
    };

    std::vector<Entry> predictions;

    // Calculated metrics per class
    std::map<AppType, ClassMetrics> class_metrics;

    double overall_accuracy = 0.0;
    double macro_f1         = 0.0;

    // Confusion matrix
    // confusion[actual][predicted] = count
    std::map<AppType,
             std::map<AppType, int>> confusion;

    // App type to string
    std::string appName(AppType app) const;

    // All unique classes seen
    std::vector<AppType> getClasses() const;
};

#endif // ML_METRICS_H