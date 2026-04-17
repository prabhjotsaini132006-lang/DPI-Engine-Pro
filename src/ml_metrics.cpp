#include "ml_metrics.h"
#include <algorithm>
#include <set>

using namespace std;

void MLMetrics::addPrediction(AppType actual,
                               AppType predicted)
{
    predictions.push_back({actual, predicted});
    confusion[actual][predicted]++;
}

void MLMetrics::calculate()
{
    if (predictions.empty()) return;

    // Get all classes
    set<AppType> class_set;
    for (const auto& p : predictions) {
        class_set.insert(p.actual);
        class_set.insert(p.predicted);
    }

    int total   = (int)predictions.size();
    int correct = 0;

    // Count correct
    for (const auto& p : predictions) {
        if (p.actual == p.predicted) correct++;
    }
    overall_accuracy = (double)correct / total;

    // Per class metrics
    double f1_sum = 0.0;
    int    n_classes = 0;

    for (AppType cls : class_set) {
        int tp = 0, fp = 0, fn = 0;

        for (const auto& p : predictions) {
            if (p.actual    == cls &&
                p.predicted == cls) tp++;
            if (p.actual    != cls &&
                p.predicted == cls) fp++;
            if (p.actual    == cls &&
                p.predicted != cls) fn++;
        }

        ClassMetrics cm;
        cm.support = tp + fn;

        cm.precision = (tp + fp) > 0 ?
            (double)tp / (tp + fp) : 0.0;

        cm.recall = (tp + fn) > 0 ?
            (double)tp / (tp + fn) : 0.0;

        cm.f1_score =
            (cm.precision + cm.recall) > 0 ?
            2.0 * cm.precision * cm.recall /
            (cm.precision + cm.recall) : 0.0;

        class_metrics[cls] = cm;

        if (cm.support > 0) {
            f1_sum += cm.f1_score;
            n_classes++;
        }
    }

    macro_f1 = n_classes > 0 ?
        f1_sum / n_classes : 0.0;
}

void MLMetrics::printReport() const
{
    cout << "\n════════════════════════════════════════\n";
    cout << "          ML Evaluation Metrics          \n";
    cout << "════════════════════════════════════════\n";
    cout << fixed << setprecision(3);

    cout << "Overall Accuracy: "
         << (overall_accuracy * 100.0) << "%\n";
    cout << "Macro F1 Score:   "
         << (macro_f1 * 100.0) << "%\n";
    cout << "Total samples:    "
         << predictions.size() << "\n\n";

    cout << setw(12) << "Class"
         << setw(12) << "Precision"
         << setw(10) << "Recall"
         << setw(10) << "F1"
         << setw(10) << "Support"
         << "\n";
    cout << string(54, '-') << "\n";

    for (const auto& pair : class_metrics) {
        if (pair.second.support == 0) continue;
        const ClassMetrics& cm = pair.second;

        cout << setw(12) << appName(pair.first)
             << setw(11) << (cm.precision*100) << "%"
             << setw(9)  << (cm.recall*100)    << "%"
             << setw(9)  << (cm.f1_score*100)  << "%"
             << setw(10) << cm.support
             << "\n";
    }
    cout << "════════════════════════════════════════\n";
}

void MLMetrics::printConfusionMatrix() const
{
    vector<AppType> classes = getClasses();
    if (classes.empty()) return;

    cout << "\n=== Confusion Matrix ===\n";
    cout << "Rows=Actual, Cols=Predicted\n\n";

    // Header
    cout << setw(12) << " ";
    for (AppType cls : classes) {
        cout << setw(10) << appName(cls);
    }
    cout << "\n" << string(12 + classes.size()*10, '-')
         << "\n";

    // Rows
    for (AppType actual : classes) {
        cout << setw(12) << appName(actual);
        for (AppType predicted : classes) {
            int count = 0;
            auto it = confusion.find(actual);
            if (it != confusion.end()) {
                auto it2 = it->second.find(predicted);
                if (it2 != it->second.end()) {
                    count = it2->second;
                }
            }
            cout << setw(10) << count;
        }
        cout << "\n";
    }
    cout << "\n";
}

double MLMetrics::accuracy() const
{
    return overall_accuracy;
}

double MLMetrics::macroF1() const
{
    return macro_f1;
}

void MLMetrics::reset()
{
    predictions.clear();
    class_metrics.clear();
    confusion.clear();
    overall_accuracy = 0.0;
    macro_f1         = 0.0;
}

string MLMetrics::appName(AppType app) const
{
    switch (app) {
        case AppType::YOUTUBE:  return "YOUTUBE";
        case AppType::DNS:      return "DNS";
        case AppType::WHATSAPP: return "WHATSAPP";
        case AppType::ZOOM:     return "ZOOM";
        case AppType::HTTP:     return "HTTP";
        case AppType::HTTPS:    return "HTTPS";
        case AppType::GAMING:   return "GAMING";
        case AppType::NETFLIX:  return "NETFLIX";
        case AppType::SPOTIFY:  return "SPOTIFY";
        case AppType::STEAM:    return "STEAM";
        case AppType::TIKTOK:   return "TIKTOK";
        default:                return "UNKNOWN";
    }
}

vector<AppType> MLMetrics::getClasses() const
{
    set<AppType> class_set;
    for (const auto& p : predictions) {
        class_set.insert(p.actual);
    }
    return vector<AppType>(
        class_set.begin(), class_set.end());
}