#include "model_evaluator.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstdlib>
#include <ctime>

using namespace std;

void EvalResult::print() const
{
    cout << "\n=== Model Evaluation Results ===" << endl;
    cout << fixed << setprecision(2);
    cout << "Overall Accuracy: "
         << (overall_accuracy * 100.0)
         << "%" << endl;
    cout << "Total samples:    " << total_samples << endl;
    cout << "Correct:          " << correct       << endl;
    cout << "Incorrect:        " << incorrect     << endl;

    cout << "\nPer-Class Accuracy:" << endl;
    cout << setw(12) << "App"
         << setw(10) << "Correct"
         << setw(10) << "Total"
         << setw(12) << "Accuracy" << endl;
    cout << string(44, '-') << endl;

    for (const auto& pair : class_total) {
        AppType app    = pair.first;
        int     total  = pair.second;
        int     correct_count = 0;

        auto it = class_correct.find(app);
        if (it != class_correct.end()) {
            correct_count = it->second;
        }

        double acc = total > 0 ?
            (double)correct_count / total * 100.0 : 0.0;

        string app_name;
        switch (app) {
            case AppType::YOUTUBE:  app_name = "YOUTUBE";  break;
            case AppType::DNS:      app_name = "DNS";      break;
            case AppType::WHATSAPP: app_name = "WHATSAPP"; break;
            case AppType::ZOOM:     app_name = "ZOOM";     break;
            case AppType::HTTP:     app_name = "HTTP";     break;
            case AppType::HTTPS:    app_name = "HTTPS";    break;
            case AppType::GAMING:   app_name = "GAMING";   break;
            default:                app_name = "UNKNOWN";  break;
        }

        cout << setw(12) << app_name
             << setw(10) << correct_count
             << setw(10) << total
             << setw(11) << acc << "%" << endl;
    }
}

ModelEvaluator::ModelEvaluator(double test_split)
    : test_split(test_split)
{
    srand((unsigned int)time(nullptr));
}

void ModelEvaluator::splitData(
    const vector<FlowFeatures>& data,
    vector<FlowFeatures>& train,
    vector<FlowFeatures>& test)
{
    // Shuffle data
    vector<FlowFeatures> shuffled = data;
    for (int i = (int)shuffled.size() - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        swap(shuffled[i], shuffled[j]);
    }

    // Split
    int test_size = (int)(shuffled.size() * test_split);
    int train_size = (int)shuffled.size() - test_size;

    train.assign(shuffled.begin(),
                 shuffled.begin() + train_size);
    test.assign(shuffled.begin() + train_size,
                shuffled.end());
}

EvalResult ModelEvaluator::evaluate(
    const vector<FlowFeatures>& data)
{
    EvalResult result;

    if (data.size() < 5) {
        cerr << "ModelEvaluator: Not enough data" << endl;
        return result;
    }

    vector<FlowFeatures> train, test;
    splitData(data, train, test);

    cout << "ModelEvaluator: Training on "
         << train.size() << " samples, testing on "
         << test.size()  << " samples" << endl;

    // Train Decision Tree
    DecisionTree tree(5, 2);
    tree.train(train);

    // Evaluate on test set
    int correct = 0;
    for (const auto& f : test) {
        AppType predicted = tree.predict(f);
        AppType actual    = f.label;

        result.class_total[actual]++;

        if (predicted == actual) {
            correct++;
            result.class_correct[actual]++;
        }
    }

    result.total_samples    = (int)test.size();
    result.correct          = correct;
    result.incorrect        = (int)test.size() - correct;
    result.overall_accuracy =
        (double)correct / (double)test.size();

    return result;
}

EvalResult ModelEvaluator::evaluateRF(
    const vector<FlowFeatures>& data,
    int n_trees,
    int max_depth,
    int min_samples)
{
    EvalResult result;

    if (data.size() < 5) {
        cerr << "ModelEvaluator: Not enough data" << endl;
        return result;
    }

    vector<FlowFeatures> train, test;
    splitData(data, train, test);

    cout << "ModelEvaluator: Training RF on "
         << train.size() << " samples, testing on "
         << test.size()  << " samples" << endl;

    // Train Random Forest
    RandomForest rf(n_trees, max_depth, min_samples);
    rf.train(train);

    // Evaluate on test set
    int correct = 0;
    for (const auto& f : test) {
        AppType predicted = rf.predict(f);
        AppType actual    = f.label;

        result.class_total[actual]++;

        if (predicted == actual) {
            correct++;
            result.class_correct[actual]++;
        }
    }

    result.total_samples    = (int)test.size();
    result.correct          = correct;
    result.incorrect        = (int)test.size() - correct;
    result.overall_accuracy =
        (double)correct / (double)test.size();

    return result;
}

void ModelEvaluator::compareModels(
    const vector<FlowFeatures>& data)
{
    cout << "\n════════════════════════════════════" << endl;
    cout << "     Model Comparison Report         " << endl;
    cout << "════════════════════════════════════" << endl;

    cout << "\n── Decision Tree ──" << endl;
    EvalResult dt_result = evaluate(data);
    dt_result.print();

    cout << "\n── Random Forest ──" << endl;
    EvalResult rf_result = evaluateRF(data);
    rf_result.print();

    cout << "\n── Summary ──" << endl;
    cout << fixed << setprecision(2);
    cout << "Decision Tree accuracy: "
         << (dt_result.overall_accuracy * 100.0)
         << "%" << endl;
    cout << "Random Forest accuracy: "
         << (rf_result.overall_accuracy * 100.0)
         << "%" << endl;

    if (rf_result.overall_accuracy >
        dt_result.overall_accuracy) {
        cout << "Winner: Random Forest by "
             << ((rf_result.overall_accuracy -
                  dt_result.overall_accuracy) * 100.0)
             << "%" << endl;
    } else {
        cout << "Winner: Decision Tree by "
             << ((dt_result.overall_accuracy -
                  rf_result.overall_accuracy) * 100.0)
             << "%" << endl;
    }
    cout << "════════════════════════════════════" << endl;
}

string ModelEvaluator::appTypeToStr(AppType app) const
{
    switch (app) {
        case AppType::YOUTUBE:  return "YOUTUBE";
        case AppType::DNS:      return "DNS";
        case AppType::WHATSAPP: return "WHATSAPP";
        case AppType::ZOOM:     return "ZOOM";
        case AppType::HTTP:     return "HTTP";
        case AppType::HTTPS:    return "HTTPS";
        case AppType::GAMING:   return "GAMING";
        default:                return "UNKNOWN";
    }
}