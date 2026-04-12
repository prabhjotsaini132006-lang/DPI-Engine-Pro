#ifndef ML_CLASSIFIER_H
#define ML_CLASSIFIER_H

#include "flow_features.h"
#include "decision_tree.h"
#include "training_data.h"
#include <string>



// Prediction with confidence score
struct Prediction {
    AppType app_type   = AppType::UNKNOWN;
    double  confidence = 0.0;  // 0.0 to 1.0
};

class MLClassifier{
public:
	// Predict with confidence score
	Prediction predictWithConfidence(const FlowFeatures& flow) const;

	MLClassifier();

	bool train(const std::string& csv_file);

	AppType predict(const FlowFeatures& flow) const;

	bool saveModel(const std::string& filename) const;

	bool loadModel(const std::string& filename);
	
	bool loadOrTrain(const std::string& csv_file,
		const std::string& model_file);

	bool isTrained() const;

	void printInfo() const;

	private:
	
	DecisionTree tree;
	bool trained=false;
	int training_samples=0;
};

#endif