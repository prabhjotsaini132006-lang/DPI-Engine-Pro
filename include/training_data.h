#ifndef TRAINING_DATA_H
#define TRAINING_DATA_H

#include "flow_features.h"
#include <vector>
#include <string>

class TrainingData{
	
public:
// Load labeled flows from a CSV file
    // Returns true if successful, false if file not found
    bool loadCSV(const std::string& filename);

    // Get all loaded flow features
    const std::vector<FlowFeatures>& getData() const;

    // How many flows were loaded
    size_t size() const;

    // Print summary of loaded data
    void printSummary() const;

private:

	std::vector<FlowFeatures> flows;

	// Helper: convert string label to AppType
    AppType stringToAppType(const std::string& label) const;

    // Helper: split a CSV line into fields
    std::vector<std::string> splitCSVLine(const std::string& line) const;
};

#endif // TRAINING_DATA_H