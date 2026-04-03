#include "training_data.h"
#include <fstream>
#include <sstream>
#include <iostream>

using namespace std;

vector<string> TrainingData::splitCSVLine(const string& line) const
{
	vector<string> fields;
	stringstream ss(line);
	string field;

	while(getline(ss,field,',')){
		fields.push_back(field);
	}
	
	return false;
}

AppType TrainingData::stringToAppType(const string& label) const
{
	if(label == "YOUTUBE") return AppType::YOUTUBE;
	if(label == "DNS") return AppType::DNS;
	if(label == "WHATSAPP") return AppType::WHATSAPP;
	if(label == "ZOOM") return AppType::ZOOM;
	if(label == "HTTP") return AppType::HTTP;
	if(label == "HTTPS") return AppType::HTTPS;
	if(label == "FACEBOOK") return AppType::FACEBOOK;
	if(label == "GAMING") return AppType::GAMING;
	return AppType::UNKNOWN;
}

bool TrainingData::loadCSV(const string& filename)
{
    ifstream file(filename);

    // Check if file opened successfully
    if (!file.is_open()) {
        cerr << "ERROR: Could not open file: " << filename << endl;
        return false;
    }

    string line;
    int lineNumber = 0;

    while (getline(file, line)) {
        lineNumber++;

        // Skip header row (first line)
        if (lineNumber == 1) continue;

        // Skip empty lines
        if (line.empty()) continue;

        // Split line into fields
        vector<string> fields = splitCSVLine(line);

        // We expect exactly 13 fields
        if (fields.size() != 13) {
            cerr << "WARNING: Skipping malformed line " 
                 << lineNumber << endl;
            continue;
        }

        // Parse each field into a FlowFeatures struct
        FlowFeatures f;
        f.total_packets       = stoull(fields[0]);
        f.total_bytes         = stoull(fields[1]);
        f.avg_packet_size     = stod(fields[2]);
        f.max_packet_size     = stoull(fields[3]);
        f.min_packet_size     = stoull(fields[4]);
        f.flow_duration_ms    = stod(fields[5]);
        f.packets_per_second  = stod(fields[6]);
        f.bytes_per_second    = stod(fields[7]);
        f.avg_inter_arrival_ms= stod(fields[8]);
        f.dst_port            = (uint16_t)stoi(fields[9]);
        f.protocol            = (uint8_t)stoi(fields[10]);
        f.has_tls             = (fields[11] == "1");
        f.label               = stringToAppType(fields[12]);

        flows.push_back(f);
    }

    file.close();
    return true;
}

const vector<FlowFeatures>& TrainingData::getData() const
{
    return flows;
}

size_t TrainingData::size() const
{
    return flows.size();
}

void TrainingData::printSummary() const
{
    cout << "Training data loaded: " << flows.size() << " flows" << endl;

    // Count each app type
    int counts[9] = {0}; // one per AppType

    for (const auto& f : flows) {
        counts[(int)f.label]++;
    }

    cout << "  YOUTUBE:  " << counts[(int)AppType::YOUTUBE]  << endl;
    cout << "  DNS:      " << counts[(int)AppType::DNS]      << endl;
    cout << "  WHATSAPP: " << counts[(int)AppType::WHATSAPP] << endl;
    cout << "  ZOOM:     " << counts[(int)AppType::ZOOM]     << endl;
    cout << "  HTTP:     " << counts[(int)AppType::HTTP]     << endl;
    cout << "  HTTPS:    " << counts[(int)AppType::HTTPS]    << endl;
    cout << "  UNKNOWN:  " << counts[(int)AppType::UNKNOWN]  << endl;
}	

 