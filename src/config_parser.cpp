#include "config_parser.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

using namespace std;

string ConfigParser::trim(const string& s) const
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool ConfigParser::parseLine(
    const string& line,
    string& current_section)
{
    string trimmed = trim(line);

    // Skip empty lines and comments
    if (trimmed.empty() ||
        trimmed[0] == '#' ||
        trimmed[0] == ';') {
        return true;
    }

    // Section header [section]
    if (trimmed[0] == '[') {
        size_t end = trimmed.find(']');
        if (end == string::npos) return false;
        current_section = trim(
            trimmed.substr(1, end - 1));
        return true;
    }

    // Key = value
    size_t eq = trimmed.find('=');
    if (eq == string::npos) return false;

    string key   = trim(trimmed.substr(0, eq));
    string value = trim(trimmed.substr(eq + 1));

    // Remove inline comments
    size_t comment = value.find('#');
    if (comment != string::npos) {
        value = trim(value.substr(0, comment));
    }

    if (!current_section.empty() && !key.empty()) {
        data[current_section][key] = value;
    }

    return true;
}

bool ConfigParser::load(const string& filename)
{
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "ConfigParser: Cannot open "
             << filename << endl;
        return false;
    }

    string line;
    string current_section = "";
    int    line_num        = 0;

    while (getline(file, line)) {
        line_num++;
        if (!parseLine(line, current_section)) {
            cerr << "ConfigParser: Parse error "
                 << "on line " << line_num << endl;
        }
    }

    cout << "ConfigParser: Loaded "
         << filename << endl;
    return true;
}

string ConfigParser::get(
    const string& section,
    const string& key,
    const string& default_val) const
{
    auto sec_it = data.find(section);
    if (sec_it == data.end()) return default_val;

    auto key_it = sec_it->second.find(key);
    if (key_it == sec_it->second.end())
        return default_val;

    return key_it->second;
}

void ConfigParser::applyTo(DPIConfig& config) const
{
    // [files]
    string csv = get("files", "csv_file");
    if (!csv.empty()) config.csv_file = csv;

    string model = get("files", "model_file");
    if (!model.empty()) config.model_file = model;

    string rules = get("files", "rules_file");
    if (!rules.empty()) config.rules_file = rules;

    // [ml]
    string use_rf = get("ml", "use_random_forest");
    if (use_rf == "true")  config.use_random_forest = true;
    if (use_rf == "false") config.use_random_forest = false;

    string trees = get("ml", "rf_trees");
    if (!trees.empty())
        config.rf_trees = stoi(trees);

    string depth = get("ml", "tree_max_depth");
    if (!depth.empty())
        config.tree_max_depth = stoi(depth);

    string conf = get("ml", "min_confidence");
    if (!conf.empty())
        config.min_confidence = stod(conf);

    // [engine]
    string threads = get("engine", "worker_threads");
    if (!threads.empty())
        config.worker_threads = stoi(threads);

    string flow_timeout = get("engine",
                               "flow_timeout_sec");
    if (!flow_timeout.empty())
        config.flow_timeout_sec = stoi(flow_timeout);

    string cache_timeout = get("engine",
                                "cache_timeout_sec");
    if (!cache_timeout.empty())
        config.cache_timeout_sec = stoi(cache_timeout);

    // [output]
    string verbose = get("output", "verbose");
    if (verbose == "true")  config.verbose = true;
    if (verbose == "false") config.verbose = false;

    string blocked = get("output",
                         "print_blocked_only");
    if (blocked == "true")
        config.print_blocked_only = true;
}

void ConfigParser::printSettings() const
{
    cout << "=== Config Settings ===" << endl;
    for (const auto& section : data) {
        cout << "[" << section.first << "]" << endl;
        for (const auto& kv : section.second) {
            cout << "  " << kv.first
                 << " = " << kv.second << endl;
        }
    }
}