#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "dpi_engine.h"
#include <string>
#include <map>

// ─────────────────────────────────────────
// Parses INI-style config files
// Loads settings into DPIConfig
// ─────────────────────────────────────────
class ConfigParser {
public:
    // Load config from file
    bool load(const std::string& filename);

    // Apply loaded config to DPIConfig
    void applyTo(DPIConfig& config) const;

    // Print all loaded settings
    void printSettings() const;

    // Get a value directly
    std::string get(const std::string& section,
                    const std::string& key,
                    const std::string& default_val = "")
                    const;

private:
    // section -> key -> value
    std::map<std::string,
             std::map<std::string, std::string>> data;

    // Parse one line
    bool parseLine(const std::string& line,
                   std::string& current_section);

    // Trim whitespace
    std::string trim(const std::string& s) const;
};

#endif // CONFIG_PARSER_H