#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include "flow_features.h"
#include "types.h"
#include <string>
#include <vector>
#include <unordered_set>

// ─────────────────────────────────────────
// A single blocking rule
// ─────────────────────────────────────────
struct Rule {
    enum class Type {
        BLOCK_APP,     // block by app type
        BLOCK_IP,      // block by destination IP
        BLOCK_PORT,    // block by destination port
        BLOCK_DOMAIN   // block by domain keyword
    };

    Type        type;
    AppType     app_type  = AppType::UNKNOWN;
    uint32_t    ip        = 0;
    uint16_t    port      = 0;
    std::string domain    = "";
    std::string comment   = "";
};

// ─────────────────────────────────────────
// Manages all blocking rules
// Loads from file, checks flows
// ─────────────────────────────────────────
class RuleManager {
public:
    RuleManager() {}

    // Load rules from a text file
    bool loadRules(const std::string& filename);

    // Add a rule manually
    void addRule(const Rule& rule);

    // Check if a flow should be blocked
    bool shouldBlock(const Flow& flow) const;

    // Print all loaded rules
    void printRules() const;

    // How many rules loaded
    size_t ruleCount() const { return rules.size(); }

    // Add default rules
    void addDefaultRules();

private:
    std::vector<Rule> rules;

    // Parse one line from rules file
    bool parseLine(const std::string& line);

    // Convert string to AppType
    AppType stringToAppType(const std::string& s) const;

    // Convert "192.168.1.1" to uint32_t
    uint32_t parseIP(const std::string& ip_str) const;
};

#endif // RULE_MANAGER_H