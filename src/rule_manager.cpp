#include "rule_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>

using namespace std;

bool RuleManager::loadRules(const string& filename)
{
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "RuleManager: Cannot open "
             << filename << endl;
        return false;
    }

    string line;
    int loaded = 0;

    while (getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        if (parseLine(line)) loaded++;
    }

    cout << "RuleManager: Loaded " << loaded
         << " rules from " << filename << endl;
    return true;
}

bool RuleManager::parseLine(const string& line)
{
    istringstream ss(line);
    string type_str;
    ss >> type_str;

    Rule rule;

    if (type_str == "BLOCK_APP") {
        string app_str;
        ss >> app_str;
        rule.type     = Rule::Type::BLOCK_APP;
        rule.app_type = stringToAppType(app_str);
        if (rule.app_type == AppType::UNKNOWN) return false;
    }
    else if (type_str == "BLOCK_IP") {
        string ip_str;
        ss >> ip_str;
        rule.type = Rule::Type::BLOCK_IP;
        rule.ip   = parseIP(ip_str);
    }
    else if (type_str == "BLOCK_PORT") {
        int port;
        ss >> port;
        rule.type = Rule::Type::BLOCK_PORT;
        rule.port = (uint16_t)port;
    }
    else if (type_str == "BLOCK_DOMAIN") {
        string domain;
        ss >> domain;
        rule.type   = Rule::Type::BLOCK_DOMAIN;
        rule.domain = domain;
    }
    else {
        return false;  // unknown rule type
    }

    // Optional comment
    string comment;
    getline(ss, comment);
    rule.comment = comment;

    rules.push_back(rule);
    return true;
}

bool RuleManager::shouldBlock(const Flow& flow) const
{
    for (const auto& rule : rules) {
        switch (rule.type) {

        case Rule::Type::BLOCK_APP:
            if (flow.app_type == rule.app_type)
                return true;
            break;

        case Rule::Type::BLOCK_IP:
            if (flow.tuple.dst_ip == rule.ip)
                return true;
            break;

        case Rule::Type::BLOCK_PORT:
            if (flow.tuple.dst_port == rule.port)
                return true;
            break;

        case Rule::Type::BLOCK_DOMAIN:
            if (!flow.sni.empty() &&
                flow.sni.find(rule.domain)
                != string::npos)
                return true;
            break;
        }
    }
    return false;
}

void RuleManager::addRule(const Rule& rule)
{
    rules.push_back(rule);
}

void RuleManager::addDefaultRules()
{
    // No hardcoded defaults — all rules come from rules.txt
    cout << "RuleManager: Rules loaded from file" << endl;
}

void RuleManager::printRules() const
{
    cout << "=== Blocking Rules ===" << endl;
    for (size_t i = 0; i < rules.size(); i++) {
        const Rule& r = rules[i];
        cout << "[" << i << "] ";
        switch (r.type) {
        case Rule::Type::BLOCK_APP:
            cout << "BLOCK_APP ";
            switch (r.app_type) {
            case AppType::YOUTUBE:  cout << "YOUTUBE";  break;
            case AppType::GAMING:   cout << "GAMING";   break;
            case AppType::FACEBOOK: cout << "FACEBOOK"; break;
            default:                cout << "UNKNOWN";  break;
            }
            break;
        case Rule::Type::BLOCK_IP:
            cout << "BLOCK_IP "
                 << ((r.ip >> 24) & 0xFF) << "."
                 << ((r.ip >> 16) & 0xFF) << "."
                 << ((r.ip >> 8)  & 0xFF) << "."
                 << ( r.ip        & 0xFF);
            break;
        case Rule::Type::BLOCK_PORT:
            cout << "BLOCK_PORT " << r.port;
            break;
        case Rule::Type::BLOCK_DOMAIN:
            cout << "BLOCK_DOMAIN " << r.domain;
            break;
        }
        if (!r.comment.empty())
            cout << "  #" << r.comment;
        cout << endl;
    }
}

AppType RuleManager::stringToAppType(
    const string& s) const
{
    if (s == "YOUTUBE")  return AppType::YOUTUBE;
    if (s == "FACEBOOK") return AppType::FACEBOOK;
    if (s == "ZOOM")     return AppType::ZOOM;
    if (s == "WHATSAPP") return AppType::WHATSAPP;
    if (s == "GAMING")   return AppType::GAMING;
    if (s == "HTTP")     return AppType::HTTP;
    if (s == "HTTPS")    return AppType::HTTPS;
    if (s == "DNS")      return AppType::DNS;
    if (s == "NETFLIX")  return AppType::NETFLIX;
    if (s == "SPOTIFY")  return AppType::SPOTIFY;
    if (s == "STEAM")    return AppType::STEAM;
    if (s == "TIKTOK")   return AppType::TIKTOK;
    return AppType::UNKNOWN;
}

uint32_t RuleManager::parseIP(const string& ip_str) const
{
    uint32_t result = 0;
    int      octet  = 0;
    int      shift  = 24;

    for (char c : ip_str) {
        if (c == '.') {
            result |= (octet << shift);
            shift  -= 8;
            octet   = 0;
        } else {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= octet;  // last octet
    return result;
}