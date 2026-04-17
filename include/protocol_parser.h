#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include <string>
#include <map>
#include <cstdint>

// ─────────────────────────────────────────
// HTTP Parsed Data
// ─────────────────────────────────────────
struct HTTPData {
    bool        valid   = false;
    std::string method  = "";   // GET POST PUT DELETE
    std::string url     = "";   // /path/to/resource
    std::string host    = "";   // Host header
    std::string version = "";   // HTTP/1.1
    int         status  = 0;    // 200 404 etc (response)
    bool        is_request  = false;
    bool        is_response = false;

    std::map<std::string, std::string> headers;
};

// ─────────────────────────────────────────
// DNS Parsed Data
// ─────────────────────────────────────────
struct DNSData {
    bool        valid       = false;
    std::string query_name  = "";   // what domain
    uint16_t    query_type  = 0;    // A=1 AAAA=28 MX=15
    bool        is_query    = false;
    bool        is_response = false;
    uint16_t    answer_count = 0;
    std::string query_type_str = "";
};

// ─────────────────────────────────────────
// TLS Enhanced Data
// ─────────────────────────────────────────
struct TLSData {
    bool        valid       = false;
    std::string sni         = "";    // server name
    std::string ja3         = "";    // JA3 fingerprint
    uint16_t    tls_version = 0;
    std::string version_str = "";
};

// ─────────────────────────────────────────
// Protocol Parser
// Deep packet inspection for HTTP DNS TLS
// ─────────────────────────────────────────
class ProtocolParser {
public:
    // Parse HTTP from TCP payload
    HTTPData parseHTTP(const uint8_t* payload,
                       uint16_t len) const;

    // Parse DNS from UDP payload
    DNSData parseDNS(const uint8_t* payload,
                     uint16_t len) const;

    // Enhanced TLS parsing with JA3
    TLSData parseTLS(const uint8_t* payload,
                     uint16_t len) const;

private:
    // Read uint16 big endian
    uint16_t readU16(const uint8_t* p) const;

    // Read uint32 big endian
    uint32_t readU32(const uint8_t* p) const;

    // Parse DNS name from wire format
    std::string parseDNSName(
        const uint8_t* data,
        uint16_t       total_len,
        uint16_t       offset) const;

    // DNS query type to string
    std::string dnsTypeStr(uint16_t type) const;

    // TLS version to string
    std::string tlsVersionStr(
        uint16_t version) const;
};

#endif // PROTOCOL_PARSER_H

