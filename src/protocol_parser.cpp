#include "protocol_parser.h"
#include <sstream>
#include <cstring>

using namespace std;

uint16_t ProtocolParser::readU16(
    const uint8_t* p) const
{
    return ((uint16_t)p[0] << 8) | p[1];
}

uint32_t ProtocolParser::readU32(
    const uint8_t* p) const
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
            p[3];
}

// ─────────────────────────────────────────
// HTTP Parser
// ─────────────────────────────────────────
HTTPData ProtocolParser::parseHTTP(
    const uint8_t* payload,
    uint16_t len) const
{
    HTTPData result;
    if (len < 4) return result;

    string data((const char*)payload, len);

    // Check if HTTP request
    static const char* methods[] = {
        "GET ", "POST ", "PUT ",
        "DELETE ", "HEAD ", "OPTIONS ",
        nullptr
    };

    bool is_request = false;
    for (int i = 0; methods[i]; i++) {
        if (data.substr(0, strlen(methods[i]))
            == methods[i]) {
            is_request = true;
            break;
        }
    }

    // Check if HTTP response
    bool is_response =
        (data.substr(0, 5) == "HTTP/");

    if (!is_request && !is_response) {
        return result;
    }

    result.valid = true;

    if (is_request) {
        result.is_request = true;

        // Parse method
        size_t space1 = data.find(' ');
        if (space1 != string::npos) {
            result.method = data.substr(0, space1);

            // Parse URL
            size_t space2 = data.find(' ', space1+1);
            if (space2 != string::npos) {
                result.url = data.substr(
                    space1+1, space2-space1-1);

                // Parse version
                size_t crlf = data.find("\r\n",
                                         space2);
                if (crlf != string::npos) {
                    result.version = data.substr(
                        space2+1, crlf-space2-1);
                }
            }
        }
    }

    if (is_response) {
        result.is_response = true;

        // Parse status code
        size_t space1 = data.find(' ');
        if (space1 != string::npos) {
            result.version = data.substr(0, space1);
            size_t space2 = data.find(
                ' ', space1+1);
            if (space2 != string::npos) {
                string status_str = data.substr(
                    space1+1, space2-space1-1);
                try {
                    result.status = stoi(status_str);
                } catch (...) {}
            }
        }
    }

    // Parse headers
    size_t header_start = data.find("\r\n");
    if (header_start == string::npos)
        return result;

    header_start += 2;
    size_t header_end = data.find("\r\n\r\n",
                                   header_start);
    if (header_end == string::npos)
        header_end = data.size();

    string headers_str = data.substr(
        header_start,
        header_end - header_start);

    // Parse each header line
    size_t pos = 0;
    while (pos < headers_str.size()) {
        size_t crlf = headers_str.find("\r\n", pos);
        if (crlf == string::npos)
            crlf = headers_str.size();

        string line = headers_str.substr(
            pos, crlf - pos);

        size_t colon = line.find(':');
        if (colon != string::npos) {
            string key   = line.substr(0, colon);
            string value = line.substr(colon + 2);

            result.headers[key] = value;

            // Extract Host header specially
            if (key == "Host") {
                result.host = value;
            }
        }

        pos = crlf + 2;
    }

    return result;
}

// ─────────────────────────────────────────
// DNS Parser
// ─────────────────────────────────────────
string ProtocolParser::parseDNSName(
    const uint8_t* data,
    uint16_t       total_len,
    uint16_t       offset) const
{
    string name = "";
    int    jumps = 0;
    uint16_t pos = offset;

    while (pos < total_len) {
        uint8_t len = data[pos];

        // Pointer (compression)
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= total_len) break;
            uint16_t ptr = ((len & 0x3F) << 8)
                          | data[pos+1];
            pos = ptr;
            jumps++;
            if (jumps > 10) break;
            continue;
        }

        // End of name
        if (len == 0) break;

        pos++;
        if (pos + len > total_len) break;

        if (!name.empty()) name += ".";
        name += string((const char*)(data + pos),
                       len);
        pos += len;
    }

    return name;
}

string ProtocolParser::dnsTypeStr(
    uint16_t type) const
{
    switch (type) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        default: return "TYPE" + to_string(type);
    }
}

DNSData ProtocolParser::parseDNS(
    const uint8_t* payload,
    uint16_t len) const
{
    DNSData result;

    // DNS header is 12 bytes minimum
    if (len < 12) return result;

    uint16_t flags   = readU16(payload + 2);
    uint16_t qdcount = readU16(payload + 4);

    bool is_response = (flags & 0x8000) != 0;
    bool is_query    = !is_response;

    result.is_query    = is_query;
    result.is_response = is_response;
    result.answer_count = readU16(payload + 6);

    // Parse first question
    if (qdcount > 0 && len > 12) {
        result.query_name = parseDNSName(
            payload, len, 12);

        // Find query type after name
        uint16_t pos = 12;
        while (pos < len) {
            uint8_t label_len = payload[pos];
            if ((label_len & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            if (label_len == 0) {
                pos++;
                break;
            }
            pos += 1 + label_len;
        }

        if (pos + 2 <= len) {
            result.query_type =
                readU16(payload + pos);
            result.query_type_str =
                dnsTypeStr(result.query_type);
        }

        result.valid = !result.query_name.empty();
    }

    return result;
}

// ─────────────────────────────────────────
// TLS Enhanced Parser
// ─────────────────────────────────────────
string ProtocolParser::tlsVersionStr(
    uint16_t version) const
{
    switch (version) {
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default:     return "Unknown TLS";
    }
}

TLSData ProtocolParser::parseTLS(
    const uint8_t* payload,
    uint16_t len) const
{
    TLSData result;

    if (len < 5) return result;

    // Check TLS record
    if (payload[0] != 22) return result;
    if (payload[1] != 3)  return result;

    uint16_t tls_version =
        ((uint16_t)payload[1] << 8) | payload[2];

    result.tls_version = tls_version;
    result.version_str = tlsVersionStr(tls_version);

    // Check ClientHello
    if (len < 47) return result;
    if (payload[5] != 1) return result;

    // Session ID
    uint8_t session_id_len = payload[43];
    size_t pos = 44 + session_id_len;
    if (pos + 2 > len) return result;

    // Cipher suites
    uint16_t cipher_len = readU16(payload + pos);
    pos += 2;

    // JA3 string starts here
    ostringstream ja3;

    // TLS version
    uint16_t client_version =
        readU16(payload + 9);
    ja3 << client_version << ",";

    // Cipher suites for JA3
    ostringstream ciphers;
    bool first = true;
    for (uint16_t i = 0; i+1 < cipher_len &&
         pos+i+1 < len; i += 2)
    {
        uint16_t cipher =
            readU16(payload + pos + i);
        if (cipher != 0x0000) {
            if (!first) ciphers << "-";
            ciphers << cipher;
            first = false;
        }
    }
    ja3 << ciphers.str() << ",";

    pos += cipher_len;
    if (pos >= len) return result;

    // Compression
    uint8_t comp_len = payload[pos++];
    pos += comp_len;
    if (pos + 2 > len) return result;

    // Extensions
    uint16_t ext_total = readU16(payload + pos);
    pos += 2;

    ostringstream extensions;
    ostringstream elliptic_curves;
    ostringstream ec_formats;
    bool first_ext = true;
    bool first_ec  = true;

    size_t ext_end = pos + ext_total;
    while (pos + 4 <= ext_end && pos + 4 <= len) {
        uint16_t ext_type = readU16(payload + pos);
        uint16_t ext_len  =
            readU16(payload + pos + 2);
        pos += 4;

        if (!first_ext) extensions << "-";
        extensions << ext_type;
        first_ext = false;

        // SNI extension
        if (ext_type == 0x0000 &&
            ext_len > 5 && pos + ext_len <= len) {
            uint16_t name_len =
                readU16(payload + pos + 3);
            if (pos + 5 + name_len <= len) {
                result.sni = string(
                    (const char*)(payload+pos+5),
                    name_len);
            }
        }

        // Elliptic curves
        if (ext_type == 0x000a &&
            ext_len >= 2 && pos + ext_len <= len) {
            uint16_t curves_len =
                readU16(payload + pos);
            for (uint16_t i = 2;
                 i+1 < curves_len && pos+i+1 < len;
                 i += 2)
            {
                uint16_t curve =
                    readU16(payload + pos + i);
                if (!first_ec) elliptic_curves << "-";
                elliptic_curves << curve;
                first_ec = false;
            }
        }

        pos += ext_len;
    }

    // Build JA3 string
    ja3 << extensions.str() << ","
        << elliptic_curves.str() << ","
        << ec_formats.str();

    result.ja3   = ja3.str();
    result.valid = true;

    return result;
}