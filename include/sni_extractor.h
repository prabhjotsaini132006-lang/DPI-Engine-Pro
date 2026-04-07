#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <string>
#include <cstdint>

class SNIExtractor {
public:
    // Try to extract SNI from TLS payload
    // Returns empty string if not found
    std::string extract(const uint8_t* payload,
                        uint16_t       len) const;

private:
    // Parse TLS extensions to find SNI
    std::string parseExtensions(const uint8_t* data,
                                uint16_t       len) const;
};

#endif // SNI_EXTRACTOR_H